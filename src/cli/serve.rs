//! The `serve` command: bind listeners and run until interrupted.

use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::{Config, ListenerKind};
use crate::smtp::directory::Directory;
use crate::smtp::server::{Server, TlsMode};
use crate::smtp::sink::MessageSink;
use crate::storage::SplitDelivery;

/// Run the server with a validated configuration.
pub fn run(config: Config) -> ExitCode {
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			eprintln!("error: cannot start async runtime: {error}");
			return ExitCode::FAILURE;
		}
	};
	match runtime.block_on(serve(config)) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}

async fn serve(config: Config) -> std::io::Result<()> {
	if config.listeners.is_empty() {
		eprintln!("warning: no listeners configured, nothing to serve");
		return Ok(());
	}

	// Recipient resolution and credentials shared by sessions and delivery.
	let directory = Arc::new(
		Directory::new(
			config.domains.iter().cloned(),
			config.accounts.iter().flat_map(|account| {
				account
					.addresses
					.iter()
					.map(|address| (address.clone(), account.name.clone()))
			}),
		)
		.with_password_hashes(config.accounts.iter().filter_map(|account| {
			account
				.password_hash
				.as_ref()
				.map(|hash| (account.name.clone(), hash.clone()))
		})),
	);

	// Local recipients go to account mailboxes; authenticated relay mail
	// is queued in the outbound spool, DKIM-signed when configured.
	let mut split = SplitDelivery::new(&config.data_dir, Arc::clone(&directory))?;
	if let Some(dkim) = &config.dkim {
		let signer = crate::dkim::Signer::load(&dkim.selector, &dkim.key_file)
			.map_err(std::io::Error::other)?;
		split = split.with_signer(Arc::new(signer));
	}
	let sink: Arc<dyn MessageSink> = Arc::new(split);

	// SPF verification for unauthenticated inbound mail.
	let spf_dns: Arc<dyn crate::spf::DnsLookup> = Arc::new(crate::spf::SystemDns::from_system()?);

	// The queue worker drains the outbound spool in the background.
	let connector = Arc::new(crate::queue::MxConnector::from_system()?);
	let worker = Arc::new(crate::queue::Worker::new(
		crate::storage::FsSpool::open(&config.data_dir)?,
		connector,
		&config.hostname,
	));
	tokio::spawn(worker.run(std::time::Duration::from_secs(30)));

	// TLS is loaded once and shared; failure to load is fatal (fail closed).
	let tls_acceptor = match &config.tls {
		Some(tls_config) => Some(crate::tls::acceptor(tls_config).map_err(std::io::Error::other)?),
		None => None,
	};

	let mut tasks = Vec::new();
	for listener_config in &config.listeners {
		match listener_config.kind {
			ListenerKind::Smtp | ListenerKind::Submission | ListenerKind::Submissions => {
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
				let mode = match listener_config.kind {
					ListenerKind::Submissions => TlsMode::Implicit,
					_ => TlsMode::Opportunistic,
				};
				let mut server = Server::new(&config.hostname, Arc::clone(&sink))
					.with_directory(Arc::clone(&directory))
					.with_spf(Arc::clone(&spf_dns));
				if let Some(acceptor) = &tls_acceptor {
					server = server.with_tls(acceptor.clone(), mode);
				}
				tasks.push(tokio::spawn(Arc::new(server).serve(listener)));
			}
		}
	}

	// Run until the first listener fails or the process is interrupted.
	for task in tasks {
		task.await
			.map_err(|error| std::io::Error::other(error.to_string()))??;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::{IpAddr, Ipv4Addr};
	use std::path::Path;

	use crate::config::Listener;
	use crate::smtp::sink::MemorySink;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	fn test_config(data_dir: &Path, listeners: Vec<Listener>) -> Config {
		let toml = format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
			data_dir.display()
		);
		let mut config: Config = toml::from_str(&toml).expect("base config");
		config.listeners = listeners;
		config
	}

	#[test]
	fn run_with_no_listeners_exits_cleanly() {
		let dir = tempfile::tempdir().expect("tempdir");
		assert_eq!(run(test_config(dir.path(), vec![])), ExitCode::SUCCESS);
	}

	#[tokio::test]
	async fn serve_binds_and_answers() {
		// Port 0 lets the OS pick a free port; we then talk to it.
		let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
			.await
			.expect("bind");
		let addr = listener.local_addr().expect("addr");

		let sink: Arc<dyn MessageSink> = Arc::new(MemorySink::new());
		let server = Arc::new(Server::new("mail.example.org", sink));
		let task = tokio::spawn(server.serve(listener));

		let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
		let mut buffer = [0u8; 64];
		let read = client.read(&mut buffer).await.expect("greeting");
		assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("220 "));
		client.write_all(b"QUIT\r\n").await.expect("quit");
		task.abort();
	}

	#[tokio::test]
	async fn serve_fails_on_unbindable_address() {
		// Two listeners on the same port: the second bind must fail.
		let probe = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
			.await
			.expect("probe bind");
		let port = probe.local_addr().expect("addr").port();

		let dir = tempfile::tempdir().expect("tempdir");
		let listener: Listener =
			toml::from_str(&format!("kind = \"smtp\"\nport = {port}")).expect("listener config");
		let config = test_config(dir.path(), vec![listener]);
		assert!(serve(config).await.is_err());
	}

	#[tokio::test]
	async fn serve_fails_on_unwritable_data_dir() {
		let listener: Listener = toml::from_str("kind = \"smtp\"\nport = 0").expect("listener");
		let config = test_config(Path::new("/proc/no-such-dir"), vec![listener]);
		assert!(serve(config).await.is_err());
	}
}
