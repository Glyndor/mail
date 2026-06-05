//! The `serve` command: bind listeners and run until interrupted.

use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::{Config, ListenerKind};
use crate::smtp::server::Server;
use crate::smtp::sink::{MemorySink, MessageSink};

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

	// Storage is not implemented yet: messages go to a process-local sink.
	let sink: Arc<dyn MessageSink> = Arc::new(MemorySink::new());
	let mut tasks = Vec::new();

	for listener_config in &config.listeners {
		match listener_config.kind {
			ListenerKind::Smtp | ListenerKind::Submission | ListenerKind::Submissions => {
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
				let server = Arc::new(Server::new(&config.hostname, Arc::clone(&sink)));
				tasks.push(tokio::spawn(server.serve(listener)));
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

	use crate::config::Listener;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	fn test_config(listeners: Vec<Listener>) -> Config {
		let toml = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";
		let mut config: Config = toml::from_str(toml).expect("base config");
		config.listeners = listeners;
		config
	}

	#[test]
	fn run_with_no_listeners_exits_cleanly() {
		assert_eq!(run(test_config(vec![])), ExitCode::SUCCESS);
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

		let listener: Listener =
			toml::from_str(&format!("kind = \"smtp\"\nport = {port}")).expect("listener config");
		let config = test_config(vec![listener]);
		assert!(serve(config).await.is_err());
	}
}
