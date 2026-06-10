//! IMAP network layer: implicit TLS only.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::directory_store::DirectoryHandle;
use crate::smtp::line::{LineDecoder, LineError};

use super::session::Session;

/// How a listener negotiates TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
	/// TLS handshake before any IMAP traffic (`imaps`, 993).
	Implicit,
	/// Plaintext greeting; STARTTLS upgrade required before LOGIN (`imap`, 143).
	StartTls,
}

/// Maximum concurrent IMAP connections per listener.
const MAX_CONNECTIONS: usize = 500;

/// Idle read timeout. RFC 9051 §5.4 recommends the server close the connection
/// after 30 minutes of inactivity; we enforce it to kill Slowloris sessions.
const READ_TIMEOUT: Duration = Duration::from_secs(1800);

/// Anything the connection loop can read from and write to.
trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

/// IMAP server: one instance per listener.
pub struct Server {
	hostname: String,
	data_dir: PathBuf,
	directory: DirectoryHandle,
	tls: TlsAcceptor,
	tls_mode: TlsMode,
}

impl Server {
	/// Create a server. TLS material is mandatory either way: LOGIN never
	/// crosses plaintext.
	pub fn new(
		hostname: &str,
		data_dir: PathBuf,
		directory: DirectoryHandle,
		tls: TlsAcceptor,
		tls_mode: TlsMode,
	) -> Self {
		Server {
			hostname: hostname.to_string(),
			data_dir,
			directory,
			tls,
			tls_mode,
		}
	}

	/// Accept connections forever.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
		loop {
			let (stream, peer) = listener.accept().await?;
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "IMAP connection limit reached, dropping");
				continue;
			};
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				let _permit = permit;
				tracing::debug!(%peer, "imap connection accepted");
				if let Err(error) = server.handle(stream).await {
					tracing::debug!(%peer, %error, "imap connection ended with error");
				}
			});
		}
	}

	/// Drive one connection: TLS handshake (or plaintext with STARTTLS),
	/// then the command loop.
	pub async fn handle<S>(&self, stream: S) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		let (mut stream, mut session): (Box<dyn Connection>, Session) = match self.tls_mode {
			TlsMode::Implicit => {
				let tls = self.tls.accept(stream).await?;
				(
					Box::new(tls),
					Session::new(
						&self.hostname,
						self.data_dir.clone(),
						self.directory.current(),
					),
				)
			}
			TlsMode::StartTls => (
				Box::new(stream),
				Session::new(
					&self.hostname,
					self.data_dir.clone(),
					self.directory.current(),
				)
				.with_starttls(),
			),
		};

		let greeting = session.greeting();
		stream.write_all(&greeting.bytes).await?;
		stream.flush().await?;

		let mut decoder = LineDecoder::new();
		let mut buffer = [0u8; 4096];
		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					let read = match tokio::time::timeout(
						READ_TIMEOUT,
						stream.read(&mut buffer),
					)
					.await
					{
						Ok(Ok(n)) => n,
						Ok(Err(e)) => return Err(e),
						Err(_) => {
							tracing::debug!("IMAP idle timeout, closing connection");
							let _ = stream.write_all(b"* BYE idle timeout\r\n").await;
							return Ok(());
						}
					};
					if read == 0 {
						return Ok(());
					}
					decoder.feed(&buffer[..read]);
					continue;
				}
				Err(error) => {
					let message: &[u8] = match error {
						LineError::TooLong => b"* BYE line too long\r\n",
						LineError::BareControlCharacter | LineError::NulByte => {
							b"* BYE protocol error\r\n"
						}
					};
					stream.write_all(message).await?;
					stream.flush().await?;
					return Ok(());
				}
			};

			let Ok(line) = String::from_utf8(line) else {
				stream.write_all(b"* BAD non-ASCII command\r\n").await?;
				stream.flush().await?;
				continue;
			};

			let mut output = session.command_line(&line);
			loop {
				stream.write_all(&output.bytes).await?;
				stream.flush().await?;
				if output.close {
					return Ok(());
				}
				if let Some(size) = output.collect_literal {
					// Read exactly `size` literal bytes (plus trailing CRLF
					// which the line decoder will consume as an empty line).
					let mut literal = decoder.take_buffered(size);
					let mut chunk = [0u8; 4096];
					while literal.len() < size {
						let read = stream.read(&mut chunk).await?;
						if read == 0 {
							return Ok(());
						}
						let needed = size - literal.len();
						if read <= needed {
							literal.extend_from_slice(&chunk[..read]);
						} else {
							literal.extend_from_slice(&chunk[..needed]);
							decoder.feed(&chunk[needed..read]);
						}
					}
					output = session.literal_done(&literal);
					continue;
				}
				if output.upgrade_tls {
					// Pre-handshake bytes are dropped: nothing buffered in
					// plaintext can leak into the TLS session.
					let tls = self.tls.accept(stream).await?;
					stream = Box::new(tls);
					session.tls_started();
					decoder = LineDecoder::new();
					break;
				}
				if output.idle {
					// Read lines until DONE.
					loop {
						match decoder.next_line() {
							Ok(Some(line)) => {
								if line.eq_ignore_ascii_case(b"DONE") {
									break;
								}
								// Anything else during IDLE is ignored.
							}
							Ok(None) => {
								let read = match tokio::time::timeout(
									READ_TIMEOUT,
									stream.read(&mut buffer),
								)
								.await
								{
									Ok(Ok(n)) => n,
									Ok(Err(e)) => return Err(e),
									Err(_) => {
										tracing::debug!("IMAP idle timeout during IDLE, closing");
										let _ = stream.write_all(b"* BYE idle timeout\r\n").await;
										return Ok(());
									}
								};
								if read == 0 {
									return Ok(());
								}
								decoder.feed(&buffer[..read]);
							}
							Err(_) => return Ok(()),
						}
					}
					output = session.idle_done();
					continue;
				}
				break;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	use tokio_rustls::TlsConnector;
	use tokio_rustls::rustls::pki_types::ServerName;
	use tokio_rustls::rustls::{ClientConfig, RootCertStore};

	fn directory() -> DirectoryHandle {
		DirectoryHandle::new(
			crate::smtp::directory::Directory::new(
				["example.org".to_string()],
				[("alice@example.org".to_string(), "alice".to_string())],
			)
			.with_password_hashes(HashMap::from([(
				"alice".to_string(),
				crate::smtp::auth::tests::hash("secret"),
			)])),
		)
	}

	#[tokio::test]
	async fn starttls_upgrade_then_login() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
		let server = Server::new(
			"mail.example.org",
			dir.path().to_path_buf(),
			directory(),
			acceptor,
			TlsMode::StartTls,
		);

		let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream).await });

		// Plaintext greeting advertises STARTTLS.
		let mut chunk = [0u8; 1024];
		let read = client.read(&mut chunk).await.expect("greeting");
		let greeting = String::from_utf8_lossy(&chunk[..read]).to_string();
		assert!(greeting.contains("STARTTLS"), "{greeting}");

		client
			.write_all(b"a1 STARTTLS\r\n")
			.await
			.expect("starttls");
		let read = client.read(&mut chunk).await.expect("ok");
		assert!(String::from_utf8_lossy(&chunk[..read]).contains("a1 OK"));

		// Handshake over the same stream.
		let mut roots = RootCertStore::empty();
		roots.add(cert).expect("trust cert");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		let connector = TlsConnector::from(Arc::new(config));
		let name = ServerName::try_from("mail.example.org").expect("name");
		let mut tls = connector.connect(name, client).await.expect("handshake");

		tls.write_all(b"a2 LOGIN alice secret\r\n")
			.await
			.expect("login");
		let read = tls.read(&mut chunk).await.expect("response");
		let response = String::from_utf8_lossy(&chunk[..read]).to_string();
		assert!(response.contains("a2 OK"), "{response}");
		tls.write_all(b"a3 LOGOUT\r\n").await.expect("logout");
		let _ = tls.read(&mut chunk).await;
		task.abort();
	}

	#[tokio::test]
	async fn full_read_session_over_tls() {
		let dir = tempfile::tempdir().expect("tempdir");
		let inbox = dir.path().join("accounts/alice/new");
		std::fs::create_dir_all(&inbox).expect("dirs");
		let id = uuid::Uuid::now_v7();
		std::fs::write(
			inbox.join(format!("{id}.eml")),
			b"From: b@x.example\r\nSubject: hi\r\n\r\nhello\r\n",
		)
		.expect("write");

		let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
		let server = Server::new(
			"mail.example.org",
			dir.path().to_path_buf(),
			directory(),
			acceptor,
			TlsMode::Implicit,
		);

		let (client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream).await });

		let mut roots = RootCertStore::empty();
		roots.add(cert).expect("trust cert");
		let config = ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		let connector = TlsConnector::from(Arc::new(config));
		let name = ServerName::try_from("mail.example.org").expect("name");
		let mut tls = connector.connect(name, client).await.expect("handshake");

		async fn read_until(tls: &mut (impl AsyncRead + Unpin), needle: &str) -> String {
			let mut collected = String::new();
			let mut chunk = [0u8; 4096];
			while !collected.contains(needle) {
				let read = tls.read(&mut chunk).await.expect("read");
				assert!(
					read > 0,
					"connection closed waiting for {needle:?}: {collected}"
				);
				collected.push_str(&String::from_utf8_lossy(&chunk[..read]));
			}
			collected
		}

		let greeting = read_until(&mut tls, "IMAP4rev2 ready").await;
		assert!(greeting.starts_with("* OK"), "{greeting}");

		tls.write_all(b"a1 LOGIN alice secret\r\n")
			.await
			.expect("login");
		read_until(&mut tls, "a1 OK").await;

		tls.write_all(b"a2 SELECT INBOX\r\n").await.expect("select");
		let select = read_until(&mut tls, "a2 OK").await;
		assert!(select.contains("* 1 EXISTS"), "{select}");

		tls.write_all(b"a3 FETCH 1 (BODY[])\r\n")
			.await
			.expect("fetch");
		let fetch = read_until(&mut tls, "a3 OK").await;
		assert!(fetch.contains("Subject: hi"), "{fetch}");

		tls.write_all(b"a4 LOGOUT\r\n").await.expect("logout");
		read_until(&mut tls, "a4 OK").await;
		task.abort();
	}
}
