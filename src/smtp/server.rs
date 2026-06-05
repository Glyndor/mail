//! SMTP network layer: accepts connections and drives sessions.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::line::{LineDecoder, LineError};
use super::reply::Reply;
use super::session::{Action, Session};
use super::sink::MessageSink;

/// Read buffer size per connection.
const READ_BUFFER: usize = 4096;

/// Anything the connection loop can read from and write to.
trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

/// What the connection loop is currently reading.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
	Commands,
	Data,
}

/// How a listener treats TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
	/// Plaintext; STARTTLS offered when an acceptor is configured.
	Opportunistic,
	/// TLS handshake before any SMTP traffic (`submissions`).
	Implicit,
}

/// SMTP server: one instance per listener.
pub struct Server {
	hostname: String,
	sink: Arc<dyn MessageSink>,
	tls: Option<TlsAcceptor>,
	tls_mode: TlsMode,
	local_domains: Arc<std::collections::HashSet<String>>,
}

impl Server {
	/// Create a plaintext server (STARTTLS unavailable). Without
	/// `with_local_domains` every recipient is rejected (fail closed).
	pub fn new(hostname: &str, sink: Arc<dyn MessageSink>) -> Self {
		Server {
			hostname: hostname.to_string(),
			sink,
			tls: None,
			tls_mode: TlsMode::Opportunistic,
			local_domains: Arc::new(std::collections::HashSet::new()),
		}
	}

	/// Enable TLS with the given acceptor and mode.
	pub fn with_tls(mut self, acceptor: TlsAcceptor, mode: TlsMode) -> Self {
		self.tls = Some(acceptor);
		self.tls_mode = mode;
		self
	}

	/// Set the domains this server accepts mail for (lowercased).
	pub fn with_local_domains(mut self, domains: Arc<std::collections::HashSet<String>>) -> Self {
		self.local_domains = domains;
		self
	}

	fn new_session(&self) -> Session {
		Session::new(&self.hostname).with_local_domains(Arc::clone(&self.local_domains))
	}

	/// Accept connections forever. Each connection runs in its own task.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		loop {
			let (stream, peer) = listener.accept().await?;
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				tracing::debug!(%peer, "connection accepted");
				if let Err(error) = server.handle(stream).await {
					tracing::debug!(%peer, %error, "connection ended with error");
				}
			});
		}
	}

	/// Drive one connection from greeting to close.
	pub async fn handle<S>(&self, stream: S) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		match (self.tls_mode, &self.tls) {
			(TlsMode::Implicit, Some(acceptor)) => {
				let tls_stream = acceptor.accept(stream).await?;
				self.run(Box::new(tls_stream), self.new_session()).await
			}
			(TlsMode::Implicit, None) => Err(std::io::Error::other(
				"implicit TLS listener without TLS acceptor",
			)),
			(TlsMode::Opportunistic, Some(_)) => {
				let session = self.new_session().with_tls_available();
				self.run(Box::new(stream), session).await
			}
			(TlsMode::Opportunistic, None) => self.run(Box::new(stream), self.new_session()).await,
		}
	}

	/// The protocol loop over an established (plain or TLS) stream.
	async fn run(
		&self,
		mut stream: Box<dyn Connection>,
		mut session: Session,
	) -> std::io::Result<()> {
		send(&mut stream, &session.greeting()).await?;

		let mut decoder = LineDecoder::new();
		let mut mode = Mode::Commands;
		let mut buffer = [0u8; READ_BUFFER];

		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					let read = stream.read(&mut buffer).await?;
					if read == 0 {
						return Ok(());
					}
					decoder.feed(&buffer[..read]);
					continue;
				}
				Err(error) => {
					send(&mut stream, &line_error_reply(&error)).await?;
					return Ok(());
				}
			};

			let Ok(line) = String::from_utf8(line) else {
				if mode == Mode::Commands {
					send(&mut stream, &Reply::syntax_error()).await?;
					continue;
				}
				// Binary in DATA: not yet supported, fail the transaction.
				send(
					&mut stream,
					&Reply::single(554, "8-bit data not yet supported"),
				)
				.await?;
				return Ok(());
			};

			let action = match mode {
				Mode::Commands => Some(session.command_line(&line)),
				Mode::Data => session.data_line(&line),
			};
			let Some(action) = action else {
				continue;
			};

			mode = Mode::Commands;
			match action {
				Action::Continue(reply) => send(&mut stream, &reply).await?,
				Action::CollectData(reply) => {
					mode = Mode::Data;
					send(&mut stream, &reply).await?;
				}
				Action::Deliver(reply, message) => {
					let reply = match self.sink.deliver(message) {
						Ok(()) => reply,
						Err(error) => {
							tracing::warn!(%error, "delivery failed");
							Reply::single(451, "temporary storage failure, try again")
						}
					};
					send(&mut stream, &reply).await?;
				}
				Action::UpgradeTls(reply) => {
					let Some(acceptor) = &self.tls else {
						// The session only emits UpgradeTls when TLS was
						// offered; reaching this is a programming error.
						send(&mut stream, &Reply::single(454, "TLS not available")).await?;
						return Ok(());
					};
					send(&mut stream, &reply).await?;
					// Bytes received before the handshake are discarded:
					// a pipelining client cannot smuggle plaintext commands
					// into the TLS session.
					let tls_stream = acceptor.accept(stream).await?;
					stream = Box::new(tls_stream);
					session.tls_started();
					decoder = LineDecoder::new();
					send(&mut stream, &session.greeting()).await?;
				}
				Action::Close(reply) => {
					send(&mut stream, &reply).await?;
					return Ok(());
				}
			}
		}
	}
}

fn line_error_reply(error: &LineError) -> Reply {
	match error {
		LineError::BareControlCharacter => {
			Reply::single(554, "bare CR or LF is not allowed, closing connection")
		}
		LineError::TooLong => Reply::single(500, "line too long, closing connection"),
		LineError::NulByte => Reply::single(554, "NUL byte received, closing connection"),
	}
}

async fn send<W>(writer: &mut W, reply: &Reply) -> std::io::Result<()>
where
	W: AsyncWrite + Unpin + ?Sized,
{
	writer.write_all(reply.to_string().as_bytes()).await?;
	writer.flush().await
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::smtp::sink::MemorySink;

	fn test_domains() -> Arc<std::collections::HashSet<String>> {
		Arc::new(std::collections::HashSet::from(["example.org".to_string()]))
	}

	/// Run one scripted client conversation, returning the full server output.
	async fn converse(input: &[u8]) -> (String, Arc<MemorySink>) {
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_local_domains(test_domains());

		let (client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream).await });

		let (mut client_read, mut client_write) = tokio::io::split(client);
		client_write.write_all(input).await.expect("client write");
		client_write.shutdown().await.expect("client shutdown");

		let mut output = Vec::new();
		client_read
			.read_to_end(&mut output)
			.await
			.expect("client read");
		task.await.expect("server task").expect("server result");
		(String::from_utf8(output).expect("ascii output"), sink)
	}

	#[tokio::test]
	async fn greets_on_connect() {
		let (output, _) = converse(b"").await;
		assert!(output.starts_with("220 mail.example.org ESMTP ready\r\n"));
	}

	#[tokio::test]
	async fn full_transaction_is_stored() {
		let script = b"EHLO client.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
		let (output, sink) = converse(script).await;
		assert!(
			output.contains("250-mail.example.org"),
			"EHLO reply: {output}"
		);
		assert!(output.contains("354 "), "DATA go-ahead: {output}");
		assert!(output.ends_with("221 closing connection\r\n"), "{output}");

		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		assert_eq!(messages[0].reverse_path, "alice@example.org");
		assert_eq!(messages[0].data, b"Subject: hi\r\n\r\nhello\r\n");
	}

	#[tokio::test]
	async fn bare_lf_closes_connection() {
		let (output, sink) = converse(b"EHLO x.example\nMAIL FROM:<a@b.example>\r\n").await;
		assert!(output.contains("554 bare CR or LF"), "{output}");
		assert!(sink.messages().is_empty());
	}

	#[tokio::test]
	async fn bare_cr_closes_connection() {
		let (output, _) = converse(b"EHLO x\rexample\r\n").await;
		assert!(output.contains("554 bare CR or LF"), "{output}");
	}

	#[tokio::test]
	async fn nul_byte_closes_connection() {
		let (output, _) = converse(b"EHLO x\0.example\r\n").await;
		assert!(output.contains("554 NUL byte"), "{output}");
	}

	#[tokio::test]
	async fn overlong_line_closes_connection() {
		let mut script = vec![b'x'; 2000];
		script.extend_from_slice(b"\r\n");
		let (output, _) = converse(&script).await;
		assert!(output.contains("500 line too long"), "{output}");
	}

	#[tokio::test]
	async fn out_of_order_commands_are_rejected() {
		let (output, sink) = converse(b"MAIL FROM:<a@example.org>\r\nQUIT\r\n").await;
		assert!(output.contains("503 bad sequence"), "{output}");
		assert!(sink.messages().is_empty());
	}

	#[tokio::test]
	async fn non_utf8_command_gets_syntax_error() {
		let (output, _) = converse(b"EHLO caf\xC3\xA9.example\r\nQUIT\r\n").await;
		// Non-ASCII is rejected by the command parser after UTF-8 decoding.
		assert!(output.contains("500 syntax error"), "{output}");
	}

	#[tokio::test]
	async fn invalid_utf8_in_data_fails_transaction() {
		let script = b"EHLO client.example.org\r\n\
MAIL FROM:<a@example.org>\r\n\
RCPT TO:<b@example.org>\r\n\
DATA\r\n\
\xFF\xFE binary\r\n";
		let (output, sink) = converse(script).await;
		assert!(output.contains("554 8-bit data"), "{output}");
		assert!(sink.messages().is_empty());
	}

	#[tokio::test]
	async fn starttls_not_offered_without_acceptor() {
		let (output, _) = converse(b"EHLO client.example.org\r\nSTARTTLS\r\nQUIT\r\n").await;
		assert!(!output.contains("250-STARTTLS"), "{output}");
		assert!(output.contains("454 TLS not available"), "{output}");
	}

	/// Test client TLS connector trusting the given certificate.
	fn test_connector(
		cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
	) -> tokio_rustls::TlsConnector {
		let mut roots = tokio_rustls::rustls::RootCertStore::empty();
		roots.add(cert).expect("trust test certificate");
		let config = tokio_rustls::rustls::ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth();
		tokio_rustls::TlsConnector::from(Arc::new(config))
	}

	async fn read_reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
		let mut buffer = [0u8; 1024];
		let read = reader.read(&mut buffer).await.expect("read reply");
		String::from_utf8_lossy(&buffer[..read]).to_string()
	}

	#[tokio::test]
	async fn starttls_upgrade_and_transaction() {
		let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_local_domains(test_domains())
			.with_tls(acceptor, TlsMode::Opportunistic);

		let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream).await });

		assert!(read_reply(&mut client).await.starts_with("220 "));
		client
			.write_all(b"EHLO c.example.org\r\n")
			.await
			.expect("ehlo");
		let ehlo = read_reply(&mut client).await;
		assert!(ehlo.contains("250 STARTTLS"), "{ehlo}");

		client.write_all(b"STARTTLS\r\n").await.expect("starttls");
		assert!(read_reply(&mut client).await.starts_with("220 "));

		// TLS handshake over the same stream.
		let connector = test_connector(cert);
		let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org")
			.expect("server name");
		let mut tls_client = connector
			.connect(server_name, client)
			.await
			.expect("tls handshake");

		// Fresh greeting inside TLS; the session forgot the plaintext EHLO.
		assert!(read_reply(&mut tls_client).await.starts_with("220 "));
		tls_client
			.write_all(b"EHLO c.example.org\r\n")
			.await
			.expect("tls ehlo");
		let tls_ehlo = read_reply(&mut tls_client).await;
		// STARTTLS must not be offered again inside TLS.
		assert!(!tls_ehlo.contains("STARTTLS"), "{tls_ehlo}");

		tls_client
			.write_all(b"MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n")
			.await
			.expect("transaction");
		let mut got = String::new();
		while !got.contains("354 ") {
			got.push_str(&read_reply(&mut tls_client).await);
		}
		tls_client
			.write_all(b"secret\r\n.\r\nQUIT\r\n")
			.await
			.expect("data");
		let mut tail = String::new();
		while !tail.contains("221 ") {
			tail.push_str(&read_reply(&mut tls_client).await);
		}

		drop(tls_client);
		task.abort();
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		assert_eq!(messages[0].data, b"secret\r\n");
	}

	#[tokio::test]
	async fn implicit_tls_serves_inside_handshake() {
		let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_tls(acceptor, TlsMode::Implicit);

		let (client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream).await });

		let connector = test_connector(cert);
		let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org")
			.expect("server name");
		let mut tls_client = connector
			.connect(server_name, client)
			.await
			.expect("tls handshake");

		assert!(read_reply(&mut tls_client).await.starts_with("220 "));
		tls_client.write_all(b"QUIT\r\n").await.expect("quit");
		assert!(read_reply(&mut tls_client).await.contains("221 "));
		task.abort();
	}

	#[tokio::test]
	async fn implicit_tls_without_acceptor_errors() {
		let sink = Arc::new(MemorySink::new());
		let server = Server {
			hostname: "mail.example.org".to_string(),
			sink: sink as Arc<dyn MessageSink>,
			tls: None,
			tls_mode: TlsMode::Implicit,
			local_domains: Arc::new(std::collections::HashSet::new()),
		};
		let (_client, server_stream) = tokio::io::duplex(1024);
		assert!(server.handle(server_stream).await.is_err());
	}

	#[tokio::test]
	async fn serve_accepts_tcp_connections() {
		let sink = Arc::new(MemorySink::new());
		let server = Arc::new(Server::new(
			"mail.example.org",
			sink as Arc<dyn MessageSink>,
		));
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let addr = listener.local_addr().expect("local addr");
		let task = tokio::spawn(server.serve(listener));

		let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
		let mut greeting = [0u8; 64];
		let read = client.read(&mut greeting).await.expect("read greeting");
		assert!(String::from_utf8_lossy(&greeting[..read]).starts_with("220 "));

		client.write_all(b"QUIT\r\n").await.expect("write quit");
		let mut rest = Vec::new();
		client.read_to_end(&mut rest).await.expect("read close");
		assert!(String::from_utf8_lossy(&rest).contains("221 "));
		task.abort();
	}
}
