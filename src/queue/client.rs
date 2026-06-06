//! Minimal SMTP client for outbound delivery.
//!
//! Speaks just enough ESMTP to hand a message to a remote server: EHLO,
//! opportunistic STARTTLS, MAIL, RCPT, DATA. Strict about replies; any
//! unexpected code aborts the attempt.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Whether the attempt may be retried later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
	/// 4xx or connection trouble: retry later.
	Transient(String),
	/// 5xx: the remote refused permanently.
	Permanent(String),
}

impl DeliveryError {
	fn from_reply(code: u16, line: &str) -> Self {
		if code >= 500 {
			DeliveryError::Permanent(format!("{code} {line}"))
		} else {
			DeliveryError::Transient(format!("{code} {line}"))
		}
	}
}

/// One outbound delivery attempt over an established stream.
///
/// `server_name` is the MX hostname used for TLS verification when the
/// remote offers STARTTLS. TLS is opportunistic: a remote without STARTTLS
/// still gets the mail (MTA-STS/DANE enforcement comes later).
pub async fn deliver<S>(
	stream: S,
	server_name: &str,
	ehlo_hostname: &str,
	reverse_path: &str,
	recipients: &[String],
	data: &[u8],
	require_tls: bool,
) -> Result<(), DeliveryError>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let mut conn = Conn::new(Box::new(stream));
	conn.expect(220).await?;

	conn.command(&format!("EHLO {ehlo_hostname}"), 250).await?;
	let offers_starttls = conn.last_reply_contains("STARTTLS");
	if require_tls && !offers_starttls {
		// MTA-STS enforce: never downgrade to plaintext; retry later.
		return Err(DeliveryError::Transient(
			"MTA-STS enforce but remote offers no STARTTLS".into(),
		));
	}

	if offers_starttls {
		conn.command("STARTTLS", 220).await?;
		let inner = conn.into_inner();
		let tls = tls_connect(inner, server_name).await?;
		conn = Conn::new(Box::new(tls));
		conn.command(&format!("EHLO {ehlo_hostname}"), 250).await?;
	}

	conn.command(&format!("MAIL FROM:<{reverse_path}>"), 250)
		.await?;
	for recipient in recipients {
		conn.command(&format!("RCPT TO:<{recipient}>"), 250).await?;
	}
	conn.command("DATA", 354).await?;
	conn.send_data(data).await?;
	conn.expect(250).await?;
	let _ = conn.command("QUIT", 221).await;
	Ok(())
}

async fn tls_connect(
	stream: Box<dyn Stream>,
	server_name: &str,
) -> Result<tokio_rustls::client::TlsStream<Box<dyn Stream>>, DeliveryError> {
	let mut roots = RootCertStore::empty();
	roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	let config = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let name = ServerName::try_from(server_name.to_string())
		.map_err(|_| DeliveryError::Transient(format!("invalid TLS name {server_name}")))?;
	TlsConnector::from(Arc::new(config))
		.connect(name, stream)
		.await
		.map_err(|error| DeliveryError::Transient(format!("TLS handshake failed: {error}")))
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Buffered SMTP conversation state.
struct Conn {
	stream: Box<dyn Stream>,
	buffer: Vec<u8>,
	last_reply: String,
}

impl Conn {
	fn new(stream: Box<dyn Stream>) -> Self {
		Conn {
			stream,
			buffer: Vec::new(),
			last_reply: String::new(),
		}
	}

	fn into_inner(self) -> Box<dyn Stream> {
		self.stream
	}

	fn last_reply_contains(&self, needle: &str) -> bool {
		self.last_reply.contains(needle)
	}

	async fn command(&mut self, line: &str, expected: u16) -> Result<(), DeliveryError> {
		self.stream
			.write_all(format!("{line}\r\n").as_bytes())
			.await
			.map_err(io_transient)?;
		self.stream.flush().await.map_err(io_transient)?;
		self.expect(expected).await
	}

	/// Send message data with dot-stuffing and the final terminator.
	async fn send_data(&mut self, data: &[u8]) -> Result<(), DeliveryError> {
		let mut wire = Vec::with_capacity(data.len() + 16);
		for line in data.split_inclusive(|&b| b == b'\n') {
			if line.first() == Some(&b'.') {
				wire.push(b'.');
			}
			wire.extend_from_slice(line);
		}
		if !wire.ends_with(b"\r\n") {
			wire.extend_from_slice(b"\r\n");
		}
		wire.extend_from_slice(b".\r\n");
		self.stream.write_all(&wire).await.map_err(io_transient)?;
		self.stream.flush().await.map_err(io_transient)
	}

	/// Read one (possibly multiline) reply and require `expected`.
	async fn expect(&mut self, expected: u16) -> Result<(), DeliveryError> {
		let reply = self.read_reply().await?;
		let code: u16 = reply
			.get(..3)
			.and_then(|head| head.parse().ok())
			.ok_or_else(|| DeliveryError::Transient(format!("malformed reply: {reply}")))?;
		self.last_reply = reply;
		if code != expected {
			return Err(DeliveryError::from_reply(code, &self.last_reply));
		}
		Ok(())
	}

	async fn read_reply(&mut self) -> Result<String, DeliveryError> {
		loop {
			if let Some(reply) = complete_reply(&self.buffer) {
				let text = String::from_utf8_lossy(&self.buffer[..reply]).to_string();
				self.buffer.drain(..reply);
				return Ok(text);
			}
			if self.buffer.len() > 64 * 1024 {
				return Err(DeliveryError::Transient("oversized reply".into()));
			}
			let mut chunk = [0u8; 4096];
			let read = self.stream.read(&mut chunk).await.map_err(io_transient)?;
			if read == 0 {
				return Err(DeliveryError::Transient(
					"connection closed mid-reply".into(),
				));
			}
			self.buffer.extend_from_slice(&chunk[..read]);
		}
	}
}

fn io_transient(error: std::io::Error) -> DeliveryError {
	DeliveryError::Transient(error.to_string())
}

/// Length of a complete reply in `buffer` (through the final CRLF of its
/// last line), or `None` if more bytes are needed.
fn complete_reply(buffer: &[u8]) -> Option<usize> {
	let mut offset = 0;
	loop {
		let rest = &buffer[offset..];
		let line_end = rest.windows(2).position(|w| w == b"\r\n")? + 2;
		let line = &rest[..line_end];
		// A line like `250-...` continues; `250 ...` (or bare code) ends.
		let continues = line.len() >= 4 && line[3] == b'-';
		offset += line_end;
		if !continues {
			return Some(offset);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn detects_complete_single_line_reply() {
		assert_eq!(complete_reply(b"250 ok\r\n"), Some(8));
		assert_eq!(complete_reply(b"250 ok"), None);
	}

	#[test]
	fn detects_multiline_reply() {
		let reply = b"250-a\r\n250-b\r\n250 c\r\n";
		assert_eq!(complete_reply(reply), Some(reply.len()));
		assert_eq!(complete_reply(b"250-a\r\n"), None);
	}

	#[tokio::test]
	async fn delivers_to_own_server() {
		use crate::smtp::directory::Directory;
		use crate::smtp::server::Server;
		use crate::smtp::sink::{MemorySink, MessageSink};

		let sink = Arc::new(MemorySink::new());
		let directory = Arc::new(Directory::new(
			["example.org".to_string()],
			[("bob@example.org".to_string(), "bob".to_string())],
		));
		let server = Server::new("mx.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(directory);

		let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });

		deliver(
			client_stream,
			"mx.example.org",
			"mail.sender.example",
			"alice@sender.example",
			&["bob@example.org".to_string()],
			b"Subject: hi\r\n\r\n.leading dot\r\nbody\r\n",
			false,
		)
		.await
		.expect("delivery succeeds");

		task.abort();
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		assert_eq!(messages[0].reverse_path, "alice@sender.example");
		let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
		// Dot-stuffing round-trips.
		assert!(data.ends_with(".leading dot\r\nbody\r\n"), "{data}");
	}

	#[tokio::test]
	async fn permanent_rejection_is_permanent() {
		use crate::smtp::directory::Directory;
		use crate::smtp::server::Server;
		use crate::smtp::sink::{MemorySink, MessageSink};

		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mx.example.org", sink as Arc<dyn MessageSink>)
			.with_directory(Arc::new(Directory::new(["example.org".to_string()], [])));

		let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });

		let result = deliver(
			client_stream,
			"mx.example.org",
			"mail.sender.example",
			"alice@sender.example",
			&["unknown@example.org".to_string()],
			b"body\r\n",
			false,
		)
		.await;

		task.abort();
		assert!(matches!(result, Err(DeliveryError::Permanent(_))));
	}
}
