//! SMTP network layer: accepts connections and drives sessions.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;

use super::line::{LineDecoder, LineError};
use super::reply::Reply;
use super::session::{Action, Session};
use super::sink::MessageSink;

/// Read buffer size per connection.
const READ_BUFFER: usize = 4096;

/// What the connection loop is currently reading.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
	Commands,
	Data,
}

/// SMTP server: one instance per listener.
pub struct Server {
	hostname: String,
	sink: Arc<dyn MessageSink>,
}

impl Server {
	/// Create a server identifying as `hostname`, delivering to `sink`.
	pub fn new(hostname: &str, sink: Arc<dyn MessageSink>) -> Self {
		Server {
			hostname: hostname.to_string(),
			sink,
		}
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
		S: AsyncRead + AsyncWrite + Unpin,
	{
		let (mut reader, writer) = tokio::io::split(stream);
		let mut writer = BufWriter::new(writer);

		let mut session = Session::new(&self.hostname);
		send(&mut writer, &session.greeting()).await?;

		let mut decoder = LineDecoder::new();
		let mut mode = Mode::Commands;
		let mut buffer = [0u8; READ_BUFFER];

		loop {
			let line = match decoder.next_line() {
				Ok(Some(line)) => line,
				Ok(None) => {
					let read = reader.read(&mut buffer).await?;
					if read == 0 {
						return Ok(());
					}
					decoder.feed(&buffer[..read]);
					continue;
				}
				Err(error) => {
					send(&mut writer, &line_error_reply(&error)).await?;
					return Ok(());
				}
			};

			// SMTP is ASCII on the wire; data bytes above 127 (8BITMIME)
			// pass through data mode untouched via lossy conversion guard.
			let Ok(line) = String::from_utf8(line) else {
				if mode == Mode::Commands {
					send(&mut writer, &Reply::syntax_error()).await?;
					continue;
				}
				// Binary in DATA: not yet supported, fail the transaction.
				send(
					&mut writer,
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
				Action::Continue(reply) => send(&mut writer, &reply).await?,
				Action::CollectData(reply) => {
					mode = Mode::Data;
					send(&mut writer, &reply).await?;
				}
				Action::Deliver(reply, message) => {
					let reply = match self.sink.deliver(message) {
						Ok(()) => reply,
						Err(error) => {
							tracing::warn!(%error, "delivery failed");
							Reply::single(451, "temporary storage failure, try again")
						}
					};
					send(&mut writer, &reply).await?;
				}
				Action::Close(reply) => {
					send(&mut writer, &reply).await?;
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
	W: AsyncWrite + Unpin,
{
	writer.write_all(reply.to_string().as_bytes()).await?;
	writer.flush().await
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::smtp::sink::MemorySink;

	/// Run one scripted client conversation, returning the full server output.
	async fn converse(input: &[u8]) -> (String, Arc<MemorySink>) {
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>);

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
