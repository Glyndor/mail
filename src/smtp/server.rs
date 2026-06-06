//! SMTP network layer: accepts connections and drives sessions.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::directory::Directory;
use super::line::{LineDecoder, LineError};
use super::reply::Reply;
use super::session::{Action, Session};
use super::sink::MessageSink;
use crate::directory_store::DirectoryHandle;

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
	Auth,
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
	directory: DirectoryHandle,
	spf: Option<Arc<dyn crate::spf::DnsLookup>>,
}

impl Server {
	/// Create a plaintext server (STARTTLS unavailable). Without
	/// `with_directory` every recipient is rejected (fail closed).
	pub fn new(hostname: &str, sink: Arc<dyn MessageSink>) -> Self {
		Server {
			hostname: hostname.to_string(),
			sink,
			tls: None,
			tls_mode: TlsMode::Opportunistic,
			directory: DirectoryHandle::new(Directory::default()),
			spf: None,
		}
	}

	/// Enable SPF verification of unauthenticated inbound mail.
	pub fn with_spf(mut self, dns: Arc<dyn crate::spf::DnsLookup>) -> Self {
		self.spf = Some(dns);
		self
	}

	/// Enable TLS with the given acceptor and mode.
	pub fn with_tls(mut self, acceptor: TlsAcceptor, mode: TlsMode) -> Self {
		self.tls = Some(acceptor);
		self.tls_mode = mode;
		self
	}

	/// Set the directory handle used to resolve recipients. Sessions
	/// snapshot it at connection start.
	pub fn with_directory(mut self, directory: DirectoryHandle) -> Self {
		self.directory = directory;
		self
	}

	fn new_session(&self) -> Session {
		Session::new(&self.hostname).with_directory(self.directory.current())
	}

	/// Accept connections forever. Each connection runs in its own task.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		loop {
			let (stream, peer) = listener.accept().await?;
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				tracing::debug!(%peer, "connection accepted");
				if let Err(error) = server.handle(stream, Some(peer.ip())).await {
					tracing::debug!(%peer, %error, "connection ended with error");
				}
			});
		}
	}

	/// Drive one connection from greeting to close. `peer` is the client
	/// address recorded in trace headers; `None` for in-memory tests.
	pub async fn handle<S>(&self, stream: S, peer: Option<IpAddr>) -> std::io::Result<()>
	where
		S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	{
		match (self.tls_mode, &self.tls) {
			(TlsMode::Implicit, Some(acceptor)) => {
				let tls_stream = acceptor.accept(stream).await?;
				let session = self.new_session().with_tls_active();
				self.run(Box::new(tls_stream), session, peer).await
			}
			(TlsMode::Implicit, None) => Err(std::io::Error::other(
				"implicit TLS listener without TLS acceptor",
			)),
			(TlsMode::Opportunistic, Some(_)) => {
				let session = self.new_session().with_tls_available();
				self.run(Box::new(stream), session, peer).await
			}
			(TlsMode::Opportunistic, None) => {
				self.run(Box::new(stream), self.new_session(), peer).await
			}
		}
	}

	/// The protocol loop over an established (plain or TLS) stream.
	async fn run(
		&self,
		mut stream: Box<dyn Connection>,
		mut session: Session,
		peer: Option<IpAddr>,
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
				// Argon2 verification is CPU-bound; acceptable inline while
				// per-connection rate limiting keeps attempts scarce.
				Mode::Auth => Some(session.auth_line(&line)),
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
				Action::CollectAuthResponse(reply) => {
					mode = Mode::Auth;
					send(&mut stream, &reply).await?;
				}
				Action::Deliver(reply, mut message) => {
					// SPF and DKIM apply to unauthenticated mail from a
					// known peer.
					let mut auth_headers = String::new();
					if let (Some(dns), Some(ip), None) = (&self.spf, peer, session.authenticated())
					{
						let domain = spf_domain(&message.reverse_path, session.helo_domain());
						let outcome = match &domain {
							Some(domain) => crate::spf::check_host(dns.as_ref(), ip, domain).await,
							None => crate::spf::SpfOutcome::None,
						};
						match outcome {
							crate::spf::SpfOutcome::Fail => {
								send(
									&mut stream,
									&Reply::single(550, "5.7.23 SPF validation failed"),
								)
								.await?;
								continue;
							}
							crate::spf::SpfOutcome::TempError => {
								send(
									&mut stream,
									&Reply::single(451, "4.4.3 SPF check temporarily failed"),
								)
								.await?;
								continue;
							}
							outcome => {
								auth_headers.push_str(&format!(
									"Received-SPF: {} (domain of {}) client-ip={ip}\r\n",
									outcome.as_str(),
									domain.as_deref().unwrap_or("unknown"),
								));

								// DKIM is recorded; DMARC decides policy.
								let dkim_results =
									crate::dkim::verify_message(dns.as_ref(), &message.data).await;

								let from = crate::dmarc::from_domain(&message.data);
								let dmarc = match &from {
									Some(from) => {
										crate::dmarc::evaluate(
											dns.as_ref(),
											from,
											(outcome, domain.as_deref()),
											&dkim_results,
										)
										.await
									}
									// No usable From header: nothing to align.
									None => crate::dmarc::DmarcOutcome::PermError,
								};
								match dmarc {
									crate::dmarc::DmarcOutcome::Reject => {
										send(
											&mut stream,
											&Reply::single(550, "5.7.1 rejected by DMARC policy"),
										)
										.await?;
										continue;
									}
									crate::dmarc::DmarcOutcome::TempError => {
										send(
											&mut stream,
											&Reply::single(
												451,
												"4.4.3 DMARC check temporarily failed",
											),
										)
										.await?;
										continue;
									}
									_ => {}
								}

								let mut results = format!(
									"Authentication-Results: {}; spf={}",
									self.hostname,
									outcome.as_str()
								);
								if let Some(domain) = &domain {
									results.push_str(&format!(" smtp.mailfrom={domain}"));
								}
								for dkim in &dkim_results {
									results.push_str(&format!("; dkim={}", dkim.outcome.as_str()));
									if let Some(d) = &dkim.domain {
										results.push_str(&format!(" header.d={d}"));
									}
								}
								results.push_str(&format!("; dmarc={}", dmarc.as_str()));
								if let Some(from) = &from {
									results.push_str(&format!(" header.from={from}"));
								}
								results.push_str("\r\n");
								auth_headers.push_str(&results);
							}
						}
					}
					let header = received_header(
						session.helo_domain(),
						peer,
						&self.hostname,
						session.tls_active(),
						std::time::SystemTime::now(),
					);
					let mut stamped = header.into_bytes();
					stamped.extend_from_slice(auth_headers.as_bytes());
					stamped.append(&mut message.data);
					message.data = stamped;
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

/// The domain SPF evaluates: the MAIL FROM domain, or the HELO domain for
/// the null reverse-path (RFC 7208 section 2.4).
fn spf_domain(reverse_path: &str, helo: Option<&str>) -> Option<String> {
	if reverse_path.is_empty() {
		return helo.map(|h| h.to_string());
	}
	reverse_path
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_ascii_lowercase())
}

/// Build the RFC 5321 section 4.4 trace header prepended to accepted mail.
fn received_header(
	helo: Option<&str>,
	peer: Option<IpAddr>,
	hostname: &str,
	tls: bool,
	now: std::time::SystemTime,
) -> String {
	let client = helo.unwrap_or("unknown");
	let peer = match peer {
		Some(ip) => format!("[{ip}]"),
		None => "[unknown]".to_string(),
	};
	let protocol = if tls { "ESMTPS" } else { "ESMTP" };
	format!(
		"Received: from {client} ({peer})\r\n\tby {hostname} with {protocol};\r\n\t{}\r\n",
		crate::clock::rfc5322(now)
	)
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

	fn test_directory() -> DirectoryHandle {
		DirectoryHandle::new(Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
				("b@example.org".to_string(), "bob".to_string()),
			],
		))
	}

	/// Run one scripted client conversation, returning the full server output.
	async fn converse(input: &[u8]) -> (String, Arc<MemorySink>) {
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory());

		let (client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });

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
		let data = String::from_utf8(messages[0].data.clone()).expect("ascii message");
		assert!(
			data.starts_with("Received: from client.example.org ([unknown])\r\n"),
			"{data}"
		);
		assert!(data.contains("with ESMTP;"), "{data}");
		assert!(data.ends_with("Subject: hi\r\n\r\nhello\r\n"), "{data}");
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

	/// DNS stub serving one SPF TXT record for `sender.example`.
	struct OneRecordDns {
		record: &'static str,
	}

	type DnsFuture<'a, T> =
		std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

	impl crate::spf::DnsLookup for OneRecordDns {
		fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
			let result = if name == "sender.example" {
				vec![self.record.to_string()]
			} else {
				Vec::new()
			};
			Box::pin(async move { Ok(result) })
		}

		fn addresses(&self, _name: &str) -> DnsFuture<'_, Vec<std::net::IpAddr>> {
			Box::pin(async { Ok(Vec::new()) })
		}

		fn mx(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	async fn converse_with_spf(record: &'static str) -> (String, Arc<MemorySink>) {
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
			.with_directory(test_directory())
			.with_spf(Arc::new(OneRecordDns { record }));

		let (client, server_stream) = tokio::io::duplex(64 * 1024);
		let peer = Some("192.0.2.7".parse().expect("ip"));
		let task = tokio::spawn(async move { server.handle(server_stream, peer).await });

		let script = b"EHLO client.example.org\r\n\
MAIL FROM:<eve@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
		let (mut client_read, mut client_write) = tokio::io::split(client);
		client_write.write_all(script).await.expect("client write");
		client_write.shutdown().await.expect("client shutdown");
		let mut output = Vec::new();
		client_read
			.read_to_end(&mut output)
			.await
			.expect("client read");
		task.await.expect("task").expect("server result");
		(String::from_utf8(output).expect("ascii"), sink)
	}

	#[tokio::test]
	async fn spf_fail_rejects_the_message() {
		let (output, sink) = converse_with_spf("v=spf1 -all").await;
		assert!(output.contains("550 5.7.23"), "{output}");
		assert!(sink.messages().is_empty());
	}

	#[tokio::test]
	async fn spf_pass_stamps_received_spf_header() {
		let (output, sink) = converse_with_spf("v=spf1 ip4:192.0.2.0/24 -all").await;
		assert!(!output.contains("550"), "{output}");
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
		assert!(
			data.contains("Received-SPF: pass (domain of sender.example) client-ip=192.0.2.7"),
			"{data}"
		);
	}

	#[tokio::test]
	async fn unsigned_message_records_dkim_none() {
		let (_, sink) = converse_with_spf("v=spf1 ip4:192.0.2.0/24 -all").await;
		let data = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
		assert!(
			data.contains(
				"Authentication-Results: mail.example.org; spf=pass smtp.mailfrom=sender.example; dkim=none"
			),
			"{data}"
		);
	}

	#[tokio::test]
	async fn spf_softfail_is_accepted_and_recorded() {
		let (output, sink) = converse_with_spf("v=spf1 ~all").await;
		assert!(!output.contains("550"), "{output}");
		let data = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
		assert!(data.contains("Received-SPF: softfail"), "{data}");
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
			.with_directory(test_directory())
			.with_tls(acceptor, TlsMode::Opportunistic);

		let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });

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
		let data = String::from_utf8(messages[0].data.clone()).expect("ascii message");
		// The trace header records the TLS protocol.
		assert!(data.starts_with("Received: from c.example.org"), "{data}");
		assert!(data.contains("with ESMTPS;"), "{data}");
		assert!(data.ends_with("secret\r\n"), "{data}");
	}

	#[tokio::test]
	async fn implicit_tls_serves_inside_handshake() {
		let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
		let sink = Arc::new(MemorySink::new());
		let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
			.with_tls(acceptor, TlsMode::Implicit);

		let (client, server_stream) = tokio::io::duplex(64 * 1024);
		let task = tokio::spawn(async move { server.handle(server_stream, None).await });

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
			directory: DirectoryHandle::new(Directory::default()),
			spf: None,
		};
		let (_client, server_stream) = tokio::io::duplex(1024);
		assert!(server.handle(server_stream, None).await.is_err());
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
