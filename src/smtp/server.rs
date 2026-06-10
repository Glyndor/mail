//! SMTP network layer: accepts connections and drives sessions.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::directory::Directory;
use super::line::{LineDecoder, LineError};
use super::reply::Reply;
use super::session::{Action, Session};
use super::sink::MessageSink;
use crate::directory_store::DirectoryHandle;

/// Read buffer size per connection.
const READ_BUFFER: usize = 4096;

/// Maximum concurrent connections per listener. Excess connections are dropped
/// immediately (TCP RST) to prevent file-descriptor exhaustion.
const MAX_CONNECTIONS: usize = 1000;

/// Per-read idle timeout. RFC 5321 §4.5.3.2 mandates at least 5 minutes between
/// command-phase reads; we match that minimum to kill Slowloris connections.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

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
	/// If set, DMARC delivery records are written here for aggregate reports.
	report_dir: Option<std::path::PathBuf>,
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
			report_dir: None,
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

	/// Enable DMARC aggregate report storage. Delivery records are written
	/// under `data_dir/dmarc-reports/` for later flushing and sending.
	pub fn with_report_dir(mut self, data_dir: std::path::PathBuf) -> Self {
		self.report_dir = Some(data_dir);
		self
	}

	fn new_session(&self) -> Session {
		Session::new(&self.hostname).with_directory(self.directory.current())
	}

	/// Accept connections forever. Each connection runs in its own task.
	pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
		let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
		loop {
			let (stream, peer) = listener.accept().await?;
			let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
				tracing::warn!(%peer, "SMTP connection limit reached, dropping");
				continue;
			};
			let server = Arc::clone(&self);
			tokio::spawn(async move {
				let _permit = permit;
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
					let read = match tokio::time::timeout(COMMAND_TIMEOUT, stream.read(&mut buffer))
						.await
					{
						Ok(Ok(n)) => n,
						Ok(Err(e)) => return Err(e),
						Err(_) => {
							tracing::debug!("SMTP command timeout, closing connection");
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
					send(&mut stream, &line_error_reply(&error)).await?;
					return Ok(());
				}
			};

			// In Data mode, pass raw bytes to support 8BITMIME (RFC 6152).
			let action = if mode == Mode::Data {
				session.data_line(&line)
			} else {
				let Ok(line_str) = String::from_utf8(line) else {
					if mode == Mode::Commands {
						send(&mut stream, &Reply::syntax_error()).await?;
						continue;
					}
					// Auth responses must be ASCII; abort.
					send(
						&mut stream,
						&Reply::single(501, "non-ASCII in AUTH response"),
					)
					.await?;
					return Ok(());
				};
				match mode {
					Mode::Commands => Some(session.command_line(&line_str)),
					// Argon2 is CPU-bound; per-connection rate limiting keeps attempts scarce.
					Mode::Auth => Some(session.auth_line(&line_str)),
					Mode::Data => unreachable!(),
				}
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
							Some(domain) => {
								let helo = session.helo_domain().unwrap_or("");
								crate::spf::check_host(
									dns.as_ref(),
									ip,
									domain,
									&message.reverse_path,
									helo,
								)
								.await
							}
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
								// Record DMARC result for aggregate reporting.
								if let (Some(report_data_dir), Some(from_domain)) =
									(&self.report_dir, &from)
								{
									let disposition = match &dmarc {
										crate::dmarc::DmarcOutcome::Reject => "reject",
										_ => "none",
									};
									let ts = std::time::SystemTime::now()
										.duration_since(std::time::UNIX_EPOCH)
										.map(|d| d.as_secs())
										.unwrap_or(0);
									let best_dkim = dkim_results.first();
									let record = crate::dmarc::report::DeliveryRecord {
										timestamp: ts,
										source_ip: peer.map(|p| p.to_string()).unwrap_or_default(),
										envelope_from: domain.as_deref().unwrap_or("").to_owned(),
										header_from: from_domain.clone(),
										spf: outcome.as_str().to_owned(),
										dkim: best_dkim
											.map(|r| r.outcome.as_str())
											.unwrap_or("none")
											.to_owned(),
										dkim_domain: best_dkim
											.and_then(|r| r.domain.clone())
											.unwrap_or_default(),
										dmarc: dmarc.as_str().to_owned(),
										disposition: disposition.to_owned(),
										policy_domain: from_domain.clone(),
										published_policy: String::new(),
										pct: 100,
									};
									let today =
										crate::dmarc::aggregate::unix_to_day(record.timestamp);
									crate::dmarc::aggregate::record_delivery(
										report_data_dir,
										&today,
										&record,
									);
								}

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

								let mut methods: Vec<String> = Vec::new();

								let mut spf_result = format!("spf={}", outcome.as_str());
								if let Some(domain) = &domain {
									spf_result.push_str(&format!(" smtp.mailfrom={domain}"));
								}
								methods.push(spf_result);

								if dkim_results.is_empty() {
									methods.push("dkim=none".to_string());
								} else {
									for dkim in &dkim_results {
										let mut entry = format!("dkim={}", dkim.outcome.as_str());
										if let Some(d) = &dkim.domain {
											entry.push_str(&format!(" header.d={d}"));
										}
										methods.push(entry);
									}
								}

								let mut dmarc_result = format!("dmarc={}", dmarc.as_str());
								if let Some(from) = &from {
									dmarc_result.push_str(&format!(" header.from={from}"));
								}
								methods.push(dmarc_result);

								auth_headers
									.push_str(&format_auth_results(&self.hostname, &methods));
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

/// Build a folded `Authentication-Results` header (RFC 8601 §2.2).
/// Each method result is placed on a separate folded continuation line.
fn format_auth_results(hostname: &str, methods: &[String]) -> String {
	let mut out = format!("Authentication-Results: {hostname}");
	for method in methods {
		out.push_str(";\r\n\t");
		out.push_str(method);
	}
	out.push_str("\r\n");
	out
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
#[path = "server_tests.rs"]
mod tests;
