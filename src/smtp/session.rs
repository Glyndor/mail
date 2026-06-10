//! Per-connection SMTP session state machine.
//!
//! The session is sans-IO: it consumes parsed commands and data lines and
//! produces replies plus completed messages. The network layer owns sockets
//! and feeds this machine, which keeps the protocol logic fully unit-testable.

use std::sync::Arc;

use super::address::Address;
use super::command::{Command, ParseError};
use super::directory::{Directory, Resolution};
use super::reply::Reply;

/// Maximum accepted message size in bytes until quotas exist.
pub const MAX_MESSAGE_SIZE: usize = 25 * 1024 * 1024;

/// Maximum number of accepted recipients per transaction (RFC 5321 minimum).
pub const MAX_RECIPIENTS: usize = 100;

/// Where the session is in the SMTP dialogue.
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
	/// Connection open, no HELO/EHLO yet.
	Connected,
	/// Greeted; ready for a mail transaction.
	Greeted,
	/// MAIL FROM accepted; collecting recipients.
	ReceivingRecipients { reverse_path: String },
	/// DATA accepted; collecting message lines.
	ReceivingData {
		reverse_path: String,
		recipients: Vec<String>,
		size: usize,
		body: Vec<u8>,
	},
}

/// A message accepted by the session, ready for delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedMessage {
	pub reverse_path: String,
	pub recipients: Vec<String>,
	pub data: Vec<u8>,
}

/// What the network layer must do after a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// Send the reply and keep reading commands.
	Continue(Reply),
	/// Send the reply and switch to reading data lines.
	CollectData(Reply),
	/// Send the reply, hand the message to delivery, keep reading commands.
	Deliver(Reply, AcceptedMessage),
	/// Send the reply, then upgrade the connection to TLS (RFC 3207).
	UpgradeTls(Reply),
	/// Send the 334 challenge and read one authentication response line.
	CollectAuthResponse(Reply),
	/// Send the reply and close the connection.
	Close(Reply),
}

/// SMTP session state machine.
#[derive(Debug)]
pub struct Session {
	hostname: String,
	state: State,
	/// Whether STARTTLS can be offered (TLS configured, not yet active).
	tls_available: bool,
	/// Whether the connection is already inside TLS.
	tls_active: bool,
	/// Account name once AUTH succeeded.
	authenticated: Option<String>,
	/// Failed authentication attempts on this connection.
	auth_failures: u8,
	/// The domain the client announced in HELO/EHLO, for trace headers.
	helo_domain: Option<String>,
	/// Recipient resolution. An empty directory rejects every recipient
	/// (fail closed).
	directory: Arc<Directory>,
}

impl Session {
	/// Create a session for a freshly accepted plaintext connection.
	pub fn new(hostname: &str) -> Self {
		Session {
			hostname: hostname.to_string(),
			state: State::Connected,
			tls_available: false,
			tls_active: false,
			authenticated: None,
			auth_failures: 0,
			helo_domain: None,
			directory: Arc::new(Directory::default()),
		}
	}

	/// The authenticated account, if AUTH succeeded.
	pub fn authenticated(&self) -> Option<&str> {
		self.authenticated.as_deref()
	}

	/// Mark this session as running inside TLS from the start
	/// (implicit-TLS listeners).
	pub fn with_tls_active(mut self) -> Self {
		self.tls_active = true;
		self
	}

	/// The domain announced by the client in HELO/EHLO.
	pub fn helo_domain(&self) -> Option<&str> {
		self.helo_domain.as_deref()
	}

	/// Whether the connection is inside TLS.
	pub fn tls_active(&self) -> bool {
		self.tls_active
	}

	/// Set the directory used to resolve recipients.
	pub fn with_directory(mut self, directory: Arc<Directory>) -> Self {
		self.directory = directory;
		self
	}

	/// Offer STARTTLS on this session.
	pub fn with_tls_available(mut self) -> Self {
		self.tls_available = true;
		self
	}

	/// Called by the network layer once the TLS handshake completed.
	/// Per RFC 3207 the server forgets everything learned before the
	/// upgrade; the client must greet again.
	pub fn tls_started(&mut self) {
		self.state = State::Connected;
		self.tls_available = false;
		self.tls_active = true;
		self.helo_domain = None;
	}

	/// The greeting sent when the connection opens.
	pub fn greeting(&self) -> Reply {
		Reply::single(220, &format!("{} ESMTP ready", self.hostname))
	}

	/// Feed one command line (CRLF already stripped and enforced upstream).
	pub fn command_line(&mut self, line: &str) -> Action {
		match super::command::parse(line) {
			Ok(command) => self.apply(command),
			Err(ParseError::UnknownCommand) => Action::Continue(Reply::syntax_error()),
			Err(ParseError::LineTooLong) => Action::Continue(Reply::single(500, "line too long")),
			Err(ParseError::InvalidCharacters) => Action::Continue(Reply::syntax_error()),
			Err(ParseError::InvalidArguments) => Action::Continue(Reply::invalid_arguments()),
			Err(ParseError::UnsupportedParameter) => {
				Action::Continue(Reply::single(555, "parameter not implemented"))
			}
		}
	}

	fn apply(&mut self, command: Command) -> Action {
		match command {
			Command::Helo { domain } | Command::Ehlo { domain } => self.greet(domain),
			Command::MailFrom {
				reverse_path,
				size,
				body: _,
			} => self.mail_from(reverse_path, size),
			Command::RcptTo { forward_path } => self.rcpt_to(forward_path),
			Command::Data => self.data(),
			Command::Rset => {
				self.reset();
				Action::Continue(Reply::ok())
			}
			Command::Noop => Action::Continue(Reply::ok()),
			Command::Quit => Action::Close(Reply::closing()),
			Command::Vrfy => Action::Continue(Reply::vrfy_not_disclosed()),
			Command::StartTls => self.start_tls(),
			Command::Auth { mechanism, initial } => self.auth(&mechanism, initial),
		}
	}

	fn auth(&mut self, mechanism: &str, initial: Option<String>) -> Action {
		if !self.tls_active {
			// Credentials never cross plaintext.
			return Action::Continue(Reply::single(
				538,
				"5.7.11 encryption required for authentication",
			));
		}
		if self.authenticated.is_some() {
			return Action::Continue(Reply::bad_sequence());
		}
		if self.state != State::Greeted {
			return Action::Continue(Reply::bad_sequence());
		}
		if mechanism != "PLAIN" {
			return Action::Continue(Reply::single(504, "mechanism not supported"));
		}
		match initial {
			Some(response) => self.verify_plain(&response),
			None => Action::CollectAuthResponse(Reply::single(334, "")),
		}
	}

	/// Feed the response line of a challenged AUTH (server sent 334).
	pub fn auth_line(&mut self, line: &str) -> Action {
		if line == "*" {
			return Action::Continue(Reply::single(501, "authentication cancelled"));
		}
		self.verify_plain(line)
	}

	fn verify_plain(&mut self, encoded: &str) -> Action {
		use super::auth::{parse_plain, verify_password};

		let failure = |session: &mut Session| {
			session.auth_failures += 1;
			let reply = Reply::single(535, "5.7.8 authentication credentials invalid");
			if session.auth_failures >= 3 {
				Action::Close(reply)
			} else {
				Action::Continue(reply)
			}
		};

		let Ok(credentials) = parse_plain(encoded) else {
			return failure(self);
		};
		let Some((account, hash)) = self.directory.credentials(&credentials.authcid) else {
			// Unknown user: same reply as a bad password, no oracle.
			return failure(self);
		};
		if !verify_password(hash, &credentials.password) {
			return failure(self);
		}
		self.authenticated = Some(account);
		Action::Continue(Reply::single(235, "2.7.0 authentication successful"))
	}

	fn greet(&mut self, domain: String) -> Action {
		self.state = State::Greeted;
		self.helo_domain = Some(domain);
		let mut lines = vec![
			self.hostname.clone(),
			"PIPELINING".to_string(),
			"8BITMIME".to_string(),
			format!("SIZE {MAX_MESSAGE_SIZE}"),
		];
		if self.tls_available {
			lines.push("STARTTLS".to_string());
		}
		if self.tls_active && self.authenticated.is_none() {
			lines.push("AUTH PLAIN".to_string());
		}
		Action::Continue(Reply::new(250, lines))
	}

	fn start_tls(&mut self) -> Action {
		if !self.tls_available {
			return Action::Continue(Reply::single(454, "TLS not available"));
		}
		match self.state {
			// RFC 3207: STARTTLS requires EHLO first and no open transaction.
			State::Greeted => Action::UpgradeTls(Reply::single(220, "ready to start TLS")),
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	fn mail_from(&mut self, reverse_path: String, size: Option<u64>) -> Action {
		match self.state {
			State::Greeted => {
				match (&self.authenticated, Address::parse(&reverse_path)) {
					// Authenticated senders must use one of their own
					// addresses — no spoofing, no null path.
					(Some(account), Ok(address))
						if !self.directory.owns_address(account, &address) =>
					{
						return Action::Continue(Reply::single(
							553,
							"5.7.1 sender address not owned by authenticated user",
						));
					}
					(Some(_), Err(_)) => {
						return Action::Continue(Reply::single(553, "invalid reverse-path"));
					}
					// The null reverse-path (bounces) is legal when
					// unauthenticated; anything else must parse.
					(None, Err(_)) if !reverse_path.is_empty() => {
						return Action::Continue(Reply::single(553, "invalid reverse-path"));
					}
					_ => {}
				}
				// SIZE is declared up front: reject oversize without DATA.
				if size.is_some_and(|s| s > MAX_MESSAGE_SIZE as u64) {
					return Action::Continue(Reply::single(552, "message exceeds maximum size"));
				}
				self.state = State::ReceivingRecipients { reverse_path };
				Action::Continue(Reply::ok())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	fn rcpt_to(&mut self, forward_path: String) -> Action {
		let Ok(address) = Address::parse(&forward_path) else {
			return Action::Continue(Reply::single(553, "invalid recipient address"));
		};
		match self.directory.resolve(&address) {
			// Foreign domains are relayed only for authenticated users.
			Resolution::NotLocal => {
				if self.authenticated.is_none() {
					return Action::Continue(Reply::single(550, "5.7.1 relaying denied"));
				}
			}
			Resolution::UnknownUser => {
				return Action::Continue(Reply::single(550, "5.1.1 no such user"));
			}
			Resolution::Account(_) => {}
		}
		let forward_path = address.to_string();
		match &mut self.state {
			State::ReceivingRecipients { reverse_path } => {
				let reverse_path = reverse_path.clone();
				self.state = State::ReceivingData {
					reverse_path,
					recipients: vec![forward_path],
					size: 0,
					body: Vec::new(),
				};
				Action::Continue(Reply::ok())
			}
			State::ReceivingData {
				recipients, body, ..
			} if body.is_empty() => {
				if recipients.len() >= MAX_RECIPIENTS {
					return Action::Continue(Reply::single(452, "too many recipients"));
				}
				recipients.push(forward_path);
				Action::Continue(Reply::ok())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	fn data(&mut self) -> Action {
		match &self.state {
			State::ReceivingData { body, .. } if body.is_empty() => {
				Action::CollectData(Reply::start_mail_input())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	/// Feed one data line (CRLF already stripped and enforced upstream).
	/// Returns `None` while more lines are expected.
	pub fn data_line(&mut self, line: &str) -> Option<Action> {
		let State::ReceivingData {
			reverse_path,
			recipients,
			size,
			body,
		} = &mut self.state
		else {
			// Programming error in the network layer; fail the transaction.
			self.reset();
			return Some(Action::Continue(Reply::bad_sequence()));
		};

		if line == "." {
			let message = AcceptedMessage {
				reverse_path: reverse_path.clone(),
				recipients: recipients.clone(),
				data: body.clone(),
			};
			let oversize = *size > MAX_MESSAGE_SIZE;
			self.state = State::Greeted;
			if oversize {
				return Some(Action::Continue(Reply::single(
					552,
					"message exceeds maximum size",
				)));
			}
			return Some(Action::Deliver(Reply::ok(), message));
		}

		// Dot-unstuffing (RFC 5321 section 4.5.2).
		let content = line.strip_prefix('.').unwrap_or(line);
		*size += content.len() + 2;
		if *size <= MAX_MESSAGE_SIZE {
			body.extend_from_slice(content.as_bytes());
			body.extend_from_slice(b"\r\n");
		}
		None
	}

	/// Drop any in-progress transaction, keeping the greeting.
	fn reset(&mut self) {
		if self.state != State::Connected {
			self.state = State::Greeted;
		}
	}
}

#[cfg(test)]
#[path = "session_tests_basic.rs"]
mod tests_basic;

#[cfg(test)]
#[path = "session_tests_auth.rs"]
mod tests_auth;

