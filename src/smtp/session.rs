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
				// The null reverse-path (bounces) is legal; anything else
				// must be a syntactically valid address.
				if !reverse_path.is_empty() && Address::parse(&reverse_path).is_err() {
					return Action::Continue(Reply::single(553, "invalid reverse-path"));
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
			// Not one of our domains: this server does not relay.
			Resolution::NotLocal => {
				return Action::Continue(Reply::single(550, "5.7.1 relaying denied"));
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
mod tests {
	use super::*;

	fn test_directory() -> Arc<Directory> {
		let mut entries: Vec<(String, String)> = vec![
			("b@example.org".to_string(), "bob".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("c@example.org".to_string(), "bob".to_string()),
			("overflow@example.org".to_string(), "bob".to_string()),
		];
		for i in 0..=MAX_RECIPIENTS {
			entries.push((format!("r{i}@example.org"), "bob".to_string()));
		}
		Arc::new(Directory::new(["example.org".to_string()], entries))
	}

	fn greeted() -> Session {
		let mut session = Session::new("mail.example.org").with_directory(test_directory());
		session.command_line("EHLO client.example.org");
		session
	}

	fn reply_code(action: &Action) -> u16 {
		match action {
			Action::Continue(r)
			| Action::CollectData(r)
			| Action::UpgradeTls(r)
			| Action::CollectAuthResponse(r)
			| Action::Close(r) => r.code(),
			Action::Deliver(r, _) => r.code(),
		}
	}

	#[test]
	fn greeting_announces_hostname() {
		let session = Session::new("mail.example.org");
		assert_eq!(
			session.greeting().to_string(),
			"220 mail.example.org ESMTP ready\r\n"
		);
	}

	#[test]
	fn full_transaction_delivers_message() {
		let mut session = greeted();
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
			250
		);
		assert_eq!(
			reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
			250
		);
		let action = session.command_line("DATA");
		assert!(matches!(action, Action::CollectData(_)));

		assert_eq!(session.data_line("Subject: hi"), None);
		assert_eq!(session.data_line(""), None);
		assert_eq!(session.data_line("hello"), None);
		let Some(Action::Deliver(reply, message)) = session.data_line(".") else {
			panic!("expected delivery");
		};
		assert_eq!(reply.code(), 250);
		assert_eq!(message.reverse_path, "alice@example.org");
		assert_eq!(message.recipients, vec!["bob@example.org".to_string()]);
		assert_eq!(message.data, b"Subject: hi\r\n\r\nhello\r\n");
	}

	#[test]
	fn dot_stuffed_lines_are_unstuffed() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		session.command_line("RCPT TO:<b@example.org>");
		session.command_line("DATA");
		assert_eq!(session.data_line("..leading dot"), None);
		let Some(Action::Deliver(_, message)) = session.data_line(".") else {
			panic!("expected delivery");
		};
		assert_eq!(message.data, b".leading dot\r\n");
	}

	#[test]
	fn mail_before_greeting_is_rejected() {
		let mut session = Session::new("mail.example.org");
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
			503
		);
	}

	#[test]
	fn rcpt_without_mail_is_rejected() {
		let mut session = greeted();
		assert_eq!(
			reply_code(&session.command_line("RCPT TO:<b@example.org>")),
			503
		);
	}

	#[test]
	fn data_without_recipients_is_rejected() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		assert_eq!(reply_code(&session.command_line("DATA")), 503);
	}

	#[test]
	fn empty_recipient_is_rejected() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		assert_eq!(reply_code(&session.command_line("RCPT TO:<>")), 553);
	}

	#[test]
	fn malformed_recipient_is_rejected() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		assert_eq!(
			reply_code(&session.command_line("RCPT TO:<no-at-sign>")),
			553
		);
	}

	#[test]
	fn non_local_recipient_is_denied() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		let action = session.command_line("RCPT TO:<b@elsewhere.example>");
		assert_eq!(reply_code(&action), 550);
	}

	#[test]
	fn recipient_domain_match_is_case_insensitive() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		assert_eq!(
			reply_code(&session.command_line("RCPT TO:<b@EXAMPLE.ORG>")),
			250
		);
	}

	#[test]
	fn unknown_user_in_local_domain_is_denied() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		let action = session.command_line("RCPT TO:<stranger@example.org>");
		assert_eq!(reply_code(&action), 550);
	}

	#[test]
	fn without_local_domains_every_recipient_is_denied() {
		let mut session = Session::new("mail.example.org");
		session.command_line("EHLO client.example.org");
		session.command_line("MAIL FROM:<a@example.org>");
		assert_eq!(
			reply_code(&session.command_line("RCPT TO:<b@example.org>")),
			550
		);
	}

	#[test]
	fn malformed_reverse_path_is_rejected() {
		let mut session = greeted();
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<not-an-address>")),
			553
		);
		// Null reverse-path stays legal for bounces.
		assert_eq!(reply_code(&session.command_line("MAIL FROM:<>")), 250);
	}

	#[test]
	fn recipient_limit_is_enforced() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		for i in 0..MAX_RECIPIENTS {
			let action = session.command_line(&format!("RCPT TO:<r{i}@example.org>"));
			assert_eq!(reply_code(&action), 250, "recipient {i} accepted");
		}
		let action = session.command_line("RCPT TO:<overflow@example.org>");
		assert_eq!(reply_code(&action), 452);
	}

	#[test]
	fn rset_aborts_transaction() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		assert_eq!(reply_code(&session.command_line("RSET")), 250);
		// After RSET a new MAIL FROM must be accepted.
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<c@example.org>")),
			250
		);
	}

	#[test]
	fn declared_size_within_limit_is_accepted() {
		let mut session = greeted();
		let action = session.command_line(&format!(
			"MAIL FROM:<a@example.org> SIZE={} BODY=8BITMIME",
			MAX_MESSAGE_SIZE
		));
		assert_eq!(reply_code(&action), 250);
	}

	#[test]
	fn declared_oversize_is_rejected_at_mail_time() {
		let mut session = greeted();
		let action = session.command_line(&format!(
			"MAIL FROM:<a@example.org> SIZE={}",
			MAX_MESSAGE_SIZE as u64 + 1
		));
		assert_eq!(reply_code(&action), 552);
		// The transaction never started: RCPT must fail.
		assert_eq!(
			reply_code(&session.command_line("RCPT TO:<b@example.org>")),
			503
		);
	}

	#[test]
	fn unsupported_parameter_gets_555() {
		let mut session = greeted();
		let action = session.command_line("MAIL FROM:<a@example.org> AUTH=<>");
		assert_eq!(reply_code(&action), 555);
	}

	fn auth_directory() -> Arc<Directory> {
		Arc::new(
			Directory::new(
				["example.org".to_string()],
				[("alice@example.org".to_string(), "alice".to_string())],
			)
			.with_password_hashes([(
				"alice".to_string(),
				crate::smtp::auth::tests::hash("secret"),
			)]),
		)
	}

	fn plain(authcid: &str, password: &str) -> String {
		use base64::Engine;
		base64::engine::general_purpose::STANDARD.encode(format!("\0{authcid}\0{password}"))
	}

	fn tls_session() -> Session {
		let mut session = Session::new("mail.example.org")
			.with_directory(auth_directory())
			.with_tls_active();
		session.command_line("EHLO client.example.org");
		session
	}

	#[test]
	fn auth_rejected_outside_tls() {
		let mut session = greeted();
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
		assert_eq!(reply_code(&action), 538);
		assert_eq!(session.authenticated(), None);
	}

	#[test]
	fn ehlo_advertises_auth_only_inside_tls() {
		let mut plain_session = greeted();
		let Action::Continue(reply) = plain_session.command_line("EHLO c.example.org") else {
			panic!("expected continue");
		};
		assert!(!reply.to_string().contains("AUTH PLAIN"));

		let mut tls = tls_session();
		let Action::Continue(reply) = tls.command_line("EHLO c.example.org") else {
			panic!("expected continue");
		};
		assert!(reply.to_string().contains("AUTH PLAIN"), "{reply}");
	}

	#[test]
	fn auth_with_initial_response_succeeds() {
		let mut session = tls_session();
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
		assert_eq!(reply_code(&action), 235);
		assert_eq!(session.authenticated(), Some("alice"));
	}

	#[test]
	fn auth_by_address_succeeds() {
		let mut session = tls_session();
		let action = session.command_line(&format!(
			"AUTH PLAIN {}",
			plain("alice@example.org", "secret")
		));
		assert_eq!(reply_code(&action), 235);
	}

	#[test]
	fn auth_challenge_flow_succeeds() {
		let mut session = tls_session();
		let action = session.command_line("AUTH PLAIN");
		assert!(matches!(action, Action::CollectAuthResponse(_)));
		assert_eq!(reply_code(&action), 334);
		let action = session.auth_line(&plain("alice", "secret"));
		assert_eq!(reply_code(&action), 235);
	}

	#[test]
	fn auth_challenge_can_be_cancelled() {
		let mut session = tls_session();
		session.command_line("AUTH PLAIN");
		let action = session.auth_line("*");
		assert_eq!(reply_code(&action), 501);
		assert_eq!(session.authenticated(), None);
	}

	#[test]
	fn wrong_password_gets_535_without_detail() {
		let mut session = tls_session();
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
		assert_eq!(reply_code(&action), 535);
		assert_eq!(session.authenticated(), None);
	}

	#[test]
	fn unknown_user_gets_same_reply_as_wrong_password() {
		let mut session = tls_session();
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("mallory", "secret")));
		assert_eq!(reply_code(&action), 535);
	}

	#[test]
	fn third_failure_closes_connection() {
		let mut session = tls_session();
		for _ in 0..2 {
			let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
			assert!(matches!(action, Action::Continue(_)));
		}
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
		assert!(matches!(action, Action::Close(_)));
	}

	#[test]
	fn auth_after_success_is_bad_sequence() {
		let mut session = tls_session();
		session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
		assert_eq!(reply_code(&action), 503);
	}

	#[test]
	fn unsupported_mechanism_gets_504() {
		let mut session = tls_session();
		assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 504);
	}

	#[test]
	fn auth_inside_transaction_is_bad_sequence() {
		let mut session = tls_session();
		session.command_line("MAIL FROM:<alice@example.org>");
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
		assert_eq!(reply_code(&action), 503);
	}

	#[test]
	fn quit_closes_connection() {
		let mut session = greeted();
		let action = session.command_line("QUIT");
		assert!(matches!(action, Action::Close(_)));
		assert_eq!(reply_code(&action), 221);
	}

	#[test]
	fn vrfy_discloses_nothing() {
		let mut session = greeted();
		assert_eq!(reply_code(&session.command_line("VRFY alice")), 252);
	}

	#[test]
	fn starttls_without_tls_configured_is_unavailable() {
		let mut session = greeted();
		assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
	}

	#[test]
	fn ehlo_advertises_starttls_when_available() {
		let mut session = Session::new("mail.example.org").with_tls_available();
		let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
			panic!("expected continue");
		};
		assert!(reply.to_string().contains("250 STARTTLS\r\n"));
	}

	#[test]
	fn ehlo_does_not_advertise_starttls_when_unavailable() {
		let mut session = greeted();
		let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
			panic!("expected continue");
		};
		assert!(!reply.to_string().contains("STARTTLS"));
	}

	#[test]
	fn starttls_upgrades_after_greeting() {
		let mut session = Session::new("mail.example.org").with_tls_available();
		session.command_line("EHLO client.example.org");
		let action = session.command_line("STARTTLS");
		assert!(matches!(action, Action::UpgradeTls(_)));
		assert_eq!(reply_code(&action), 220);
	}

	#[test]
	fn starttls_before_greeting_is_bad_sequence() {
		let mut session = Session::new("mail.example.org").with_tls_available();
		assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
	}

	#[test]
	fn starttls_inside_transaction_is_bad_sequence() {
		let mut session = Session::new("mail.example.org").with_tls_available();
		session.command_line("EHLO client.example.org");
		session.command_line("MAIL FROM:<a@example.org>");
		assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
	}

	#[test]
	fn tls_started_resets_session() {
		let mut session = Session::new("mail.example.org").with_tls_available();
		session.command_line("EHLO client.example.org");
		session.tls_started();
		// Must greet again before a transaction.
		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
			503
		);
		// And STARTTLS is no longer offered nor accepted.
		let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
			panic!("expected continue");
		};
		assert!(!reply.to_string().contains("STARTTLS"));
		assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
	}

	#[test]
	fn unknown_command_gets_500() {
		let mut session = greeted();
		assert_eq!(reply_code(&session.command_line("EXPN staff")), 500);
	}

	#[test]
	fn oversize_message_is_rejected_and_not_delivered() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		session.command_line("RCPT TO:<b@example.org>");
		session.command_line("DATA");
		let chunk = "x".repeat(1024);
		let lines_needed = MAX_MESSAGE_SIZE / chunk.len() + 1;
		for _ in 0..lines_needed {
			assert_eq!(session.data_line(&chunk), None);
		}
		let Some(action) = session.data_line(".") else {
			panic!("expected final action");
		};
		assert_eq!(reply_code(&action), 552);
		assert!(matches!(action, Action::Continue(_)));
	}

	#[test]
	fn data_line_outside_data_state_fails_closed() {
		let mut session = greeted();
		let action = session.data_line("stray");
		assert_eq!(action.map(|a| reply_code(&a)), Some(503));
	}

	#[test]
	fn second_transaction_works_after_delivery() {
		let mut session = greeted();
		session.command_line("MAIL FROM:<a@example.org>");
		session.command_line("RCPT TO:<b@example.org>");
		session.command_line("DATA");
		session.data_line("first");
		assert!(matches!(session.data_line("."), Some(Action::Deliver(..))));

		assert_eq!(
			reply_code(&session.command_line("MAIL FROM:<c@example.org>")),
			250
		);
	}
}
