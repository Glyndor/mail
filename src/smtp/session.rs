//! Per-connection SMTP session state machine.
//!
//! The session is sans-IO: it consumes parsed commands and data lines and
//! produces replies plus completed messages. The network layer owns sockets
//! and feeds this machine, which keeps the protocol logic fully unit-testable.

use super::command::{Command, ParseError};
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
	/// Send the reply and close the connection.
	Close(Reply),
}

/// SMTP session state machine.
#[derive(Debug)]
pub struct Session {
	hostname: String,
	state: State,
}

impl Session {
	/// Create a session for a freshly accepted connection.
	pub fn new(hostname: &str) -> Self {
		Session {
			hostname: hostname.to_string(),
			state: State::Connected,
		}
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
		}
	}

	fn apply(&mut self, command: Command) -> Action {
		match command {
			Command::Helo { domain } | Command::Ehlo { domain } => self.greet(domain),
			Command::MailFrom { reverse_path } => self.mail_from(reverse_path),
			Command::RcptTo { forward_path } => self.rcpt_to(forward_path),
			Command::Data => self.data(),
			Command::Rset => {
				self.reset();
				Action::Continue(Reply::ok())
			}
			Command::Noop => Action::Continue(Reply::ok()),
			Command::Quit => Action::Close(Reply::closing()),
			Command::Vrfy => Action::Continue(Reply::vrfy_not_disclosed()),
			Command::StartTls => {
				// TLS upgrade is wired in the network layer; not yet available.
				Action::Continue(Reply::single(454, "TLS not available"))
			}
		}
	}

	fn greet(&mut self, _domain: String) -> Action {
		self.state = State::Greeted;
		let lines = vec![
			self.hostname.clone(),
			"PIPELINING".to_string(),
			"8BITMIME".to_string(),
			format!("SIZE {MAX_MESSAGE_SIZE}"),
		];
		Action::Continue(Reply::new(250, lines))
	}

	fn mail_from(&mut self, reverse_path: String) -> Action {
		match self.state {
			State::Greeted => {
				self.state = State::ReceivingRecipients { reverse_path };
				Action::Continue(Reply::ok())
			}
			_ => Action::Continue(Reply::bad_sequence()),
		}
	}

	fn rcpt_to(&mut self, forward_path: String) -> Action {
		if forward_path.is_empty() {
			return Action::Continue(Reply::invalid_arguments());
		}
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

	fn greeted() -> Session {
		let mut session = Session::new("mail.example.org");
		session.command_line("EHLO client.example.org");
		session
	}

	fn reply_code(action: &Action) -> u16 {
		match action {
			Action::Continue(r) | Action::CollectData(r) | Action::Close(r) => r.code(),
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
		assert_eq!(reply_code(&session.command_line("RCPT TO:<>")), 501);
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
	fn starttls_unavailable_for_now() {
		let mut session = greeted();
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
