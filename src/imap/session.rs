//! IMAP session state machine (sans-IO).

use std::path::PathBuf;
use std::sync::Arc;

use crate::smtp::directory::Directory;

use super::command::{Command, FetchItem, ParseError, StoreMode, Tagged};
use super::mailbox::{Flag, Snapshot, render_flags};

/// Server output produced by one step: zero or more complete response
/// lines/literals, ready for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
	pub bytes: Vec<u8>,
	/// Close the connection after sending.
	pub close: bool,
	/// After sending, read exactly this many literal bytes and feed them
	/// to [`Session::literal_done`].
	pub collect_literal: Option<usize>,
	/// After sending, read lines until `DONE` and call [`Session::idle_done`].
	pub idle: bool,
}

impl Output {
	fn text(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: false,
			collect_literal: None,
			idle: false,
		}
	}

	fn closing(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: true,
			collect_literal: None,
			idle: false,
		}
	}
}

enum State {
	NotAuthenticated {
		login_failures: u8,
	},
	Authenticated {
		account: String,
	},
	Selected {
		account: String,
		snapshot: Snapshot,
		read_only: bool,
	},
}

/// One IMAP connection's protocol state.
pub struct Session {
	hostname: String,
	data_dir: PathBuf,
	directory: Arc<Directory>,
	state: State,
	/// In-flight APPEND: (tag, flags) while the literal arrives.
	pending_append: Option<(String, Vec<Flag>)>,
}

const CAPABILITIES: &str = "IMAP4rev2 AUTH=PLAIN";

impl Session {
	/// New session over an established TLS connection.
	pub fn new(hostname: &str, data_dir: PathBuf, directory: Arc<Directory>) -> Self {
		Session {
			hostname: hostname.to_string(),
			data_dir,
			directory,
			state: State::NotAuthenticated { login_failures: 0 },
			pending_append: None,
		}
	}

	/// The greeting sent when the connection opens.
	pub fn greeting(&self) -> Output {
		Output::text(format!(
			"* OK [CAPABILITY {CAPABILITIES}] {} IMAP4rev2 ready\r\n",
			self.hostname
		))
	}

	/// Feed one command line (CRLF stripped).
	pub fn command_line(&mut self, line: &str) -> Output {
		let tagged = match super::command::parse(line) {
			Ok(tagged) => tagged,
			Err(ParseError::Malformed) => {
				return Output::text("* BAD malformed command\r\n".to_string());
			}
			Err(ParseError::Unknown(tag)) => {
				return Output::text(format!("{tag} BAD unknown command\r\n"));
			}
			Err(ParseError::BadArguments(tag)) => {
				return Output::text(format!("{tag} BAD invalid arguments\r\n"));
			}
		};
		self.apply(tagged)
	}

	fn apply(&mut self, tagged: Tagged) -> Output {
		let tag = tagged.tag;
		match tagged.command {
			Command::Capability => Output::text(format!(
				"* CAPABILITY {CAPABILITIES}\r\n{tag} OK CAPABILITY completed\r\n"
			)),
			Command::Noop => Output::text(format!("{tag} OK NOOP completed\r\n")),
			Command::Logout => Output::closing(format!(
				"* BYE logging out\r\n{tag} OK LOGOUT completed\r\n"
			)),
			Command::Login { username, password } => self.login(&tag, &username, &password),
			Command::List { pattern, .. } => self.list(&tag, &pattern),
			Command::Select { mailbox } => self.select(&tag, &mailbox, false),
			Command::Examine { mailbox } => self.select(&tag, &mailbox, true),
			Command::Close => self.close(&tag),
			Command::Expunge => self.expunge(&tag),
			Command::Idle => {
				if self.account().is_none() {
					return Output::text(format!("{tag} NO not authenticated\r\n"));
				}
				let mut output = Output::text("+ idling\r\n".to_string());
				output.idle = true;
				// The tag is needed when DONE arrives.
				self.pending_append = Some((tag, Vec::new()));
				output
			}
			Command::Append {
				mailbox,
				flags,
				size,
			} => self.append_begin(&tag, &mailbox, &flags, size),
			Command::Fetch {
				sequence,
				items,
				uid,
			} => self.fetch(&tag, &sequence, &items, uid),
			Command::Store {
				sequence,
				mode,
				flags,
				silent,
				uid,
			} => self.store(&tag, &sequence, mode, &flags, silent, uid),
		}
	}

	fn login(&mut self, tag: &str, username: &str, password: &str) -> Output {
		let State::NotAuthenticated { login_failures } = &mut self.state else {
			return Output::text(format!("{tag} BAD already authenticated\r\n"));
		};
		let verified = self
			.directory
			.credentials(username)
			.filter(|(_, hash)| crate::smtp::auth::verify_password(hash, password))
			.map(|(account, _)| account);
		match verified {
			Some(account) => {
				self.state = State::Authenticated { account };
				Output::text(format!("{tag} OK LOGIN completed\r\n"))
			}
			None => {
				*login_failures += 1;
				let response = format!("{tag} NO LOGIN failed\r\n");
				if *login_failures >= 3 {
					Output::closing(format!("* BYE too many failures\r\n{response}"))
				} else {
					Output::text(response)
				}
			}
		}
	}

	fn account(&self) -> Option<&str> {
		match &self.state {
			State::NotAuthenticated { .. } => None,
			State::Authenticated { account } | State::Selected { account, .. } => Some(account),
		}
	}

	fn list(&mut self, tag: &str, pattern: &str) -> Output {
		if self.account().is_none() {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		}
		// Only INBOX exists in this slice.
		let matches = pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case("INBOX");
		let mut response = String::new();
		if matches {
			response.push_str("* LIST () \"/\" INBOX\r\n");
		}
		response.push_str(&format!("{tag} OK LIST completed\r\n"));
		Output::text(response)
	}

	fn select(&mut self, tag: &str, mailbox: &str, read_only: bool) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox.eq_ignore_ascii_case("INBOX") {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let snapshot = match Snapshot::inbox(&self.data_dir, &account) {
			Ok(snapshot) => snapshot,
			Err(_) => return Output::text(format!("{tag} NO cannot open mailbox\r\n")),
		};
		let response = format!(
			"* {count} EXISTS\r\n\
* OK [UIDVALIDITY {validity}] UIDs valid\r\n\
* OK [UIDNEXT {next}] predicted next UID\r\n\
* FLAGS (\\Seen \\Deleted)\r\n\
{tag} OK [{mode}] {verb} completed\r\n",
			count = snapshot.len(),
			validity = snapshot.uid_validity(),
			next = snapshot.uid_next(),
			mode = if read_only { "READ-ONLY" } else { "READ-WRITE" },
			verb = if read_only { "EXAMINE" } else { "SELECT" },
		);
		self.state = State::Selected {
			account,
			snapshot,
			read_only,
		};
		Output::text(response)
	}

	fn store(
		&mut self,
		tag: &str,
		sequence: &super::command::SequenceSet,
		mode: StoreMode,
		flag_tokens: &[String],
		silent: bool,
		uid: bool,
	) -> Output {
		let State::Selected {
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}

		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut response = String::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if !sequence.contains(selector, total) {
				continue;
			}
			let message_uid = message.uid;
			let mut updated: Vec<Flag> = match mode {
				StoreMode::Set => flags.clone(),
				StoreMode::Add => {
					let mut existing = message.flags.clone();
					for flag in &flags {
						if !existing.contains(flag) {
							existing.push(*flag);
						}
					}
					existing
				}
				StoreMode::Remove => message
					.flags
					.iter()
					.copied()
					.filter(|flag| !flags.contains(flag))
					.collect(),
			};
			updated.dedup();
			let stored = match snapshot.store_flags(sequence_number, updated) {
				Ok(stored) => render_flags(stored),
				Err(_) => {
					return Output::text(format!("{tag} NO cannot store flags\r\n"));
				}
			};
			if !silent {
				if uid {
					response.push_str(&format!(
						"* {sequence_number} FETCH (UID {message_uid} FLAGS {stored})\r\n"
					));
				} else {
					response.push_str(&format!("* {sequence_number} FETCH (FLAGS {stored})\r\n"));
				}
			}
		}
		response.push_str(&format!("{tag} OK STORE completed\r\n"));
		Output::text(response)
	}

	fn expunge(&mut self, tag: &str) -> Output {
		let State::Selected {
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		match snapshot.expunge() {
			Ok(expunged) => {
				let mut response = String::new();
				for sequence_number in expunged {
					response.push_str(&format!("* {sequence_number} EXPUNGE\r\n"));
				}
				response.push_str(&format!("{tag} OK EXPUNGE completed\r\n"));
				Output::text(response)
			}
			Err(_) => Output::text(format!("{tag} NO EXPUNGE failed\r\n")),
		}
	}

	fn append_begin(
		&mut self,
		tag: &str,
		mailbox: &str,
		flag_tokens: &[String],
		size: usize,
	) -> Output {
		if self.account().is_none() {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		}
		if !mailbox.eq_ignore_ascii_case("INBOX") {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}
		self.pending_append = Some((tag.to_string(), flags));
		let mut output = Output::text("+ ready for literal data\r\n".to_string());
		output.collect_literal = Some(size);
		output
	}

	/// Called by the network layer with the complete APPEND literal.
	pub fn literal_done(&mut self, data: &[u8]) -> Output {
		let Some((tag, flags)) = self.pending_append.take() else {
			return Output::text("* BAD unexpected literal\r\n".to_string());
		};
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match super::mailbox::append(&self.data_dir, &account, &flags, data) {
			Ok(_) => Output::text(format!("{tag} OK APPEND completed\r\n")),
			Err(_) => Output::text(format!("{tag} NO APPEND failed\r\n")),
		}
	}

	/// Called by the network layer when an IDLE ends with DONE.
	pub fn idle_done(&mut self) -> Output {
		match self.pending_append.take() {
			Some((tag, _)) => Output::text(format!("{tag} OK IDLE terminated\r\n")),
			None => Output::text("* BAD not idling\r\n".to_string()),
		}
	}

	fn close(&mut self, tag: &str) -> Output {
		match &self.state {
			State::Selected { account, .. } => {
				self.state = State::Authenticated {
					account: account.clone(),
				};
				Output::text(format!("{tag} OK CLOSE completed\r\n"))
			}
			_ => Output::text(format!("{tag} BAD no mailbox selected\r\n")),
		}
	}

	fn fetch(
		&mut self,
		tag: &str,
		sequence: &super::command::SequenceSet,
		items: &[FetchItem],
		uid: bool,
	) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut bytes = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if !sequence.contains(selector, total) {
				continue;
			}

			let mut parts: Vec<Vec<u8>> = Vec::new();
			for item in items {
				match item {
					FetchItem::Flags => {
						parts.push(format!("FLAGS {}", render_flags(&message.flags)).into_bytes());
					}
					FetchItem::Uid => {
						parts.push(format!("UID {}", message.uid).into_bytes());
					}
					FetchItem::Rfc822Size => {
						parts.push(format!("RFC822.SIZE {}", message.size).into_bytes());
					}
					FetchItem::InternalDate => {
						// Snapshot has no per-message date metadata yet.
						parts.push(b"INTERNALDATE \"01-Jan-1970 00:00:00 +0000\"".to_vec());
					}
					FetchItem::Body => match snapshot.read(message) {
						Ok(data) => {
							let mut part = format!("BODY[] {{{}}}\r\n", data.len()).into_bytes();
							part.extend_from_slice(&data);
							parts.push(part);
						}
						Err(_) => {
							return Output::text(format!("{tag} NO message unavailable\r\n"));
						}
					},
				}
			}

			bytes.extend_from_slice(format!("* {sequence_number} FETCH (").as_bytes());
			for (index, part) in parts.iter().enumerate() {
				if index > 0 {
					bytes.push(b' ');
				}
				bytes.extend_from_slice(part);
			}
			bytes.extend_from_slice(b")\r\n");
		}
		bytes.extend_from_slice(format!("{tag} OK FETCH completed\r\n").as_bytes());
		Output {
			bytes,
			close: false,
			collect_literal: None,
			idle: false,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	fn directory() -> Arc<Directory> {
		Arc::new(
			Directory::new(
				["example.org".to_string()],
				[("alice@example.org".to_string(), "alice".to_string())],
			)
			.with_password_hashes(HashMap::from([(
				"alice".to_string(),
				crate::smtp::auth::tests::hash("secret"),
			)])),
		)
	}

	fn deliver(dir: &std::path::Path, body: &[u8]) {
		let new_dir = dir.join("accounts").join("alice").join("new");
		std::fs::create_dir_all(&new_dir).expect("create dirs");
		let id = uuid::Uuid::now_v7();
		std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
	}

	fn logged_in(dir: &std::path::Path) -> Session {
		let mut session = Session::new("mail.example.org", dir.to_path_buf(), directory());
		let output = session.command_line("a1 LOGIN alice secret");
		assert!(text(&output).contains("a1 OK"), "{}", text(&output));
		session
	}

	fn text(output: &Output) -> String {
		String::from_utf8_lossy(&output.bytes).to_string()
	}

	#[test]
	fn greeting_announces_capabilities() {
		let dir = tempfile::tempdir().expect("tempdir");
		let session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
		assert!(text(&session.greeting()).contains("IMAP4rev2"));
	}

	#[test]
	fn login_with_wrong_password_fails_and_third_failure_closes() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
		for round in 0..2 {
			let output = session.command_line(&format!("a{round} LOGIN alice wrong"));
			assert!(text(&output).contains("NO LOGIN failed"));
			assert!(!output.close);
		}
		let output = session.command_line("a3 LOGIN alice wrong");
		assert!(output.close);
		assert!(text(&output).contains("BYE"));
	}

	#[test]
	fn unauthenticated_select_is_refused() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
		let output = session.command_line("a1 SELECT INBOX");
		assert!(text(&output).contains("a1 NO"));
	}

	#[test]
	fn list_shows_inbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.command_line(r#"a2 LIST "" "*""#);
		assert!(text(&output).contains("* LIST () \"/\" INBOX"));
		assert!(text(&output).contains("a2 OK"));
	}

	#[test]
	fn select_reports_exists_and_uidvalidity() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"From: a@example.org\r\n\r\nhi\r\n");
		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 SELECT INBOX");
		let response = text(&output);
		assert!(response.contains("* 1 EXISTS"), "{response}");
		assert!(response.contains("UIDVALIDITY"), "{response}");
		assert!(
			response.contains("a2 OK [READ-WRITE] SELECT completed"),
			"{response}"
		);
	}

	#[test]
	fn fetch_returns_flags_size_and_body() {
		let dir = tempfile::tempdir().expect("tempdir");
		let body = b"From: a@example.org\r\nSubject: hi\r\n\r\nhello\r\n";
		deliver(dir.path(), body);
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");

		let output = session.command_line("a3 FETCH 1 (FLAGS RFC822.SIZE UID BODY[])");
		let response = text(&output);
		assert!(response.contains("* 1 FETCH (FLAGS ()"), "{response}");
		assert!(
			response.contains(&format!("RFC822.SIZE {}", body.len())),
			"{response}"
		);
		assert!(response.contains("UID 1"), "{response}");
		assert!(
			response.contains(&format!("BODY[] {{{}}}", body.len())),
			"{response}"
		);
		assert!(response.contains("Subject: hi"), "{response}");
		assert!(response.contains("a3 OK FETCH completed"), "{response}");
	}

	#[test]
	fn uid_fetch_filters_by_uid() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"first\r\n");
		deliver(dir.path(), b"second\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");

		let output = session.command_line("a3 UID FETCH 2 (FLAGS)");
		let response = text(&output);
		assert!(response.contains("* 2 FETCH"), "{response}");
		assert!(!response.contains("* 1 FETCH"), "{response}");
		assert!(response.contains("UID 2"), "{response}");
	}

	#[test]
	fn fetch_without_selected_mailbox_is_bad() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 FETCH 1 (FLAGS)");
		assert!(text(&output).contains("a2 BAD"));
	}

	#[test]
	fn close_returns_to_authenticated() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		let output = session.command_line("a3 CLOSE");
		assert!(text(&output).contains("a3 OK"));
		let output = session.command_line("a4 FETCH 1 (FLAGS)");
		assert!(text(&output).contains("a4 BAD"));
	}

	#[test]
	fn store_and_expunge_flow() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		deliver(dir.path(), b"two\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");

		let output = session.command_line(r"a3 STORE 1 +FLAGS (\Seen \Deleted)");
		let response = text(&output);
		assert!(
			response.contains(r"* 1 FETCH (FLAGS (\Seen \Deleted))"),
			"{response}"
		);
		assert!(response.contains("a3 OK"), "{response}");

		let output = session.command_line(r"a4 STORE 1 -FLAGS (\Seen)");
		assert!(text(&output).contains(r"* 1 FETCH (FLAGS (\Deleted))"));

		let output = session.command_line("a5 EXPUNGE");
		let response = text(&output);
		assert!(response.contains("* 1 EXPUNGE"), "{response}");
		assert!(response.contains("a5 OK"), "{response}");

		// Remaining message renumbered to sequence 1.
		let output = session.command_line("a6 FETCH 1 (BODY[])");
		assert!(text(&output).contains("two"), "{}", text(&output));
	}

	#[test]
	fn silent_store_suppresses_untagged_response() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		let output = session.command_line(r"a3 STORE 1 +FLAGS.SILENT (\Seen)");
		let response = text(&output);
		assert!(!response.contains("FETCH"), "{response}");
		assert!(response.contains("a3 OK"), "{response}");
	}

	#[test]
	fn uid_store_reports_uid() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		deliver(dir.path(), b"two\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		let output = session.command_line(r"a3 UID STORE 2 +FLAGS (\Flagged)");
		let response = text(&output);
		assert!(
			response.contains(r"* 2 FETCH (UID 2 FLAGS (\Flagged))"),
			"{response}"
		);
	}

	#[test]
	fn examine_refuses_store_and_expunge() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 EXAMINE INBOX");
		let output = session.command_line(r"a3 STORE 1 +FLAGS (\Seen)");
		assert!(text(&output).contains("a3 NO"), "{}", text(&output));
		let output = session.command_line("a4 EXPUNGE");
		assert!(text(&output).contains("a4 NO"), "{}", text(&output));
	}

	#[test]
	fn store_rejects_unsupported_flag() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		let output = session.command_line(r"a3 STORE 1 +FLAGS (\Recent)");
		assert!(text(&output).contains("a3 BAD"), "{}", text(&output));
	}

	#[test]
	fn append_stores_message_with_flags() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());

		let output = session.command_line(r"a2 APPEND INBOX (\Seen) {14}");
		assert_eq!(output.collect_literal, Some(14));
		assert!(text(&output).starts_with("+ "), "{}", text(&output));

		let output = session.literal_done(b"Subject: bye\r\n");
		assert!(text(&output).contains("a2 OK"), "{}", text(&output));

		// The appended message is visible on SELECT, with its flag.
		let output = session.command_line("a3 SELECT INBOX");
		assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
		let output = session.command_line("a4 FETCH 1 (FLAGS BODY[])");
		let response = text(&output);
		assert!(response.contains(r"FLAGS (\Seen)"), "{response}");
		assert!(response.contains("Subject: bye"), "{response}");
	}

	#[test]
	fn append_requires_authentication_and_known_mailbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
		let output = session.command_line("a1 APPEND INBOX {5}");
		assert!(text(&output).contains("a1 NO"));
		assert_eq!(output.collect_literal, None);

		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 APPEND Archive {5}");
		assert!(text(&output).contains("TRYCREATE"), "{}", text(&output));
	}

	#[test]
	fn unexpected_literal_is_rejected() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.literal_done(b"stray");
		assert!(text(&output).contains("BAD"), "{}", text(&output));
	}

	#[test]
	fn idle_flow() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 IDLE");
		assert!(output.idle);
		assert!(text(&output).starts_with("+ "));
		let output = session.idle_done();
		assert!(text(&output).contains("a2 OK"), "{}", text(&output));
		// A second DONE without IDLE is an error.
		let output = session.idle_done();
		assert!(text(&output).contains("BAD"));
	}

	#[test]
	fn idle_requires_authentication() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
		let output = session.command_line("a1 IDLE");
		assert!(text(&output).contains("a1 NO"));
		assert!(!output.idle);
	}

	#[test]
	fn logout_closes() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 LOGOUT");
		assert!(output.close);
		assert!(text(&output).contains("* BYE"));
	}

	#[test]
	fn examine_is_read_only() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 EXAMINE INBOX");
		assert!(text(&output).contains("READ-ONLY"));
	}

	#[test]
	fn unknown_mailbox_is_refused() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 SELECT Archive");
		assert!(text(&output).contains("a2 NO"));
	}
}
