//! IMAP session state machine (sans-IO).

use std::path::PathBuf;
use std::sync::Arc;

use crate::smtp::directory::Directory;

use super::command::{Command, FetchItem, ParseError, Tagged};
use super::mailbox::Snapshot;

/// Server output produced by one step: zero or more complete response
/// lines/literals, ready for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
	pub bytes: Vec<u8>,
	/// Close the connection after sending.
	pub close: bool,
}

impl Output {
	fn text(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: false,
		}
	}

	fn closing(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: true,
		}
	}
}

enum State {
	NotAuthenticated { login_failures: u8 },
	Authenticated { account: String },
	Selected { account: String, snapshot: Snapshot },
}

/// One IMAP connection's protocol state.
pub struct Session {
	hostname: String,
	data_dir: PathBuf,
	directory: Arc<Directory>,
	state: State,
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
			Command::Fetch {
				sequence,
				items,
				uid,
			} => self.fetch(&tag, &sequence, &items, uid),
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
		self.state = State::Selected { account, snapshot };
		Output::text(response)
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
					FetchItem::Flags => parts.push(b"FLAGS ()".to_vec()),
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
