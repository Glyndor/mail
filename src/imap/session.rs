//! IMAP session state machine (sans-IO).

use std::path::PathBuf;
use std::sync::Arc;

use crate::smtp::directory::Directory;

use super::command::{Command, FetchItem, ParseError, SearchKey, StatusItem, StoreMode, Tagged};
use super::mailbox::{self, Flag, Snapshot, render_flags};

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
	/// After sending, perform the TLS handshake and call [`Session::tls_started`].
	pub upgrade_tls: bool,
}

impl Output {
	fn text(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: false,
			collect_literal: None,
			idle: false,
			upgrade_tls: false,
		}
	}

	fn closing(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: true,
			collect_literal: None,
			idle: false,
			upgrade_tls: false,
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
	/// In-flight APPEND: (tag, mailbox, flags) while the literal arrives.
	pending_append: Option<(String, String, Vec<Flag>)>,
	/// Tag of an in-flight IDLE.
	idle_tag: Option<String>,
	/// Whether the connection is inside TLS. LOGIN is refused outside.
	tls_active: bool,
	/// Whether STARTTLS can still be offered.
	tls_available: bool,
}

impl Session {
	/// New session over an established TLS connection.
	pub fn new(hostname: &str, data_dir: PathBuf, directory: Arc<Directory>) -> Self {
		Session {
			hostname: hostname.to_string(),
			data_dir,
			directory,
			state: State::NotAuthenticated { login_failures: 0 },
			pending_append: None,
			idle_tag: None,
			tls_active: true,
			tls_available: false,
		}
	}

	/// Mark this session as starting in plaintext with STARTTLS available.
	pub fn with_starttls(mut self) -> Self {
		self.tls_active = false;
		self.tls_available = true;
		self
	}

	/// Called by the network layer after the TLS handshake completed.
	pub fn tls_started(&mut self) {
		self.tls_active = true;
		self.tls_available = false;
		self.state = State::NotAuthenticated { login_failures: 0 };
	}

	fn capabilities(&self) -> String {
		let mut capabilities = String::from("IMAP4rev2 MOVE");
		if self.tls_available {
			capabilities.push_str(" STARTTLS");
		}
		if self.tls_active {
			capabilities.push_str(" AUTH=PLAIN");
		} else {
			capabilities.push_str(" LOGINDISABLED");
		}
		capabilities
	}

	/// The greeting sent when the connection opens.
	pub fn greeting(&self) -> Output {
		Output::text(format!(
			"* OK [CAPABILITY {}] {} IMAP4rev2 ready\r\n",
			self.capabilities(),
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
				"* CAPABILITY {}\r\n{tag} OK CAPABILITY completed\r\n",
				self.capabilities()
			)),
			Command::StartTls => {
				if !self.tls_available {
					return Output::text(format!("{tag} BAD TLS already active\r\n"));
				}
				let mut output = Output::text(format!("{tag} OK begin TLS now\r\n"));
				output.upgrade_tls = true;
				output
			}
			Command::Noop => Output::text(format!("{tag} OK NOOP completed\r\n")),
			Command::Logout => Output::closing(format!(
				"* BYE logging out\r\n{tag} OK LOGOUT completed\r\n"
			)),
			Command::Login { username, password } => self.login(&tag, &username, &password),
			Command::List { pattern, .. } => self.list(&tag, &pattern),
			Command::Select { mailbox } => self.select(&tag, &mailbox, false),
			Command::Examine { mailbox } => self.select(&tag, &mailbox, true),
			Command::Close => self.close(&tag),
			Command::Create { mailbox } => self.mailbox_op(&tag, "CREATE", |dir, account| {
				mailbox::create(dir, account, &mailbox)
			}),
			Command::Delete { mailbox } => self.mailbox_op(&tag, "DELETE", |dir, account| {
				mailbox::delete(dir, account, &mailbox)
			}),
			Command::Rename { from, to } => self.mailbox_op(&tag, "RENAME", |dir, account| {
				mailbox::rename(dir, account, &from, &to)
			}),
			Command::Expunge => self.expunge(&tag),
			Command::Idle => {
				if self.account().is_none() {
					return Output::text(format!("{tag} NO not authenticated\r\n"));
				}
				let mut output = Output::text("+ idling\r\n".to_string());
				output.idle = true;
				self.idle_tag = Some(tag);
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
			Command::Copy {
				sequence,
				mailbox,
				uid,
				remove_source,
			} => self.copy(&tag, &sequence, &mailbox, uid, remove_source),
			Command::Search { criteria, uid } => self.search(&tag, &criteria, uid),
			Command::Status { mailbox, items } => self.status(&tag, &mailbox, &items),
			Command::Subscribe { mailbox } => self.subscription_op(&tag, |data_dir, account| {
				mailbox::subscribe(data_dir, account, &mailbox)
			}),
			Command::Unsubscribe { mailbox } => self.subscription_op(&tag, |data_dir, account| {
				mailbox::unsubscribe(data_dir, account, &mailbox)
			}),
			Command::Lsub { pattern, .. } => self.lsub(&tag, &pattern),
		}
	}

	fn login(&mut self, tag: &str, username: &str, password: &str) -> Output {
		if !self.tls_active {
			// Credentials never cross plaintext.
			return Output::text(format!("{tag} NO [PRIVACYREQUIRED] STARTTLS first\r\n"));
		}
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
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let mut response = String::new();
		for name in mailbox::list(&self.data_dir, &account) {
			let matches = pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case(&name);
			if matches {
				response.push_str(&format!("* LIST () \"/\" \"{name}\"\r\n"));
			}
		}
		response.push_str(&format!("{tag} OK LIST completed\r\n"));
		Output::text(response)
	}

	/// Run a mailbox management operation in any authenticated state.
	fn mailbox_op(
		&mut self,
		tag: &str,
		verb: &str,
		operation: impl FnOnce(&std::path::Path, &str) -> std::io::Result<()>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match operation(&self.data_dir, &account) {
			Ok(()) => Output::text(format!("{tag} OK {verb} completed\r\n")),
			Err(error) => Output::text(format!("{tag} NO {error}\r\n")),
		}
	}

	fn select(&mut self, tag: &str, mailbox: &str, read_only: bool) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let snapshot = match Snapshot::open(&self.data_dir, &account, mailbox) {
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

	fn copy(
		&mut self,
		tag: &str,
		sequence: &super::command::SequenceSet,
		target: &str,
		uid: bool,
		remove_source: bool,
	) -> Output {
		let data_dir = self.data_dir.clone();
		let State::Selected {
			account,
			snapshot,
			read_only,
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if remove_source && *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		let account = account.clone();
		if !mailbox::exists(&data_dir, &account, target) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}

		// Collect matching sequence numbers first: removal renumbers.
		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut matched = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if sequence.contains(selector, total) {
				matched.push(sequence_number);
			}
		}

		// Copy all before removing any: a failed copy must not lose mail.
		for sequence_number in &matched {
			let Some(message) = snapshot.by_sequence(*sequence_number) else {
				return Output::text(format!("{tag} NO message vanished\r\n"));
			};
			let data = match snapshot.read(message) {
				Ok(data) => data,
				Err(_) => return Output::text(format!("{tag} NO message unavailable\r\n")),
			};
			if mailbox::append(&data_dir, &account, target, &message.flags, &data).is_err() {
				return Output::text(format!("{tag} NO copy failed\r\n"));
			}
		}

		let mut response = String::new();
		if remove_source {
			// Remove bottom-up so earlier sequence numbers stay valid, but
			// emit EXPUNGE top-down with renumber-correct values.
			for (offset, sequence_number) in matched.iter().enumerate() {
				let current = sequence_number - u32::try_from(offset).unwrap_or(0);
				if snapshot.remove_at(current).is_err() {
					return Output::text(format!("{tag} NO move failed\r\n"));
				}
				response.push_str(&format!("* {current} EXPUNGE\r\n"));
			}
		}
		let verb = if remove_source { "MOVE" } else { "COPY" };
		response.push_str(&format!("{tag} OK {verb} completed\r\n"));
		Output::text(response)
	}

	fn search(&mut self, tag: &str, criteria: &[SearchKey], uid: bool) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut hits = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			// Message content loaded lazily: only for content criteria.
			let mut content: Option<String> = None;
			let load = |snapshot: &Snapshot| -> String {
				snapshot
					.read(message)
					.map(|data| String::from_utf8_lossy(&data).to_ascii_lowercase())
					.unwrap_or_default()
			};

			let matches = criteria.iter().all(|key| match key {
				SearchKey::All => true,
				SearchKey::FlagIs(flag, wanted) => message.flags.contains(flag) == *wanted,
				SearchKey::Sequence(set) => set.contains(sequence_number, total),
				SearchKey::UidSet(set) => set.contains(message.uid, total),
				SearchKey::Header(name, needle) => {
					let text = content.get_or_insert_with(|| load(snapshot));
					header_value(text, name).is_some_and(|value| value.contains(needle.as_str()))
				}
				SearchKey::Text(needle) => {
					let text = content.get_or_insert_with(|| load(snapshot));
					text.contains(needle.as_str())
				}
			});
			if matches {
				hits.push(if uid { message.uid } else { sequence_number });
			}
		}

		let mut response = String::from("* SEARCH");
		for hit in hits {
			response.push_str(&format!(" {hit}"));
		}
		response.push_str(&format!("\r\n{tag} OK SEARCH completed\r\n"));
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
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}
		self.pending_append = Some((tag.to_string(), mailbox.to_string(), flags));
		let mut output = Output::text("+ ready for literal data\r\n".to_string());
		output.collect_literal = Some(size);
		output
	}

	/// Called by the network layer with the complete APPEND literal.
	pub fn literal_done(&mut self, data: &[u8]) -> Output {
		let Some((tag, mailbox, flags)) = self.pending_append.take() else {
			return Output::text("* BAD unexpected literal\r\n".to_string());
		};
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match mailbox::append(&self.data_dir, &account, &mailbox, &flags, data) {
			Ok(_) => Output::text(format!("{tag} OK APPEND completed\r\n")),
			Err(_) => Output::text(format!("{tag} NO APPEND failed\r\n")),
		}
	}

	/// Called by the network layer when an IDLE ends with DONE.
	pub fn idle_done(&mut self) -> Output {
		match self.idle_tag.take() {
			Some(tag) => Output::text(format!("{tag} OK IDLE terminated\r\n")),
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

	fn status(&mut self, tag: &str, mailbox: &str, items: &[StatusItem]) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let snapshot = match Snapshot::open(&self.data_dir, &account, mailbox) {
			Ok(s) => s,
			Err(_) => return Output::text(format!("{tag} NO cannot open mailbox\r\n")),
		};
		let mut parts = String::new();
		for (i, item) in items.iter().enumerate() {
			if i > 0 {
				parts.push(' ');
			}
			let value: u32 = match item {
				StatusItem::Messages => snapshot.len() as u32,
				StatusItem::Recent => 0,
				StatusItem::Uidnext => snapshot.uid_next(),
				StatusItem::Uidvalidity => snapshot.uid_validity(),
				StatusItem::Unseen => snapshot
					.messages()
					.filter(|m| !m.flags.contains(&Flag::Seen))
					.count() as u32,
			};
			let name = match item {
				StatusItem::Messages => "MESSAGES",
				StatusItem::Recent => "RECENT",
				StatusItem::Uidnext => "UIDNEXT",
				StatusItem::Uidvalidity => "UIDVALIDITY",
				StatusItem::Unseen => "UNSEEN",
			};
			parts.push_str(&format!("{name} {value}"));
		}
		Output::text(format!(
			"* STATUS \"{mailbox}\" ({parts})\r\n{tag} OK STATUS completed\r\n"
		))
	}

	fn lsub(&mut self, tag: &str, pattern: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let mut response = String::new();
		for name in mailbox::list_subscribed(&self.data_dir, &account) {
			let matches = pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case(&name);
			if matches {
				response.push_str(&format!("* LSUB () \"/\" \"{name}\"\r\n"));
			}
		}
		response.push_str(&format!("{tag} OK LSUB completed\r\n"));
		Output::text(response)
	}

	fn subscription_op(
		&mut self,
		tag: &str,
		operation: impl FnOnce(&std::path::Path, &str) -> std::io::Result<()>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match operation(&self.data_dir, &account) {
			Ok(()) => Output::text(format!("{tag} OK completed\r\n")),
			Err(error) => Output::text(format!("{tag} NO {error}\r\n")),
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
						let dt = format_internaldate(message.internal_date);
						parts.push(format!("INTERNALDATE \"{dt}\"").into_bytes());
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
			upgrade_tls: false,
		}
	}
}

/// Format a SystemTime as an IMAP INTERNALDATE string (RFC 3501).
fn format_internaldate(t: std::time::SystemTime) -> String {
	const MONTHS: [&str; 12] = [
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	];
	let secs = t
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();
	let (year, month, day) = epoch_to_ymd(secs / 86400);
	let hms = secs % 86400;
	format!(
		"{:2}-{}-{:04} {:02}:{:02}:{:02} +0000",
		day,
		MONTHS[month as usize - 1],
		year,
		hms / 3600,
		(hms % 3600) / 60,
		hms % 60
	)
}

/// Proleptic Gregorian calendar: days since Unix epoch → (year, month 1-12, day 1-31).
fn epoch_to_ymd(days: u64) -> (u64, u64, u64) {
	let z = days + 719_468;
	let era = z / 146_097;
	let doe = z % 146_097;
	let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = if m <= 2 { y + 1 } else { y };
	(y, m, d)
}

/// Extract a header value (lowercased input) from a lowercased message,
/// folding included. `None` if the header is absent.
fn header_value(lower_message: &str, name: &str) -> Option<String> {
	let header_end = lower_message
		.find("\r\n\r\n")
		.unwrap_or(lower_message.len());
	let headers = &lower_message[..header_end];
	let mut value: Option<String> = None;
	for line in headers.split("\r\n") {
		if line.starts_with(' ') || line.starts_with('\t') {
			if let Some(value) = &mut value {
				value.push(' ');
				value.push_str(line.trim());
			}
			continue;
		}
		if value.is_some() {
			break;
		}
		if let Some(rest) = line.strip_prefix(name)
			&& let Some(rest) = rest.strip_prefix(':')
		{
			value = Some(rest.trim().to_string());
		}
	}
	value
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
		assert!(text(&output).contains("* LIST () \"/\" \"INBOX\""));
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
	fn mailbox_lifecycle() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());

		let output = session.command_line("a2 CREATE Sent");
		assert!(text(&output).contains("a2 OK"), "{}", text(&output));

		// APPEND into the new mailbox works now.
		let output = session.command_line("a3 APPEND Sent {10}");
		assert_eq!(output.collect_literal, Some(10));
		let output = session.literal_done(b"sent body\n");
		assert!(text(&output).contains("a3 OK"), "{}", text(&output));

		let output = session.command_line("a4 SELECT Sent");
		assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
		session.command_line("a5 CLOSE");

		let output = session.command_line(r#"a6 LIST "" "*""#);
		let response = text(&output);
		assert!(response.contains("\"INBOX\""), "{response}");
		assert!(response.contains("\"Sent\""), "{response}");

		let output = session.command_line("a7 RENAME Sent Outbox");
		assert!(text(&output).contains("a7 OK"), "{}", text(&output));
		let output = session.command_line("a8 SELECT Outbox");
		assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
		session.command_line("a9 CLOSE");

		let output = session.command_line("b1 DELETE Outbox");
		assert!(text(&output).contains("b1 OK"), "{}", text(&output));
		let output = session.command_line("b2 SELECT Outbox");
		assert!(text(&output).contains("b2 NO"), "{}", text(&output));
	}

	#[test]
	fn mailbox_management_guards() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		// INBOX cannot be created, deleted or renamed.
		assert!(text(&session.command_line("a2 CREATE INBOX")).contains("a2 NO"));
		assert!(text(&session.command_line("a3 DELETE INBOX")).contains("a3 NO"));
		assert!(text(&session.command_line("a4 RENAME INBOX X")).contains("a4 NO"));
		// Traversal and invalid names are refused.
		assert!(text(&session.command_line("a5 CREATE ../escape")).contains("a5 NO"));
		assert!(text(&session.command_line("a6 DELETE missing")).contains("a6 NO"));
		// Duplicate create fails.
		session.command_line("a7 CREATE Drafts");
		assert!(text(&session.command_line("a8 CREATE Drafts")).contains("a8 NO"));
	}

	#[test]
	fn copy_preserves_source_and_flags() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 CREATE Archive");
		session.command_line("a3 SELECT INBOX");
		session.command_line(r"a4 STORE 1 +FLAGS (\Seen)");

		let output = session.command_line("a5 COPY 1 Archive");
		assert!(text(&output).contains("a5 OK COPY"), "{}", text(&output));

		// Source intact.
		let output = session.command_line("a6 FETCH 1 (FLAGS)");
		assert!(text(&output).contains(r"FLAGS (\Seen)"));
		session.command_line("a7 CLOSE");

		// Target has the copy with flags.
		let output = session.command_line("a8 SELECT Archive");
		assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
		let output = session.command_line("a9 FETCH 1 (FLAGS BODY[])");
		let response = text(&output);
		assert!(response.contains(r"FLAGS (\Seen)"), "{response}");
		assert!(response.contains("one"), "{response}");
	}

	#[test]
	fn move_removes_source_with_expunge() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		deliver(dir.path(), b"two\r\n");
		deliver(dir.path(), b"three\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 CREATE Trash");
		session.command_line("a3 SELECT INBOX");

		let output = session.command_line("a4 MOVE 1,3 Trash");
		let response = text(&output);
		// Renumbering: removing seq 1 makes old 3 the new 2.
		assert!(response.contains("* 1 EXPUNGE"), "{response}");
		assert!(response.contains("* 2 EXPUNGE"), "{response}");
		assert!(response.contains("a4 OK MOVE"), "{response}");

		let output = session.command_line("a5 FETCH 1 (BODY[])");
		assert!(text(&output).contains("two"), "{}", text(&output));
		session.command_line("a6 CLOSE");

		let output = session.command_line("a7 SELECT Trash");
		assert!(text(&output).contains("* 2 EXISTS"), "{}", text(&output));
	}

	#[test]
	fn uid_move_and_guards() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 CREATE Trash");

		// MOVE refused on read-only EXAMINE.
		session.command_line("a3 EXAMINE INBOX");
		let output = session.command_line("a4 MOVE 1 Trash");
		assert!(text(&output).contains("a4 NO"), "{}", text(&output));
		// COPY allowed on read-only.
		let output = session.command_line("a5 COPY 1 Trash");
		assert!(text(&output).contains("a5 OK"), "{}", text(&output));
		session.command_line("a6 CLOSE");

		session.command_line("a7 SELECT INBOX");
		let output = session.command_line("a8 UID MOVE 1 Trash");
		assert!(text(&output).contains("a8 OK MOVE"), "{}", text(&output));
		// Missing target answers TRYCREATE.
		let output = session.command_line("a9 COPY 1 Nowhere");
		assert!(text(&output).contains("TRYCREATE"), "{}", text(&output));
	}

	#[test]
	fn search_by_flags_headers_and_text() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(
			dir.path(),
			b"From: alice@example.org\r\nSubject: project update\r\n\r\nquarterly numbers\r\n",
		);
		deliver(
			dir.path(),
			b"From: bob@example.org\r\nSubject: lunch\r\n\r\ntacos tomorrow\r\n",
		);
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		session.command_line(r"a3 STORE 1 +FLAGS (\Seen)");

		let response = text(&session.command_line("a4 SEARCH UNSEEN"));
		assert!(response.contains("* SEARCH 2\r\n"), "{response}");

		let response = text(&session.command_line("a5 SEARCH FROM alice"));
		assert!(response.contains("* SEARCH 1\r\n"), "{response}");

		let response = text(&session.command_line(r#"a6 SEARCH SUBJECT "project update""#));
		assert!(response.contains("* SEARCH 1\r\n"), "{response}");

		let response = text(&session.command_line("a7 SEARCH TEXT tacos"));
		assert!(response.contains("* SEARCH 2\r\n"), "{response}");

		// AND semantics: seen + from alice = 1; unseen + from alice = none.
		let response = text(&session.command_line("a8 SEARCH SEEN FROM alice"));
		assert!(response.contains("* SEARCH 1\r\n"), "{response}");
		let response = text(&session.command_line("a9 SEARCH UNSEEN FROM alice"));
		assert!(response.contains("* SEARCH\r\n"), "{response}");

		let response = text(&session.command_line("b1 SEARCH ALL"));
		assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");
	}

	#[test]
	fn uid_search_returns_uids() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"From: a@x.example\r\n\r\none\r\n");
		deliver(dir.path(), b"From: a@x.example\r\n\r\ntwo\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		session.command_line(r"a3 STORE 1 +FLAGS (\Deleted)");
		session.command_line("a4 EXPUNGE");

		// One message left: sequence 1, but UID 2.
		let response = text(&session.command_line("a5 UID SEARCH ALL"));
		assert!(response.contains("* SEARCH 2\r\n"), "{response}");
		let response = text(&session.command_line("a6 SEARCH UID 2"));
		assert!(response.contains("* SEARCH 1\r\n"), "{response}");
	}

	#[test]
	fn search_requires_selection_and_valid_criteria() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let response = text(&session.command_line("a2 SEARCH ALL"));
		assert!(response.contains("a2 BAD"), "{response}");
		session.command_line("a3 SELECT INBOX");
		let response = text(&session.command_line("a4 SEARCH BOGUSKEY"));
		assert!(response.contains("a4 BAD"), "{response}");
	}

	#[test]
	fn plaintext_session_disables_login_until_starttls() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session =
			Session::new("mail.example.org", dir.path().to_path_buf(), directory()).with_starttls();

		let greeting = text(&session.greeting());
		assert!(greeting.contains("STARTTLS"), "{greeting}");
		assert!(greeting.contains("LOGINDISABLED"), "{greeting}");
		assert!(!greeting.contains("AUTH=PLAIN"), "{greeting}");

		let output = session.command_line("a1 LOGIN alice secret");
		assert!(
			text(&output).contains("PRIVACYREQUIRED"),
			"{}",
			text(&output)
		);

		let output = session.command_line("a2 STARTTLS");
		assert!(output.upgrade_tls);
		assert!(text(&output).contains("a2 OK"), "{}", text(&output));

		session.tls_started();
		let output = session.command_line("a3 CAPABILITY");
		let response = text(&output);
		assert!(!response.contains("STARTTLS"), "{response}");
		assert!(response.contains("AUTH=PLAIN"), "{response}");
		let output = session.command_line("a4 LOGIN alice secret");
		assert!(text(&output).contains("a4 OK"), "{}", text(&output));
	}

	#[test]
	fn starttls_inside_tls_is_bad() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 STARTTLS");
		assert!(text(&output).contains("a2 BAD"), "{}", text(&output));
		assert!(!output.upgrade_tls);
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

	#[test]
	fn status_reports_counts_for_inbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"one\r\n");
		deliver(dir.path(), b"two\r\n");
		let mut session = logged_in(dir.path());

		let response = text(
			&session.command_line("a2 STATUS INBOX (MESSAGES UIDNEXT UIDVALIDITY UNSEEN RECENT)"),
		);
		assert!(response.contains("MESSAGES 2"), "{response}");
		assert!(response.contains("UNSEEN 2"), "{response}");
		assert!(response.contains("RECENT 0"), "{response}");
		assert!(response.contains("a2 OK STATUS completed"), "{response}");

		// Mark one seen; UNSEEN should drop to 1.
		session.command_line("a3 SELECT INBOX");
		session.command_line(r"a4 STORE 1 +FLAGS (\Seen)");
		session.command_line("a5 CLOSE");
		let response = text(&session.command_line("a6 STATUS INBOX (MESSAGES UNSEEN)"));
		assert!(response.contains("MESSAGES 2"), "{response}");
		assert!(response.contains("UNSEEN 1"), "{response}");
	}

	#[test]
	fn status_requires_authentication_and_existing_mailbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
		let output = session.command_line("a1 STATUS INBOX (MESSAGES)");
		assert!(text(&output).contains("a1 NO"), "{}", text(&output));

		let mut session = logged_in(dir.path());
		let output = session.command_line("a2 STATUS Archive (MESSAGES)");
		assert!(text(&output).contains("a2 NO"), "{}", text(&output));
	}

	#[test]
	fn subscribe_and_lsub_flow() {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut session = logged_in(dir.path());
		session.command_line("a2 CREATE Sent");

		// INBOX always present in LSUB even without explicit SUBSCRIBE.
		let response = text(&session.command_line(r#"a3 LSUB "" "*""#));
		assert!(response.contains("\"INBOX\""), "{response}");
		assert!(response.contains("a3 OK LSUB completed"), "{response}");

		// Subscribe Sent; it must appear.
		let output = session.command_line("a4 SUBSCRIBE Sent");
		assert!(text(&output).contains("a4 OK"), "{}", text(&output));
		let response = text(&session.command_line(r#"a5 LSUB "" "*""#));
		assert!(response.contains("\"Sent\""), "{response}");

		// Unsubscribe Sent; it disappears.
		session.command_line("a6 UNSUBSCRIBE Sent");
		let response = text(&session.command_line(r#"a7 LSUB "" "*""#));
		assert!(!response.contains("\"Sent\""), "{response}");
		assert!(response.contains("\"INBOX\""), "{response}");
	}

	#[test]
	fn internaldate_is_not_epoch() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), b"From: a@x.example\r\n\r\nhi\r\n");
		let mut session = logged_in(dir.path());
		session.command_line("a2 SELECT INBOX");
		let response = text(&session.command_line("a3 FETCH 1 (INTERNALDATE)"));
		// Must not be the epoch placeholder.
		assert!(!response.contains("01-Jan-1970"), "{response}");
		assert!(response.contains("INTERNALDATE"), "{response}");
		assert!(response.contains("a3 OK FETCH completed"), "{response}");
	}

	#[test]
	fn internaldate_format_sanity() {
		// 2024-06-09 12:34:56 UTC = 1717936496 seconds since epoch.
		let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_717_936_496);
		assert_eq!(format_internaldate(t), " 9-Jun-2024 12:34:56 +0000");
		// Epoch itself.
		assert_eq!(
			format_internaldate(std::time::UNIX_EPOCH),
			" 1-Jan-1970 00:00:00 +0000"
		);
		// A date with a two-digit day (no space padding).
		let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_718_000_000);
		let s = format_internaldate(t);
		// 2024-06-10 in UTC; day >= 10 so no leading space.
		assert!(
			!s.starts_with(' '),
			"expected no leading space for day >= 10: {s}"
		);
	}
}
