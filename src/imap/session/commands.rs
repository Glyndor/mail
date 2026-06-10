use super::super::command::SequenceSet;
use super::helpers::{format_internaldate, search_matches};
use super::mailbox::{self, Flag, Snapshot, render_flags};
use super::{FetchItem, Output, SearchKey, Session, State, StatusItem, StoreMode};

impl Session {
	pub(super) fn store(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
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

	pub(super) fn copy(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		target: &str,
		uid: bool,
		remove_source: bool,
	) -> Output {
		let data_dir = self.data_dir.clone();
		let State::Selected {
			account,
			snapshot,
			read_only,
			..
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

	pub(super) fn search(&mut self, tag: &str, criteria: &[SearchKey], uid: bool) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut hits = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let matches = criteria
				.iter()
				.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content));
			if matches {
				hits.push(if uid { message.uid } else { seqno });
			}
		}

		let mut response = String::from("* SEARCH");
		for hit in hits {
			response.push_str(&format!(" {hit}"));
		}
		response.push_str(&format!("\r\n{tag} OK SEARCH completed\r\n"));
		Output::text(response)
	}

	pub(super) fn expunge(&mut self, tag: &str) -> Output {
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

	pub(super) fn append_begin(
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

	/// Poll for mailbox changes during IDLE. Refreshes the snapshot and emits
	/// untagged EXISTS/FLAGS responses if the message count changed. Returns
	/// `None` when not in IDLE or no mailbox is selected.
	pub fn check_idle(&mut self) -> Option<Output> {
		self.idle_tag.as_ref()?;
		let State::Selected {
			account,
			mailbox,
			snapshot,
			..
		} = &mut self.state
		else {
			return None;
		};
		let fresh = match Snapshot::open(&self.data_dir, account, mailbox) {
			Ok(s) => s,
			Err(_) => return None,
		};
		if fresh.uid_validity() != snapshot.uid_validity() || fresh.len() != snapshot.len() {
			let exists = fresh.len();
			*snapshot = fresh;
			Some(Output::text(format!("* {exists} EXISTS\r\n")))
		} else {
			None
		}
	}

	pub(super) fn status(&mut self, tag: &str, mailbox: &str, items: &[StatusItem]) -> Output {
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

	pub(super) fn fetch(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
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
