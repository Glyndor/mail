//! Filesystem-backed mailboxes: INBOX at `accounts/<name>/new/`, other
//! mailboxes under `accounts/<name>/folders/<mailbox>/new/`.

use std::path::{Path, PathBuf};

use uuid::Uuid;

/// A snapshot of one mailbox at SELECT time. Sequence numbers are positions
/// in `messages` (1-based); UIDs derive from the time-ordered UUID v7 names.
#[derive(Debug)]
pub struct Snapshot {
	account_dir: PathBuf,
	messages: Vec<MessageRef>,
	uid_validity: u32,
}

/// One message in the snapshot.
#[derive(Debug, Clone)]
pub struct MessageRef {
	pub uid: u32,
	id: Uuid,
	pub size: u64,
	pub flags: Vec<Flag>,
	/// File mtime; used for INTERNALDATE.
	pub internal_date: std::time::SystemTime,
}

/// Supported permanent flags (RFC 9051 section 2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Flag {
	Seen,
	Answered,
	Flagged,
	Deleted,
	Draft,
}

impl Flag {
	/// Parse the IMAP flag token.
	pub fn parse(token: &str) -> Option<Flag> {
		match token.to_ascii_lowercase().as_str() {
			"\\seen" => Some(Flag::Seen),
			"\\answered" => Some(Flag::Answered),
			"\\flagged" => Some(Flag::Flagged),
			"\\deleted" => Some(Flag::Deleted),
			"\\draft" => Some(Flag::Draft),
			_ => None,
		}
	}

	/// The wire representation.
	pub fn as_str(self) -> &'static str {
		match self {
			Flag::Seen => "\\Seen",
			Flag::Answered => "\\Answered",
			Flag::Flagged => "\\Flagged",
			Flag::Deleted => "\\Deleted",
			Flag::Draft => "\\Draft",
		}
	}
}

/// Render a flag list for FETCH/STORE responses.
pub fn render_flags(flags: &[Flag]) -> String {
	let tokens: Vec<&str> = flags.iter().map(|flag| flag.as_str()).collect();
	format!("({})", tokens.join(" "))
}

/// Whether a client-supplied mailbox name is safe and supported.
pub fn valid_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= 128
		&& !name.eq_ignore_ascii_case("INBOX")
		&& name
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
		&& !name.starts_with('.')
		&& !name.ends_with(' ')
}

/// The on-disk directory of a mailbox (its `new/` subdirectory).
pub fn mailbox_dir(data_dir: &Path, account: &str, mailbox: &str) -> Option<PathBuf> {
	let base = data_dir.join("accounts").join(account);
	if mailbox.eq_ignore_ascii_case("INBOX") {
		return Some(base.join("new"));
	}
	if !valid_name(mailbox) {
		return None;
	}
	Some(base.join("folders").join(mailbox).join("new"))
}

/// Whether a mailbox exists. INBOX always exists.
pub fn exists(data_dir: &Path, account: &str, mailbox: &str) -> bool {
	if mailbox.eq_ignore_ascii_case("INBOX") {
		return true;
	}
	mailbox_dir(data_dir, account, mailbox).is_some_and(|dir| dir.is_dir())
}

/// Create a mailbox. Fails if invalid or already existing.
pub fn create(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let dir = mailbox_dir(data_dir, account, mailbox)
		.filter(|_| !mailbox.eq_ignore_ascii_case("INBOX"))
		.ok_or_else(|| std::io::Error::other("invalid mailbox name"))?;
	if dir.is_dir() {
		return Err(std::io::Error::other("mailbox already exists"));
	}
	std::fs::create_dir_all(&dir)
}

/// Delete a mailbox and its messages. INBOX cannot be deleted.
pub fn delete(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	if mailbox.eq_ignore_ascii_case("INBOX") || !valid_name(mailbox) {
		return Err(std::io::Error::other("cannot delete this mailbox"));
	}
	let dir = data_dir
		.join("accounts")
		.join(account)
		.join("folders")
		.join(mailbox);
	if !dir.is_dir() {
		return Err(std::io::Error::other("no such mailbox"));
	}
	std::fs::remove_dir_all(dir)
}

/// Rename a mailbox. INBOX cannot be renamed.
pub fn rename(data_dir: &Path, account: &str, from: &str, to: &str) -> std::io::Result<()> {
	if from.eq_ignore_ascii_case("INBOX")
		|| !valid_name(from)
		|| !valid_name(to)
		|| exists(data_dir, account, to)
	{
		return Err(std::io::Error::other("cannot rename"));
	}
	let folders = data_dir.join("accounts").join(account).join("folders");
	if !folders.join(from).is_dir() {
		return Err(std::io::Error::other("no such mailbox"));
	}
	std::fs::rename(folders.join(from), folders.join(to))
}

/// Existing mailbox names: INBOX plus folders, sorted.
pub fn list(data_dir: &Path, account: &str) -> Vec<String> {
	let mut names = vec!["INBOX".to_string()];
	let folders = data_dir.join("accounts").join(account).join("folders");
	if let Ok(entries) = std::fs::read_dir(folders) {
		for entry in entries.flatten() {
			if entry.path().is_dir()
				&& let Some(name) = entry.file_name().to_str()
				&& valid_name(name)
			{
				names.push(name.to_string());
			}
		}
	}
	names[1..].sort();
	names
}

impl Snapshot {
	/// Build the snapshot of any existing mailbox.
	pub fn open(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<Snapshot> {
		let account_dir = mailbox_dir(data_dir, account, mailbox)
			.ok_or_else(|| std::io::Error::other("invalid mailbox name"))?;
		let mut ids: Vec<Uuid> = Vec::new();
		match std::fs::read_dir(&account_dir) {
			Ok(entries) => {
				for entry in entries {
					let entry = entry?;
					let name = entry.file_name();
					let Some(name) = name.to_str() else { continue };
					if let Some(stem) = name.strip_suffix(".eml")
						&& let Ok(id) = Uuid::parse_str(stem)
					{
						ids.push(id);
					}
				}
			}
			// An account that never received mail has no directory yet.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
		ids.sort();

		let mut messages = Vec::with_capacity(ids.len());
		for (index, id) in ids.iter().enumerate() {
			let meta = std::fs::metadata(account_dir.join(format!("{id}.eml")));
			let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
			let internal_date = meta
				.as_ref()
				.ok()
				.and_then(|m| m.modified().ok())
				.unwrap_or(std::time::SystemTime::UNIX_EPOCH);
			let flags = read_flags(&account_dir, *id);
			messages.push(MessageRef {
				// Snapshot UIDs: position in the time-ordered listing.
				uid: u32::try_from(index + 1).unwrap_or(u32::MAX),
				id: *id,
				size,
				flags,
				internal_date,
			});
		}
		Ok(Snapshot {
			account_dir,
			messages,
			// Derived from the newest message so a changed mailbox between
			// sessions changes validity. 1 for an empty mailbox.
			uid_validity: ids.last().map(|id| (id.as_u128() as u32) | 1).unwrap_or(1),
		})
	}

	pub fn len(&self) -> usize {
		self.messages.len()
	}

	pub fn is_empty(&self) -> bool {
		self.messages.is_empty()
	}

	pub fn uid_validity(&self) -> u32 {
		self.uid_validity
	}

	/// Iterator over all messages in sequence order.
	pub fn messages(&self) -> impl Iterator<Item = &MessageRef> {
		self.messages.iter()
	}

	/// Next UID a new message would get.
	pub fn uid_next(&self) -> u32 {
		u32::try_from(self.messages.len() + 1).unwrap_or(u32::MAX)
	}

	/// Message by 1-based sequence number.
	pub fn by_sequence(&self, sequence: u32) -> Option<&MessageRef> {
		self.messages
			.get(usize::try_from(sequence).ok()?.checked_sub(1)?)
	}

	/// Sequence number for a UID.
	pub fn sequence_of_uid(&self, uid: u32) -> Option<u32> {
		self.messages
			.iter()
			.position(|message| message.uid == uid)
			.map(|index| u32::try_from(index + 1).unwrap_or(u32::MAX))
	}

	/// Raw message bytes.
	pub fn read(&self, message: &MessageRef) -> std::io::Result<Vec<u8>> {
		std::fs::read(self.account_dir.join(format!("{}.eml", message.id)))
	}

	/// Replace the flags of the message at `sequence` (1-based), persisting
	/// crash-safely. Returns the new flag set.
	pub fn store_flags(&mut self, sequence: u32, flags: Vec<Flag>) -> std::io::Result<&[Flag]> {
		let index = usize::try_from(sequence)
			.ok()
			.and_then(|s| s.checked_sub(1))
			.filter(|index| *index < self.messages.len())
			.ok_or_else(|| std::io::Error::other("no such message"))?;
		let id = self.messages[index].id;
		write_flags(&self.account_dir, id, &flags)?;
		self.messages[index].flags = flags;
		Ok(&self.messages[index].flags)
	}

	/// Remove one message (file + sidecar) by sequence number.
	pub fn remove_at(&mut self, sequence: u32) -> std::io::Result<()> {
		let index = usize::try_from(sequence)
			.ok()
			.and_then(|s| s.checked_sub(1))
			.filter(|index| *index < self.messages.len())
			.ok_or_else(|| std::io::Error::other("no such message"))?;
		let id = self.messages[index].id;
		std::fs::remove_file(self.account_dir.join(format!("{id}.eml")))?;
		let _ = std::fs::remove_file(self.account_dir.join(format!("{id}.flags")));
		self.messages.remove(index);
		Ok(())
	}

	/// Remove every `\Deleted` message (file + sidecar). Returns the
	/// sequence numbers expunged, in the order responses must be sent
	/// (each number is valid at the moment it is emitted).
	pub fn expunge(&mut self) -> std::io::Result<Vec<u32>> {
		let mut expunged = Vec::new();
		let mut index = 0;
		while index < self.messages.len() {
			if self.messages[index].flags.contains(&Flag::Deleted) {
				let id = self.messages[index].id;
				std::fs::remove_file(self.account_dir.join(format!("{id}.eml")))?;
				let _ = std::fs::remove_file(self.account_dir.join(format!("{id}.flags")));
				self.messages.remove(index);
				expunged.push(u32::try_from(index + 1).unwrap_or(u32::MAX));
			} else {
				index += 1;
			}
		}
		Ok(expunged)
	}
}

/// Append a message to a mailbox crash-safely, with flags.
/// Standalone because APPEND may target a mailbox that is not selected.
pub fn append(
	data_dir: &Path,
	account: &str,
	mailbox: &str,
	flags: &[Flag],
	data: &[u8],
) -> std::io::Result<Uuid> {
	let account_dir = mailbox_dir(data_dir, account, mailbox)
		.ok_or_else(|| std::io::Error::other("invalid mailbox name"))?;
	let tmp_dir = data_dir.join("accounts").join(account).join("tmp");
	std::fs::create_dir_all(&account_dir)?;
	std::fs::create_dir_all(&tmp_dir)?;

	let id = Uuid::now_v7();
	let tmp = tmp_dir.join(format!("{id}.eml"));
	std::fs::write(&tmp, data)?;
	std::fs::rename(&tmp, account_dir.join(format!("{id}.eml")))?;
	if !flags.is_empty() {
		write_flags(&account_dir, id, flags)?;
	}
	Ok(id)
}

/// Subscribe to a mailbox (the mailbox must already exist).
pub fn subscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	if !exists(data_dir, account, mailbox) {
		return Err(std::io::Error::other("no such mailbox"));
	}
	let normalized = if mailbox.eq_ignore_ascii_case("INBOX") {
		"INBOX".to_string()
	} else {
		mailbox.to_string()
	};
	let mut subs = list_subscribed(data_dir, account);
	if !subs.iter().any(|s| s.eq_ignore_ascii_case(&normalized)) {
		subs.push(normalized);
		write_subscriptions(data_dir, account, &subs)?;
	}
	Ok(())
}

/// Remove a subscription. Silently succeeds if not subscribed.
pub fn unsubscribe(data_dir: &Path, account: &str, mailbox: &str) -> std::io::Result<()> {
	let subs: Vec<String> = list_subscribed(data_dir, account)
		.into_iter()
		.filter(|s| !s.eq_ignore_ascii_case(mailbox))
		.collect();
	write_subscriptions(data_dir, account, &subs)
}

/// Subscribed mailboxes; INBOX is always subscribed.
pub fn list_subscribed(data_dir: &Path, account: &str) -> Vec<String> {
	let path = data_dir
		.join("accounts")
		.join(account)
		.join(".subscriptions");
	let mut names: Vec<String> = std::fs::read_to_string(&path)
		.unwrap_or_default()
		.lines()
		.filter(|l| !l.is_empty())
		.map(str::to_string)
		.collect();
	if !names.iter().any(|n| n.eq_ignore_ascii_case("INBOX")) {
		names.insert(0, "INBOX".to_string());
	}
	names
}

fn write_subscriptions(data_dir: &Path, account: &str, names: &[String]) -> std::io::Result<()> {
	let path = data_dir
		.join("accounts")
		.join(account)
		.join(".subscriptions");
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	std::fs::write(
		&path,
		names.iter().fold(String::new(), |mut s, n| {
			s.push_str(n);
			s.push('\n');
			s
		}),
	)
}

fn read_flags(account_dir: &Path, id: Uuid) -> Vec<Flag> {
	std::fs::read(account_dir.join(format!("{id}.flags")))
		.ok()
		.and_then(|bytes| serde_json::from_slice(&bytes).ok())
		.unwrap_or_default()
}

fn write_flags(account_dir: &Path, id: Uuid, flags: &[Flag]) -> std::io::Result<()> {
	let bytes = serde_json::to_vec(flags).map_err(std::io::Error::other)?;
	let tmp = account_dir.join(format!("{id}.flags.tmp"));
	std::fs::write(&tmp, &bytes)?;
	std::fs::rename(&tmp, account_dir.join(format!("{id}.flags")))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn deliver(dir: &Path, account: &str, body: &[u8]) -> Uuid {
		let new_dir = dir.join("accounts").join(account).join("new");
		std::fs::create_dir_all(&new_dir).expect("create dirs");
		let id = Uuid::now_v7();
		std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
		id
	}

	#[test]
	fn empty_or_missing_inbox_is_empty() {
		let dir = tempfile::tempdir().expect("tempdir");
		let snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
		assert!(snapshot.is_empty());
		assert_eq!(snapshot.uid_validity(), 1);
		assert_eq!(snapshot.uid_next(), 1);
	}

	#[test]
	fn messages_are_ordered_and_readable() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"first\r\n");
		deliver(dir.path(), "alice", b"second\r\n");

		let snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
		assert_eq!(snapshot.len(), 2);

		let first = snapshot.by_sequence(1).expect("seq 1");
		let second = snapshot.by_sequence(2).expect("seq 2");
		assert_eq!(first.uid, 1);
		assert_eq!(second.uid, 2);
		assert_eq!(snapshot.read(first).expect("read"), b"first\r\n");
		assert_eq!(snapshot.read(second).expect("read"), b"second\r\n");
		assert_eq!(first.size, 7);
		assert_eq!(snapshot.sequence_of_uid(2), Some(2));
		assert_eq!(snapshot.sequence_of_uid(99), None);
		assert!(snapshot.by_sequence(3).is_none());
		assert!(snapshot.by_sequence(0).is_none());
	}

	#[test]
	fn flags_roundtrip_and_expunge() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"one\r\n");
		deliver(dir.path(), "alice", b"two\r\n");
		deliver(dir.path(), "alice", b"three\r\n");

		let mut snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
		snapshot
			.store_flags(1, vec![Flag::Seen, Flag::Deleted])
			.expect("store");
		snapshot.store_flags(3, vec![Flag::Deleted]).expect("store");

		// A fresh snapshot reads the persisted flags.
		let reloaded = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
		assert_eq!(
			reloaded.by_sequence(1).expect("seq 1").flags,
			vec![Flag::Seen, Flag::Deleted]
		);
		assert!(reloaded.by_sequence(2).expect("seq 2").flags.is_empty());

		let expunged = snapshot.expunge().expect("expunge");
		// Both deletions report sequence numbers valid at emission time:
		// removing seq 1 renumbers old seq 3 to 2.
		assert_eq!(expunged, vec![1, 2]);
		assert_eq!(snapshot.len(), 1);
		assert_eq!(
			snapshot
				.read(snapshot.by_sequence(1).expect("seq 1"))
				.expect("read"),
			b"two\r\n"
		);

		// Files are gone on disk too.
		let after = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
		assert_eq!(after.len(), 1);
	}

	#[test]
	fn store_flags_rejects_bad_sequence() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"one\r\n");
		let mut snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
		assert!(snapshot.store_flags(0, vec![]).is_err());
		assert!(snapshot.store_flags(2, vec![]).is_err());
	}

	#[test]
	fn flag_tokens_parse_and_render() {
		assert_eq!(Flag::parse("\\Seen"), Some(Flag::Seen));
		assert_eq!(Flag::parse("\\DELETED"), Some(Flag::Deleted));
		assert_eq!(Flag::parse("\\Recent"), None);
		assert_eq!(
			render_flags(&[Flag::Seen, Flag::Flagged]),
			"(\\Seen \\Flagged)"
		);
		assert_eq!(render_flags(&[]), "()");
	}

	#[test]
	fn name_validation() {
		assert!(valid_name("Sent"));
		assert!(valid_name("My Folder.2024"));
		assert!(!valid_name("INBOX"));
		assert!(!valid_name("inbox"));
		assert!(!valid_name("../up"));
		assert!(!valid_name("a/b"));
		assert!(!valid_name(".hidden"));
		assert!(!valid_name(""));
		assert!(!valid_name("trailing "));
	}

	#[test]
	fn create_list_rename_delete_roundtrip() {
		let dir = tempfile::tempdir().expect("tempdir");
		create(dir.path(), "alice", "Sent").expect("create");
		assert!(exists(dir.path(), "alice", "Sent"));
		assert!(create(dir.path(), "alice", "Sent").is_err());

		append(dir.path(), "alice", "Sent", &[Flag::Seen], b"sent\r\n").expect("append");
		let snapshot = Snapshot::open(dir.path(), "alice", "Sent").expect("open");
		assert_eq!(snapshot.len(), 1);
		assert_eq!(
			snapshot.by_sequence(1).expect("seq").flags,
			vec![Flag::Seen]
		);

		assert_eq!(list(dir.path(), "alice"), vec!["INBOX", "Sent"]);

		rename(dir.path(), "alice", "Sent", "Outbox").expect("rename");
		assert!(!exists(dir.path(), "alice", "Sent"));
		assert!(exists(dir.path(), "alice", "Outbox"));

		delete(dir.path(), "alice", "Outbox").expect("delete");
		assert!(!exists(dir.path(), "alice", "Outbox"));
		assert!(delete(dir.path(), "alice", "Outbox").is_err());
	}

	#[test]
	fn inbox_is_protected() {
		let dir = tempfile::tempdir().expect("tempdir");
		assert!(create(dir.path(), "alice", "INBOX").is_err());
		assert!(delete(dir.path(), "alice", "INBOX").is_err());
		assert!(rename(dir.path(), "alice", "INBOX", "X").is_err());
		assert!(exists(dir.path(), "alice", "INBOX"));
	}

	#[test]
	fn ignores_foreign_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"mail\r\n");
		std::fs::write(dir.path().join("accounts/alice/new/notes.txt"), b"not mail")
			.expect("write");
		let snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
		assert_eq!(snapshot.len(), 1);
	}
}
