//! Filesystem-backed mailbox view: INBOX from `accounts/<name>/new/`.

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
}

impl Snapshot {
	/// Build the INBOX snapshot for an account under `data_dir`.
	pub fn inbox(data_dir: &Path, account: &str) -> std::io::Result<Snapshot> {
		let account_dir = data_dir.join("accounts").join(account).join("new");
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
			let size = std::fs::metadata(account_dir.join(format!("{id}.eml")))
				.map(|metadata| metadata.len())
				.unwrap_or(0);
			messages.push(MessageRef {
				// Snapshot UIDs: position in the time-ordered listing.
				uid: u32::try_from(index + 1).unwrap_or(u32::MAX),
				id: *id,
				size,
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
		let snapshot = Snapshot::inbox(dir.path(), "alice").expect("snapshot");
		assert!(snapshot.is_empty());
		assert_eq!(snapshot.uid_validity(), 1);
		assert_eq!(snapshot.uid_next(), 1);
	}

	#[test]
	fn messages_are_ordered_and_readable() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"first\r\n");
		deliver(dir.path(), "alice", b"second\r\n");

		let snapshot = Snapshot::inbox(dir.path(), "alice").expect("snapshot");
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
	fn ignores_foreign_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		deliver(dir.path(), "alice", b"mail\r\n");
		std::fs::write(dir.path().join("accounts/alice/new/notes.txt"), b"not mail")
			.expect("write");
		let snapshot = Snapshot::inbox(dir.path(), "alice").expect("snapshot");
		assert_eq!(snapshot.len(), 1);
	}
}
