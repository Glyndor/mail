//! Crash-safe filesystem spool for accepted messages.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

/// Envelope metadata stored next to the raw message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
	/// Spool id (UUID v7: time-ordered).
	pub id: Uuid,
	/// SMTP reverse-path (empty for bounces).
	pub reverse_path: String,
	/// Accepted recipients.
	pub recipients: Vec<String>,
}

/// One spooled message: envelope plus raw message bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolEntry {
	pub envelope: Envelope,
	pub data: Vec<u8>,
}

/// Filesystem spool rooted at `<data_dir>/spool`.
#[derive(Debug)]
pub struct FsSpool {
	root: PathBuf,
}

impl FsSpool {
	/// Open (creating if needed) the spool under `data_dir`.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let root = data_dir.join("spool");
		fs::create_dir_all(root.join("tmp"))?;
		fs::create_dir_all(root.join("new"))?;
		Ok(FsSpool { root })
	}

	/// Persist one message crash-safely and return its spool id.
	///
	/// Both files are first written and fsynced under `tmp/`, then renamed
	/// into `new/` — envelope last, so a visible envelope guarantees a
	/// complete message file next to it.
	pub fn store(&self, message: &AcceptedMessage) -> std::io::Result<Uuid> {
		let id = Uuid::now_v7();
		let envelope = Envelope {
			id,
			reverse_path: message.reverse_path.clone(),
			recipients: message.recipients.clone(),
		};

		let tmp_message = self.root.join("tmp").join(format!("{id}.eml"));
		let tmp_envelope = self.root.join("tmp").join(format!("{id}.json"));
		let final_message = self.root.join("new").join(format!("{id}.eml"));
		let final_envelope = self.root.join("new").join(format!("{id}.json"));

		write_sync(&tmp_message, &message.data)?;
		let envelope_bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
		write_sync(&tmp_envelope, &envelope_bytes)?;

		fs::rename(&tmp_message, &final_message)?;
		fs::rename(&tmp_envelope, &final_envelope)?;
		Ok(id)
	}

	/// Load one spooled entry by id.
	pub fn load(&self, id: Uuid) -> std::io::Result<SpoolEntry> {
		let envelope_bytes = fs::read(self.root.join("new").join(format!("{id}.json")))?;
		let envelope: Envelope =
			serde_json::from_slice(&envelope_bytes).map_err(std::io::Error::other)?;
		let data = fs::read(self.root.join("new").join(format!("{id}.eml")))?;
		Ok(SpoolEntry { envelope, data })
	}

	/// List ids of all complete spooled messages, oldest first.
	pub fn list(&self) -> std::io::Result<Vec<Uuid>> {
		let mut ids = Vec::new();
		for entry in fs::read_dir(self.root.join("new"))? {
			let entry = entry?;
			let name = entry.file_name();
			let Some(name) = name.to_str() else {
				continue;
			};
			if let Some(stem) = name.strip_suffix(".json")
				&& let Ok(id) = Uuid::parse_str(stem)
			{
				ids.push(id);
			}
		}
		// UUID v7 sorts chronologically.
		ids.sort();
		Ok(ids)
	}

	/// Remove a spooled message after successful processing.
	pub fn remove(&self, id: Uuid) -> std::io::Result<()> {
		// Envelope first: a message file without an envelope is invisible.
		fs::remove_file(self.root.join("new").join(format!("{id}.json")))?;
		fs::remove_file(self.root.join("new").join(format!("{id}.eml")))?;
		Ok(())
	}
}

impl MessageSink for FsSpool {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.store(&message)
			.map(|_| ())
			.map_err(|error| SinkError::Unavailable(error.to_string()))
	}
}

/// Write `bytes` to `path` and fsync the file before returning.
fn write_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
	let mut file = fs::File::create(path)?;
	file.write_all(bytes)?;
	file.sync_all()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample_message() -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: "alice@example.org".into(),
			recipients: vec!["bob@example.org".into()],
			data: b"Subject: hi\r\n\r\nhello\r\n".to_vec(),
		}
	}

	#[test]
	fn stores_and_loads_roundtrip() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let id = spool.store(&sample_message()).expect("store");
		let entry = spool.load(id).expect("load");

		assert_eq!(entry.envelope.id, id);
		assert_eq!(entry.envelope.reverse_path, "alice@example.org");
		assert_eq!(
			entry.envelope.recipients,
			vec!["bob@example.org".to_string()]
		);
		assert_eq!(entry.data, sample_message().data);
	}

	#[test]
	fn list_returns_ids_oldest_first() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let first = spool.store(&sample_message()).expect("store first");
		let second = spool.store(&sample_message()).expect("store second");

		assert_eq!(spool.list().expect("list"), vec![first, second]);
	}

	#[test]
	fn remove_deletes_both_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");

		let id = spool.store(&sample_message()).expect("store");
		spool.remove(id).expect("remove");

		assert!(spool.list().expect("list").is_empty());
		assert!(spool.load(id).is_err());
	}

	#[test]
	fn load_unknown_id_fails() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		assert!(spool.load(Uuid::now_v7()).is_err());
	}

	#[test]
	fn list_ignores_foreign_files() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		fs::write(dir.path().join("spool/new/readme.txt"), b"not mail").expect("write");
		fs::write(dir.path().join("spool/new/bad.json"), b"{}").expect("write");
		assert!(spool.list().expect("list").is_empty());
	}

	#[test]
	fn incomplete_tmp_files_are_invisible() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		// Simulate a crash: files in tmp/ never renamed.
		fs::write(dir.path().join("spool/tmp/crash.eml"), b"partial").expect("write");
		assert!(spool.list().expect("list").is_empty());
	}

	#[test]
	fn sink_implementation_stores_messages() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = FsSpool::open(dir.path()).expect("open spool");
		spool.deliver(sample_message()).expect("deliver");
		assert_eq!(spool.list().expect("list").len(), 1);
	}

	#[test]
	fn open_fails_on_unwritable_root() {
		let result = FsSpool::open(Path::new("/proc/no-such-dir"));
		assert!(result.is_err());
	}
}
