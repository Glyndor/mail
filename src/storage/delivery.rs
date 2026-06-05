//! Local delivery: accepted inbound messages land in account mailboxes.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;

use crate::smtp::address::Address;
use crate::smtp::directory::{Directory, Resolution};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use super::spool::write_sync;

/// Delivers messages into `data_dir/accounts/<account>/new/`, one crash-safe
/// copy per distinct recipient account.
#[derive(Debug)]
pub struct LocalDelivery {
	accounts_root: PathBuf,
	directory: Arc<Directory>,
}

impl LocalDelivery {
	/// Create a local delivery sink rooted at `data_dir`. Creates the
	/// accounts directory eagerly so an unwritable data_dir fails at
	/// startup, not on first delivery.
	pub fn new(data_dir: &std::path::Path, directory: Arc<Directory>) -> std::io::Result<Self> {
		let accounts_root = data_dir.join("accounts");
		fs::create_dir_all(&accounts_root)?;
		Ok(LocalDelivery {
			accounts_root,
			directory,
		})
	}

	/// Resolve recipients to their distinct accounts. The session already
	/// rejected unresolvable recipients; hitting one here is a logic error
	/// and fails the whole delivery (fail closed, client retries).
	fn accounts_for(&self, message: &AcceptedMessage) -> Result<BTreeSet<String>, SinkError> {
		let mut accounts = BTreeSet::new();
		for recipient in &message.recipients {
			let address = Address::parse(recipient).map_err(|_| {
				SinkError::Unavailable(format!("unparseable recipient {recipient}"))
			})?;
			match self.directory.resolve(&address) {
				Resolution::Account(account) => {
					accounts.insert(account);
				}
				_ => {
					return Err(SinkError::Unavailable(format!(
						"recipient {recipient} no longer resolves to an account"
					)));
				}
			}
		}
		Ok(accounts)
	}

	fn deliver_to_account(&self, account: &str, data: &[u8]) -> std::io::Result<Uuid> {
		let id = Uuid::now_v7();
		let account_dir = self.accounts_root.join(account);
		let tmp_dir = account_dir.join("tmp");
		let new_dir = account_dir.join("new");
		fs::create_dir_all(&tmp_dir)?;
		fs::create_dir_all(&new_dir)?;

		let tmp_path = tmp_dir.join(format!("{id}.eml"));
		write_sync(&tmp_path, data)?;
		fs::rename(&tmp_path, new_dir.join(format!("{id}.eml")))?;
		Ok(id)
	}
}

impl MessageSink for LocalDelivery {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		let accounts = self.accounts_for(&message)?;
		if accounts.is_empty() {
			return Err(SinkError::Unavailable("no recipient accounts".into()));
		}
		for account in &accounts {
			self.deliver_to_account(account, &message.data)
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn directory() -> Arc<Directory> {
		Arc::new(Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("also-alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		))
	}

	fn message(recipients: &[&str]) -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: "sender@elsewhere.example".into(),
			recipients: recipients.iter().map(|r| r.to_string()).collect(),
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		}
	}

	fn list_inbox(root: &std::path::Path, account: &str) -> Vec<PathBuf> {
		let dir = root.join("accounts").join(account).join("new");
		match fs::read_dir(dir) {
			Ok(entries) => entries.map(|e| e.expect("entry").path()).collect(),
			Err(_) => Vec::new(),
		}
	}

	#[test]
	fn delivers_one_copy_per_account() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");

		delivery
			.deliver(message(&[
				"alice@example.org",
				"also-alice@example.org",
				"bob@example.org",
			]))
			.expect("delivery succeeds");

		// Two addresses for alice still mean one copy.
		assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
		assert_eq!(list_inbox(dir.path(), "bob").len(), 1);
	}

	#[test]
	fn delivered_file_contains_message_data() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("delivery succeeds");

		let files = list_inbox(dir.path(), "alice");
		let content = fs::read(&files[0]).expect("read delivered file");
		assert_eq!(content, b"Subject: hi\r\n\r\nbody\r\n");
	}

	#[test]
	fn unresolvable_recipient_fails_delivery() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		let result = delivery.deliver(message(&["stranger@example.org"]));
		assert!(result.is_err());
		assert!(list_inbox(dir.path(), "alice").is_empty());
	}

	#[test]
	fn empty_recipient_list_fails_delivery() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		assert!(delivery.deliver(message(&[])).is_err());
	}

	#[test]
	fn tmp_leftovers_are_not_visible_in_inbox() {
		let dir = tempfile::tempdir().expect("tempdir");
		let delivery = LocalDelivery::new(dir.path(), directory()).expect("create delivery");
		delivery
			.deliver(message(&["alice@example.org"]))
			.expect("delivery succeeds");
		// Simulate a crashed write.
		fs::write(dir.path().join("accounts/alice/tmp/crash.eml"), b"partial").expect("write tmp");
		assert_eq!(list_inbox(dir.path(), "alice").len(), 1);
	}
}
