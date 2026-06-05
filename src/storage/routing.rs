//! Delivery routing: local recipients to mailboxes, remote to the queue.

use std::sync::Arc;

use crate::smtp::address::Address;
use crate::smtp::directory::{Directory, Resolution};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};

use super::delivery::LocalDelivery;
use super::spool::FsSpool;

/// Splits an accepted message between local mailbox delivery and the
/// outbound spool, according to the directory.
#[derive(Debug)]
pub struct SplitDelivery {
	directory: Arc<Directory>,
	local: LocalDelivery,
	outbound: FsSpool,
}

impl SplitDelivery {
	/// Create the routing sink rooted at `data_dir`.
	pub fn new(data_dir: &std::path::Path, directory: Arc<Directory>) -> std::io::Result<Self> {
		Ok(SplitDelivery {
			local: LocalDelivery::new(data_dir, Arc::clone(&directory))?,
			outbound: FsSpool::open(data_dir)?,
			directory,
		})
	}
}

impl MessageSink for SplitDelivery {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		let mut local = Vec::new();
		let mut remote = Vec::new();
		for recipient in &message.recipients {
			let address = Address::parse(recipient).map_err(|_| {
				SinkError::Unavailable(format!("unparseable recipient {recipient}"))
			})?;
			match self.directory.resolve(&address) {
				Resolution::Account(_) => local.push(recipient.clone()),
				Resolution::NotLocal => remote.push(recipient.clone()),
				// The session rejected unknown local users; drift here is
				// a logic error and the whole delivery fails closed.
				Resolution::UnknownUser => {
					return Err(SinkError::Unavailable(format!(
						"recipient {recipient} no longer resolves"
					)));
				}
			}
		}

		if !local.is_empty() {
			self.local.deliver(AcceptedMessage {
				recipients: local,
				..message.clone()
			})?;
		}
		if !remote.is_empty() {
			self.outbound
				.store(&AcceptedMessage {
					recipients: remote,
					..message
				})
				.map_err(|error| SinkError::Unavailable(error.to_string()))?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	fn directory() -> Arc<Directory> {
		Arc::new(Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		))
	}

	fn message(recipients: &[&str]) -> AcceptedMessage {
		AcceptedMessage {
			reverse_path: "alice@example.org".into(),
			recipients: recipients.iter().map(|r| r.to_string()).collect(),
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		}
	}

	fn inbox_count(root: &std::path::Path, account: &str) -> usize {
		fs::read_dir(root.join("accounts").join(account).join("new"))
			.map(|entries| entries.count())
			.unwrap_or(0)
	}

	fn spool_count(root: &std::path::Path) -> usize {
		FsSpool::open(root)
			.expect("open spool")
			.list()
			.expect("list")
			.len()
	}

	#[test]
	fn local_only_message_skips_the_spool() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["alice@example.org"]))
			.expect("deliver");
		assert_eq!(inbox_count(dir.path(), "alice"), 1);
		assert_eq!(spool_count(dir.path()), 0);
	}

	#[test]
	fn remote_only_message_goes_to_the_spool() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["bob@elsewhere.example"]))
			.expect("deliver");
		assert_eq!(inbox_count(dir.path(), "alice"), 0);
		assert_eq!(spool_count(dir.path()), 1);
	}

	#[test]
	fn mixed_message_is_split() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		sink.deliver(message(&["alice@example.org", "bob@elsewhere.example"]))
			.expect("deliver");
		assert_eq!(inbox_count(dir.path(), "alice"), 1);

		let spool = FsSpool::open(dir.path()).expect("spool");
		let ids = spool.list().expect("list");
		assert_eq!(ids.len(), 1);
		let entry = spool.load(ids[0]).expect("load");
		// Only the remote recipient is queued for outbound delivery.
		assert_eq!(
			entry.envelope.recipients,
			vec!["bob@elsewhere.example".to_string()]
		);
	}

	#[test]
	fn unknown_local_user_fails_closed() {
		let dir = tempfile::tempdir().expect("tempdir");
		let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
		let result = sink.deliver(message(&["stranger@example.org"]));
		assert!(result.is_err());
		assert_eq!(spool_count(dir.path()), 0);
	}
}
