//! The queue worker: drains the outbound spool.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::smtp::address::Address;
use crate::storage::FsSpool;

use super::client::{self, DeliveryError};
use super::resolver::Connector;

/// Maximum delivery attempts per spool entry before it is dropped.
/// Attempt counting is in-memory for now; a restart starts over.
const MAX_ATTEMPTS: u32 = 10;

/// Outbound queue worker.
pub struct Worker {
	spool: FsSpool,
	connector: Arc<dyn Connector>,
	ehlo_hostname: String,
	attempts: std::sync::Mutex<BTreeMap<uuid::Uuid, u32>>,
}

impl Worker {
	/// Create a worker draining `spool` through `connector`.
	pub fn new(spool: FsSpool, connector: Arc<dyn Connector>, ehlo_hostname: &str) -> Self {
		Worker {
			spool,
			connector,
			ehlo_hostname: ehlo_hostname.to_string(),
			attempts: std::sync::Mutex::new(BTreeMap::new()),
		}
	}

	/// Run forever, scanning the spool periodically.
	pub async fn run(self: Arc<Self>, interval: Duration) {
		loop {
			if let Err(error) = self.pass().await {
				tracing::warn!(%error, "queue pass failed");
			}
			tokio::time::sleep(interval).await;
		}
	}

	/// One pass over the spool. Returns the number of delivered entries.
	pub async fn pass(&self) -> std::io::Result<usize> {
		let mut delivered = 0;
		for id in self.spool.list()? {
			match self.deliver_entry(id).await {
				Outcome::Delivered => {
					self.spool.remove(id)?;
					self.attempts.lock().expect("attempts mutex").remove(&id);
					delivered += 1;
				}
				Outcome::Dropped(reason) => {
					tracing::warn!(%id, %reason, "dropping undeliverable message");
					self.spool.remove(id)?;
					self.attempts.lock().expect("attempts mutex").remove(&id);
				}
				Outcome::Retry(reason) => {
					let attempts = {
						let mut attempts = self.attempts.lock().expect("attempts mutex");
						let entry = attempts.entry(id).or_insert(0);
						*entry += 1;
						*entry
					};
					if attempts >= MAX_ATTEMPTS {
						tracing::warn!(%id, %reason, attempts, "giving up on message");
						self.spool.remove(id)?;
						self.attempts.lock().expect("attempts mutex").remove(&id);
					} else {
						tracing::debug!(%id, %reason, attempts, "delivery deferred");
					}
				}
			}
		}
		Ok(delivered)
	}

	async fn deliver_entry(&self, id: uuid::Uuid) -> Outcome {
		let entry = match self.spool.load(id) {
			Ok(entry) => entry,
			Err(error) => return Outcome::Retry(format!("spool read failed: {error}")),
		};

		// Group recipients by domain: one conversation per exchanger.
		let mut by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
		for recipient in &entry.envelope.recipients {
			let Ok(address) = Address::parse(recipient) else {
				return Outcome::Dropped(format!("unparseable recipient {recipient}"));
			};
			by_domain
				.entry(address.domain().to_string())
				.or_default()
				.push(recipient.clone());
		}

		for (domain, recipients) in by_domain {
			let (stream, server_name) = match self.connector.connect(&domain).await {
				Ok(connection) => connection,
				Err(DeliveryError::Transient(reason)) => return Outcome::Retry(reason),
				Err(DeliveryError::Permanent(reason)) => return Outcome::Dropped(reason),
			};
			let result = client::deliver(
				stream,
				&server_name,
				&self.ehlo_hostname,
				&entry.envelope.reverse_path,
				&recipients,
				&entry.data,
			)
			.await;
			match result {
				Ok(()) => {}
				Err(DeliveryError::Transient(reason)) => return Outcome::Retry(reason),
				Err(DeliveryError::Permanent(reason)) => return Outcome::Dropped(reason),
			}
		}
		Outcome::Delivered
	}
}

enum Outcome {
	Delivered,
	Retry(String),
	Dropped(String),
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::queue::resolver::{BoxedStream, ConnectFuture};
	use crate::smtp::directory::Directory;
	use crate::smtp::server::Server;
	use crate::smtp::session::AcceptedMessage;
	use crate::smtp::sink::{MemorySink, MessageSink};

	/// Connector that hands out duplex pipes served by an in-process server.
	struct LoopbackConnector {
		sink: Arc<MemorySink>,
		/// Domains the fake remote server accepts mail for.
		domain: String,
	}

	impl Connector for LoopbackConnector {
		fn connect(&self, _domain: &str) -> ConnectFuture<'_> {
			Box::pin(async move {
				let directory = Arc::new(Directory::new(
					[self.domain.clone()],
					[(format!("bob@{}", self.domain), "bob".to_string())],
				));
				let server = Server::new(
					"mx.remote.example",
					self.sink.clone() as Arc<dyn MessageSink>,
				)
				.with_directory(directory);
				let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
				tokio::spawn(async move { server.handle(server_stream, None).await });
				Ok((
					Box::new(client_stream) as BoxedStream,
					"mx.remote.example".to_string(),
				))
			})
		}
	}

	/// Connector that always fails with a transient error.
	struct DownConnector;

	impl Connector for DownConnector {
		fn connect(&self, _domain: &str) -> ConnectFuture<'_> {
			Box::pin(async { Err(DeliveryError::Transient("connection refused".into())) })
		}
	}

	fn spool_with_message(dir: &std::path::Path, recipient: &str) -> FsSpool {
		let spool = FsSpool::open(dir).expect("open spool");
		spool
			.store(&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec![recipient.to_string()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			})
			.expect("store");
		spool
	}

	#[tokio::test]
	async fn delivers_and_clears_the_spool() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = spool_with_message(dir.path(), "bob@remote.example");
		let sink = Arc::new(MemorySink::new());
		let connector = Arc::new(LoopbackConnector {
			sink: sink.clone(),
			domain: "remote.example".to_string(),
		});

		let worker = Worker::new(spool, connector, "mail.sender.example");
		let delivered = worker.pass().await.expect("pass");

		assert_eq!(delivered, 1);
		assert!(worker.spool.list().expect("list").is_empty());
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		assert_eq!(
			messages[0].recipients,
			vec!["bob@remote.example".to_string()]
		);
	}

	#[tokio::test]
	async fn permanent_rejection_drops_the_entry() {
		let dir = tempfile::tempdir().expect("tempdir");
		// The loopback server only knows bob@; carol@ gets 550.
		let spool = spool_with_message(dir.path(), "carol@remote.example");
		let sink = Arc::new(MemorySink::new());
		let connector = Arc::new(LoopbackConnector {
			sink: sink.clone(),
			domain: "remote.example".to_string(),
		});

		let worker = Worker::new(spool, connector, "mail.sender.example");
		let delivered = worker.pass().await.expect("pass");

		assert_eq!(delivered, 0);
		// Dropped, not retried: the spool is empty and nothing arrived.
		assert!(worker.spool.list().expect("list").is_empty());
		assert!(sink.messages().is_empty());
	}

	#[tokio::test]
	async fn transient_failure_keeps_the_entry_until_max_attempts() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = spool_with_message(dir.path(), "bob@remote.example");
		let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example");

		for _ in 0..MAX_ATTEMPTS - 1 {
			assert_eq!(worker.pass().await.expect("pass"), 0);
			assert_eq!(worker.spool.list().expect("list").len(), 1);
		}
		// The final attempt gives up and drops the entry.
		assert_eq!(worker.pass().await.expect("pass"), 0);
		assert!(worker.spool.list().expect("list").is_empty());
	}
}
