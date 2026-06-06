//! The queue worker: drains the outbound spool.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::smtp::address::Address;
use crate::smtp::sink::MessageSink;
use crate::storage::FsSpool;

use super::client::{self, DeliveryError};
use super::resolver::Connector;

/// Maximum delivery attempts per spool entry before it is dropped.
/// Counts persist in the envelope, so restarts do not reset them.
const MAX_ATTEMPTS: u32 = 10;

/// Base retry delay; attempt n waits `base * 2^n`, capped at one hour.
const BACKOFF_BASE_SECS: u64 = 60;
const BACKOFF_CAP_SECS: u64 = 3600;

/// When attempt number `attempts` may run, given the current time.
fn backoff_until(now_epoch: u64, attempts: u32) -> u64 {
	let delay = BACKOFF_BASE_SECS
		.saturating_mul(1u64 << attempts.min(16))
		.min(BACKOFF_CAP_SECS);
	now_epoch.saturating_add(delay)
}

/// Outbound queue worker.
pub struct Worker {
	spool: FsSpool,
	connector: Arc<dyn Connector>,
	ehlo_hostname: String,
	/// Where bounces are delivered. `None` drops them with a warning.
	bounce_sink: Option<Arc<dyn MessageSink>>,
	/// MTA-STS policy store plus the DNS used for discovery.
	mta_sts: Option<(
		Arc<crate::mtasts::PolicyStore>,
		Arc<dyn crate::spf::DnsLookup>,
	)>,
	/// Test override for "now" (epoch seconds); 0 means the real clock.
	clock: std::sync::atomic::AtomicU64,
}

impl Worker {
	/// Create a worker draining `spool` through `connector`.
	pub fn new(spool: FsSpool, connector: Arc<dyn Connector>, ehlo_hostname: &str) -> Self {
		Worker {
			spool,
			connector,
			ehlo_hostname: ehlo_hostname.to_string(),
			bounce_sink: None,
			mta_sts: None,
			clock: std::sync::atomic::AtomicU64::new(0),
		}
	}

	/// Enforce MTA-STS policies on outbound delivery.
	pub fn with_mta_sts(
		mut self,
		store: Arc<crate::mtasts::PolicyStore>,
		dns: Arc<dyn crate::spf::DnsLookup>,
	) -> Self {
		self.mta_sts = Some((store, dns));
		self
	}

	#[cfg(test)]
	fn set_now(&self, epoch: u64) {
		self.clock
			.store(epoch, std::sync::atomic::Ordering::Relaxed);
	}

	fn now_epoch(&self) -> u64 {
		let test_clock = self.clock.load(std::sync::atomic::Ordering::Relaxed);
		if test_clock != 0 {
			return test_clock;
		}
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	}

	/// Deliver bounces for failed mail through this sink.
	pub fn with_bounce_sink(mut self, sink: Arc<dyn MessageSink>) -> Self {
		self.bounce_sink = Some(sink);
		self
	}

	/// Generate and deliver a bounce for a dropped spool entry.
	fn bounce(&self, id: uuid::Uuid, reason: &str) {
		let Ok(entry) = self.spool.load(id) else {
			return;
		};
		let Some(message) = super::bounce::build(
			&self.ehlo_hostname,
			&entry.envelope.reverse_path,
			&entry.envelope.recipients,
			reason,
			&entry.data,
			std::time::SystemTime::now(),
		) else {
			return;
		};
		match &self.bounce_sink {
			Some(sink) => {
				if let Err(error) = sink.deliver(message) {
					tracing::warn!(%id, %error, "bounce delivery failed");
				}
			}
			None => tracing::warn!(%id, "dropping bounce: no bounce sink configured"),
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
		let now = self.now_epoch();
		let mut delivered = 0;
		for id in self.spool.list()? {
			// Skip entries whose backoff has not elapsed yet.
			match self.spool.load(id) {
				Ok(entry) if entry.envelope.next_attempt > now => continue,
				Ok(_) => {}
				// Vanished or unreadable: let deliver_entry classify it.
				Err(_) => {}
			}
			match self.deliver_entry(id).await {
				Outcome::Delivered => {
					self.spool.remove(id)?;
					delivered += 1;
				}
				Outcome::Dropped(reason) => {
					tracing::warn!(%id, %reason, "dropping undeliverable message");
					self.bounce(id, &reason);
					self.spool.remove(id)?;
				}
				Outcome::Retry(reason) => {
					let prior = self
						.spool
						.load(id)
						.map(|entry| entry.envelope.attempts)
						.unwrap_or(MAX_ATTEMPTS);
					let attempts = self
						.spool
						.record_attempt(id, backoff_until(now, prior + 1))
						.unwrap_or(MAX_ATTEMPTS);
					if attempts >= MAX_ATTEMPTS {
						tracing::warn!(%id, %reason, attempts, "giving up on message");
						self.bounce(id, &reason);
						self.spool.remove(id)?;
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
			// MTA-STS: an enforce policy constrains MX choice and mandates TLS.
			let policy = match &self.mta_sts {
				Some((store, dns)) => match store.policy(dns.as_ref(), &domain).await {
					Ok(policy) => {
						policy.filter(|policy| policy.mode == crate::mtasts::Mode::Enforce)
					}
					Err(crate::mtasts::PolicyError::Temporary(reason)) => {
						return Outcome::Retry(reason);
					}
					// Malformed/absent policies fall back to opportunistic.
					Err(_) => None,
				},
				None => None,
			};
			let require_tls = policy.is_some();

			let (stream, server_name) = match self.connector.connect(&domain, policy.as_ref()).await
			{
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
				require_tls,
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
		fn connect(
			&self,
			_domain: &str,
			_policy: Option<&crate::mtasts::Policy>,
		) -> ConnectFuture<'_> {
			Box::pin(async move {
				let directory = crate::directory_store::DirectoryHandle::new(Directory::new(
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
		fn connect(
			&self,
			_domain: &str,
			_policy: Option<&crate::mtasts::Policy>,
		) -> ConnectFuture<'_> {
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
	async fn permanent_rejection_drops_and_bounces() {
		let dir = tempfile::tempdir().expect("tempdir");
		// The loopback server only knows bob@; carol@ gets 550.
		let spool = spool_with_message(dir.path(), "carol@remote.example");
		let sink = Arc::new(MemorySink::new());
		let connector = Arc::new(LoopbackConnector {
			sink: sink.clone(),
			domain: "remote.example".to_string(),
		});
		let bounce_sink = Arc::new(MemorySink::new());

		let worker = Worker::new(spool, connector, "mail.sender.example")
			.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>);
		let delivered = worker.pass().await.expect("pass");

		assert_eq!(delivered, 0);
		// Dropped, not retried: the spool is empty and nothing arrived.
		assert!(worker.spool.list().expect("list").is_empty());
		assert!(sink.messages().is_empty());

		// The sender got a bounce with the null reverse-path.
		let bounces = bounce_sink.messages();
		assert_eq!(bounces.len(), 1);
		assert_eq!(bounces[0].reverse_path, "");
		assert_eq!(
			bounces[0].recipients,
			vec!["alice@sender.example".to_string()]
		);
		let body = String::from_utf8(bounces[0].data.clone()).expect("ascii");
		assert!(body.contains("carol@remote.example"), "{body}");
	}

	#[tokio::test]
	async fn retry_exhaustion_bounces_once() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = spool_with_message(dir.path(), "bob@remote.example");
		let bounce_sink = Arc::new(MemorySink::new());
		let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example")
			.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>);

		for round in 0..MAX_ATTEMPTS {
			// Jump past every backoff window so each pass really retries.
			worker.set_now(1_000_000 + u64::from(round) * 10_000);
			let _ = worker.pass().await.expect("pass");
		}
		assert!(worker.spool.list().expect("list").is_empty());
		assert_eq!(bounce_sink.messages().len(), 1);
	}

	#[tokio::test]
	async fn transient_failure_keeps_the_entry_until_max_attempts() {
		let dir = tempfile::tempdir().expect("tempdir");
		let spool = spool_with_message(dir.path(), "bob@remote.example");
		let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example");

		for round in 0..MAX_ATTEMPTS - 1 {
			worker.set_now(1_000_000 + u64::from(round) * 10_000);
			assert_eq!(worker.pass().await.expect("pass"), 0);
			assert_eq!(worker.spool.list().expect("list").len(), 1);
		}
		// Within the backoff window nothing is attempted.
		assert_eq!(worker.pass().await.expect("pass"), 0);
		assert_eq!(worker.spool.list().expect("list").len(), 1);
		// The final attempt gives up and drops the entry.
		worker.set_now(2_000_000);
		assert_eq!(worker.pass().await.expect("pass"), 0);
		assert!(worker.spool.list().expect("list").is_empty());
	}
}
