//! Destination for messages accepted by the SMTP server.

use super::session::AcceptedMessage;

/// Receives accepted messages. The real implementation will be the storage
/// layer; tests and early milestones use the in-memory sink.
pub trait MessageSink: Send + Sync {
	/// Persist an accepted message. Returning an error makes the server
	/// answer with a transient failure so the client retries later.
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError>;
}

/// Why a delivery could not be accepted.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
	#[error("storage unavailable: {0}")]
	Unavailable(String),
}

/// In-memory sink: collects messages, for tests and early development.
#[derive(Debug, Default)]
pub struct MemorySink {
	messages: std::sync::Mutex<Vec<AcceptedMessage>>,
}

impl MemorySink {
	/// Create an empty sink.
	pub fn new() -> Self {
		Self::default()
	}

	/// Messages delivered so far.
	pub fn messages(&self) -> Vec<AcceptedMessage> {
		self.messages.lock().expect("sink mutex poisoned").clone()
	}
}

impl MessageSink for MemorySink {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.messages
			.lock()
			.map_err(|_| SinkError::Unavailable("sink mutex poisoned".into()))?
			.push(message);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn memory_sink_collects_messages() {
		let sink = MemorySink::new();
		let message = AcceptedMessage {
			reverse_path: "a@example.org".into(),
			recipients: vec!["b@example.org".into()],
			data: b"hello\r\n".to_vec(),
		};
		sink.deliver(message.clone()).expect("delivery succeeds");
		assert_eq!(sink.messages(), vec![message]);
	}
}
