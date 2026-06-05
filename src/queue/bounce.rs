//! Bounce (non-delivery report) generation.

use crate::clock;
use crate::smtp::session::AcceptedMessage;

/// Build a non-delivery report for a failed message.
///
/// The envelope uses the null reverse-path so a failing bounce can never
/// generate another bounce (loop prevention, RFC 5321 section 4.5.5).
/// Returns `None` when the original itself was a bounce.
pub fn build(
	hostname: &str,
	original_reverse_path: &str,
	failed_recipients: &[String],
	reason: &str,
	original_data: &[u8],
	now: std::time::SystemTime,
) -> Option<AcceptedMessage> {
	if original_reverse_path.is_empty() {
		// Never bounce a bounce.
		return None;
	}

	let recipients_block: String = failed_recipients
		.iter()
		.map(|recipient| format!("   {recipient}\r\n"))
		.collect();
	let original_headers = original_header_block(original_data);

	let body = format!(
		"From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
To: <{original_reverse_path}>\r\n\
Subject: Undelivered Mail Returned to Sender\r\n\
Date: {date}\r\n\
Auto-Submitted: auto-replied\r\n\
\r\n\
This is the mail system at host {hostname}.\r\n\
\r\n\
Your message could not be delivered to the following recipients:\r\n\
\r\n\
{recipients_block}\
\r\n\
Reason:\r\n\
   {reason}\r\n\
\r\n\
The message will not be retried. Headers of the original message follow.\r\n\
\r\n\
{original_headers}",
		date = clock::rfc5322(now),
	);

	Some(AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![original_reverse_path.to_string()],
		data: body.into_bytes(),
	})
}

/// The header block of the original message (up to the first empty line),
/// capped so a huge message cannot inflate the bounce.
fn original_header_block(data: &[u8]) -> String {
	const MAX_HEADERS: usize = 4096;
	let end = data
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|position| position + 2)
		.unwrap_or(data.len())
		.min(MAX_HEADERS);
	String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::{Duration, UNIX_EPOCH};

	fn original() -> &'static [u8] {
		b"From: alice@example.org\r\nSubject: hi\r\n\r\nsecret body\r\n"
	}

	#[test]
	fn builds_bounce_to_the_sender() {
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["bob@elsewhere.example".to_string()],
			"550 5.1.1 no such user",
			original(),
			UNIX_EPOCH + Duration::from_secs(1_780_662_896),
		)
		.expect("bounce built");

		assert_eq!(bounce.reverse_path, "");
		assert_eq!(bounce.recipients, vec!["alice@example.org".to_string()]);
		let body = String::from_utf8(bounce.data).expect("ascii");
		assert!(body.contains("MAILER-DAEMON@mail.example.org"), "{body}");
		assert!(body.contains("bob@elsewhere.example"), "{body}");
		assert!(body.contains("550 5.1.1 no such user"), "{body}");
		assert!(body.contains("Subject: hi"), "{body}");
		// The original body must not leak into the bounce.
		assert!(!body.contains("secret body"), "{body}");
		assert!(body.contains("Auto-Submitted: auto-replied"), "{body}");
	}

	#[test]
	fn never_bounces_a_bounce() {
		assert!(
			build(
				"mail.example.org",
				"",
				&["x@example.org".to_string()],
				"reason",
				original(),
				UNIX_EPOCH,
			)
			.is_none()
		);
	}

	#[test]
	fn caps_quoted_headers() {
		let mut huge = b"From: a@example.org\r\n".to_vec();
		huge.extend(std::iter::repeat_n(b'x', 100_000));
		let bounce = build(
			"mail.example.org",
			"alice@example.org",
			&["b@c.example".to_string()],
			"reason",
			&huge,
			UNIX_EPOCH,
		)
		.expect("bounce built");
		assert!(bounce.data.len() < 10_000);
	}
}
