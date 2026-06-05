//! SMTP server replies (RFC 5321 section 4.2).

use std::fmt;

/// A server reply: three-digit code plus one or more text lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
	code: u16,
	lines: Vec<String>,
}

impl Reply {
	/// Build a reply. Panics if `code` is not a valid SMTP reply code or no
	/// lines are given — both are programming errors, not runtime input.
	pub fn new(code: u16, lines: Vec<String>) -> Self {
		assert!(
			(200..=599).contains(&code),
			"invalid SMTP reply code {code}"
		);
		assert!(!lines.is_empty(), "a reply needs at least one line");
		Reply { code, lines }
	}

	/// Single-line convenience constructor.
	pub fn single(code: u16, text: &str) -> Self {
		Reply::new(code, vec![text.to_string()])
	}

	/// The reply code.
	pub fn code(&self) -> u16 {
		self.code
	}

	/// Whether this reply indicates success (2xx) or an intermediate
	/// positive state (3xx).
	pub fn is_positive(&self) -> bool {
		(200..400).contains(&self.code)
	}
}

impl fmt::Display for Reply {
	/// Render with CRLF terminators, hyphen-continuation on all lines but
	/// the last (RFC 5321 section 4.2.1).
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let last = self.lines.len() - 1;
		for (i, line) in self.lines.iter().enumerate() {
			let separator = if i == last { ' ' } else { '-' };
			write!(f, "{}{}{}\r\n", self.code, separator, line)?;
		}
		Ok(())
	}
}

/// Frequently used replies.
impl Reply {
	pub fn ok() -> Self {
		Reply::single(250, "ok")
	}

	pub fn closing() -> Self {
		Reply::single(221, "closing connection")
	}

	pub fn syntax_error() -> Self {
		Reply::single(500, "syntax error")
	}

	pub fn invalid_arguments() -> Self {
		Reply::single(501, "invalid arguments")
	}

	pub fn bad_sequence() -> Self {
		Reply::single(503, "bad sequence of commands")
	}

	pub fn vrfy_not_disclosed() -> Self {
		Reply::single(252, "cannot verify, send some mail and find out")
	}

	pub fn start_mail_input() -> Self {
		Reply::single(354, "start mail input, end with <CRLF>.<CRLF>")
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn renders_single_line_with_crlf() {
		assert_eq!(Reply::ok().to_string(), "250 ok\r\n");
	}

	#[test]
	fn renders_multiline_with_continuation() {
		let reply = Reply::new(
			250,
			vec![
				"mail.example.org".into(),
				"PIPELINING".into(),
				"SIZE 1000".into(),
			],
		);
		assert_eq!(
			reply.to_string(),
			"250-mail.example.org\r\n250-PIPELINING\r\n250 SIZE 1000\r\n"
		);
	}

	#[test]
	fn positive_detection() {
		assert!(Reply::ok().is_positive());
		assert!(Reply::start_mail_input().is_positive());
		assert!(!Reply::syntax_error().is_positive());
		assert!(!Reply::bad_sequence().is_positive());
	}

	#[test]
	#[should_panic(expected = "invalid SMTP reply code")]
	fn rejects_invalid_code() {
		let _ = Reply::single(102, "nope");
	}

	#[test]
	#[should_panic(expected = "at least one line")]
	fn rejects_empty_lines() {
		let _ = Reply::new(250, vec![]);
	}
}
