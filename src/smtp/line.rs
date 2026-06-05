//! Strict CRLF line framing for SMTP streams.
//!
//! RFC 5321 requires CRLF line endings. Accepting bare LF or bare CR is the
//! root of SMTP smuggling, so this decoder rejects both outright: a bare CR
//! or LF anywhere in the stream is a protocol error, never silently fixed.

/// Maximum data line length accepted, excluding CRLF (RFC 5321 says 998).
pub const MAX_LINE_LENGTH: usize = 998;

/// Errors produced while decoding lines from the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
	/// A CR not followed by LF, or an LF not preceded by CR.
	BareControlCharacter,
	/// Line longer than `MAX_LINE_LENGTH`.
	TooLong,
	/// Line contains a NUL byte.
	NulByte,
}

/// Incremental CRLF line decoder over received bytes.
#[derive(Debug, Default)]
pub struct LineDecoder {
	buffer: Vec<u8>,
}

impl LineDecoder {
	/// Create an empty decoder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Append received bytes to the internal buffer.
	pub fn feed(&mut self, bytes: &[u8]) {
		self.buffer.extend_from_slice(bytes);
	}

	/// Drain up to `max` already-buffered bytes (for literal payloads that
	/// arrived in the same read as their command line).
	pub fn take_buffered(&mut self, max: usize) -> Vec<u8> {
		let take = self.buffer.len().min(max);
		self.buffer.drain(..take).collect()
	}

	/// Try to extract the next complete line (without CRLF). Returns
	/// `Ok(None)` when more bytes are needed.
	pub fn next_line(&mut self) -> Result<Option<Vec<u8>>, LineError> {
		let mut i = 0;
		while i < self.buffer.len() {
			match self.buffer[i] {
				0 => return Err(LineError::NulByte),
				b'\n' => return Err(LineError::BareControlCharacter),
				b'\r' => {
					match self.buffer.get(i + 1) {
						Some(b'\n') => {
							if i > MAX_LINE_LENGTH {
								return Err(LineError::TooLong);
							}
							let line = self.buffer[..i].to_vec();
							self.buffer.drain(..i + 2);
							return Ok(Some(line));
						}
						Some(_) => return Err(LineError::BareControlCharacter),
						// CR is the last byte so far: wait for more input.
						None => return Ok(None),
					}
				}
				_ => i += 1,
			}
		}
		if self.buffer.len() > MAX_LINE_LENGTH + 1 {
			return Err(LineError::TooLong);
		}
		Ok(None)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn decode_all(input: &[u8]) -> Result<Vec<Vec<u8>>, LineError> {
		let mut decoder = LineDecoder::new();
		decoder.feed(input);
		let mut lines = Vec::new();
		while let Some(line) = decoder.next_line()? {
			lines.push(line);
		}
		Ok(lines)
	}

	#[test]
	fn decodes_crlf_lines() {
		let lines = decode_all(b"HELO a.example\r\nNOOP\r\n").expect("valid stream");
		assert_eq!(lines, vec![b"HELO a.example".to_vec(), b"NOOP".to_vec()]);
	}

	#[test]
	fn decodes_empty_line() {
		let lines = decode_all(b"\r\n").expect("valid stream");
		assert_eq!(lines, vec![Vec::<u8>::new()]);
	}

	#[test]
	fn waits_for_more_input_on_partial_line() {
		let mut decoder = LineDecoder::new();
		decoder.feed(b"HEL");
		assert_eq!(decoder.next_line(), Ok(None));
		decoder.feed(b"O a.example\r\n");
		assert_eq!(decoder.next_line(), Ok(Some(b"HELO a.example".to_vec())));
	}

	#[test]
	fn waits_when_cr_is_last_byte() {
		let mut decoder = LineDecoder::new();
		decoder.feed(b"NOOP\r");
		assert_eq!(decoder.next_line(), Ok(None));
		decoder.feed(b"\n");
		assert_eq!(decoder.next_line(), Ok(Some(b"NOOP".to_vec())));
	}

	#[test]
	fn take_buffered_drains_up_to_max() {
		let mut decoder = LineDecoder::new();
		decoder.feed(b"hello world");
		assert_eq!(decoder.take_buffered(5), b"hello");
		assert_eq!(decoder.take_buffered(100), b" world");
		assert!(decoder.take_buffered(10).is_empty());
	}

	#[test]
	fn rejects_bare_lf() {
		assert_eq!(decode_all(b"NOOP\n"), Err(LineError::BareControlCharacter));
	}

	#[test]
	fn rejects_bare_cr() {
		assert_eq!(
			decode_all(b"NO\rOP\r\n"),
			Err(LineError::BareControlCharacter)
		);
	}

	#[test]
	fn rejects_lf_cr() {
		assert_eq!(
			decode_all(b"NOOP\n\r"),
			Err(LineError::BareControlCharacter)
		);
	}

	#[test]
	fn rejects_nul_byte() {
		assert_eq!(decode_all(b"NO\0OP\r\n"), Err(LineError::NulByte));
	}

	#[test]
	fn rejects_overlong_line_with_terminator() {
		let mut input = vec![b'x'; MAX_LINE_LENGTH + 1];
		input.extend_from_slice(b"\r\n");
		assert_eq!(decode_all(&input), Err(LineError::TooLong));
	}

	#[test]
	fn rejects_overlong_line_without_terminator() {
		let input = vec![b'x'; MAX_LINE_LENGTH + 2];
		assert_eq!(decode_all(&input), Err(LineError::TooLong));
	}

	#[test]
	fn accepts_line_at_exact_limit() {
		let mut input = vec![b'x'; MAX_LINE_LENGTH];
		input.extend_from_slice(b"\r\n");
		let lines = decode_all(&input).expect("line at limit is valid");
		assert_eq!(lines[0].len(), MAX_LINE_LENGTH);
	}
}
