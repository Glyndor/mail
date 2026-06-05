//! Header and body canonicalization (RFC 6376 section 3.4).

use super::signature::Canon;

/// Canonicalize one header for hashing: `name` is the original header name,
/// `value` the raw value (without the terminating CRLF).
pub fn header(canon: Canon, name: &str, value: &str) -> String {
	match canon {
		Canon::Simple => format!("{name}:{value}\r\n"),
		Canon::Relaxed => {
			let name = name.to_ascii_lowercase();
			// Unfold, collapse runs of WSP, trim.
			let mut collapsed = String::with_capacity(value.len());
			let mut in_space = false;
			for c in value.chars() {
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
					in_space = true;
				} else {
					if in_space && !collapsed.is_empty() {
						collapsed.push(' ');
					}
					in_space = false;
					collapsed.push(c);
				}
			}
			format!("{name}:{collapsed}\r\n")
		}
	}
}

/// Canonicalize the message body.
pub fn body(canon: Canon, body: &[u8]) -> Vec<u8> {
	match canon {
		Canon::Simple => simple_body(body),
		Canon::Relaxed => relaxed_body(body),
	}
}

/// Simple body: strip trailing empty lines, ensure one final CRLF.
fn simple_body(body: &[u8]) -> Vec<u8> {
	let mut out = body.to_vec();
	while out.ends_with(b"\r\n\r\n") {
		out.truncate(out.len() - 2);
	}
	if out == b"\r\n" {
		return b"\r\n".to_vec();
	}
	if !out.is_empty() && !out.ends_with(b"\r\n") {
		out.extend_from_slice(b"\r\n");
	}
	if out.is_empty() {
		out.extend_from_slice(b"\r\n");
	}
	out
}

/// Relaxed body: per line, strip trailing WSP and collapse inner WSP runs
/// to one space; then strip trailing empty lines and ensure one final CRLF.
fn relaxed_body(body: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(body.len());
	for line in body.split_inclusive(|&b| b == b'\n') {
		let line = line
			.strip_suffix(b"\r\n")
			.or_else(|| line.strip_suffix(b"\n"))
			.unwrap_or(line);
		let mut canonical = Vec::with_capacity(line.len());
		let mut in_space = false;
		for &byte in line {
			if byte == b' ' || byte == b'\t' {
				in_space = true;
			} else {
				if in_space && !canonical.is_empty() {
					canonical.push(b' ');
				}
				in_space = false;
				canonical.push(byte);
			}
		}
		out.extend_from_slice(&canonical);
		out.extend_from_slice(b"\r\n");
	}
	while out.ends_with(b"\r\n\r\n") {
		out.truncate(out.len() - 2);
	}
	if out.is_empty() {
		// An empty body canonicalizes to nothing in relaxed mode... except
		// the hash input is then empty CRLF per errata; keep RFC text: empty.
		return Vec::new();
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn relaxed_header_lowercases_and_collapses() {
		assert_eq!(
			header(Canon::Relaxed, "Subject", "  Hello \t world\r\n\t!"),
			"subject:Hello world !\r\n"
		);
	}

	#[test]
	fn simple_header_is_verbatim() {
		assert_eq!(
			header(Canon::Simple, "Subject", " Hello"),
			"Subject: Hello\r\n"
		);
	}

	#[test]
	fn relaxed_body_collapses_and_trims() {
		let input = b"Hello \t world \r\nline2\t\tx\r\n\r\n\r\n";
		assert_eq!(body(Canon::Relaxed, input), b"Hello world\r\nline2 x\r\n");
	}

	#[test]
	fn simple_body_strips_trailing_blank_lines_only() {
		let input = b"Hello  world\r\n\r\n\r\n";
		assert_eq!(body(Canon::Simple, input), b"Hello  world\r\n");
	}

	#[test]
	fn empty_bodies() {
		assert_eq!(body(Canon::Simple, b""), b"\r\n");
		assert_eq!(body(Canon::Relaxed, b""), b"");
	}
}
