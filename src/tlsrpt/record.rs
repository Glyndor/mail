//! TLS-RPT record parsing (RFC 8460 section 3).

/// A parsed `_smtp._tls` TLS-RPT policy record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
	/// Report recipients parsed from `rua=` (RFC 8460 §3).
	/// Each element is a `mailto:` or `https:` URI; other schemes are
	/// dropped. A record with no valid URI is malformed, so this is never
	/// empty in an `Ok` result.
	pub rua: Vec<String>,
}

/// Parse a `v=TLSRPTv1` TXT record. Returns `None` for records that are not
/// TLS-RPT at all; `Err` for TLS-RPT records that are malformed (no usable
/// `rua=`). Mirrors the shape of `dmarc::record::parse`.
pub fn parse(text: &str) -> Option<Result<Record, ()>> {
	let mut tags = text.split(';').map(str::trim);
	// v=TLSRPTv1 must be the first tag (RFC 8460 §3).
	if tags.next() != Some("v=TLSRPTv1") {
		return None;
	}

	let mut rua: Option<Vec<String>> = None;

	for tag in tags {
		if tag.is_empty() {
			continue;
		}
		let Some((name, value)) = tag.split_once('=') else {
			return Some(Err(()));
		};
		// Only rua= is defined; unknown tags are ignored (RFC 8460 §3).
		if name.trim() == "rua" {
			rua = Some(parse_rua_list(value.trim()));
		}
	}

	// rua= is required and must yield at least one usable URI.
	match rua {
		Some(uris) if !uris.is_empty() => Some(Ok(Record { rua: uris })),
		_ => Some(Err(())),
	}
}

/// Parse the `rua=` value into a list of report URIs, keeping only the
/// `mailto:` and `https:` schemes defined by RFC 8460 §3. Blank entries and
/// unsupported schemes are dropped.
fn parse_rua_list(value: &str) -> Vec<String> {
	value
		.split(',')
		.filter_map(|uri| {
			let uri = uri.trim();
			let lower = uri.to_ascii_lowercase();
			if lower.starts_with("mailto:") || lower.starts_with("https:") {
				Some(uri.to_string())
			} else {
				None
			}
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_mailto_record() {
		let record = parse("v=TLSRPTv1; rua=mailto:tlsrpt@example.com")
			.expect("is tlsrpt")
			.expect("valid");
		assert_eq!(record.rua, vec!["mailto:tlsrpt@example.com"]);
	}

	#[test]
	fn parses_https_record() {
		let record = parse("v=TLSRPTv1; rua=https://reports.example.com/tlsrpt")
			.expect("is tlsrpt")
			.expect("valid");
		assert_eq!(record.rua, vec!["https://reports.example.com/tlsrpt"]);
	}

	#[test]
	fn parses_multiple_uris() {
		let record = parse("v=TLSRPTv1; rua=mailto:a@example.com,https://r.example.net/r")
			.expect("is tlsrpt")
			.expect("valid");
		assert_eq!(
			record.rua,
			vec!["mailto:a@example.com", "https://r.example.net/r"]
		);
	}

	#[test]
	fn drops_unsupported_schemes() {
		let record = parse("v=TLSRPTv1; rua=ftp://example.com/r,mailto:ok@example.com")
			.expect("is tlsrpt")
			.expect("valid");
		assert_eq!(record.rua, vec!["mailto:ok@example.com"]);
	}

	#[test]
	fn ignores_unknown_tags() {
		let record = parse("v=TLSRPTv1; rua=mailto:a@example.com; foo=bar")
			.expect("is tlsrpt")
			.expect("valid");
		assert_eq!(record.rua, vec!["mailto:a@example.com"]);
	}

	#[test]
	fn scheme_match_is_case_insensitive() {
		let record = parse("v=TLSRPTv1; rua=MAILTO:Ops@Example.Com")
			.expect("is tlsrpt")
			.expect("valid");
		// Original casing is preserved; only scheme detection is folded.
		assert_eq!(record.rua, vec!["MAILTO:Ops@Example.Com"]);
	}

	#[test]
	fn non_tlsrpt_text_is_none() {
		assert!(parse("v=DMARC1; p=none").is_none());
		assert!(parse("v=spf1 -all").is_none());
		assert!(parse("random text").is_none());
	}

	#[test]
	fn version_must_be_first() {
		assert!(parse("rua=mailto:a@example.com; v=TLSRPTv1").is_none());
	}

	#[test]
	fn missing_rua_is_error() {
		assert_eq!(parse("v=TLSRPTv1"), Some(Err(())));
	}

	#[test]
	fn rua_with_only_unsupported_schemes_is_error() {
		assert_eq!(parse("v=TLSRPTv1; rua=ftp://example.com/r"), Some(Err(())));
	}

	#[test]
	fn malformed_tag_without_equals_is_error() {
		assert_eq!(parse("v=TLSRPTv1; rua"), Some(Err(())));
	}

	#[test]
	fn trailing_semicolon_is_tolerated() {
		let record = parse("v=TLSRPTv1; rua=mailto:a@example.com;")
			.expect("is tlsrpt")
			.expect("valid");
		assert_eq!(record.rua, vec!["mailto:a@example.com"]);
	}
}
