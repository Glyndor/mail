//! `DKIM-Signature` header parsing (RFC 6376 section 3.5).

/// Canonicalization mode (RFC 6376 section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canon {
	Simple,
	Relaxed,
}

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
	RsaSha256,
	Ed25519Sha256,
}

/// A parsed DKIM-Signature header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
	pub algorithm: Algorithm,
	pub domain: String,
	pub selector: String,
	pub signed_headers: Vec<String>,
	pub body_hash: Vec<u8>,
	pub signature: Vec<u8>,
	pub header_canon: Canon,
	pub body_canon: Canon,
	/// `l=` body length limit, if present.
	pub body_length: Option<usize>,
	/// `x=` expiration (UNIX seconds), if present.
	pub expiration: Option<u64>,
}

/// Why a signature header could not be used: always a permerror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureError(pub String);

/// Parse the value of a `DKIM-Signature` header.
pub fn parse(value: &str) -> Result<Signature, SignatureError> {
	let mut version = None;
	let mut algorithm = None;
	let mut domain = None;
	let mut selector = None;
	let mut signed_headers = None;
	let mut body_hash = None;
	let mut signature = None;
	let mut header_canon = Canon::Simple;
	let mut body_canon = Canon::Simple;
	let mut body_length = None;
	let mut expiration = None;

	for tag in value.split(';') {
		let tag = tag.trim();
		if tag.is_empty() {
			continue;
		}
		let (name, tag_value) = tag
			.split_once('=')
			.ok_or_else(|| SignatureError(format!("malformed tag \"{tag}\"")))?;
		// Tag values may contain folding whitespace; strip it all.
		let compact: String = tag_value.chars().filter(|c| !c.is_whitespace()).collect();
		match name.trim() {
			"v" => version = Some(compact),
			"a" => {
				algorithm = Some(match compact.as_str() {
					"rsa-sha256" => Algorithm::RsaSha256,
					"ed25519-sha256" => Algorithm::Ed25519Sha256,
					other => {
						return Err(SignatureError(format!("unsupported algorithm {other}")));
					}
				});
			}
			"d" => domain = Some(compact.to_ascii_lowercase()),
			"s" => selector = Some(compact.to_ascii_lowercase()),
			"h" => {
				signed_headers = Some(
					compact
						.split(':')
						.map(|h| h.to_ascii_lowercase())
						.collect::<Vec<_>>(),
				);
			}
			"bh" => body_hash = Some(decode_base64(&compact, "bh")?),
			"b" => signature = Some(decode_base64(&compact, "b")?),
			"c" => {
				let (header, body) = compact
					.split_once('/')
					.unwrap_or((compact.as_str(), "simple"));
				header_canon = parse_canon(header)?;
				body_canon = parse_canon(body)?;
			}
			"l" => {
				body_length = Some(
					compact
						.parse()
						.map_err(|_| SignatureError("invalid l= tag".into()))?,
				);
			}
			"x" => {
				expiration = Some(
					compact
						.parse()
						.map_err(|_| SignatureError("invalid x= tag".into()))?,
				);
			}
			// Unknown tags must be ignored (section 3.2).
			_ => {}
		}
	}

	if version.as_deref() != Some("1") {
		return Err(SignatureError("v= must be 1".into()));
	}
	let signed_headers = signed_headers.ok_or_else(|| SignatureError("missing h= tag".into()))?;
	// The From header must be signed (section 5.4).
	if !signed_headers.iter().any(|h| h == "from") {
		return Err(SignatureError("h= does not cover From".into()));
	}
	Ok(Signature {
		algorithm: algorithm.ok_or_else(|| SignatureError("missing a= tag".into()))?,
		domain: domain.ok_or_else(|| SignatureError("missing d= tag".into()))?,
		selector: selector.ok_or_else(|| SignatureError("missing s= tag".into()))?,
		signed_headers,
		body_hash: body_hash.ok_or_else(|| SignatureError("missing bh= tag".into()))?,
		signature: signature.ok_or_else(|| SignatureError("missing b= tag".into()))?,
		header_canon,
		body_canon,
		body_length,
		expiration,
	})
}

fn parse_canon(text: &str) -> Result<Canon, SignatureError> {
	match text {
		"simple" => Ok(Canon::Simple),
		"relaxed" => Ok(Canon::Relaxed),
		other => Err(SignatureError(format!("unknown canonicalization {other}"))),
	}
}

fn decode_base64(text: &str, tag: &str) -> Result<Vec<u8>, SignatureError> {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD
		.decode(text)
		.map_err(|_| SignatureError(format!("invalid base64 in {tag}= tag")))
}

#[cfg(test)]
mod tests {
	use super::*;

	const SAMPLE: &str = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; \
s=sel; h=from:to:subject; bh=aGFzaA==; b=c2ln";

	#[test]
	fn parses_complete_signature() {
		let signature = parse(SAMPLE).expect("valid signature");
		assert_eq!(signature.algorithm, Algorithm::RsaSha256);
		assert_eq!(signature.domain, "example.org");
		assert_eq!(signature.selector, "sel");
		assert_eq!(signature.signed_headers, vec!["from", "to", "subject"]);
		assert_eq!(signature.body_hash, b"hash");
		assert_eq!(signature.signature, b"sig");
		assert_eq!(signature.header_canon, Canon::Relaxed);
		assert_eq!(signature.body_canon, Canon::Relaxed);
	}

	#[test]
	fn defaults_to_simple_canonicalization() {
		let signature =
			parse("v=1; a=ed25519-sha256; d=example.org; s=sel; h=from; bh=aGFzaA==; b=c2ln")
				.expect("valid");
		assert_eq!(signature.algorithm, Algorithm::Ed25519Sha256);
		assert_eq!(signature.header_canon, Canon::Simple);
		assert_eq!(signature.body_canon, Canon::Simple);
	}

	#[test]
	fn strips_folding_whitespace_in_values() {
		let folded = "v=1; a=rsa-sha256; d=example.org; s=sel; h=from : to; \
bh=aGF z aA==; b=c2 ln";
		let signature = parse(folded).expect("valid");
		assert_eq!(signature.body_hash, b"hash");
		assert_eq!(signature.signature, b"sig");
	}

	#[test]
	fn rejects_missing_required_tags() {
		assert!(parse("v=1; a=rsa-sha256; d=example.org; s=sel; bh=aGFzaA==; b=c2ln").is_err());
		assert!(parse("v=1; a=rsa-sha256; s=sel; h=from; bh=aGFzaA==; b=c2ln").is_err());
		assert!(parse("a=rsa-sha256; d=e.org; s=sel; h=from; bh=aGFzaA==; b=c2ln").is_err());
	}

	#[test]
	fn rejects_unsigned_from() {
		assert!(
			parse("v=1; a=rsa-sha256; d=example.org; s=sel; h=to:subject; bh=aGFzaA==; b=c2ln")
				.is_err()
		);
	}

	#[test]
	fn rejects_unsupported_algorithm() {
		assert!(
			parse("v=1; a=rsa-sha1; d=example.org; s=sel; h=from; bh=aGFzaA==; b=c2ln").is_err()
		);
	}

	#[test]
	fn parses_length_and_expiration() {
		let signature = parse(
			"v=1; a=rsa-sha256; d=example.org; s=sel; h=from; bh=aGFzaA==; b=c2ln; l=100; x=12345",
		)
		.expect("valid");
		assert_eq!(signature.body_length, Some(100));
		assert_eq!(signature.expiration, Some(12345));
	}
}
