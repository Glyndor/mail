//! DKIM signing (RFC 6376 section 5) for outbound mail.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::canon;
use super::signature::Canon;

/// Headers included in the signature when present.
const SIGNED_HEADERS: [&str; 6] = ["from", "to", "cc", "subject", "date", "message-id"];

/// An ed25519 DKIM signer for one selector.
pub struct Signer {
	selector: String,
	key: Ed25519KeyPair,
}

/// Why signing material could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
	#[error("cannot read key file {path}: {source}")]
	Read {
		path: String,
		source: std::io::Error,
	},
	#[error("invalid ed25519 key in {0}: expected PKCS#8 PEM")]
	InvalidKey(String),
}

impl Signer {
	/// Load a PKCS#8 PEM ed25519 private key.
	pub fn load(selector: &str, key_file: &std::path::Path) -> Result<Self, SignerError> {
		let pem = std::fs::read_to_string(key_file).map_err(|source| SignerError::Read {
			path: key_file.display().to_string(),
			source,
		})?;
		let der = pem_body(&pem)
			.ok_or_else(|| SignerError::InvalidKey(key_file.display().to_string()))?;
		let key = Ed25519KeyPair::from_pkcs8(&der)
			.map_err(|_| SignerError::InvalidKey(key_file.display().to_string()))?;
		Ok(Signer {
			selector: selector.to_string(),
			key,
		})
	}

	/// The DNS TXT record value publishing this signer's public key.
	pub fn dns_record_value(&self) -> String {
		format!(
			"v=DKIM1; k=ed25519; p={}",
			BASE64.encode(self.key.public_key().as_ref())
		)
	}

	/// Sign a raw message for `domain`, returning the full DKIM-Signature
	/// header line (with trailing CRLF) to prepend.
	pub fn sign(&self, domain: &str, raw: &[u8]) -> Option<String> {
		let (headers, body) = split_message(raw)?;

		let canonical_body = canon::body(Canon::Relaxed, body);
		let body_hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));

		// Collect present signable headers, bottom-up per name.
		let mut signed_names = Vec::new();
		let mut hash_input = String::new();
		for name in SIGNED_HEADERS {
			for (header_name, header_value) in headers.iter().rev() {
				if header_name.eq_ignore_ascii_case(name) {
					signed_names.push(name.to_string());
					hash_input.push_str(&canon::header(Canon::Relaxed, header_name, header_value));
					break;
				}
			}
		}
		if !signed_names.contains(&"from".to_string()) {
			// Unsigned From is forbidden; refuse to produce a signature.
			return None;
		}

		let value = format!(
			" v=1; a=ed25519-sha256; c=relaxed/relaxed; d={domain}; s={}; h={}; bh={body_hash}; b=",
			self.selector,
			signed_names.join(":"),
		);
		let mut dkim_line = canon::header(Canon::Relaxed, "DKIM-Signature", &value);
		dkim_line.truncate(dkim_line.len() - 2);
		hash_input.push_str(&dkim_line);

		let signature = BASE64.encode(self.key.sign(hash_input.as_bytes()).as_ref());
		Some(format!("DKIM-Signature:{value}{signature}\r\n"))
	}
}

/// Generate a fresh ed25519 key, returning (PKCS#8 PEM, DNS record value).
pub fn generate_key() -> Result<(String, String), SignerError> {
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
		.map_err(|_| SignerError::InvalidKey("key generation failed".into()))?;
	let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
		.map_err(|_| SignerError::InvalidKey("key generation failed".into()))?;

	let body = BASE64.encode(pkcs8.as_ref());
	let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
	for chunk in body.as_bytes().chunks(64) {
		pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
		pem.push('\n');
	}
	pem.push_str("-----END PRIVATE KEY-----\n");

	let record = format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	Ok((pem, record))
}

/// Extract the DER body of a single-block PEM file.
fn pem_body(pem: &str) -> Option<Vec<u8>> {
	let mut body = String::new();
	let mut inside = false;
	for line in pem.lines() {
		if line.starts_with("-----BEGIN ") {
			inside = true;
			continue;
		}
		if line.starts_with("-----END ") {
			break;
		}
		if inside {
			body.push_str(line.trim());
		}
	}
	if body.is_empty() {
		return None;
	}
	BASE64.decode(body).ok()
}

/// Header (name, value) pairs of a message.
type HeaderPairs<'a> = Vec<(&'a str, &'a str)>;

/// Split raw message into header (name, value) pairs and body.
fn split_message(raw: &[u8]) -> Option<(HeaderPairs<'_>, &[u8])> {
	let (header_end, body_start) = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
		Some(position) => (position + 2, position + 4),
		None => (raw.len(), raw.len()),
	};
	let block = std::str::from_utf8(&raw[..header_end]).ok()?;
	let body = &raw[body_start..];

	let mut headers = Vec::new();
	let mut current: Option<(usize, usize)> = None;
	let mut offset = 0;
	for line in block.split_inclusive("\r\n") {
		let start = offset;
		offset += line.len();
		let content = line.strip_suffix("\r\n").unwrap_or(line);
		if content.starts_with(' ') || content.starts_with('\t') {
			if let Some((_, end)) = &mut current {
				*end = offset;
			}
			continue;
		}
		if let Some((from, to)) = current.take() {
			headers.push(&block[from..to]);
		}
		if !content.is_empty() {
			current = Some((start, offset));
		}
	}
	if let Some((from, to)) = current.take() {
		headers.push(&block[from..to]);
	}

	let mut parsed = Vec::with_capacity(headers.len());
	for header in headers {
		let header = header.strip_suffix("\r\n").unwrap_or(header);
		let colon = header.find(':')?;
		parsed.push((header[..colon].trim_end(), &header[colon + 1..]));
	}
	Some((parsed, body))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;
	use std::io::Write;
	use std::pin::Pin;

	use crate::spf::{DnsFailure, DnsLookup};

	fn temp_signer() -> (Signer, String) {
		let (pem, record) = generate_key().expect("generate");
		let mut file = tempfile::NamedTempFile::new().expect("temp file");
		file.write_all(pem.as_bytes()).expect("write key");
		let signer = Signer::load("sel", file.path()).expect("load key");
		// Keep the file alive long enough.
		std::mem::forget(file);
		(signer, record)
	}

	struct OneKeyDns {
		records: HashMap<String, Vec<String>>,
	}

	impl DnsLookup for OneKeyDns {
		fn txt(
			&self,
			name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			let result = Ok(self.records.get(name).cloned().unwrap_or_default());
			Box::pin(async move { result })
		}

		fn addresses(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>>
		{
			Box::pin(async { Ok(Vec::new()) })
		}

		fn mx(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	#[tokio::test]
	async fn signed_message_verifies_with_own_verifier() {
		let (signer, record) = temp_signer();
		let raw =
			b"From: alice@example.org\r\nSubject: hi\r\nTo: bob@elsewhere.example\r\n\r\nHello\r\n";
		let header = signer.sign("example.org", raw).expect("signs");
		let mut signed = header.into_bytes();
		signed.extend_from_slice(raw);

		let mut records = HashMap::new();
		records.insert("sel._domainkey.example.org".to_string(), vec![record]);
		let dns = OneKeyDns { records };

		let results = crate::dkim::verify_message(&dns, &signed).await;
		assert_eq!(results.len(), 1);
		assert_eq!(
			results[0].outcome,
			crate::dkim::DkimOutcome::Pass,
			"{results:?}"
		);
		assert_eq!(results[0].domain.as_deref(), Some("example.org"));
	}

	#[test]
	fn refuses_to_sign_without_from() {
		let (signer, _) = temp_signer();
		assert!(
			signer
				.sign("example.org", b"Subject: x\r\n\r\nbody\r\n")
				.is_none()
		);
	}

	#[test]
	fn dns_record_value_matches_generated_record() {
		let (signer, record) = temp_signer();
		assert_eq!(signer.dns_record_value(), record);
	}

	#[test]
	fn load_rejects_garbage() {
		let mut file = tempfile::NamedTempFile::new().expect("temp file");
		file.write_all(b"not a key").expect("write");
		assert!(Signer::load("sel", file.path()).is_err());
		assert!(Signer::load("sel", std::path::Path::new("/nonexistent")).is_err());
	}
}
