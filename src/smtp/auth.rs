//! SASL PLAIN credential parsing and verification (RFC 4616).

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Parsed PLAIN credentials.
#[derive(Debug, PartialEq, Eq)]
pub struct PlainCredentials {
	pub authcid: String,
	pub password: String,
}

/// Why a PLAIN exchange was rejected before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlainError {
	/// Not valid base64.
	BadEncoding,
	/// Decoded message is not `authzid NUL authcid NUL passwd`.
	BadFormat,
	/// An authorization identity different from the authentication
	/// identity was requested; impersonation is not supported.
	AuthzidMismatch,
}

/// Decode the base64 SASL PLAIN message.
pub fn parse_plain(encoded: &str) -> Result<PlainCredentials, PlainError> {
	let decoded = BASE64
		.decode(encoded.trim())
		.map_err(|_| PlainError::BadEncoding)?;
	let text = String::from_utf8(decoded).map_err(|_| PlainError::BadFormat)?;
	let mut parts = text.split('\0');
	let (Some(authzid), Some(authcid), Some(password), None) =
		(parts.next(), parts.next(), parts.next(), parts.next())
	else {
		return Err(PlainError::BadFormat);
	};
	if authcid.is_empty() || password.is_empty() {
		return Err(PlainError::BadFormat);
	}
	if !authzid.is_empty() && authzid != authcid {
		return Err(PlainError::AuthzidMismatch);
	}
	Ok(PlainCredentials {
		authcid: authcid.to_string(),
		password: password.to_string(),
	})
}

/// Verify a password against an argon2id PHC hash. Any malformed hash or
/// mismatch is a plain `false`: callers must not learn why.
pub fn verify_password(phc_hash: &str, password: &str) -> bool {
	let Ok(parsed) = PasswordHash::new(phc_hash) else {
		return false;
	};
	Argon2::default()
		.verify_password(password.as_bytes(), &parsed)
		.is_ok()
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use argon2::password_hash::{PasswordHasher, SaltString};

	pub(crate) fn hash(password: &str) -> String {
		// Test-time hashing; runtime only ever verifies.
		let salt = SaltString::encode_b64(b"0123456789abcdef").expect("salt");
		Argon2::default()
			.hash_password(password.as_bytes(), &salt)
			.expect("hash")
			.to_string()
	}

	fn encode(authzid: &str, authcid: &str, password: &str) -> String {
		BASE64.encode(format!("{authzid}\0{authcid}\0{password}"))
	}

	#[test]
	fn parses_plain_without_authzid() {
		let parsed = parse_plain(&encode("", "alice", "secret")).expect("valid");
		assert_eq!(parsed.authcid, "alice");
		assert_eq!(parsed.password, "secret");
	}

	#[test]
	fn parses_plain_with_matching_authzid() {
		assert!(parse_plain(&encode("alice", "alice", "secret")).is_ok());
	}

	#[test]
	fn rejects_foreign_authzid() {
		assert_eq!(
			parse_plain(&encode("root", "alice", "secret")),
			Err(PlainError::AuthzidMismatch)
		);
	}

	#[test]
	fn rejects_bad_base64() {
		assert_eq!(parse_plain("!!not-base64!!"), Err(PlainError::BadEncoding));
	}

	#[test]
	fn rejects_wrong_field_count() {
		assert_eq!(
			parse_plain(&BASE64.encode("only-one-field")),
			Err(PlainError::BadFormat)
		);
		assert_eq!(
			parse_plain(&BASE64.encode("a\0b\0c\0d")),
			Err(PlainError::BadFormat)
		);
	}

	#[test]
	fn rejects_empty_identity_or_password() {
		assert_eq!(
			parse_plain(&encode("", "", "secret")),
			Err(PlainError::BadFormat)
		);
		assert_eq!(
			parse_plain(&encode("", "alice", "")),
			Err(PlainError::BadFormat)
		);
	}

	#[test]
	fn verifies_correct_password() {
		let phc = hash("secret");
		assert!(verify_password(&phc, "secret"));
	}

	#[test]
	fn rejects_wrong_password() {
		let phc = hash("secret");
		assert!(!verify_password(&phc, "not-secret"));
	}

	#[test]
	fn rejects_malformed_hash() {
		assert!(!verify_password("not-a-phc-string", "secret"));
	}
}
