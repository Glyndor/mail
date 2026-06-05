//! TLS configuration: certificate and key locations.

use std::path::PathBuf;

use serde::Deserialize;

/// TLS material for all listeners. PEM-encoded files.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
	/// Certificate chain, leaf first (PEM).
	pub cert_file: PathBuf,
	/// Private key for the leaf certificate (PEM, PKCS#8 or RSA/EC).
	pub key_file: PathBuf,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_tls_section() {
		let tls: Tls = toml::from_str(
			r#"
cert_file = "/etc/mail/cert.pem"
key_file = "/etc/mail/key.pem"
"#,
		)
		.expect("parse tls");
		assert_eq!(tls.cert_file, PathBuf::from("/etc/mail/cert.pem"));
		assert_eq!(tls.key_file, PathBuf::from("/etc/mail/key.pem"));
	}

	#[test]
	fn rejects_missing_key_file() {
		let result: Result<Tls, _> = toml::from_str(r#"cert_file = "/etc/mail/cert.pem""#);
		assert!(result.is_err());
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Tls, _> = toml::from_str(
			r#"
cert_file = "/a.pem"
key_file = "/b.pem"
ciphers = "all"
"#,
		);
		assert!(result.is_err());
	}
}
