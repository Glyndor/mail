//! DKIM signing configuration.

use std::path::PathBuf;

use serde::Deserialize;

/// Outbound DKIM signing material.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dkim {
	/// Selector published at `<selector>._domainkey.<domain>`.
	pub selector: String,
	/// ed25519 private key, PKCS#8 PEM.
	pub key_file: PathBuf,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_dkim_section() {
		let dkim: Dkim = toml::from_str(
			r#"
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
		)
		.expect("parse dkim");
		assert_eq!(dkim.selector, "mail");
	}

	#[test]
	fn rejects_missing_fields_and_unknown_keys() {
		assert!(toml::from_str::<Dkim>(r#"selector = "mail""#).is_err());
		assert!(
			toml::from_str::<Dkim>(
				r#"
selector = "mail"
key_file = "/k.pem"
algorithm = "rsa"
"#
			)
			.is_err()
		);
	}
}
