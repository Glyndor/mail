//! Management API configuration.

use serde::Deserialize;

/// Management API settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
	/// argon2id PHC hash of the bearer token.
	pub token_hash: String,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_api_section() {
		let api: Api = toml::from_str(r#"token_hash = "$argon2id$x""#).expect("parse");
		assert_eq!(api.token_hash, "$argon2id$x");
	}

	#[test]
	fn rejects_unknown_keys() {
		assert!(
			toml::from_str::<Api>(
				r#"token_hash = "x"
port = 1"#
			)
			.is_err()
		);
	}
}
