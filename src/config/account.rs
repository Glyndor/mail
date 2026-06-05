//! Account definitions: who receives mail at which addresses.

use serde::Deserialize;

/// One mail account.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
	/// Account name; doubles as the mailbox directory name.
	pub name: String,
	/// Addresses delivered to this account.
	pub addresses: Vec<String>,
	/// argon2id password hash (PHC string). Without it the account is
	/// receive-only and cannot authenticate.
	pub password_hash: Option<String>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_account() {
		let account: Account = toml::from_str(
			r#"
name = "alice"
addresses = ["alice@example.org", "postmaster@example.org"]
"#,
		)
		.expect("parse account");
		assert_eq!(account.name, "alice");
		assert_eq!(account.addresses.len(), 2);
	}

	#[test]
	fn rejects_unknown_keys() {
		let result: Result<Account, _> = toml::from_str(
			r#"
name = "alice"
addresses = []
quota = "1G"
"#,
		);
		assert!(result.is_err());
	}
}
