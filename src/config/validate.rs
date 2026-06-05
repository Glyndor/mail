//! Semantic validation beyond what the type system enforces.

use std::collections::HashSet;

use super::{Config, ConfigError};

impl Config {
	/// Validate the configuration. Any violation is an error: the server
	/// refuses to start rather than run with a questionable setup.
	pub(super) fn validate(&self) -> Result<(), ConfigError> {
		validate_dns_name("hostname", &self.hostname)?;
		self.validate_data_dir()?;
		self.validate_domains()?;
		self.validate_accounts()?;
		self.validate_listeners()?;
		Ok(())
	}

	fn validate_accounts(&self) -> Result<(), ConfigError> {
		let domains: HashSet<String> = self
			.domains
			.iter()
			.map(|domain| domain.to_ascii_lowercase())
			.collect();
		let mut names = HashSet::new();
		let mut addresses = HashSet::new();
		for account in &self.accounts {
			let name = &account.name;
			// The name becomes a directory under data_dir: keep it boring.
			let safe_name = !name.is_empty()
				&& name.len() <= 64
				&& name
					.chars()
					.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
				&& !name.starts_with('-');
			if !safe_name {
				return Err(ConfigError::Invalid(format!(
					"account name \"{name}\" must be lowercase alphanumeric/hyphen"
				)));
			}
			if !names.insert(name.clone()) {
				return Err(ConfigError::Invalid(format!(
					"duplicate account name \"{name}\""
				)));
			}
			if account.addresses.is_empty() {
				return Err(ConfigError::Invalid(format!(
					"account \"{name}\" has no addresses"
				)));
			}
			for raw in &account.addresses {
				let address = crate::smtp::address::Address::parse(raw).map_err(|_| {
					ConfigError::Invalid(format!("account \"{name}\": invalid address \"{raw}\""))
				})?;
				if !domains.contains(address.domain()) {
					return Err(ConfigError::Invalid(format!(
						"account \"{name}\": address \"{raw}\" is not in a configured domain"
					)));
				}
				if !addresses.insert(address.to_string().to_ascii_lowercase()) {
					return Err(ConfigError::Invalid(format!(
						"address \"{raw}\" is assigned to more than one account"
					)));
				}
			}
		}
		Ok(())
	}

	fn validate_domains(&self) -> Result<(), ConfigError> {
		if !self.listeners.is_empty() && self.domains.is_empty() {
			return Err(ConfigError::Invalid(
				"at least one entry in \"domains\" is required when listeners are configured"
					.into(),
			));
		}
		let mut seen = HashSet::new();
		for domain in &self.domains {
			validate_dns_name("domain", domain)?;
			if !seen.insert(domain.to_ascii_lowercase()) {
				return Err(ConfigError::Invalid(format!(
					"duplicate domain \"{domain}\""
				)));
			}
		}
		Ok(())
	}

	fn validate_data_dir(&self) -> Result<(), ConfigError> {
		if self.data_dir.as_os_str().is_empty() {
			return Err(ConfigError::Invalid("data_dir must not be empty".into()));
		}
		if !self.data_dir.is_absolute() {
			return Err(ConfigError::Invalid(format!(
				"data_dir \"{}\" must be an absolute path",
				self.data_dir.display()
			)));
		}
		Ok(())
	}

	fn validate_listeners(&self) -> Result<(), ConfigError> {
		let mut seen = HashSet::new();
		for listener in &self.listeners {
			let addr = listener.socket_addr();
			if !seen.insert(addr) {
				return Err(ConfigError::Invalid(format!(
					"duplicate listener address {addr}"
				)));
			}
			if listener.kind == crate::config::ListenerKind::Submissions && self.tls.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"submissions\" (implicit TLS) but no [tls] section is configured"
				)));
			}
		}
		Ok(())
	}
}

/// Validate a fully qualified DNS name; `field` names it in errors.
fn validate_dns_name(field: &str, name: &str) -> Result<(), ConfigError> {
	let name = name.trim();
	if name.is_empty() {
		return Err(ConfigError::Invalid(format!("{field} must not be empty")));
	}
	if !name.contains('.') {
		return Err(ConfigError::Invalid(format!(
			"{field} \"{name}\" must be fully qualified (contain a dot)"
		)));
	}
	if name.len() > 253
		|| name
			.split('.')
			.any(|label| label.is_empty() || label.len() > 63)
	{
		return Err(ConfigError::Invalid(format!(
			"{field} \"{name}\" is not a valid DNS name"
		)));
	}
	let valid_chars = name
		.chars()
		.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
	if !valid_chars {
		return Err(ConfigError::Invalid(format!(
			"{field} \"{name}\" contains invalid characters"
		)));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn config_from(toml: &str) -> Result<Config, ConfigError> {
		let config: Config =
			toml::from_str(toml).map_err(|e| ConfigError::Invalid(e.to_string()))?;
		config.validate()?;
		Ok(config)
	}

	#[test]
	fn accepts_valid_config_with_listeners() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"

[[listeners]]
kind = "submission"
"#,
		);
		assert!(result.is_ok());
	}

	#[test]
	fn rejects_empty_hostname() {
		let result = config_from(
			r#"
hostname = ""
data_dir = "/var/lib/mail"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_unqualified_hostname() {
		let result = config_from(
			r#"
hostname = "localhost"
data_dir = "/var/lib/mail"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_hostname_with_invalid_characters() {
		let result = config_from(
			r#"
hostname = "mail.exa mple.org"
data_dir = "/var/lib/mail"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_hostname_with_empty_label() {
		let result = config_from(
			r#"
hostname = "mail..example.org"
data_dir = "/var/lib/mail"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_overlong_hostname() {
		let label = "a".repeat(64);
		let result = config_from(&format!(
			"hostname = \"{label}.example.org\"\ndata_dir = \"/var/lib/mail\"\n"
		));
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_relative_data_dir() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "relative/path"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_duplicate_listeners() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"

[[listeners]]
kind = "smtp"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_submissions_listener_without_tls() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "submissions"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn accepts_submissions_listener_with_tls() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "submissions"

[tls]
cert_file = "/etc/mail/cert.pem"
key_file = "/etc/mail/key.pem"
"#,
		);
		assert!(result.is_ok());
	}

	#[test]
	fn rejects_listeners_without_domains() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[[listeners]]
kind = "smtp"
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_invalid_domain_entry() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["nodot"]
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_duplicate_domains_case_insensitively() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "EXAMPLE.org"]
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn accepts_valid_accounts() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org", "postmaster@EXAMPLE.org"]
"#,
		);
		assert!(result.is_ok());
	}

	#[test]
	fn rejects_account_with_unsafe_name() {
		for name in ["", "Alice", "a/b", "-x", "a b"] {
			let result = config_from(&format!(
				"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n\n[[accounts]]\nname = \"{name}\"\naddresses = [\"a@example.org\"]\n"
			));
			assert!(
				matches!(result, Err(ConfigError::Invalid(_))),
				"name {name:?} must be rejected"
			);
		}
	}

	#[test]
	fn rejects_account_without_addresses() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = []
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_address_outside_domains() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@elsewhere.example"]
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_address_claimed_twice() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["shared@example.org"]

[[accounts]]
name = "bob"
addresses = ["SHARED@example.org"]
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn rejects_duplicate_account_names() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["a@example.org"]

[[accounts]]
name = "alice"
addresses = ["b@example.org"]
"#,
		);
		assert!(matches!(result, Err(ConfigError::Invalid(_))));
	}

	#[test]
	fn accepts_same_port_on_different_addresses() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"
addr = "127.0.0.1"

[[listeners]]
kind = "smtp"
addr = "127.0.0.2"
"#,
		);
		assert!(result.is_ok());
	}
}
