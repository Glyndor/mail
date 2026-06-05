//! Semantic validation beyond what the type system enforces.

use std::collections::HashSet;

use super::{Config, ConfigError};

impl Config {
	/// Validate the configuration. Any violation is an error: the server
	/// refuses to start rather than run with a questionable setup.
	pub(super) fn validate(&self) -> Result<(), ConfigError> {
		self.validate_hostname()?;
		self.validate_data_dir()?;
		self.validate_listeners()?;
		Ok(())
	}

	fn validate_hostname(&self) -> Result<(), ConfigError> {
		let hostname = self.hostname.trim();
		if hostname.is_empty() {
			return Err(ConfigError::Invalid("hostname must not be empty".into()));
		}
		if !hostname.contains('.') {
			return Err(ConfigError::Invalid(format!(
				"hostname \"{hostname}\" must be fully qualified (contain a dot)"
			)));
		}
		if hostname.len() > 253
			|| hostname
				.split('.')
				.any(|label| label.is_empty() || label.len() > 63)
		{
			return Err(ConfigError::Invalid(format!(
				"hostname \"{hostname}\" is not a valid DNS name"
			)));
		}
		let valid_chars = hostname
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
		if !valid_chars {
			return Err(ConfigError::Invalid(format!(
				"hostname \"{hostname}\" contains invalid characters"
			)));
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
	fn accepts_same_port_on_different_addresses() {
		let result = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

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
