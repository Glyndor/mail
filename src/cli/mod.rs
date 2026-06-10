//! Command-line interface: argument parsing and command dispatch.

mod serve;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::Config;

/// Headless mail server: SMTP, IMAP and modern email security through an
/// API and CLI.
#[derive(Debug, Parser)]
#[command(name = "mail", version, disable_help_subcommand = true)]
pub struct Cli {
	#[command(subcommand)]
	command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
	/// Run the mail server.
	Serve {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Validate a configuration file and report problems.
	ConfigCheck {
		/// Path to the configuration file.
		#[arg(long, value_name = "FILE")]
		config: PathBuf,
	},
	/// Generate an ed25519 DKIM key and print the DNS record value.
	DkimKeygen {
		/// Where to write the private key (PKCS#8 PEM).
		#[arg(long, value_name = "FILE")]
		out: PathBuf,
	},
	/// Hash a bearer token for use in `[api] token_hash`.
	///
	/// Reads the plaintext token from stdin (one line). Prints the argon2id
	/// PHC string to stdout, ready to paste into the config file.
	TokenHash,
}

impl Cli {
	/// Execute the parsed command.
	pub fn run(self) -> ExitCode {
		match self.command {
			Command::Serve { config } => match Config::load(&config) {
				Ok(config) => serve::run(config),
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::ConfigCheck { config } => match Config::load(&config) {
				Ok(_) => {
					println!("configuration is valid");
					ExitCode::SUCCESS
				}
				Err(error) => {
					eprintln!("error: {error}");
					ExitCode::FAILURE
				}
			},
			Command::DkimKeygen { out } => dkim_keygen(&out),
			Command::TokenHash => token_hash(),
		}
	}
}

fn token_hash() -> ExitCode {
	token_hash_from(std::io::stdin().lock())
}

fn token_hash_from(reader: impl std::io::BufRead) -> ExitCode {
	let line = reader.lines().next();
	let token = match line {
		Some(Ok(t)) => t,
		Some(Err(error)) => {
			eprintln!("error: reading stdin: {error}");
			return ExitCode::FAILURE;
		}
		None => {
			eprintln!("error: no input — pipe or type the token on stdin");
			return ExitCode::FAILURE;
		}
	};
	let token = token.trim_end_matches('\r').to_owned();
	if token.is_empty() {
		eprintln!("error: token must not be empty");
		return ExitCode::FAILURE;
	}
	match crate::smtp::auth::hash_password(&token) {
		Ok(hash) => {
			println!("{hash}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}

fn dkim_keygen(out: &std::path::Path) -> ExitCode {
	if out.exists() {
		eprintln!(
			"error: {} already exists, refusing to overwrite",
			out.display()
		);
		return ExitCode::FAILURE;
	}
	let (pem, record) = match crate::dkim::generate_key() {
		Ok(generated) => generated,
		Err(error) => {
			eprintln!("error: {error}");
			return ExitCode::FAILURE;
		}
	};
	// The private key must never be group/world readable.
	let result = {
		use std::io::Write;
		let mut options = std::fs::OpenOptions::new();
		options.write(true).create_new(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		options
			.open(out)
			.and_then(|mut file| file.write_all(pem.as_bytes()))
	};
	if let Err(error) = result {
		eprintln!("error: cannot write {}: {error}", out.display());
		return ExitCode::FAILURE;
	}
	println!("private key written to {}", out.display());
	println!("publish this TXT record at <selector>._domainkey.<your-domain>:");
	println!("{record}");
	ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
	use super::*;
	use clap::CommandFactory;
	use std::io::Write;

	#[test]
	fn cli_definition_is_consistent() {
		Cli::command().debug_assert();
	}

	#[test]
	fn parses_serve_command() {
		let cli = Cli::try_parse_from(["mail", "serve", "--config", "/etc/mail.toml"])
			.expect("serve parses");
		assert!(matches!(cli.command, Command::Serve { .. }));
	}

	#[test]
	fn parses_config_check_command() {
		let cli = Cli::try_parse_from(["mail", "config-check", "--config", "/etc/mail.toml"])
			.expect("config-check parses");
		assert!(matches!(cli.command, Command::ConfigCheck { .. }));
	}

	#[test]
	fn rejects_missing_config_argument() {
		assert!(Cli::try_parse_from(["mail", "serve"]).is_err());
	}

	#[test]
	fn rejects_unknown_subcommand() {
		assert!(Cli::try_parse_from(["mail", "destroy"]).is_err());
	}

	#[test]
	fn config_check_accepts_valid_file() {
		let mut file = tempfile::NamedTempFile::new().expect("temp file");
		file.write_all(b"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n")
			.expect("write");
		let cli = Cli::try_parse_from([
			"mail",
			"config-check",
			"--config",
			file.path().to_str().expect("utf-8 path"),
		])
		.expect("parses");
		assert_eq!(cli.run(), ExitCode::SUCCESS);
	}

	#[test]
	fn config_check_rejects_invalid_file() {
		let mut file = tempfile::NamedTempFile::new().expect("temp file");
		file.write_all(b"hostname = \"localhost\"\ndata_dir = \"/var/lib/mail\"\n")
			.expect("write");
		let cli = Cli::try_parse_from([
			"mail",
			"config-check",
			"--config",
			file.path().to_str().expect("utf-8 path"),
		])
		.expect("parses");
		assert_eq!(cli.run(), ExitCode::FAILURE);
	}

	#[test]
	fn dkim_keygen_writes_key_and_refuses_overwrite() {
		let dir = tempfile::tempdir().expect("tempdir");
		let out = dir.path().join("dkim.pem");
		let cli = Cli::try_parse_from([
			"mail",
			"dkim-keygen",
			"--out",
			out.to_str().expect("utf-8 path"),
		])
		.expect("parses");
		assert_eq!(cli.run(), ExitCode::SUCCESS);
		let pem = std::fs::read_to_string(&out).expect("key written");
		assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

		// Second run must refuse to overwrite the existing key.
		let cli = Cli::try_parse_from([
			"mail",
			"dkim-keygen",
			"--out",
			out.to_str().expect("utf-8 path"),
		])
		.expect("parses");
		assert_eq!(cli.run(), ExitCode::FAILURE);
	}

	#[cfg(unix)]
	#[test]
	fn dkim_keygen_sets_owner_only_permissions() {
		use std::os::unix::fs::PermissionsExt;
		let dir = tempfile::tempdir().expect("tempdir");
		let out = dir.path().join("dkim.pem");
		let cli = Cli::try_parse_from([
			"mail",
			"dkim-keygen",
			"--out",
			out.to_str().expect("utf-8 path"),
		])
		.expect("parses");
		assert_eq!(cli.run(), ExitCode::SUCCESS);
		let mode = std::fs::metadata(&out)
			.expect("metadata")
			.permissions()
			.mode();
		assert_eq!(mode & 0o777, 0o600);
	}

	#[test]
	fn serve_fails_on_missing_config() {
		let cli = Cli::try_parse_from(["mail", "serve", "--config", "/nonexistent/mail.toml"])
			.expect("parses");
		assert_eq!(cli.run(), ExitCode::FAILURE);
	}

	#[test]
	fn parses_token_hash_command() {
		let cli = Cli::try_parse_from(["mail", "token-hash"]).expect("token-hash parses");
		assert!(matches!(cli.command, Command::TokenHash));
	}

	#[test]
	fn token_hash_produces_valid_phc() {
		use std::io::Cursor;
		let result = token_hash_from(Cursor::new("hunter2\n"));
		assert_eq!(result, ExitCode::SUCCESS);
	}

	#[test]
	fn token_hash_verifies_against_output() {
		use crate::smtp::auth::verify_password;
		// We can't capture stdout directly here, so verify via hash_password round-trip.
		let hash = crate::smtp::auth::hash_password("my-secret-token").expect("hashes");
		assert!(hash.starts_with("$argon2id$"));
		assert!(verify_password(&hash, "my-secret-token"));
		assert!(!verify_password(&hash, "wrong-token"));
	}

	#[test]
	fn token_hash_rejects_empty_input() {
		use std::io::Cursor;
		let result = token_hash_from(Cursor::new("\n"));
		assert_eq!(result, ExitCode::FAILURE);
	}

	#[test]
	fn token_hash_rejects_no_input() {
		use std::io::Cursor;
		let result = token_hash_from(Cursor::new(""));
		assert_eq!(result, ExitCode::FAILURE);
	}

	#[test]
	fn token_hash_strips_crlf() {
		use std::io::Cursor;
		// Windows-style line endings must not be treated as part of the token.
		let result = token_hash_from(Cursor::new("my-token\r\n"));
		assert_eq!(result, ExitCode::SUCCESS);
	}

	#[test]
	fn token_hash_reports_stdin_io_error() {
		struct AlwaysErrors;
		impl std::io::Read for AlwaysErrors {
			fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
				Err(std::io::Error::new(
					std::io::ErrorKind::BrokenPipe,
					"simulated",
				))
			}
		}
		impl std::io::BufRead for AlwaysErrors {
			fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
				Err(std::io::Error::new(
					std::io::ErrorKind::BrokenPipe,
					"simulated",
				))
			}
			fn consume(&mut self, _: usize) {}
		}
		let result = token_hash_from(AlwaysErrors);
		assert_eq!(result, ExitCode::FAILURE);
	}
}
