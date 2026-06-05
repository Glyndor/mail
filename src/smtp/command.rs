//! SMTP command parsing (RFC 5321 section 4.1).
//!
//! Parsing is strict by design: commands must be ASCII, terminated by CRLF
//! (enforced by the line reader before reaching this parser), and within
//! length limits. Anything questionable is rejected — never guessed at.

/// Maximum command line length, including CRLF (RFC 5321 section 4.5.3.1.4).
pub const MAX_COMMAND_LINE: usize = 512;

/// A parsed SMTP client command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	/// `HELO <domain>`
	Helo { domain: String },
	/// `EHLO <domain>`
	Ehlo { domain: String },
	/// `MAIL FROM:<reverse-path> [parameters]`
	MailFrom { reverse_path: String },
	/// `RCPT TO:<forward-path> [parameters]`
	RcptTo { forward_path: String },
	/// `DATA`
	Data,
	/// `RSET`
	Rset,
	/// `NOOP`
	Noop,
	/// `QUIT`
	Quit,
	/// `VRFY <string>` — always answered with a non-disclosure reply.
	Vrfy,
	/// `STARTTLS`
	StartTls,
}

/// Why a command line failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
	/// The line exceeds `MAX_COMMAND_LINE`.
	LineTooLong,
	/// The line contains non-ASCII or control characters.
	InvalidCharacters,
	/// The verb is not recognized.
	UnknownCommand,
	/// The verb is known but its arguments are malformed or missing.
	InvalidArguments,
}

/// Parse one command line (without the trailing CRLF).
pub fn parse(line: &str) -> Result<Command, ParseError> {
	if line.len() > MAX_COMMAND_LINE {
		return Err(ParseError::LineTooLong);
	}
	if line.chars().any(|c| !c.is_ascii() || c.is_ascii_control()) {
		return Err(ParseError::InvalidCharacters);
	}

	let (verb, args) = match line.split_once(' ') {
		Some((verb, args)) => (verb, args.trim()),
		None => (line, ""),
	};

	match verb.to_ascii_uppercase().as_str() {
		"HELO" => parse_domain_arg(args).map(|domain| Command::Helo { domain }),
		"EHLO" => parse_domain_arg(args).map(|domain| Command::Ehlo { domain }),
		"MAIL" => {
			parse_path_arg(args, "FROM:").map(|path| Command::MailFrom { reverse_path: path })
		}
		"RCPT" => parse_path_arg(args, "TO:").map(|path| Command::RcptTo { forward_path: path }),
		"DATA" => parse_no_args(args, Command::Data),
		"RSET" => parse_no_args(args, Command::Rset),
		"NOOP" => Ok(Command::Noop),
		"QUIT" => parse_no_args(args, Command::Quit),
		"VRFY" => Ok(Command::Vrfy),
		"STARTTLS" => parse_no_args(args, Command::StartTls),
		_ => Err(ParseError::UnknownCommand),
	}
}

fn parse_no_args(args: &str, command: Command) -> Result<Command, ParseError> {
	if args.is_empty() {
		Ok(command)
	} else {
		Err(ParseError::InvalidArguments)
	}
}

fn parse_domain_arg(args: &str) -> Result<String, ParseError> {
	if args.is_empty() || args.contains(' ') {
		return Err(ParseError::InvalidArguments);
	}
	Ok(args.to_string())
}

/// Parse `FROM:<path>` / `TO:<path>` arguments. ESMTP parameters after the
/// path are not yet supported and are rejected (fail closed).
fn parse_path_arg(args: &str, prefix: &str) -> Result<String, ParseError> {
	let rest = args
		.get(..prefix.len())
		.filter(|head| head.eq_ignore_ascii_case(prefix))
		.map(|_| args[prefix.len()..].trim_start())
		.ok_or(ParseError::InvalidArguments)?;

	let path = rest
		.strip_prefix('<')
		.and_then(|p| p.strip_suffix('>'))
		.ok_or(ParseError::InvalidArguments)?;

	if path.contains('<') || path.contains('>') || path.contains(' ') {
		return Err(ParseError::InvalidArguments);
	}
	Ok(path.to_string())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_helo_and_ehlo() {
		assert_eq!(
			parse("HELO client.example.org"),
			Ok(Command::Helo {
				domain: "client.example.org".into()
			})
		);
		assert_eq!(
			parse("ehlo client.example.org"),
			Ok(Command::Ehlo {
				domain: "client.example.org".into()
			})
		);
	}

	#[test]
	fn rejects_helo_without_domain() {
		assert_eq!(parse("HELO"), Err(ParseError::InvalidArguments));
		assert_eq!(parse("HELO "), Err(ParseError::InvalidArguments));
	}

	#[test]
	fn parses_mail_from() {
		assert_eq!(
			parse("MAIL FROM:<alice@example.org>"),
			Ok(Command::MailFrom {
				reverse_path: "alice@example.org".into()
			})
		);
	}

	#[test]
	fn parses_null_reverse_path() {
		assert_eq!(
			parse("MAIL FROM:<>"),
			Ok(Command::MailFrom {
				reverse_path: String::new()
			})
		);
	}

	#[test]
	fn parses_rcpt_to_case_insensitively() {
		assert_eq!(
			parse("rcpt to:<bob@example.org>"),
			Ok(Command::RcptTo {
				forward_path: "bob@example.org".into()
			})
		);
	}

	#[test]
	fn rejects_paths_without_angle_brackets() {
		assert_eq!(
			parse("MAIL FROM:alice@example.org"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_nested_angle_brackets() {
		assert_eq!(
			parse("MAIL FROM:<<alice@example.org>>"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_esmtp_parameters_for_now() {
		assert_eq!(
			parse("MAIL FROM:<alice@example.org> SIZE=1000"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn parses_bare_commands() {
		assert_eq!(parse("DATA"), Ok(Command::Data));
		assert_eq!(parse("RSET"), Ok(Command::Rset));
		assert_eq!(parse("QUIT"), Ok(Command::Quit));
		assert_eq!(parse("NOOP"), Ok(Command::Noop));
		assert_eq!(parse("STARTTLS"), Ok(Command::StartTls));
	}

	#[test]
	fn rejects_arguments_on_bare_commands() {
		assert_eq!(parse("DATA now"), Err(ParseError::InvalidArguments));
		assert_eq!(parse("QUIT bye"), Err(ParseError::InvalidArguments));
		assert_eq!(parse("STARTTLS x"), Err(ParseError::InvalidArguments));
	}

	#[test]
	fn vrfy_parses_regardless_of_argument() {
		assert_eq!(parse("VRFY alice"), Ok(Command::Vrfy));
		assert_eq!(parse("VRFY"), Ok(Command::Vrfy));
	}

	#[test]
	fn rejects_unknown_verbs() {
		assert_eq!(parse("EXPN list"), Err(ParseError::UnknownCommand));
		assert_eq!(parse(""), Err(ParseError::UnknownCommand));
	}

	#[test]
	fn rejects_control_characters() {
		assert_eq!(parse("NOOP\r"), Err(ParseError::InvalidCharacters));
		assert_eq!(parse("NO\0OP"), Err(ParseError::InvalidCharacters));
	}

	#[test]
	fn rejects_non_ascii() {
		assert_eq!(
			parse("HELO münchen.example"),
			Err(ParseError::InvalidCharacters)
		);
	}

	#[test]
	fn rejects_overlong_lines() {
		let line = format!("HELO {}", "a".repeat(MAX_COMMAND_LINE));
		assert_eq!(parse(&line), Err(ParseError::LineTooLong));
	}
}
