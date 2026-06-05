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
	MailFrom {
		reverse_path: String,
		/// `SIZE=` parameter (RFC 1870), declared message size in bytes.
		size: Option<u64>,
		/// `BODY=` parameter (RFC 6152).
		body: Option<Body>,
	},
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

/// `BODY=` parameter values (RFC 6152).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
	SevenBit,
	EightBitMime,
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
	/// A syntactically valid ESMTP parameter this server does not implement.
	UnsupportedParameter,
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
			let (path, params) = parse_path_arg(args, "FROM:")?;
			let (size, body) = parse_mail_parameters(&params)?;
			Ok(Command::MailFrom {
				reverse_path: path,
				size,
				body,
			})
		}
		"RCPT" => {
			let (path, params) = parse_path_arg(args, "TO:")?;
			// No RCPT parameters (DSN extensions) are implemented yet.
			if !params.is_empty() {
				return Err(ParseError::UnsupportedParameter);
			}
			Ok(Command::RcptTo { forward_path: path })
		}
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

/// Parse `FROM:<path>` / `TO:<path>` arguments, returning the path and any
/// trailing ESMTP parameter string (RFC 5321 section 4.1.2).
fn parse_path_arg(args: &str, prefix: &str) -> Result<(String, String), ParseError> {
	let rest = args
		.get(..prefix.len())
		.filter(|head| head.eq_ignore_ascii_case(prefix))
		.map(|_| args[prefix.len()..].trim_start())
		.ok_or(ParseError::InvalidArguments)?;

	let after_open = rest.strip_prefix('<').ok_or(ParseError::InvalidArguments)?;
	let (path, after_close) = after_open
		.split_once('>')
		.ok_or(ParseError::InvalidArguments)?;

	if path.contains('<') || path.contains('>') || path.contains(' ') {
		return Err(ParseError::InvalidArguments);
	}
	if !after_close.is_empty() && !after_close.starts_with(' ') {
		return Err(ParseError::InvalidArguments);
	}
	Ok((path.to_string(), after_close.trim().to_string()))
}

/// Parse MAIL parameters: `SIZE=<bytes>` and `BODY=7BIT|8BITMIME` are
/// implemented; anything else is rejected as unsupported (555).
fn parse_mail_parameters(params: &str) -> Result<(Option<u64>, Option<Body>), ParseError> {
	let mut size = None;
	let mut body = None;
	for parameter in params.split_ascii_whitespace() {
		let (keyword, value) = match parameter.split_once('=') {
			Some((keyword, value)) => (keyword, Some(value)),
			None => (parameter, None),
		};
		if keyword.is_empty()
			|| !keyword
				.chars()
				.all(|c| c.is_ascii_alphanumeric() || c == '-')
		{
			return Err(ParseError::InvalidArguments);
		}
		match keyword.to_ascii_uppercase().as_str() {
			"SIZE" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				let parsed: u64 = value.parse().map_err(|_| ParseError::InvalidArguments)?;
				if size.replace(parsed).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			"BODY" => {
				let value = value.ok_or(ParseError::InvalidArguments)?;
				let parsed = match value.to_ascii_uppercase().as_str() {
					"7BIT" => Body::SevenBit,
					"8BITMIME" => Body::EightBitMime,
					_ => return Err(ParseError::InvalidArguments),
				};
				if body.replace(parsed).is_some() {
					return Err(ParseError::InvalidArguments);
				}
			}
			_ => return Err(ParseError::UnsupportedParameter),
		}
	}
	Ok((size, body))
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
				reverse_path: "alice@example.org".into(),
				size: None,
				body: None
			})
		);
	}

	#[test]
	fn parses_null_reverse_path() {
		assert_eq!(
			parse("MAIL FROM:<>"),
			Ok(Command::MailFrom {
				reverse_path: String::new(),
				size: None,
				body: None
			})
		);
	}

	#[test]
	fn parses_size_and_body_parameters() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE=1000 BODY=8BITMIME"),
			Ok(Command::MailFrom {
				reverse_path: "a@example.org".into(),
				size: Some(1000),
				body: Some(Body::EightBitMime)
			})
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> body=7bit"),
			Ok(Command::MailFrom {
				reverse_path: "a@example.org".into(),
				size: None,
				body: Some(Body::SevenBit)
			})
		);
	}

	#[test]
	fn rejects_malformed_parameters() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE=abc"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> BODY=BINARYMIME"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> SIZE=1 SIZE=2"),
			Err(ParseError::InvalidArguments)
		);
		assert_eq!(
			parse("MAIL FROM:<a@example.org> =5"),
			Err(ParseError::InvalidArguments)
		);
	}

	#[test]
	fn rejects_unsupported_parameters() {
		assert_eq!(
			parse("MAIL FROM:<a@example.org> AUTH=<>"),
			Err(ParseError::UnsupportedParameter)
		);
		assert_eq!(
			parse("RCPT TO:<b@example.org> NOTIFY=SUCCESS"),
			Err(ParseError::UnsupportedParameter)
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
	fn rejects_garbage_after_path() {
		assert_eq!(
			parse("MAIL FROM:<alice@example.org>junk"),
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
