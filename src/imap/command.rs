//! IMAP command parsing (RFC 9051 section 6), strict subset.

/// Maximum command line length accepted.
pub const MAX_COMMAND_LINE: usize = 8192;

/// A parsed client command with its tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tagged {
	pub tag: String,
	pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	Capability,
	Noop,
	Logout,
	StartTls,
	Login {
		username: String,
		password: String,
	},
	List {
		reference: String,
		pattern: String,
	},
	Select {
		mailbox: String,
	},
	Examine {
		mailbox: String,
	},
	Close,
	Create {
		mailbox: String,
	},
	Delete {
		mailbox: String,
	},
	Rename {
		from: String,
		to: String,
	},
	Expunge,
	Idle,
	/// `APPEND <mailbox> [(flags)] {size}` — the literal body follows.
	Append {
		mailbox: String,
		flags: Vec<String>,
		size: usize,
	},
	Fetch {
		sequence: SequenceSet,
		items: Vec<FetchItem>,
		uid: bool,
	},
	Store {
		sequence: SequenceSet,
		mode: StoreMode,
		flags: Vec<String>,
		silent: bool,
		uid: bool,
	},
	Copy {
		sequence: SequenceSet,
		mailbox: String,
		uid: bool,
		/// MOVE removes the source messages after copying.
		remove_source: bool,
	},
	Search {
		criteria: Vec<SearchKey>,
		uid: bool,
	},
	Status {
		mailbox: String,
		items: Vec<StatusItem>,
	},
	Subscribe {
		mailbox: String,
	},
	Unsubscribe {
		mailbox: String,
	},
	Lsub {
		reference: String,
		pattern: String,
	},
}

/// Items that can be requested in a STATUS command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusItem {
	Messages,
	Recent,
	Uidnext,
	Uidvalidity,
	Unseen,
}

/// A single SEARCH criterion; multiple keys AND together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
	All,
	/// Flag present (true) or absent (false).
	FlagIs(super::mailbox::Flag, bool),
	/// Header substring: (header name lowercased, needle lowercased).
	Header(String, String),
	/// Substring anywhere in the message (headers + body).
	Text(String),
	/// Explicit message sequence set.
	Sequence(SequenceSet),
	/// Explicit UID set (`UID <set>`).
	UidSet(SequenceSet),
}

/// How STORE changes the flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
	Set,
	Add,
	Remove,
}

/// What FETCH must return per message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchItem {
	Flags,
	Rfc822Size,
	Uid,
	/// `BODY[]` / `RFC822`: the full raw message.
	Body,
	InternalDate,
}

/// A `1`, `1:5`, `1:*`, `*` style sequence set (comma-separated ranges).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSet {
	pub ranges: Vec<(u32, Option<u32>)>,
}

impl SequenceSet {
	/// Whether `value` (a sequence number or UID) is included, given the
	/// maximum existing value for `*`.
	pub fn contains(&self, value: u32, max: u32) -> bool {
		self.ranges.iter().any(|(start, end)| {
			let start = *start;
			let end = end.unwrap_or(start);
			let (low, high) = if start == 0 {
				(max, end.min(max).max(max))
			} else if end == 0 {
				(start.min(max), max)
			} else if start <= end {
				(start, end)
			} else {
				(end, start)
			};
			value >= low && value <= high
		})
	}
}

/// Why a line failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
	/// No tag or malformed structure: answered with `* BAD`.
	Malformed,
	/// Valid tag but unknown/unsupported command: tagged `BAD`.
	Unknown(String),
	/// Valid tag, known command, bad arguments: tagged `BAD`.
	BadArguments(String),
}

/// Parse one command line.
pub fn parse(line: &str) -> Result<Tagged, ParseError> {
	if line.len() > MAX_COMMAND_LINE || line.chars().any(|c| c.is_ascii_control()) {
		return Err(ParseError::Malformed);
	}
	let (tag, rest) = line.split_once(' ').ok_or(ParseError::Malformed)?;
	let valid_tag = !tag.is_empty()
		&& tag.len() <= 32
		&& tag
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || ".-_+".contains(c));
	if !valid_tag {
		return Err(ParseError::Malformed);
	}
	let tag = tag.to_string();

	let (verb, args) = match rest.split_once(' ') {
		Some((verb, args)) => (verb, args),
		None => (rest, ""),
	};

	let command = match verb.to_ascii_uppercase().as_str() {
		"CAPABILITY" => no_args(&tag, args, Command::Capability)?,
		"NOOP" => no_args(&tag, args, Command::Noop)?,
		"LOGOUT" => no_args(&tag, args, Command::Logout)?,
		"STARTTLS" => no_args(&tag, args, Command::StartTls)?,
		"LOGIN" => parse_login(&tag, args)?,
		"LIST" => parse_list(&tag, args)?,
		"SELECT" => Command::Select {
			mailbox: parse_mailbox(&tag, args)?,
		},
		"EXAMINE" => Command::Examine {
			mailbox: parse_mailbox(&tag, args)?,
		},
		"CLOSE" => no_args(&tag, args, Command::Close)?,
		"CREATE" => Command::Create {
			mailbox: parse_mailbox(&tag, args)?,
		},
		"DELETE" => Command::Delete {
			mailbox: parse_mailbox(&tag, args)?,
		},
		"RENAME" => {
			let bad = || ParseError::BadArguments(tag.clone());
			let (from, rest) = parse_astring(args).ok_or_else(bad)?;
			let (to, rest) = parse_astring(rest).ok_or_else(bad)?;
			if !rest.trim().is_empty() || from.is_empty() || to.is_empty() {
				return Err(bad());
			}
			Command::Rename { from, to }
		}
		"EXPUNGE" => no_args(&tag, args, Command::Expunge)?,
		"IDLE" => no_args(&tag, args, Command::Idle)?,
		"APPEND" => parse_append(&tag, args)?,
		"FETCH" => parse_fetch(&tag, args, false)?,
		"STORE" => parse_store(&tag, args, false)?,
		"COPY" => parse_copy(&tag, args, false, false)?,
		"MOVE" => parse_copy(&tag, args, false, true)?,
		"SEARCH" => parse_search(&tag, args, false)?,
		"STATUS" => parse_status(&tag, args)?,
		"SUBSCRIBE" => Command::Subscribe {
			mailbox: parse_mailbox(&tag, args)?,
		},
		"UNSUBSCRIBE" => Command::Unsubscribe {
			mailbox: parse_mailbox(&tag, args)?,
		},
		"LSUB" => {
			let (reference, rest) =
				parse_astring(args).ok_or_else(|| ParseError::BadArguments(tag.clone()))?;
			let (pattern, rest) =
				parse_astring(rest).ok_or_else(|| ParseError::BadArguments(tag.clone()))?;
			if !rest.trim().is_empty() {
				return Err(ParseError::BadArguments(tag));
			}
			Command::Lsub { reference, pattern }
		}
		"UID" => {
			let (sub, sub_args) = args
				.split_once(' ')
				.ok_or_else(|| ParseError::BadArguments(tag.clone()))?;
			if sub.eq_ignore_ascii_case("FETCH") {
				parse_fetch(&tag, sub_args, true)?
			} else if sub.eq_ignore_ascii_case("STORE") {
				parse_store(&tag, sub_args, true)?
			} else if sub.eq_ignore_ascii_case("COPY") {
				parse_copy(&tag, sub_args, true, false)?
			} else if sub.eq_ignore_ascii_case("MOVE") {
				parse_copy(&tag, sub_args, true, true)?
			} else if sub.eq_ignore_ascii_case("SEARCH") {
				parse_search(&tag, sub_args, true)?
			} else {
				return Err(ParseError::Unknown(tag));
			}
		}
		_ => return Err(ParseError::Unknown(tag)),
	};
	Ok(Tagged { tag, command })
}

fn no_args(tag: &str, args: &str, command: Command) -> Result<Command, ParseError> {
	if args.is_empty() {
		Ok(command)
	} else {
		Err(ParseError::BadArguments(tag.to_string()))
	}
}

/// An astring: quoted string or bare atom. Literals are not supported yet.
fn parse_astring(input: &str) -> Option<(String, &str)> {
	let input = input.trim_start();
	if let Some(rest) = input.strip_prefix('"') {
		let mut value = String::new();
		let mut chars = rest.char_indices();
		while let Some((index, c)) = chars.next() {
			match c {
				'\\' => {
					let (_, escaped) = chars.next()?;
					value.push(escaped);
				}
				'"' => return Some((value, &rest[index + 1..])),
				_ => value.push(c),
			}
		}
		None
	} else {
		let end = input.find(' ').unwrap_or(input.len());
		if end == 0 {
			return None;
		}
		Some((input[..end].to_string(), &input[end..]))
	}
}

fn parse_login(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (username, rest) = parse_astring(args).ok_or_else(bad)?;
	let (password, rest) = parse_astring(rest).ok_or_else(bad)?;
	if !rest.trim().is_empty() || username.is_empty() || password.is_empty() {
		return Err(bad());
	}
	Ok(Command::Login { username, password })
}

fn parse_list(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (reference, rest) = parse_astring(args).ok_or_else(bad)?;
	let (pattern, rest) = parse_astring(rest).ok_or_else(bad)?;
	if !rest.trim().is_empty() {
		return Err(bad());
	}
	Ok(Command::List { reference, pattern })
}

fn parse_mailbox(tag: &str, args: &str) -> Result<String, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, rest) = parse_astring(args).ok_or_else(bad)?;
	if !rest.trim().is_empty() || mailbox.is_empty() {
		return Err(bad());
	}
	Ok(mailbox)
}

fn parse_fetch(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (sequence_text, items_text) = args.split_once(' ').ok_or_else(bad)?;
	let sequence = parse_sequence_set(sequence_text).ok_or_else(bad)?;

	let items_text = items_text.trim();
	let inner = items_text
		.strip_prefix('(')
		.and_then(|t| t.strip_suffix(')'))
		.unwrap_or(items_text);
	let mut items = Vec::new();
	for word in inner.split_whitespace() {
		match word.to_ascii_uppercase().as_str() {
			"FLAGS" => items.push(FetchItem::Flags),
			"RFC822.SIZE" => items.push(FetchItem::Rfc822Size),
			"UID" => items.push(FetchItem::Uid),
			"INTERNALDATE" => items.push(FetchItem::InternalDate),
			"BODY[]" | "BODY.PEEK[]" | "RFC822" => items.push(FetchItem::Body),
			"ALL" => {
				items.extend([
					FetchItem::Flags,
					FetchItem::InternalDate,
					FetchItem::Rfc822Size,
				]);
			}
			"FAST" => {
				items.extend([
					FetchItem::Flags,
					FetchItem::InternalDate,
					FetchItem::Rfc822Size,
				]);
			}
			_ => return Err(bad()),
		}
	}
	if items.is_empty() {
		return Err(bad());
	}
	// UID FETCH must always report the UID (RFC 9051 section 6.4.8).
	if uid && !items.contains(&FetchItem::Uid) {
		items.push(FetchItem::Uid);
	}
	Ok(Command::Fetch {
		sequence,
		items,
		uid,
	})
}

/// Maximum literal size accepted for APPEND (matches the SMTP cap).
pub const MAX_APPEND_SIZE: usize = 25 * 1024 * 1024;

fn parse_append(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, rest) = parse_astring(args).ok_or_else(bad)?;
	if mailbox.is_empty() {
		return Err(bad());
	}
	let rest = rest.trim();

	// Optional flag list, then the literal size.
	let (flags, literal_text) = if let Some(after) = rest.strip_prefix('(') {
		let (inside, after) = after.split_once(')').ok_or_else(bad)?;
		(
			inside
				.split_whitespace()
				.map(|token| token.to_string())
				.collect(),
			after.trim(),
		)
	} else {
		(Vec::new(), rest)
	};

	// `{n}` synchronizing or `{n+}` non-synchronizing literal.
	let size_text = literal_text
		.strip_prefix('{')
		.and_then(|t| t.strip_suffix('}'))
		.ok_or_else(bad)?;
	let size_text = size_text.strip_suffix('+').unwrap_or(size_text);
	let size: usize = size_text.parse().map_err(|_| bad())?;
	if size == 0 || size > MAX_APPEND_SIZE {
		return Err(bad());
	}
	Ok(Command::Append {
		mailbox,
		flags,
		size,
	})
}

fn parse_search(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	use crate::imap::mailbox::Flag;
	let bad = || ParseError::BadArguments(tag.to_string());

	let mut criteria = Vec::new();
	let mut rest = args.trim();
	while !rest.is_empty() {
		let (word, after) = match rest.split_once(' ') {
			Some((word, after)) => (word, after.trim_start()),
			None => (rest, ""),
		};
		let upper = word.to_ascii_uppercase();
		let key = match upper.as_str() {
			"ALL" => {
				rest = after;
				criteria.push(SearchKey::All);
				continue;
			}
			"SEEN" => SearchKey::FlagIs(Flag::Seen, true),
			"UNSEEN" => SearchKey::FlagIs(Flag::Seen, false),
			"DELETED" => SearchKey::FlagIs(Flag::Deleted, true),
			"UNDELETED" => SearchKey::FlagIs(Flag::Deleted, false),
			"FLAGGED" => SearchKey::FlagIs(Flag::Flagged, true),
			"UNFLAGGED" => SearchKey::FlagIs(Flag::Flagged, false),
			"ANSWERED" => SearchKey::FlagIs(Flag::Answered, true),
			"UNANSWERED" => SearchKey::FlagIs(Flag::Answered, false),
			"DRAFT" => SearchKey::FlagIs(Flag::Draft, true),
			"UNDRAFT" => SearchKey::FlagIs(Flag::Draft, false),
			"FROM" | "TO" | "SUBJECT" => {
				let (needle, after_value) = parse_astring(after).ok_or_else(bad)?;
				rest = after_value.trim_start();
				criteria.push(SearchKey::Header(
					upper.to_ascii_lowercase(),
					needle.to_ascii_lowercase(),
				));
				continue;
			}
			"TEXT" => {
				let (needle, after_value) = parse_astring(after).ok_or_else(bad)?;
				rest = after_value.trim_start();
				criteria.push(SearchKey::Text(needle.to_ascii_lowercase()));
				continue;
			}
			"UID" => {
				let (set_text, after_value) = match after.split_once(' ') {
					Some((set_text, after_value)) => (set_text, after_value.trim_start()),
					None => (after, ""),
				};
				let set = parse_sequence_set(set_text).ok_or_else(bad)?;
				rest = after_value;
				criteria.push(SearchKey::UidSet(set));
				continue;
			}
			_ => match parse_sequence_set(word) {
				Some(set) => SearchKey::Sequence(set),
				None => return Err(bad()),
			},
		};
		rest = after;
		criteria.push(key);
	}
	if criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Search { criteria, uid })
}

fn parse_copy(
	tag: &str,
	args: &str,
	uid: bool,
	remove_source: bool,
) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (sequence_text, mailbox_text) = args.split_once(' ').ok_or_else(bad)?;
	let sequence = parse_sequence_set(sequence_text).ok_or_else(bad)?;
	let (mailbox, rest) = parse_astring(mailbox_text).ok_or_else(bad)?;
	if !rest.trim().is_empty() || mailbox.is_empty() {
		return Err(bad());
	}
	Ok(Command::Copy {
		sequence,
		mailbox,
		uid,
		remove_source,
	})
}

fn parse_store(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (sequence_text, rest) = args.split_once(' ').ok_or_else(bad)?;
	let sequence = parse_sequence_set(sequence_text).ok_or_else(bad)?;

	let (item, flags_text) = rest.split_once(' ').ok_or_else(bad)?;
	let item = item.to_ascii_uppercase();
	let (mode, silent) = match item.as_str() {
		"FLAGS" => (StoreMode::Set, false),
		"FLAGS.SILENT" => (StoreMode::Set, true),
		"+FLAGS" => (StoreMode::Add, false),
		"+FLAGS.SILENT" => (StoreMode::Add, true),
		"-FLAGS" => (StoreMode::Remove, false),
		"-FLAGS.SILENT" => (StoreMode::Remove, true),
		_ => return Err(bad()),
	};

	let flags_text = flags_text.trim();
	let inner = flags_text
		.strip_prefix('(')
		.and_then(|t| t.strip_suffix(')'))
		.unwrap_or(flags_text);
	let flags: Vec<String> = inner
		.split_whitespace()
		.map(|token| token.to_string())
		.collect();
	Ok(Command::Store {
		sequence,
		mode,
		flags,
		silent,
		uid,
	})
}

/// Parse `1`, `1:5`, `1:*`, `*`, comma-separated. `0` encodes `*` here.
fn parse_sequence_set(text: &str) -> Option<SequenceSet> {
	let mut ranges = Vec::new();
	for part in text.split(',') {
		let (start, end) = match part.split_once(':') {
			Some((start, end)) => (parse_seq_number(start)?, Some(parse_seq_number(end)?)),
			None => (parse_seq_number(part)?, None),
		};
		ranges.push((start, end));
	}
	if ranges.is_empty() {
		return None;
	}
	Some(SequenceSet { ranges })
}

fn parse_status(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, rest) = parse_astring(args).ok_or_else(bad)?;
	if mailbox.is_empty() {
		return Err(bad());
	}
	let rest = rest.trim();
	let inner = rest
		.strip_prefix('(')
		.and_then(|t| t.strip_suffix(')'))
		.ok_or_else(bad)?;
	let mut items = Vec::new();
	for word in inner.split_whitespace() {
		let item = match word.to_ascii_uppercase().as_str() {
			"MESSAGES" => StatusItem::Messages,
			"RECENT" => StatusItem::Recent,
			"UIDNEXT" => StatusItem::Uidnext,
			"UIDVALIDITY" => StatusItem::Uidvalidity,
			"UNSEEN" => StatusItem::Unseen,
			_ => return Err(bad()),
		};
		items.push(item);
	}
	if items.is_empty() {
		return Err(bad());
	}
	Ok(Command::Status { mailbox, items })
}

fn parse_seq_number(text: &str) -> Option<u32> {
	if text == "*" {
		return Some(0);
	}
	let value: u32 = text.parse().ok()?;
	if value == 0 { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_simple_commands() {
		assert_eq!(
			parse("a1 CAPABILITY").expect("parses").command,
			Command::Capability
		);
		assert_eq!(parse("a2 noop").expect("parses").command, Command::Noop);
		assert_eq!(parse("a3 LOGOUT").expect("parses").tag, "a3".to_string());
	}

	#[test]
	fn parses_login_with_quoted_strings() {
		let parsed = parse(r#"a1 LOGIN "alice" "p@ss w\"ord""#).expect("parses");
		assert_eq!(
			parsed.command,
			Command::Login {
				username: "alice".into(),
				password: "p@ss w\"ord".into()
			}
		);
	}

	#[test]
	fn parses_login_with_atoms() {
		let parsed = parse("a1 LOGIN alice@example.org secret").expect("parses");
		assert_eq!(
			parsed.command,
			Command::Login {
				username: "alice@example.org".into(),
				password: "secret".into()
			}
		);
	}

	#[test]
	fn parses_list_and_select() {
		assert_eq!(
			parse(r#"a1 LIST "" "*""#).expect("parses").command,
			Command::List {
				reference: String::new(),
				pattern: "*".into()
			}
		);
		assert_eq!(
			parse("a2 SELECT INBOX").expect("parses").command,
			Command::Select {
				mailbox: "INBOX".into()
			}
		);
	}

	#[test]
	fn parses_fetch_variants() {
		let parsed = parse("a1 FETCH 1:5 (FLAGS RFC822.SIZE)").expect("parses");
		let Command::Fetch {
			sequence,
			items,
			uid,
		} = parsed.command
		else {
			panic!("expected fetch");
		};
		assert!(!uid);
		assert_eq!(items, vec![FetchItem::Flags, FetchItem::Rfc822Size]);
		assert!(sequence.contains(3, 10));
		assert!(!sequence.contains(6, 10));

		let parsed = parse("a2 UID FETCH 1:* (BODY[])").expect("parses");
		let Command::Fetch { items, uid, .. } = parsed.command else {
			panic!("expected fetch");
		};
		assert!(uid);
		assert!(items.contains(&FetchItem::Body));
		assert!(items.contains(&FetchItem::Uid));
	}

	#[test]
	fn sequence_star_means_max() {
		let set = parse_sequence_set("*").expect("parses");
		assert!(set.contains(7, 7));
		assert!(!set.contains(6, 7));
		let set = parse_sequence_set("3:*").expect("parses");
		assert!(set.contains(3, 7));
		assert!(set.contains(7, 7));
		assert!(!set.contains(2, 7));
	}

	#[test]
	fn rejects_malformed_lines() {
		assert_eq!(parse("CAPABILITY"), Err(ParseError::Malformed));
		assert_eq!(parse(""), Err(ParseError::Malformed));
		assert_eq!(parse("ta!g NOOP"), Err(ParseError::Malformed));
	}

	#[test]
	fn unknown_commands_keep_the_tag() {
		assert_eq!(
			parse("a1 XFROBNICATE"),
			Err(ParseError::Unknown("a1".to_string()))
		);
		assert_eq!(
			parse("a2 STARTTLS").expect("parses").command,
			Command::StartTls
		);
	}

	#[test]
	fn rejects_bad_arguments() {
		assert_eq!(
			parse("a1 LOGIN onlyuser"),
			Err(ParseError::BadArguments("a1".to_string()))
		);
		assert_eq!(
			parse("a1 FETCH 0 (FLAGS)"),
			Err(ParseError::BadArguments("a1".to_string()))
		);
		assert_eq!(
			parse("a1 FETCH 1 (BOGUS)"),
			Err(ParseError::BadArguments("a1".to_string()))
		);
	}
}
