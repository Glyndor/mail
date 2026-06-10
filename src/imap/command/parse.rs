use super::*;

/// Maximum literal size accepted for APPEND (matches the SMTP cap).
pub const MAX_APPEND_SIZE: usize = 25 * 1024 * 1024;

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
		"SEARCH" => super::search::parse_search(&tag, args, false)?,
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
				super::search::parse_search(&tag, sub_args, true)?
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
pub(super) fn parse_astring(input: &str) -> Option<(String, &str)> {
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
