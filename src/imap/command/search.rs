use super::parse::parse_astring;
use super::{Command, ParseError, SearchKey, parse_imap_date, parse_sequence_set};
use crate::imap::mailbox::Flag;

pub(super) fn parse_search(tag: &str, args: &str, uid: bool) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let mut criteria = Vec::new();
	let mut rest = args.trim();
	while !rest.is_empty() {
		let (key, after) = parse_search_key(rest).ok_or_else(bad)?;
		criteria.push(key);
		rest = after.trim_start();
	}
	if criteria.is_empty() {
		return Err(bad());
	}
	Ok(Command::Search { criteria, uid })
}

/// Parse one search-key from the start of `s`, return `(key, remaining)`.
pub(super) fn parse_search_key(s: &str) -> Option<(SearchKey, &str)> {
	if s.starts_with('(') {
		let close = find_close_paren(s)?;
		let inner = s[1..close].trim();
		let after = s[close + 1..].trim_start();
		let mut keys = Vec::new();
		let mut inner_rest = inner;
		while !inner_rest.is_empty() {
			let (key, rest) = parse_search_key(inner_rest)?;
			keys.push(key);
			inner_rest = rest.trim_start();
		}
		return Some((SearchKey::And(keys), after));
	}

	let (word, after) = match s.find(|c: char| c.is_ascii_whitespace() || c == '(') {
		Some(i) => (&s[..i], s[i..].trim_start()),
		None => (s, ""),
	};
	let upper = word.to_ascii_uppercase();

	let (key, rest) = match upper.as_str() {
		"ALL" => (SearchKey::All, after),
		"SEEN" => (SearchKey::FlagIs(Flag::Seen, true), after),
		"UNSEEN" => (SearchKey::FlagIs(Flag::Seen, false), after),
		"DELETED" => (SearchKey::FlagIs(Flag::Deleted, true), after),
		"UNDELETED" => (SearchKey::FlagIs(Flag::Deleted, false), after),
		"FLAGGED" => (SearchKey::FlagIs(Flag::Flagged, true), after),
		"UNFLAGGED" => (SearchKey::FlagIs(Flag::Flagged, false), after),
		"ANSWERED" => (SearchKey::FlagIs(Flag::Answered, true), after),
		"UNANSWERED" => (SearchKey::FlagIs(Flag::Answered, false), after),
		"DRAFT" => (SearchKey::FlagIs(Flag::Draft, true), after),
		"UNDRAFT" => (SearchKey::FlagIs(Flag::Draft, false), after),
		"FROM" | "TO" | "SUBJECT" => {
			let (needle, rest) = parse_astring(after)?;
			(
				SearchKey::Header(upper.to_ascii_lowercase(), needle.to_ascii_lowercase()),
				rest.trim_start(),
			)
		}
		"TEXT" => {
			let (needle, rest) = parse_astring(after)?;
			(
				SearchKey::Text(needle.to_ascii_lowercase()),
				rest.trim_start(),
			)
		}
		"UID" => {
			let (set_text, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((t, r)) => (t, r.trim_start()),
				None => (after, ""),
			};
			let set = parse_sequence_set(set_text)?;
			(SearchKey::UidSet(set), rest)
		}
		"OR" => {
			let (key1, rest1) = parse_search_key(after.trim_start())?;
			let (key2, rest2) = parse_search_key(rest1.trim_start())?;
			(SearchKey::Or(Box::new(key1), Box::new(key2)), rest2)
		}
		"NOT" => {
			let (key, rest) = parse_search_key(after.trim_start())?;
			(SearchKey::Not(Box::new(key)), rest)
		}
		"BEFORE" => {
			let (date_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((d, r)) => (d, r.trim_start()),
				None => (after, ""),
			};
			let (y, m, d) = parse_imap_date(date_str)?;
			(SearchKey::Before(y, m, d), rest)
		}
		"SINCE" => {
			let (date_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((d, r)) => (d, r.trim_start()),
				None => (after, ""),
			};
			let (y, m, d) = parse_imap_date(date_str)?;
			(SearchKey::Since(y, m, d), rest)
		}
		"ON" => {
			let (date_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((d, r)) => (d, r.trim_start()),
				None => (after, ""),
			};
			let (y, m, d) = parse_imap_date(date_str)?;
			(SearchKey::On(y, m, d), rest)
		}
		"LARGER" => {
			let (n_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((n, r)) => (n, r.trim_start()),
				None => (after, ""),
			};
			let n: u32 = n_str.parse().ok()?;
			(SearchKey::Larger(n), rest)
		}
		"SMALLER" => {
			let (n_str, rest) = match after.split_once(|c: char| c.is_ascii_whitespace()) {
				Some((n, r)) => (n, r.trim_start()),
				None => (after, ""),
			};
			let n: u32 = n_str.parse().ok()?;
			(SearchKey::Smaller(n), rest)
		}
		_ => {
			let set = parse_sequence_set(word)?;
			(SearchKey::Sequence(set), after)
		}
	};
	Some((key, rest))
}

/// Find the index of the `)` that closes the `(` at position 0 of `s`.
fn find_close_paren(s: &str) -> Option<usize> {
	let mut depth = 0usize;
	for (i, c) in s.char_indices() {
		match c {
			'(' => depth += 1,
			')' => {
				depth -= 1;
				if depth == 0 {
					return Some(i);
				}
			}
			_ => {}
		}
	}
	None
}
