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
	/// Logical OR of two criteria.
	Or(Box<SearchKey>, Box<SearchKey>),
	/// Logical NOT of one criterion.
	Not(Box<SearchKey>),
	/// Parenthesized group: implicitly AND'd (RFC 3501 §6.4.4 search-key).
	And(Vec<SearchKey>),
	/// INTERNALDATE strictly before midnight UTC of this date (year, month, day).
	Before(u32, u8, u8),
	/// INTERNALDATE on or after midnight UTC of this date.
	Since(u32, u8, u8),
	/// INTERNALDATE falls within this date (midnight to midnight UTC).
	On(u32, u8, u8),
	/// RFC 2822 size strictly greater than n octets.
	Larger(u32),
	/// RFC 2822 size strictly less than n octets.
	Smaller(u32),
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

fn parse_seq_number(text: &str) -> Option<u32> {
	if text == "*" {
		return Some(0);
	}
	let value: u32 = text.parse().ok()?;
	if value == 0 { None } else { Some(value) }
}

/// Parse an IMAP date-text (`1-Jan-2023` or `01-Jan-2023`).
/// Returns `(year, month, day)` on success.
fn parse_imap_date(s: &str) -> Option<(u32, u8, u8)> {
	let mut parts = s.splitn(3, '-');
	let day: u8 = parts.next()?.parse().ok()?;
	let month: u8 = match parts.next()?.to_ascii_uppercase().as_str() {
		"JAN" => 1,
		"FEB" => 2,
		"MAR" => 3,
		"APR" => 4,
		"MAY" => 5,
		"JUN" => 6,
		"JUL" => 7,
		"AUG" => 8,
		"SEP" => 9,
		"OCT" => 10,
		"NOV" => 11,
		"DEC" => 12,
		_ => return None,
	};
	let year: u32 = parts.next()?.parse().ok()?;
	if day == 0 || day > 31 || month == 0 || month > 12 {
		return None;
	}
	Some((year, month, day))
}

mod parse;
mod search;

pub use parse::parse;

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;
