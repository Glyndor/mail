use super::mailbox::Snapshot;
use super::{SearchKey, mailbox};

/// Format a SystemTime as an IMAP INTERNALDATE string (RFC 3501).
pub(super) fn format_internaldate(t: std::time::SystemTime) -> String {
	const MONTHS: [&str; 12] = [
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	];
	let secs = t
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();
	let (year, month, day) = epoch_to_ymd(secs / 86400);
	let hms = secs % 86400;
	format!(
		"{:2}-{}-{:04} {:02}:{:02}:{:02} +0000",
		day,
		MONTHS[month as usize - 1],
		year,
		hms / 3600,
		(hms % 3600) / 60,
		hms % 60
	)
}

/// Proleptic Gregorian calendar: days since Unix epoch → (year, month 1-12, day 1-31).
fn epoch_to_ymd(days: u64) -> (u64, u64, u64) {
	let z = days + 719_468;
	let era = z / 146_097;
	let doe = z % 146_097;
	let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = if m <= 2 { y + 1 } else { y };
	(y, m, d)
}

pub(super) fn search_matches(
	key: &SearchKey,
	message: &mailbox::MessageRef,
	seqno: u32,
	total: u32,
	snapshot: &Snapshot,
	content: &mut Option<String>,
) -> bool {
	match key {
		SearchKey::All => true,
		SearchKey::FlagIs(flag, wanted) => message.flags.contains(flag) == *wanted,
		SearchKey::Sequence(set) => set.contains(seqno, total),
		SearchKey::UidSet(set) => set.contains(message.uid, total),
		SearchKey::Header(name, needle) => {
			let text = content.get_or_insert_with(|| load_content(snapshot, message));
			header_value(text, name).is_some_and(|v| v.contains(needle.as_str()))
		}
		SearchKey::Text(needle) => {
			let text = content.get_or_insert_with(|| load_content(snapshot, message));
			text.contains(needle.as_str())
		}
		SearchKey::Or(a, b) => {
			search_matches(a, message, seqno, total, snapshot, content)
				|| search_matches(b, message, seqno, total, snapshot, content)
		}
		SearchKey::Not(k) => !search_matches(k, message, seqno, total, snapshot, content),
		SearchKey::And(keys) => keys
			.iter()
			.all(|k| search_matches(k, message, seqno, total, snapshot, content)),
		SearchKey::Before(y, m, d) => {
			systemtime_to_epoch_day(message.internal_date) < date_to_epoch_day(*y, *m, *d)
		}
		SearchKey::Since(y, m, d) => {
			systemtime_to_epoch_day(message.internal_date) >= date_to_epoch_day(*y, *m, *d)
		}
		SearchKey::On(y, m, d) => {
			systemtime_to_epoch_day(message.internal_date) == date_to_epoch_day(*y, *m, *d)
		}
		SearchKey::Larger(n) => message.size > u64::from(*n),
		SearchKey::Smaller(n) => message.size < u64::from(*n),
	}
}

pub(super) fn load_content(snapshot: &Snapshot, message: &mailbox::MessageRef) -> String {
	snapshot
		.read(message)
		.map(|data| String::from_utf8_lossy(&data).to_ascii_lowercase())
		.unwrap_or_default()
}

/// Convert (year, month, day) UTC to days-since-Unix-epoch.
/// Algorithm: https://howardhinnant.github.io/date_algorithms.html
pub(super) fn date_to_epoch_day(year: u32, month: u8, day: u8) -> i64 {
	let y = year as i64 - if month <= 2 { 1 } else { 0 };
	let era = y.div_euclid(400);
	let yoe = y - era * 400;
	let m = month as i64;
	let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	era * 146097 + doe - 719468
}

pub(super) fn systemtime_to_epoch_day(t: std::time::SystemTime) -> i64 {
	match t.duration_since(std::time::SystemTime::UNIX_EPOCH) {
		Ok(d) => (d.as_secs() / 86400) as i64,
		Err(e) => -((e.duration().as_secs() / 86400 + 1) as i64),
	}
}

pub(super) fn header_value(lower_message: &str, name: &str) -> Option<String> {
	let header_end = lower_message
		.find("\r\n\r\n")
		.unwrap_or(lower_message.len());
	let headers = &lower_message[..header_end];
	let mut value: Option<String> = None;
	for line in headers.split("\r\n") {
		if line.starts_with(' ') || line.starts_with('\t') {
			if let Some(value) = &mut value {
				value.push(' ');
				value.push_str(line.trim());
			}
			continue;
		}
		if value.is_some() {
			break;
		}
		if let Some(rest) = line.strip_prefix(name)
			&& let Some(rest) = rest.strip_prefix(':')
		{
			value = Some(rest.trim().to_string());
		}
	}
	value
}
