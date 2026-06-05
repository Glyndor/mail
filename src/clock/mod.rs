//! RFC 5322 date-time formatting from system time, without external crates.
//!
//! Mail trace headers want `Day, DD Mon YYYY HH:MM:SS +0000`. The server
//! always stamps UTC, so no zone database is needed.

use std::time::{SystemTime, UNIX_EPOCH};

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format a timestamp as an RFC 5322 date-time in UTC.
pub fn rfc5322(time: SystemTime) -> String {
	let secs = time
		.duration_since(UNIX_EPOCH)
		.map(|duration| duration.as_secs() as i64)
		.unwrap_or(0);

	let days_since_epoch = secs.div_euclid(86_400);
	let seconds_of_day = secs.rem_euclid(86_400);

	let (year, month, day) = civil_from_days(days_since_epoch);
	// 1970-01-01 was a Thursday (weekday index 4).
	let weekday = (days_since_epoch + 4).rem_euclid(7) as usize;

	format!(
		"{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
		DAYS[weekday],
		day,
		MONTHS[(month - 1) as usize],
		year,
		seconds_of_day / 3600,
		(seconds_of_day % 3600) / 60,
		seconds_of_day % 60,
	)
}

/// Days-since-epoch to (year, month, day), Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z.rem_euclid(146_097);
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let year = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
	(if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;

	fn at(epoch_secs: u64) -> SystemTime {
		UNIX_EPOCH + Duration::from_secs(epoch_secs)
	}

	#[test]
	fn formats_epoch() {
		assert_eq!(rfc5322(at(0)), "Thu, 01 Jan 1970 00:00:00 +0000");
	}

	#[test]
	fn formats_known_date() {
		// 2026-06-05 12:34:56 UTC.
		assert_eq!(
			rfc5322(at(1_780_662_896)),
			"Fri, 05 Jun 2026 12:34:56 +0000"
		);
	}

	#[test]
	fn formats_leap_day() {
		// 2024-02-29 00:00:00 UTC.
		assert_eq!(
			rfc5322(at(1_709_164_800)),
			"Thu, 29 Feb 2024 00:00:00 +0000"
		);
	}

	#[test]
	fn formats_year_boundary() {
		// 2025-12-31 23:59:59 UTC.
		assert_eq!(
			rfc5322(at(1_767_225_599)),
			"Wed, 31 Dec 2025 23:59:59 +0000"
		);
	}

	#[test]
	fn pre_epoch_clamps_to_epoch() {
		let before = UNIX_EPOCH - Duration::from_secs(86_400);
		assert_eq!(rfc5322(before), "Thu, 01 Jan 1970 00:00:00 +0000");
	}
}
