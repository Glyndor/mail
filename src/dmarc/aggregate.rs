//! DMARC aggregate report accumulation and flushing (RFC 7489 §7.2).
//!
//! Records are written as JSONL to
//! `{data_dir}/dmarc-reports/{YYYYMMDD}/{from_domain}.jsonl`
//! by `record_delivery()` during inbound SMTP processing.
//!
//! `flush_day()` reads completed-day directories, generates XML reports,
//! and returns `Vec<(recipient, AcceptedMessage)>` for the caller to queue.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::smtp::session::AcceptedMessage;

use super::report::{DeliveryRecord, build_email, build_xml};

/// Write one delivery record to the per-domain JSONL file for today.
/// Errors are logged but not propagated — losing a few records is
/// preferable to blocking the delivery path.
pub fn record_delivery(data_dir: &Path, today: &str, record: &DeliveryRecord) {
	let dir = data_dir.join("dmarc-reports").join(today);
	let _ = std::fs::create_dir_all(&dir);
	let path = record_path(&dir, &record.header_from);
	let Ok(mut file) = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(&path)
	else {
		tracing::warn!(path = %path.display(), "cannot open dmarc record file");
		return;
	};
	match serde_json::to_string(record) {
		Ok(line) => {
			use std::io::Write;
			let _ = writeln!(file, "{line}");
		}
		Err(e) => tracing::warn!(%e, "cannot serialize dmarc record"),
	}
}

/// Generate and queue reports for every completed reporting day that has
/// accumulated records and a known rua= address. Returns one
/// `AcceptedMessage` per rua= recipient per domain.
///
/// `today` is `"YYYYMMDD"` of the current day; completed days are those
/// that are older (different from `today`).
pub async fn flush_pending(
	data_dir: &Path,
	today: &str,
	org_name: &str,
	org_email: &str,
	reporting_domain: &str,
	dns: &dyn crate::spf::DnsLookup,
) -> Vec<AcceptedMessage> {
	let reports_root = data_dir.join("dmarc-reports");
	let Ok(entries) = std::fs::read_dir(&reports_root) else {
		return Vec::new();
	};

	let mut messages = Vec::new();

	for entry in entries.flatten() {
		let day = match entry.file_name().into_string() {
			Ok(s) if s != today && s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) => s,
			_ => continue,
		};

		let day_dir = entry.path();
		let Ok(domain_files) = std::fs::read_dir(&day_dir) else {
			continue;
		};

		let mut to_remove: Vec<PathBuf> = Vec::new();

		for domain_entry in domain_files.flatten() {
			let path = domain_entry.path();
			if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
				continue;
			}
			let from_domain = match path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) {
				Some(d) if !d.is_empty() => d,
				_ => continue,
			};

			let records = read_records(&path);
			if records.is_empty() {
				to_remove.push(path);
				continue;
			}

			// Look up rua= for this domain's DMARC record.
			let rua = match lookup_rua(dns, &from_domain).await {
				Some(r) => r,
				None => {
					// No rua= or DNS failure — skip sending but still remove.
					to_remove.push(path);
					continue;
				}
			};

			let (period_start, period_end) = day_period(&day);
			let report_id = format!("{reporting_domain}.{from_domain}.{period_start}");
			let gz = build_xml(
				org_name,
				org_email,
				&report_id,
				period_start,
				period_end,
				&from_domain,
				&records,
			);

			for uri in &rua {
				let Some(to_addr) = uri.strip_prefix("mailto:") else {
					continue;
				};
				let email_bytes = build_email(
					&from_domain,
					to_addr,
					&report_id,
					period_start,
					period_end,
					reporting_domain,
					&gz,
				);
				messages.push(AcceptedMessage {
					reverse_path: format!("postmaster@{reporting_domain}"),
					recipients: vec![to_addr.to_string()],
					data: email_bytes,
				});
			}
			to_remove.push(path);
		}

		// Remove processed files.
		for path in to_remove {
			let _ = std::fs::remove_file(&path);
		}
		// Remove empty day directory.
		let _ = std::fs::remove_dir(&day_dir);
	}

	messages
}

fn record_path(dir: &Path, domain: &str) -> PathBuf {
	// Sanitize domain for use as a filename: keep alnum, dots, hyphens.
	let safe: String = domain
		.chars()
		.map(|c| {
			if c.is_alphanumeric() || c == '.' || c == '-' {
				c
			} else {
				'_'
			}
		})
		.collect();
	dir.join(format!("{safe}.jsonl"))
}

fn read_records(path: &Path) -> Vec<DeliveryRecord> {
	let Ok(file) = std::fs::File::open(path) else {
		return Vec::new();
	};
	std::io::BufReader::new(file)
		.lines()
		.map_while(Result::ok)
		.filter(|l| !l.is_empty())
		.filter_map(|l| serde_json::from_str::<DeliveryRecord>(&l).ok())
		.collect()
}

/// Return the rua= list from the domain's live DMARC record, or None.
async fn lookup_rua(dns: &dyn crate::spf::DnsLookup, domain: &str) -> Option<Vec<String>> {
	let txt = format!("_dmarc.{domain}");
	let records = dns.txt(&txt).await.ok()?;
	for record in &records {
		if let Some(Ok(dmarc)) = super::record::parse(record)
			&& !dmarc.rua.is_empty()
		{
			return Some(dmarc.rua);
		}
	}
	None
}

/// Convert a `"YYYYMMDD"` day string to a (period_start, period_end) in Unix seconds.
fn day_period(day: &str) -> (u64, u64) {
	// Parse YYYY MM DD as UTC midnight..next midnight.
	let year: u64 = day[..4].parse().unwrap_or(0);
	let month: u64 = day[4..6].parse().unwrap_or(0);
	let dom: u64 = day[6..8].parse().unwrap_or(0);
	let start = ymd_to_unix(year, month, dom);
	(start, start + 86400)
}

/// Hinnant's algorithm: convert (year, month, day) to days since Unix epoch.
fn ymd_to_unix(y: u64, m: u64, d: u64) -> u64 {
	let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
	let era = y / 400;
	let yoe = y - era * 400;
	let doy = (153 * m + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	(era * 146097 + doe).wrapping_sub(719468) * 86400
}

/// Return today's date as `"YYYYMMDD"` using the given Unix timestamp.
pub fn unix_to_day(ts: u64) -> String {
	// Reverse Hinnant: days since epoch → Gregorian.
	let days = ts / 86400;
	let z = days.wrapping_add(719468);
	let era = z / 146097;
	let doe = z - era * 146097;
	let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	let y = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = doy - (153 * mp + 2) / 5 + 1;
	let m = if mp < 10 { mp + 3 } else { mp - 9 };
	let y = if m <= 2 { y + 1 } else { y };
	format!("{y:04}{m:02}{d:02}")
}

#[cfg(test)]
#[path = "aggregate_tests.rs"]
mod tests;
