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
mod tests {
	use super::*;
	use std::collections::HashMap;
	use std::net::IpAddr;
	use std::pin::Pin;

	#[derive(Default)]
	struct FakeDns {
		txt: HashMap<String, Vec<String>>,
		fail: bool,
	}

	impl crate::spf::DnsLookup for FakeDns {
		fn txt(
			&self,
			name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>>
		{
			let result = if self.fail {
				Err(crate::spf::DnsFailure::Temporary)
			} else {
				Ok(self.txt.get(name).cloned().unwrap_or_default())
			};
			Box::pin(async move { result })
		}

		fn addresses(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, crate::spf::DnsFailure>> + Send + '_>>
		{
			Box::pin(async move { Ok(Vec::new()) })
		}

		fn mx(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>>
		{
			Box::pin(async move { Ok(Vec::new()) })
		}
	}

	fn dns_with_dmarc(domain: &str, policy: &str) -> FakeDns {
		let mut dns = FakeDns::default();
		dns.txt
			.entry(format!("_dmarc.{domain}"))
			.or_default()
			.push(format!("v=DMARC1; p={policy}; rua=mailto:dmarc@{domain}"));
		dns
	}

	fn sample_record(domain: &str) -> DeliveryRecord {
		DeliveryRecord {
			timestamp: 1_700_000_000,
			source_ip: "1.2.3.4".to_string(),
			envelope_from: domain.to_string(),
			header_from: domain.to_string(),
			spf: "pass".to_string(),
			dkim: "pass".to_string(),
			dkim_domain: domain.to_string(),
			dmarc: "pass".to_string(),
			disposition: "none".to_string(),
			policy_domain: domain.to_string(),
			published_policy: "reject".to_string(),
			pct: 100,
		}
	}

	#[test]
	fn unix_to_day_known_dates() {
		// 2024-01-01 00:00:00 UTC = 1704067200
		assert_eq!(unix_to_day(1_704_067_200), "20240101");
		// 2024-02-29 00:00:00 UTC = 1709164800 (leap day)
		assert_eq!(unix_to_day(1_709_164_800), "20240229");
		// 2024-12-31 23:59:59 → still 20241231
		assert_eq!(unix_to_day(1_735_689_599), "20241231");
	}

	#[test]
	fn day_period_round_trips() {
		let day = "20240101";
		let (start, end) = day_period(day);
		assert_eq!(end - start, 86400);
		assert_eq!(unix_to_day(start), day);
		assert_eq!(unix_to_day(end - 1), day);
	}

	#[test]
	fn record_path_sanitizes_domain() {
		let dir = std::path::Path::new("/tmp");
		let path = record_path(dir, "example.org");
		assert_eq!(
			path.file_name().unwrap().to_str().unwrap(),
			"example.org.jsonl"
		);
		let path = record_path(dir, "bad/domain");
		let filename = path.file_name().unwrap().to_str().unwrap();
		assert!(!filename.contains('/'), "{filename}");
	}

	#[test]
	fn record_and_read_roundtrip() {
		let dir = tempfile::tempdir().expect("tempdir");
		let record = DeliveryRecord {
			timestamp: 1_700_000_000,
			source_ip: "1.2.3.4".to_string(),
			envelope_from: "example.org".to_string(),
			header_from: "example.org".to_string(),
			spf: "pass".to_string(),
			dkim: "pass".to_string(),
			dkim_domain: "example.org".to_string(),
			dmarc: "pass".to_string(),
			disposition: "none".to_string(),
			policy_domain: "example.org".to_string(),
			published_policy: "reject".to_string(),
			pct: 100,
		};
		record_delivery(dir.path(), "20240101", &record);
		let path = dir
			.path()
			.join("dmarc-reports")
			.join("20240101")
			.join("example.org.jsonl");
		let records = read_records(&path);
		assert_eq!(records.len(), 1);
		assert_eq!(records[0].source_ip, "1.2.3.4");
	}

	#[tokio::test]
	async fn flush_pending_generates_report_and_removes_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let record = sample_record("example.org");
		record_delivery(dir.path(), "20240101", &record);

		let dns = dns_with_dmarc("example.org", "reject");
		let messages = flush_pending(
			dir.path(),
			"20240102",
			"Org",
			"admin@org.example",
			"org.example",
			&dns,
		)
		.await;

		assert_eq!(messages.len(), 1);
		assert_eq!(messages[0].recipients, ["dmarc@example.org"]);
		assert!(messages[0].reverse_path.starts_with("postmaster@"));
		assert!(!messages[0].data.is_empty());

		let jsonl = dir
			.path()
			.join("dmarc-reports")
			.join("20240101")
			.join("example.org.jsonl");
		assert!(!jsonl.exists(), "JSONL must be removed after flush");
	}

	#[tokio::test]
	async fn flush_pending_skips_today_directory() {
		let dir = tempfile::tempdir().expect("tempdir");
		let record = sample_record("example.org");
		record_delivery(dir.path(), "20240101", &record);

		// Pass today = same day as the record directory.
		let dns = dns_with_dmarc("example.org", "reject");
		let messages = flush_pending(
			dir.path(),
			"20240101",
			"Org",
			"admin@org.example",
			"org.example",
			&dns,
		)
		.await;

		assert!(messages.is_empty(), "today's directory must not be flushed");
		let jsonl = dir
			.path()
			.join("dmarc-reports")
			.join("20240101")
			.join("example.org.jsonl");
		assert!(jsonl.exists(), "file must remain when directory is skipped");
	}

	#[tokio::test]
	async fn flush_pending_no_rua_removes_file_without_sending() {
		let dir = tempfile::tempdir().expect("tempdir");
		let record = sample_record("example.org");
		record_delivery(dir.path(), "20240101", &record);

		// DNS returns no DMARC record at all.
		let dns = FakeDns::default();
		let messages = flush_pending(
			dir.path(),
			"20240102",
			"Org",
			"admin@org.example",
			"org.example",
			&dns,
		)
		.await;

		assert!(messages.is_empty(), "no rua= must produce no messages");
		let jsonl = dir
			.path()
			.join("dmarc-reports")
			.join("20240101")
			.join("example.org.jsonl");
		assert!(
			!jsonl.exists(),
			"file must still be removed when rua= absent"
		);
	}

	#[tokio::test]
	async fn flush_pending_empty_records_removes_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let day_dir = dir.path().join("dmarc-reports").join("20240101");
		std::fs::create_dir_all(&day_dir).expect("mkdir");
		std::fs::write(day_dir.join("example.org.jsonl"), b"").expect("write");

		let dns = dns_with_dmarc("example.org", "reject");
		let messages = flush_pending(
			dir.path(),
			"20240102",
			"Org",
			"admin@org.example",
			"org.example",
			&dns,
		)
		.await;

		assert!(messages.is_empty());
		assert!(!day_dir.join("example.org.jsonl").exists());
	}

	#[tokio::test]
	async fn flush_pending_empty_root_returns_empty() {
		let dir = tempfile::tempdir().expect("tempdir");
		// No dmarc-reports directory at all.
		let dns = dns_with_dmarc("example.org", "reject");
		let messages = flush_pending(
			dir.path(),
			"20240102",
			"Org",
			"admin@org.example",
			"org.example",
			&dns,
		)
		.await;
		assert!(messages.is_empty());
	}

	#[tokio::test]
	async fn flush_pending_dns_failure_removes_file_without_sending() {
		let dir = tempfile::tempdir().expect("tempdir");
		let record = sample_record("example.org");
		record_delivery(dir.path(), "20240101", &record);

		let dns = FakeDns {
			fail: true,
			..FakeDns::default()
		};
		let messages = flush_pending(
			dir.path(),
			"20240102",
			"Org",
			"admin@org.example",
			"org.example",
			&dns,
		)
		.await;

		assert!(messages.is_empty(), "DNS failure must produce no messages");
		let jsonl = dir
			.path()
			.join("dmarc-reports")
			.join("20240101")
			.join("example.org.jsonl");
		assert!(!jsonl.exists(), "file must still be removed on DNS failure");
	}
}
