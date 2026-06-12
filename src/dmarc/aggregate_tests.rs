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
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>> {
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
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, crate::spf::DnsFailure>> + Send + '_>> {
		Box::pin(async move { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, crate::spf::DnsFailure>> + Send + '_>> {
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
