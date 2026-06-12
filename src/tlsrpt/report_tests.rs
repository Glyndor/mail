use super::*;

fn session(result: &str, ip: &str) -> TlsSession {
	TlsSession {
		timestamp: 1_700_000_000,
		policy_type: "sts".to_string(),
		policy_domain: "example.com".to_string(),
		policy_strings: vec!["version: STSv1".to_string(), "mode: enforce".to_string()],
		mx_host: vec!["*.mail.example.com".to_string()],
		sending_mta_ip: "203.0.113.5".to_string(),
		receiving_mx_hostname: "mx.example.com".to_string(),
		receiving_ip: ip.to_string(),
		result: result.to_string(),
	}
}

fn parse(json: &str) -> serde_json::Value {
	serde_json::from_str(json).expect("valid json")
}

#[test]
fn json_has_required_top_level_fields() {
	let json = generate_json(
		"Test Org",
		"mailto:tlsrpt@test.org",
		"report-1",
		1_700_000_000,
		1_700_086_400,
		&[session(RESULT_SUCCESS, "198.51.100.1")],
	);
	let v = parse(&json);
	assert_eq!(v["organization-name"], "Test Org");
	assert_eq!(v["contact-info"], "mailto:tlsrpt@test.org");
	assert_eq!(v["report-id"], "report-1");
	assert_eq!(v["date-range"]["start-datetime"], "2023-11-14T22:13:20Z");
	assert_eq!(v["date-range"]["end-datetime"], "2023-11-15T22:13:20Z");
	assert!(v["policies"].is_array());
}

#[test]
fn successful_sessions_count_in_summary() {
	let json = generate_json(
		"Org",
		"mailto:r@org.example",
		"r",
		0,
		86400,
		&[
			session(RESULT_SUCCESS, "198.51.100.1"),
			session(RESULT_SUCCESS, "198.51.100.1"),
		],
	);
	let v = parse(&json);
	let summary = &v["policies"][0]["summary"];
	assert_eq!(summary["total-successful-session-count"], 2);
	assert_eq!(summary["total-failure-session-count"], 0);
	// No failures → failure-details omitted entirely.
	assert!(v["policies"][0].get("failure-details").is_none());
}

#[test]
fn policy_block_carries_policy_metadata() {
	let json = generate_json(
		"Org",
		"mailto:r@org.example",
		"r",
		0,
		86400,
		&[session(RESULT_SUCCESS, "198.51.100.1")],
	);
	let v = parse(&json);
	let policy = &v["policies"][0]["policy"];
	assert_eq!(policy["policy-type"], "sts");
	assert_eq!(policy["policy-domain"], "example.com");
	assert_eq!(policy["mx-host"][0], "*.mail.example.com");
	assert_eq!(policy["policy-string"][1], "mode: enforce");
}

#[test]
fn failures_are_grouped_and_counted() {
	let json = generate_json(
		"Org",
		"mailto:r@org.example",
		"r",
		0,
		86400,
		&[
			session("certificate-expired", "198.51.100.1"),
			session("certificate-expired", "198.51.100.1"),
			session("starttls-not-supported", "198.51.100.2"),
		],
	);
	let v = parse(&json);
	let policy = &v["policies"][0];
	assert_eq!(policy["summary"]["total-failure-session-count"], 3);
	let details = policy["failure-details"].as_array().expect("array");
	assert_eq!(details.len(), 2);
	// Sorted by key: certificate-expired before starttls-not-supported.
	assert_eq!(details[0]["result-type"], "certificate-expired");
	assert_eq!(details[0]["failed-session-count"], 2);
	assert_eq!(details[0]["sending-mta-ip"], "203.0.113.5");
	assert_eq!(details[0]["receiving-mx-hostname"], "mx.example.com");
	assert_eq!(details[1]["result-type"], "starttls-not-supported");
	assert_eq!(details[1]["failed-session-count"], 1);
}

#[test]
fn mixed_success_and_failure_in_one_policy() {
	let json = generate_json(
		"Org",
		"mailto:r@org.example",
		"r",
		0,
		86400,
		&[
			session(RESULT_SUCCESS, "198.51.100.1"),
			session("validation-failure", "198.51.100.1"),
		],
	);
	let v = parse(&json);
	let summary = &v["policies"][0]["summary"];
	assert_eq!(summary["total-successful-session-count"], 1);
	assert_eq!(summary["total-failure-session-count"], 1);
}

#[test]
fn distinct_policy_types_produce_separate_blocks() {
	let mut tlsa = session(RESULT_SUCCESS, "198.51.100.1");
	tlsa.policy_type = "tlsa".to_string();
	let json = generate_json(
		"Org",
		"mailto:r@org.example",
		"r",
		0,
		86400,
		&[session(RESULT_SUCCESS, "198.51.100.1"), tlsa],
	);
	let v = parse(&json);
	let policies = v["policies"].as_array().expect("array");
	assert_eq!(policies.len(), 2);
	// BTreeMap ordering: "sts" sorts before "tlsa".
	assert_eq!(policies[0]["policy"]["policy-type"], "sts");
	assert_eq!(policies[1]["policy"]["policy-type"], "tlsa");
}

#[test]
fn receiving_ip_omitted_when_empty() {
	let mut s = session("dane-required", "");
	s.receiving_ip = String::new();
	let json = generate_json("Org", "mailto:r@org.example", "r", 0, 86400, &[s]);
	let v = parse(&json);
	let detail = &v["policies"][0]["failure-details"][0];
	assert!(detail.get("receiving-ip").is_none());
}

#[test]
fn empty_sessions_yield_no_policies() {
	let json = generate_json("Org", "mailto:r@org.example", "r", 0, 86400, &[]);
	let v = parse(&json);
	assert_eq!(v["policies"].as_array().expect("array").len(), 0);
}

#[test]
fn build_report_returns_valid_gzip() {
	use flate2::read::GzDecoder;
	use std::io::Read;
	let gz = build_report(
		"Org",
		"mailto:r@org.example",
		"r1",
		0,
		86400,
		&[session(RESULT_SUCCESS, "198.51.100.1")],
	);
	let mut decoder = GzDecoder::new(gz.as_slice());
	let mut json = String::new();
	decoder.read_to_string(&mut json).expect("valid gzip");
	let v = parse(&json);
	assert_eq!(v["organization-name"], "Org");
}

#[test]
fn build_email_has_correct_structure() {
	let attachment = build_report(
		"Org",
		"mailto:r@org.example",
		"r1",
		1_700_000_000,
		1_700_086_400,
		&[session(RESULT_SUCCESS, "198.51.100.1")],
	);
	let email = build_email(
		"example.com",
		"tlsrpt@example.com",
		"r1",
		1_700_000_000,
		1_700_086_400,
		"reporter.example",
		&attachment,
	);
	let email_str = String::from_utf8_lossy(&email);
	assert!(
		email_str.contains("From: postmaster@reporter.example"),
		"{email_str}"
	);
	assert!(email_str.contains("To: tlsrpt@example.com"), "{email_str}");
	assert!(
		email_str.contains("Report Domain: example.com"),
		"{email_str}"
	);
	assert!(
		email_str.contains("TLS-Report-Domain: example.com"),
		"{email_str}"
	);
	assert!(email_str.contains("application/tlsrpt+gzip"), "{email_str}");
	assert!(
		email_str.contains("reporter.example!example.com!1700000000!1700086400.json.gz"),
		"{email_str}"
	);
	assert!(email_str.contains("multipart/report"), "{email_str}");
}

#[test]
fn session_round_trips_through_json() {
	let s = session("certificate-expired", "198.51.100.1");
	let line = serde_json::to_string(&s).expect("serialize");
	let back: TlsSession = serde_json::from_str(&line).expect("deserialize");
	assert_eq!(back.result, "certificate-expired");
	assert_eq!(back.policy_domain, "example.com");
	assert_eq!(back.mx_host, vec!["*.mail.example.com"]);
}
