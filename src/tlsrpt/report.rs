//! TLS-RPT report generation (RFC 8460 §4).
//!
//! Outbound TLS session outcomes are accumulated as `TlsSession` records and
//! rolled up into the RFC 8460 §4.4 JSON report, gzip-compressed and wrapped
//! in a MIME message for delivery to the policy domain's `rua=` address.

use std::collections::BTreeMap;
use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::clock;

/// The sentinel `result` value marking a successful TLS session. Any other
/// value is treated as a failure result-type and reported in `failure-details`.
pub const RESULT_SUCCESS: &str = "successful";

/// One accumulated outbound TLS session outcome for a single policy domain.
///
/// Serializable so it can be journaled as JSONL between flushes, the same way
/// DMARC delivery records are.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsSession {
	/// Unix timestamp (seconds) of the session attempt.
	pub timestamp: u64,
	/// Policy type that governed the session: `sts`, `tlsa` or `no-policy-found`.
	pub policy_type: String,
	/// The recipient (policy) domain this session targeted.
	pub policy_domain: String,
	/// Lines of the applied policy (e.g. the MTA-STS policy body), if any.
	pub policy_strings: Vec<String>,
	/// MX host patterns the policy named, if any.
	pub mx_host: Vec<String>,
	/// IP address the sending MTA connected from.
	pub sending_mta_ip: String,
	/// The receiving MX hostname that was contacted.
	pub receiving_mx_hostname: String,
	/// The receiving MX IP address, if known.
	pub receiving_ip: String,
	/// `successful` ([`RESULT_SUCCESS`]) or an RFC 8460 §4.3 failure result-type.
	pub result: String,
}

/// Build a gzip-compressed RFC 8460 §4.4 JSON report for one policy domain.
/// `sessions` is the full set of TLS sessions recorded for that domain during
/// the reporting period.
pub fn build_report(
	org_name: &str,
	contact_info: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	sessions: &[TlsSession],
) -> Vec<u8> {
	let json = generate_json(
		org_name,
		contact_info,
		report_id,
		period_start,
		period_end,
		sessions,
	);
	let mut enc = GzEncoder::new(Vec::new(), Compression::default());
	enc.write_all(json.as_bytes())
		.expect("in-memory gzip cannot fail");
	enc.finish().expect("in-memory gzip cannot fail")
}

#[derive(serde::Serialize)]
struct ReportJson<'a> {
	#[serde(rename = "organization-name")]
	organization_name: &'a str,
	#[serde(rename = "date-range")]
	date_range: DateRange,
	#[serde(rename = "contact-info")]
	contact_info: &'a str,
	#[serde(rename = "report-id")]
	report_id: &'a str,
	policies: Vec<PolicyJson>,
}

#[derive(serde::Serialize)]
struct DateRange {
	#[serde(rename = "start-datetime")]
	start_datetime: String,
	#[serde(rename = "end-datetime")]
	end_datetime: String,
}

#[derive(serde::Serialize)]
struct PolicyJson {
	policy: PolicyInfo,
	summary: Summary,
	#[serde(rename = "failure-details", skip_serializing_if = "Vec::is_empty")]
	failure_details: Vec<FailureDetail>,
}

#[derive(serde::Serialize)]
struct PolicyInfo {
	#[serde(rename = "policy-type")]
	policy_type: String,
	#[serde(rename = "policy-string", skip_serializing_if = "Vec::is_empty")]
	policy_string: Vec<String>,
	#[serde(rename = "policy-domain")]
	policy_domain: String,
	#[serde(rename = "mx-host", skip_serializing_if = "Vec::is_empty")]
	mx_host: Vec<String>,
}

#[derive(serde::Serialize)]
struct Summary {
	#[serde(rename = "total-successful-session-count")]
	total_successful_session_count: u64,
	#[serde(rename = "total-failure-session-count")]
	total_failure_session_count: u64,
}

#[derive(serde::Serialize)]
struct FailureDetail {
	#[serde(rename = "result-type")]
	result_type: String,
	#[serde(rename = "sending-mta-ip")]
	sending_mta_ip: String,
	#[serde(rename = "receiving-mx-hostname")]
	receiving_mx_hostname: String,
	#[serde(rename = "receiving-ip", skip_serializing_if = "String::is_empty")]
	receiving_ip: String,
	#[serde(rename = "failed-session-count")]
	failed_session_count: u64,
}

fn generate_json(
	org_name: &str,
	contact_info: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	sessions: &[TlsSession],
) -> String {
	let report = ReportJson {
		organization_name: org_name,
		date_range: DateRange {
			start_datetime: clock::rfc3339(period_start),
			end_datetime: clock::rfc3339(period_end),
		},
		contact_info,
		report_id,
		policies: build_policies(sessions),
	};
	serde_json::to_string(&report).expect("report serialization cannot fail")
}

/// Group sessions into policy blocks keyed by (policy-domain, policy-type),
/// counting successes/failures and aggregating failure details. Ordering is
/// deterministic (sorted keys) so reports are reproducible.
fn build_policies(sessions: &[TlsSession]) -> Vec<PolicyJson> {
	// Preserve insertion of the first session's policy metadata per group.
	let mut groups: BTreeMap<(&str, &str), PolicyGroup> = BTreeMap::new();

	for session in sessions {
		let key = (session.policy_domain.as_str(), session.policy_type.as_str());
		let group = groups.entry(key).or_default();
		if group.policy_string.is_empty() && !session.policy_strings.is_empty() {
			group.policy_string = session.policy_strings.clone();
		}
		if group.mx_host.is_empty() && !session.mx_host.is_empty() {
			group.mx_host = session.mx_host.clone();
		}
		if session.result == RESULT_SUCCESS {
			group.successful += 1;
		} else {
			group.failures += 1;
			let fkey = (
				session.result.clone(),
				session.sending_mta_ip.clone(),
				session.receiving_mx_hostname.clone(),
				session.receiving_ip.clone(),
			);
			*group.failure_counts.entry(fkey).or_insert(0) += 1;
		}
	}

	groups
		.into_iter()
		.map(|((policy_domain, policy_type), group)| PolicyJson {
			policy: PolicyInfo {
				policy_type: policy_type.to_string(),
				policy_string: group.policy_string,
				policy_domain: policy_domain.to_string(),
				mx_host: group.mx_host,
			},
			summary: Summary {
				total_successful_session_count: group.successful,
				total_failure_session_count: group.failures,
			},
			failure_details: group
				.failure_counts
				.into_iter()
				.map(
					|(
						(result_type, sending_mta_ip, receiving_mx_hostname, receiving_ip),
						count,
					)| {
						FailureDetail {
							result_type,
							sending_mta_ip,
							receiving_mx_hostname,
							receiving_ip,
							failed_session_count: count,
						}
					},
				)
				.collect(),
		})
		.collect()
}

#[derive(Default)]
struct PolicyGroup {
	policy_string: Vec<String>,
	mx_host: Vec<String>,
	successful: u64,
	failures: u64,
	/// (result-type, sending-mta-ip, receiving-mx-hostname, receiving-ip) → count.
	failure_counts: BTreeMap<(String, String, String, String), u64>,
}

/// Build the MIME email carrying the report as a gzip attachment per
/// RFC 8460 §3. Returns raw RFC 5322 bytes ready for the outbound spool.
pub fn build_email(
	policy_domain: &str,
	to_address: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	reporting_domain: &str,
	attachment: &[u8],
) -> Vec<u8> {
	use base64::Engine;
	let b64 = base64::engine::general_purpose::STANDARD.encode(attachment);
	let filename =
		format!("{reporting_domain}!{policy_domain}!{period_start}!{period_end}.json.gz");
	let boundary = format!("tlsrpt-boundary-{report_id}");
	let mut email = String::with_capacity(512 + b64.len());

	email.push_str(&format!("From: postmaster@{reporting_domain}\r\n"));
	email.push_str(&format!("To: {to_address}\r\n"));
	email.push_str(&format!(
		"Subject: Report Domain: {policy_domain} Submitter: {reporting_domain} Report-ID: <{report_id}>\r\n"
	));
	email.push_str("TLS-Report-Domain: ");
	email.push_str(policy_domain);
	email.push_str("\r\n");
	email.push_str(&format!("TLS-Report-Submitter: {reporting_domain}\r\n"));
	email.push_str("MIME-Version: 1.0\r\n");
	email.push_str(&format!(
		"Content-Type: multipart/report; report-type=\"tlsrpt\"; boundary=\"{boundary}\"\r\n"
	));
	email.push_str("\r\n");
	email.push_str(&format!("--{boundary}\r\n"));
	email.push_str("Content-Type: text/plain\r\n\r\n");
	email.push_str(&format!(
		"This is a TLS-RPT report for {policy_domain}.\r\n"
	));
	email.push_str("\r\n");
	email.push_str(&format!("--{boundary}\r\n"));
	email.push_str(&format!(
		"Content-Type: application/tlsrpt+gzip; name=\"{filename}\"\r\n"
	));
	email.push_str("Content-Transfer-Encoding: base64\r\n");
	email.push_str(&format!(
		"Content-Disposition: attachment; filename=\"{filename}\"\r\n"
	));
	email.push_str("\r\n");
	// Fold base64 at 76 chars per RFC 2045.
	for chunk in b64.as_bytes().chunks(76) {
		email.push_str(std::str::from_utf8(chunk).unwrap_or(""));
		email.push_str("\r\n");
	}
	email.push_str(&format!("\r\n--{boundary}--\r\n"));
	email.into_bytes()
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
