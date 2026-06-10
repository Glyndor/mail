//! DMARC aggregate report generation (RFC 7489 §7).

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

/// One per-message DMARC delivery record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeliveryRecord {
	/// Unix timestamp (seconds) of acceptance.
	pub timestamp: u64,
	/// Sending client IP address.
	pub source_ip: String,
	/// RFC5321.MailFrom domain (envelope from), empty if null sender.
	pub envelope_from: String,
	/// RFC5322.From domain.
	pub header_from: String,
	/// SPF result keyword.
	pub spf: String,
	/// DKIM result keyword; empty string means no DKIM signatures.
	pub dkim: String,
	/// Authenticated identifier domain from the passing DKIM signature, if any.
	pub dkim_domain: String,
	/// DMARC result keyword.
	pub dmarc: String,
	/// Disposition actually applied (none/quarantine/reject).
	pub disposition: String,
	/// Domain whose DMARC record was consulted.
	pub policy_domain: String,
	/// Published p= policy.
	pub published_policy: String,
	/// Published pct= value.
	pub pct: u8,
}

/// Build a gzip-compressed aggregate XML report (RFC 7489 Appendix C).
/// `records` is the full set of delivery records for `domain` during the period.
pub fn build_xml(
	org_name: &str,
	org_email: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	domain: &str,
	records: &[DeliveryRecord],
) -> Vec<u8> {
	let xml = generate_xml(
		org_name,
		org_email,
		report_id,
		period_start,
		period_end,
		domain,
		records,
	);
	let mut enc = GzEncoder::new(Vec::new(), Compression::default());
	enc.write_all(xml.as_bytes())
		.expect("in-memory gzip cannot fail");
	enc.finish().expect("in-memory gzip cannot fail")
}

fn generate_xml(
	org_name: &str,
	org_email: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	domain: &str,
	records: &[DeliveryRecord],
) -> String {
	use std::collections::HashMap;

	let mut out = String::with_capacity(2048);
	out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
	out.push_str("<feedback>\n");

	// Report metadata.
	out.push_str("  <report_metadata>\n");
	out.push_str(&format!(
		"    <org_name>{}</org_name>\n",
		xml_escape(org_name)
	));
	out.push_str(&format!("    <email>{}</email>\n", xml_escape(org_email)));
	out.push_str(&format!(
		"    <report_id>{}</report_id>\n",
		xml_escape(report_id)
	));
	out.push_str("    <date_range>\n");
	out.push_str(&format!("      <begin>{period_start}</begin>\n"));
	out.push_str(&format!("      <end>{period_end}</end>\n"));
	out.push_str("    </date_range>\n");
	out.push_str("  </report_metadata>\n");

	// Published policy — use the first record that has policy info.
	let published = records
		.first()
		.map(|r| (r.published_policy.as_str(), r.pct))
		.unwrap_or(("none", 100));
	out.push_str("  <policy_published>\n");
	out.push_str(&format!("    <domain>{}</domain>\n", xml_escape(domain)));
	out.push_str(&format!("    <p>{}</p>\n", xml_escape(published.0)));
	out.push_str(&format!("    <sp>{}</sp>\n", xml_escape(published.0)));
	out.push_str(&format!("    <pct>{}</pct>\n", published.1));
	out.push_str("  </policy_published>\n");

	// Aggregate: group by (source_ip, disposition, spf, dkim).
	type RowKey = (String, String, String, String);
	let mut rows: HashMap<RowKey, (u64, &DeliveryRecord)> = HashMap::new();
	for rec in records {
		let key = (
			rec.source_ip.clone(),
			rec.disposition.clone(),
			rec.spf.clone(),
			rec.dkim.clone(),
		);
		let entry = rows.entry(key).or_insert((0, rec));
		entry.0 += 1;
	}

	let mut sorted_rows: Vec<_> = rows.into_iter().collect();
	sorted_rows.sort_by_key(|(k, _)| k.clone());

	for ((source_ip, disposition, spf, dkim), (count, rec)) in &sorted_rows {
		out.push_str("  <record>\n");
		out.push_str("    <row>\n");
		out.push_str(&format!(
			"      <source_ip>{}</source_ip>\n",
			xml_escape(source_ip)
		));
		out.push_str(&format!("      <count>{count}</count>\n"));
		out.push_str("      <policy_evaluated>\n");
		out.push_str(&format!(
			"        <disposition>{}</disposition>\n",
			xml_escape(disposition)
		));
		out.push_str(&format!("        <dkim>{}</dkim>\n", xml_escape(dkim)));
		out.push_str(&format!("        <spf>{}</spf>\n", xml_escape(spf)));
		out.push_str("      </policy_evaluated>\n");
		out.push_str("    </row>\n");
		out.push_str("    <identifiers>\n");
		out.push_str(&format!(
			"      <header_from>{}</header_from>\n",
			xml_escape(&rec.header_from)
		));
		if !rec.envelope_from.is_empty() {
			out.push_str(&format!(
				"      <envelope_from>{}</envelope_from>\n",
				xml_escape(&rec.envelope_from)
			));
		}
		out.push_str("    </identifiers>\n");
		out.push_str("    <auth_results>\n");
		if !rec.dkim_domain.is_empty() {
			out.push_str("      <dkim>\n");
			out.push_str(&format!(
				"        <domain>{}</domain>\n",
				xml_escape(&rec.dkim_domain)
			));
			out.push_str(&format!("        <result>{dkim}</result>\n"));
			out.push_str("      </dkim>\n");
		}
		out.push_str("      <spf>\n");
		let spf_domain = if rec.envelope_from.is_empty() {
			domain
		} else {
			&rec.envelope_from
		};
		out.push_str(&format!(
			"        <domain>{}</domain>\n",
			xml_escape(spf_domain)
		));
		out.push_str(&format!("        <result>{spf}</result>\n"));
		out.push_str("      </spf>\n");
		out.push_str("    </auth_results>\n");
		out.push_str("  </record>\n");
	}

	out.push_str("</feedback>\n");
	out
}

/// Escape `&`, `<`, `>`, `"`, `'` for XML text/attribute content.
fn xml_escape(s: &str) -> String {
	s.chars()
		.flat_map(|c| match c {
			'&' => "&amp;".chars().collect::<Vec<_>>(),
			'<' => "&lt;".chars().collect(),
			'>' => "&gt;".chars().collect(),
			'"' => "&quot;".chars().collect(),
			'\'' => "&apos;".chars().collect(),
			c => vec![c],
		})
		.collect()
}

/// Build the MIME email carrying the report as a gzip attachment.
/// Returns raw RFC 5322 bytes ready for FsSpool.
pub fn build_email(
	from_domain: &str,
	to_address: &str,
	report_id: &str,
	period_start: u64,
	period_end: u64,
	reporting_domain: &str,
	attachment: &[u8],
) -> Vec<u8> {
	use base64::Engine;
	let b64 = base64::engine::general_purpose::STANDARD.encode(attachment);
	let filename = format!("{reporting_domain}!{from_domain}!{period_start}!{period_end}.xml.gz");
	let boundary = format!("report-boundary-{report_id}");
	let mut email = String::with_capacity(512 + b64.len());

	email.push_str(&format!("From: postmaster@{reporting_domain}\r\n"));
	email.push_str(&format!("To: {to_address}\r\n"));
	email.push_str(&format!(
		"Subject: Report Domain: {from_domain} Submitter: {reporting_domain} Report-ID: <{report_id}>\r\n"
	));
	email.push_str("MIME-Version: 1.0\r\n");
	email.push_str(&format!(
		"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
	));
	email.push_str("\r\n");
	email.push_str(&format!("--{boundary}\r\n"));
	email.push_str("Content-Type: text/plain\r\n\r\n");
	email.push_str(&format!(
		"This is a DMARC aggregate report for {from_domain}.\r\n"
	));
	email.push_str("\r\n");
	email.push_str(&format!("--{boundary}\r\n"));
	email.push_str(&format!(
		"Content-Type: application/gzip; name=\"{filename}\"\r\n"
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
mod tests {
	use super::*;

	fn sample_records() -> Vec<DeliveryRecord> {
		vec![
			DeliveryRecord {
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
			},
			DeliveryRecord {
				timestamp: 1_700_000_100,
				source_ip: "5.6.7.8".to_string(),
				envelope_from: "attacker.example".to_string(),
				header_from: "example.org".to_string(),
				spf: "fail".to_string(),
				dkim: "fail".to_string(),
				dkim_domain: String::new(),
				dmarc: "fail".to_string(),
				disposition: "reject".to_string(),
				policy_domain: "example.org".to_string(),
				published_policy: "reject".to_string(),
				pct: 100,
			},
		]
	}

	#[test]
	fn xml_contains_required_elements() {
		let records = sample_records();
		let xml = generate_xml(
			"Test Org",
			"dmarc@test.org",
			"report-1",
			1_700_000_000,
			1_700_086_400,
			"example.org",
			&records,
		);
		assert!(xml.contains("<feedback>"), "{xml}");
		assert!(xml.contains("<report_metadata>"), "{xml}");
		assert!(xml.contains("<policy_published>"), "{xml}");
		assert!(xml.contains("<record>"), "{xml}");
		assert!(xml.contains("1.2.3.4"), "{xml}");
		assert!(xml.contains("5.6.7.8"), "{xml}");
		assert!(xml.contains("<disposition>reject</disposition>"), "{xml}");
	}

	#[test]
	fn build_xml_returns_valid_gzip() {
		use flate2::read::GzDecoder;
		use std::io::Read;
		let records = sample_records();
		let gz = build_xml(
			"Test Org",
			"dmarc@test.org",
			"report-2",
			1_700_000_000,
			1_700_086_400,
			"example.org",
			&records,
		);
		let mut decoder = GzDecoder::new(gz.as_slice());
		let mut xml = String::new();
		decoder.read_to_string(&mut xml).expect("valid gzip");
		assert!(xml.contains("<feedback>"), "{xml}");
	}

	#[test]
	fn xml_escapes_special_characters() {
		assert_eq!(
			xml_escape("a&b<c>d\"e'f"),
			"a&amp;b&lt;c&gt;d&quot;e&apos;f"
		);
	}

	#[test]
	fn build_email_has_correct_structure() {
		let attachment = build_xml(
			"Test Org",
			"dmarc@test.org",
			"r1",
			1_700_000_000,
			1_700_086_400,
			"example.org",
			&sample_records(),
		);
		let email = build_email(
			"sender.example",
			"reports@example.org",
			"r1",
			1_700_000_000,
			1_700_086_400,
			"example.org",
			&attachment,
		);
		let email_str = String::from_utf8_lossy(&email);
		assert!(
			email_str.contains("From: postmaster@example.org"),
			"{email_str}"
		);
		assert!(email_str.contains("To: reports@example.org"), "{email_str}");
		assert!(
			email_str.contains("Report Domain: sender.example"),
			"{email_str}"
		);
		assert!(email_str.contains("application/gzip"), "{email_str}");
		assert!(email_str.contains(".xml.gz"), "{email_str}");
	}

	#[test]
	fn records_with_same_ip_are_aggregated() {
		let mut records = sample_records();
		records.push(DeliveryRecord {
			source_ip: "1.2.3.4".to_string(),
			..records[0].clone()
		});
		let xml = generate_xml("Org", "e@o.org", "r", 0, 86400, "example.org", &records);
		// 1.2.3.4 should appear once with count 2.
		assert!(xml.contains("<count>2</count>"), "{xml}");
	}
}
