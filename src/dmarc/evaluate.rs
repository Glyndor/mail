//! DMARC evaluation: alignment of SPF/DKIM results with the From domain.

use crate::dkim::{DkimOutcome, DkimResult};
use crate::spf::{DnsFailure, DnsLookup, SpfOutcome};

use super::record::{Alignment, Policy, Record};

/// DMARC outcome for `Authentication-Results` and policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcOutcome {
	Pass,
	/// Failed with the record requesting rejection (quarantine is treated
	/// as reject until a quarantine mailbox exists).
	Reject,
	/// Failed but the record requests no action.
	Fail,
	None,
	TempError,
	PermError,
}

impl DmarcOutcome {
	/// Keyword for `Authentication-Results`.
	pub fn as_str(self) -> &'static str {
		match self {
			DmarcOutcome::Pass => "pass",
			DmarcOutcome::Reject | DmarcOutcome::Fail => "fail",
			DmarcOutcome::None => "none",
			DmarcOutcome::TempError => "temperror",
			DmarcOutcome::PermError => "permerror",
		}
	}
}

/// Extract the domain of the RFC5322.From header from a raw message.
/// Multiple From headers or no parseable address yield `None`.
pub fn from_domain(raw: &[u8]) -> Option<String> {
	let header_end = raw
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|p| p + 2)
		.unwrap_or(raw.len());
	let headers = std::str::from_utf8(&raw[..header_end]).ok()?;

	let mut from_value: Option<String> = None;
	let mut current: Option<String> = None;
	let mut in_from = false;
	for line in headers.split_inclusive("\r\n") {
		let content = line.strip_suffix("\r\n").unwrap_or(line);
		if content.starts_with(' ') || content.starts_with('\t') {
			if in_from && let Some(value) = &mut current {
				value.push(' ');
				value.push_str(content.trim());
			}
			continue;
		}
		if in_from {
			// A second From header is an attack vector: refuse to choose.
			if from_value.is_some() {
				return None;
			}
			from_value = current.take();
			in_from = false;
		}
		if let Some(rest) = content
			.get(..5)
			.filter(|head| head.eq_ignore_ascii_case("from:"))
			.map(|_| &content[5..])
		{
			in_from = true;
			current = Some(rest.trim().to_string());
		}
	}
	if in_from {
		if from_value.is_some() {
			return None;
		}
		from_value = current.take();
	}

	let value = from_value?;
	// `Display <user@domain>` or bare `user@domain`.
	let address = match (value.rfind('<'), value.rfind('>')) {
		(Some(open), Some(close)) if open < close => &value[open + 1..close],
		_ => value.trim(),
	};
	let (_, domain) = address.rsplit_once('@')?;
	let domain = domain.trim().to_ascii_lowercase();
	if domain.is_empty() || domain.contains(' ') {
		return None;
	}
	Some(domain)
}

/// Evaluate DMARC for a message: `from_domain` is the RFC5322.From domain,
/// `spf` the SPF result with the domain it was evaluated on.
pub async fn evaluate(
	dns: &dyn DnsLookup,
	from_domain: &str,
	spf: (SpfOutcome, Option<&str>),
	dkim: &[DkimResult],
) -> DmarcOutcome {
	evaluate_inner(dns, from_domain, spf, dkim, sample_pct()).await
}

/// Draws a random number in [1, 100] for pct= sampling.
fn sample_pct() -> u8 {
	use ring::rand::{SecureRandom, SystemRandom};
	let rng = SystemRandom::new();
	let mut buf = [0u8; 1];
	// Ignore fill errors — on failure the result is 0, which causes
	// non-sampled treatment (safe: slightly over-permissive, not under).
	let _ = rng.fill(&mut buf);
	(buf[0] % 100) + 1
}

/// Testable inner evaluator that accepts an explicit pct roll (1–100).
async fn evaluate_inner(
	dns: &dyn DnsLookup,
	from_domain: &str,
	spf: (SpfOutcome, Option<&str>),
	dkim: &[DkimResult],
	pct_roll: u8,
) -> DmarcOutcome {
	let (record, applied_policy) = match fetch_record(dns, from_domain).await {
		Ok(Some(found)) => found,
		Ok(None) => return DmarcOutcome::None,
		Err(outcome) => return outcome,
	};

	let dkim_aligned = dkim.iter().any(|result| {
		result.outcome == DkimOutcome::Pass
			&& result
				.domain
				.as_deref()
				.is_some_and(|d| aligned(record.dkim_alignment, d, from_domain))
	});
	let spf_aligned = spf.0 == SpfOutcome::Pass
		&& spf
			.1
			.is_some_and(|domain| aligned(record.spf_alignment, domain, from_domain));

	if dkim_aligned || spf_aligned {
		return DmarcOutcome::Pass;
	}
	match applied_policy {
		Policy::None => DmarcOutcome::Fail,
		// RFC 7489 §6.6.2: apply policy only to pct% of failing messages;
		// non-sampled messages are treated as if policy were "none".
		Policy::Quarantine | Policy::Reject => {
			if record.pct < 100 && pct_roll > record.pct {
				DmarcOutcome::Fail
			} else {
				DmarcOutcome::Reject
			}
		}
	}
}

/// Fetch `_dmarc.<domain>`, falling back to the organizational domain for
/// subdomains. Returns the record plus the policy that applies.
async fn fetch_record(
	dns: &dyn DnsLookup,
	domain: &str,
) -> Result<Option<(Record, Policy)>, DmarcOutcome> {
	if let Some(record) = lookup(dns, domain).await? {
		let policy = record.policy;
		return Ok(Some((record, policy)));
	}
	let organizational = organizational_domain(domain);
	if organizational != domain
		&& let Some(record) = lookup(dns, &organizational).await?
	{
		let policy = record.subdomain_policy;
		return Ok(Some((record, policy)));
	}
	Ok(None)
}

async fn lookup(dns: &dyn DnsLookup, domain: &str) -> Result<Option<Record>, DmarcOutcome> {
	let name = format!("_dmarc.{domain}");
	let texts = match dns.txt(&name).await {
		Ok(texts) => texts,
		Err(DnsFailure::Temporary) => return Err(DmarcOutcome::TempError),
	};
	let mut records = texts.iter().filter_map(|text| super::record::parse(text));
	match records.next() {
		None => Ok(None),
		Some(parsed) => {
			// Multiple DMARC records mean none applies (section 6.6.3).
			if records.next().is_some() {
				return Ok(None);
			}
			parsed.map(Some).map_err(|()| DmarcOutcome::PermError)
		}
	}
}

/// Identifier alignment (RFC 7489 section 3.1).
fn aligned(mode: Alignment, identifier: &str, from_domain: &str) -> bool {
	let identifier = identifier.to_ascii_lowercase();
	let from_domain = from_domain.to_ascii_lowercase();
	match mode {
		Alignment::Strict => identifier == from_domain,
		Alignment::Relaxed => {
			organizational_domain(&identifier) == organizational_domain(&from_domain)
		}
	}
}

/// Return the organizational (registrable) domain using the Mozilla PSL.
/// Falls back to the rightmost two labels when the PSL returns no result.
fn organizational_domain(domain: &str) -> String {
	use psl::Psl;
	if let Some(d) = psl::List.domain(domain.as_bytes())
		&& let Ok(s) = std::str::from_utf8(d.as_bytes())
	{
		return s.to_ascii_lowercase();
	}
	// Fallback: two-label heuristic (covers plain TLDs like .com, .org).
	let labels: Vec<&str> = domain.split('.').collect();
	if labels.len() <= 2 {
		return domain.to_string();
	}
	labels[labels.len() - 2..].join(".")
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;
	use std::pin::Pin;

	struct TxtDns {
		records: HashMap<String, Vec<String>>,
		fail: bool,
	}

	impl DnsLookup for TxtDns {
		fn txt(
			&self,
			name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			let result = if self.fail {
				Err(DnsFailure::Temporary)
			} else {
				Ok(self.records.get(name).cloned().unwrap_or_default())
			};
			Box::pin(async move { result })
		}

		fn addresses(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>>
		{
			Box::pin(async { Ok(Vec::new()) })
		}

		fn mx(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	fn dns(records: &[(&str, &str)]) -> TxtDns {
		let mut map: HashMap<String, Vec<String>> = HashMap::new();
		for (name, value) in records {
			map.entry(name.to_string())
				.or_default()
				.push(value.to_string());
		}
		TxtDns {
			records: map,
			fail: false,
		}
	}

	fn dkim_pass(domain: &str) -> Vec<DkimResult> {
		vec![DkimResult {
			outcome: DkimOutcome::Pass,
			domain: Some(domain.to_string()),
		}]
	}

	#[test]
	fn extracts_from_domain() {
		assert_eq!(
			from_domain(b"From: Alice <alice@Example.ORG>\r\n\r\nbody"),
			Some("example.org".to_string())
		);
		assert_eq!(
			from_domain(b"Subject: x\r\nFrom: bob@example.org\r\n\r\n"),
			Some("example.org".to_string())
		);
		assert_eq!(
			from_domain(b"From: folded\r\n <carol@example.org>\r\n\r\n"),
			Some("example.org".to_string())
		);
	}

	#[test]
	fn duplicate_from_headers_refuse_extraction() {
		let raw = b"From: a@one.example\r\nFrom: b@two.example\r\n\r\nbody";
		assert_eq!(from_domain(raw), None);
	}

	#[test]
	fn missing_or_malformed_from_is_none() {
		assert_eq!(from_domain(b"Subject: x\r\n\r\nbody"), None);
		assert_eq!(from_domain(b"From: no-address-here\r\n\r\n"), None);
	}

	#[tokio::test]
	async fn aligned_dkim_passes() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject")]);
		let outcome = evaluate(
			&dns,
			"example.org",
			(SpfOutcome::Fail, None),
			&dkim_pass("example.org"),
		)
		.await;
		assert_eq!(outcome, DmarcOutcome::Pass);
	}

	#[tokio::test]
	async fn aligned_spf_passes() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject")]);
		let outcome = evaluate(
			&dns,
			"example.org",
			(SpfOutcome::Pass, Some("mail.example.org")),
			&[],
		)
		.await;
		// Relaxed alignment: mail.example.org aligns with example.org.
		assert_eq!(outcome, DmarcOutcome::Pass);
	}

	#[tokio::test]
	async fn strict_spf_alignment_requires_exact_match() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject; aspf=s")]);
		let outcome = evaluate(
			&dns,
			"example.org",
			(SpfOutcome::Pass, Some("mail.example.org")),
			&[],
		)
		.await;
		assert_eq!(outcome, DmarcOutcome::Reject);
	}

	#[tokio::test]
	async fn unaligned_with_reject_policy_rejects() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject")]);
		let outcome = evaluate(
			&dns,
			"example.org",
			(SpfOutcome::Pass, Some("elsewhere.example")),
			&dkim_pass("elsewhere.example"),
		)
		.await;
		assert_eq!(outcome, DmarcOutcome::Reject);
	}

	#[tokio::test]
	async fn quarantine_is_treated_as_reject() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=quarantine")]);
		let outcome = evaluate(&dns, "example.org", (SpfOutcome::Fail, None), &[]).await;
		assert_eq!(outcome, DmarcOutcome::Reject);
	}

	#[tokio::test]
	async fn policy_none_records_failure_without_reject() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=none")]);
		let outcome = evaluate(&dns, "example.org", (SpfOutcome::Fail, None), &[]).await;
		assert_eq!(outcome, DmarcOutcome::Fail);
	}

	#[tokio::test]
	async fn no_record_is_none() {
		let dns = dns(&[]);
		let outcome = evaluate(
			&dns,
			"example.org",
			(SpfOutcome::Pass, Some("example.org")),
			&[],
		)
		.await;
		assert_eq!(outcome, DmarcOutcome::None);
	}

	#[tokio::test]
	async fn subdomain_falls_back_to_organizational_policy() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject; sp=none")]);
		let outcome = evaluate(&dns, "news.example.org", (SpfOutcome::Fail, None), &[]).await;
		// sp=none applies to the subdomain: fail without reject.
		assert_eq!(outcome, DmarcOutcome::Fail);
	}

	#[tokio::test]
	async fn malformed_record_is_permerror() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=bogus")]);
		let outcome = evaluate(&dns, "example.org", (SpfOutcome::Fail, None), &[]).await;
		assert_eq!(outcome, DmarcOutcome::PermError);
	}

	#[tokio::test]
	async fn dns_failure_is_temperror() {
		let mut dns = dns(&[]);
		dns.fail = true;
		let outcome = evaluate(&dns, "example.org", (SpfOutcome::Fail, None), &[]).await;
		assert_eq!(outcome, DmarcOutcome::TempError);
	}

	#[tokio::test]
	async fn pct_100_always_enforces() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject; pct=100")]);
		let outcome = evaluate_inner(&dns, "example.org", (SpfOutcome::Fail, None), &[], 100).await;
		assert_eq!(outcome, DmarcOutcome::Reject);
		let outcome = evaluate_inner(&dns, "example.org", (SpfOutcome::Fail, None), &[], 1).await;
		assert_eq!(outcome, DmarcOutcome::Reject);
	}

	#[tokio::test]
	async fn pct_0_never_enforces() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject; pct=0")]);
		let outcome = evaluate_inner(&dns, "example.org", (SpfOutcome::Fail, None), &[], 1).await;
		assert_eq!(outcome, DmarcOutcome::Fail);
		let outcome = evaluate_inner(&dns, "example.org", (SpfOutcome::Fail, None), &[], 100).await;
		assert_eq!(outcome, DmarcOutcome::Fail);
	}

	#[tokio::test]
	async fn pct_50_boundary() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject; pct=50")]);
		let outcome = evaluate_inner(&dns, "example.org", (SpfOutcome::Fail, None), &[], 50).await;
		assert_eq!(outcome, DmarcOutcome::Reject);
		let outcome = evaluate_inner(&dns, "example.org", (SpfOutcome::Fail, None), &[], 51).await;
		assert_eq!(outcome, DmarcOutcome::Fail);
	}

	#[tokio::test]
	async fn pct_sampling_does_not_affect_passing_messages() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=reject; pct=0")]);
		let outcome = evaluate_inner(
			&dns,
			"example.org",
			(SpfOutcome::Fail, None),
			&dkim_pass("example.org"),
			1,
		)
		.await;
		assert_eq!(outcome, DmarcOutcome::Pass);
	}

	#[tokio::test]
	async fn pct_sampling_does_not_affect_policy_none() {
		let dns = dns(&[("_dmarc.example.org", "v=DMARC1; p=none; pct=0")]);
		let outcome = evaluate_inner(&dns, "example.org", (SpfOutcome::Fail, None), &[], 1).await;
		assert_eq!(outcome, DmarcOutcome::Fail);
	}

	// PSL-based organizational domain tests

	#[test]
	fn psl_two_part_tld_is_handled() {
		assert_eq!(organizational_domain("news.example.co.uk"), "example.co.uk");
		assert_eq!(organizational_domain("mail.example.co.uk"), "example.co.uk");
	}

	#[test]
	fn psl_plain_tld_unchanged() {
		assert_eq!(organizational_domain("example.com"), "example.com");
		assert_eq!(organizational_domain("sub.example.org"), "example.org");
	}

	#[test]
	fn psl_different_co_uk_domains_do_not_align() {
		let a = organizational_domain("victim.co.uk");
		let b = organizational_domain("attacker.co.uk");
		assert_ne!(
			a, b,
			"distinct co.uk registrations must not share org domain"
		);
		assert_eq!(a, "victim.co.uk");
		assert_eq!(b, "attacker.co.uk");
	}

	#[tokio::test]
	async fn relaxed_alignment_uses_psl_for_co_uk() {
		let dns = dns(&[("_dmarc.example.co.uk", "v=DMARC1; p=reject")]);
		let outcome = evaluate(
			&dns,
			"example.co.uk",
			(SpfOutcome::Fail, None),
			&dkim_pass("news.example.co.uk"),
		)
		.await;
		assert_eq!(outcome, DmarcOutcome::Pass);
	}
}
