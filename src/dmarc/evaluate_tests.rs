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
