use super::*;
use std::collections::HashMap;
use std::pin::Pin;

/// Scripted resolver: maps of name → records.
#[derive(Default)]
struct FakeDns {
	txt: HashMap<String, Vec<String>>,
	addresses: HashMap<String, Vec<IpAddr>>,
	mx: HashMap<String, Vec<String>>,
	fail_txt: bool,
}

impl DnsLookup for FakeDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail_txt {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.txt.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn addresses(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		let result = Ok(self.addresses.get(name).cloned().unwrap_or_default());
		Box::pin(async move { result })
	}

	fn mx(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = Ok(self.mx.get(name).cloned().unwrap_or_default());
		Box::pin(async move { result })
	}
}

fn dns_with(records: &[(&str, &str)]) -> FakeDns {
	let mut dns = FakeDns::default();
	for (name, record) in records {
		dns.txt
			.entry(name.to_string())
			.or_default()
			.push(record.to_string());
	}
	dns
}

fn ip(text: &str) -> IpAddr {
	text.parse().expect("ip")
}

async fn outcome(dns: &FakeDns, from_ip: &str, domain: &str) -> SpfOutcome {
	check_host(dns, ip(from_ip), domain, "test@example.org", "example.org").await
}

// ── Core SPF evaluation tests ──────────────────────────────────────────────

#[tokio::test]
async fn no_record_is_none() {
	let dns = FakeDns::default();
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::None
	);
}

#[tokio::test]
async fn ip4_match_passes_and_all_fails() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:192.0.2.0/24 -all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.99", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn ip6_match() {
	let dns = dns_with(&[("example.org", "v=spf1 ip6:2001:db8::/32 ~all")]);
	assert_eq!(
		outcome(&dns, "2001:db8::1", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "2001:db9::1", "example.org").await,
		SpfOutcome::SoftFail
	);
}

#[tokio::test]
async fn a_mechanism_resolves_the_domain() {
	let mut dns = dns_with(&[("example.org", "v=spf1 a -all")]);
	dns.addresses
		.insert("example.org".into(), vec![ip("192.0.2.10")]);
	assert_eq!(
		outcome(&dns, "192.0.2.10", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "192.0.2.11", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn mx_mechanism_resolves_exchangers() {
	let mut dns = dns_with(&[("example.org", "v=spf1 mx -all")]);
	dns.mx
		.insert("example.org".into(), vec!["mx.example.org".into()]);
	dns.addresses
		.insert("mx.example.org".into(), vec![ip("192.0.2.20")]);
	assert_eq!(
		outcome(&dns, "192.0.2.20", "example.org").await,
		SpfOutcome::Pass
	);
}

#[tokio::test]
async fn include_passes_through() {
	let dns = dns_with(&[
		("example.org", "v=spf1 include:_spf.example.org -all"),
		("_spf.example.org", "v=spf1 ip4:192.0.2.0/24 -all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.5", "example.org").await,
		SpfOutcome::Pass
	);
	// A fail inside the include does not match; outer -all decides.
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn include_of_missing_record_is_permerror() {
	let dns = dns_with(&[("example.org", "v=spf1 include:missing.example -all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn redirect_is_followed() {
	let dns = dns_with(&[
		("example.org", "v=spf1 redirect=_spf.example.org"),
		("_spf.example.org", "v=spf1 ip4:192.0.2.0/24 -all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.5", "example.org").await,
		SpfOutcome::Pass
	);
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Fail
	);
}

#[tokio::test]
async fn lookup_loop_hits_the_budget() {
	let dns = dns_with(&[
		("a.example", "v=spf1 include:b.example -all"),
		("b.example", "v=spf1 include:a.example -all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "a.example").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn malformed_record_is_permerror() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:notanip -all")]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn multiple_records_are_permerror() {
	let dns = dns_with(&[
		("example.org", "v=spf1 -all"),
		("example.org", "v=spf1 +all"),
	]);
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::PermError
	);
}

#[tokio::test]
async fn dns_failure_is_temperror() {
	let mut dns = dns_with(&[("example.org", "v=spf1 -all")]);
	dns.fail_txt = true;
	assert_eq!(
		outcome(&dns, "192.0.2.1", "example.org").await,
		SpfOutcome::TempError
	);
}

#[tokio::test]
async fn no_match_without_all_is_neutral() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:192.0.2.0/24")]);
	assert_eq!(
		outcome(&dns, "198.51.100.1", "example.org").await,
		SpfOutcome::Neutral
	);
}

#[tokio::test]
async fn zero_prefix_matches_everything() {
	let dns = dns_with(&[("example.org", "v=spf1 ip4:0.0.0.0/0 -all")]);
	assert_eq!(
		outcome(&dns, "203.0.113.7", "example.org").await,
		SpfOutcome::Pass
	);
}

// ── Macro expansion unit tests ─────────────────────────────────────────────

fn v4(text: &str) -> IpAddr {
	text.parse::<std::net::Ipv4Addr>().expect("ipv4").into()
}
fn v6(text: &str) -> IpAddr {
	text.parse::<std::net::Ipv6Addr>().expect("ipv6").into()
}

#[test]
fn expand_literal_percent() {
	assert_eq!(
		expand_macro("100%%", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Ok("100%".to_string())
	);
}

#[test]
fn expand_percent_underscore_is_space() {
	assert_eq!(
		expand_macro("a%_b", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Ok("a b".to_string())
	);
}

#[test]
fn expand_percent_minus_is_url_encoded_space() {
	assert_eq!(
		expand_macro("a%-b", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Ok("a%20b".to_string())
	);
}

#[test]
fn expand_i_ipv4() {
	assert_eq!(
		expand_macro("%{i}", v4("192.0.2.3"), "example.org", "s@e.org", "e.org"),
		Ok("192.0.2.3".to_string())
	);
}

#[test]
fn expand_i_ipv6() {
	let expected = "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1";
	assert_eq!(
		expand_macro("%{i}", v6("2001:db8::1"), "example.org", "s@e.org", "e.org"),
		Ok(expected.to_string())
	);
}

#[test]
fn expand_ir_ipv4_reverses_octets() {
	assert_eq!(
		expand_macro("%{ir}", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Ok("4.3.2.1".to_string())
	);
}

#[test]
fn expand_ir_in_dnsbl_spec() {
	assert_eq!(
		expand_macro(
			"%{ir}.dnsbl.example.com",
			v4("1.2.3.4"),
			"example.org",
			"s@e.org",
			"e.org"
		),
		Ok("4.3.2.1.dnsbl.example.com".to_string())
	);
}

#[test]
fn expand_d_is_current_domain() {
	assert_eq!(
		expand_macro(
			"mail.%{d}",
			v4("1.2.3.4"),
			"example.org",
			"s@e.org",
			"e.org"
		),
		Ok("mail.example.org".to_string())
	);
}

#[test]
fn expand_v_ipv4_is_in_addr() {
	assert_eq!(
		expand_macro("%{v}", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Ok("in-addr".to_string())
	);
}

#[test]
fn expand_v_ipv6_is_ip6() {
	assert_eq!(
		expand_macro("%{v}", v6("::1"), "example.org", "s@e.org", "e.org"),
		Ok("ip6".to_string())
	);
}

#[test]
fn expand_s_is_sender() {
	assert_eq!(
		expand_macro(
			"%{s}",
			v4("1.2.3.4"),
			"example.org",
			"alice@example.org",
			"e.org"
		),
		Ok("alice@example.org".to_string())
	);
}

#[test]
fn expand_l_is_local_part() {
	assert_eq!(
		expand_macro(
			"%{l}",
			v4("1.2.3.4"),
			"example.org",
			"alice@example.org",
			"e.org"
		),
		Ok("alice".to_string())
	);
}

#[test]
fn expand_o_is_sender_domain() {
	assert_eq!(
		expand_macro(
			"%{o}",
			v4("1.2.3.4"),
			"example.org",
			"alice@example.org",
			"e.org"
		),
		Ok("example.org".to_string())
	);
}

#[test]
fn expand_h_is_helo_domain() {
	assert_eq!(
		expand_macro(
			"%{h}",
			v4("1.2.3.4"),
			"example.org",
			"s@e.org",
			"helo.example"
		),
		Ok("helo.example".to_string())
	);
}

#[test]
fn expand_d2_takes_rightmost_two_labels() {
	// %{d2} from "a.b.c.d" → "c.d"
	assert_eq!(
		expand_macro("%{d2}", v4("1.2.3.4"), "a.b.c.d", "s@e.org", "e.org"),
		Ok("c.d".to_string())
	);
}

#[test]
fn expand_dr_reverses_domain_labels() {
	assert_eq!(
		expand_macro("%{dr}", v4("1.2.3.4"), "a.b.c", "s@e.org", "e.org"),
		Ok("c.b.a".to_string())
	);
}

#[test]
fn expand_no_macro_is_noop() {
	assert_eq!(
		expand_macro(
			"plain.domain",
			v4("1.2.3.4"),
			"example.org",
			"s@e.org",
			"e.org"
		),
		Ok("plain.domain".to_string())
	);
}

#[test]
fn expand_unknown_letter_is_permerror() {
	assert_eq!(
		expand_macro("%{x}", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Err(SpfOutcome::PermError)
	);
}

#[test]
fn expand_unclosed_brace_is_permerror() {
	assert_eq!(
		expand_macro("%{ir", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Err(SpfOutcome::PermError)
	);
}

#[test]
fn expand_bare_percent_is_permerror() {
	assert_eq!(
		expand_macro("foo%bar", v4("1.2.3.4"), "example.org", "s@e.org", "e.org"),
		Err(SpfOutcome::PermError)
	);
}

// ── Macro integration tests ────────────────────────────────────────────────

#[tokio::test]
async fn a_mechanism_with_domain_macro() {
	let mut dns = dns_with(&[("example.org", "v=spf1 a:mail.%{d} -all")]);
	dns.addresses
		.insert("mail.example.org".into(), vec![ip("192.0.2.50")]);
	let result = check_host(
		&dns,
		ip("192.0.2.50"),
		"example.org",
		"user@example.org",
		"example.org",
	)
	.await;
	assert_eq!(result, SpfOutcome::Pass);
}

#[tokio::test]
async fn a_mechanism_with_reversed_ip_macro() {
	// The `a:` mechanism resolves `%{ir}.trusted.example` for IP `1.2.3.4`
	// → looks up A records of `4.3.2.1.trusted.example`.
	// Passes only if the connecting IP appears in those A records.
	let mut dns = dns_with(&[("example.org", "v=spf1 a:%{ir}.trusted.example -all")]);
	dns.addresses
		.insert("4.3.2.1.trusted.example".into(), vec![ip("1.2.3.4")]);
	let result = check_host(
		&dns,
		ip("1.2.3.4"),
		"example.org",
		"user@example.org",
		"example.org",
	)
	.await;
	assert_eq!(result, SpfOutcome::Pass);

	// Wrong IP: macro expands to different domain, no A record → -all Fail.
	let result2 = check_host(
		&dns,
		ip("9.8.7.6"),
		"example.org",
		"user@example.org",
		"example.org",
	)
	.await;
	assert_eq!(result2, SpfOutcome::Fail);
}

#[tokio::test]
async fn macro_expansion_error_in_mechanism_is_permerror() {
	let dns = dns_with(&[("example.org", "v=spf1 a:%{z} -all")]);
	let result = check_host(
		&dns,
		ip("192.0.2.1"),
		"example.org",
		"user@example.org",
		"example.org",
	)
	.await;
	assert_eq!(result, SpfOutcome::PermError);
}
