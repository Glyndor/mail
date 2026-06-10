use super::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

#[derive(Default)]
struct FakeDns {
	txt: HashMap<String, Vec<String>>,
	addresses: HashMap<String, Vec<IpAddr>>,
}

impl DnsLookup for FakeDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = Ok(self.txt.get(name).cloned().unwrap_or_default());
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
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
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

fn v4(text: &str) -> IpAddr {
	text.parse::<std::net::Ipv4Addr>().expect("ipv4").into()
}
fn v6(text: &str) -> IpAddr {
	text.parse::<std::net::Ipv6Addr>().expect("ipv6").into()
}

// ── Macro expansion unit tests ─────────────────────────────────────────────

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
