//! The `check_host()` function (RFC 7208 section 4).

use std::net::IpAddr;

use super::dns::{DnsFailure, DnsLookup};
use super::record::{Mechanism, Qualifier, Record};

/// Maximum DNS-querying terms per evaluation (RFC 7208 section 4.6.4).
const MAX_DNS_MECHANISMS: u32 = 10;

/// SPF evaluation result (RFC 7208 section 2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfOutcome {
	None,
	Neutral,
	Pass,
	Fail,
	SoftFail,
	TempError,
	PermError,
}

impl SpfOutcome {
	/// Lowercase keyword for `Received-SPF`.
	pub fn as_str(self) -> &'static str {
		match self {
			SpfOutcome::None => "none",
			SpfOutcome::Neutral => "neutral",
			SpfOutcome::Pass => "pass",
			SpfOutcome::Fail => "fail",
			SpfOutcome::SoftFail => "softfail",
			SpfOutcome::TempError => "temperror",
			SpfOutcome::PermError => "permerror",
		}
	}
}

/// Evaluate SPF for `ip` sending mail from `domain`.
pub async fn check_host(dns: &dyn DnsLookup, ip: IpAddr, domain: &str) -> SpfOutcome {
	let mut budget = MAX_DNS_MECHANISMS;
	check_host_inner(dns, ip, domain, &mut budget, 0).await
}

/// Recursion depth guard: includes/redirects each consume DNS budget, but a
/// cycle of zero-budget terms must still terminate.
const MAX_DEPTH: u32 = 10;

async fn check_host_inner(
	dns: &dyn DnsLookup,
	ip: IpAddr,
	domain: &str,
	budget: &mut u32,
	depth: u32,
) -> SpfOutcome {
	if depth >= MAX_DEPTH {
		return SpfOutcome::PermError;
	}

	let record = match fetch_record(dns, domain).await {
		Ok(Some(record)) => record,
		Ok(None) => return SpfOutcome::None,
		Err(outcome) => return outcome,
	};

	for (qualifier, mechanism) in &record.directives {
		let matched = match mechanism {
			Mechanism::All => true,
			Mechanism::Ip4 { network, prefix } => match ip {
				IpAddr::V4(v4) => v4_in_network(v4, *network, *prefix),
				IpAddr::V6(_) => false,
			},
			Mechanism::Ip6 { network, prefix } => match ip {
				IpAddr::V6(v6) => v6_in_network(v6, *network, *prefix),
				IpAddr::V4(_) => false,
			},
			Mechanism::A {
				domain: target,
				prefix4,
				prefix6,
			} => {
				if !consume(budget) {
					return SpfOutcome::PermError;
				}
				let name = target.as_deref().unwrap_or(domain);
				match dns.addresses(name).await {
					Ok(addresses) => addresses
						.iter()
						.any(|address| address_matches(ip, *address, *prefix4, *prefix6)),
					Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
				}
			}
			Mechanism::Mx {
				domain: target,
				prefix4,
				prefix6,
			} => {
				if !consume(budget) {
					return SpfOutcome::PermError;
				}
				let name = target.as_deref().unwrap_or(domain);
				let exchangers = match dns.mx(name).await {
					Ok(exchangers) => exchangers,
					Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
				};
				let mut matched = false;
				for exchanger in exchangers.iter().take(10) {
					match dns.addresses(exchanger).await {
						Ok(addresses) => {
							if addresses
								.iter()
								.any(|address| address_matches(ip, *address, *prefix4, *prefix6))
							{
								matched = true;
								break;
							}
						}
						Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
					}
				}
				matched
			}
			Mechanism::Include { domain: included } => {
				if !consume(budget) {
					return SpfOutcome::PermError;
				}
				match Box::pin(check_host_inner(dns, ip, included, budget, depth + 1)).await {
					SpfOutcome::Pass => true,
					SpfOutcome::Fail | SpfOutcome::SoftFail | SpfOutcome::Neutral => false,
					// include of a domain without a record is a permerror
					// (RFC 7208 section 5.2).
					SpfOutcome::None => return SpfOutcome::PermError,
					outcome @ (SpfOutcome::TempError | SpfOutcome::PermError) => {
						return outcome;
					}
				}
			}
			Mechanism::Exists { domain } => {
				// RFC 7208 §5.7: pass if the domain has any A/AAAA record.
				if !consume(budget) {
					return SpfOutcome::PermError;
				}
				match dns.addresses(domain).await {
					Ok(addresses) => !addresses.is_empty(),
					Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
				}
			}
			Mechanism::Ptr { .. } => {
				// RFC 7208 §5.5: deprecated. Evaluating ptr: requires reverse
				// DNS lookups (not in DnsLookup today) and is strongly
				// discouraged by the RFC. Treated as non-matching to avoid
				// PermError on records that contain it. Consumes DNS budget
				// to discourage abuse of multiple ptr: terms.
				if !consume(budget) {
					return SpfOutcome::PermError;
				}
				false
			}
		};

		if matched {
			return match qualifier {
				Qualifier::Pass => SpfOutcome::Pass,
				Qualifier::Fail => SpfOutcome::Fail,
				Qualifier::SoftFail => SpfOutcome::SoftFail,
				Qualifier::Neutral => SpfOutcome::Neutral,
			};
		}
	}

	if let Some(redirect) = &record.redirect {
		if !consume(budget) {
			return SpfOutcome::PermError;
		}
		let outcome = Box::pin(check_host_inner(dns, ip, redirect, budget, depth + 1)).await;
		// A redirect target without a record is a permerror (section 6.1).
		return if outcome == SpfOutcome::None {
			SpfOutcome::PermError
		} else {
			outcome
		};
	}

	// No mechanism matched and no redirect: default neutral (section 4.7).
	SpfOutcome::Neutral
}

fn consume(budget: &mut u32) -> bool {
	if *budget == 0 {
		return false;
	}
	*budget -= 1;
	true
}

async fn fetch_record(dns: &dyn DnsLookup, domain: &str) -> Result<Option<Record>, SpfOutcome> {
	let texts = match dns.txt(domain).await {
		Ok(texts) => texts,
		Err(DnsFailure::Temporary) => return Err(SpfOutcome::TempError),
	};
	let mut records = texts
		.iter()
		.filter(|text| *text == "v=spf1" || text.starts_with("v=spf1 "));
	let Some(text) = records.next() else {
		return Ok(None);
	};
	// Multiple v=spf1 records are a permerror (section 4.5).
	if records.next().is_some() {
		return Err(SpfOutcome::PermError);
	}
	super::record::parse(text)
		.map(Some)
		.map_err(|_| SpfOutcome::PermError)
}

fn address_matches(ip: IpAddr, candidate: IpAddr, prefix4: u8, prefix6: u8) -> bool {
	match (ip, candidate) {
		(IpAddr::V4(ip), IpAddr::V4(candidate)) => v4_in_network(ip, candidate, prefix4),
		(IpAddr::V6(ip), IpAddr::V6(candidate)) => v6_in_network(ip, candidate, prefix6),
		_ => false,
	}
}

fn v4_in_network(ip: std::net::Ipv4Addr, network: std::net::Ipv4Addr, prefix: u8) -> bool {
	let mask = if prefix == 0 {
		0
	} else {
		u32::MAX << (32 - u32::from(prefix))
	};
	(u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn v6_in_network(ip: std::net::Ipv6Addr, network: std::net::Ipv6Addr, prefix: u8) -> bool {
	let mask = if prefix == 0 {
		0
	} else {
		u128::MAX << (128 - u128::from(prefix))
	};
	(u128::from(ip) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
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
		check_host(dns, ip(from_ip), domain).await
	}

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

	#[tokio::test]
	async fn exists_matches_when_domain_has_an_a_record() {
		let mut dns = dns_with(&[("example.org", "v=spf1 exists:_spf.example.org -all")]);
		dns.addresses
			.insert("_spf.example.org".into(), vec![ip("192.0.2.1")]);
		assert_eq!(
			outcome(&dns, "198.51.100.7", "example.org").await,
			SpfOutcome::Pass
		);
	}

	#[tokio::test]
	async fn exists_does_not_match_when_domain_is_empty() {
		let dns = dns_with(&[("example.org", "v=spf1 exists:_absent.example.org -all")]);
		// No address record for _absent.example.org → mechanism does not match.
		assert_eq!(
			outcome(&dns, "198.51.100.7", "example.org").await,
			SpfOutcome::Fail
		);
	}

	#[tokio::test]
	async fn ptr_does_not_match_and_falls_through() {
		// ptr: is deprecated; treated as non-matching so the next term decides.
		let dns = dns_with(&[(
			"example.org",
			"v=spf1 ptr:example.org ip4:192.0.2.0/24 -all",
		)]);
		// ptr non-match → ip4 hit → Pass
		assert_eq!(
			outcome(&dns, "192.0.2.5", "example.org").await,
			SpfOutcome::Pass
		);
		// ptr non-match → ip4 miss → -all → Fail
		assert_eq!(
			outcome(&dns, "198.51.100.5", "example.org").await,
			SpfOutcome::Fail
		);
	}

	#[tokio::test]
	async fn bare_ptr_does_not_match_and_falls_through() {
		let dns = dns_with(&[("example.org", "v=spf1 ptr ~all")]);
		assert_eq!(
			outcome(&dns, "192.0.2.5", "example.org").await,
			SpfOutcome::SoftFail
		);
	}
}
