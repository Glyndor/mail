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
/// `sender` is the RFC 5321 MAIL FROM address (empty for null reverse-path).
/// `helo` is the EHLO/HELO domain announced by the client.
pub async fn check_host(
	dns: &dyn DnsLookup,
	ip: IpAddr,
	domain: &str,
	sender: &str,
	helo: &str,
) -> SpfOutcome {
	let mut budget = MAX_DNS_MECHANISMS;
	check_host_inner(dns, ip, domain, sender, helo, &mut budget, 0).await
}

/// Recursion depth guard: includes/redirects each consume DNS budget, but a
/// cycle of zero-budget terms must still terminate.
const MAX_DEPTH: u32 = 10;

async fn check_host_inner(
	dns: &dyn DnsLookup,
	ip: IpAddr,
	domain: &str,
	sender: &str,
	helo: &str,
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
				let spec = target.as_deref().unwrap_or(domain);
				let name = match expand_macro(spec, ip, domain, sender, helo) {
					Ok(n) => n,
					Err(e) => return e,
				};
				match dns.addresses(&name).await {
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
				let spec = target.as_deref().unwrap_or(domain);
				let name = match expand_macro(spec, ip, domain, sender, helo) {
					Ok(n) => n,
					Err(e) => return e,
				};
				let exchangers = match dns.mx(&name).await {
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
			Mechanism::Include { domain: spec } => {
				if !consume(budget) {
					return SpfOutcome::PermError;
				}
				let included = match expand_macro(spec, ip, domain, sender, helo) {
					Ok(d) => d,
					Err(e) => return e,
				};
				match Box::pin(check_host_inner(
					dns,
					ip,
					&included,
					sender,
					helo,
					budget,
					depth + 1,
				))
				.await
				{
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

	if let Some(spec) = &record.redirect {
		if !consume(budget) {
			return SpfOutcome::PermError;
		}
		let target = match expand_macro(spec, ip, domain, sender, helo) {
			Ok(d) => d,
			Err(e) => return e,
		};
		let outcome = Box::pin(check_host_inner(
			dns,
			ip,
			&target,
			sender,
			helo,
			budget,
			depth + 1,
		))
		.await;
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

/// Expand macro-strings in a domain-spec (RFC 7208 §7).
/// Returns `PermError` on malformed macro syntax or unknown macro letter.
/// Fast-paths if `spec` contains no `%`.
pub(crate) fn expand_macro(
	spec: &str,
	ip: IpAddr,
	current_domain: &str,
	sender: &str,
	helo: &str,
) -> Result<String, SpfOutcome> {
	if !spec.contains('%') {
		return Ok(spec.to_string());
	}
	let mut result = String::with_capacity(spec.len() * 2);
	let mut rest = spec;
	while let Some(offset) = rest.find('%') {
		result.push_str(&rest[..offset]);
		rest = &rest[offset + 1..];
		let ch = rest.chars().next().ok_or(SpfOutcome::PermError)?;
		match ch {
			'%' => {
				result.push('%');
				rest = &rest[1..];
			}
			'_' => {
				result.push(' ');
				rest = &rest[1..];
			}
			'-' => {
				result.push_str("%20");
				rest = &rest[1..];
			}
			'{' => {
				let close = rest.find('}').ok_or(SpfOutcome::PermError)?;
				let inner = &rest[1..close];
				rest = &rest[close + 1..];
				result.push_str(&expand_macro_inner(
					inner,
					ip,
					current_domain,
					sender,
					helo,
				)?);
			}
			_ => return Err(SpfOutcome::PermError),
		}
	}
	result.push_str(rest);
	Ok(result)
}

/// Expand the content of `%{...}` (letter + optional transformers).
fn expand_macro_inner(
	inner: &str,
	ip: IpAddr,
	current_domain: &str,
	sender: &str,
	helo: &str,
) -> Result<String, SpfOutcome> {
	let mut chars = inner.chars();
	let letter = chars
		.next()
		.ok_or(SpfOutcome::PermError)?
		.to_ascii_lowercase();
	let (count, reverse, delimiters) = parse_macro_transformers(chars.as_str())?;

	let raw = match letter {
		's' => sender.to_string(),
		'l' => sender
			.split_once('@')
			.map_or(sender, |(local, _)| local)
			.to_string(),
		'o' => sender
			.rsplit_once('@')
			.map_or(sender, |(_, domain)| domain)
			.to_string(),
		'd' => current_domain.to_string(),
		'i' => ip_to_macro_str(ip),
		'v' => match ip {
			IpAddr::V4(_) => "in-addr".to_string(),
			IpAddr::V6(_) => "ip6".to_string(),
		},
		'h' => helo.to_string(),
		_ => return Err(SpfOutcome::PermError),
	};

	let mut parts: Vec<&str> = raw.split(|c: char| delimiters.contains(&c)).collect();
	if reverse {
		parts.reverse();
	}
	if let Some(n) = count {
		let skip = parts.len().saturating_sub(n);
		parts.drain(..skip);
	}
	Ok(parts.join("."))
}

/// Parse `[digit][r][delimiter...]` macro transformers (RFC 7208 §7.1).
fn parse_macro_transformers(s: &str) -> Result<(Option<usize>, bool, Vec<char>), SpfOutcome> {
	let count_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
	let count = if count_end == 0 {
		None
	} else {
		Some(
			s[..count_end]
				.parse::<usize>()
				.map_err(|_| SpfOutcome::PermError)?,
		)
	};
	let rest = &s[count_end..];

	let reverse = matches!(rest.chars().next(), Some('r') | Some('R'));
	let delimiters_str = if reverse { &rest[1..] } else { rest };

	let delimiters = if delimiters_str.is_empty() {
		vec!['.']
	} else {
		let chars: Vec<char> = delimiters_str.chars().collect();
		for &d in &chars {
			if !".+-,/_=".contains(d) {
				return Err(SpfOutcome::PermError);
			}
		}
		chars
	};

	Ok((count, reverse, delimiters))
}

/// Format `ip` for use in macro expansion (RFC 7208 §7.3).
/// IPv4: dotted-decimal. IPv6: 32 lowercase hex nibbles separated by `.`.
fn ip_to_macro_str(ip: IpAddr) -> String {
	match ip {
		IpAddr::V4(v4) => v4.to_string(),
		IpAddr::V6(v6) => {
			let nibbles: Vec<String> = v6
				.octets()
				.iter()
				.flat_map(|&b| [format!("{:x}", (b >> 4) & 0xf), format!("{:x}", b & 0xf)])
				.collect();
			nibbles.join(".")
		}
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

#[cfg(test)]
#[path = "evaluator_tests.rs"]
mod tests;
