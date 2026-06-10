//! SPF record parsing (RFC 7208 sections 4.6, 5).

/// Mechanism qualifier (RFC 7208 section 4.6.2). Default is `+`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
	Pass,
	Fail,
	SoftFail,
	Neutral,
}

/// A single mechanism, with optional CIDR prefixes where applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
	All,
	Ip4 {
		network: std::net::Ipv4Addr,
		prefix: u8,
	},
	Ip6 {
		network: std::net::Ipv6Addr,
		prefix: u8,
	},
	A {
		domain: Option<String>,
		prefix4: u8,
		prefix6: u8,
	},
	Mx {
		domain: Option<String>,
		prefix4: u8,
		prefix6: u8,
	},
	Include {
		domain: String,
	},
	/// `exists:domain` — matches if the domain has any A/AAAA record.
	Exists {
		domain: String,
	},
	/// `ptr` / `ptr:domain` — deprecated (RFC 7208 §5.5); retained for
	/// compatibility but treated as always non-matching at evaluation.
	Ptr {
		domain: Option<String>,
	},
}

/// A parsed SPF record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
	pub directives: Vec<(Qualifier, Mechanism)>,
	pub redirect: Option<String>,
}

/// Why a record failed to parse: always a `permerror`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError(pub String);

/// Parse the content of a `v=spf1` TXT record.
pub fn parse(text: &str) -> Result<Record, RecordError> {
	let mut terms = text.split_ascii_whitespace();
	if terms.next() != Some("v=spf1") {
		return Err(RecordError("missing v=spf1 version tag".into()));
	}

	let mut record = Record::default();
	for term in terms {
		// Modifiers contain `=`; `redirect` is the only one we act on,
		// unknown modifiers are ignored per section 6.
		if let Some((name, value)) = term.split_once('=') {
			if name.eq_ignore_ascii_case("redirect") {
				if record.redirect.is_some() {
					return Err(RecordError("duplicate redirect modifier".into()));
				}
				record.redirect = Some(value.to_ascii_lowercase());
			} else if name.eq_ignore_ascii_case("exp") || !name.contains(':') {
				// Ignored modifier.
			}
			continue;
		}

		let (qualifier, body) = match term.chars().next() {
			Some('+') => (Qualifier::Pass, &term[1..]),
			Some('-') => (Qualifier::Fail, &term[1..]),
			Some('~') => (Qualifier::SoftFail, &term[1..]),
			Some('?') => (Qualifier::Neutral, &term[1..]),
			_ => (Qualifier::Pass, term),
		};
		record.directives.push((qualifier, parse_mechanism(body)?));
	}
	Ok(record)
}

fn parse_mechanism(body: &str) -> Result<Mechanism, RecordError> {
	let lower = body.to_ascii_lowercase();
	if lower == "all" {
		return Ok(Mechanism::All);
	}
	if let Some(value) = lower.strip_prefix("ip4:") {
		let (addr, prefix) = split_cidr(value, 32)?;
		let network: std::net::Ipv4Addr = addr
			.parse()
			.map_err(|_| RecordError(format!("invalid ip4 address {addr}")))?;
		return Ok(Mechanism::Ip4 { network, prefix });
	}
	if let Some(value) = lower.strip_prefix("ip6:") {
		let (addr, prefix) = split_cidr(value, 128)?;
		let network: std::net::Ipv6Addr = addr
			.parse()
			.map_err(|_| RecordError(format!("invalid ip6 address {addr}")))?;
		return Ok(Mechanism::Ip6 { network, prefix });
	}
	if let Some(value) = lower.strip_prefix("include:") {
		if value.is_empty() {
			return Err(RecordError("include without domain".into()));
		}
		return Ok(Mechanism::Include {
			domain: value.to_string(),
		});
	}
	if lower == "a" || lower.starts_with("a:") || lower.starts_with("a/") {
		let (domain, prefix4, prefix6) = parse_domain_spec(&lower[1..])?;
		return Ok(Mechanism::A {
			domain,
			prefix4,
			prefix6,
		});
	}
	if lower == "mx" || lower.starts_with("mx:") || lower.starts_with("mx/") {
		let (domain, prefix4, prefix6) = parse_domain_spec(&lower[2..])?;
		return Ok(Mechanism::Mx {
			domain,
			prefix4,
			prefix6,
		});
	}
	if let Some(value) = lower.strip_prefix("exists:") {
		if value.is_empty() {
			return Err(RecordError("exists without domain".into()));
		}
		return Ok(Mechanism::Exists {
			domain: value.to_string(),
		});
	}
	if lower == "ptr" || lower.starts_with("ptr:") {
		let domain = lower
			.strip_prefix("ptr:")
			.filter(|d| !d.is_empty())
			.map(str::to_string);
		return Ok(Mechanism::Ptr { domain });
	}
	Err(RecordError(format!("unsupported mechanism \"{body}\"")))
}

/// Parse the `[:domain][/prefix4[//prefix6]]` tail of `a`/`mx`.
fn parse_domain_spec(tail: &str) -> Result<(Option<String>, u8, u8), RecordError> {
	let (domain_part, cidr_part) = match tail.find('/') {
		Some(slash) => (&tail[..slash], &tail[slash..]),
		None => (tail, ""),
	};
	let domain = domain_part
		.strip_prefix(':')
		.filter(|d| !d.is_empty())
		.map(|d| d.to_string());
	if !domain_part.is_empty() && domain.is_none() {
		return Err(RecordError(format!("malformed domain spec \"{tail}\"")));
	}

	let (mut prefix4, mut prefix6) = (32u8, 128u8);
	if !cidr_part.is_empty() {
		let cidr = &cidr_part[1..];
		// Forms: `/n` (v4), `/n//m` (both), `//m` (v6 only).
		let (four, six) = if let Some(rest) = cidr.strip_prefix('/') {
			("", Some(rest))
		} else {
			match cidr.split_once("//") {
				Some((four, six)) => (four, Some(six)),
				None => (cidr, None),
			}
		};
		if !four.is_empty() {
			prefix4 = parse_prefix(four, 32)?;
		}
		if let Some(six) = six {
			prefix6 = parse_prefix(six, 128)?;
		}
	}
	Ok((domain, prefix4, prefix6))
}

fn split_cidr(value: &str, max: u8) -> Result<(&str, u8), RecordError> {
	match value.split_once('/') {
		Some((addr, prefix)) => Ok((addr, parse_prefix(prefix, max)?)),
		None => Ok((value, max)),
	}
}

fn parse_prefix(text: &str, max: u8) -> Result<u8, RecordError> {
	let prefix: u8 = text
		.parse()
		.map_err(|_| RecordError(format!("invalid prefix \"{text}\"")))?;
	if prefix > max {
		return Err(RecordError(format!("prefix /{prefix} exceeds /{max}")));
	}
	Ok(prefix)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_typical_record() {
		let record =
			parse("v=spf1 ip4:192.0.2.0/24 include:_spf.example.org ~all").expect("valid record");
		assert_eq!(record.directives.len(), 3);
		assert_eq!(
			record.directives[0],
			(
				Qualifier::Pass,
				Mechanism::Ip4 {
					network: "192.0.2.0".parse().expect("ip"),
					prefix: 24
				}
			)
		);
		assert_eq!(record.directives[2], (Qualifier::SoftFail, Mechanism::All));
	}

	#[test]
	fn parses_a_and_mx_with_cidr() {
		let record = parse("v=spf1 a mx:mail.example.org/28 a:other.example//64 -all")
			.expect("valid record");
		assert_eq!(
			record.directives[0].1,
			Mechanism::A {
				domain: None,
				prefix4: 32,
				prefix6: 128
			}
		);
		assert_eq!(
			record.directives[1].1,
			Mechanism::Mx {
				domain: Some("mail.example.org".into()),
				prefix4: 28,
				prefix6: 128
			}
		);
		assert_eq!(
			record.directives[2].1,
			Mechanism::A {
				domain: Some("other.example".into()),
				prefix4: 32,
				prefix6: 64
			}
		);
	}

	#[test]
	fn parses_redirect_and_ignores_unknown_modifiers() {
		let record =
			parse("v=spf1 exp=explain.example.org redirect=_spf.example.org").expect("valid");
		assert_eq!(record.redirect.as_deref(), Some("_spf.example.org"));
		assert!(record.directives.is_empty());
	}

	#[test]
	fn rejects_wrong_version() {
		assert!(parse("v=spf2 -all").is_err());
		assert!(parse("-all").is_err());
	}

	#[test]
	fn rejects_bad_addresses_and_prefixes() {
		assert!(parse("v=spf1 ip4:999.0.2.0/24").is_err());
		assert!(parse("v=spf1 ip4:192.0.2.0/33").is_err());
		assert!(parse("v=spf1 ip6:zzzz::/64").is_err());
		assert!(parse("v=spf1 a/129").is_err());
	}

	#[test]
	fn rejects_unknown_mechanism_and_duplicates() {
		assert!(parse("v=spf1 redirect=a.example redirect=b.example").is_err());
		assert!(parse("v=spf1 include:").is_err());
		assert!(parse("v=spf1 exists:").is_err());
	}

	#[test]
	fn parses_exists_and_ptr() {
		let record = parse("v=spf1 exists:_spf.%{d}.example.org ptr ?all").expect("valid");
		assert_eq!(
			record.directives[0].1,
			Mechanism::Exists {
				domain: "_spf.%{d}.example.org".into()
			}
		);
		assert_eq!(record.directives[1].1, Mechanism::Ptr { domain: None });
		assert_eq!(record.directives[2].1, Mechanism::All);

		let record = parse("v=spf1 ptr:example.org -all").expect("valid");
		assert_eq!(
			record.directives[0].1,
			Mechanism::Ptr {
				domain: Some("example.org".into())
			}
		);
	}

	#[test]
	fn all_qualifiers_parse() {
		let record = parse("v=spf1 +all -all ~all ?all").expect("valid");
		let qualifiers: Vec<Qualifier> = record.directives.iter().map(|(q, _)| *q).collect();
		assert_eq!(
			qualifiers,
			vec![
				Qualifier::Pass,
				Qualifier::Fail,
				Qualifier::SoftFail,
				Qualifier::Neutral
			]
		);
	}
}
