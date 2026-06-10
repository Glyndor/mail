//! DMARC record parsing (RFC 7489 section 6.3).

/// Requested policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
	None,
	Quarantine,
	Reject,
}

/// Alignment mode for SPF/DKIM identifiers (RFC 7489 section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
	Relaxed,
	Strict,
}

/// A parsed `_dmarc` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
	pub policy: Policy,
	/// Subdomain policy; defaults to `policy`.
	pub subdomain_policy: Policy,
	pub dkim_alignment: Alignment,
	pub spf_alignment: Alignment,
	/// Percentage of messages subject to the policy (0–100, default 100).
	pub pct: u8,
}

/// Parse a `v=DMARC1` TXT record. Returns `None` for records that are not
/// DMARC at all; `Err` for DMARC records that are malformed (permerror).
pub fn parse(text: &str) -> Option<Result<Record, ()>> {
	let mut tags = text.split(';').map(str::trim);
	if tags.next() != Some("v=DMARC1") {
		return None;
	}

	let mut policy = None;
	let mut subdomain_policy = None;
	let mut dkim_alignment = Alignment::Relaxed;
	let mut spf_alignment = Alignment::Relaxed;
	let mut pct: u8 = 100;

	for tag in tags {
		if tag.is_empty() {
			continue;
		}
		let Some((name, value)) = tag.split_once('=') else {
			return Some(Err(()));
		};
		let value = value.trim();
		match name.trim() {
			"p" => match parse_policy(value) {
				Some(parsed) => policy = Some(parsed),
				None => return Some(Err(())),
			},
			"sp" => match parse_policy(value) {
				Some(parsed) => subdomain_policy = Some(parsed),
				None => return Some(Err(())),
			},
			"adkim" => match parse_alignment(value) {
				Some(parsed) => dkim_alignment = parsed,
				None => return Some(Err(())),
			},
			"aspf" => match parse_alignment(value) {
				Some(parsed) => spf_alignment = parsed,
				None => return Some(Err(())),
			},
			"pct" => match value.parse::<u8>() {
				Ok(v) => pct = v.min(100),
				Err(_) => return Some(Err(())),
			},
			_ => {}
		}
	}

	let Some(policy) = policy else {
		// p= is required (section 6.3).
		return Some(Err(()));
	};
	Some(Ok(Record {
		policy,
		subdomain_policy: subdomain_policy.unwrap_or(policy),
		dkim_alignment,
		spf_alignment,
		pct,
	}))
}

fn parse_policy(value: &str) -> Option<Policy> {
	match value.to_ascii_lowercase().as_str() {
		"none" => Some(Policy::None),
		"quarantine" => Some(Policy::Quarantine),
		"reject" => Some(Policy::Reject),
		_ => None,
	}
}

fn parse_alignment(value: &str) -> Option<Alignment> {
	match value.to_ascii_lowercase().as_str() {
		"r" => Some(Alignment::Relaxed),
		"s" => Some(Alignment::Strict),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_typical_record() {
		let record = parse("v=DMARC1; p=reject; adkim=s; aspf=r")
			.expect("is dmarc")
			.expect("valid");
		assert_eq!(record.policy, Policy::Reject);
		assert_eq!(record.subdomain_policy, Policy::Reject);
		assert_eq!(record.dkim_alignment, Alignment::Strict);
		assert_eq!(record.spf_alignment, Alignment::Relaxed);
	}

	#[test]
	fn subdomain_policy_overrides() {
		let record = parse("v=DMARC1; p=reject; sp=none")
			.expect("is dmarc")
			.expect("valid");
		assert_eq!(record.policy, Policy::Reject);
		assert_eq!(record.subdomain_policy, Policy::None);
	}

	#[test]
	fn parses_pct_and_ignores_reporting_tags() {
		let record = parse("v=DMARC1; p=quarantine; rua=mailto:agg@example.org; pct=50")
			.expect("is dmarc")
			.expect("valid");
		assert_eq!(record.policy, Policy::Quarantine);
		assert_eq!(record.pct, 50);
	}

	#[test]
	fn pct_defaults_to_100() {
		let record = parse("v=DMARC1; p=reject")
			.expect("is dmarc")
			.expect("valid");
		assert_eq!(record.pct, 100);
	}

	#[test]
	fn pct_clamped_to_100() {
		let record = parse("v=DMARC1; p=reject; pct=200")
			.expect("is dmarc")
			.expect("valid");
		assert_eq!(record.pct, 100);
	}

	#[test]
	fn pct_zero_parsed() {
		let record = parse("v=DMARC1; p=reject; pct=0")
			.expect("is dmarc")
			.expect("valid");
		assert_eq!(record.pct, 0);
	}

	#[test]
	fn pct_non_numeric_is_error() {
		assert_eq!(parse("v=DMARC1; p=reject; pct=all"), Some(Err(())));
	}

	#[test]
	fn non_dmarc_text_is_none() {
		assert!(parse("v=spf1 -all").is_none());
		assert!(parse("some random text").is_none());
	}

	#[test]
	fn missing_policy_is_error() {
		assert_eq!(parse("v=DMARC1; adkim=s"), Some(Err(())));
	}

	#[test]
	fn malformed_values_are_errors() {
		assert_eq!(parse("v=DMARC1; p=destroy"), Some(Err(())));
		assert_eq!(parse("v=DMARC1; p=none; adkim=x"), Some(Err(())));
		assert_eq!(parse("v=DMARC1; p"), Some(Err(())));
	}
}
