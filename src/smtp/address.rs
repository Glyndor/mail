//! Mailbox address validation (RFC 5321 section 4.1.2, strict subset).
//!
//! Quoted local parts and address literals are intentionally not accepted:
//! they are a recurring source of parser differentials and abuse, and real
//! mail rarely needs them. Strictness here is a feature.

/// Maximum total address length (RFC 5321 section 4.5.3.1.3).
const MAX_ADDRESS: usize = 254;
/// Maximum local-part length (RFC 5321 section 4.5.3.1.1).
const MAX_LOCAL_PART: usize = 64;

/// A validated `local-part@domain` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
	local_part: String,
	domain: String,
}

/// Why an address was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
	TooLong,
	MissingAtSign,
	InvalidLocalPart,
	InvalidDomain,
}

impl Address {
	/// Parse and validate an address.
	pub fn parse(raw: &str) -> Result<Self, AddressError> {
		if raw.len() > MAX_ADDRESS {
			return Err(AddressError::TooLong);
		}
		let (local_part, domain) = raw.rsplit_once('@').ok_or(AddressError::MissingAtSign)?;
		validate_local_part(local_part)?;
		validate_domain(domain)?;
		Ok(Address {
			local_part: local_part.to_string(),
			// Domains compare case-insensitively; store lowercase.
			domain: domain.to_ascii_lowercase(),
		})
	}

	/// The (case-preserved) local part.
	pub fn local_part(&self) -> &str {
		&self.local_part
	}

	/// The lowercased domain.
	pub fn domain(&self) -> &str {
		&self.domain
	}
}

impl std::fmt::Display for Address {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}@{}", self.local_part, self.domain)
	}
}

/// Dot-string per RFC 5321: atoms separated by single dots.
fn validate_local_part(local_part: &str) -> Result<(), AddressError> {
	if local_part.is_empty() || local_part.len() > MAX_LOCAL_PART {
		return Err(AddressError::InvalidLocalPart);
	}
	let valid_atom_char = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c);
	for atom in local_part.split('.') {
		if atom.is_empty() || !atom.chars().all(valid_atom_char) {
			return Err(AddressError::InvalidLocalPart);
		}
	}
	Ok(())
}

fn validate_domain(domain: &str) -> Result<(), AddressError> {
	if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
		return Err(AddressError::InvalidDomain);
	}
	for label in domain.split('.') {
		let valid = !label.is_empty()
			&& label.len() <= 63
			&& !label.starts_with('-')
			&& !label.ends_with('-')
			&& label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
		if !valid {
			return Err(AddressError::InvalidDomain);
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_simple_address() {
		let address = Address::parse("alice@example.org").expect("valid");
		assert_eq!(address.local_part(), "alice");
		assert_eq!(address.domain(), "example.org");
		assert_eq!(address.to_string(), "alice@example.org");
	}

	#[test]
	fn lowercases_domain_but_preserves_local_part() {
		let address = Address::parse("Alice.B@EXAMPLE.ORG").expect("valid");
		assert_eq!(address.local_part(), "Alice.B");
		assert_eq!(address.domain(), "example.org");
	}

	#[test]
	fn accepts_subaddressing_and_special_atoms() {
		assert!(Address::parse("user+tag@example.org").is_ok());
		assert!(Address::parse("user_name@example.org").is_ok());
		assert!(Address::parse("user=x{a}!b@example.org").is_ok());
	}

	#[test]
	fn rejects_missing_at_sign() {
		assert_eq!(
			Address::parse("example.org"),
			Err(AddressError::MissingAtSign)
		);
	}

	#[test]
	fn rejects_empty_or_dotted_local_part() {
		assert_eq!(
			Address::parse("@example.org"),
			Err(AddressError::InvalidLocalPart)
		);
		assert_eq!(
			Address::parse(".a@example.org"),
			Err(AddressError::InvalidLocalPart)
		);
		assert_eq!(
			Address::parse("a..b@example.org"),
			Err(AddressError::InvalidLocalPart)
		);
	}

	#[test]
	fn rejects_quoted_local_part() {
		assert_eq!(
			Address::parse("\"a b\"@example.org"),
			Err(AddressError::InvalidLocalPart)
		);
	}

	#[test]
	fn rejects_overlong_local_part() {
		let raw = format!("{}@example.org", "a".repeat(MAX_LOCAL_PART + 1));
		assert_eq!(Address::parse(&raw), Err(AddressError::InvalidLocalPart));
	}

	#[test]
	fn rejects_overlong_address() {
		let raw = format!("a@{}.example.org", "b".repeat(MAX_ADDRESS));
		assert_eq!(Address::parse(&raw), Err(AddressError::TooLong));
	}

	#[test]
	fn rejects_bad_domains() {
		assert_eq!(Address::parse("a@"), Err(AddressError::InvalidDomain));
		assert_eq!(Address::parse("a@nodot"), Err(AddressError::InvalidDomain));
		assert_eq!(
			Address::parse("a@-bad.example.org"),
			Err(AddressError::InvalidDomain)
		);
		assert_eq!(
			Address::parse("a@bad-.example.org"),
			Err(AddressError::InvalidDomain)
		);
		assert_eq!(
			Address::parse("a@exa_mple.org"),
			Err(AddressError::InvalidDomain)
		);
		assert_eq!(
			Address::parse("a@[127.0.0.1]"),
			Err(AddressError::InvalidDomain)
		);
	}

	#[test]
	fn rejects_overlong_domain_label() {
		let raw = format!("a@{}.org", "b".repeat(64));
		assert_eq!(Address::parse(&raw), Err(AddressError::InvalidDomain));
	}
}
