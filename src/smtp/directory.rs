//! Recipient resolution: which account, if any, receives an address.

use std::collections::{HashMap, HashSet};

use super::address::Address;

/// Outcome of resolving a recipient address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
	/// The domain is not served here; accepting would mean relaying.
	NotLocal,
	/// The domain is local but no account owns the address.
	UnknownUser,
	/// The address belongs to this account.
	Account(String),
}

/// Immutable lookup table built from the configuration.
#[derive(Debug, Default)]
pub struct Directory {
	domains: HashSet<String>,
	accounts_by_address: HashMap<String, String>,
}

impl Directory {
	/// Build a directory. Domains and address keys are lowercased here so
	/// lookups are case-insensitive regardless of the config's spelling.
	pub fn new(
		domains: impl IntoIterator<Item = String>,
		address_accounts: impl IntoIterator<Item = (String, String)>,
	) -> Self {
		Directory {
			domains: domains
				.into_iter()
				.map(|domain| domain.to_ascii_lowercase())
				.collect(),
			accounts_by_address: address_accounts
				.into_iter()
				.map(|(address, account)| (address.to_ascii_lowercase(), account))
				.collect(),
		}
	}

	/// Resolve a validated address.
	pub fn resolve(&self, address: &Address) -> Resolution {
		if !self.domains.contains(address.domain()) {
			return Resolution::NotLocal;
		}
		match self
			.accounts_by_address
			.get(&address.to_string().to_ascii_lowercase())
		{
			Some(account) => Resolution::Account(account.clone()),
			None => Resolution::UnknownUser,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn directory() -> Directory {
		Directory::new(
			["example.org".to_string()],
			[("Alice@EXAMPLE.org".to_string(), "alice".to_string())],
		)
	}

	fn parse(raw: &str) -> Address {
		Address::parse(raw).expect("valid address")
	}

	#[test]
	fn resolves_known_address_case_insensitively() {
		assert_eq!(
			directory().resolve(&parse("ALICE@example.ORG")),
			Resolution::Account("alice".to_string())
		);
	}

	#[test]
	fn unknown_user_in_local_domain() {
		assert_eq!(
			directory().resolve(&parse("bob@example.org")),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn foreign_domain_is_not_local() {
		assert_eq!(
			directory().resolve(&parse("alice@elsewhere.example")),
			Resolution::NotLocal
		);
	}

	#[test]
	fn empty_directory_resolves_nothing() {
		let empty = Directory::default();
		assert_eq!(
			empty.resolve(&parse("alice@example.org")),
			Resolution::NotLocal
		);
	}
}
