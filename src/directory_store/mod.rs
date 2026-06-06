//! Runtime account store and the hot-reloadable directory handle.
//!
//! Static accounts come from the config file and never change at runtime;
//! dynamic accounts live in `<data_dir>/accounts.toml`, managed through the
//! API. The effective directory is rebuilt and swapped on every mutation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::config::Account;
use crate::smtp::address::Address;
use crate::smtp::directory::Directory;

/// Hot-swappable view of the directory. Cheap to clone; readers snapshot.
#[derive(Clone)]
pub struct DirectoryHandle {
	inner: Arc<RwLock<Arc<Directory>>>,
}

impl std::fmt::Debug for DirectoryHandle {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("DirectoryHandle")
	}
}

impl DirectoryHandle {
	/// Wrap an initial directory.
	pub fn new(directory: Directory) -> Self {
		DirectoryHandle {
			inner: Arc::new(RwLock::new(Arc::new(directory))),
		}
	}

	/// The current directory snapshot.
	pub fn current(&self) -> Arc<Directory> {
		Arc::clone(&self.inner.read().expect("directory lock"))
	}

	/// Replace the directory.
	pub fn replace(&self, directory: Directory) {
		*self.inner.write().expect("directory lock") = Arc::new(directory);
	}
}

/// A dynamic account as persisted in `accounts.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAccount {
	pub name: String,
	pub addresses: Vec<String>,
	pub password_hash: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DynamicFile {
	#[serde(default)]
	accounts: Vec<DynamicAccount>,
}

/// Errors from the account store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
	#[error("invalid account: {0}")]
	Invalid(String),
	#[error("account {0} already exists")]
	Duplicate(String),
	#[error("no such dynamic account: {0}")]
	NotFound(String),
	#[error("storage failure: {0}")]
	Io(#[from] std::io::Error),
}

/// The mutable account store: static accounts + persisted dynamic ones.
pub struct AccountStore {
	path: PathBuf,
	domains: Vec<String>,
	static_accounts: Vec<Account>,
	dynamic: RwLock<Vec<DynamicAccount>>,
	handle: DirectoryHandle,
}

impl AccountStore {
	/// Load the store, merge with the static configuration and build the
	/// initial directory.
	pub fn open(
		data_dir: &Path,
		domains: Vec<String>,
		static_accounts: Vec<Account>,
	) -> Result<Self, StoreError> {
		let path = data_dir.join("accounts.toml");
		let dynamic: DynamicFile = match std::fs::read_to_string(&path) {
			Ok(text) => {
				toml::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => DynamicFile::default(),
			Err(error) => return Err(error.into()),
		};

		let store = AccountStore {
			path,
			domains,
			static_accounts,
			dynamic: RwLock::new(dynamic.accounts),
			handle: DirectoryHandle::new(Directory::default()),
		};
		store.handle.replace(store.build_directory());
		Ok(store)
	}

	/// The hot-reloadable handle shared with servers and delivery.
	pub fn handle(&self) -> DirectoryHandle {
		self.handle.clone()
	}

	/// Account views (name + addresses) across static and dynamic accounts.
	pub fn account_views(&self) -> Vec<(String, Vec<String>, bool)> {
		let dynamic = self.dynamic.read().expect("store lock");
		let mut views: Vec<(String, Vec<String>, bool)> = self
			.static_accounts
			.iter()
			.map(|account| (account.name.clone(), account.addresses.clone(), false))
			.collect();
		views.extend(
			dynamic
				.iter()
				.map(|account| (account.name.clone(), account.addresses.clone(), true)),
		);
		views
	}

	/// Add a dynamic account. `password_hash` must already be argon2id.
	pub fn add(&self, account: DynamicAccount) -> Result<(), StoreError> {
		validate_name(&account.name)?;
		if account.addresses.is_empty() {
			return Err(StoreError::Invalid("addresses must not be empty".into()));
		}
		for raw in &account.addresses {
			let address = Address::parse(raw)
				.map_err(|_| StoreError::Invalid(format!("invalid address {raw}")))?;
			if !self
				.domains
				.iter()
				.any(|domain| domain.eq_ignore_ascii_case(address.domain()))
			{
				return Err(StoreError::Invalid(format!(
					"address {raw} is not in a configured domain"
				)));
			}
		}

		let mut dynamic = self.dynamic.write().expect("store lock");
		let name_taken = self
			.static_accounts
			.iter()
			.map(|existing| existing.name.as_str())
			.chain(dynamic.iter().map(|existing| existing.name.as_str()))
			.any(|existing| existing == account.name);
		if name_taken {
			return Err(StoreError::Duplicate(account.name.clone()));
		}
		let mut known_addresses: Vec<String> = self
			.static_accounts
			.iter()
			.flat_map(|existing| existing.addresses.iter())
			.chain(
				dynamic
					.iter()
					.flat_map(|existing| existing.addresses.iter()),
			)
			.map(|address| address.to_ascii_lowercase())
			.collect();
		known_addresses.sort();
		for raw in &account.addresses {
			if known_addresses
				.binary_search(&raw.to_ascii_lowercase())
				.is_ok()
			{
				return Err(StoreError::Duplicate(raw.clone()));
			}
		}

		dynamic.push(account);
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Remove a dynamic account. Static accounts cannot be removed here.
	pub fn remove(&self, name: &str) -> Result<(), StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let before = dynamic.len();
		dynamic.retain(|account| account.name != name);
		if dynamic.len() == before {
			return Err(StoreError::NotFound(name.to_string()));
		}
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	/// Replace the password hash of a dynamic account.
	pub fn set_password_hash(&self, name: &str, hash: String) -> Result<(), StoreError> {
		let mut dynamic = self.dynamic.write().expect("store lock");
		let account = dynamic
			.iter_mut()
			.find(|account| account.name == name)
			.ok_or_else(|| StoreError::NotFound(name.to_string()))?;
		account.password_hash = hash;
		self.persist(&dynamic)?;
		drop(dynamic);
		self.handle.replace(self.build_directory());
		Ok(())
	}

	fn persist(&self, dynamic: &[DynamicAccount]) -> Result<(), StoreError> {
		let file = DynamicFile {
			accounts: dynamic.to_vec(),
		};
		let text = toml::to_string_pretty(&file)
			.map_err(|error| StoreError::Invalid(error.to_string()))?;
		let tmp = self.path.with_extension("toml.tmp");
		std::fs::write(&tmp, text)?;
		std::fs::rename(&tmp, &self.path)?;
		Ok(())
	}

	fn build_directory(&self) -> Directory {
		let dynamic = self.dynamic.read().expect("store lock");
		let address_accounts = self
			.static_accounts
			.iter()
			.flat_map(|account| {
				account
					.addresses
					.iter()
					.map(|address| (address.clone(), account.name.clone()))
			})
			.chain(dynamic.iter().flat_map(|account| {
				account
					.addresses
					.iter()
					.map(|address| (address.clone(), account.name.clone()))
			}))
			.collect::<Vec<_>>();
		let hashes = self
			.static_accounts
			.iter()
			.filter_map(|account| {
				account
					.password_hash
					.as_ref()
					.map(|hash| (account.name.clone(), hash.clone()))
			})
			.chain(
				dynamic
					.iter()
					.map(|account| (account.name.clone(), account.password_hash.clone())),
			)
			.collect::<Vec<_>>();
		Directory::new(self.domains.iter().cloned(), address_accounts).with_password_hashes(hashes)
	}
}

fn validate_name(name: &str) -> Result<(), StoreError> {
	let safe = !name.is_empty()
		&& name.len() <= 64
		&& name
			.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
		&& !name.starts_with('-');
	if safe {
		Ok(())
	} else {
		Err(StoreError::Invalid(format!(
			"account name \"{name}\" must be lowercase alphanumeric/hyphen"
		)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::smtp::directory::Resolution;

	fn static_account() -> Account {
		Account {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: None,
		}
	}

	fn open_store(dir: &Path) -> AccountStore {
		AccountStore::open(dir, vec!["example.org".to_string()], vec![static_account()])
			.expect("open store")
	}

	fn dynamic(name: &str, address: &str) -> DynamicAccount {
		DynamicAccount {
			name: name.to_string(),
			addresses: vec![address.to_string()],
			password_hash: "$argon2id$stub".to_string(),
		}
	}

	fn resolves(handle: &DirectoryHandle, raw: &str) -> Resolution {
		handle
			.current()
			.resolve(&Address::parse(raw).expect("address"))
	}

	#[test]
	fn add_swaps_the_directory_and_persists() {
		let dir = tempfile::tempdir().expect("tempdir");
		let store = open_store(dir.path());
		let handle = store.handle();

		assert_eq!(
			resolves(&handle, "bob@example.org"),
			Resolution::UnknownUser
		);
		store.add(dynamic("bob", "bob@example.org")).expect("add");
		assert_eq!(
			resolves(&handle, "bob@example.org"),
			Resolution::Account("bob".to_string())
		);

		// A fresh store sees the persisted account.
		let reopened = open_store(dir.path());
		assert_eq!(
			resolves(&reopened.handle(), "bob@example.org"),
			Resolution::Account("bob".to_string())
		);
	}

	#[test]
	fn rejects_duplicates_and_foreign_domains() {
		let dir = tempfile::tempdir().expect("tempdir");
		let store = open_store(dir.path());

		// Static name and address are taken.
		assert!(matches!(
			store.add(dynamic("alice", "alice2@example.org")),
			Err(StoreError::Duplicate(_))
		));
		assert!(matches!(
			store.add(dynamic("bob", "ALICE@example.org")),
			Err(StoreError::Duplicate(_))
		));
		assert!(matches!(
			store.add(dynamic("bob", "bob@elsewhere.example")),
			Err(StoreError::Invalid(_))
		));
		assert!(matches!(
			store.add(dynamic("Bad Name", "bob@example.org")),
			Err(StoreError::Invalid(_))
		));
	}

	#[test]
	fn remove_only_dynamic_accounts() {
		let dir = tempfile::tempdir().expect("tempdir");
		let store = open_store(dir.path());
		store.add(dynamic("bob", "bob@example.org")).expect("add");

		assert!(matches!(
			store.remove("alice"),
			Err(StoreError::NotFound(_))
		));
		store.remove("bob").expect("remove");
		assert_eq!(
			resolves(&store.handle(), "bob@example.org"),
			Resolution::UnknownUser
		);
	}

	#[test]
	fn password_change_swaps_credentials() {
		let dir = tempfile::tempdir().expect("tempdir");
		let store = open_store(dir.path());
		store.add(dynamic("bob", "bob@example.org")).expect("add");

		let real_hash = crate::smtp::auth::tests::hash("secret");
		store
			.set_password_hash("bob", real_hash)
			.expect("set password");
		let directory = store.handle().current();
		let (account, hash) = directory.credentials("bob").expect("credentials");
		assert_eq!(account, "bob");
		assert!(crate::smtp::auth::verify_password(hash, "secret"));
	}

	#[test]
	fn account_views_mark_origin() {
		let dir = tempfile::tempdir().expect("tempdir");
		let store = open_store(dir.path());
		store.add(dynamic("bob", "bob@example.org")).expect("add");
		let views = store.account_views();
		assert_eq!(views.len(), 2);
		assert_eq!(views[0].0, "alice");
		assert!(!views[0].2);
		assert_eq!(views[1].0, "bob");
		assert!(views[1].2);
	}
}
