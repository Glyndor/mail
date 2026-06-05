//! DNS access for SPF evaluation, behind a trait for testability.

use std::net::IpAddr;
use std::pin::Pin;

/// A DNS query failure as SPF distinguishes them (RFC 7208 section 2.6.6/7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsFailure {
	/// Transient lookup problem: evaluation yields `temperror`.
	Temporary,
}

type LookupResult<T> = Result<T, DnsFailure>;
type Lookup<'a, T> = Pin<Box<dyn Future<Output = LookupResult<T>> + Send + 'a>>;

/// The queries SPF evaluation needs. Nonexistent names return empty vectors,
/// not errors.
pub trait DnsLookup: Send + Sync {
	/// TXT records of a name.
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>>;
	/// A/AAAA addresses of a name.
	fn addresses(&self, name: &str) -> Lookup<'_, Vec<IpAddr>>;
	/// MX exchange hostnames of a name.
	fn mx(&self, name: &str) -> Lookup<'_, Vec<String>>;
}

/// Real resolver on top of hickory.
pub struct SystemDns {
	resolver: hickory_resolver::TokioResolver,
}

impl SystemDns {
	/// Build from the system DNS configuration.
	pub fn from_system() -> std::io::Result<Self> {
		let builder =
			hickory_resolver::TokioResolver::builder_tokio().map_err(std::io::Error::other)?;
		Ok(SystemDns {
			resolver: builder.build().map_err(std::io::Error::other)?,
		})
	}

	async fn lookup(
		&self,
		name: &str,
		record_type: hickory_resolver::proto::rr::RecordType,
	) -> LookupResult<Vec<hickory_resolver::proto::rr::RData>> {
		use hickory_resolver::net::{DnsError, NetError};
		match self.resolver.lookup(format!("{name}."), record_type).await {
			Ok(lookup) => Ok(lookup
				.answers()
				.iter()
				.map(|record| record.data.clone())
				.collect()),
			Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(Vec::new()),
			Err(_) => Err(DnsFailure::Temporary),
		}
	}
}

impl DnsLookup for SystemDns {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let name = name.to_string();
		Box::pin(async move {
			use hickory_resolver::proto::rr::{RData, RecordType};
			let records = self.lookup(&name, RecordType::TXT).await?;
			Ok(records
				.iter()
				.filter_map(|data| match data {
					RData::TXT(txt) => Some(
						txt.txt_data
							.iter()
							.map(|chunk| String::from_utf8_lossy(chunk).to_string())
							.collect::<Vec<_>>()
							.concat(),
					),
					_ => None,
				})
				.collect())
		})
	}

	fn addresses(&self, name: &str) -> Lookup<'_, Vec<IpAddr>> {
		let name = name.to_string();
		Box::pin(async move {
			use hickory_resolver::net::{DnsError, NetError};
			match self.resolver.lookup_ip(format!("{name}.")).await {
				Ok(lookup) => Ok(lookup.iter().collect()),
				Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(Vec::new()),
				Err(_) => Err(DnsFailure::Temporary),
			}
		})
	}

	fn mx(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let name = name.to_string();
		Box::pin(async move {
			use hickory_resolver::proto::rr::{RData, RecordType};
			let records = self.lookup(&name, RecordType::MX).await?;
			Ok(records
				.iter()
				.filter_map(|data| match data {
					RData::MX(mx) => Some(mx.exchange.to_utf8().trim_end_matches('.').to_string()),
					_ => None,
				})
				.collect())
		})
	}
}
