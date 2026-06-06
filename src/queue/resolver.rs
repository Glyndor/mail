//! Connecting to the responsible server for a recipient domain.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::mtasts::Policy;

use super::client::DeliveryError;

/// A bidirectional stream the SMTP client can drive.
pub type BoxedStream = Box<dyn DynStream>;

/// Future returned by [`Connector::connect`].
pub type ConnectFuture<'a> = std::pin::Pin<
	Box<dyn Future<Output = Result<(BoxedStream, String), DeliveryError>> + Send + 'a>,
>;

/// Object-safe stream alias.
pub trait DynStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DynStream for T {}

/// Opens a connection to the mail exchanger of a domain. Abstracted so the
/// worker can be tested without DNS or network access.
pub trait Connector: Send + Sync {
	/// Connect to an exchanger for `domain`. With an enforce-mode policy,
	/// only policy-permitted MX hosts may be contacted.
	fn connect(&self, domain: &str, policy: Option<&Policy>) -> ConnectFuture<'_>;
}

/// Real connector: system resolver for MX records, TCP to port 25.
pub struct MxConnector {
	resolver: hickory_resolver::TokioResolver,
}

impl MxConnector {
	/// Build a connector using the system DNS configuration.
	pub fn from_system() -> std::io::Result<Self> {
		let builder =
			hickory_resolver::TokioResolver::builder_tokio().map_err(std::io::Error::other)?;
		Ok(MxConnector {
			resolver: builder.build().map_err(std::io::Error::other)?,
		})
	}

	/// MX hostnames in preference order; implicit MX (the domain itself,
	/// RFC 5321 section 5.1) when no MX records exist.
	async fn exchangers(&self, domain: &str) -> Result<Vec<String>, DeliveryError> {
		use hickory_resolver::net::{DnsError, NetError};
		use hickory_resolver::proto::rr::{RecordType, rdata::MX};

		match self
			.resolver
			.lookup(format!("{domain}."), RecordType::MX)
			.await
		{
			Ok(lookup) => {
				let mut records: Vec<&MX> = lookup
					.answers()
					.iter()
					.filter_map(|record| match &record.data {
						hickory_resolver::proto::rr::RData::MX(mx) => Some(mx),
						_ => None,
					})
					.collect();
				records.sort_by_key(|mx| mx.preference);
				let hosts: Vec<String> = records
					.iter()
					.map(|mx| mx.exchange.to_utf8().trim_end_matches('.').to_string())
					.collect();
				if hosts.is_empty() {
					Ok(vec![domain.to_string()])
				} else {
					Ok(hosts)
				}
			}
			// No MX records: fall back to the implicit MX.
			Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(vec![domain.to_string()]),
			Err(error) => Err(DeliveryError::Transient(format!(
				"MX lookup failed: {error}"
			))),
		}
	}
}

impl Connector for MxConnector {
	fn connect(&self, domain: &str, policy: Option<&Policy>) -> ConnectFuture<'_> {
		let domain = domain.to_string();
		let policy = policy.cloned();
		Box::pin(async move {
			let mut hosts = self.exchangers(&domain).await?;
			if let Some(policy) = &policy {
				hosts.retain(|host| policy.permits_mx(host));
				if hosts.is_empty() {
					// Never contact unlisted hosts under enforce: retry later.
					return Err(DeliveryError::Transient(format!(
						"no MTA-STS-permitted MX for {domain}"
					)));
				}
			}
			let mut last_error = DeliveryError::Transient(format!("no exchangers for {domain}"));
			for host in hosts {
				match TcpStream::connect((host.as_str(), 25)).await {
					Ok(stream) => return Ok((Box::new(stream) as BoxedStream, host)),
					Err(error) => {
						last_error = DeliveryError::Transient(format!(
							"connect to {host}:25 failed: {error}"
						));
					}
				}
			}
			Err(last_error)
		})
	}
}
