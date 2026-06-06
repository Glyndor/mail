//! MTA-STS policy parsing, fetching and caching (RFC 8461).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::spf::{DnsFailure, DnsLookup};

/// Policy mode (RFC 8461 section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
	Enforce,
	Testing,
	None,
}

/// A parsed MTA-STS policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
	pub mode: Mode,
	/// Allowed MX patterns: exact hostnames or `*.domain` wildcards.
	pub mx: Vec<String>,
	pub max_age: u64,
}

impl Policy {
	/// Whether an MX hostname is permitted by this policy.
	pub fn permits_mx(&self, host: &str) -> bool {
		let host = host.to_ascii_lowercase();
		self.mx.iter().any(|pattern| {
			if let Some(suffix) = pattern.strip_prefix("*.") {
				// Wildcard matches exactly one leftmost label.
				host.strip_suffix(suffix)
					.and_then(|head| head.strip_suffix('.'))
					.is_some_and(|label| !label.is_empty() && !label.contains('.'))
			} else {
				host == *pattern
			}
		})
	}
}

/// Why a policy could not be obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
	/// The domain publishes no MTA-STS record.
	NotFound,
	/// Discovery or fetch failed transiently.
	Temporary(String),
	/// The policy file is malformed.
	Malformed(String),
}

/// Parse `mta-sts.txt` (RFC 8461 section 3.2).
pub fn parse(text: &str) -> Result<Policy, PolicyError> {
	let mut version = None;
	let mut mode = None;
	let mut max_age = None;
	let mut mx = Vec::new();

	for line in text.lines() {
		let line = line.trim_end_matches('\r').trim();
		if line.is_empty() {
			continue;
		}
		let Some((key, value)) = line.split_once(':') else {
			return Err(PolicyError::Malformed(format!("bad line \"{line}\"")));
		};
		let value = value.trim();
		match key.trim() {
			"version" => version = Some(value.to_string()),
			"mode" => {
				mode = Some(match value {
					"enforce" => Mode::Enforce,
					"testing" => Mode::Testing,
					"none" => Mode::None,
					other => {
						return Err(PolicyError::Malformed(format!("unknown mode {other}")));
					}
				});
			}
			"max_age" => {
				max_age = Some(
					value
						.parse()
						.map_err(|_| PolicyError::Malformed("bad max_age".into()))?,
				);
			}
			"mx" => mx.push(value.to_ascii_lowercase()),
			// Unknown keys are ignored for forward compatibility.
			_ => {}
		}
	}

	if version.as_deref() != Some("STSv1") {
		return Err(PolicyError::Malformed("version must be STSv1".into()));
	}
	let mode = mode.ok_or_else(|| PolicyError::Malformed("missing mode".into()))?;
	if mode != Mode::None && mx.is_empty() {
		return Err(PolicyError::Malformed("missing mx entries".into()));
	}
	Ok(Policy {
		mode,
		mx,
		max_age: max_age.ok_or_else(|| PolicyError::Malformed("missing max_age".into()))?,
	})
}

type FetchResult = Result<String, PolicyError>;
type FetchFuture<'a> = Pin<Box<dyn Future<Output = FetchResult> + Send + 'a>>;

/// Fetches the HTTPS policy document. Abstracted for offline tests.
pub trait PolicyFetcher: Send + Sync {
	/// GET `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
	fn fetch(&self, domain: &str) -> FetchFuture<'_>;
}

/// Real fetcher over reqwest with WebPKI verification.
pub struct SystemFetcher {
	client: reqwest::Client,
}

impl SystemFetcher {
	/// Build with conservative timeouts and no redirects (RFC 8461 §3.3).
	pub fn new() -> Result<Self, PolicyError> {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(30))
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| PolicyError::Temporary(error.to_string()))?;
		Ok(SystemFetcher { client })
	}
}

impl PolicyFetcher for SystemFetcher {
	fn fetch(&self, domain: &str) -> FetchFuture<'_> {
		let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
		Box::pin(async move {
			let response = self
				.client
				.get(&url)
				.send()
				.await
				.map_err(|error| PolicyError::Temporary(error.to_string()))?;
			if !response.status().is_success() {
				return Err(PolicyError::Temporary(format!(
					"policy fetch returned {}",
					response.status()
				)));
			}
			// Policies are tiny; cap the body defensively.
			let body = response
				.text()
				.await
				.map_err(|error| PolicyError::Temporary(error.to_string()))?;
			if body.len() > 64 * 1024 {
				return Err(PolicyError::Malformed("oversized policy".into()));
			}
			Ok(body)
		})
	}
}

/// Cap on how long a policy is cached regardless of `max_age`.
const MAX_CACHE: Duration = Duration::from_secs(24 * 3600);

/// Discovery + cache: TXT presence check, HTTPS fetch, expiry by max_age.
pub struct PolicyStore {
	fetcher: Box<dyn PolicyFetcher>,
	cache: Mutex<HashMap<String, (Option<Policy>, Instant)>>,
}

impl PolicyStore {
	/// Create a store over a fetcher.
	pub fn new(fetcher: Box<dyn PolicyFetcher>) -> Self {
		PolicyStore {
			fetcher,
			cache: Mutex::new(HashMap::new()),
		}
	}

	/// The policy for a recipient domain, or `None` when the domain does
	/// not publish MTA-STS. Transient failures propagate so callers retry.
	pub async fn policy(
		&self,
		dns: &dyn DnsLookup,
		domain: &str,
	) -> Result<Option<Policy>, PolicyError> {
		let domain = domain.to_ascii_lowercase();
		if let Some((policy, expiry)) = self
			.cache
			.lock()
			.expect("mta-sts cache mutex")
			.get(&domain)
			.cloned() && Instant::now() < expiry
		{
			return Ok(policy);
		}

		// Discovery: the `_mta-sts` TXT record must exist (section 3.1).
		let records = match dns.txt(&format!("_mta-sts.{domain}")).await {
			Ok(records) => records,
			Err(DnsFailure::Temporary) => {
				return Err(PolicyError::Temporary("TXT lookup failed".into()));
			}
		};
		let advertised = records.iter().any(|record| record.starts_with("v=STSv1"));
		if !advertised {
			self.cache
				.lock()
				.expect("mta-sts cache mutex")
				.insert(domain, (None, Instant::now() + Duration::from_secs(600)));
			return Ok(None);
		}

		let body = self.fetcher.fetch(&domain).await?;
		let policy = parse(&body)?;
		let ttl = Duration::from_secs(policy.max_age).min(MAX_CACHE);
		self.cache
			.lock()
			.expect("mta-sts cache mutex")
			.insert(domain, (Some(policy.clone()), Instant::now() + ttl));
		Ok(Some(policy))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap as Map;
	use std::sync::atomic::{AtomicU32, Ordering};

	const SAMPLE: &str = "version: STSv1\nmode: enforce\nmx: mx1.example.org\nmx: *.backup.example.org\nmax_age: 86400\n";

	#[test]
	fn parses_policy_and_matches_mx() {
		let policy = parse(SAMPLE).expect("valid policy");
		assert_eq!(policy.mode, Mode::Enforce);
		assert_eq!(policy.max_age, 86400);
		assert!(policy.permits_mx("mx1.example.org"));
		assert!(policy.permits_mx("MX1.EXAMPLE.ORG"));
		assert!(policy.permits_mx("a.backup.example.org"));
		assert!(!policy.permits_mx("deep.a.backup.example.org"));
		assert!(!policy.permits_mx("backup.example.org"));
		assert!(!policy.permits_mx("evil.example"));
	}

	#[test]
	fn parses_crlf_and_ignores_unknown_keys() {
		let policy = parse(
			"version: STSv1\r\nmode: testing\r\nmx: a.example\r\nmax_age: 60\r\nfuture: x\r\n",
		)
		.expect("valid policy");
		assert_eq!(policy.mode, Mode::Testing);
	}

	#[test]
	fn rejects_malformed_policies() {
		assert!(parse("mode: enforce\nmx: a.example\nmax_age: 60").is_err());
		assert!(parse("version: STSv1\nmx: a.example\nmax_age: 60").is_err());
		assert!(parse("version: STSv1\nmode: enforce\nmax_age: 60").is_err());
		assert!(parse("version: STSv1\nmode: enforce\nmx: a.example").is_err());
		assert!(parse("version: STSv1\nmode: bogus\nmx: a.example\nmax_age: 1").is_err());
		assert!(parse("version: STSv1\nmode: enforce\nmx: a.example\nmax_age: x").is_err());
		assert!(parse("not a policy").is_err());
	}

	#[test]
	fn mode_none_needs_no_mx() {
		let policy = parse("version: STSv1\nmode: none\nmax_age: 60").expect("valid");
		assert_eq!(policy.mode, Mode::None);
	}

	struct FakeDns {
		txt: Map<String, Vec<String>>,
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
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>>
		{
			Box::pin(async { Ok(Vec::new()) })
		}

		fn mx(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	struct CountingFetcher {
		calls: std::sync::Arc<AtomicU32>,
	}

	impl PolicyFetcher for CountingFetcher {
		fn fetch(&self, _domain: &str) -> FetchFuture<'_> {
			self.calls.fetch_add(1, Ordering::Relaxed);
			Box::pin(async { Ok(SAMPLE.to_string()) })
		}
	}

	#[tokio::test]
	async fn discovery_fetch_and_cache() {
		let mut txt = Map::new();
		txt.insert(
			"_mta-sts.example.org".to_string(),
			vec!["v=STSv1; id=2026a".to_string()],
		);
		let dns = FakeDns { txt };
		let calls = std::sync::Arc::new(AtomicU32::new(0));
		let store = PolicyStore::new(Box::new(CountingFetcher {
			calls: calls.clone(),
		}));

		let policy = store
			.policy(&dns, "example.org")
			.await
			.expect("ok")
			.expect("policy");
		assert_eq!(policy.mode, Mode::Enforce);

		// Second lookup (case-insensitive) is served from the cache.
		let _ = store.policy(&dns, "EXAMPLE.org").await.expect("ok");
		assert_eq!(calls.load(Ordering::Relaxed), 1);
	}

	#[tokio::test]
	async fn no_txt_record_means_no_policy() {
		let dns = FakeDns { txt: Map::new() };
		let store = PolicyStore::new(Box::new(CountingFetcher {
			calls: std::sync::Arc::new(AtomicU32::new(0)),
		}));
		let policy = store.policy(&dns, "example.org").await.expect("ok");
		assert!(policy.is_none());
	}
}
