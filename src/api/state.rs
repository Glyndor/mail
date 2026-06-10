//! Shared API state and bearer-token authentication.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::directory_store::AccountStore;
use crate::storage::FsSpool;

use super::error::ApiError;

/// State shared by every handler.
#[derive(Clone)]
pub struct ApiState {
	inner: Arc<Inner>,
}

struct Inner {
	/// Token hash: either `sha256:<lowercase-hex>` or a legacy argon2id PHC string.
	token_hash: String,
	data_dir: PathBuf,
	domains: Vec<String>,
	store: Arc<AccountStore>,
	spool: FsSpool,
	auth_limiter: std::sync::Mutex<AuthLimiter>,
}

/// Sliding-window failure counter. Prevents brute force on the bearer token.
struct AuthLimiter {
	failures: u32,
	window_start: std::time::Instant,
}

const AUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const AUTH_MAX_FAILURES: u32 = 20;

impl AuthLimiter {
	fn new() -> Self {
		AuthLimiter {
			failures: 0,
			window_start: std::time::Instant::now(),
		}
	}

	fn is_limited(&mut self) -> bool {
		if self.window_start.elapsed() >= AUTH_WINDOW {
			self.failures = 0;
			self.window_start = std::time::Instant::now();
		}
		self.failures >= AUTH_MAX_FAILURES
	}

	fn record_failure(&mut self) {
		if self.window_start.elapsed() >= AUTH_WINDOW {
			self.failures = 0;
			self.window_start = std::time::Instant::now();
		}
		self.failures = self.failures.saturating_add(1);
	}

	fn reset(&mut self) {
		self.failures = 0;
		self.window_start = std::time::Instant::now();
	}
}

/// What the API exposes about an account: never credentials.
#[derive(Clone, serde::Serialize)]
pub struct AccountView {
	pub name: String,
	pub addresses: Vec<String>,
	/// Whether the account is API-managed (deletable) or from the config.
	pub dynamic: bool,
}

impl ApiState {
	/// Build the state from configuration data.
	pub fn new(
		token_hash: &str,
		data_dir: PathBuf,
		domains: Vec<String>,
		store: Arc<AccountStore>,
		spool: FsSpool,
	) -> Self {
		ApiState {
			inner: Arc::new(Inner {
				token_hash: token_hash.to_string(),
				data_dir,
				domains,
				store,
				spool,
				auth_limiter: std::sync::Mutex::new(AuthLimiter::new()),
			}),
		}
	}

	pub fn domains(&self) -> &[String] {
		&self.inner.domains
	}

	pub fn accounts(&self) -> Vec<AccountView> {
		self.inner
			.store
			.account_views()
			.into_iter()
			.map(|(name, addresses, dynamic)| AccountView {
				name,
				addresses,
				dynamic,
			})
			.collect()
	}

	pub fn store(&self) -> &AccountStore {
		&self.inner.store
	}

	pub fn spool(&self) -> &FsSpool {
		&self.inner.spool
	}

	pub fn data_dir(&self) -> &std::path::Path {
		&self.inner.data_dir
	}

	fn token_matches(&self, token: &str) -> bool {
		let stored = &self.inner.token_hash;
		if let Some(expected_hex) = stored.strip_prefix("sha256:") {
			// O(1) SHA-256: correct threat model for a bearer token.
			// Comparing hex-encoded digests: timing leaks here cannot reveal
			// the preimage (SHA-256 is pre-image resistant).
			let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
			let actual_hex = digest
				.as_ref()
				.iter()
				.fold(String::with_capacity(64), |mut s, b| {
					use std::fmt::Write;
					write!(s, "{b:02x}").ok();
					s
				});
			expected_hex == actual_hex
		} else {
			// Backward compat: argon2id PHC (legacy; generate new hash with `mail token-hash`).
			crate::smtp::auth::verify_password(stored, token)
		}
	}
}

/// Middleware: every request must carry the bearer token.
pub async fn require_bearer_token(
	State(state): State<ApiState>,
	request: Request,
	next: Next,
) -> Result<Response, ApiError> {
	// Reject before any token work when failure budget is exhausted.
	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if limiter.is_limited() {
			return Err(ApiError::rate_limited());
		}
	}

	let token = request
		.headers()
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "));

	let authorized = token.is_some_and(|t| state.token_matches(t));

	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if authorized {
			limiter.reset();
		} else {
			limiter.record_failure();
		}
	}

	if !authorized {
		return Err(ApiError::unauthenticated());
	}
	Ok(next.run(request).await)
}
