//! Shared API state and bearer-token authentication.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::config::Account;
use crate::storage::FsSpool;

use super::error::ApiError;

/// State shared by every handler.
#[derive(Clone)]
pub struct ApiState {
	inner: Arc<Inner>,
}

struct Inner {
	/// argon2id PHC hash of the API token.
	token_hash: String,
	domains: Vec<String>,
	accounts: Vec<AccountView>,
	spool: FsSpool,
}

/// What the API exposes about an account: never credentials.
#[derive(Clone, serde::Serialize)]
pub struct AccountView {
	pub name: String,
	pub addresses: Vec<String>,
}

impl ApiState {
	/// Build the state from configuration data.
	pub fn new(
		token_hash: &str,
		domains: Vec<String>,
		accounts: &[Account],
		spool: FsSpool,
	) -> Self {
		ApiState {
			inner: Arc::new(Inner {
				token_hash: token_hash.to_string(),
				domains,
				accounts: accounts
					.iter()
					.map(|account| AccountView {
						name: account.name.clone(),
						addresses: account.addresses.clone(),
					})
					.collect(),
				spool,
			}),
		}
	}

	pub fn domains(&self) -> &[String] {
		&self.inner.domains
	}

	pub fn accounts(&self) -> &[AccountView] {
		&self.inner.accounts
	}

	pub fn spool(&self) -> &FsSpool {
		&self.inner.spool
	}

	fn token_matches(&self, token: &str) -> bool {
		crate::smtp::auth::verify_password(&self.inner.token_hash, token)
	}
}

/// Middleware: every request must carry the bearer token.
pub async fn require_bearer_token(
	State(state): State<ApiState>,
	request: Request,
	next: Next,
) -> Result<Response, ApiError> {
	let authorized = request
		.headers()
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "))
		.is_some_and(|token| state.token_matches(token));
	if !authorized {
		return Err(ApiError::unauthenticated());
	}
	Ok(next.run(request).await)
}
