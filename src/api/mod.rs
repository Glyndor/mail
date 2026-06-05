//! Management HTTP API (`/api/v1`).
//!
//! Read-only views plus queue management, consumed by the CLI and by
//! mail-panel. Every endpoint requires the bearer token; the listener
//! binds to localhost unless explicitly configured otherwise.

mod error;
mod state;
pub mod v1;

pub use state::ApiState;

use axum::Router;
use axum::middleware;

/// Build the API router with authentication applied to every route.
pub fn router(state: ApiState) -> Router {
	Router::new()
		.nest("/api/v1", v1::router())
		.layer(middleware::from_fn_with_state(
			state.clone(),
			state::require_bearer_token,
		))
		.with_state(state)
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::body::Body;
	use axum::http::{Request, StatusCode, header};
	use tower::ServiceExt;

	use crate::smtp::session::AcceptedMessage;
	use crate::storage::FsSpool;

	const TOKEN: &str = "test-token";

	fn test_state(dir: &std::path::Path, queued: usize) -> ApiState {
		let spool = FsSpool::open(dir).expect("open spool");
		for i in 0..queued {
			spool
				.store(&AcceptedMessage {
					reverse_path: format!("a{i}@example.org"),
					recipients: vec![format!("r{i}@elsewhere.example")],
					data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
				})
				.expect("store");
		}
		let accounts = vec![crate::config::Account {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: Some("$argon2id$secret".to_string()),
		}];
		ApiState::new(
			&crate::smtp::auth::tests::hash(TOKEN),
			vec!["example.org".to_string()],
			&accounts,
			spool,
		)
	}

	async fn request(
		app: &Router,
		method: &str,
		path: &str,
		token: Option<&str>,
	) -> (StatusCode, serde_json::Value) {
		let mut builder = Request::builder().method(method).uri(path);
		if let Some(token) = token {
			builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
		}
		let response = app
			.clone()
			.oneshot(builder.body(Body::empty()).expect("request"))
			.await
			.expect("response");
		let status = response.status();
		let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.expect("body");
		let json = if bytes.is_empty() {
			serde_json::Value::Null
		} else {
			serde_json::from_slice(&bytes).expect("json body")
		};
		(status, json)
	}

	#[tokio::test]
	async fn requests_without_token_are_rejected() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		let (status, body) = request(&app, "GET", "/api/v1/status", None).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED);
		assert_eq!(body["error"]["code"], "unauthenticated");

		let (status, _) = request(&app, "GET", "/api/v1/status", Some("wrong")).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED);
	}

	#[tokio::test]
	async fn status_reports_counts() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 2));
		let (status, body) = request(&app, "GET", "/api/v1/status", Some(TOKEN)).await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(body["domains"], 1);
		assert_eq!(body["accounts"], 1);
		assert_eq!(body["queue_size"], 2);
	}

	#[tokio::test]
	async fn accounts_never_expose_credentials() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		let (status, body) = request(&app, "GET", "/api/v1/accounts", Some(TOKEN)).await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(body["accounts"][0]["name"], "alice");
		assert!(!body.to_string().contains("argon2"), "{body}");
	}

	#[tokio::test]
	async fn domains_are_listed() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		let (status, body) = request(&app, "GET", "/api/v1/domains", Some(TOKEN)).await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(body["domains"][0], "example.org");
	}

	#[tokio::test]
	async fn queue_pagination_walks_all_entries() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 5));

		let (status, page) = request(&app, "GET", "/api/v1/queue?limit=2", Some(TOKEN)).await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(page["entries"].as_array().expect("entries").len(), 2);
		let cursor = page["next_cursor"].as_str().expect("cursor").to_string();

		let (_, page2) = request(
			&app,
			"GET",
			&format!("/api/v1/queue?limit=2&cursor={cursor}"),
			Some(TOKEN),
		)
		.await;
		assert_eq!(page2["entries"].as_array().expect("entries").len(), 2);
		// No overlap between pages.
		assert_ne!(page["entries"][0]["id"], page2["entries"][0]["id"]);

		let cursor2 = page2["next_cursor"].as_str().expect("cursor").to_string();
		let (_, page3) = request(
			&app,
			"GET",
			&format!("/api/v1/queue?limit=2&cursor={cursor2}"),
			Some(TOKEN),
		)
		.await;
		assert_eq!(page3["entries"].as_array().expect("entries").len(), 1);
		assert!(page3["next_cursor"].is_null());
	}

	#[tokio::test]
	async fn queue_rejects_zero_limit() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		let (status, body) = request(&app, "GET", "/api/v1/queue?limit=0", Some(TOKEN)).await;
		assert_eq!(status, StatusCode::BAD_REQUEST);
		assert_eq!(body["error"]["code"], "invalid_input");
	}

	#[tokio::test]
	async fn queue_entry_can_be_removed_once() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 1));
		let (_, page) = request(&app, "GET", "/api/v1/queue", Some(TOKEN)).await;
		let id = page["entries"][0]["id"].as_str().expect("id").to_string();

		let (status, body) =
			request(&app, "DELETE", &format!("/api/v1/queue/{id}"), Some(TOKEN)).await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(body["removed"], id.as_str());

		let (status, body) =
			request(&app, "DELETE", &format!("/api/v1/queue/{id}"), Some(TOKEN)).await;
		assert_eq!(status, StatusCode::NOT_FOUND);
		assert_eq!(body["error"]["code"], "not_found");
	}

	#[tokio::test]
	async fn unknown_route_is_404() {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		let (status, _) = request(&app, "GET", "/api/v1/nope", Some(TOKEN)).await;
		assert_eq!(status, StatusCode::NOT_FOUND);
	}
}
