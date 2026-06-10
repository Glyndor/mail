//! The API error shape: `{"error": {"code", "message"}}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// An API error with a machine-readable code.
#[derive(Debug)]
pub struct ApiError {
	pub status: StatusCode,
	pub code: &'static str,
	pub message: String,
}

impl ApiError {
	pub fn unauthenticated() -> Self {
		ApiError {
			status: StatusCode::UNAUTHORIZED,
			code: "unauthenticated",
			message: "A valid bearer token is required.".to_string(),
		}
	}

	pub fn not_found(message: &str) -> Self {
		ApiError {
			status: StatusCode::NOT_FOUND,
			code: "not_found",
			message: message.to_string(),
		}
	}

	pub fn invalid_input(message: &str) -> Self {
		ApiError {
			status: StatusCode::BAD_REQUEST,
			code: "invalid_input",
			message: message.to_string(),
		}
	}

	pub fn internal() -> Self {
		ApiError {
			status: StatusCode::INTERNAL_SERVER_ERROR,
			code: "internal",
			message: "Internal error.".to_string(),
		}
	}

	pub fn rate_limited() -> Self {
		ApiError {
			status: StatusCode::TOO_MANY_REQUESTS,
			code: "rate_limited",
			message: "Too many failed authentication attempts. Try again later.".to_string(),
		}
	}
}

#[derive(Serialize)]
struct ErrorBody {
	error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
	code: &'static str,
	message: String,
}

impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let body = ErrorBody {
			error: ErrorDetail {
				code: self.code,
				message: self.message,
			},
		};
		(self.status, Json(body)).into_response()
	}
}
