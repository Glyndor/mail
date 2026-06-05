//! `GET /api/v1/status`.

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::api::error::ApiError;
use crate::api::state::ApiState;

#[derive(Serialize)]
pub struct Status {
	version: &'static str,
	domains: usize,
	accounts: usize,
	queue_size: usize,
}

pub async fn get(State(state): State<ApiState>) -> Result<Json<Status>, ApiError> {
	let queue_size = state
		.spool()
		.list()
		.map_err(|_| ApiError::internal())?
		.len();
	Ok(Json(Status {
		version: env!("CARGO_PKG_VERSION"),
		domains: state.domains().len(),
		accounts: state.accounts().len(),
		queue_size,
	}))
}
