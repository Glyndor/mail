//! `GET /api/v1/domains`.

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::api::state::ApiState;

#[derive(Serialize)]
pub struct Domains {
	domains: Vec<String>,
}

pub async fn list(State(state): State<ApiState>) -> Json<Domains> {
	Json(Domains {
		domains: state.domains().to_vec(),
	})
}
