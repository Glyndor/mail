//! `GET /api/v1/accounts`.

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::api::state::{AccountView, ApiState};

#[derive(Serialize)]
pub struct Accounts {
	accounts: Vec<AccountView>,
}

pub async fn list(State(state): State<ApiState>) -> Json<Accounts> {
	Json(Accounts {
		accounts: state.accounts().to_vec(),
	})
}
