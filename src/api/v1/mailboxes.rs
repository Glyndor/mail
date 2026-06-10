//! `/api/v1/accounts/{name}/mailboxes`: list mailboxes for an account.

use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::imap::mailbox;

#[derive(Serialize)]
pub struct Mailboxes {
	mailboxes: Vec<String>,
}

pub async fn list(
	State(state): State<ApiState>,
	Path(name): Path<String>,
) -> Result<Json<Mailboxes>, ApiError> {
	let known = state
		.store()
		.account_views()
		.into_iter()
		.any(|(n, _, _)| n == name);
	if !known {
		return Err(ApiError::not_found("no such account"));
	}
	let mailboxes = mailbox::list(state.data_dir(), &name);
	Ok(Json(Mailboxes { mailboxes }))
}
