//! `GET /api/v1/queue` and `DELETE /api/v1/queue/{id}`.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::ApiState;

/// Hard ceiling on page size: list endpoints are never unbounded.
const MAX_LIMIT: usize = 100;

#[derive(Deserialize)]
pub struct ListParams {
	limit: Option<usize>,
	cursor: Option<Uuid>,
}

#[derive(Serialize)]
pub struct QueueEntry {
	id: Uuid,
	reverse_path: String,
	recipients: Vec<String>,
}

#[derive(Serialize)]
pub struct QueuePage {
	entries: Vec<QueueEntry>,
	/// Pass as `cursor` to fetch the next page; absent on the last page.
	#[serde(skip_serializing_if = "Option::is_none")]
	next_cursor: Option<Uuid>,
}

pub async fn list(
	State(state): State<ApiState>,
	Query(params): Query<ListParams>,
) -> Result<Json<QueuePage>, ApiError> {
	let limit = params.limit.unwrap_or(50).min(MAX_LIMIT);
	if limit == 0 {
		return Err(ApiError::invalid_input("limit must be at least 1"));
	}

	let ids = state.spool().list().map_err(|_| ApiError::internal())?;
	let start = match params.cursor {
		// UUID v7 ids sort chronologically: resume strictly after cursor.
		Some(cursor) => ids.partition_point(|id| *id <= cursor),
		None => 0,
	};
	let page: Vec<Uuid> = ids.iter().skip(start).take(limit).copied().collect();
	let next_cursor = if start + page.len() < ids.len() {
		page.last().copied()
	} else {
		None
	};

	let mut entries = Vec::with_capacity(page.len());
	for id in page {
		// An entry can vanish between list and load (worker delivered it).
		if let Ok(entry) = state.spool().load(id) {
			entries.push(QueueEntry {
				id,
				reverse_path: entry.envelope.reverse_path,
				recipients: entry.envelope.recipients,
			});
		}
	}
	Ok(Json(QueuePage {
		entries,
		next_cursor,
	}))
}

#[derive(Serialize)]
pub struct Removed {
	removed: Uuid,
}

pub async fn remove(
	State(state): State<ApiState>,
	Path(id): Path<Uuid>,
) -> Result<Json<Removed>, ApiError> {
	if state.spool().load(id).is_err() {
		return Err(ApiError::not_found("no such queue entry"));
	}
	state.spool().remove(id).map_err(|_| ApiError::internal())?;
	Ok(Json(Removed { removed: id }))
}
