//! `/api/v1` routes. Each route module mirrors its path.

mod accounts;
mod domains;
mod mailboxes;
mod queue;
mod status;

use axum::Router;
use axum::routing::get;

use super::state::ApiState;

/// The v1 route tree.
pub fn router() -> Router<ApiState> {
	Router::new()
		.route("/status", get(status::get))
		.route("/domains", get(domains::list))
		.route("/accounts", get(accounts::list).post(accounts::create))
		.route("/accounts/{name}", axum::routing::delete(accounts::remove))
		.route(
			"/accounts/{name}/password",
			axum::routing::put(accounts::set_password),
		)
		.route("/accounts/{name}/mailboxes", get(mailboxes::list))
		.route("/queue", get(queue::list))
		.route("/queue/{id}", axum::routing::delete(queue::remove))
}
