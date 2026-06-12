//! TLS-RPT (RFC 8460) reporting for transport security.

mod record;
pub mod report;

pub use record::{Record, parse};
