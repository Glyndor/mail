//! TLS-RPT (RFC 8460) reporting for transport security.

mod record;

pub use record::{Record, parse};
