//! DKIM verification (RFC 6376) for inbound mail.

mod canon;
mod signature;
mod verify;

pub use verify::{DkimOutcome, DkimResult, verify_message};
