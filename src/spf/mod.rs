//! SPF evaluation (RFC 7208) for inbound mail.

mod dns;
mod evaluator;
mod record;

pub use dns::{DnsFailure, DnsLookup, SystemDns};
pub use evaluator::{SpfOutcome, check_host};
