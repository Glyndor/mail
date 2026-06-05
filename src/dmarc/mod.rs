//! DMARC policy evaluation (RFC 7489) for inbound mail.

mod evaluate;
mod record;

pub use evaluate::{DmarcOutcome, evaluate, from_domain};
