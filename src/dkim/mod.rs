//! DKIM signing and verification (RFC 6376).

mod canon;
mod sign;
mod signature;
mod verify;

pub use sign::{Signer, SignerError, generate_key};
pub use verify::{DkimOutcome, DkimResult, verify_message};
