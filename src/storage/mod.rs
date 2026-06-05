//! Message storage.
//!
//! Messages are stored as individual RFC 5322 files plus a JSON envelope
//! sidecar, written crash-safely (write to a temporary file, fsync, rename).
//! An embedded index and the account/mailbox model build on top of this
//! spool; PostgreSQL stays an option for deployments that need it, but the
//! default install must work with zero external services.

mod delivery;
mod spool;

pub use delivery::LocalDelivery;
pub use spool::{Envelope, FsSpool, SpoolEntry};
