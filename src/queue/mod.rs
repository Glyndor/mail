//! Outbound delivery queue: takes spooled relay mail to remote servers.

pub mod client;
mod resolver;
mod worker;

pub use resolver::{Connector, MxConnector};
pub use worker::Worker;
