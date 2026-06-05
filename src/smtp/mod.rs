//! SMTP protocol implementation (RFC 5321).
//!
//! `command` parses client commands, `reply` renders server replies, and
//! `session` drives the per-connection state machine.

pub mod address;
pub mod command;
pub mod line;
pub mod reply;
pub mod server;
pub mod session;
pub mod sink;
