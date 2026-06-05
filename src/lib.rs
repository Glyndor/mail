//! Glyndor mail server library.
//!
//! Headless mail server: SMTP, IMAP and modern email security, exposed
//! through an API and a CLI. This crate hosts all server logic; the binary
//! in `main.rs` is a thin entry point.

pub mod cli;
pub mod clock;
pub mod config;
pub mod dkim;
pub mod queue;
pub mod smtp;
pub mod spf;
pub mod storage;
pub mod tls;
