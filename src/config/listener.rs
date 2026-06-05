//! Listener definitions: which services bind where.

use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

use super::Config;

/// The service a listener exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerKind {
	/// Inbound mail from other servers (port 25).
	Smtp,
	/// Authenticated client submission with STARTTLS (port 587).
	Submission,
	/// Authenticated client submission over implicit TLS (port 465).
	Submissions,
	/// Management HTTP API.
	Api,
	/// IMAP over implicit TLS (port 993).
	Imaps,
	/// IMAP with mandatory STARTTLS upgrade (port 143).
	Imap,
}

impl ListenerKind {
	/// The IANA default port for this service.
	pub const fn default_port(self) -> u16 {
		match self {
			ListenerKind::Smtp => 25,
			ListenerKind::Submission => 587,
			ListenerKind::Submissions => 465,
			ListenerKind::Api => 8025,
			ListenerKind::Imaps => 993,
			ListenerKind::Imap => 143,
		}
	}
}

/// A single network listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
	/// Service exposed on this listener.
	pub kind: ListenerKind,
	/// Bind address. Defaults to loopback: external exposure is opt-in.
	#[serde(default = "Config::default_bind_addr")]
	pub addr: IpAddr,
	/// Bind port. Defaults to the service's IANA port.
	pub port: Option<u16>,
}

impl Listener {
	/// The socket address this listener binds to.
	pub fn socket_addr(&self) -> SocketAddr {
		SocketAddr::new(self.addr, self.port.unwrap_or(self.kind.default_port()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_ports_match_iana() {
		assert_eq!(ListenerKind::Smtp.default_port(), 25);
		assert_eq!(ListenerKind::Submission.default_port(), 587);
		assert_eq!(ListenerKind::Submissions.default_port(), 465);
	}

	#[test]
	fn listener_defaults_to_loopback_and_service_port() {
		let listener: Listener = toml::from_str(r#"kind = "smtp""#).expect("parse listener");
		let addr = listener.socket_addr();
		assert!(addr.ip().is_loopback());
		assert_eq!(addr.port(), 25);
	}

	#[test]
	fn listener_accepts_explicit_addr_and_port() {
		let listener: Listener = toml::from_str(
			r#"
kind = "submissions"
addr = "0.0.0.0"
port = 2465
"#,
		)
		.expect("parse listener");
		let addr = listener.socket_addr();
		assert!(!addr.ip().is_loopback());
		assert_eq!(addr.port(), 2465);
	}

	#[test]
	fn listener_rejects_unknown_keys() {
		let result: Result<Listener, _> = toml::from_str(
			r#"
kind = "smtp"
oops = 1
"#,
		);
		assert!(result.is_err());
	}
}
