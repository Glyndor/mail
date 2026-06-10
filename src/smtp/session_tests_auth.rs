use super::*;

fn reply_code(action: &Action) -> u16 {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r) => r.code(),
		Action::Deliver(r, _) => r.code(),
	}
}

fn auth_directory() -> Arc<Directory> {
	Arc::new(
		Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("secret"),
		)]),
	)
}

fn plain(authcid: &str, password: &str) -> String {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD.encode(format!("\0{authcid}\0{password}"))
}

fn tls_session() -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_tls_active();
	session.command_line("EHLO client.example.org");
	session
}

fn authenticated_session() -> Session {
	let mut session = tls_session();
	session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(session.authenticated(), Some("alice"));
	session
}

// Unauthenticated session with no TLS — used for relay/sender tests.
fn greeted_plain() -> Session {
	let mut session = Session::new("mail.example.org").with_directory(auth_directory());
	session.command_line("EHLO client.example.org");
	session
}

#[test]
fn auth_rejected_outside_tls() {
	let mut session = greeted_plain();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 538);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn ehlo_advertises_auth_only_inside_tls() {
	let mut plain_session = greeted_plain();
	let Action::Continue(reply) = plain_session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("AUTH PLAIN"));

	let mut tls = tls_session();
	let Action::Continue(reply) = tls.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(reply.to_string().contains("AUTH PLAIN"), "{reply}");
}

#[test]
fn auth_with_initial_response_succeeds() {
	let mut session = tls_session();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 235);
	assert_eq!(session.authenticated(), Some("alice"));
}

#[test]
fn auth_by_address_succeeds() {
	let mut session = tls_session();
	let action = session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice@example.org", "secret")
	));
	assert_eq!(reply_code(&action), 235);
}

#[test]
fn auth_challenge_flow_succeeds() {
	let mut session = tls_session();
	let action = session.command_line("AUTH PLAIN");
	assert!(matches!(action, Action::CollectAuthResponse(_)));
	assert_eq!(reply_code(&action), 334);
	let action = session.auth_line(&plain("alice", "secret"));
	assert_eq!(reply_code(&action), 235);
}

#[test]
fn auth_challenge_can_be_cancelled() {
	let mut session = tls_session();
	session.command_line("AUTH PLAIN");
	let action = session.auth_line("*");
	assert_eq!(reply_code(&action), 501);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn wrong_password_gets_535_without_detail() {
	let mut session = tls_session();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
	assert_eq!(reply_code(&action), 535);
	assert_eq!(session.authenticated(), None);
}

#[test]
fn unknown_user_gets_same_reply_as_wrong_password() {
	let mut session = tls_session();
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("mallory", "secret")));
	assert_eq!(reply_code(&action), 535);
}

#[test]
fn third_failure_closes_connection() {
	let mut session = tls_session();
	for _ in 0..2 {
		let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
		assert!(matches!(action, Action::Continue(_)));
	}
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "wrong")));
	assert!(matches!(action, Action::Close(_)));
}

#[test]
fn auth_after_success_is_bad_sequence() {
	let mut session = tls_session();
	session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 503);
}

#[test]
fn unsupported_mechanism_gets_504() {
	let mut session = tls_session();
	assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 504);
}

#[test]
fn auth_inside_transaction_is_bad_sequence() {
	let mut session = tls_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line(&format!("AUTH PLAIN {}", plain("alice", "secret")));
	assert_eq!(reply_code(&action), 503);
}

#[test]
fn authenticated_user_may_relay_to_foreign_domains() {
	let mut session = authenticated_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line("RCPT TO:<bob@elsewhere.example>");
	assert_eq!(reply_code(&action), 250);
}

#[test]
fn unauthenticated_relay_stays_denied() {
	let mut session = tls_session();
	session.command_line("MAIL FROM:<someone@elsewhere.example>");
	let action = session.command_line("RCPT TO:<bob@elsewhere.example>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
fn authenticated_sender_must_own_the_address() {
	let mut session = authenticated_session();
	let action = session.command_line("MAIL FROM:<other@elsewhere.example>");
	assert_eq!(reply_code(&action), 553);
}

#[test]
fn authenticated_sender_cannot_use_null_path() {
	let mut session = authenticated_session();
	let action = session.command_line("MAIL FROM:<>");
	assert_eq!(reply_code(&action), 553);
}

#[test]
fn authenticated_relay_still_rejects_unknown_local_users() {
	let mut session = authenticated_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line("RCPT TO:<stranger@example.org>");
	assert_eq!(reply_code(&action), 550);
}

// TLS / STARTTLS tests

#[test]
fn starttls_without_tls_configured_is_unavailable() {
	let mut session = greeted_plain();
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
}

#[test]
fn ehlo_advertises_starttls_when_available() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(reply.to_string().contains("250 STARTTLS\r\n"));
}

#[test]
fn ehlo_does_not_advertise_starttls_when_unavailable() {
	let mut session = greeted_plain();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("STARTTLS"));
}

#[test]
fn starttls_upgrades_after_greeting() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	let action = session.command_line("STARTTLS");
	assert!(matches!(action, Action::UpgradeTls(_)));
	assert_eq!(reply_code(&action), 220);
}

#[test]
fn starttls_before_greeting_is_bad_sequence() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
}

#[test]
fn starttls_inside_transaction_is_bad_sequence() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
}

#[test]
fn tls_started_resets_session() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	session.tls_started();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		503
	);
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("STARTTLS"));
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
}
