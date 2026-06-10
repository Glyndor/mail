use super::*;

fn test_directory() -> Arc<Directory> {
	let mut entries: Vec<(String, String)> = vec![
		("b@example.org".to_string(), "bob".to_string()),
		("bob@example.org".to_string(), "bob".to_string()),
		("c@example.org".to_string(), "bob".to_string()),
		("overflow@example.org".to_string(), "bob".to_string()),
	];
	for i in 0..=MAX_RECIPIENTS {
		entries.push((format!("r{i}@example.org"), "bob".to_string()));
	}
	Arc::new(Directory::new(["example.org".to_string()], entries))
}

pub(super) fn greeted() -> Session {
	let mut session = Session::new("mail.example.org").with_directory(test_directory());
	session.command_line("EHLO client.example.org");
	session
}

pub(super) fn reply_code(action: &Action) -> u16 {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r) => r.code(),
		Action::Deliver(r, _) => r.code(),
	}
}

#[test]
fn greeting_announces_hostname() {
	let session = Session::new("mail.example.org");
	assert_eq!(
		session.greeting().to_string(),
		"220 mail.example.org ESMTP ready\r\n"
	);
}

#[test]
fn full_transaction_delivers_message() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
		250
	);
	let action = session.command_line("DATA");
	assert!(matches!(action, Action::CollectData(_)));

	assert_eq!(session.data_line(b"Subject: hi"), None);
	assert_eq!(session.data_line(b""), None);
	assert_eq!(session.data_line(b"hello"), None);
	let Some(Action::Deliver(reply, message)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert_eq!(reply.code(), 250);
	assert_eq!(message.reverse_path, "alice@example.org");
	assert_eq!(message.recipients, vec!["bob@example.org".to_string()]);
	assert_eq!(message.data, b"Subject: hi\r\n\r\nhello\r\n");
}

#[test]
fn dot_stuffed_lines_are_unstuffed() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	assert_eq!(session.data_line(b"..leading dot"), None);
	let Some(Action::Deliver(_, message)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert_eq!(message.data, b".leading dot\r\n");
}

#[test]
fn mail_before_greeting_is_rejected() {
	let mut session = Session::new("mail.example.org");
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		503
	);
}

#[test]
fn rcpt_without_mail_is_rejected() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@example.org>")),
		503
	);
}

#[test]
fn data_without_recipients_is_rejected() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("DATA")), 503);
}

#[test]
fn empty_recipient_is_rejected() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("RCPT TO:<>")), 553);
}

#[test]
fn malformed_recipient_is_rejected() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<no-at-sign>")),
		553
	);
}

#[test]
fn non_local_recipient_is_denied() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	let action = session.command_line("RCPT TO:<b@elsewhere.example>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
fn recipient_domain_match_is_case_insensitive() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@EXAMPLE.ORG>")),
		250
	);
}

#[test]
fn unknown_user_in_local_domain_is_denied() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	let action = session.command_line("RCPT TO:<stranger@example.org>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
fn without_local_domains_every_recipient_is_denied() {
	let mut session = Session::new("mail.example.org");
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@example.org>")),
		550
	);
}

#[test]
fn malformed_reverse_path_is_rejected() {
	let mut session = greeted();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<not-an-address>")),
		553
	);
	// Null reverse-path stays legal for bounces.
	assert_eq!(reply_code(&session.command_line("MAIL FROM:<>")), 250);
}

#[test]
fn recipient_limit_is_enforced() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	for i in 0..MAX_RECIPIENTS {
		let action = session.command_line(&format!("RCPT TO:<r{i}@example.org>"));
		assert_eq!(reply_code(&action), 250, "recipient {i} accepted");
	}
	let action = session.command_line("RCPT TO:<overflow@example.org>");
	assert_eq!(reply_code(&action), 452);
}

#[test]
fn rset_aborts_transaction() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("RSET")), 250);
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<c@example.org>")),
		250
	);
}

#[test]
fn declared_size_within_limit_is_accepted() {
	let mut session = greeted();
	let action = session.command_line(&format!(
		"MAIL FROM:<a@example.org> SIZE={} BODY=8BITMIME",
		MAX_MESSAGE_SIZE
	));
	assert_eq!(reply_code(&action), 250);
}

#[test]
fn declared_oversize_is_rejected_at_mail_time() {
	let mut session = greeted();
	let action = session.command_line(&format!(
		"MAIL FROM:<a@example.org> SIZE={}",
		MAX_MESSAGE_SIZE as u64 + 1
	));
	assert_eq!(reply_code(&action), 552);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@example.org>")),
		503
	);
}

#[test]
fn unsupported_parameter_gets_555() {
	let mut session = greeted();
	let action = session.command_line("MAIL FROM:<a@example.org> AUTH=<>");
	assert_eq!(reply_code(&action), 555);
}

#[test]
fn quit_closes_connection() {
	let mut session = greeted();
	let action = session.command_line("QUIT");
	assert!(matches!(action, Action::Close(_)));
	assert_eq!(reply_code(&action), 221);
}

#[test]
fn vrfy_discloses_nothing() {
	let mut session = greeted();
	assert_eq!(reply_code(&session.command_line("VRFY alice")), 252);
}

#[test]
fn unknown_command_gets_500() {
	let mut session = greeted();
	assert_eq!(reply_code(&session.command_line("EXPN staff")), 500);
}

#[test]
fn oversize_message_is_rejected_and_not_delivered() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	let chunk = "x".repeat(1024);
	let lines_needed = MAX_MESSAGE_SIZE / chunk.len() + 1;
	for _ in 0..lines_needed {
		assert_eq!(session.data_line(chunk.as_bytes()), None);
	}
	let Some(action) = session.data_line(b".") else {
		panic!("expected final action");
	};
	assert_eq!(reply_code(&action), 552);
	assert!(matches!(action, Action::Continue(_)));
}

#[test]
fn data_line_outside_data_state_fails_closed() {
	let mut session = greeted();
	let action = session.data_line(b"stray");
	assert_eq!(action.map(|a| reply_code(&a)), Some(503));
}

#[test]
fn second_transaction_works_after_delivery() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	session.data_line(b"first");
	assert!(matches!(session.data_line(b"."), Some(Action::Deliver(..))));

	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<c@example.org>")),
		250
	);
}
