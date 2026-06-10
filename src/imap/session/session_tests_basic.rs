use super::*;

#[test]
fn greeting_announces_capabilities() {
	let dir = tempfile::tempdir().expect("tempdir");
	let session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let greeting = text(&session.greeting());
	assert!(greeting.contains("IMAP4rev2"), "{greeting}");
	assert!(greeting.contains("IDLE"), "{greeting}");
	assert!(greeting.contains("LITERAL+"), "{greeting}");
}

#[test]
fn login_with_wrong_password_fails_and_third_failure_closes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	for round in 0..2 {
		let output = session.command_line(&format!("a{round} LOGIN alice wrong"));
		assert!(text(&output).contains("NO LOGIN failed"));
		assert!(!output.close);
	}
	let output = session.command_line("a3 LOGIN alice wrong");
	assert!(output.close);
	assert!(text(&output).contains("BYE"));
}

#[test]
fn unauthenticated_select_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 SELECT INBOX");
	assert!(text(&output).contains("a1 NO"));
}

#[test]
fn list_shows_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line(r#"a2 LIST "" "*""#);
	assert!(text(&output).contains("* LIST () \"/\" \"INBOX\""));
	assert!(text(&output).contains("a2 OK"));
}

#[test]
fn select_reports_exists_and_uidvalidity() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\nhi\r\n");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 SELECT INBOX");
	let response = text(&output);
	assert!(response.contains("* 1 EXISTS"), "{response}");
	assert!(response.contains("UIDVALIDITY"), "{response}");
	assert!(
		response.contains("a2 OK [READ-WRITE] SELECT completed"),
		"{response}"
	);
}

#[test]
fn fetch_returns_flags_size_and_body() {
	let dir = tempfile::tempdir().expect("tempdir");
	let body = b"From: a@example.org\r\nSubject: hi\r\n\r\nhello\r\n";
	deliver(dir.path(), body);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let output = session.command_line("a3 FETCH 1 (FLAGS RFC822.SIZE UID BODY[])");
	let response = text(&output);
	assert!(response.contains("* 1 FETCH (FLAGS ()"), "{response}");
	assert!(
		response.contains(&format!("RFC822.SIZE {}", body.len())),
		"{response}"
	);
	assert!(response.contains("UID 1"), "{response}");
	assert!(
		response.contains(&format!("BODY[] {{{}}}", body.len())),
		"{response}"
	);
	assert!(response.contains("Subject: hi"), "{response}");
	assert!(response.contains("a3 OK FETCH completed"), "{response}");
}

#[test]
fn uid_fetch_filters_by_uid() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"first\r\n");
	deliver(dir.path(), b"second\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let output = session.command_line("a3 UID FETCH 2 (FLAGS)");
	let response = text(&output);
	assert!(response.contains("* 2 FETCH"), "{response}");
	assert!(!response.contains("* 1 FETCH"), "{response}");
	assert!(response.contains("UID 2"), "{response}");
}

#[test]
fn fetch_without_selected_mailbox_is_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 FETCH 1 (FLAGS)");
	assert!(text(&output).contains("a2 BAD"));
}

#[test]
fn close_returns_to_authenticated() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let output = session.command_line("a3 CLOSE");
	assert!(text(&output).contains("a3 OK"));
	let output = session.command_line("a4 FETCH 1 (FLAGS)");
	assert!(text(&output).contains("a4 BAD"));
}

#[test]
fn store_and_expunge_flow() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	let output = session.command_line(r"a3 STORE 1 +FLAGS (\Seen \Deleted)");
	let response = text(&output);
	assert!(
		response.contains(r"* 1 FETCH (FLAGS (\Seen \Deleted))"),
		"{response}"
	);
	assert!(response.contains("a3 OK"), "{response}");

	let output = session.command_line(r"a4 STORE 1 -FLAGS (\Seen)");
	assert!(text(&output).contains(r"* 1 FETCH (FLAGS (\Deleted))"));

	let output = session.command_line("a5 EXPUNGE");
	let response = text(&output);
	assert!(response.contains("* 1 EXPUNGE"), "{response}");
	assert!(response.contains("a5 OK"), "{response}");

	// Remaining message renumbered to sequence 1.
	let output = session.command_line("a6 FETCH 1 (BODY[])");
	assert!(text(&output).contains("two"), "{}", text(&output));
}

#[test]
fn silent_store_suppresses_untagged_response() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let output = session.command_line(r"a3 STORE 1 +FLAGS.SILENT (\Seen)");
	let response = text(&output);
	assert!(!response.contains("FETCH"), "{response}");
	assert!(response.contains("a3 OK"), "{response}");
}

#[test]
fn uid_store_reports_uid() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let output = session.command_line(r"a3 UID STORE 2 +FLAGS (\Flagged)");
	let response = text(&output);
	assert!(
		response.contains(r"* 2 FETCH (UID 2 FLAGS (\Flagged))"),
		"{response}"
	);
}

#[test]
fn examine_refuses_store_and_expunge() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 EXAMINE INBOX");
	let output = session.command_line(r"a3 STORE 1 +FLAGS (\Seen)");
	assert!(text(&output).contains("a3 NO"), "{}", text(&output));
	let output = session.command_line("a4 EXPUNGE");
	assert!(text(&output).contains("a4 NO"), "{}", text(&output));
}

#[test]
fn store_rejects_unsupported_flag() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let output = session.command_line(r"a3 STORE 1 +FLAGS (\Recent)");
	assert!(text(&output).contains("a3 BAD"), "{}", text(&output));
}
