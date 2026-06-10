use super::*;

#[test]
fn append_stores_message_with_flags() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());

	let output = session.command_line(r"a2 APPEND INBOX (\Seen) {14}");
	assert_eq!(output.collect_literal, Some(14));
	assert!(text(&output).starts_with("+ "), "{}", text(&output));

	let output = session.literal_done(b"Subject: bye\r\n");
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));

	// The appended message is visible on SELECT, with its flag.
	let output = session.command_line("a3 SELECT INBOX");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	let output = session.command_line("a4 FETCH 1 (FLAGS BODY[])");
	let response = text(&output);
	assert!(response.contains(r"FLAGS (\Seen)"), "{response}");
	assert!(response.contains("Subject: bye"), "{response}");
}

#[test]
fn append_requires_authentication_and_known_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 APPEND INBOX {5}");
	assert!(text(&output).contains("a1 NO"));
	assert_eq!(output.collect_literal, None);

	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 APPEND Archive {5}");
	assert!(text(&output).contains("TRYCREATE"), "{}", text(&output));
}

#[test]
fn unexpected_literal_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.literal_done(b"stray");
	assert!(text(&output).contains("BAD"), "{}", text(&output));
}

#[test]
fn idle_flow() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 IDLE");
	assert!(output.idle);
	assert!(text(&output).starts_with("+ "));
	let output = session.idle_done();
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));
	// A second DONE without IDLE is an error.
	let output = session.idle_done();
	assert!(text(&output).contains("BAD"));
}

#[test]
fn idle_requires_authentication() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory());
	let output = session.command_line("a1 IDLE");
	assert!(text(&output).contains("a1 NO"));
	assert!(!output.idle);
}

#[test]
fn check_idle_detects_new_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\none\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	let output = session.command_line("a3 IDLE");
	assert!(output.idle, "should enter IDLE");

	// No change yet — check_idle returns None.
	assert!(session.check_idle().is_none());

	// Deliver a second message while idle.
	deliver(dir.path(), b"From: b@example.org\r\n\r\ntwo\r\n");

	// check_idle should now return an EXISTS notification.
	let notification = session.check_idle().expect("should get notification");
	let msg = text(&notification);
	assert!(msg.contains("* 2 EXISTS"), "{msg}");

	// Subsequent call returns None (no more changes).
	assert!(session.check_idle().is_none());
}

#[test]
fn check_idle_returns_none_when_not_idling() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// Not in IDLE — should be None even if mailbox changes.
	assert!(session.check_idle().is_none());
	session.command_line("a2 SELECT INBOX");
	assert!(session.check_idle().is_none());
}

#[test]
fn mailbox_lifecycle() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());

	let output = session.command_line("a2 CREATE Sent");
	assert!(text(&output).contains("a2 OK"), "{}", text(&output));

	// APPEND into the new mailbox works now.
	let output = session.command_line("a3 APPEND Sent {10}");
	assert_eq!(output.collect_literal, Some(10));
	let output = session.literal_done(b"sent body\n");
	assert!(text(&output).contains("a3 OK"), "{}", text(&output));

	let output = session.command_line("a4 SELECT Sent");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	session.command_line("a5 CLOSE");

	let output = session.command_line(r#"a6 LIST "" "*""#);
	let response = text(&output);
	assert!(response.contains("\"INBOX\""), "{response}");
	assert!(response.contains("\"Sent\""), "{response}");

	let output = session.command_line("a7 RENAME Sent Outbox");
	assert!(text(&output).contains("a7 OK"), "{}", text(&output));
	let output = session.command_line("a8 SELECT Outbox");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	session.command_line("a9 CLOSE");

	let output = session.command_line("b1 DELETE Outbox");
	assert!(text(&output).contains("b1 OK"), "{}", text(&output));
	let output = session.command_line("b2 SELECT Outbox");
	assert!(text(&output).contains("b2 NO"), "{}", text(&output));
}

#[test]
fn mailbox_management_guards() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// INBOX cannot be created, deleted or renamed.
	assert!(text(&session.command_line("a2 CREATE INBOX")).contains("a2 NO"));
	assert!(text(&session.command_line("a3 DELETE INBOX")).contains("a3 NO"));
	assert!(text(&session.command_line("a4 RENAME INBOX X")).contains("a4 NO"));
	// Traversal and invalid names are refused.
	assert!(text(&session.command_line("a5 CREATE ../escape")).contains("a5 NO"));
	assert!(text(&session.command_line("a6 DELETE missing")).contains("a6 NO"));
	// Duplicate create fails.
	session.command_line("a7 CREATE Drafts");
	assert!(text(&session.command_line("a8 CREATE Drafts")).contains("a8 NO"));
}

#[test]
fn copy_preserves_source_and_flags() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Archive");
	session.command_line("a3 SELECT INBOX");
	session.command_line(r"a4 STORE 1 +FLAGS (\Seen)");

	let output = session.command_line("a5 COPY 1 Archive");
	assert!(text(&output).contains("a5 OK COPY"), "{}", text(&output));

	// Source intact.
	let output = session.command_line("a6 FETCH 1 (FLAGS)");
	assert!(text(&output).contains(r"FLAGS (\Seen)"));
	session.command_line("a7 CLOSE");

	// Target has the copy with flags.
	let output = session.command_line("a8 SELECT Archive");
	assert!(text(&output).contains("* 1 EXISTS"), "{}", text(&output));
	let output = session.command_line("a9 FETCH 1 (FLAGS BODY[])");
	let response = text(&output);
	assert!(response.contains(r"FLAGS (\Seen)"), "{response}");
	assert!(response.contains("one"), "{response}");
}
