use super::*;

#[test]
fn move_removes_source_with_expunge() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	deliver(dir.path(), b"two\r\n");
	deliver(dir.path(), b"three\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Trash");
	session.command_line("a3 SELECT INBOX");

	let output = session.command_line("a4 MOVE 1,3 Trash");
	let response = text(&output);
	// Renumbering: removing seq 1 makes old 3 the new 2.
	assert!(response.contains("* 1 EXPUNGE"), "{response}");
	assert!(response.contains("* 2 EXPUNGE"), "{response}");
	assert!(response.contains("a4 OK MOVE"), "{response}");

	let output = session.command_line("a5 FETCH 1 (BODY[])");
	assert!(text(&output).contains("two"), "{}", text(&output));
	session.command_line("a6 CLOSE");

	let output = session.command_line("a7 SELECT Trash");
	assert!(text(&output).contains("* 2 EXISTS"), "{}", text(&output));
}

#[test]
fn uid_move_and_guards() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"one\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 CREATE Trash");

	// MOVE refused on read-only EXAMINE.
	session.command_line("a3 EXAMINE INBOX");
	let output = session.command_line("a4 MOVE 1 Trash");
	assert!(text(&output).contains("a4 NO"), "{}", text(&output));
	// COPY allowed on read-only.
	let output = session.command_line("a5 COPY 1 Trash");
	assert!(text(&output).contains("a5 OK"), "{}", text(&output));
	session.command_line("a6 CLOSE");

	session.command_line("a7 SELECT INBOX");
	let output = session.command_line("a8 UID MOVE 1 Trash");
	assert!(text(&output).contains("a8 OK MOVE"), "{}", text(&output));
	// Missing target answers TRYCREATE.
	let output = session.command_line("a9 COPY 1 Nowhere");
	assert!(text(&output).contains("TRYCREATE"), "{}", text(&output));
}

#[test]
fn search_by_flags_headers_and_text() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(
		dir.path(),
		b"From: alice@example.org\r\nSubject: project update\r\n\r\nquarterly numbers\r\n",
	);
	deliver(
		dir.path(),
		b"From: bob@example.org\r\nSubject: lunch\r\n\r\ntacos tomorrow\r\n",
	);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1 +FLAGS (\Seen)");

	let response = text(&session.command_line("a4 SEARCH UNSEEN"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	let response = text(&session.command_line("a5 SEARCH FROM alice"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	let response = text(&session.command_line(r#"a6 SEARCH SUBJECT "project update""#));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	let response = text(&session.command_line("a7 SEARCH TEXT tacos"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	// AND semantics: seen + from alice = 1; unseen + from alice = none.
	let response = text(&session.command_line("a8 SEARCH SEEN FROM alice"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");
	let response = text(&session.command_line("a9 SEARCH UNSEEN FROM alice"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");

	let response = text(&session.command_line("b1 SEARCH ALL"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");
}

#[test]
fn uid_search_returns_uids() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@x.example\r\n\r\none\r\n");
	deliver(dir.path(), b"From: a@x.example\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1 +FLAGS (\Deleted)");
	session.command_line("a4 EXPUNGE");

	// One message left: sequence 1, but UID 2.
	let response = text(&session.command_line("a5 UID SEARCH ALL"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");
	let response = text(&session.command_line("a6 SEARCH UID 2"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");
}

#[test]
fn search_requires_selection_and_valid_criteria() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let response = text(&session.command_line("a2 SEARCH ALL"));
	assert!(response.contains("a2 BAD"), "{response}");
	session.command_line("a3 SELECT INBOX");
	let response = text(&session.command_line("a4 SEARCH BOGUSKEY"));
	assert!(response.contains("a4 BAD"), "{response}");
}

#[test]
fn search_or_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\none\r\n");
	deliver(dir.path(), b"From: b@example.org\r\n\r\ntwo\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");
	session.command_line(r"a3 STORE 1 +FLAGS (\Seen)");

	// OR SEEN FLAGGED → message 1 (seen) only
	let response = text(&session.command_line("a4 SEARCH OR SEEN FLAGGED"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// OR SEEN UNSEEN → all
	let response = text(&session.command_line("a5 SEARCH OR SEEN UNSEEN"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");

	// NOT SEEN → message 2
	let response = text(&session.command_line("a6 SEARCH NOT SEEN"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	// Nested: OR (NOT SEEN) FLAGGED → message 2
	let response = text(&session.command_line("a7 SEARCH OR (NOT SEEN) FLAGGED"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");
}

#[test]
fn search_date_criteria() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), b"From: a@example.org\r\n\r\nbody\r\n");
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// SINCE epoch: all messages match (files exist after 1970).
	let response = text(&session.command_line("a3 SEARCH SINCE 1-Jan-1970"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// BEFORE far future: all messages match.
	let response = text(&session.command_line("a4 SEARCH BEFORE 1-Jan-2200"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// SINCE far future: no messages match.
	let response = text(&session.command_line("a5 SEARCH SINCE 1-Jan-2200"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");

	// BEFORE epoch: no messages match (files are newer than 1970-01-01).
	let response = text(&session.command_line("a6 SEARCH BEFORE 1-Jan-1970"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");
}

#[test]
fn search_larger_smaller() {
	let dir = tempfile::tempdir().expect("tempdir");
	let short = b"From: a@example.org\r\n\r\nhi\r\n";
	let long = b"From: b@example.org\r\n\r\nThis is a much longer message body.\r\n";
	deliver(dir.path(), short);
	deliver(dir.path(), long);
	let mut session = logged_in(dir.path());
	session.command_line("a2 SELECT INBOX");

	// LARGER 5 → both messages (both > 5 bytes).
	let response = text(&session.command_line("a3 SEARCH LARGER 5"));
	assert!(response.contains("* SEARCH 1 2\r\n"), "{response}");

	// LARGER 50 → only the long message (60 bytes > 50; short is 27 bytes).
	let response = text(&session.command_line("a4 SEARCH LARGER 50"));
	assert!(response.contains("* SEARCH 2\r\n"), "{response}");

	// SMALLER 50 → only the short message (27 bytes < 50; long is 60 bytes).
	let response = text(&session.command_line("a5 SEARCH SMALLER 50"));
	assert!(response.contains("* SEARCH 1\r\n"), "{response}");

	// SMALLER 5 → no messages (both > 5 bytes).
	let response = text(&session.command_line("a6 SEARCH SMALLER 5"));
	assert!(response.contains("* SEARCH\r\n"), "{response}");
}
