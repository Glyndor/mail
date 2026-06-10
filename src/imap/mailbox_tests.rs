use super::*;

fn deliver(dir: &Path, account: &str, body: &[u8]) -> Uuid {
	let new_dir = dir.join("accounts").join(account).join("new");
	std::fs::create_dir_all(&new_dir).expect("create dirs");
	let id = Uuid::now_v7();
	std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
	id
}

#[test]
fn empty_or_missing_inbox_is_empty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	assert!(snapshot.is_empty());
	assert_eq!(snapshot.uid_validity(), 1);
	assert_eq!(snapshot.uid_next(), 1);
}

#[test]
fn messages_are_ordered_and_readable() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"first\r\n");
	deliver(dir.path(), "alice", b"second\r\n");

	let snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	assert_eq!(snapshot.len(), 2);

	let first = snapshot.by_sequence(1).expect("seq 1");
	let second = snapshot.by_sequence(2).expect("seq 2");
	assert_eq!(first.uid, 1);
	assert_eq!(second.uid, 2);
	assert_eq!(snapshot.read(first).expect("read"), b"first\r\n");
	assert_eq!(snapshot.read(second).expect("read"), b"second\r\n");
	assert_eq!(first.size, 7);
	assert_eq!(snapshot.sequence_of_uid(2), Some(2));
	assert_eq!(snapshot.sequence_of_uid(99), None);
	assert!(snapshot.by_sequence(3).is_none());
	assert!(snapshot.by_sequence(0).is_none());
}

#[test]
fn flags_roundtrip_and_expunge() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"one\r\n");
	deliver(dir.path(), "alice", b"two\r\n");
	deliver(dir.path(), "alice", b"three\r\n");

	let mut snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	snapshot
		.store_flags(1, vec![Flag::Seen, Flag::Deleted])
		.expect("store");
	snapshot.store_flags(3, vec![Flag::Deleted]).expect("store");

	// A fresh snapshot reads the persisted flags.
	let reloaded = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	assert_eq!(
		reloaded.by_sequence(1).expect("seq 1").flags,
		vec![Flag::Seen, Flag::Deleted]
	);
	assert!(reloaded.by_sequence(2).expect("seq 2").flags.is_empty());

	let expunged = snapshot.expunge().expect("expunge");
	// Both deletions report sequence numbers valid at emission time:
	// removing seq 1 renumbers old seq 3 to 2.
	assert_eq!(expunged, vec![1, 2]);
	assert_eq!(snapshot.len(), 1);
	assert_eq!(
		snapshot
			.read(snapshot.by_sequence(1).expect("seq 1"))
			.expect("read"),
		b"two\r\n"
	);

	// Files are gone on disk too.
	let after = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	assert_eq!(after.len(), 1);
}

#[test]
fn store_flags_rejects_bad_sequence() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"one\r\n");
	let mut snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	assert!(snapshot.store_flags(0, vec![]).is_err());
	assert!(snapshot.store_flags(2, vec![]).is_err());
}

#[test]
fn flag_tokens_parse_and_render() {
	assert_eq!(Flag::parse("\\Seen"), Some(Flag::Seen));
	assert_eq!(Flag::parse("\\DELETED"), Some(Flag::Deleted));
	assert_eq!(Flag::parse("\\Recent"), None);
	assert_eq!(
		render_flags(&[Flag::Seen, Flag::Flagged]),
		"(\\Seen \\Flagged)"
	);
	assert_eq!(render_flags(&[]), "()");
}

#[test]
fn name_validation() {
	assert!(valid_name("Sent"));
	assert!(valid_name("My Folder.2024"));
	assert!(!valid_name("INBOX"));
	assert!(!valid_name("inbox"));
	assert!(!valid_name("../up"));
	assert!(!valid_name("a/b"));
	assert!(!valid_name(".hidden"));
	assert!(!valid_name(""));
	assert!(!valid_name("trailing "));
}

#[test]
fn create_list_rename_delete_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	create(dir.path(), "alice", "Sent").expect("create");
	assert!(exists(dir.path(), "alice", "Sent"));
	assert!(create(dir.path(), "alice", "Sent").is_err());

	append(dir.path(), "alice", "Sent", &[Flag::Seen], b"sent\r\n").expect("append");
	let snapshot = Snapshot::open(dir.path(), "alice", "Sent").expect("open");
	assert_eq!(snapshot.len(), 1);
	assert_eq!(
		snapshot.by_sequence(1).expect("seq").flags,
		vec![Flag::Seen]
	);

	assert_eq!(list(dir.path(), "alice"), vec!["INBOX", "Sent"]);

	rename(dir.path(), "alice", "Sent", "Outbox").expect("rename");
	assert!(!exists(dir.path(), "alice", "Sent"));
	assert!(exists(dir.path(), "alice", "Outbox"));

	delete(dir.path(), "alice", "Outbox").expect("delete");
	assert!(!exists(dir.path(), "alice", "Outbox"));
	assert!(delete(dir.path(), "alice", "Outbox").is_err());
}

#[test]
fn inbox_is_protected() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(create(dir.path(), "alice", "INBOX").is_err());
	assert!(delete(dir.path(), "alice", "INBOX").is_err());
	assert!(rename(dir.path(), "alice", "INBOX", "X").is_err());
	assert!(exists(dir.path(), "alice", "INBOX"));
}

#[test]
fn ignores_foreign_files() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"mail\r\n");
	std::fs::write(dir.path().join("accounts/alice/new/notes.txt"), b"not mail").expect("write");
	let snapshot = Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	assert_eq!(snapshot.len(), 1);
}
