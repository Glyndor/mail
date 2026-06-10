use super::*;
use crate::smtp::sink::MemorySink;

fn test_directory() -> DirectoryHandle {
	DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("b@example.org".to_string(), "bob".to_string()),
		],
	))
}

/// Run one scripted client conversation, returning the full server output.
async fn converse(input: &[u8]) -> (String, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory());

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(input).await.expect("client write");
	client_write.shutdown().await.expect("client shutdown");

	let mut output = Vec::new();
	client_read
		.read_to_end(&mut output)
		.await
		.expect("client read");
	task.await.expect("server task").expect("server result");
	(String::from_utf8(output).expect("ascii output"), sink)
}

#[tokio::test]
async fn greets_on_connect() {
	let (output, _) = converse(b"").await;
	assert!(output.starts_with("220 mail.example.org ESMTP ready\r\n"));
}

#[tokio::test]
async fn full_transaction_is_stored() {
	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<alice@example.org>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
	let (output, sink) = converse(script).await;
	assert!(
		output.contains("250-mail.example.org"),
		"EHLO reply: {output}"
	);
	assert!(output.contains("354 "), "DATA go-ahead: {output}");
	assert!(output.ends_with("221 closing connection\r\n"), "{output}");

	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].reverse_path, "alice@example.org");
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii message");
	assert!(
		data.starts_with("Received: from client.example.org ([unknown])\r\n"),
		"{data}"
	);
	assert!(data.contains("with ESMTP;"), "{data}");
	assert!(data.ends_with("Subject: hi\r\n\r\nhello\r\n"), "{data}");
}

#[tokio::test]
async fn bare_lf_closes_connection() {
	let (output, sink) = converse(b"EHLO x.example\nMAIL FROM:<a@b.example>\r\n").await;
	assert!(output.contains("554 bare CR or LF"), "{output}");
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn bare_cr_closes_connection() {
	let (output, _) = converse(b"EHLO x\rexample\r\n").await;
	assert!(output.contains("554 bare CR or LF"), "{output}");
}

#[tokio::test]
async fn nul_byte_closes_connection() {
	let (output, _) = converse(b"EHLO x\0.example\r\n").await;
	assert!(output.contains("554 NUL byte"), "{output}");
}

#[tokio::test]
async fn overlong_line_closes_connection() {
	let mut script = vec![b'x'; 2000];
	script.extend_from_slice(b"\r\n");
	let (output, _) = converse(&script).await;
	assert!(output.contains("500 line too long"), "{output}");
}

#[tokio::test]
async fn out_of_order_commands_are_rejected() {
	let (output, sink) = converse(b"MAIL FROM:<a@example.org>\r\nQUIT\r\n").await;
	assert!(output.contains("503 bad sequence"), "{output}");
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn non_utf8_command_gets_syntax_error() {
	let (output, _) = converse(b"EHLO caf\xC3\xA9.example\r\nQUIT\r\n").await;
	// Non-ASCII is rejected by the command parser after UTF-8 decoding.
	assert!(output.contains("500 syntax error"), "{output}");
}

#[tokio::test]
async fn eight_bit_data_in_message_body_is_accepted() {
	// 8BITMIME: raw 8-bit content in the DATA phase must be accepted.
	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<a@example.org>\r\n\
RCPT TO:<b@example.org>\r\n\
DATA\r\n\
Subject: test\r\n\
\xFF\xFE binary content\r\n\
.\r\n";
	let (output, sink) = converse(script).await;
	assert!(output.contains("250"), "{output}");
	assert_eq!(sink.messages().len(), 1);
	let data = &sink.messages()[0].data;
	assert!(data.iter().any(|&b| b > 127), "8-bit bytes preserved");
}

#[tokio::test]
async fn starttls_not_offered_without_acceptor() {
	let (output, _) = converse(b"EHLO client.example.org\r\nSTARTTLS\r\nQUIT\r\n").await;
	assert!(!output.contains("250-STARTTLS"), "{output}");
	assert!(output.contains("454 TLS not available"), "{output}");
}

/// DNS stub serving one SPF TXT record for `sender.example`.
struct OneRecordDns {
	record: &'static str,
}

type DnsFuture<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for OneRecordDns {
	fn txt(&self, name: &str) -> DnsFuture<'_, Vec<String>> {
		let result = if name == "sender.example" {
			vec![self.record.to_string()]
		} else {
			Vec::new()
		};
		Box::pin(async move { Ok(result) })
	}

	fn addresses(&self, _name: &str) -> DnsFuture<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> DnsFuture<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

async fn converse_with_spf(record: &'static str) -> (String, Arc<MemorySink>) {
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_spf(Arc::new(OneRecordDns { record }));

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });

	let script = b"EHLO client.example.org\r\n\
MAIL FROM:<eve@sender.example>\r\n\
RCPT TO:<bob@example.org>\r\n\
DATA\r\n\
Subject: hi\r\n\
\r\n\
hello\r\n\
.\r\n\
QUIT\r\n";
	let (mut client_read, mut client_write) = tokio::io::split(client);
	client_write.write_all(script).await.expect("client write");
	client_write.shutdown().await.expect("client shutdown");
	let mut output = Vec::new();
	client_read
		.read_to_end(&mut output)
		.await
		.expect("client read");
	task.await.expect("task").expect("server result");
	(String::from_utf8(output).expect("ascii"), sink)
}

#[tokio::test]
async fn spf_fail_rejects_the_message() {
	let (output, sink) = converse_with_spf("v=spf1 -all").await;
	assert!(output.contains("550 5.7.23"), "{output}");
	assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn spf_pass_stamps_received_spf_header() {
	let (output, sink) = converse_with_spf("v=spf1 ip4:192.0.2.0/24 -all").await;
	assert!(!output.contains("550"), "{output}");
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii");
	assert!(
		data.contains("Received-SPF: pass (domain of sender.example) client-ip=192.0.2.7"),
		"{data}"
	);
}

#[tokio::test]
async fn unsigned_message_records_dkim_none() {
	let (_, sink) = converse_with_spf("v=spf1 ip4:192.0.2.0/24 -all").await;
	let data = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
	assert!(
		data.contains(
			"Authentication-Results: mail.example.org;\r\n\tspf=pass smtp.mailfrom=sender.example;\r\n\tdkim=none;\r\n\tdmarc="
		),
		"{data}"
	);
}

#[tokio::test]
async fn spf_softfail_is_accepted_and_recorded() {
	let (output, sink) = converse_with_spf("v=spf1 ~all").await;
	assert!(!output.contains("550"), "{output}");
	let data = String::from_utf8(sink.messages()[0].data.clone()).expect("ascii");
	assert!(data.contains("Received-SPF: softfail"), "{data}");
}

/// Test client TLS connector trusting the given certificate.
fn test_connector(
	cert: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) -> tokio_rustls::TlsConnector {
	let mut roots = tokio_rustls::rustls::RootCertStore::empty();
	roots.add(cert).expect("trust test certificate");
	let config = tokio_rustls::rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn read_reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> String {
	let mut buffer = [0u8; 1024];
	let read = reader.read(&mut buffer).await.expect("read reply");
	String::from_utf8_lossy(&buffer[..read]).to_string()
}

#[tokio::test]
async fn starttls_upgrade_and_transaction() {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(test_directory())
		.with_tls(acceptor, TlsMode::Opportunistic);

	let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	assert!(read_reply(&mut client).await.starts_with("220 "));
	client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("ehlo");
	let ehlo = read_reply(&mut client).await;
	assert!(ehlo.contains("250 STARTTLS"), "{ehlo}");

	client.write_all(b"STARTTLS\r\n").await.expect("starttls");
	assert!(read_reply(&mut client).await.starts_with("220 "));

	// TLS handshake over the same stream.
	let connector = test_connector(cert);
	let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org")
		.expect("server name");
	let mut tls_client = connector
		.connect(server_name, client)
		.await
		.expect("tls handshake");

	// Fresh greeting inside TLS; the session forgot the plaintext EHLO.
	assert!(read_reply(&mut tls_client).await.starts_with("220 "));
	tls_client
		.write_all(b"EHLO c.example.org\r\n")
		.await
		.expect("tls ehlo");
	let tls_ehlo = read_reply(&mut tls_client).await;
	// STARTTLS must not be offered again inside TLS.
	assert!(!tls_ehlo.contains("STARTTLS"), "{tls_ehlo}");

	tls_client
		.write_all(b"MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n")
		.await
		.expect("transaction");
	let mut got = String::new();
	while !got.contains("354 ") {
		got.push_str(&read_reply(&mut tls_client).await);
	}
	tls_client
		.write_all(b"secret\r\n.\r\nQUIT\r\n")
		.await
		.expect("data");
	let mut tail = String::new();
	while !tail.contains("221 ") {
		tail.push_str(&read_reply(&mut tls_client).await);
	}

	drop(tls_client);
	task.abort();
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = String::from_utf8(messages[0].data.clone()).expect("ascii message");
	// The trace header records the TLS protocol.
	assert!(data.starts_with("Received: from c.example.org"), "{data}");
	assert!(data.contains("with ESMTPS;"), "{data}");
	assert!(data.ends_with("secret\r\n"), "{data}");
}

#[tokio::test]
async fn implicit_tls_serves_inside_handshake() {
	let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
		.with_tls(acceptor, TlsMode::Implicit);

	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(server_stream, None).await });

	let connector = test_connector(cert);
	let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("mail.example.org")
		.expect("server name");
	let mut tls_client = connector
		.connect(server_name, client)
		.await
		.expect("tls handshake");

	assert!(read_reply(&mut tls_client).await.starts_with("220 "));
	tls_client.write_all(b"QUIT\r\n").await.expect("quit");
	assert!(read_reply(&mut tls_client).await.contains("221 "));
	task.abort();
}

#[tokio::test]
async fn implicit_tls_without_acceptor_errors() {
	let sink = Arc::new(MemorySink::new());
	let server = Server {
		hostname: "mail.example.org".to_string(),
		sink: sink as Arc<dyn MessageSink>,
		tls: None,
		tls_mode: TlsMode::Implicit,
		directory: DirectoryHandle::new(Directory::default()),
		spf: None,
		report_dir: None,
	};
	let (_client, server_stream) = tokio::io::duplex(1024);
	assert!(server.handle(server_stream, None).await.is_err());
}

#[tokio::test]
async fn serve_accepts_tcp_connections() {
	let sink = Arc::new(MemorySink::new());
	let server = Arc::new(Server::new(
		"mail.example.org",
		sink as Arc<dyn MessageSink>,
	));
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("local addr");
	let task = tokio::spawn(server.serve(listener));

	let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
	let mut greeting = [0u8; 64];
	let read = client.read(&mut greeting).await.expect("read greeting");
	assert!(String::from_utf8_lossy(&greeting[..read]).starts_with("220 "));

	client.write_all(b"QUIT\r\n").await.expect("write quit");
	let mut rest = Vec::new();
	client.read_to_end(&mut rest).await.expect("read close");
	assert!(String::from_utf8_lossy(&rest).contains("221 "));
	task.abort();
}
