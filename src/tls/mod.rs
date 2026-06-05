//! TLS material loading: PEM files into a rustls acceptor.

use std::path::Path;
use std::sync::Arc;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::Tls;

/// Errors while loading TLS material. Always fatal: the server refuses to
/// start with broken TLS rather than degrade to plaintext.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
	#[error("cannot read {path}: {source}")]
	Read {
		path: String,
		source: std::io::Error,
	},
	#[error("no certificates found in {0}")]
	NoCertificates(String),
	#[error("no private key found in {0}")]
	NoPrivateKey(String),
	#[error("invalid TLS material: {0}")]
	Invalid(String),
}

/// Build a TLS acceptor from the configured PEM files.
pub fn acceptor(config: &Tls) -> Result<TlsAcceptor, TlsError> {
	let certs = load_certs(&config.cert_file)?;
	let key = load_key(&config.key_file)?;
	let server_config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
	let pem = std::fs::read(path).map_err(|source| TlsError::Read {
		path: path.display().to_string(),
		source,
	})?;
	let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_slice())
		.collect::<Result<_, _>>()
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	if certs.is_empty() {
		return Err(TlsError::NoCertificates(path.display().to_string()));
	}
	Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
	let pem = std::fs::read(path).map_err(|source| TlsError::Read {
		path: path.display().to_string(),
		source,
	})?;
	rustls_pemfile::private_key(&mut pem.as_slice())
		.map_err(|error| TlsError::Invalid(error.to_string()))?
		.ok_or_else(|| TlsError::NoPrivateKey(path.display().to_string()))
}

/// Test-only helpers shared across modules.
#[cfg(test)]
pub(crate) mod test_support {
	use tokio_rustls::TlsAcceptor;
	use tokio_rustls::rustls::ServerConfig;
	use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

	/// Build an acceptor from a fresh self-signed certificate, returning the
	/// certificate so test clients can trust it.
	pub(crate) fn acceptor_and_cert() -> (TlsAcceptor, CertificateDer<'static>) {
		let certified = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
			.expect("generate certificate");
		let cert = certified.cert.der().clone();
		let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).expect("key der");
		let config = ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(vec![cert.clone()], key)
			.expect("server config");
		(TlsAcceptor::from(std::sync::Arc::new(config)), cert)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	/// Write a self-signed certificate + key pair into `dir`.
	pub(crate) fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
		let certified = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
			.expect("generate certificate");
		let cert_path = dir.join("cert.pem");
		let key_path = dir.join("key.pem");
		std::fs::write(&cert_path, certified.cert.pem()).expect("write cert");
		std::fs::write(&key_path, certified.signing_key.serialize_pem()).expect("write key");
		(cert_path, key_path)
	}

	fn tls_config(cert_file: PathBuf, key_file: PathBuf) -> Tls {
		let toml = format!(
			"cert_file = \"{}\"\nkey_file = \"{}\"\n",
			cert_file.display(),
			key_file.display()
		);
		toml::from_str(&toml).expect("tls config")
	}

	#[test]
	fn builds_acceptor_from_valid_material() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, key) = write_self_signed(dir.path());
		assert!(acceptor(&tls_config(cert, key)).is_ok());
	}

	#[test]
	fn fails_on_missing_cert_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (_, key) = write_self_signed(dir.path());
		let result = acceptor(&tls_config(dir.path().join("missing.pem"), key));
		assert!(matches!(result, Err(TlsError::Read { .. })));
	}

	#[test]
	fn fails_on_missing_key_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, _) = write_self_signed(dir.path());
		let result = acceptor(&tls_config(cert, dir.path().join("missing.pem")));
		assert!(matches!(result, Err(TlsError::Read { .. })));
	}

	#[test]
	fn fails_on_empty_cert_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (_, key) = write_self_signed(dir.path());
		let empty = dir.path().join("empty.pem");
		std::fs::write(&empty, b"").expect("write empty");
		let result = acceptor(&tls_config(empty, key));
		assert!(matches!(result, Err(TlsError::NoCertificates(_))));
	}

	#[test]
	fn fails_on_key_without_key_material() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, _) = write_self_signed(dir.path());
		let bogus = dir.path().join("bogus.pem");
		std::fs::write(&bogus, b"not a key").expect("write bogus");
		let result = acceptor(&tls_config(cert, bogus));
		assert!(matches!(result, Err(TlsError::NoPrivateKey(_))));
	}

	#[test]
	fn fails_on_mismatched_cert_and_key() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, _) = write_self_signed(dir.path());
		let other = tempfile::tempdir().expect("tempdir");
		let (_, foreign_key) = write_self_signed(other.path());
		// A key from a different certificate must be rejected.
		let result = acceptor(&tls_config(cert, foreign_key));
		assert!(matches!(result, Err(TlsError::Invalid(_))));
	}
}
