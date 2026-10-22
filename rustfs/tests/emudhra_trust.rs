// The October 2026 eMudhra intermediates must be rejected even when an
// operator's custom root store still contains their original trust anchors.
// Public fixtures and provenance are in fixtures/emudhra/README.md.
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::{CertificateError, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const AT: UnixTime = UnixTime::since_unix_epoch(Duration::from_secs(1_792_641_600));

fn certificates(path: &Path) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(&std::fs::read(path).expect("read public certificate fixture"))
        .map(|cert| cert.expect("parse public certificate fixture"))
        .collect()
}

fn verifier(root_path: &Path) -> Arc<WebPkiServerVerifier> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(root_path) {
        roots.add(cert).expect("add fixture trust anchor");
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build()
        .expect("construct normal RustFS TLS verifier")
}

#[test]
fn compromised_intermediates_are_distrusted_with_original_roots() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/emudhra");
    let verifier = verifier(&fixtures.join("roots.pem"));
    let mut checked = 0;
    for entry in std::fs::read_dir(&fixtures).expect("read incident fixtures") {
        let path = entry.expect("read fixture entry").path();
        let name = path
            .file_name()
            .expect("fixture filename")
            .to_str()
            .expect("UTF-8 fixture filename");
        if !name.ends_with(".we-have-a-problem.com.pem") {
            continue;
        }
        let host = name.trim_end_matches(".pem").to_owned();
        let chain = certificates(&path);
        let result =
            verifier.verify_server_cert(&chain[0], &chain[1..], &ServerName::try_from(host).expect("fixture hostname"), &[], AT);
        assert!(
            matches!(result, Err(rustls::Error::InvalidCertificate(CertificateError::Other(ref error)))
                if error.0.to_string() == "CertDistrusted"),
            "{name}: {result:?}"
        );
        checked += 1;
    }
    assert_eq!(checked, 12, "every direct and cross-signed TLS chain must be checked");
}

#[test]
fn unrelated_private_ca_still_verifies() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/emudhra");
    let chain = certificates(&fixtures.join("private-leaf.pem"));
    let result = verifier(&fixtures.join("private-root.pem")).verify_server_cert(
        &chain[0],
        &[],
        &ServerName::try_from("private.test").expect("private fixture hostname"),
        &[],
        AT,
    );
    assert!(result.is_ok(), "unrelated private CA was rejected: {result:?}");
}
