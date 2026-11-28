//! Agent mTLS: CSR enrollment against a stub sign-csr endpoint and a client-cert-only TLS server.

// Integration test harness: panics on setup/teardown are acceptable failure signals.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use parton::mtls::{self, EnrollOutcome};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, IsCa,
    KeyPair, SanType,
};
use serde_json::{json, Value};
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls;

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn new_ca(name: &str) -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Ca { cert, key }
}

async fn spawn_http(app: Router) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Stub sign-csr endpoint that signs whatever CSR it receives with `ca`.
async fn spawn_sign_csr(ca: Arc<Ca>) -> SocketAddr {
    let app = Router::new().route(
        "/api/parton/enroll/sign-csr",
        post(move |Json(body): Json<Value>| {
            let ca = ca.clone();
            async move {
                assert_eq!(body["enrollment_id"], "abc");
                assert_eq!(body["token"], "ghe.abc.secret");
                let csr =
                    CertificateSigningRequestParams::from_pem(body["csr_pem"].as_str().unwrap())
                        .unwrap();
                let cert = csr.signed_by(&ca.cert, &ca.key).unwrap();
                Json(json!({"cert_pem": cert.pem()}))
            }
        }),
    );
    spawn_http(app).await
}

/// TLS server that demands a client certificate signed by `client_ca`; replies `200 ok`.
async fn spawn_mtls_server(server_ca: &Ca, client_ca: &Ca) -> SocketAddr {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
    let key = KeyPair::generate().unwrap();
    let cert = params
        .signed_by(&key, &server_ca.cert, &server_ca.key)
        .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(client_ca.cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

fn write_ca(dir: &std::path::Path, name: &str, ca: &Ca) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, ca.cert.pem()).unwrap();
    path
}

fn set_env(state: &std::path::Path, ca_path: &std::path::Path) {
    std::env::set_var("PARTON_STATE_DIR", state);
    std::env::set_var("PARTON_CP_CA_PATH", ca_path);
}

fn clear_env() {
    std::env::remove_var("PARTON_STATE_DIR");
    std::env::remove_var("PARTON_CP_CA_PATH");
}

async fn get_ok(addr: SocketAddr) -> anyhow::Result<String> {
    let client = mtls::client_builder()?.build()?;
    Ok(client
        .get(format!("https://{addr}/"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

#[tokio::test]
#[serial]
async fn enrolls_then_presents_client_cert_to_mtls_listener() {
    let ca = Arc::new(new_ca("test cp ca"));
    let sign = spawn_sign_csr(ca.clone()).await;
    let tls = spawn_mtls_server(&ca, &ca).await;
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    set_env(&state, &write_ca(tmp.path(), "ca.pem", &ca));

    // No certificate yet: the mTLS listener refuses the handshake.
    assert!(get_ok(tls).await.is_err());

    let outcome = mtls::ensure_identity(
        &format!("http://{sign}/api/parton/heartbeat"),
        "node-1",
        "ghe.abc.secret",
    )
    .await
    .unwrap();
    assert_eq!(outcome, EnrollOutcome::Ready);
    assert!(state.join("client.csr").exists());
    assert!(state.join("client.crt").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(state.join("client.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    assert_eq!(get_ok(tls).await.unwrap(), "ok");

    // A second call reuses the stored identity without contacting the control plane.
    let again = mtls::ensure_identity("http://127.0.0.1:1/x", "node-1", "ghe.abc.secret")
        .await
        .unwrap();
    assert_eq!(again, EnrollOutcome::Ready);
    clear_env();
}

#[tokio::test]
#[serial]
async fn missing_sign_csr_endpoint_keeps_heartbeating_without_cert() {
    for status in [StatusCode::NOT_FOUND, StatusCode::NOT_IMPLEMENTED] {
        let app = Router::new().route(
            "/api/parton/enroll/sign-csr",
            post(move || async move { status }),
        );
        let sign = spawn_http(app).await;
        let ca = new_ca("ca");
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        set_env(&state, &write_ca(tmp.path(), "ca.pem", &ca));
        let outcome = mtls::ensure_identity(
            &format!("http://{sign}/api/parton/heartbeat"),
            "node-1",
            "ghe.abc.secret",
        )
        .await
        .unwrap();
        assert_eq!(outcome, EnrollOutcome::Unsupported);
        assert!(!state.join("client.crt").exists());
        clear_env();
    }
}

#[tokio::test]
#[serial]
async fn server_error_from_sign_csr_is_an_error() {
    let app = Router::new().route(
        "/api/parton/enroll/sign-csr",
        post(|| async { StatusCode::UNAUTHORIZED }),
    );
    let sign = spawn_http(app).await;
    let tmp = tempfile::tempdir().unwrap();
    let ca = new_ca("ca");
    set_env(&tmp.path().join("s"), &write_ca(tmp.path(), "ca.pem", &ca));
    let result = mtls::ensure_identity(
        &format!("http://{sign}/api/parton/heartbeat"),
        "node-1",
        "ghe.abc.secret",
    )
    .await;
    assert!(result.is_err());
    clear_env();
}

#[tokio::test]
#[serial]
async fn wrong_ca_is_rejected_and_bad_ca_path_fails_closed() {
    let ca = Arc::new(new_ca("real ca"));
    let other = new_ca("other ca");
    let sign = spawn_sign_csr(ca.clone()).await;
    let tls = spawn_mtls_server(&ca, &ca).await;
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    set_env(&state, &write_ca(tmp.path(), "ca.pem", &ca));
    mtls::ensure_identity(
        &format!("http://{sign}/api/parton/heartbeat"),
        "node-1",
        "ghe.abc.secret",
    )
    .await
    .unwrap();

    // The server cert is not signed by the CA the agent trusts.
    set_env(&state, &write_ca(tmp.path(), "other.pem", &other));
    assert!(get_ok(tls).await.is_err());

    set_env(&state, &tmp.path().join("missing.pem"));
    assert!(mtls::client_builder().is_err());
    clear_env();
}

#[test]
#[serial]
fn https_is_required_when_ca_is_set() {
    clear_env();
    assert!(mtls::require_https_when_ca_set("http://cp/api/parton/heartbeat").is_ok());
    std::env::set_var("PARTON_CP_CA_PATH", "/etc/parton/cp_ca.pem");
    assert!(mtls::require_https_when_ca_set("http://cp/api/parton/heartbeat").is_err());
    assert!(mtls::require_https_when_ca_set("https://cp:8443/api/parton/heartbeat").is_ok());
    clear_env();
}
