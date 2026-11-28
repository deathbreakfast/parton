//! Agent mTLS toward the control plane.
//!
//! When `PARTON_CP_CA_PATH` is set, Parton trusts only that CA for control-plane calls, requires an
//! `https` heartbeat URL, and presents a client certificate it enrolled for. The private key is
//! generated on the host and never leaves it; only a certificate signing request (CSR) is sent.
//!
//! Enrollment: `POST <heartbeat-origin>/api/parton/enroll/sign-csr` with JSON
//! `{enrollment_id, token, csr_pem}`, answered by `{cert_pem, chain_pem?}`. `enrollment_id` is the
//! middle segment of `PARTON_ENROLLMENT_TOKEN` (`ghe.<id>.<secret>`).
//!
//! Files live under `PARTON_STATE_DIR` (default `/etc/parton`): `client.key` (mode 0600),
//! `client.csr` and `client.crt` (leaf certificate followed by any chain).

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

const DEFAULT_STATE_DIR: &str = "/etc/parton";
const SIGN_CSR_PATH: &str = "/api/parton/enroll/sign-csr";

/// Directory holding the host key, CSR and signed certificate (`PARTON_STATE_DIR`).
#[must_use]
pub fn state_dir() -> PathBuf {
    std::env::var("PARTON_STATE_DIR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_STATE_DIR), PathBuf::from)
}

/// Path of the control-plane CA bundle (`PARTON_CP_CA_PATH`), when mTLS is enabled.
#[must_use]
pub fn cp_ca_path() -> Option<PathBuf> {
    std::env::var("PARTON_CP_CA_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Fail closed when `PARTON_CP_CA_PATH` is set but the heartbeat URL is not `https`.
///
/// # Errors
///
/// Returns an error when a CA path is configured and `endpoint` does not start with `https://`.
pub fn require_https_when_ca_set(endpoint: &str) -> anyhow::Result<()> {
    if cp_ca_path().is_some() && !endpoint.trim().to_ascii_lowercase().starts_with("https://") {
        anyhow::bail!(
            "PARTON_CP_CA_PATH is set but PARTON_HEARTBEAT_URL is not https; refusing to start"
        );
    }
    Ok(())
}

/// Start an HTTP client builder for control-plane calls.
///
/// Without `PARTON_CP_CA_PATH` this is a plain builder. With it, only that CA is trusted, and the
/// enrolled client certificate is presented when one exists.
///
/// # Errors
///
/// Returns an error when the CA file or the stored client identity cannot be read or parsed.
pub fn client_builder() -> anyhow::Result<reqwest::ClientBuilder> {
    let builder = reqwest::Client::builder();
    let Some(ca_path) = cp_ca_path() else {
        return Ok(builder);
    };
    let ca_pem = std::fs::read(&ca_path)
        .with_context(|| format!("read PARTON_CP_CA_PATH {}", ca_path.display()))?;
    let ca = reqwest::Certificate::from_pem(&ca_pem)
        .with_context(|| format!("parse CA certificate {}", ca_path.display()))?;
    let mut builder = builder
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca);
    let dir = state_dir();
    let (key_path, cert_path) = (dir.join("client.key"), dir.join("client.crt"));
    if key_path.exists() && cert_path.exists() {
        let mut pem =
            std::fs::read(&cert_path).with_context(|| format!("read {}", cert_path.display()))?;
        pem.push(b'\n');
        pem.extend(
            std::fs::read(&key_path).with_context(|| format!("read {}", key_path.display()))?,
        );
        let identity = reqwest::Identity::from_pem(&pem).context("parse client identity")?;
        builder = builder.identity(identity);
    }
    Ok(builder)
}

/// Result of an enrollment attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// A signed certificate is stored (now or from an earlier run).
    Ready,
    /// The control plane has no sign-csr endpoint yet (404/501); keep heartbeating as before.
    Unsupported,
}

#[derive(Serialize)]
struct SignCsrRequest<'a> {
    enrollment_id: &'a str,
    token: &'a str,
    csr_pem: &'a str,
}

#[derive(Deserialize)]
struct SignCsrResponse {
    cert_pem: String,
    #[serde(default)]
    chain_pem: Option<String>,
}

/// Extract `<id>` from a `ghe.<id>.<secret>` enrollment token.
#[must_use]
pub fn enrollment_id_from_token(token: &str) -> Option<&str> {
    let mut parts = token.trim().splitn(3, '.');
    let (prefix, id, secret) = (parts.next()?, parts.next()?, parts.next()?);
    (prefix == "ghe" && !id.is_empty() && !secret.is_empty()).then_some(id)
}

/// Sign-csr URL on the same origin as the heartbeat endpoint.
///
/// # Errors
///
/// Returns an error when `heartbeat_endpoint` is not an absolute URL.
pub fn sign_csr_url(heartbeat_endpoint: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(heartbeat_endpoint.trim())
        .with_context(|| format!("parse heartbeat URL {heartbeat_endpoint}"))?;
    let origin = url.origin().ascii_serialization();
    Ok(format!("{origin}{SIGN_CSR_PATH}"))
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn load_or_create_key(dir: &Path) -> anyhow::Result<rcgen::KeyPair> {
    let key_path = dir.join("client.key");
    if key_path.exists() {
        let pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;
        return rcgen::KeyPair::from_pem(&pem).context("parse stored client key");
    }
    let key = rcgen::KeyPair::generate().context("generate client key")?;
    write_private(&key_path, key.serialize_pem().as_bytes())?;
    Ok(key)
}

/// Make sure a signed client certificate exists under [`state_dir`], enrolling when it does not.
///
/// Generates the host key if missing, writes `client.csr`, posts it with the enrollment token and
/// stores the signed certificate. A 404 or 501 from the control plane returns
/// [`EnrollOutcome::Unsupported`] after a warning.
///
/// # Errors
///
/// Returns an error when the token is malformed, local files cannot be written, the request
/// fails, or the control plane answers with another non-success status.
#[tracing::instrument(skip(heartbeat_endpoint, enrollment_token))]
pub async fn ensure_identity(
    heartbeat_endpoint: &str,
    node_id: &str,
    enrollment_token: &str,
) -> anyhow::Result<EnrollOutcome> {
    let dir = state_dir();
    let cert_path = dir.join("client.crt");
    if cert_path.exists() && dir.join("client.key").exists() {
        return Ok(EnrollOutcome::Ready);
    }
    let enrollment_id = enrollment_id_from_token(enrollment_token)
        .context("PARTON_ENROLLMENT_TOKEN is not of the form ghe.<id>.<secret>")?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let key = load_or_create_key(&dir)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .context("build certificate request parameters")?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, node_id);
    let csr_pem = params
        .serialize_request(&key)
        .context("build CSR")?
        .pem()
        .context("encode CSR")?;
    std::fs::write(dir.join("client.csr"), &csr_pem).context("write client.csr")?;

    let url = sign_csr_url(heartbeat_endpoint)?;
    let client = client_builder()?
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client for sign-csr request")?;
    let response = client
        .post(&url)
        .json(&SignCsrRequest {
            enrollment_id,
            token: enrollment_token,
            csr_pem: &csr_pem,
        })
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    if matches!(
        status,
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::NOT_IMPLEMENTED
    ) {
        tracing::warn!(%status, %url, "control plane has no sign-csr endpoint; continuing without a client certificate");
        return Ok(EnrollOutcome::Unsupported);
    }
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|e| format!("<unreadable body: {e}>"));
        anyhow::bail!("sign-csr failed ({status}): {body}");
    }
    let signed: SignCsrResponse = response.json().await.context("decode sign-csr response")?;
    let mut crt = signed.cert_pem;
    if let Some(chain) = signed.chain_pem {
        if !crt.ends_with('\n') {
            crt.push('\n');
        }
        crt.push_str(&chain);
    }
    std::fs::write(&cert_path, crt).with_context(|| format!("write {}", cert_path.display()))?;
    tracing::info!(path = %cert_path.display(), "stored signed client certificate");
    Ok(EnrollOutcome::Ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enrollment_id() {
        assert_eq!(enrollment_id_from_token("ghe.abc.secret"), Some("abc"));
        assert_eq!(enrollment_id_from_token("ghe.abc.s.e"), Some("abc"));
        assert_eq!(enrollment_id_from_token("ghe..secret"), None);
        assert_eq!(enrollment_id_from_token("ghe.abc"), None);
        assert_eq!(enrollment_id_from_token("xyz.abc.secret"), None);
        assert_eq!(enrollment_id_from_token(""), None);
    }

    #[test]
    fn sign_csr_url_uses_heartbeat_origin() {
        assert_eq!(
            sign_csr_url("https://cp.example:8443/api/parton/heartbeat").unwrap(),
            "https://cp.example:8443/api/parton/enroll/sign-csr"
        );
        assert!(sign_csr_url("not a url").is_err());
    }
}
