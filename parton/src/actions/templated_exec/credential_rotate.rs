//! Credential-rotation templates: change the password a running engine accepts.
//!
//! Passwords arrive only in [`ContainerActionRequest::secret_env_vars`], resolved from Neutrino
//! refs when the command is claimed. They are written verbatim to a short-lived `0600` file and
//! handed to `docker exec --env-file`; the fixed in-container scripts read them from the
//! environment, so neither password appears in argv, the response, or logs.

use super::super::secret_env::validate_deploy_secret_env_entry;
use super::super::types::{
    ContainerActionRequest, SecretEnvVar, TemplatedExecId, ROTATE_NEW_PASSWORD_ENV,
};
use anyhow::Context;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Users-config override the `ClickHouse` server reloads (sorts after the image's `default-user.xml`).
const CH_PASSWORD_OVERRIDE_PATH: &str =
    "/etc/clickhouse-server/users.d/zz-nucleus-rotated-password.xml";

/// `nucleus` always; `nucleus_repl` only when the role exists. `\getenv` needs psql 15+.
const PG_ROTATE_SCRIPT: &str = r"set -eu
psql -q -v ON_ERROR_STOP=1 -U nucleus -d postgres <<'SQL'
\getenv pw PARTON_ROTATE_NEW_PASSWORD
ALTER ROLE nucleus PASSWORD :'pw';
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nucleus_repl') AS has_repl \gset
\if :has_repl
ALTER ROLE nucleus_repl PASSWORD :'pw';
\endif
SQL
";

/// Logs in with the old password, or the new one when a previous attempt already rotated, then
/// sets `masterauth` before `requirepass` so the session stays authenticated until the end.
const REDIS_ROTATE_SCRIPT: &str = r#"set -eu
REDISCLI_AUTH="$PARTON_ROTATE_OLD_PASSWORD"
export REDISCLI_AUTH
if [ "$(redis-cli PING 2>/dev/null)" != "PONG" ]; then
  REDISCLI_AUTH="$PARTON_ROTATE_NEW_PASSWORD"
fi
for key in masterauth requirepass; do
  out=$(printf '%s' "$PARTON_ROTATE_NEW_PASSWORD" | redis-cli -x CONFIG SET "$key")
  if [ "$out" != "OK" ]; then
    echo "CONFIG SET $key: $out" >&2
    exit 1
  fi
done
"#;

/// Same old-then-new login fallback as Redis, so a retried rotation stays idempotent.
const MONGO_ROTATE_EVAL: &str = "const admin = db.getSiblingDB('admin'); \
let ok = false; \
try { ok = admin.auth('nucleus', process.env.PARTON_ROTATE_OLD_PASSWORD || '').ok === 1 } catch (e) { } \
if (!ok) { admin.auth('nucleus', process.env.PARTON_ROTATE_NEW_PASSWORD) } \
admin.changeUserPassword('nucleus', process.env.PARTON_ROTATE_NEW_PASSWORD)";

fn ch_rotate_script() -> String {
    format!(
        r#"set -eu
f={CH_PASSWORD_OVERRIDE_PATH}
umask 077
printf '<clickhouse><users><default><password><![CDATA[%s]]></password></default></users></clickhouse>\n' "$PARTON_ROTATE_NEW_PASSWORD" > "$f.tmp"
chown clickhouse:clickhouse "$f.tmp" 2>/dev/null || true
mv "$f.tmp" "$f"
"#
    )
}

/// Check `vars` against the template's secret env allowlist.
///
/// Templates without an allowlist ([`TemplatedExecId::rotation_secret_env`] is `None`) must carry
/// no secret env at all.
///
/// # Errors
///
/// `secret_env_not_allowed` / `secret_env_name_not_allowed` / `secret_env_duplicate` /
/// `secret_env_empty` / `secret_env_missing` / `secret_env_value_invalid`, or the newline and
/// name checks from [`validate_deploy_secret_env_entry`]. Messages never include values.
pub(crate) fn validate_rotation_secret_env(
    template: TemplatedExecId,
    vars: &[SecretEnvVar],
) -> anyhow::Result<()> {
    let Some((required, optional)) = template.rotation_secret_env() else {
        if !vars.is_empty() {
            anyhow::bail!("secret_env_not_allowed");
        }
        return Ok(());
    };
    let mut seen: Vec<&str> = Vec::with_capacity(vars.len());
    for v in vars {
        let name = v.name.trim();
        if !required.contains(&name) && !optional.contains(&name) {
            anyhow::bail!("secret_env_name_not_allowed: {name}");
        }
        if seen.contains(&name) {
            anyhow::bail!("secret_env_duplicate: {name}");
        }
        validate_deploy_secret_env_entry(name, v.value.as_str())?;
        if v.value.is_empty() {
            anyhow::bail!("secret_env_empty: {name}");
        }
        if matches!(template, TemplatedExecId::ChRotatePassword)
            && name == ROTATE_NEW_PASSWORD_ENV
            && v.value.contains("]]>")
        {
            anyhow::bail!("secret_env_value_invalid: {name}");
        }
        seen.push(name);
    }
    for name in required {
        if !seen.contains(name) {
            anyhow::bail!("secret_env_missing: {name}");
        }
    }
    Ok(())
}

/// Build the `docker exec` argv for a rotation template (`env_file` when it carries secret env).
#[must_use]
pub(crate) fn rotation_exec_argv(
    container_ref: &str,
    id: TemplatedExecId,
    env_file: Option<&Path>,
) -> Vec<String> {
    let mut argv = vec!["exec".to_string()];
    if let Some(path) = env_file {
        argv.push("--env-file".into());
        argv.push(path.display().to_string());
    }
    argv.push(container_ref.to_string());
    match id {
        TemplatedExecId::PgRotatePassword => {
            argv.extend(["sh".into(), "-c".into(), PG_ROTATE_SCRIPT.into()]);
        }
        TemplatedExecId::RedisRotatePassword => {
            argv.extend(["sh".into(), "-c".into(), REDIS_ROTATE_SCRIPT.into()]);
        }
        TemplatedExecId::MongoChangeUserPassword => {
            argv.extend([
                "mongosh".into(),
                "--quiet".into(),
                "--eval".into(),
                MONGO_ROTATE_EVAL.into(),
            ]);
        }
        TemplatedExecId::ChRotatePassword => {
            argv.extend(["sh".into(), "-c".into(), ch_rotate_script()]);
        }
        // Scratch image: no shell, the binary sits at the root.
        TemplatedExecId::NatsAuthReload => {
            argv.extend(["/nats-server".into(), "--signal".into(), "reload=1".into()]);
        }
        _ => return Vec::new(),
    }
    argv
}

/// Short-lived `docker exec --env-file`, removed on drop.
pub(crate) struct RotationEnvFile {
    path: PathBuf,
}

impl RotationEnvFile {
    /// Write `request.secret_env_vars` as verbatim `NAME=value` lines to a new `0600` file.
    ///
    /// Docker's env-file parser takes everything after the first `=` literally, so values are not
    /// quoted. Call [`validate_rotation_secret_env`] first (it rejects newlines).
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be created or written.
    pub(crate) fn write(request: &ContainerActionRequest) -> anyhow::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "parton-rotate-secret-env-{}-{}.env",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&path)
            .with_context(|| format!("create rotate secret env file {}", path.display()))?;
        // Own the path from here so a failed write still removes it.
        let env_file = Self { path };
        let mut contents = String::new();
        for v in &request.secret_env_vars {
            contents.push_str(v.name.trim());
            contents.push('=');
            contents.push_str(&v.value);
            contents.push('\n');
        }
        file.write_all(contents.as_bytes())
            .with_context(|| format!("write rotate secret env file {}", env_file.path.display()))?;
        Ok(env_file)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RotationEnvFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
