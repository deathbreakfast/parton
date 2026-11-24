use super::*;
use crate::actions::types::{
    SecretEnvVar, TemplatedExecParams, TemplatedExecSpec, ROTATE_NEW_PASSWORD_ENV,
    ROTATE_OLD_PASSWORD_ENV,
};
use runner::CommandOutput;
use std::cell::RefCell;

const NEW_PW: &str = "n3w-S3ntinel $pw#\"'\\";
const OLD_PW: &str = "0ld-S3ntinel `x` %s";

const ROTATION_TEMPLATES: [TemplatedExecId; 5] = [
    TemplatedExecId::PgRotatePassword,
    TemplatedExecId::RedisRotatePassword,
    TemplatedExecId::MongoChangeUserPassword,
    TemplatedExecId::ChRotatePassword,
    TemplatedExecId::NatsAuthReload,
];

/// Records argv and the `--env-file` contents while the file still exists.
struct EnvFileRunner {
    output: CommandOutput,
    seen: RefCell<Vec<Vec<String>>>,
    env_files: RefCell<Vec<(String, String)>>,
}

impl EnvFileRunner {
    fn new(status_success: bool, stdout: &str, stderr: &str) -> Self {
        Self {
            output: CommandOutput {
                status_success,
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
            seen: RefCell::new(vec![]),
            env_files: RefCell::new(vec![]),
        }
    }
}

impl DockerCliRunner for EnvFileRunner {
    fn run(&self, args: &[String]) -> anyhow::Result<CommandOutput> {
        self.seen.borrow_mut().push(args.to_vec());
        if let Some(i) = args.iter().position(|a| a == "--env-file") {
            let path = args[i + 1].clone();
            let contents = std::fs::read_to_string(&path)?;
            self.env_files.borrow_mut().push((path, contents));
        }
        Ok(self.output.clone())
    }
}

fn secret(name: &str, value: &str) -> SecretEnvVar {
    SecretEnvVar {
        name: name.into(),
        value: value.into(),
    }
}

fn both_passwords() -> Vec<SecretEnvVar> {
    vec![
        secret(ROTATE_NEW_PASSWORD_ENV, NEW_PW),
        secret(ROTATE_OLD_PASSWORD_ENV, OLD_PW),
    ]
}

fn secrets_for(template: TemplatedExecId) -> Vec<SecretEnvVar> {
    if matches!(template, TemplatedExecId::NatsAuthReload) {
        vec![]
    } else {
        both_passwords()
    }
}

fn request(
    template: TemplatedExecId,
    secret_env_vars: Vec<SecretEnvVar>,
) -> ContainerActionRequest {
    ContainerActionRequest {
        node_id: "n1".into(),
        container_ref: "engine-1".into(),
        action: ContainerActionKind::TemplatedExec,
        tail_lines: None,
        image_ref: None,
        env_vars: vec![],
        secret_env_vars,
        port_mappings: vec![],
        entrypoint: None,
        command: vec![],
        restart_policy: None,
        volume_mounts: vec![],
        resource_limits: None,
        health_check: None,
        labels: std::collections::HashMap::default(),
        extra_hosts: vec![],
        network: None,
        diagnostic: None,
        wireguard_peer: None,
        grow_fs: None,
        templated_exec: Some(TemplatedExecSpec {
            template,
            params: TemplatedExecParams::default(),
        }),
        expected_container_id: None,
    }
}

fn run_ok(template: TemplatedExecId) -> (ContainerActionResponse, EnvFileRunner) {
    let runner = EnvFileRunner::new(true, "OK", "");
    let resp =
        run_templated_exec_with(&request(template, secrets_for(template)), &runner).expect("resp");
    (resp, runner)
}

fn argv_of(runner: &EnvFileRunner) -> Vec<String> {
    let seen = runner.seen.borrow();
    assert_eq!(seen.len(), 1, "one docker call");
    seen[0].clone()
}

#[test]
fn rotation_templates_never_put_passwords_in_argv_or_response() {
    for template in ROTATION_TEMPLATES {
        let (resp, runner) = run_ok(template);
        assert!(resp.success, "{template:?}: {}", resp.message);
        for arg in argv_of(&runner) {
            for pw in [NEW_PW, OLD_PW] {
                assert!(
                    !arg.contains(pw),
                    "{template:?} argv leaks a password: {arg}"
                );
            }
        }
        let resp_json = serde_json::to_string(&resp).expect("json");
        assert!(!resp_json.contains(NEW_PW) && !resp_json.contains(OLD_PW));
    }
}

#[test]
fn rotation_env_file_is_verbatim_and_removed_after_success() {
    let (_, runner) = run_ok(TemplatedExecId::RedisRotatePassword);
    let argv = argv_of(&runner);
    assert_eq!(&argv[..2], ["exec", "--env-file"]);
    assert_eq!(argv[3], "engine-1");
    let files = runner.env_files.borrow();
    let (path, contents) = &files[0];
    assert_eq!(
        contents,
        &format!("{ROTATE_NEW_PASSWORD_ENV}={NEW_PW}\n{ROTATE_OLD_PASSWORD_ENV}={OLD_PW}\n")
    );
    assert!(!std::path::Path::new(path).exists(), "env file removed");
}

#[cfg(unix)]
#[test]
fn rotation_env_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    struct ModeRunner(RefCell<u32>);
    impl DockerCliRunner for ModeRunner {
        fn run(&self, args: &[String]) -> anyhow::Result<CommandOutput> {
            let i = args
                .iter()
                .position(|a| a == "--env-file")
                .expect("env file");
            *self.0.borrow_mut() = std::fs::metadata(&args[i + 1])?.permissions().mode() & 0o777;
            Ok(CommandOutput {
                status_success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }
    let runner = ModeRunner(RefCell::new(0));
    run_templated_exec_with(
        &request(TemplatedExecId::PgRotatePassword, both_passwords()),
        &runner,
    )
    .expect("resp");
    assert_eq!(*runner.0.borrow(), 0o600);
}

#[test]
fn rotation_env_file_is_removed_when_docker_fails_to_spawn() {
    struct FailRunner(RefCell<String>);
    impl DockerCliRunner for FailRunner {
        fn run(&self, args: &[String]) -> anyhow::Result<CommandOutput> {
            let i = args
                .iter()
                .position(|a| a == "--env-file")
                .expect("env file");
            *self.0.borrow_mut() = args[i + 1].clone();
            anyhow::bail!("failed to spawn docker")
        }
    }
    let runner = FailRunner(RefCell::new(String::new()));
    run_templated_exec_with(
        &request(TemplatedExecId::MongoChangeUserPassword, both_passwords()),
        &runner,
    )
    .expect_err("spawn");
    let path = runner.0.borrow().clone();
    assert_ne!(path, "");
    assert!(!std::path::Path::new(&path).exists(), "env file removed");
}

#[test]
fn pg_rotate_renders_both_roles_via_getenv() {
    let (resp, runner) = run_ok(TemplatedExecId::PgRotatePassword);
    assert_eq!(resp.message, "pg_rotate_password ok");
    let argv = argv_of(&runner);
    assert_eq!(&argv[4..6], ["sh", "-c"]);
    let script = &argv[6];
    assert!(script.contains(r"\getenv pw PARTON_ROTATE_NEW_PASSWORD"));
    assert!(script.contains("ALTER ROLE nucleus PASSWORD :'pw';"));
    assert!(script.contains("ALTER ROLE nucleus_repl PASSWORD :'pw';"));
    assert!(script.contains(r"\if :has_repl"));
    assert!(
        script.contains("<<'SQL'"),
        "quoted heredoc: no shell expansion"
    );
}

#[test]
fn redis_rotate_sets_masterauth_before_requirepass_over_stdin() {
    let (resp, runner) = run_ok(TemplatedExecId::RedisRotatePassword);
    assert_eq!(resp.message, "redis_rotate_password ok");
    let script = &argv_of(&runner)[6];
    assert!(script.contains("for key in masterauth requirepass"));
    assert!(script.contains("redis-cli -x CONFIG SET"));
    assert!(script.contains(r#"REDISCLI_AUTH="$PARTON_ROTATE_OLD_PASSWORD""#));
    assert!(!script.contains(" -a "), "no password flag");
}

#[test]
fn mongo_change_user_password_renders_eval() {
    let (resp, runner) = run_ok(TemplatedExecId::MongoChangeUserPassword);
    assert_eq!(resp.message, "mongo_change_user_password ok");
    let argv = argv_of(&runner);
    assert_eq!(&argv[4..7], ["mongosh", "--quiet", "--eval"]);
    assert!(argv[7]
        .contains("admin.changeUserPassword('nucleus', process.env.PARTON_ROTATE_NEW_PASSWORD)"));
    assert!(argv[7].contains("process.env.PARTON_ROTATE_OLD_PASSWORD"));
}

#[test]
fn mongo_change_user_password_not_primary_message() {
    let runner = EnvFileRunner::new(false, "", "MongoServerError: not primary");
    let resp = run_templated_exec_with(
        &request(TemplatedExecId::MongoChangeUserPassword, both_passwords()),
        &runner,
    )
    .expect("resp");
    assert!(!resp.success);
    assert_eq!(resp.message, "mongo_change_user_password not_primary");
}

#[test]
fn ch_rotate_writes_users_d_override() {
    let (resp, runner) = run_ok(TemplatedExecId::ChRotatePassword);
    assert_eq!(resp.message, "ch_rotate_password ok");
    let script = &argv_of(&runner)[6];
    assert!(script.contains("/etc/clickhouse-server/users.d/zz-nucleus-rotated-password.xml"));
    assert!(script.contains("<![CDATA[%s]]>"));
    assert!(script.contains(r#""$PARTON_ROTATE_NEW_PASSWORD""#));
}

#[test]
fn nats_auth_reload_signals_pid_one_without_env_file() {
    let (resp, runner) = run_ok(TemplatedExecId::NatsAuthReload);
    assert_eq!(resp.message, "nats_auth_reload ok");
    assert_eq!(
        argv_of(&runner),
        ["exec", "engine-1", "/nats-server", "--signal", "reload=1"]
    );
}

#[test]
fn rotation_failure_reports_static_message() {
    let runner = EnvFileRunner::new(false, "", "CONFIG SET masterauth: ERR something");
    let resp = run_templated_exec_with(
        &request(TemplatedExecId::RedisRotatePassword, both_passwords()),
        &runner,
    )
    .expect("resp");
    assert!(!resp.success);
    assert_eq!(resp.message, "redis_rotate_password failed");
}

fn assert_rejected(template: TemplatedExecId, vars: Vec<SecretEnvVar>, want: &str) {
    let runner = EnvFileRunner::new(true, "OK", "");
    let err = run_templated_exec_with(&request(template, vars), &runner).expect_err(want);
    let msg = err.to_string();
    assert!(msg.contains(want), "{template:?}: {msg}");
    assert!(
        !msg.contains(NEW_PW) && !msg.contains(OLD_PW),
        "error leaks a value"
    );
    assert!(runner.seen.borrow().is_empty(), "docker must not run");
}

#[test]
fn allowlist_rejects_unknown_secret_name() {
    let mut vars = both_passwords();
    vars.push(secret("PGPASSWORD", NEW_PW));
    assert_rejected(
        TemplatedExecId::PgRotatePassword,
        vars,
        "secret_env_name_not_allowed",
    );
}

#[test]
fn allowlist_rejects_missing_new_password() {
    for template in [
        TemplatedExecId::PgRotatePassword,
        TemplatedExecId::RedisRotatePassword,
        TemplatedExecId::MongoChangeUserPassword,
        TemplatedExecId::ChRotatePassword,
    ] {
        assert_rejected(
            template,
            vec![secret(ROTATE_OLD_PASSWORD_ENV, OLD_PW)],
            "secret_env_missing: PARTON_ROTATE_NEW_PASSWORD",
        );
    }
}

#[test]
fn allowlist_requires_old_password_for_redis_and_mongo() {
    for template in [
        TemplatedExecId::RedisRotatePassword,
        TemplatedExecId::MongoChangeUserPassword,
    ] {
        assert_rejected(
            template,
            vec![secret(ROTATE_NEW_PASSWORD_ENV, NEW_PW)],
            "secret_env_missing: PARTON_ROTATE_OLD_PASSWORD",
        );
    }
}

#[test]
fn allowlist_old_password_optional_for_pg_and_clickhouse() {
    for template in [
        TemplatedExecId::PgRotatePassword,
        TemplatedExecId::ChRotatePassword,
    ] {
        let runner = EnvFileRunner::new(true, "", "");
        let resp = run_templated_exec_with(
            &request(template, vec![secret(ROTATE_NEW_PASSWORD_ENV, NEW_PW)]),
            &runner,
        )
        .expect("resp");
        assert!(resp.success);
    }
}

#[test]
fn allowlist_rejects_duplicate_and_empty_values() {
    assert_rejected(
        TemplatedExecId::PgRotatePassword,
        vec![
            secret(ROTATE_NEW_PASSWORD_ENV, NEW_PW),
            secret(ROTATE_NEW_PASSWORD_ENV, OLD_PW),
        ],
        "secret_env_duplicate",
    );
    assert_rejected(
        TemplatedExecId::PgRotatePassword,
        vec![secret(ROTATE_NEW_PASSWORD_ENV, "")],
        "secret_env_empty",
    );
}

#[test]
fn allowlist_rejects_newline_in_value() {
    assert_rejected(
        TemplatedExecId::PgRotatePassword,
        vec![secret(ROTATE_NEW_PASSWORD_ENV, "a\nb")],
        "newline",
    );
}

#[test]
fn allowlist_rejects_cdata_terminator_for_clickhouse() {
    assert_rejected(
        TemplatedExecId::ChRotatePassword,
        vec![secret(ROTATE_NEW_PASSWORD_ENV, "abc]]>def")],
        "secret_env_value_invalid",
    );
}

#[test]
fn allowlist_rejects_secret_env_on_nats_and_non_rotation_templates() {
    assert_rejected(
        TemplatedExecId::NatsAuthReload,
        vec![secret(ROTATE_NEW_PASSWORD_ENV, NEW_PW)],
        "secret_env_name_not_allowed",
    );
    for template in [
        TemplatedExecId::PgPromote,
        TemplatedExecId::RedisReplicaofNoOne,
        TemplatedExecId::MongoRsStepDown,
    ] {
        assert_rejected(template, both_passwords(), "secret_env_not_allowed");
    }
}

#[test]
fn rotation_templates_round_trip_wire_labels() {
    for template in ROTATION_TEMPLATES {
        let wire = serde_json::to_value(template).expect("ser");
        assert_eq!(wire, serde_json::json!(template.as_str()));
        let back: TemplatedExecId = serde_json::from_value(wire).expect("de");
        assert_eq!(back, template);
    }
    let unknown: Result<TemplatedExecId, _> =
        serde_json::from_value(serde_json::json!("pg_alter_role_free_text"));
    assert!(unknown.is_err());
}
