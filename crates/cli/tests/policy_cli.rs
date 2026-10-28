//! Offline diagnostics use only a synthetic config and envelope. No daemon/helper.
use std::{path::PathBuf, process::{Command, Output}};
struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("karambit-policy-{label}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("secrets/dev")).unwrap();
        let mut config = serde_json::to_value(karambit_core::Config::default()).unwrap();
        config["policy"] = serde_json::json!({"rules":[{"subject":{"secret":"dev/*"},"action":"get","who":"agent","effect":"allow"}]});
        std::fs::write(root.join("config.json"), config.to_string()).unwrap();
        // Envelope metadata only: deliberately not decryptable.
        std::fs::write(root.join("secrets/dev/item.json"), r#"{"v":2,"name":"dev/item","tier":"bio","eph":"","wrap_nonce":"","wrapped_dek":"","nonce":"","ct":"synthetic-never-output","created":0,"updated":0}"#).unwrap();
        Self(root)
    }
    /// Run with HOME and KARAMBIT_DIR pointing at a directory that does not exist (CI shape).
    fn run_without_vault(&self, args: &[&str]) -> Output {
        let home = self.0.join("no-home");
        Command::new(env!("CARGO_BIN_EXE_karambit")).args(args).env_clear()
            .env("HOME", &home).current_dir(&self.0).output().unwrap()
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_karambit")).args(args).env_clear()
            .env("HOME", &self.0).env("KARAMBIT_DIR", &self.0).current_dir(&self.0).output().unwrap()
    }
}
impl Drop for Fixture { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }
#[test]
fn policy_explain_test_validate_and_env_smoke() {
    let f = Fixture::new("smoke");
    let out = f.run(&["policy", "explain", "get", "dev/item", "--as", "agent:pi"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["rule_index"], 0);
    assert_eq!(result["reason_code"], "policy.rule_allow");
    assert_eq!(result["base_authorization_required"], true);
    assert!(f.run(&["policy", "validate"]).status.success());
    std::fs::write(f.0.join("cases.json"), r#"[{"action":"get","subject":"dev/item","as":"agent:pi","expected":"allow"}]"#).unwrap();
    assert!(f.run(&["policy", "test", "cases.json"]).status.success());
    std::fs::write(f.0.join(".karambit.env"), "# schema: ITEM required dev\n# schema: OTHER optional\nITEM=karambit:dev/item\n").unwrap();
    let out = f.run(&["env", "check"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("unverified"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("synthetic-never-output"));
    assert!(!f.0.join("run").exists());
    assert!(!f.0.join("audit.jsonl").exists());
}
#[test]
fn schema_missing_required_variable_is_error() {
    let f = Fixture::new("missing");
    std::fs::write(f.0.join(".karambit.env"), "# schema: ITEM required\n").unwrap();
    let out = f.run(&["env", "check"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("schema missing required variable: ITEM"));
}
#[test]
fn env_check_rejects_planted_code_loading_assignment() {
    let f = Fixture::new("code-loading");
    std::fs::write(f.0.join(".karambit.env"), "ITEM=karambit:dev/item\nNODE_OPTIONS=--require ./x.js\n").unwrap();
    let out = f.run(&["env", "check"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("NODE_OPTIONS can't be a plain value"), "{}", String::from_utf8_lossy(&out.stderr));
}

const POLICY: &str = r#"{"rules":[{"subject":{"secret":"dev/*"},"action":"get","who":"agent","effect":"deny"}]}"#;

#[test]
fn policy_commands_take_config_file_without_a_vault() {
    let f = Fixture::new("cfgfile");
    std::fs::write(f.0.join("bare.json"), POLICY).unwrap();
    std::fs::write(f.0.join("full.json"), format!(r#"{{"default_tier":"bio","policy":{POLICY}}}"#)).unwrap();
    std::fs::write(f.0.join("cases.json"), r#"[{"action":"get","subject":"dev/item","as":"agent:pi","expected":"deny"}]"#).unwrap();
    for file in ["bare.json", "full.json"] {
        let out = f.run_without_vault(&["policy", "validate", "--config", file]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let out = f.run_without_vault(&["policy", "test", "cases.json", "--config", file]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let out = f.run_without_vault(&["policy", "explain", "get", "dev/item", "--as", "agent:pi", "--config", file]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(result["effect"], "deny");
    }
    // The file's policy is used, not the vault's: its allow rule would fail this deny case.
    assert!(!f.run(&["policy", "test", "cases.json"]).status.success());
    // A wrong file is an error, not an empty (green) policy.
    std::fs::write(f.0.join("wrong.json"), r#"{"unrelated":1}"#).unwrap();
    assert!(!f.run_without_vault(&["policy", "validate", "--config", "wrong.json"]).status.success());
    assert!(!f.0.join("no-home").exists() && !f.0.join("run").exists() && !f.0.join("audit.jsonl").exists());
}

#[test]
fn env_check_offline_refs_reports_local_refs_unverified_without_a_vault() {
    let f = Fixture::new("offline-refs");
    std::fs::write(f.0.join(".karambit.env"), "# schema: ITEM required dev\nITEM=karambit:dev/missing\nOTHER=somesrc:x/y#z\n").unwrap();
    // Without the flag the missing local secret still fails; with it, it is only unverified.
    assert!(!f.run_without_vault(&["env", "check"]).status.success());
    let out = f.run_without_vault(&["env", "check", "--offline-refs"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<_> = report["variables"].as_array().unwrap().iter().map(|v| v["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["local_unverified", "backend_source_unverified"]);
    assert!(report["local_existence"].as_str().unwrap().starts_with("unverified"));
    // Schema errors are still errors.
    std::fs::write(f.0.join("bad.env"), "# schema: ITEM required\n").unwrap();
    assert!(!f.run_without_vault(&["env", "check", "bad.env", "--offline-refs"]).status.success());
    std::fs::write(f.0.join("badname.env"), "ITEM=karambit:../etc/passwd\n").unwrap();
    assert!(!f.run_without_vault(&["env", "check", "badname.env", "--offline-refs"]).status.success());
    assert!(!f.0.join("no-home").exists() && !f.0.join("run").exists() && !f.0.join("audit.jsonl").exists());
}

#[test]
fn policy_test_live_fails_without_a_running_daemon_and_never_starts_one() {
    let f = Fixture::new("live");
    std::fs::write(f.0.join("cases.json"), r#"[{"action":"get","subject":"dev/item","as":"agent:pi","expected":"allow"}]"#).unwrap();
    let out = f.run(&["policy", "test", "cases.json", "--live"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no running daemon"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!f.0.join("run").exists(), "--live must not spawn a daemon");
}
