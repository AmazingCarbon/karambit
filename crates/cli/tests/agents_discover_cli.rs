//! Read-only discovery works in an agent-marked, uninitialized synthetic HOME.
#[test]
fn agents_discover_json_smoke() {
    use std::{fs, process::Command};
    let home = std::env::temp_dir().join(format!("karambit-agents-cli-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".local/bin")).unwrap();
    fs::write(home.join(".local/bin/claude"), "").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_karambit"))
        .args(["agents", "discover", "--json"])
        .env_clear().env("HOME", &home).env("KARAMBIT_DIR", home.join("vault"))
        .env("PI_CODING_AGENT", "1").output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let rows: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(rows.as_array().unwrap().iter().any(|r| r["kind"] == "claude"));
    assert!(!home.join("vault").exists(), "discovery must not initialize a vault");
    fs::remove_dir_all(home).unwrap();
}
