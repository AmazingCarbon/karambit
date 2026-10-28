//! `karambit doctor --agent-env` end to end: the cargo-built CLI, synthetic HOME / KARAMBIT_DIR /
//! TMPDIR only. No daemon is started, no live vault is read. The generated canary is never exposed
//! to these tests (no env hook, no file): they assert that no canary-shaped run (64 hex chars, or the
//! 44-char base64 of 32 bytes, or the 20-char prefix of a hex run) appears in stdout/stderr. The
//! deterministic no-leak proof with the known canary lives in the `doctor.rs` unit tests.
//! Valid under `cargo test` and `cargo test --release`.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Sandbox {
        // Short path: the test socket must fit in sockaddr_un.
        let root = PathBuf::from("/tmp").join(format!("kdc-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["home", "vault/keys", "tmp"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("vault/audit.jsonl"), b"{}\n").unwrap();
        std::fs::write(root.join("vault/config.json"), serde_json::to_vec(&karambit_core::Config::default()).unwrap()).unwrap();
        Sandbox { root }
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_karambit"));
        c.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.root.join("home"))
            .env("KARAMBIT_DIR", self.root.join("vault"))
            .env("TMPDIR", self.root.join("tmp"))
            // Integration tests never compile or run the Secure Enclave probe.
            .env("KARAMBIT_DOCTOR_SKIP_KEY_PROBE", "1");
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }
    fn scratch_dirs(&self) -> Vec<String> {
        std::fs::read_dir(self.root.join("tmp")).unwrap().flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("karambit-doctor-")).collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        fn unlock(p: &Path) {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        unlock(&e.path())
                    }
                }
            }
        }
        unlock(&self.root);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn all_output(o: &Output) -> Vec<u8> {
    let mut v = o.stdout.clone();
    v.extend_from_slice(&o.stderr);
    v
}

/// Longest run of bytes satisfying `pred` in `hay`.
fn longest_run(hay: &[u8], pred: impl Fn(u8) -> bool) -> usize {
    let (mut best, mut cur) = (0, 0);
    for &b in hay {
        cur = if pred(b) { cur + 1 } else { 0 };
        best = best.max(cur);
    }
    best
}

/// Nothing shaped like the generated canary (or a 20-char prefix of it) appears. Hex runs of 20+
/// (which would include the 20-char truncation) and base64-alphabet runs of 44+ chars are
/// rejected (the canary is 64 hex chars; its base64 is 88). The canary NAME (`doctor/canary-` +
/// 12 hex) is allowed and is shorter than both thresholds. This is a heuristic backstop only: the
/// exact-value no-leak proof is the `collect_never_renders_the_canary…` unit test. The
/// `caller-agent` row is excluded because it echoes unconstrained caller process names (argv),
/// which may legitimately contain long hex/base64-like runs.
fn assert_no_canary_shape(out: &[u8]) {
    let text = String::from_utf8_lossy(out);
    let filtered: String = text.lines()
        .filter(|l| !l.trim_start().starts_with("caller-agent") && !l.contains("\"name\": \"caller-agent\""))
        .collect::<Vec<_>>().join("\n");
    let out = filtered.as_bytes();
    let hex = longest_run(out, |b| b.is_ascii_hexdigit());
    assert!(hex < 20, "a {hex}-char hex run (canary-shaped) appears in the output");
    let b64 = longest_run(out, |b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
    assert!(b64 < 44, "a {b64}-char base64-shaped run appears in the output");
}

#[test]
fn doctor_table_never_prints_the_canary_and_cleans_up() {
    let sb = Sandbox::new("table");
    let o = sb.run(&["doctor", "--agent-env"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_no_canary_shape(&all_output(&o));
    for row in ["sibling-env-ps", "vault-token", "key-blob-use", "daemon-socket", "audit-config-pin-writable", "redaction", "caller-agent"] {
        assert!(text.lines().any(|l| l.starts_with(row)), "missing row {row}:\n{text}");
    }
    assert!(text.lines().any(|l| l.starts_with("check") && l.contains("status") && l.contains("why")));
    assert!(text.lines().any(|l| l.starts_with("key-blob-use") && l.contains("unsupported") && l.contains("key-use probe skipped by KARAMBIT_DOCTOR_SKIP_KEY_PROBE")));
    assert!(text.lines().any(|l| l.starts_with("vault-token") && l.contains("pass")));
    assert!(text.lines().any(|l| l.starts_with("daemon-socket") && l.contains("inconclusive")));
    assert!(text.lines().any(|l| l.starts_with("redaction") && l.contains("fail") && l.contains("base64")));
    assert_eq!(text.lines().last(), Some("scope: this run only"));
    assert!(sb.scratch_dirs().is_empty(), "scratch dir survived: {:?}", sb.scratch_dirs());
    assert!(!sb.root.join("vault/run").exists(), "doctor must not start a daemon or create run/");
}

#[test]
fn doctor_json_has_checks_scope_and_no_canary() {
    let sb = Sandbox::new("json");
    let o = sb.run(&["doctor", "--agent-env", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let mut v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    {
        // Shape-check everything except the caller-agent why (unconstrained caller argv).
        let mut stripped = v.clone();
        for c in stripped["checks"].as_array_mut().unwrap() {
            if c["name"] == "caller-agent" { c["why"] = serde_json::Value::String(String::new()); }
        }
        let mut bytes = serde_json::to_vec(&stripped).unwrap();
        bytes.extend_from_slice(&o.stderr);
        assert_no_canary_shape(&bytes);
    }
    let v = std::mem::take(&mut v);
    assert_eq!(v["scope"], "this run only");
    let checks = v["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 9);
    for c in checks {
        assert!(["pass", "fail", "inconclusive", "unsupported"].contains(&c["status"].as_str().unwrap()));
        assert!(!c["why"].as_str().unwrap().is_empty());
    }
    let key = checks.iter().find(|c| c["name"] == "key-blob-use").unwrap();
    assert_eq!(key["status"], "unsupported");
    assert_eq!(key["why"], "key-use probe skipped by KARAMBIT_DOCTOR_SKIP_KEY_PROBE");
    assert!(sb.scratch_dirs().is_empty());
}

#[test]
fn doctor_defaults_to_agent_env() {
    let sb = Sandbox::new("flag");
    // `doctor` alone runs the only mode (agent env); same as `doctor --agent-env`.
    assert!(sb.run(&["doctor"]).status.success());
}

#[test]
fn doctor_never_opens_the_vault_token_and_sends_nothing_to_the_socket() {
    let sb = Sandbox::new("token");
    // A FIFO with no writer blocks any open-for-read forever.
    let token = std::ffi::CString::new(sb.root.join("home/.vault-token").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(token.as_ptr(), 0o600) }, 0);
    // A test listener on the vault's socket path stands in for the daemon; it records every byte received.
    std::fs::create_dir_all(sb.root.join("vault/run")).unwrap();
    let listener = UnixListener::bind(sb.root.join("vault/run/d.sock")).unwrap();
    let server = std::thread::spawn(move || {
        use std::io::Read;
        let (mut c, _) = listener.accept().unwrap();
        let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let mut received = Vec::new();
        let _ = c.read_to_end(&mut received);
        received
    });
    let mut cmd = sb.command(&["doctor", "--agent-env"]);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(cmd.output().unwrap()).unwrap());
    let o = rx.recv_timeout(std::time::Duration::from_secs(30)).expect("doctor blocked: it opened ~/.vault-token");
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(text.lines().any(|l| l.starts_with("vault-token") && l.contains("fail")), "{text}");
    assert!(text.lines().any(|l| l.starts_with("daemon-socket") && l.contains("pass") && l.contains("no request sent")), "{text}");
    assert!(!text.to_lowercase().contains("ping"), "{text}");
    assert_eq!(server.join().unwrap(), Vec::<u8>::new(), "the doctor sent bytes to the daemon socket");
    assert!(sb.scratch_dirs().is_empty());
}

#[test]
fn doctor_identifies_crash_leftovers_and_never_deletes_any_prefixed_dir() {
    let sb = Sandbox::new("left");
    let tmp = sb.root.join("tmp");
    // Exactly what a crashed doctor leaves: generated name grammar + marker file.
    let stale = tmp.join("karambit-doctor-999999-aaaaaaaaaaaa");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join(".karambit-doctor"), "karambit-doctor v1 pid=999999 start=1 nonce=aaaaaaaaaaaa\n").unwrap();
    // Prefix only, or right name without the marker: not ours.
    let foreign = tmp.join("karambit-doctor-crashed");
    let unmarked = tmp.join("karambit-doctor-999998-bbbbbbbbbbbb");
    for d in [&foreign, &unmarked] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("keep"), b"user data").unwrap();
    }
    let o = sb.run(&["doctor", "--agent-env"]);
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(text.contains("leftover karambit-doctor-999999-aaaaaaaaaaaa: crash leftover from an earlier doctor run; delete it by hand"), "{text}");
    assert!(text.contains("leftover karambit-doctor-crashed: not doctor-owned, left in place"), "{text}");
    assert!(text.contains("leftover karambit-doctor-999998-bbbbbbbbbbbb: not doctor-owned, left in place"), "{text}");
    // Report-only: even the genuine crash leftover is identified, not deleted.
    assert!(stale.join(".karambit-doctor").exists());
    for d in [&foreign, &unmarked] {
        assert_eq!(std::fs::read(d.join("keep")).unwrap(), b"user data");
    }
    let mut mine = sb.scratch_dirs();
    mine.sort();
    assert_eq!(mine, vec!["karambit-doctor-999998-bbbbbbbbbbbb", "karambit-doctor-999999-aaaaaaaaaaaa", "karambit-doctor-crashed"], "no scratch dir of this run may remain");
}

#[test]
fn doctor_ignores_the_old_canary_env_hook_and_never_writes_vault_files() {
    // The former KARAMBIT_DOCTOR_CANARY_OUT hook is gone: pointing it at a vault file must change nothing.
    let sb = Sandbox::new("nohook");
    let audit = sb.root.join("vault/audit.jsonl");
    let config = sb.root.join("vault/config.json");
    let (a0, c0) = (std::fs::read(&audit).unwrap(), std::fs::read(&config).unwrap());
    let link = sb.root.join("link-to-audit");
    std::os::unix::fs::symlink(&audit, &link).unwrap();
    for target in [&audit, &config, &link] {
        let o = sb.command(&["doctor", "--agent-env"]).env("KARAMBIT_DOCTOR_CANARY_OUT", target).output().unwrap();
        assert!(o.status.success());
    }
    assert_eq!(std::fs::read(&audit).unwrap(), a0);
    assert_eq!(std::fs::read(&config).unwrap(), c0);
    assert!(!sb.root.join("canary.out").exists());
}

#[test]
fn doctor_is_not_fenced_and_reports_the_detected_agent() {
    // doctor must stay runnable by an agent caller (it is how an agent environment is checked).
    let sb = Sandbox::new("agent");
    let o = sb.command(&["doctor", "--agent-env"]).env("PI_CODING_AGENT", "1").output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(text.lines().any(|l| l.starts_with("caller-agent") && l.contains("pass") && l.contains("agent detected: pi")), "{text}");
    assert!(!String::from_utf8_lossy(&o.stderr).contains("human-only"));
}

#[test]
fn canary_shape_check_tolerates_long_hex_caller_names() {
    // A direct parent whose process name is a long hex run must not trip the backstop heuristic.
    // A compiled fork/exec wrapper is used: a copied system binary would be killed by code signing,
    // and a symlink would report the target's name.
    let sb = Sandbox::new("hexcaller");
    let bin = sb.root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let src = bin.join("w.c");
    std::fs::write(&src, "#include <unistd.h>\n#include <sys/wait.h>\nint main(int c,char**v){pid_t p=fork();if(!p){execv(v[1],v+1);_exit(127);}int s;waitpid(p,&s,0);return WIFEXITED(s)?WEXITSTATUS(s):1;}\n").unwrap();
    let parent = bin.join("deadbeefdeadbeefdeadbeefdeadbeef");
    assert!(Command::new("cc").arg(&src).arg("-o").arg(&parent).status().unwrap().success());
    let c = sb.command(&["doctor", "--agent-env"]);
    let mut wrapped = Command::new(&parent);
    wrapped.arg(c.get_program()).args(c.get_args()).env_clear();
    for (k, v) in c.get_envs() { if let Some(v) = v { wrapped.env(k, v); } }
    let o = wrapped.output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(text.contains("deadbeefdeadbeefdeadbeefdeadbeef"), "fixture must put the hex name in the caller row: {text}");
    assert_no_canary_shape(&all_output(&o));
}
