//! Agent-mode CLI contract: exit 125 before launch, JSON errors, --status-fd, `help agent`,
//! `ls --brief`, generated help. Synthetic vault only; every case fails or finishes before
//! a daemon request, so no daemon, helper, Touch ID or network is used.
use std::{os::unix::process::CommandExt, path::PathBuf, process::{Command, Output}};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("karambit-agentmode-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("vault/keys")).unwrap();
        std::fs::create_dir_all(root.join("vault/secrets/dev")).unwrap();
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::write(root.join("vault/config.json"), serde_json::to_string(&karambit_core::Config::default()).unwrap()).unwrap();
        for k in ["bio.key", "open.key"] { std::fs::write(root.join("vault/keys").join(k), b"synthetic").unwrap(); }
        // Envelope metadata only: deliberately not decryptable.
        for (name, tier) in [("db", "open"), ("stripe", "bio")] {
            std::fs::write(root.join(format!("vault/secrets/dev/{name}.json")), format!(
                r#"{{"v":2,"name":"dev/{name}","tier":"{tier}","eph":"","wrap_nonce":"","wrapped_dek":"","nonce":"","ct":"synthetic-never-output","created":0,"updated":0}}"#)).unwrap();
        }
        Self(root)
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_karambit"));
        c.args(args).env_clear().env("HOME", &self.0).env("PATH", "/usr/bin:/bin")
            .env("KARAMBIT_DIR", self.0.join("vault")).current_dir(self.0.join("work"));
        c
    }
    fn run(&self, args: &[&str]) -> Output { self.cmd(args).output().unwrap() }
    /// Run with a pipe on fd 3; returns (output, what karambit wrote to fd 3).
    fn run_status(&self, args: &[&str]) -> (Output, String) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let mut c = self.cmd(args);
        unsafe { c.pre_exec(move || {
            if libc::dup2(w, 3) < 0 { return Err(std::io::Error::last_os_error()); }
            Ok(())
        }); }
        let out = c.output().unwrap();
        unsafe { libc::close(w) };
        let mut line = String::new();
        use std::{io::Read, os::fd::FromRawFd};
        unsafe { std::fs::File::from_raw_fd(r) }.read_to_string(&mut line).unwrap();
        (out, line)
    }
    fn daemon_untouched(&self) {
        assert!(!self.0.join("vault/run").exists(), "a daemon was started");
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

fn err_json(out: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stderr);
    let line = text.lines().find(|l| l.starts_with("{\"error\"")).unwrap_or_else(|| panic!("no JSON error in {text}"));
    serde_json::from_str::<serde_json::Value>(line).unwrap()["error"].clone()
}

#[test]
fn pre_launch_failures_exit_125_with_a_code() {
    let f = Fixture::new("codes");
    for (args, code) in [
        (&["run", "--json", "--aws", "nope", "--", "true"][..], "no_profile"),
        (&["run", "--json", "-e", "1BAD=dev/db", "--", "true"], "usage"),
        (&["run", "--json", "--bogus", "--", "true"], "usage"),
        (&["run", "--json"], "usage"),
        (&["aws", "--json", "nope", "--", "true"], "no_profile"),
        (&["aws", "--json", "nope", "true"], "usage"),
    ] {
        let out = f.run(args);
        assert_eq!(out.status.code(), Some(125), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        let e = err_json(&out);
        assert_eq!(e["code"], code, "{args:?}");
        assert_eq!(e["v"], 1);
        assert!(["no", "once", "after_user"].contains(&e["retry"].as_str().unwrap()));
        assert!(!e["next"].as_str().unwrap().is_empty());
    }
    // KARAMBIT_FORMAT=json selects JSON without --json; text mode keeps `next:`.
    let out = f.cmd(&["run", "--aws", "nope", "--", "true"]).env("KARAMBIT_FORMAT", "json").output().unwrap();
    assert_eq!(err_json(&out)["code"], "no_profile");
    let out = f.run(&["run", "--aws", "nope", "--", "true"]);
    assert_eq!(out.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&out.stderr).contains("next:"));
    // Outside `run`, a bad command line keeps clap's exit 2.
    assert_eq!(f.run(&["ls", "--bogus"]).status.code(), Some(2));
    f.daemon_untouched();
}

#[test]
fn status_fd_reports_refusal_and_cannot_share_stdout() {
    let f = Fixture::new("status");
    let (out, line) = f.run_status(&["run", "--status-fd", "3", "--aws", "nope", "--", "true"]);
    assert_eq!(out.status.code(), Some(125));
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["started"], false);
    assert_eq!(v["error"]["code"], "no_profile");
    assert_eq!(line.lines().count(), 1);
    // Clap errors still write the line.
    let (out, line) = f.run_status(&["run", "--status-fd", "3", "--bogus", "--", "true"]);
    assert_eq!(out.status.code(), Some(125));
    assert_eq!(serde_json::from_str::<serde_json::Value>(line.trim()).unwrap()["error"]["code"], "usage");
    // fd 0-2, closed fds, and a pipe that is also stdout are refused (the command could write it).
    for args in [&["run", "--json", "--status-fd", "1", "-e", "dev/db", "--", "true"][..], &["run", "--json", "--status-fd", "9", "-e", "dev/db", "--", "true"]] {
        let out = f.run(args);
        assert_eq!(out.status.code(), Some(125), "{args:?}");
        assert!(err_json(&out)["message"].as_str().unwrap().contains("status-fd"));
    }
    let mut c = f.cmd(&["run", "--json", "--status-fd", "3", "-e", "dev/db", "--", "true"]);
    unsafe { c.pre_exec(|| { if libc::dup2(1, 3) < 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
    let out = c.output().unwrap();
    assert_eq!(out.status.code(), Some(125));
    assert!(err_json(&out)["message"].as_str().unwrap().contains("same file as stdout"));
    f.daemon_untouched();
}

#[test]
fn ls_brief_and_compact_json() {
    let f = Fixture::new("ls");
    let out = f.run(&["ls", "--brief"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "dev/db\tagents\ndev/stripe\tagents-touch\n");
    let out = f.run(&["ls", "--brief", "--json"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), r#"[{"access":"agents","name":"dev/db"},{"access":"agents-touch","name":"dev/stripe"}]"#);
    // Full --json is one line (stdout is a pipe) and gains the access id.
    let out = f.run(&["ls", "--json"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v[1]["access"], "agents-touch");
    assert!(!text.contains("synthetic-never-output"));
    // --pretty indents.
    assert!(String::from_utf8_lossy(&f.run(&["ls", "--json", "--pretty"]).stdout).lines().count() > 2);
    f.daemon_untouched();
}

#[test]
fn help_agent_and_root_help() {
    let f = Fixture::new("help");
    let guide = f.run(&["help", "agent"]);
    assert!(guide.status.success());
    let text = String::from_utf8_lossy(&guide.stdout);
    assert!(text.starts_with("karambit agent guide v1"));
    for must in ["exit 125", "retry", "ask_user", "--status-fd", "needs_lease", "Never run it yourself"] {
        assert!(text.contains(must), "guide lacks {must}");
    }
    assert!(text.len() < 3200, "guide grew to {} bytes", text.len());
    // Root help lists every visible subcommand (the template is hand-written).
    let help = String::from_utf8_lossy(&f.run(&["--help"]).stdout).into_owned();
    for cmd in ["run", "ls", "secure", "add", "get", "rm", "policy", "lease", "block", "unblock", "status", "call", "aws", "login",
        "logout", "whoami", "sso", "env", "profile", "ref", "source", "init", "config", "agents", "helper", "keys", "backup",
        "recover", "doctor", "audit"] {
        assert!(help.lines().any(|l| l.trim_start().starts_with(&format!("{cmd} "))), "root help lacks {cmd}");
    }
    assert!(help.contains("karambit help agent"));
    f.daemon_untouched();
}

#[test]
fn call_list_shows_no_credentials() {
    let f = Fixture::new("call");
    let mut cfg = serde_json::to_value(karambit_core::Config::default()).unwrap();
    cfg["tools"] = serde_json::json!({"ci-status": {"host": "ci.example.com", "port": 443, "method": "GET",
        "path_template": "/job/{job}/lastBuild/api/json", "credential_ref": "ci/status-api", "credential_host": "ci.example.com"}});
    std::fs::write(f.0.join("vault/config.json"), cfg.to_string()).unwrap();
    let out = f.run(&["call", "--list", "--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v[0]["tool"], "ci-status");
    assert_eq!(v[0]["args"], serde_json::json!(["JOB"]));
    assert!(!text.contains("credential"), "{text}");
    assert_eq!(String::from_utf8_lossy(&f.run(&["call", "--list"]).stdout), "ci-status\tci.example.com\tJOB\n");
    f.daemon_untouched();
}
