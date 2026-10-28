//! Synthetic paired Mode B probes. No daemon, installed helper or live secret paths.
#![cfg(target_os = "macos")]
use karambit_core::sandbox::{Jail, NativeSandbox, Sandbox};
use std::{path::PathBuf, process::{Command, Output}, os::unix::process::CommandExt};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("karambit-jail-{label}-{}", std::process::id()));
        std::fs::create_dir_all(path.join("home")).unwrap();
        std::fs::create_dir_all(path.join("vault/keys")).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn run(&self, jailed: bool, script: &str, allowed: &str) -> Output {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "jail_probe_child", "--nocapture"])
            .env_clear().env("PATH", "/usr/bin:/bin")
            .env("HOME", self.0.join("home"))
            .env("JAIL_FIXTURE", &self.0).env("JAIL_SCRIPT", script)
            .env("JAIL_ENABLED", if jailed { "1" } else { "0" })
            .env("JAIL_ALLOWED", allowed).output().unwrap()
    }
    fn pair(&self, script: &str) {
        let outside = self.run(false, script, "");
        assert!(outside.status.success(), "outside prerequisite failed (inconclusive): {}", String::from_utf8_lossy(&outside.stderr));
        let inside = self.run(true, script, "");
        assert!(!inside.status.success(), "operation escaped confinement");
        assert!(!String::from_utf8_lossy(&inside.stderr).contains("installation failed"), "profile failed, not an operation denial");
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[test]
fn jail_probe_child() {
    let Ok(root) = std::env::var("JAIL_FIXTURE") else { return; };
    let root = PathBuf::from(root);
    if std::env::var("JAIL_ENABLED").unwrap() == "1" {
        let allowed = std::env::var("JAIL_ALLOWED").unwrap();
        let hosts = if allowed.is_empty() { vec![] } else { vec![allowed] };
        NativeSandbox.apply(&Jail::new(&root.join("home"), &root.join("vault"), &hosts).unwrap()).unwrap();
    }
    let error = Command::new("/bin/sh").args(["-c", &std::env::var("JAIL_SCRIPT").unwrap()]).exec();
    panic!("exec failed: {error}");
}

#[test]
fn jail_smoke_computation_and_allowed_listener() {
    let f = Fixture::new("smoke");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let script = format!("test $((6*7)) = 42 && /usr/bin/nc -z -w 2 127.0.0.1 {}", address.port());
    let result = f.run(true, &script, &address.to_string());
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
}

#[test]
fn jail_file_read_paired() {
    let f = Fixture::new("files");
    for path in ["vault/keys/blob", "home/.local/share/karambit/canary", "home/.vault-token", "home/.aws/canary", "home/.ssh/canary", "home/.kube/canary"] {
        let path = f.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "synthetic-file-canary").unwrap();
        f.pair(&format!("/bin/cat '{}'", path.display()));
    }
}

#[test]
fn jail_sibling_child() {
    if std::env::var_os("JAIL_SYNTHETIC_CANARY").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

#[test]
fn jail_sibling_env_paired() {
    let f = Fixture::new("sibling");
    let mut sibling = Command::new(std::env::current_exe().unwrap()).args(["--exact", "jail_sibling_child"]).env_clear()
        .env("JAIL_SYNTHETIC_CANARY", "sibling-proof").spawn().unwrap();
    let script = format!("/bin/ps -E -ww -p {} -o command= | /usr/bin/grep -q JAIL_SYNTHETIC_CANARY=sibling-proof", sibling.id());
    let outside = f.run(false, &script, "");
    let inside = f.run(true, &script, "");
    let _ = sibling.kill(); let _ = sibling.wait();
    assert!(outside.status.success(), "sibling outside prerequisite failed: inconclusive");
    assert!(!inside.status.success(), "sibling environment escaped confinement");
}

#[test]
fn jail_egress_and_open_paired() {
    let f = Fixture::new("egress");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    f.pair(&format!("/usr/bin/nc -z -w 2 127.0.0.1 {}", listener.local_addr().unwrap().port()));

    // Explicit local harmless application; never invoke the user's URL handler.
    let app = f.0.join("Harmless.app/Contents");
    std::fs::create_dir_all(app.join("MacOS")).unwrap();
    std::fs::write(app.join("Info.plist"), r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>handler</string><key>CFBundleIdentifier</key><string>test.karambit.jail.harmless</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>"#).unwrap();
    let marker = f.0.join("handler-ran");
    let source = f.0.join("handler.c");
    std::fs::write(&source, format!("#include <stdio.h>\nint main(void) {{ FILE *f = fopen(\"{}\", \"w\"); if (!f) return 1; fclose(f); return 0; }}", marker.display())).unwrap();
    let compile = Command::new("/usr/bin/clang").arg(&source).arg("-o").arg(app.join("MacOS/handler")).output().unwrap();
    assert!(compile.status.success(), "handler compiler prerequisite failed: inconclusive");
    let script = format!("/usr/bin/open -W -a '{}' 'http://127.0.0.1:{}/jail-probe'", app.parent().unwrap().display(), listener.local_addr().unwrap().port());
    let outside = f.run(false, &script, "");
    assert!(outside.status.success() && marker.exists(), "harmless open prerequisite failed: inconclusive: {}", String::from_utf8_lossy(&outside.stderr));
    std::fs::remove_file(&marker).unwrap();
    let inside = f.run(true, &script, "");
    assert!(!inside.status.success() && !marker.exists(), "open escaped confinement");
}
