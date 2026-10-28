//! `karambit secure --dry-run`: synthetic project, synthetic vault markers. No daemon,
//! helper, Touch ID or network. Values below are fake and must never be printed.
use std::{path::PathBuf, process::{Command, Output}};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("karambit-secure-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("vault/keys")).unwrap();
        std::fs::create_dir_all(root.join("myapp")).unwrap();
        std::fs::write(root.join("vault/config.json"), serde_json::to_string(&karambit_core::Config::default()).unwrap()).unwrap();
        for k in ["bio.key", "open.key"] { std::fs::write(root.join("vault/keys").join(k), b"synthetic").unwrap(); }
        let app = root.join("myapp");
        std::fs::write(app.join(".env"), "PORT=3000\nSTRIPE_SECRET_KEY=FAKE-STRIPE-VALUE123\nDATABASE_URL=postgres://u:FAKEPW@localhost/app\nAPP_URL=http://localhost:${PORT}\n").unwrap();
        std::fs::write(app.join(".env.local"), "GITHUB_TOKEN=ghp_FAKEVALUE\n").unwrap();
        std::fs::write(app.join(".env.example"), "STRIPE_SECRET_KEY=\n").unwrap();
        std::fs::write(app.join("package.json"), "{\n  \"name\": \"myapp\",\n  \"scripts\": {\n    \"dev\": \"next dev\",\n    \"lint\": \"eslint .\"\n  }\n}\n").unwrap();
        Self(root)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_karambit")).args(args).env_clear()
            .env("HOME", &self.0).env("PATH", "/usr/bin:/bin").env("KARAMBIT_DIR", self.0.join("vault"))
            .current_dir(self.0.join("myapp")).output().unwrap()
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[test]
fn dry_run_previews_names_only_and_changes_nothing() {
    let f = Fixture::new("dry");
    let app = f.0.join("myapp");
    let before: Vec<_> = [".env", ".env.local", "package.json"].iter().map(|n| std::fs::read(app.join(n)).unwrap()).collect();
    let out = f.run(&["secure", "--dry-run"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    for leak in ["FAKEVALUE", "FAKEPW", "FAKE-STRIPE"] {
        assert!(!stdout.contains(leak) && !stderr.contains(leak), "value leaked: {leak}\n{stdout}\n{stderr}");
    }
    assert!(stdout.contains("myapp/STRIPE_SECRET_KEY") && stdout.contains("myapp/GITHUB_TOKEN") && stdout.contains("myapp/DATABASE_URL"), "{stdout}");
    assert!(stdout.contains("PORT") && stdout.contains("plain"));
    assert!(stdout.contains("myapp/_archive/1/env-local"));
    assert!(stdout.contains("package.json: prefix dev"), "{stdout}");
    assert!(!stdout.contains(".env.example"), "examples are not touched");
    let after: Vec<_> = [".env", ".env.local", "package.json"].iter().map(|n| std::fs::read(app.join(n)).unwrap()).collect();
    assert_eq!(before, after, "dry run changed files");
    assert!(!app.join(".env.schema").exists());
    assert!(!f.0.join("vault/run").exists(), "no daemon request");
}

#[test]
fn agents_are_refused_and_nothing_changes() {
    // This suite runs under an agent harness or not; either way a write must be refused
    // (fence for agents, no-TTY for humans) and the plaintext must stay put.
    let f = Fixture::new("refuse");
    for args in [&["eat", "."][..], &["secure"], &["secure", "rebuild"]] {
        let out = f.run(args);
        assert!(!out.status.success(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("human-only") || err.contains("--yes") || err.contains("no .env.schema"), "{args:?}: {err}");
    }
    assert!(f.0.join("myapp/.env").exists() && f.0.join("myapp/.env.local").exists(), "nothing deleted");
    assert!(!f.0.join("myapp/.env.schema").exists());
}
