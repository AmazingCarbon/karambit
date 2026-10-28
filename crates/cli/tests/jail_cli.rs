//! Production CLI/shim smoke, with an empty synthetic daemon and vault. No helper.
#![cfg(target_os = "macos")]
use std::{path::PathBuf, process::{Child, Command, Stdio}, time::{Duration, Instant}};
struct Fixture { root: PathBuf, daemon: Option<Child> }
impl Fixture {
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_karambit"));
        c.env_clear().env("HOME", self.root.join("home"))
            .env("KARAMBIT_DIR", self.root.join("vault"))
            .env("PATH", "/usr/bin:/bin").current_dir(&self.root);
        c
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.daemon { let _ = child.kill(); let _ = child.wait(); }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn run_jail_production_shim_smoke() {
    let mut f = Fixture { root: PathBuf::from(format!("/tmp/kj-cli-{}", std::process::id())), daemon: None };
    for path in ["vault/keys", "home"] { std::fs::create_dir_all(f.root.join(path)).unwrap(); }
    std::fs::write(f.root.join("vault/config.json"), serde_json::to_vec(&karambit_core::Config::default()).unwrap()).unwrap();
    // Synthetic pin, not `helper pin`, and no installed paths.
    let hash = karambit_core::helper::sha256_file(std::path::Path::new(env!("CARGO_BIN_EXE_karambit"))).unwrap();
    std::fs::write(f.root.join("vault/keys/daemon.sha256"), hash).unwrap();
    f.daemon = Some(f.command().arg("daemon").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let until = Instant::now() + Duration::from_secs(5);
    while !f.root.join("vault/run/d.sock").exists() {
        assert!(Instant::now() < until, "synthetic daemon startup failed");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(f.root.join("vault/canary"), "synthetic-shim-canary").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let output = f.command().args(["run", "--jail", "--allow-host", &address.to_string(), "--", "/bin/sh", "-c",
        &format!("test $((6*7)) = 42 && ! /bin/cat vault/canary && /usr/bin/nc -z -w 2 127.0.0.1 {}", address.port())]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
