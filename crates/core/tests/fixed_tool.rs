//! Synthetic HTTPS only; never opens a vault or starts the daemon/helper.
use karambit_core::broker::fixed::{Tool, call};
use std::{io::{BufRead, BufReader}, process::{Child, Command, Stdio}};

struct Fixture { dir: std::path::PathBuf, server: Child, port: u16 }
impl Fixture {
    fn new(mode: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("karambit-fixed-{}-{}", std::process::id(), mode));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cert.cnf"), "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\n").unwrap();
        assert!(Command::new("openssl").args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config"])
            .arg(dir.join("cert.cnf")).arg("-keyout").arg(dir.join("key.pem")).arg("-out").arg(dir.join("ca.pem"))
            .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
        let mut server = Command::new("python3").arg("-u").arg("-c").arg(r#"
import http.server, ssl, sys, base64
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self, *args): pass
 def do_GET(self):
  assert self.path == '/job/staging/lastBuild/api/json'
  assert self.headers['Authorization'] == 'Basic ' + base64.b64encode(b'fixture-user:synthetic+token').decode()
  if sys.argv[2] == 'redirect':
   self.send_response(302); self.send_header('Location', 'https://localhost:1/'); self.end_headers(); return
  body = b'{"result":"SUCCESS"}'
  if sys.argv[2] == 'echo':
   body = b'fixture-user:synthetic+token synthetic%2Btoken ' + base64.b64encode(b'fixture-user:synthetic+token')
  self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body)))
  self.end_headers(); self.wfile.write(body)
s = http.server.HTTPServer(('127.0.0.1', 0), Handler)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[1]+'/ca.pem', sys.argv[1]+'/key.pem')
s.socket = c.wrap_socket(s.socket, server_side=True)
print(s.server_port, flush=True)
s.serve_forever()
"#).arg(&dir).arg(mode).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut port = String::new();
        BufReader::new(server.stdout.take().unwrap()).read_line(&mut port).unwrap();
        Self { dir, server, port: port.trim().parse().unwrap() }
    }
    fn run(&self, mode: &str, allow: bool) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "fixture_child", "--nocapture"])
            .env("FIXED_CHILD_MODE", mode).env("FIXED_CHILD_PORT", self.port.to_string())
            .env_remove("KARAMBIT_TEST_FIXED_ENDPOINT").env_remove("KARAMBIT_TEST_FIXED_CA");
        if allow {
            command.env("KARAMBIT_TEST_FIXED_ENDPOINT", format!("localhost:{}", self.port))
                .env("KARAMBIT_TEST_FIXED_CA", self.dir.join("ca.pem"));
        }
        assert!(command.status().unwrap().success());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = self.server.kill(); let _ = self.server.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

#[test]
fn fixture_child() {
    let Ok(mode) = std::env::var("FIXED_CHILD_MODE") else { return; };
    let tool = Tool { host: "localhost".into(), port: std::env::var("FIXED_CHILD_PORT").unwrap().parse().unwrap(),
        method: "GET".into(), path_template: "/job/{job}/lastBuild/api/json".into(),
        credential_ref: "fixture/ci".into(), credential_host: "localhost".into() };
    let result = call(&tool, &["staging".into()], b"fixture-user:synthetic+token");
    if mode == "guard" || !cfg!(debug_assertions) {
        assert!(result.unwrap_err().to_string().contains("SSRF"));
    } else if mode == "redirect" {
        assert!(result.is_err());
    } else if mode == "echo" {
        assert_eq!(result.unwrap(), "[REDACTED] [REDACTED] [REDACTED]");
    } else { assert_eq!(result.unwrap(), "{\"result\":\"SUCCESS\"}"); }
}

#[test]
fn fixed_tool_https_smoke() {
    Fixture::new("smoke").run("smoke", true);
    let config: karambit_core::store::Config = serde_json::from_str(include_str!("fixtures/config.json")).unwrap();
    assert!(config.tools.is_empty());
    assert!(serde_json::to_value(config).unwrap().get("tools").is_none());
}
#[test]
fn fixed_tool_echo_scrubbed() { Fixture::new("echo").run("echo", true); }
#[test]
fn fixed_tool_redirect_refused() { Fixture::new("redirect").run("redirect", true); }
#[test]
fn fixed_tool_production_guard() {
    let fixture = Fixture::new("guard");
    fixture.run("guard", false);
    // Run this test under --release too: valid debug flags cannot enable loopback.
    if !cfg!(debug_assertions) { fixture.run("guard", true); }
}
