//! Thin client for the Swift `karambit-se-helper` binary.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::process::{Command, Stdio};
#[cfg(test)]
use std::process::Command;
use zeroize::Zeroizing;

use crate::store::KeyId;

pub const HELPER_NAME: &str = "karambit-se-helper";

// Fixed prompt identities are operation names, not an authentication capability.
// Parameters are sanitized on the wire and quoted by the Swift renderer.
macro_rules! prompts {
    ($($variant:ident($id:literal $(, $field:ident)*);)*) => {
        #[derive(Debug, Clone)]
        pub enum Prompt { $($variant { $($field: String),* },)* }
        impl Prompt {
            pub(crate) fn wire(&self) -> String {
                let (id, params): (&str, Vec<String>) = match self {
                    $(Self::$variant { $($field),* } => ($id, vec![$(prompt_param($field)),*]),)*
                };
                json!({"id": id, "params": params}).to_string()
            }
            #[cfg(test)]
            fn examples() -> Vec<Self> {
                vec![$(Self::$variant { $($field: stringify!($field).into()),* }),*]
            }
        }
    };
}

prompts! {
    AddSource("add_source", name, kind, endpoint, auth_method, policy_digest, credential);
    RetargetSource("retarget_source", name, old_kind, old_endpoint, new_kind, new_endpoint, old_auth_method, new_auth_method, old_policy_digest, new_policy_digest, credential);
    RemoveSource("remove_source", name, kind, endpoint, auth_method, policy_digest, credential);
    Unlock("unlock", names);
    Use("use", names, caller, context);
    Overwrite("overwrite", names, caller);
    AddRelaxed("add_relaxed", names, caller, access);
    ChangePolicy("change_policy", names, caller);
    Delete("delete", names, caller);
    UpgradeKeys("upgrade_keys", names);
    MoveAgentKey("move_agent_key");
    VerifyAgentKey("verify_agent_key");
    ChangeConfig("change_config", key);
    Recover("recover");
    RetireKeys("retire_keys");
    RotateBackup("rotate_backup", names, caller);
    RewrapBackup("rewrap_backup", names, caller);
    AddSsoPortal("add_sso_portal", name, url, region);
    RepointSsoPortal("repoint_sso_portal", name, url, region);
    SsoLimit("sso_limit", portal, duration);
    SsoDecrypt("sso_decrypt");
    Grant("grant", names, grantee, hours, scope);
    SsoLogin("sso_login", portal, url, agent_count, profile_count, duration);
    SsoRegister("sso_register", profiles);
    SsoUse("sso_use", name, account, role);
    RunUnredacted("run_unredacted", command);
    RepinHelper("repin_helper");
    ScreenLockProbe("screen_lock_probe");
}

pub(crate) fn prompt_param(value: &str) -> String {
    value.chars().filter(|c| !c.is_control() && !matches!(*c,
        '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{061c}'
    )).take(120).collect()
}

/// The helper sees every secret, so which binary it is matters.
/// - `KARAMBIT_SE_HELPER` is honoured only with `KARAMBIT_DEV=1` and only in debug
///   builds (`cfg(debug_assertions)`); it is compiled out of release builds, so the
///   release path always goes through `verify_pin`.
/// - Otherwise: next to the running binary (also Tauri's Contents/MacOS), then
///   ~/.local/bin. Never $PATH: a planted helper earlier in PATH would see every secret.
/// - Accepted binaries are pinned by SHA-256 in `<vault>/keys/helper.sha256`
///   (trust on first use); a different binary later is refused until
///   `karambit helper pin` is run by a human.
// Test builds compile out the real launch paths (panic guards), leaving these unused.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn locate() -> Result<PathBuf> {
    crate::platform::require_helper()?;
    #[cfg(debug_assertions)]
    if std::env::var_os("KARAMBIT_DEV").is_some_and(|v| v == "1")
        && let Some(p) = std::env::var_os("KARAMBIT_SE_HELPER")
    {
        return Ok(PathBuf::from(p));
    }
    let mut cands = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(d) = exe.parent() {
            cands.push(d.join(HELPER_NAME));
        }
    if let Some(h) = std::env::var_os("HOME") {
        cands.push(PathBuf::from(h).join(".local/bin").join(HELPER_NAME));
    }
    let found = cands
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| anyhow!("{HELPER_NAME} not found (install it next to karambit or in ~/.local/bin)"))?;
    verify_pin(&found)?;
    Ok(found)
}

pub fn sha256_file(p: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let b = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
    Ok(Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect())
}

/// Kernel-selected serving executable, never a client assertion.
fn daemon_executable() -> Result<PathBuf> {
    let path = crate::agent::proc_exe(std::process::id() as i32)
        .context("serving daemon executable unavailable")?;
    Ok(std::fs::canonicalize(path)?)
}

fn daemon_pin(pf: &Path) -> PathBuf { pf.with_file_name("daemon.sha256") }

const OFFLINE_BOOTSTRAP: &str = "no trusted old pair; use owner-offline-bootstrap";

fn require_fresh(pf: &Path) -> Result<()> {
    let keys = pf.parent().context("pin parent")?;
    for path in [keys.join("bio.key"), keys.join("open.key"), keys.join("agent.key"),
                 keys.join("pub.json"), keys.parent().context("vault root")?.join("config.json")] {
        if path.try_exists()? { bail!("{OFFLINE_BOOTSTRAP}"); }
    }
    Ok(())
}

fn bootstrap_pair(pf: &Path, body: &str) -> Result<()> {
    // Pin establishment hashes the CURRENT executable as the daemon: only the
    // serving daemon (inside dispatch) may do that, never a library caller.
    crate::daemon::with_launch_cap(|_| Ok(()))?;
    require_fresh(pf)?;
    trust_guard(pf, true)?;
    let df = daemon_pin(pf);
    trust_guard(&df, true)?;
    let daemon_hash = sha256_file(&daemon_executable()?)?;
    bootstrap_pin(&df, &format!("{daemon_hash}\n"))?;
    verify_pinned_hash(&daemon_executable()?, &df, &daemon_hash)?;
    bootstrap_pin(pf, body)
}

/// Integration-test seam (non-cfg(test) builds): attempt a fresh paired bootstrap
/// from the CURRENT process outside daemon dispatch. Must always refuse.
#[doc(hidden)]
pub fn bootstrap_outside_dispatch_for_tests(pf: &Path) -> Result<()> {
    bootstrap_pair(pf, "0000000000000000000000000000000000000000000000000000000000000000\n")
}

fn pin_file() -> Option<PathBuf> {
    crate::store::Paths::resolve().ok().map(|p| p.keys().join("helper.sha256"))
}

// A missing pin after retirement is never first-install TOFU, including old
// interrupted retirements that predate the persistent marker.
fn retirement_guard(pf: &Path) -> Result<()> {
    trust_guard(pf, false)
}

fn trust_guard(pf: &Path, bootstrap: bool) -> Result<()> {
    let Some(root) = pf.parent().and_then(Path::parent) else { return Ok(()) };
    if root.join("keys.retirement").try_exists()? { bail!("key retirement incomplete; restore trusted pin before helper use"); }
    if (bootstrap || !pf.try_exists()?) && root.try_exists()? {
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("keys.retired-")
                && (entry.path().join("helper.sha256").try_exists()?
                    || entry.path().join("daemon.sha256").try_exists()?) {
                bail!("retired helper pin exists; refusing trust on first use");
            }
        }
    }
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
fn verify_pin(helper: &Path) -> Result<()> {
    let pf = pin_file().context("no vault for helper pin verification")?;
    verify_pin_at(helper, &pf)
}

pub(crate) fn verify_pin_at(helper: &Path, pf: &Path) -> Result<()> {
    retirement_guard(pf)?;
    let hash = sha256_file(helper)?;
    match std::fs::read_to_string(pf) {
        Ok(t) if t.lines().any(|l| l.trim() == hash) => Ok(()),
        Ok(_) => bail!(
            "{} doesn't match the pinned helper (sha256 {}...). If you just rebuilt or reinstalled karambit, run `karambit helper pin` in a terminal.",
            helper.display(),
            &hash[..12]
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(test)]
            missing_pin_pause();
            bootstrap_pair(pf, &format!("{hash}\n"))?;
            verify_pinned_hash(helper, pf, &hash)
        }
        Err(e) => Err(e.into()),
    }
}

// A stale NotFound is not authority to replace a pin or to trust a candidate.
fn verify_pinned_hash(helper: &Path, pf: &Path, hash: &str) -> Result<()> {
    retirement_guard(pf)?;
    if !std::fs::read_to_string(pf)?.lines().any(|line| line.trim() == hash) {
        bail!("{} doesn't match the pinned helper", helper.display());
    }
    Ok(())
}

fn bootstrap_pin(pf: &Path, body: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    retirement_guard(pf)?;
    // Completed retirement may have restored a pin since the caller's read.
    if pf.try_exists()? { return Ok(()); }
    trust_guard(pf, true)?;
    crate::audit::run(&crate::store::Paths { root: pf.parent().and_then(Path::parent).context("vault root")?.to_path_buf() }, "helper-tofu-pin", &[],
        &crate::agent::Caller::default(), json!({}), || {
        let dir = pf.parent().context("pin parent")?;
        crate::store::ensure_dir(dir)?;
        let tmp = dir.join(format!(".helper-pin-{:016x}.tmp", rand::random::<u64>()));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        let result = (|| -> Result<()> {
            file.write_all(body.as_bytes())?;
            file.sync_all()?;
            trust_guard(pf, true)?;
            match std::fs::hard_link(&tmp, pf) {
                Ok(()) => std::fs::File::open(dir)?.sync_all()?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
            Ok(())
        })();
        let cleanup = std::fs::remove_file(tmp);
        result?;
        cleanup?;
        Ok(())
    })
}

#[cfg(test)]
thread_local! {
    pub(crate) static MISSING_PIN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn missing_pin_pause() {
    MISSING_PIN_HOOK.with(|h| { if let Some(h) = h.borrow_mut().take() { h(); } });
}

#[cfg(test)]
thread_local! {
    pub(crate) static PIN_CURRENT_FIXTURE: std::cell::RefCell<Option<(crate::store::Paths, Vec<PathBuf>)>> = const { std::cell::RefCell::new(None) };
}

/// Re-pin to the helpers installed now (CLI copy + app bundle copy).
pub(crate) fn pin_current(stage: Option<(&Path, &Path)>) -> Result<Vec<(PathBuf, String)>> {
    #[cfg(test)]
    if let Some((paths, candidates)) = PIN_CURRENT_FIXTURE.with(|h| h.borrow_mut().take()) {
        return crate::audit::run(&paths, "helper-pin_current", &[], &crate::agent::Caller::default(), json!({}), || {
            pin_candidates_staged(&paths.keys().join("helper.sha256"), candidates, stage)
        });
    }
    crate::audit::run(&crate::store::Paths::resolve()?, "helper-pin_current", &[], &crate::agent::Caller::default(), json!({}), || {
        let pf = pin_file().context("no vault")?;
        let mut cands: Vec<PathBuf> = vec![];
        if let Ok(exe) = std::env::current_exe()
            && let Some(d) = exe.parent()
        {
            cands.push(d.join(HELPER_NAME));
        }
        if let Some(h) = std::env::var_os("HOME") {
            cands.push(PathBuf::from(&h).join(".local/bin").join(HELPER_NAME));
            cands.push(PathBuf::from(&h).join("Applications/Karambit.app/Contents/MacOS").join(HELPER_NAME));
        }
        pin_candidates_staged(&pf, cands, stage)
    })
}

#[cfg(test)]
pub(crate) fn pin_candidates(pf: &Path, cands: Vec<PathBuf>) -> Result<Vec<(PathBuf, String)>> {
    pin_candidates_staged(pf, cands, None)
}

fn pin_candidates_staged(pf: &Path, cands: Vec<PathBuf>, stage: Option<(&Path, &Path)>) -> Result<Vec<(PathBuf, String)>> {
    retirement_guard(pf)?;
    let df = daemon_pin(pf);
    retirement_guard(&df)?;
    let daemon = daemon_executable()?;
    let daemon_hash = sha256_file(&daemon)?;
    let mut out: Vec<(PathBuf, String)> = vec![];
    for c in cands.into_iter().filter(|p| p.is_file()) {
        let h = sha256_file(&c)?;
        if !out.iter().any(|(_, x)| x == &h) { out.push((c, h)); }
    }
    if out.is_empty() { bail!("no {HELPER_NAME} found to pin"); }
    let old = match std::fs::read(pf) {
        Ok(old) => old,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(test)]
            missing_pin_pause();
            if stage.is_some() { bail!("{OFFLINE_BOOTSTRAP}"); }
            let body = pin_body(out.iter().map(|(_, h)| h.as_str()));
            bootstrap_pair(pf, &body)?;
            for (candidate, hash) in &out { verify_pinned_hash(candidate, pf, hash)?; }
            out.push((daemon, daemon_hash));
            return Ok(out);
        }
        Err(e) => return Err(e.into()),
    };
    let old_daemon = match std::fs::read(&df) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && stage.is_none() => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!("{OFFLINE_BOOTSTRAP}"),
        Err(e) => return Err(e.into()),
    };
    let old_text = std::str::from_utf8(&old)?;
    let trusted = out.iter().find(|(_, hash)| old_text.lines().any(|line| line.trim() == hash))
        .context("no still-pinned helper copy available; use owner-offline-bootstrap")?;
    if let Some(bytes) = &old_daemon {
        if !std::str::from_utf8(bytes)?.lines().any(|line| line.trim() == daemon_hash) {
            bail!("{OFFLINE_BOOTSTRAP}");
        }
    } else {
        trust_guard(&df, true)?;
    }
    // Hash staged artifacts in the serving daemon, before approval; no asserted hashes.
    let staged = stage.map(|(daemon, helper)| -> Result<_> {
        Ok(((daemon.to_path_buf(), sha256_file(daemon)?), (helper.to_path_buf(), sha256_file(helper)?)))
    }).transpose()?;
    crate::daemon::with_launch_cap(|cap| call_at(cap, &trusted.0,
        &["auth", "--dir", dir_str(pf.parent().context("pin parent")?)?, "--prompt", &Prompt::RepinHelper {}.wire()], None))?;
    let daemon_now = match std::fs::read(&df) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    if std::fs::read(pf)? != old || daemon_now != old_daemon {
        bail!("pin changed during approval; retry");
    }
    retirement_guard(pf)?;
    retirement_guard(&df)?;
    if old_daemon.is_none() {
        // Pre-launch-channel migration: approval by the OLD helper is the only authority.
        // Never replace an existing pin, even if another request won the race.
        bootstrap_pin(&df, &format!("{daemon_hash}\n"))?;
        verify_pinned_hash(&daemon, &df, &daemon_hash)?;
        out.push((daemon, daemon_hash));
        return Ok(out);
    }
    let old_daemon = old_daemon.expect("checked above");
    let (helper_body, daemon_body) = if let Some((staged_daemon, staged_helper)) = staged {
        let helpers = pin_body(old_text.lines().chain(std::iter::once(staged_helper.1.as_str())));
        let daemons = pin_body(std::str::from_utf8(&old_daemon)?.lines().chain(std::iter::once(staged_daemon.1.as_str())));
        out = vec![staged_helper, staged_daemon];
        (helpers, daemons)
    } else {
        let helpers = pin_body(out.iter().map(|(_, h)| h.as_str()));
        out.push((daemon, daemon_hash.clone()));
        (helpers, format!("{daemon_hash}\n"))
    };
    publish_pair(pf, &df, &old, helper_body.as_bytes(), daemon_body.as_bytes())?;
    Ok(out)
}

fn pin_body<'a>(hashes: impl Iterator<Item = &'a str>) -> String {
    let hashes: std::collections::BTreeSet<_> = hashes.map(str::trim).filter(|s| !s.is_empty()).collect();
    hashes.into_iter().map(|h| format!("{h}\n")).collect()
}

fn replace_pin(pf: &Path, body: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = pf.parent().context("pin parent")?;
    let tmp = dir.join(format!(".pin-{:016x}.tmp", rand::random::<u64>()));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        std::fs::rename(&tmp, pf)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(tmp);
    result
}

fn publish_pair(pf: &Path, df: &Path, old_helper: &[u8], helper: &[u8], daemon: &[u8]) -> Result<()> {
    replace_pin(pf, helper)?;
    if let Err(error) = replace_pin(df, daemon) {
        if let Err(restore) = replace_pin(pf, old_helper) {
            bail!("daemon pin publication failed: {error}; helper pin restoration also failed: {restore}");
        }
        return Err(error.context("daemon pin publication failed; helper pin restored"));
    }
    Ok(())
}

fn call(args: &[&str], stdin: Option<&[u8]>) -> Result<Value> {
    // Unit tests must never discover installed helpers or touch live trust pins.
    #[cfg(test)]
    { crate::daemon::with_launch_cap(|cap| call_at(cap, Path::new("synthetic-test-helper"), args, stdin)) }
    #[cfg(not(test))]
    {
        let helper = locate()?;
        if args.first() == Some(&"auth") { verify_pin(&helper)?; }
        crate::daemon::with_launch_cap(|cap| call_at(cap, &helper, args, stdin))
    }
}

fn call_at(_cap: &crate::daemon::LaunchCap, helper: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<Value> {
    crate::platform::require_helper()?;
    #[cfg(test)]
    if let Some(result) = CALL_AT_HOOK.with(|h| h.borrow_mut().as_mut().map(|hook| hook(helper, args))) { return result; }
    #[cfg(test)]
    { let _ = stdin; panic!("test attempted real helper launch: {args:?}"); }
    #[cfg(not(test))]
    {
        let mut command = Command::new(helper);
        command.args(args);
        if !args.contains(&"--dir") { command.arg("--dir").arg(crate::store::Paths::resolve()?.keys()); }
        command
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let (mut child, _channel) = launch_channel::spawn(&mut command, _cap)?;
        if let Some(data) = stdin {
            child.stdin.take().context("helper stdin")?.write_all(data)?;
        }
        let out = child.wait_with_output()?;
        let v: Value = serde_json::from_slice(&out.stdout)
            .with_context(|| format!("{HELPER_NAME}: unparseable output"))?;
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            return Err(response_error(args, e));
        }
        if !out.status.success() {
            bail!("{HELPER_NAME} exited {}", out.status);
        }
        Ok(v)
    }
}

/// Only a pin-verified helper's auth response can permit paper-only recovery.
#[derive(Debug)]
pub struct BiometricsUnavailable(String);
impl std::fmt::Display for BiometricsUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for BiometricsUnavailable {}

fn response_error(args: &[&str], message: &str) -> anyhow::Error {
    if args.first() == Some(&"auth") && message.starts_with("biometrics unavailable:") {
        BiometricsUnavailable(message.to_owned()).into()
    } else { anyhow!("{message}") }
}

#[cfg(test)]
pub(crate) fn unavailable_test_response() -> anyhow::Error {
    response_error(&["auth"], "biometrics unavailable: synthetic")
}

fn dir_str(dir: &Path) -> Result<&str> {
    dir.to_str().context("non-utf8 key dir")
}

pub struct PubKeys {
    pub bio: Vec<u8>,
    pub open: Vec<u8>,
    /// Lock-safe agent key; None on vaults that haven't run `karambit keys upgrade`.
    pub agent: Option<Vec<u8>>,
}

impl PubKeys {
    pub fn get(&self, k: KeyId) -> Result<&[u8]> {
        match k {
            KeyId::Bio => Ok(&self.bio),
            KeyId::Open => Ok(&self.open),
            KeyId::Agent => self.agent.as_deref().context("vault has no agent key (run `karambit keys upgrade`)"),
        }
    }
    pub(crate) fn from_json(v: &Value) -> Result<PubKeys> {
        let g = |k: &str| -> Result<Option<Vec<u8>>> {
            v.get(k).and_then(Value::as_str).map(|s| B64.decode(s)).transpose().map_err(Into::into)
        };
        Ok(PubKeys {
            bio: g("bio")?.context("missing bio pubkey")?,
            open: g("open")?.context("missing open pubkey")?,
            agent: g("agent")?,
        })
    }
    pub fn to_json(&self) -> Value {
        let mut v = json!({ "bio": B64.encode(&self.bio), "open": B64.encode(&self.open) });
        if let Some(a) = &self.agent {
            v["agent"] = json!(B64.encode(a));
        }
        v
    }
}

pub(crate) fn keygen(dir: &Path) -> Result<PubKeys> {
    #[cfg(test)]
    if let Some(hook) = KEYGEN_HOOK.with(|h| h.borrow_mut().take()) { return hook(dir); }
    #[cfg(not(test))]
    {
        // Init's intent is already durable before this bootstrap (including debug fixtures).
        let helper = locate()?;
        verify_pin(&helper)?;
        let pf = pin_file().context("no vault")?;
        let daemon = daemon_executable()?;
        verify_pinned_hash(&daemon, &daemon_pin(&pf), &sha256_file(&daemon)?)
            .context("daemon pin required before keygen; run authenticated helper pin with the old pair, or owner-offline-bootstrap")?;
    }
    PubKeys::from_json(&call(&["keygen", "--dir", dir_str(dir)?], None)?)
}

/// Create the lock-safe agent key in an existing vault. Returns its public key.
pub(crate) fn addkey_agent(dir: &Path) -> Result<Vec<u8>> {
    let v = call(&["addkey", "--dir", dir_str(dir)?, "--tier", "agent"], None)?;
    Ok(B64.decode(v.get("agent").and_then(Value::as_str).context("addkey: missing agent pubkey")?)?)
}

pub(crate) fn pubkeys(dir: &Path) -> Result<PubKeys> {
    PubKeys::from_json(&call(&["pubkeys", "--dir", dir_str(dir)?], None)?)
}

pub fn pubkeys_cached(pub_json: &Path) -> Result<PubKeys> {
    PubKeys::from_json(&serde_json::from_slice(&std::fs::read(pub_json)?)?)
}

/// Batch ECDH: one Touch ID prompt total if any request uses the bio key.
pub(crate) fn ecdh(dir: &Path, prompt: &Prompt, reqs: &[(KeyId, &str)]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    if reqs.is_empty() {
        return Ok(vec![]);
    }
    #[cfg(test)]
    if let Some(hook) = ECDH_HOOK.with(|h| h.borrow_mut().take()) { return hook(reqs); }
    let body = json!({
        "requests": reqs.iter().map(|(k, eph)| json!({"tier": k.as_str(), "eph": eph})).collect::<Vec<_>>()
    });
    let v = call(&["ecdh", "--dir", dir_str(dir)?, "--prompt", &prompt.wire()], Some(body.to_string().as_bytes()))?;
    let arr = v.get("shared").and_then(Value::as_array).context("missing shared")?;
    if arr.len() != reqs.len() {
        bail!("helper returned {} secrets for {} requests", arr.len(), reqs.len());
    }
    arr.iter()
        .map(|s| Ok(Zeroizing::new(B64.decode(s.as_str().context("bad shared")?)?)))
        .collect()
}

#[cfg(test)]
type KeygenHook = Box<dyn FnOnce(&Path) -> Result<PubKeys>>;
#[cfg(test)]
type EcdhHook = Box<dyn FnOnce(&[(KeyId, &str)]) -> Result<Vec<Zeroizing<Vec<u8>>>>>;
#[cfg(test)]
type CallAtHook = Box<dyn FnMut(&Path, &[&str]) -> Result<Value>>;
#[cfg(test)]
thread_local! {
    pub(crate) static KEYGEN_HOOK: std::cell::RefCell<Option<KeygenHook>> = const { std::cell::RefCell::new(None) };
    pub(crate) static ECDH_HOOK: std::cell::RefCell<Option<EcdhHook>> = const { std::cell::RefCell::new(None) };
    pub(crate) static CALL_AT_HOOK: std::cell::RefCell<Option<CallAtHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type ClipHook = Box<dyn FnOnce(&[u8], u32) -> Result<()>>;
#[cfg(test)]
thread_local! {
    pub(crate) static CLIP_HOOK: std::cell::RefCell<Option<ClipHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type AuthHook = Box<dyn FnOnce() -> Result<()>>;

#[cfg(test)]
thread_local! {
    pub(crate) static AUTH_HOOK: std::cell::RefCell<Option<AuthHook>> = const { std::cell::RefCell::new(None) };
}

/// Touch ID policy gate (no key use). For add / enabling agent access / reveal.
pub(crate) fn auth(prompt: &Prompt) -> Result<()> {
    #[cfg(test)]
    if let Some(hook) = AUTH_HOOK.with(|hook| hook.borrow_mut().take()) {
        return hook();
    }
    call(&["auth", "--prompt", &prompt.wire()], None).map(|_| ())
}

/// Is the screen locked (or the helper otherwise unusable)? Probes the no-prompt
/// `open` key with a throwaway point: it's WhenUnlocked, so ECDH fails while locked.
/// Fail-closed: any error (locked, missing helper) returns true, so human leases end.
pub(crate) fn screen_locked(dir: &Path) -> bool {
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let eph = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let b64 = B64.encode(eph.public_key().to_encoded_point(false).as_bytes());
    ecdh(dir, &Prompt::ScreenLockProbe {}, &[(KeyId::Open, &b64)]).is_err()
}

pub(crate) fn selftest() -> Result<Value> {
    call(&["selftest"], None)
}

/// Copy to pasteboard as concealed; helper stays alive in the background and clears
/// after `secs`. We only wait for its ack line, not for its exit.
pub(crate) fn clip(value: &[u8], secs: u32) -> Result<()> {
    crate::daemon::with_launch_cap(|cap| clip_at(cap, value, secs))
}

fn clip_at(_cap: &crate::daemon::LaunchCap, value: &[u8], secs: u32) -> Result<()> {
    crate::platform::require_helper()?;
    #[cfg(test)]
    if let Some(hook) = CLIP_HOOK.with(|h| h.borrow_mut().take()) { return hook(value, secs); }
    #[cfg(test)]
    { let _ = value; panic!("test attempted real helper launch: clip --clear-after {secs}"); }
    #[cfg(not(test))]
    {
        use std::io::{BufRead, BufReader};
        let helper = locate()?;
        let mut command = Command::new(&helper);
        command.args(["clip", "--clear-after", &secs.to_string()])
            .arg("--dir").arg(crate::store::Paths::resolve()?.keys())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let (mut child, channel) = launch_channel::spawn(&mut command, _cap)?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        // Reap in background on EVERY path (the helper stays alive for the clear
        // timer on success, and exits on failure); the long-lived daemon must not
        // accumulate zombies from failed copies.
        std::thread::spawn(move || { let result = child.wait(); drop(channel); result });
        {
            let mut stdin = stdin.context("helper stdin")?;
            stdin.write_all(value)?;
        } // drop -> EOF
        let mut line = String::new();
        BufReader::new(stdout.context("helper stdout")?).read_line(&mut line)?;
        let v: Value = serde_json::from_str(line.trim()).context("clip: bad ack")?;
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            bail!("{e}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod repin_tests {
    use super::*;
    #[test]
    fn repin_requires_old_trusted_copy_and_preserves_pin_on_refusal() {
        let root = std::env::temp_dir().join(format!("karambit-repin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        crate::store::ensure_dir(&root).unwrap();
        let old = root.join("old-helper");
        let new = root.join("new-helper");
        let pf = root.join("helper.sha256");
        std::fs::write(&old, b"synthetic old executable").unwrap();
        std::fs::write(&new, b"synthetic new executable").unwrap();
        let original = format!("{}\n", sha256_file(&old).unwrap());
        std::fs::write(&pf, &original).unwrap();
        std::fs::write(daemon_pin(&pf), format!("{}\n", sha256_file(&daemon_executable().unwrap()).unwrap())).unwrap();
        assert!(pin_candidates(&pf, vec![new.clone()]).unwrap_err().to_string().contains("still-pinned"));
        assert_eq!(std::fs::read_to_string(&pf).unwrap(), original);
        assert!(verify_pin_at(&new, &pf).is_err(), "replacement refused while old pin survives");
        let expected = old.clone();
        CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |path, args| {
            assert_eq!(path, expected); assert_eq!(args[0], "auth"); bail!("synthetic auth refused")
        })));
        assert!(pin_candidates(&pf, vec![new.clone(), old.clone()]).is_err());
        assert_eq!(std::fs::read_to_string(&pf).unwrap(), original);
        let expected = old.clone();
        CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |path, _| {
            assert_eq!(path, expected); Ok(json!({"ok": true}))
        })));
        pin_candidates(&pf, vec![new.clone(), old]).unwrap();
        assert!(std::fs::read_to_string(&pf).unwrap().contains(&sha256_file(&new).unwrap()));
        CALL_AT_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(root).unwrap();
    }

    struct Fixture { root: PathBuf, pf: PathBuf, helper: PathBuf, staged_helper: PathBuf, staged_daemon: PathBuf }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("karambit-pair-{:016x}", rand::random::<u64>()));
            let pf = root.join("keys/helper.sha256");
            crate::store::ensure_dir(pf.parent().unwrap()).unwrap();
            let helper = root.join("old-helper");
            let staged_helper = root.join("new-helper");
            let staged_daemon = root.join("new-daemon");
            for (path, bytes) in [(&helper, b"old helper".as_slice()), (&staged_helper, b"new helper"), (&staged_daemon, b"new daemon")] {
                std::fs::write(path, bytes).unwrap();
            }
            Self { root, pf, helper, staged_helper, staged_daemon }
        }
        fn old_pair(&self) {
            std::fs::write(&self.pf, format!("{}\n", sha256_file(&self.helper).unwrap())).unwrap();
            std::fs::write(daemon_pin(&self.pf), format!("{}\n", sha256_file(&daemon_executable().unwrap()).unwrap())).unwrap();
        }
        fn stage(&self) -> Result<Vec<(PathBuf, String)>> {
            pin_candidates_staged(&self.pf, vec![self.helper.clone()], Some((&self.staged_daemon, &self.staged_helper)))
        }
        fn approve(&self) {
            let expected = self.helper.clone();
            let dir = self.pf.parent().unwrap().to_path_buf();
            CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |path, args| {
                assert_eq!(path, expected); assert_eq!(args[0], "auth");
                assert_eq!(args[1], "--dir"); assert_eq!(Path::new(args[2]), dir);
                Ok(json!({"ok":true}))
            })));
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            CALL_AT_HOOK.with(|h| h.borrow_mut().take());
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn paired_bootstrap_is_fresh_only_and_never_replaces_either_pin() {
        let f = Fixture::new();
        let helper_body = format!("{}\n", sha256_file(&f.helper).unwrap());
        bootstrap_pair(&f.pf, &helper_body).unwrap();
        let df = daemon_pin(&f.pf);
        let original = std::fs::read(&df).unwrap();
        bootstrap_pin(&df, "attacker daemon\n").unwrap();
        assert_eq!(std::fs::read(&df).unwrap(), original);
        bootstrap_pair(&f.pf, "replacement\n").unwrap();
        assert_eq!(std::fs::read_to_string(&f.pf).unwrap(), helper_body);
        assert_eq!(std::fs::read(&df).unwrap(), original);
        std::fs::write(&df, "other daemon\n").unwrap();
        assert!(bootstrap_pair(&f.pf, &helper_body).is_err());
        assert_eq!(std::fs::read_to_string(&df).unwrap(), "other daemon\n");
        for name in ["keys/bio.key", "keys/open.key", "keys/agent.key", "keys/pub.json", "config.json"] {
            let f = Fixture::new();
            std::fs::write(f.root.join(name), b"synthetic initialization evidence").unwrap();
            assert!(bootstrap_pair(&f.pf, &helper_body).unwrap_err().to_string().contains("owner-offline-bootstrap"));
            assert!(!f.pf.exists()); assert!(!daemon_pin(&f.pf).exists());
        }
    }

    #[test]
    fn legacy_daemon_tofu_requires_old_helper_approval_and_does_not_repin_helper() {
        let f = Fixture::new(); f.old_pair();
        let df = daemon_pin(&f.pf); std::fs::remove_file(&df).unwrap();
        let old = std::fs::read(&f.pf).unwrap();
        CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_, _| bail!("denied"))));
        assert!(pin_candidates(&f.pf, vec![f.helper.clone()]).is_err());
        assert!(!df.exists()); assert_eq!(std::fs::read(&f.pf).unwrap(), old);
        f.approve(); pin_candidates(&f.pf, vec![f.helper.clone()]).unwrap();
        assert_eq!(std::fs::read_to_string(&df).unwrap(), format!("{}\n", sha256_file(&daemon_executable().unwrap()).unwrap()));
        assert_eq!(std::fs::read(&f.pf).unwrap(), old);
        std::fs::remove_file(&df).unwrap();
        let injected_df = df.clone();
        CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_, _| {
            std::fs::write(&injected_df, b"concurrent pin\n")?; Ok(json!({"ok":true}))
        })));
        assert!(pin_candidates(&f.pf, vec![f.helper.clone()]).unwrap_err().to_string().contains("pin changed during approval; retry"));
        assert_eq!(std::fs::read(&df).unwrap(), b"concurrent pin\n");
        assert_eq!(std::fs::read(&f.pf).unwrap(), old);
    }

    #[test]
    fn staged_pair_union_prune_refusals_and_concurrent_change() {
        let f = Fixture::new(); f.old_pair();
        let df = daemon_pin(&f.pf);
        let old_helper = std::fs::read(&f.pf).unwrap(); let old_daemon = std::fs::read(&df).unwrap();
        CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_, _| bail!("denied"))));
        assert!(f.stage().is_err());
        assert_eq!(std::fs::read(&f.pf).unwrap(), old_helper); assert_eq!(std::fs::read(&df).unwrap(), old_daemon);
        for changed in [&f.pf, &df] {
            f.old_pair(); let changed = changed.clone();
            CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_, _| {
                std::fs::write(&changed, b"concurrent pin\n")?; Ok(json!({"ok":true}))
            })));
            assert!(f.stage().unwrap_err().to_string().contains("pin changed during approval; retry"));
            let h = std::fs::read(&f.pf).unwrap(); let d = std::fs::read(&df).unwrap();
            assert!(h == old_helper || h == b"concurrent pin\n");
            assert!(d == old_daemon || d == b"concurrent pin\n");
        }
        f.old_pair(); f.approve(); f.stage().unwrap();
        let helper_union = std::fs::read_to_string(&f.pf).unwrap();
        let daemon_union = std::fs::read_to_string(&df).unwrap();
        assert_eq!(helper_union.lines().count(), 2); assert_eq!(daemon_union.lines().count(), 2);
        assert!(helper_union.contains(&sha256_file(&f.staged_helper).unwrap()));
        assert!(daemon_union.contains(&sha256_file(&f.staged_daemon).unwrap()));
        f.approve(); f.stage().unwrap(); // deduplicated
        assert_eq!(std::fs::read_to_string(&df).unwrap(), daemon_union);
        f.approve(); pin_candidates(&f.pf, vec![f.helper.clone()]).unwrap();
        assert_eq!(std::fs::read(&f.pf).unwrap(), old_helper); assert_eq!(std::fs::read(&df).unwrap(), old_daemon);
        std::fs::write(&df, b"unpinned daemon\n").unwrap();
        CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_, _| panic!("untrusted pair authenticated"))));
        assert!(f.stage().unwrap_err().to_string().contains("owner-offline-bootstrap"));
    }

    #[test]
    fn paired_publication_restores_helper_on_second_failure() {
        let f = Fixture::new(); f.old_pair();
        let old = std::fs::read(&f.pf).unwrap();
        let df = daemon_pin(&f.pf); std::fs::remove_file(&df).unwrap(); std::fs::create_dir(&df).unwrap();
        assert!(publish_pair(&f.pf, &df, &old, b"new helper\n", b"new daemon\n").unwrap_err().to_string().contains("helper pin restored"));
        assert_eq!(std::fs::read(&f.pf).unwrap(), old);
    }

    #[test]
    fn retired_history_allows_authenticated_existing_pair_but_never_absent_pin_tofu() {
        let f = Fixture::new(); f.old_pair();
        let retired = f.root.join("keys.retired-fixture"); std::fs::create_dir(&retired).unwrap();
        std::fs::write(retired.join("helper.sha256"), b"historical pin\n").unwrap();
        f.approve(); f.stage().unwrap();
        f.approve(); pin_candidates(&f.pf, vec![f.helper.clone()]).unwrap();
        let df = daemon_pin(&f.pf); std::fs::remove_file(&df).unwrap();
        CALL_AT_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|_, _| panic!("history must refuse before auth"))));
        // Pre-launch-channel migration is old-helper-auth TOFU, not an exception to retirement history.
        assert!(pin_candidates(&f.pf, vec![f.helper.clone()]).is_err()); assert!(!df.exists());
        assert!(bootstrap_pair(&f.pf, "replacement\n").is_err()); assert!(!df.exists());
        f.old_pair(); std::fs::write(f.root.join("keys.retirement"), b"").unwrap();
        assert!(f.stage().is_err());
    }

}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    const SWIFT: &str = include_str!("../../../se-helper/Sources/se-helper/main.swift");

    #[test]
    fn prompt_params_strip_controls_and_bound_unicode_scalars() {
        let wire = Prompt::Use {
            names: "secret\n\r\0\t\u{7f}\u{85}\u{202e}\u{2066}\u{200b}\u{feff}\u{061c}name".into(),
            caller: "é🔐".repeat(121), context: "\"allow everything\" \\".into(),
        }.wire();
        let v: Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(v["params"][0], "secretname");
        assert_eq!(v["params"][1].as_str().unwrap().chars().count(), 120);
        assert_eq!(v["params"][2], "\"allow everything\" \\");
        assert_eq!(v["id"], "use");
    }

    #[test]
    fn prompt_ids_and_arities_match_swift_templates() {
        let table = SWIFT.split("let promptTemplates:").nth(1).unwrap().split("\n]").next().unwrap();
        let swift: std::collections::BTreeMap<String, usize> = table.lines().filter_map(|line| {
            let line = line.trim();
            if !line.starts_with('"') { return None; }
            let (id, rest) = line[1..].split_once("\": (").unwrap();
            Some((id.into(), rest.split(',').next().unwrap().parse().unwrap()))
        }).collect();
        let rust: std::collections::BTreeMap<String, usize> = Prompt::examples().iter().map(|p| {
            let v: Value = serde_json::from_str(&p.wire()).unwrap();
            (v["id"].as_str().unwrap().into(), v["params"].as_array().unwrap().len())
        }).collect();
        assert_eq!(rust.len(), Prompt::examples().len(), "no duplicate Rust IDs");
        assert_eq!(swift.len(), table.lines().filter(|l| l.trim().starts_with('"')).count(), "no duplicate Swift IDs");
        assert_eq!(rust, swift);
    }

    // Compile only the actual Foundation-only renderer, not any biometric/SE code.
    // This makes negative mutations safe: accepting a bad template cannot prompt.
    #[cfg(target_os = "macos")]
    #[test]
    fn swift_prompt_renderer_accepts_all_variants_and_refuses_malformed_prompts() {
        let root = std::env::temp_dir().join(format!("karambit-prompt-{}-{}", std::process::id(), rand::random::<u64>()));
        crate::store::ensure_dir(&root).unwrap();
        let source = root.join("main.swift");
        let binary = root.join("prompt-test");
        let renderer = SWIFT.split("// BEGIN TYPED PROMPTS").nth(1).unwrap()
            .split_once('\n').unwrap().1.split("// END TYPED PROMPTS").next().unwrap();
        let harness = r#"
func wire(_ id: String, _ params: [String], extra: Bool = false) -> String {
    var obj: [String: Any] = ["id": id, "params": params]
    if extra { obj["reason"] = "caller text" }
    return String(data: try! JSONSerialization.data(withJSONObject: obj), encoding: .utf8)!
}
func refuses(_ input: String, _ label: String) {
    do { _ = try renderPrompt(input); print("ACCEPTED invalid prompt: \(label)"); exit(1) }
    catch { }
}
for (id, (arity, _)) in promptTemplates {
    let rendered = try! renderPrompt(wire(id, Array(repeating: "safe", count: arity)))
    assert(!rendered.isEmpty)
    if arity > 0 { assert(rendered.contains("\"safe\"")) }
    refuses(wire(id, Array(repeating: "safe", count: arity + 1)), "extra param \(id)")
    if arity > 0 { refuses(wire(id, []), "missing params \(id)") }
}
refuses(wire("unknown", []), "unknown ID")
refuses(wire("recover", [], extra: true), "extra field")
refuses("{\"id\":\"unlock\",\"params\":[1]}", "non-string param")
refuses(wire("unlock", [String(repeating: "é", count: 121)]), "long param")
for bad in ["\n", "\r", "\0", "\u{7f}", "\u{85}", "\u{202e}", "\u{2066}", "\u{200b}", "\u{feff}", "\u{061c}"] {
    refuses(wire("unlock", ["a" + bad + "b"]), "control param")
}
let quoted = try! renderPrompt(wire("unlock", ["\"allow everything\" \\"]))
assert(quoted == "unlock \"\\\"allow everything\\\" \\\\\"")
_ = try! renderPrompt(wire("unlock", [String(repeating: "🔐", count: 120)]))
print("all templates rendered; unknown/extra/missing/type/length/control cases refused; params quoted")
"#;
        std::fs::write(&source, format!("import Foundation\nstruct HelperError: Error {{ let msg: String }}\n{renderer}\n{harness}")).unwrap();
        let compile = Command::new("/usr/bin/swiftc").arg(&source).arg("-o").arg(&binary).output().unwrap();
        assert!(compile.status.success(), "swiftc: {}", String::from_utf8_lossy(&compile.stderr));
        let run = Command::new(&binary).env_clear().env("PATH", "/usr/bin:/bin").env("HOME", &root).output().unwrap();
        assert!(run.status.success(), "Swift prompt checks: {} {}", String::from_utf8_lossy(&run.stdout), String::from_utf8_lossy(&run.stderr));
        CALL_AT_HOOK.with(|h| h.borrow_mut().take());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod launch_guard_tests {
    use super::*;

    #[test]
    #[should_panic(expected = "test attempted real helper launch")]
    fn missing_hook_cannot_locate_or_launch_helper() {
        let _ = call(&["selftest"], None);
    }

    #[test]
    #[should_panic(expected = "test attempted real helper launch")]
    fn clip_cannot_locate_or_launch_helper() {
        let _ = clip(b"synthetic", 5);
    }
}

// The protocol is specified in docs/threat-model.md, launch channel section.
#[cfg(any(not(test), target_os = "macos"))]
mod launch_channel {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::time::Duration;

    use crate::agent::{ProcessIdentity as Identity, process_identity as identity};

    use crate::platform::peer_pid;

    fn append_identity(out: &mut Vec<u8>, id: Identity) {
        out.extend_from_slice(&(id.pid as u32).to_be_bytes());
        out.extend_from_slice(&id.sec.to_be_bytes());
        out.extend_from_slice(&id.usec.to_be_bytes());
    }

    fn answer(nonce: &[u8; 32], child: Identity, parent: Identity) -> Vec<u8> {
        let mut out = nonce.to_vec();
        append_identity(&mut out, child);
        append_identity(&mut out, parent);
        out
    }

    // A registration belongs to exactly one spawned child and one socket. Taking
    // it burns authority before writing any answer, including on an I/O failure.
    fn respond(socket: &mut UnixStream, registration: &mut Option<Identity>, parent: Identity) -> Result<()> {
        let mut nonce = [0u8; 32];
        socket.read_exact(&mut nonce)?;
        let child = registration.take().context("launch channel: registration already used")?;
        if peer_pid(socket.as_raw_fd())? != child.pid || identity(child.pid)? != child || identity(parent.pid)? != parent {
            bail!("launch channel: identity mismatch");
        }
        socket.write_all(&answer(&nonce, child, parent))?;
        Ok(())
    }

    pub(super) struct Channel(UnixStream);
    impl Drop for Channel {
        fn drop(&mut self) { let _ = self.0.shutdown(std::net::Shutdown::Both); }
    }

    pub(super) fn spawn(command: &mut Command, _cap: &crate::daemon::LaunchCap) -> Result<(Child, Channel)> {
        let (daemon, helper) = UnixStream::pair()?;
        daemon.set_read_timeout(Some(Duration::from_secs(2)))?;
        daemon.set_write_timeout(Some(Duration::from_secs(2)))?;
        // Move away from stdio/fd 3 before Rust applies its stdio redirections.
        let fd = unsafe { libc::fcntl(helper.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
        if fd < 0 { return Err(std::io::Error::last_os_error().into()); }
        use std::os::fd::FromRawFd;
        let inherited = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 3) < 0 { return Err(std::io::Error::last_os_error()); }
                // dup2 clears CLOEXEC: receiver MUST set it before any child spawn.
                Ok(())
            });
        }
        let parent = identity(std::process::id() as i32)?;
        let mut child = command.spawn()?;
        drop(inherited);
        drop(helper);
        let registration = match identity(child.id() as i32) {
            Ok(id) => id,
            Err(e) => { let _ = child.kill(); let _ = child.wait(); return Err(e); }
        };
        let mut responder = match daemon.try_clone() {
            Ok(socket) => socket,
            Err(e) => { let _ = child.kill(); let _ = child.wait(); return Err(e.into()); }
        };
        // Registration is complete before the first read. A software helper can
        // ignore fd 3; its completion shuts down the pending read without delay.
        std::thread::spawn(move || {
            let _ = respond(&mut responder, &mut Some(registration), parent);
            let _ = responder.shutdown(std::net::Shutdown::Both);
        });
        Ok((child, Channel(daemon)))
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn launch_channel_binds_identity_and_burns_registration() {
            for mode in ["correct", "wrong-pid", "wrong-start", "wrong-parent-start", "used"] {
                let (mut daemon, mut helper) = UnixStream::pair().unwrap();
                let current = identity(std::process::id() as i32).unwrap();
                let mut registered = current;
                let mut unrelated = if mode == "wrong-pid" { Some(Command::new("/bin/sleep").arg("5").spawn().unwrap()) } else { None };
                if let Some(child) = &unrelated { registered = identity(child.id() as i32).unwrap(); }
                if mode == "wrong-start" { registered.usec += 1; }
                let mut registration = if mode == "used" { None } else { Some(registered) };
                helper.write_all(&[7; 32]).unwrap();
                let mut parent = current;
                if mode == "wrong-parent-start" { parent.usec += 1; }
                let result = respond(&mut daemon, &mut registration, parent);
                if let Some(child) = &mut unrelated { child.kill().unwrap(); child.wait().unwrap(); }
                if mode == "correct" {
                    result.unwrap();
                    let mut response = [0; 72];
                    helper.read_exact(&mut response).unwrap();
                    assert_eq!(response.as_slice(), answer(&[7; 32], current, current));
                    assert_ne!(response.as_slice(), answer(&[8; 32], current, current), "old answer cannot match fresh nonce");
                    helper.write_all(&[8; 32]).unwrap();
                    assert!(respond(&mut daemon, &mut registration, current).is_err(), "second use refused");
                } else {
                    assert!(result.is_err(), "{mode} accepted");
                }
                assert!(registration.is_none(), "registration consumed even on refusal");
            }
        }

        #[test]
        fn launch_channel_real_child_and_receiver_cloexec_obligation() {
            // Software-only receiver; no Swift, key, clipboard or LAContext code.
            for set_cloexec in [true, false] {
                let script = r#"
import os, socket, fcntl, subprocess, sys
if sys.argv[1] == 'yes':
    fcntl.fcntl(3, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
s = socket.socket(fileno=3)
s.sendall(bytes([9])*32)
answer = b''
while len(answer) < 72:
    block = s.recv(72-len(answer))
    if not block: raise RuntimeError('short response')
    answer += block
assert answer[:32] == bytes([9])*32
assert int.from_bytes(answer[32:36], 'big') == os.getpid()
assert int.from_bytes(answer[52:56], 'big') == os.getppid()
# Shell has no fd allocations before this test, unlike Python startup.
r = subprocess.run(['/bin/sh', '-c', 'test -S /dev/fd/3'], close_fds=False)
assert (r.returncode != 0) == (sys.argv[1] == 'yes')
assert s.recv(1) == b''
print(answer.hex())
"#;
                let mut command = Command::new("/usr/bin/python3");
                command.args(["-c", script, if set_cloexec { "yes" } else { "no" }])
                    .env_clear().env("PATH", "/usr/bin:/bin")
                    .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
                let (child, channel) = crate::daemon::with_launch_cap(|cap| spawn(&mut command, cap)).unwrap();
                eprintln!("synthetic channel: parent={} exe={} child={} receiver_cloexec={set_cloexec}", std::process::id(), std::env::current_exe().unwrap().display(), child.id());
                let output = child.wait_with_output().unwrap();
                drop(channel);
                assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
                assert_eq!(String::from_utf8(output.stdout).unwrap().trim().len(), 144);
            }
        }

        #[test]
        fn launch_cap_construction_is_daemon_private() {
            let daemon = include_str!("daemon.rs");
            assert!(daemon.contains("pub(crate) struct LaunchCap("));
            for source in [include_str!("lib.rs"), include_str!("../../cli/src/main.rs"), include_str!("../../../app/src-tauri/src/main.rs")] {
                assert!(!source.contains("LaunchCap("));
            }
            let source = include_str!("helper.rs");
            let production = source.split("#[cfg(test)]\nmod repin_tests").next().unwrap();
            assert!(!production.contains("LaunchCap("));
            assert!(production.contains("fn call_at(_cap: &crate::daemon::LaunchCap"));
            assert!(production.contains("fn clip_at(_cap: &crate::daemon::LaunchCap"));
            let root = std::env::temp_dir().join(format!("karambit-cap-{}-{}", std::process::id(), rand::random::<u64>()));
            std::fs::create_dir(&root).unwrap();
            let declaration = daemon.lines().find(|line| line.starts_with("pub(crate) struct LaunchCap")).unwrap();
            std::fs::write(root.join("privacy.rs"), format!("mod daemon {{ {declaration} }} fn main() {{ let _ = daemon::LaunchCap(()); }}")).unwrap();
            let output = Command::new("rustc").arg(root.join("privacy.rs")).arg("-o").arg(root.join("privacy")).output().unwrap();
            assert!(!output.status.success(), "client constructed launch capability");
            assert!(String::from_utf8_lossy(&output.stderr).contains("private"));
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[cfg(test)]
    mod swift_receiver_tests {
        use super::*;
        use std::process::Stdio;

        struct Scratch(std::path::PathBuf);
        impl Scratch {
            fn new() -> Self {
                let path = std::env::temp_dir().join(format!("karambit-swift-receiver-{:016x}", rand::random::<u64>()));
                std::fs::create_dir(&path).unwrap(); Self(path)
            }
        }
        impl Drop for Scratch {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        fn build(root: &Path, source: &str) -> Option<std::path::PathBuf> {
            if Command::new("swift").arg("--version").output().is_err() {
                eprintln!("unsupported: Swift unavailable; receiver matrix skipped"); return None;
            }
            let package = root.join("package");
            std::fs::create_dir_all(package.join("Sources/se-helper")).unwrap();
            std::fs::write(package.join("Package.swift"), include_str!("../../../se-helper/Package.swift")).unwrap();
            std::fs::write(package.join("Sources/se-helper/main.swift"), source).unwrap();
            let scratch = root.join("build");
            let output = Command::new("swift").args(["build", "--package-path"]).arg(&package)
                .arg("--scratch-path").arg(&scratch).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            let output = Command::new("swift").args(["build", "--show-bin-path", "--package-path"]).arg(&package)
                .arg("--scratch-path").arg(&scratch).output().unwrap();
            assert!(output.status.success());
            let binary = Path::new(String::from_utf8_lossy(&output.stdout).trim()).join("karambit-se-helper");
            std::fs::create_dir_all(root.join("bin")).unwrap();
            let isolated = root.join("bin/helper");
            std::fs::copy(binary, &isolated).unwrap(); Some(isolated)
        }
        // No daemon is launched. This test process is the synthetic parent/responder.
        // All key directories are empty; only pubkeys, malformed-input ecdh and the
        // DEBUG-only post-gate fcntl probe are permitted here.
        fn run(binary: &Path, root: &Path, case: &str, replay: &mut Vec<u8>) -> String {
            let attacker = root.join("attacker"); std::fs::create_dir_all(&attacker).unwrap();
            let hash = sha256_file(&std::env::current_exe().unwrap()).unwrap();
            std::fs::write(attacker.join("daemon.sha256"), &hash).unwrap();
            let (mut socket, helper) = UnixStream::pair().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let fd = unsafe { libc::fcntl(helper.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
            assert!(fd >= 4);
            use std::os::fd::FromRawFd;
            let inherited = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
            let mut command = Command::new(binary);
            let verb = if case == "probe" { "__probe_fd3" } else if case == "absent" { "ecdh" } else { "pubkeys" };
            command.arg(verb).arg("--dir").arg(if case == "directory" { &attacker } else { root })
                .args(["--prompt", r#"{"id":"unlock","params":["synthetic"]}"#])
                .env_clear().env("KARAMBIT_SE_TRUST_ROOT", root)
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let absent = case == "absent";
            unsafe { command.pre_exec(move || {
                if absent { libc::close(3); }
                else if libc::dup2(fd, 3) < 0 { return Err(std::io::Error::last_os_error()); }
                Ok(())
            }); }
            let child = command.spawn().unwrap();
            drop(inherited); drop(helper);
            let mut nonce = [0u8; 32];
            if !absent && socket.read_exact(&mut nonce).is_ok() {
                let mut response = answer(&nonce, identity(child.id() as i32).unwrap(), identity(std::process::id() as i32).unwrap());
                match case {
                    "short" => response.truncate(8),
                    "closed" => response.clear(),
                    "nonce" => response[0] ^= 1,
                    "identity" => response[71] ^= 1,
                    "child-pid" => response[35] ^= 1,
                    "child-seconds" => response[43] ^= 1,
                    "child-microseconds" => response[51] ^= 1,
                    "parent-pid" => response[55] ^= 1,
                    "parent-seconds" => response[63] ^= 1,
                    "replay" => response = replay.clone(),
                    _ => *replay = response.clone(),
                }
                let _ = socket.write_all(&response);
            }
            let _ = socket.shutdown(std::net::Shutdown::Both);
            let output = child.wait_with_output().unwrap();
            let text = String::from_utf8(output.stdout).unwrap();
            let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| panic!("invalid helper output {text:?}: {}", String::from_utf8_lossy(&output.stderr)));
            eprintln!("Swift receiver {case}: {value}");
            if case == "probe" {
                assert!(output.status.success()); assert_eq!(value["cloexec"], libc::FD_CLOEXEC); return String::new();
            }
            assert!(!output.status.success());
            value["error"].as_str().unwrap().to_string()
        }
        fn pin(root: &Path, valid: bool) {
            std::fs::write(root.join("daemon.sha256"), if valid {
                sha256_file(&std::env::current_exe().unwrap()).unwrap()
            } else { "0".repeat(64) }).unwrap();
        }
        fn downstream(error: &str) {
            assert!(!error.starts_with("caller refused:"), "{error}");
            assert!(!error.is_empty());
        }
        #[test]
        fn swift_receiver_matrix() {
            let scratch = Scratch::new();
            let Some(binary) = build(&scratch.0, include_str!("../../../se-helper/Sources/se-helper/main.swift")) else { return; };
            let root = scratch.0.join("keys"); std::fs::create_dir(&root).unwrap(); pin(&root, true);
            let mut replay = vec![];
            downstream(&run(&binary, &root, "positive", &mut replay));
            for (case, reason) in [("absent", "channel peer"), ("directory", "key directory not trusted"),
                ("short", "channel read"), ("closed", "channel read"), ("nonce", "nonce mismatch"),
                ("identity", "channel identity"), ("child-pid", "channel identity"),
                ("child-seconds", "channel identity"), ("child-microseconds", "channel identity"),
                ("parent-pid", "channel identity"), ("parent-seconds", "channel identity"),
                ("replay", "nonce mismatch")] {
                assert_eq!(run(&binary, &root, case, &mut replay), format!("caller refused: {reason}"));
            }
            pin(&root, false);
            assert_eq!(run(&binary, &root, "pin", &mut replay), "caller refused: parent pin mismatch");
            pin(&root, true); run(&binary, &root, "probe", &mut replay);
        }

        #[test]
        #[ignore = "subprocess-only synthetic union/prune parent"]
        fn swift_receiver_union_parent() {
            let Ok(root) = std::env::var("KARAMBIT_TEST_RECEIVER_ROOT") else { return; };
            let root = Path::new(&root);
            let binary = root.parent().unwrap().join("bin/helper");
            let error = run(&binary, root, "positive", &mut vec![]);
            if std::env::var("KARAMBIT_TEST_RECEIVER_REFUSE").is_ok() {
                assert_eq!(error, "caller refused: parent pin mismatch");
            } else { downstream(&error); }
        }

        #[test]
        fn swift_receiver_union_prune() {
            let scratch = Scratch::new();
            let Some(binary) = build(&scratch.0, include_str!("../../../se-helper/Sources/se-helper/main.swift")) else { return; };
            let root = scratch.0.join("keys"); std::fs::create_dir(&root).unwrap();
            let a = scratch.0.join("parent-a"); let b = scratch.0.join("parent-b");
            let exe = std::env::current_exe().unwrap();
            std::fs::copy(&exe, &a).unwrap(); std::fs::copy(&exe, &b).unwrap();
            // Distinct ad-hoc signatures change bytes without changing executable code.
            // Both are isolated test-runner copies, never daemon executables.
            let signed = Command::new("codesign").args(["--force", "--sign", "-", "--identifier", "karambit.synthetic.parent-b"])
                .arg(&b).output().unwrap();
            assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));
            let ha = sha256_file(&a).unwrap(); let hb = sha256_file(&b).unwrap(); assert_ne!(ha, hb);
            let helper_hash = sha256_file(&binary).unwrap();
            let pf = root.join("helper.sha256"); let df = root.join("daemon.sha256");
            let old = pin_body(std::iter::once(helper_hash.as_str()));
            bootstrap_pin(&pf, &old).unwrap(); bootstrap_pin(&df, &pin_body(std::iter::once(ha.as_str()))).unwrap();
            let union = pin_body([ha.as_str(), hb.as_str()].into_iter());
            publish_pair(&pf, &df, old.as_bytes(), old.as_bytes(), union.as_bytes()).unwrap();
            let invoke = |parent: &Path, refuse: bool| {
                let mut cmd = Command::new(parent);
                cmd.args(["--exact", "helper::launch_channel::swift_receiver_tests::swift_receiver_union_parent", "--ignored", "--nocapture"])
                    .env("KARAMBIT_TEST_RECEIVER_ROOT", &root).env_remove("KARAMBIT_TEST_RECEIVER_REFUSE");
                if refuse { cmd.env("KARAMBIT_TEST_RECEIVER_REFUSE", "1"); }
                let output = cmd.output().unwrap();
                eprintln!("union/prune {} refused={refuse}: {}", parent.display(), String::from_utf8_lossy(&output.stderr));
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
                assert!(output.status.success());
            };
            invoke(&a, false); invoke(&b, false);
            let pruned = pin_body(std::iter::once(hb.as_str()));
            publish_pair(&pf, &df, old.as_bytes(), old.as_bytes(), pruned.as_bytes()).unwrap();
            invoke(&a, true); invoke(&b, false);
        }

        #[test]
        #[ignore = "expensive mutation evidence: explicitly run after receiver matrix"]
        fn swift_receiver_mutations() {
            let source = include_str!("../../../se-helper/Sources/se-helper/main.swift");
            let channel_start = source.find("    var peer: pid_t = 0").unwrap();
            let channel_end = source.find("    guard getppid() == parentPID").unwrap();
            let aggregate = format!("{}{}", &source[..channel_start], &source[channel_end..]);
            let identity_start = source.find("    guard number(32..<36)").unwrap();
            let identity_end = source[identity_start..].find("    else { callerRefused(\"channel identity\") }").unwrap() + identity_start;
            let identity_guard = &source[identity_start..identity_end];
            let mutations = [
                ("absent", aggregate.clone()), ("short", aggregate.clone()), ("closed", aggregate),
                ("directory", source.replace("canonicalPath(directory) == trusted", "canonicalPath(directory) != nil")),
                ("pin", source.replace(".contains(hash) else", ".contains(hash) || true else")),
                ("nonce", source.replace("Array(reply[0..<32]) == nonce else", "true else")),
                ("identity", source.replace(identity_guard, "    guard true\n")),
                // Replay has independent nonce AND child-start/PID defenses.
                // Exercise single and combined bypasses against the same stale reply.
                ("replay", source.replace("Array(reply[0..<32]) == nonce else", "true else")),
                ("replay-combined", source.replace("Array(reply[0..<32]) == nonce else", "true else").replace(identity_guard, "    guard true\n")),
            ];
            let mut captured_replay = vec![];
            let scratch = Scratch::new();
            for (case, mutant) in mutations {
                assert_ne!(source, mutant);
                let Some(binary) = build(&scratch.0, &mutant) else { return; };
                let root = scratch.0.join(case); std::fs::create_dir(&root).unwrap(); pin(&root, case != "pin");
                let mut replay = vec![];
                if case == "replay" || case == "replay-combined" {
                    // A full stale reply must STILL fail the independent identity guard.
                    if case == "replay" {
                        downstream(&run(&binary, &root, "positive", &mut replay));
                        captured_replay = replay.clone();
                    } else {
                        replay = captured_replay.clone();
                        assert_eq!(replay.len(), 72);
                    }
                    let result = run(&binary, &root, "replay", &mut replay);
                    if case == "replay" { assert_eq!(result, "caller refused: channel identity"); }
                    else { downstream(&result); }
                } else {
                    downstream(&run(&binary, &root, case, &mut replay));
                    if case == "identity" {
                        for field in ["child-pid", "child-seconds", "child-microseconds", "parent-pid", "parent-seconds"] {
                            downstream(&run(&binary, &root, field, &mut replay));
                        }
                    }
                }
            }
        }
    }

}
