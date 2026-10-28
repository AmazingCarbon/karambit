//! On-disk layout under the karambit dir (default ~/.local/share/karambit, override KARAMBIT_DIR):
//!   keys/bio.key, keys/open.key   SE-wrapped key blobs (useless off this Mac)
//!   keys/pub.json                 cached public keys
//!   secrets/<ns>/<name>.json      one envelope per secret
//!   config.json, audit.jsonl

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Secure Enclave key with .biometryCurrentSet: hardware-enforced Touch ID.
    Bio,
    /// Secure Enclave key without user presence: hardware-bound, no prompt.
    Open,
}

/// Which Secure Enclave key wraps a secret's DEK. Derived from policy (see
/// `KeyId::for_policy`), recorded per file so old vaults keep decrypting.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum KeyId {
    /// Touch ID key (bio tier). Usable only while the Mac is unlocked.
    Bio,
    /// No-prompt key, usable only while unlocked: "Only me" open secrets.
    Open,
    /// No-prompt key usable while the screen is locked (after first unlock since boot):
    /// open secrets agents may use, so background agent jobs survive a screen lock.
    Agent,
}

impl KeyId {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyId::Bio => "bio",
            KeyId::Open => "open",
            KeyId::Agent => "agent",
        }
    }
    /// Target key for a policy. `has_agent_key` is false on vaults that haven't run
    /// `karambit keys upgrade` yet; they keep using the open key.
    pub fn for_policy(tier: Tier, agent_allowed: bool, public: bool, has_agent_key: bool) -> KeyId {
        match tier {
            Tier::Bio => KeyId::Bio,
            Tier::Open if has_agent_key && (agent_allowed || public) => KeyId::Agent,
            Tier::Open => KeyId::Open,
        }
    }
    /// Key implied by the tier alone (files written before `key` existed).
    pub fn legacy(tier: Tier) -> KeyId {
        match tier {
            Tier::Bio => KeyId::Bio,
            Tier::Open => KeyId::Open,
        }
    }
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Bio => "bio",
            Tier::Open => "open",
        }
    }
    pub fn parse(s: &str) -> Result<Tier> {
        match s {
            "bio" | "on" | "touch" => Ok(Tier::Bio),
            "open" | "off" => Ok(Tier::Open),
            _ => bail!("tier must be on|off (bio|open)"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretFile {
    pub v: u32,
    pub name: String,
    pub tier: Tier,
    /// When false, `karambit run` refuses to inject this secret if an agent is in the caller chain.
    #[serde(default = "yes")]
    pub agent_allowed: bool,
    /// Non-secret (email, URL, account id): agents may read it and it is not redacted.
    /// Honored only for v>=2 files, where it is bound into the wrap AAD (tamper-proof).
    #[serde(default)]
    pub public: bool,
    pub eph: String,
    pub wrap_nonce: String,
    pub wrapped_dek: String,
    pub nonce: String,
    pub ct: String,
    #[serde(default)]
    pub backup: Option<String>,
    pub created: u64,
    pub updated: u64,
    /// Wrapping key; absent in older files (then implied by `tier`). Not in the AAD on
    /// purpose: editing it can only pick a key that fails to unwrap, never relax policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyId>,
}

fn yes() -> bool {
    true
}

impl SecretFile {
    /// Trustworthy public flag: a v1 file can't prove `public` (not in its AAD), so
    /// an agent editing `public: true` into an old file is ignored, not obeyed.
    pub fn is_public(&self) -> bool {
        self.public && self.v >= 2
    }
    /// The key this file is actually wrapped to. A recorded key that contradicts the
    /// tier (e.g. agent key on a bio secret) is rejected rather than trusted.
    pub fn key_id(&self) -> Result<KeyId> {
        match (self.key, self.tier) {
            (None, t) => Ok(KeyId::legacy(t)),
            (Some(k @ KeyId::Bio), Tier::Bio) | (Some(k @ (KeyId::Open | KeyId::Agent)), Tier::Open) => Ok(k),
            (Some(k), t) => bail!("{}: key {} doesn't match tier {} (tampered?)", self.name, k.as_str(), t.as_str()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub trusted_profiles: std::collections::BTreeMap<String, String>,
    /// Schema path -> SHA-256 of the sibling package.json `scripts` ("none" if absent), pinned
    /// with the schema. Optional so older builds still read the file.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub trusted_scripts: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub killed: Option<crate::policy::Killed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::policy::Policy>,
    /// Fixed Mode-C tools; credential policy supplies each tool's access level.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tools: std::collections::BTreeMap<String, crate::broker::fixed::Tool>,
    pub default_tier: Tier,
    /// Default AWS profile for the CLI's whoami command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    pub backup_recipient: Option<String>,
    /// Set while `backup rotate` is rewriting files: some copies may already be on `to`
    /// while `backup_recipient` still names `from`. Optional so older builds read the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_rotation: Option<BackupRotation>,
    pub clip_seconds: u32,
    /// Process names (basename) that mark an AI agent in the caller chain.
    pub agent_process_names: Vec<String>,
    /// Environment variables whose presence marks an agent session.
    pub agent_env_markers: Vec<String>,
    /// Built-in default names/markers (either list, case-insensitive) that a human has
    /// opted out of. `load_config` re-adds every built-in default not listed here, so
    /// a stale pinned list still gains newly shipped defaults (e.g. Hermes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_defaults: Vec<String>,
    /// Code-loading variables (`env::CODE_LOADING_ENV`) that agent callers may still pass
    /// through to approved programs. Only a human can add entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_env: Vec<String>,
    /// After a human unlocks an "Only me + Touch ID" secret, the daemon holds it for
    /// this many hours so you aren't re-prompted, until the screen locks. 0 disables.
    #[serde(default = "default_human_lease_hours")]
    pub human_lease_hours: f64,
    /// Named AWS access portals (IAM Identity Center), like the AWS CLI's `sso-session`.
    /// Not secret. Each SSO profile names one; each portal has its own login.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub sso_portals: std::collections::BTreeMap<String, SsoPortal>,
    /// Non-secret backend bindings. Credentials live only in encrypted secret entries.
    #[serde(default)]
    pub sources: std::collections::BTreeMap<String, crate::backend::SourceConfig>,
    /// Record launch argv as typed in the audit log. Off by default: argv can hold typed
    /// credentials. Turning it on is a relaxing change (human + Touch ID).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub audit_full_argv: bool,
    /// Top-level fields this build does not know (written by a newer or forked build).
    /// Kept verbatim so saving config here never silently drops them.
    #[serde(default, flatten, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unknown_fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// Let a caller that arrived over SSH do human-only verbs. Off by default: with
    /// Remote Login on, `ssh localhost karambit ...` looks like a human to detection.
    /// Turning it on relaxes (human-only, Touch ID).
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_ssh_human: bool,
}

/// An unfinished backup rotation (see `Config::backup_rotation`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BackupRotation {
    pub from: Option<String>,
    pub to: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SsoPortal {
    pub start_url: String,
    pub region: String,
    /// Sign the portal out this many minutes after each sign-in, even if AWS would
    /// keep renewing it (None = as long as AWS allows). Can only end a sign-in sooner
    /// than IAM Identity Center's own session duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_minutes: Option<u32>,
    /// Account id -> account name, as the portal listed them at import. Display only:
    /// not secret, not authority (profiles carry their own account id).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub accounts: std::collections::BTreeMap<String, String>,
}

fn default_human_lease_hours() -> f64 {
    3.0
}

/// Built-in agent process names (matched case-insensitively against process names and
/// path segments of the executable/argv).
pub const DEFAULT_AGENT_PROCESS_NAMES: &[&str] = &[
    "pi", "claude", "kiro", "kiro-cli", "codex", "cursor-agent", "aider", "gemini",
    "opencode", "goose", "amp", "crush", "hermes", "hermes-agent", "hermes-acp",
];

/// Built-in environment variables whose presence marks an agent session.
pub const DEFAULT_AGENT_ENV_MARKERS: &[&str] = &[
    "PI_CODING_AGENT", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX",
    "CURSOR_AGENT", "AIDER_MODEL", "GEMINI_CLI", "OPENCODE",
];

impl Config {
    /// Union every built-in default into the pinned lists, except those the human listed
    /// in `removed_defaults`. The opt-out wins by itself: a removed built-in is also
    /// filtered out of the pinned list. Custom (non-default) entries and order are kept.
    /// Process names compare case-insensitively (detection lowercases them); env markers
    /// compare exactly, because env variable names are case-sensitive.
    pub fn merge_defaults(&mut self) {
        fn merge(list: &mut Vec<String>, defaults: &[&str], removed: &[String], same: fn(&str, &str) -> bool) {
            let opted_out = |s: &str| defaults.iter().any(|d| same(s, d)) && removed.iter().any(|r| same(s, r));
            list.retain(|s| !opted_out(s));
            for d in defaults {
                if !list.iter().any(|s| same(s, d)) && !opted_out(d) {
                    list.push((*d).to_string());
                }
            }
        }
        let ci: fn(&str, &str) -> bool = |a, b| a.eq_ignore_ascii_case(b);
        let exact: fn(&str, &str) -> bool = |a, b| a == b;
        merge(&mut self.agent_process_names, DEFAULT_AGENT_PROCESS_NAMES, &self.removed_defaults, ci);
        merge(&mut self.agent_env_markers, DEFAULT_AGENT_ENV_MARKERS, &self.removed_defaults, exact);
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            trusted_profiles: Default::default(),
            trusted_scripts: Default::default(),
            killed: None,
            policy: None,
            tools: Default::default(),
            default_tier: Tier::Bio,
            default_profile: None,
            backup_recipient: None,
            backup_rotation: None,
            clip_seconds: 30,
            agent_process_names: DEFAULT_AGENT_PROCESS_NAMES.iter().map(|s| s.to_string()).collect(),
            agent_env_markers: DEFAULT_AGENT_ENV_MARKERS.iter().map(|s| s.to_string()).collect(),
            removed_defaults: vec![],
            allow_env: vec![],
            human_lease_hours: default_human_lease_hours(),
            sso_portals: Default::default(),
            sources: Default::default(),
            audit_full_argv: false,
            unknown_fields: Default::default(),
            allow_ssh_human: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Paths> {
        let root = match std::env::var_os("KARAMBIT_DIR") {
            Some(d) => PathBuf::from(d),
            None => {
                let home = std::env::var_os("HOME").context("HOME unset")?;
                PathBuf::from(home).join(".local/share/karambit")
            }
        };
        Ok(Paths { root })
    }
    pub fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }
    pub fn pubkeys(&self) -> PathBuf {
        self.keys().join("pub.json")
    }
    /// Present while a recovery has replaced the keys but not yet rewrapped every file.
    pub fn recovery_pending(&self) -> PathBuf {
        self.root.join("recovery.pending")
    }
    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets")
    }
    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }
    pub fn audit(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }
    pub fn secret(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.secrets().join(format!("{name}.json")))
    }
    pub fn initialized(&self) -> bool {
        self.keys().join("bio.key").exists() && self.keys().join("open.key").exists()
    }
    /// Vault has the lock-safe agent key (new vaults, or after `karambit keys upgrade`).
    pub fn has_agent_key(&self) -> bool {
        self.keys().join("agent.key").exists()
    }
}

/// `ns/sub/name`, segments of [A-Za-z0-9._-], no leading dot, no traversal.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 200
        && name.split('/').all(|s| {
            !s.is_empty()
                && !s.starts_with('.')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        });
    if !ok {
        bail!("invalid secret name {name:?}: use ns/name with [A-Za-z0-9._-]");
    }
    Ok(())
}

/// Generic secret mutation must not bypass source management authorization.
pub(crate) fn require_generic_name(name: &str) -> Result<()> {
    if name == "sources" || name.starts_with("sources/") {
        bail!("sources/* is reserved for source management");
    }
    Ok(())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn ensure_dir(p: &Path) -> Result<()> {
    fs::create_dir_all(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Atomic write: tmp file (0600) + fsync + rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().context("no parent")?;
    ensure_dir(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn load_config(p: &Paths) -> Result<Config> {
    match fs::read(p.config()) {
        Ok(b) => {
            let mut cfg: Config = serde_json::from_slice(&b).context("config.json")?;
            cfg.merge_defaults();
            Ok(cfg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e.into()),
    }
}

pub fn save_config(p: &Paths, c: &Config) -> Result<()> {
    let lock = lock_config(p)?;
    lock.save(c)
}

/// Serialize config comparison and persistence, including ordinary config saves.
/// Separate lock file: config.json is replaced by atomic rename.
pub(crate) struct ConfigLock<'a> {
    paths: &'a Paths,
    _lock: fs::File,
}

pub(crate) fn lock_config(p: &Paths) -> Result<ConfigLock<'_>> {
    ensure_dir(&p.root)?;
    let lock = fs::OpenOptions::new().create(true).append(true).mode(0o600)
        .open(p.root.join("config.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(ConfigLock { paths: p, _lock: lock })
}

#[cfg(test)]
thread_local! { pub(crate) static FAIL_CONFIG_SAVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

impl ConfigLock<'_> {
    pub(crate) fn load(&self) -> Result<Config> { load_config(self.paths) }
    pub(crate) fn save(&self, c: &Config) -> Result<()> {
        #[cfg(test)]
        if FAIL_CONFIG_SAVE.with(|h| h.replace(false)) { bail!("injected config save failure"); }
        write_atomic(&self.paths.config(), &serde_json::to_vec_pretty(c)?)
    }
}

pub fn load_secret(p: &Paths, name: &str) -> Result<SecretFile> {
    let path = p.secret(name)?;
    let b = fs::read(&path).with_context(|| format!("no such secret: {name}"))?;
    let f: SecretFile = serde_json::from_slice(&b).with_context(|| format!("corrupt: {name}"))?;
    if f.name != name {
        bail!("{name}: name mismatch in file (moved/tampered?)");
    }
    Ok(f)
}

pub fn save_secret(p: &Paths, f: &SecretFile) -> Result<()> {
    write_atomic(&p.secret(&f.name)?, &serde_json::to_vec_pretty(f)?)
}

pub fn list_secrets(p: &Paths) -> Result<Vec<SecretFile>> {
    let mut out = Vec::new();
    let root = p.secrets();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d)? {
            let e = e?;
            let path = e.path();
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            if fname.starts_with('.') {
                continue;
            }
            if e.file_type()?.is_dir() {
                stack.push(path);
            } else if let Some(stem) = fname.strip_suffix(".json") {
                let rel = path.parent().unwrap().strip_prefix(&root).unwrap();
                let name = if rel.as_os_str().is_empty() {
                    stem.to_string()
                } else {
                    format!("{}/{stem}", rel.to_string_lossy())
                };
                if let Ok(f) = load_secret(p, &name) {
                    out.push(f);
                }
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn remove_secret(p: &Paths, name: &str) -> Result<()> {
    let path = p.secret(name)?;
    fs::remove_file(&path).with_context(|| format!("no such secret: {name}"))?;
    // Prune now-empty namespace dirs.
    let mut d = path.parent().map(Path::to_path_buf);
    while let Some(dir) = d {
        if dir == p.secrets() || fs::remove_dir(&dir).is_err() {
            break;
        }
        d = dir.parent().map(Path::to_path_buf);
    }
    Ok(())
}

/// Simple glob: `*` matches within a segment, `**` / trailing `/*` style via `*` across `/` too.
pub fn glob_match(pat: &str, name: &str) -> bool {
    fn go(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some(a), Some(b)) if a == b => go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    go(pat.as_bytes(), name.as_bytes())
}

/// Publish a complete encrypted file without replacing a concurrently-created profile.
pub(crate) fn save_secret_new(p: &Paths, f: &SecretFile) -> Result<bool> {
    let path = p.secret(&f.name)?;
    let dir = path.parent().context("no parent")?;
    ensure_dir(dir)?;
    let tmp = dir.join(format!(".import-{}", crate::sso::sha256_hex(&crate::crypto::new_dek()[..])));
    let result = (|| -> Result<bool> {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(f)?)?;
        file.sync_all()?;
        match fs::hard_link(&tmp, &path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.into()),
        }
    })();
    let _ = fs::remove_file(tmp);
    result
}

#[cfg(test)]
mod unknown_field_tests {
    use super::*;

    #[test]
    fn save_config_keeps_unknown_top_level_fields() {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-unknown-fields-{}", std::process::id())) };
        let _ = fs::remove_dir_all(&p.root);
        ensure_dir(&p.root).unwrap();
        let mut raw = serde_json::to_value(Config::default()).unwrap();
        raw["future_feature"] = serde_json::json!({"mode": "x", "n": [1, 2]});
        raw["policy"] = serde_json::json!({"rules": []});
        fs::write(p.config(), raw.to_string()).unwrap();

        // An ordinary read-modify-write, as every config change does.
        let mut cfg = load_config(&p).unwrap();
        cfg.clip_seconds = 12;
        save_config(&p, &cfg).unwrap();

        let saved: serde_json::Value = serde_json::from_slice(&fs::read(p.config()).unwrap()).unwrap();
        assert_eq!(saved["future_feature"], raw["future_feature"]);
        assert_eq!(saved["clip_seconds"], 12);
        assert!(saved.get("policy").is_some(), "known fields stay in place, not duplicated into the extra map");
        // A config with no unknown fields adds no noise.
        let mut plain = serde_json::to_value(Config::default()).unwrap();
        plain.as_object_mut().unwrap().remove("future_feature");
        assert_eq!(serde_json::to_value(Config::default()).unwrap(), plain);
        fs::remove_dir_all(&p.root).unwrap();
    }
}
