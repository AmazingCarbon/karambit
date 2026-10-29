//! karambit-core: shared by the CLI and the Tauri GUI.

pub mod platform;
pub mod agent;
pub mod audit;
pub mod aws;
pub mod backend;
pub mod broker;
pub mod crypto;
pub mod env;
pub mod envspec;
pub mod daemon;
pub mod fence;
pub mod helper;
pub mod lease;
mod launch;
pub mod shim;
pub use platform::sandbox;
pub mod redact;
pub mod sso;
pub mod policy;
pub mod store;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub use agent::Caller;
pub use store::{Config, KeyId, Paths, SecretFile, Tier};

use crypto::Dek;
use platform::helper::{Prompt, PubKeys};

#[cfg(test)]
thread_local! {
    pub(crate) static BEFORE_LIMIT_COMMIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// What `recover` has done since it replaced the keys. Lets a second run after a crash
/// finish the job instead of retiring the new keys again.
#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryProgress {
    /// Digest of pub.json the progress belongs to; a different key set invalidates it.
    pubkeys_sha256: String,
    rewrapped: std::collections::BTreeSet<String>,
}

fn pubkeys_digest(paths: &Paths) -> Result<String> {
    Ok(sso::sha256_hex(&std::fs::read(paths.pubkeys())?))
}

/// Result of trial-decrypting every backup copy with one paper key.
#[derive(Debug)]
pub struct BackupCheck {
    pub total: usize,
    pub opened: usize,
    /// (secret, why the paper key cannot recover it)
    pub unreadable: Vec<(String, &'static str)>,
    /// Set while a `backup rotate` is unfinished.
    pub rotation: Option<store::BackupRotation>,
}

/// Why the paper key could not recover this file, or Ok if its backup unwraps and opens it.
fn paper_opens(f: &SecretFile, id: &age::x25519::Identity) -> std::result::Result<(), &'static str> {
    let Some(b) = &f.backup else { return Err("no backup copy") };
    let dek = crypto::backup_unwrap(b, id).map_err(|_| "backup copy does not open with this paper key")?;
    crypto::open(&dek, f).map(|_| ()).map_err(|_| "backup copy opens but does not match the secret")
}

fn unrecoverable(files: &[SecretFile], id: &age::x25519::Identity) -> Vec<(String, &'static str)> {
    files.iter().filter_map(|f| paper_opens(f, id).err().map(|why| (f.name.clone(), why))).collect()
}

/// Decide which files recovery will give up on. Every file must be recoverable from the
/// paper key unless the human named exactly the unrecoverable set in `accept_loss`.
fn plan_recovery(files: &[SecretFile], id: &age::x25519::Identity, accept_loss: &[String]) -> Result<std::collections::BTreeSet<String>> {
    let failing = unrecoverable(files, id);
    let failing_names: std::collections::BTreeSet<String> = failing.iter().map(|(n, _)| n.clone()).collect();
    let accepted: std::collections::BTreeSet<String> = accept_loss.iter().cloned().collect();
    if failing_names == accepted { return Ok(accepted); }
    let list = failing.iter().map(|(n, why)| format!("{n} ({why})")).collect::<Vec<_>>().join(", ");
    if failing.is_empty() {
        bail!("--accept-loss names secrets the paper key can recover: {}; nothing was changed",
            accepted.iter().cloned().collect::<Vec<_>>().join(", "));
    }
    bail!("this paper key cannot recover {} of {} secrets: {list}. Nothing was changed. \
        To recover the rest and give these up, run `karambit recover --accept-loss {}`",
        failing.len(), files.len(), failing_names.iter().cloned().collect::<Vec<_>>().join(","))
}

// Encrypted envelope snapshots are taken consistently with source transactions.
struct MaintenanceSnapshot {
    config: Config,
    files: Vec<SecretFile>,
    source_credentials: std::collections::HashSet<std::path::PathBuf>,
    bytes: HashMap<String, Zeroizing<Vec<u8>>>,
}
impl MaintenanceSnapshot {
    fn load(paths: &Paths) -> Result<Self> {
        let lock = store::lock_config(paths)?;
        let config = lock.load()?;
        let mut files = Vec::new();
        let mut bytes = HashMap::new();
        for listed in store::list_secrets(paths)? {
            let raw = Zeroizing::new(std::fs::read(paths.secret(&listed.name)?)?);
            let file: SecretFile = serde_json::from_slice(&raw)?;
            anyhow::ensure!(file.name == listed.name, "envelope name changed");
            bytes.insert(file.name.clone(), raw);
            files.push(file);
        }
        let source_credentials = Self::source_credential_paths(paths)?;
        Ok(Self { config, files, source_credentials, bytes })
    }
    // Compare actual paths, including malformed envelopes skipped by list_secrets.
    fn source_credential_paths(paths: &Paths) -> Result<std::collections::HashSet<std::path::PathBuf>> {
        let root = paths.secrets().join("sources");
        let mut found = std::collections::HashSet::new();
        let mut pending = vec![root];
        while let Some(dir) = pending.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for entry in entries {
                let entry = entry?;
                if entry.file_type()?.is_dir() { pending.push(entry.path()); }
                else if entry.file_name() == "cred.json" { found.insert(entry.path()); }
            }
        }
        Ok(found)
    }
    fn check_file(&self, paths: &Paths, current: &Config, file: &SecretFile) -> Result<()> {
        let raw = Zeroizing::new(std::fs::read(paths.secret(&file.name)?).context("maintenance envelope vanished")?);
        anyhow::ensure!(self.bytes.get(&file.name) == Some(&raw), "maintenance envelope changed");
        if let Some(name) = file.name.strip_prefix("sources/").and_then(|s| s.strip_suffix("/cred")) {
            anyhow::ensure!(current.sources.get(name) == self.config.sources.get(name), "maintenance source changed");
        }
        Ok(())
    }
}

/// Semantic run authorization, independent of I/O and proof execution. Cache inputs
/// mean *validated* hits from Use (including scope, human-cache anchor and screen lock),
/// never mere presence in a map. A decision is not an authentication proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunAuthorization { Lease, OpenPublic, AgentAllowed, HumanCached, NeedsFreshAuth, Deny }

/// Refusal for a remote (SSH) caller that would need a human: nobody provably at the
/// keyboard answers the prompt or owns the cache. The text names no secret.
pub(crate) const SSH_HUMAN_REFUSAL: &str = "refused over SSH; set allow-ssh-human from a local terminal to allow";

/// A non-agent caller that arrived over SSH while `allow_ssh_human` is off.
pub(crate) fn ssh_without_human(caller: &Caller) -> bool {
    caller.remote && !caller.remote_allowed && !caller.is_agent()
}

pub(crate) fn run_authorization(caller: &Caller, file: &SecretFile, explicit_lease: bool, human_cache: bool) -> RunAuthorization {
    use RunAuthorization::*;
    let decision = if caller.is_agent() {
        if !file.is_public() && explicit_lease { return Lease; }
        if !file.agent_allowed && !file.is_public() { return Deny; }
        run_authorization_open(caller, file, false)
    } else {
        run_authorization_open(caller, file, human_cache)
    };
    // `ssh host karambit run ...` has no agent in its chain and would otherwise still
    // get a Touch ID prompt for an Only-me secret; agent-allowed and public ones stay usable.
    if ssh_without_human(caller) && matches!(decision, NeedsFreshAuth | HumanCached) { Deny } else { decision }
}

fn run_authorization_open(caller: &Caller, file: &SecretFile, human_cache: bool) -> RunAuthorization {
    use RunAuthorization::*;
    if human_cache && file.tier == Tier::Bio && !file.agent_allowed && !file.is_public() {
        return HumanCached;
    }
    if file.tier == Tier::Bio || (file.tier == Tier::Open && !file.is_public() && !caller.is_agent() && !file.agent_allowed) {
        NeedsFreshAuth
    } else if file.is_public() { OpenPublic } else { AgentAllowed }
}

/// The legacy Unlock human-cache eligibility gate, shared with bound launches.
pub(crate) fn human_cache_eligible(caller: &Caller, cfg: &Config, file: &SecretFile) -> bool {
    !caller.is_agent() && !ssh_without_human(caller) && cfg.human_lease_hours > 0.0
        && file.tier == Tier::Bio && !file.agent_allowed && !file.is_public()
}

/// Whether this policy change relaxes any of `files` (Touch ID off, agents allowed, public on).
fn policy_relaxes(files: &[SecretFile], tier: Option<Tier>, agent_allowed: Option<bool>, public: Option<bool>) -> bool {
    files.iter().any(|f| {
        (tier == Some(Tier::Open) && f.tier == Tier::Bio)
            || (agent_allowed == Some(true) && !f.agent_allowed)
            || (public == Some(true) && !f.is_public())
    })
}

pub struct Karambit {
    pub paths: Paths,
    pub cfg: Config,
    pub caller: Caller,
    /// Advisory command for legacy Use callers. Bound `run` carries a separate target.
    pub run_cmd: Option<String>,
}

#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct SecretMeta {
    pub name: String,
    pub tier: Tier,
    pub agent_allowed: bool,
    pub public: bool,
    pub has_backup: bool,
    pub created: u64,
    pub updated: u64,
    /// Active lease on this secret, if any (filled in by `list`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<daemon::LeaseView>,
}

impl From<&SecretFile> for SecretMeta {
    fn from(f: &SecretFile) -> Self {
        SecretMeta {
            name: f.name.clone(),
            tier: f.tier,
            agent_allowed: f.agent_allowed,
            public: f.is_public(),
            has_backup: f.backup.is_some(),
            created: f.created,
            updated: f.updated,
            lease: None,
        }
    }
}

pub type Plain = Zeroizing<Vec<u8>>;

pub struct Unlocked {
    pub name: String,
    pub value: Plain,
    pub public: bool,
}

pub(crate) struct UnlockedInternal {
    pub name: String,
    pub value: Plain,
    pub public: bool,
    pub dek: Dek,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct CopyResult {
    pub copied: Vec<String>,
    pub clears_in: u32,
}

impl Karambit {
    /// Open the vault for a CLI invocation (caller chain auto-detected).
    pub fn open_cli() -> Result<Karambit> {
        let paths = Paths::resolve()?;
        let cfg = store::load_config(&paths)?;
        let caller = agent::detect(&cfg);
        Ok(Karambit { paths, cfg, caller, run_cmd: None })
    }

    pub fn open_with(caller: Caller) -> Result<Karambit> {
        let paths = Paths::resolve()?;
        let cfg = store::load_config(&paths)?;
        Ok(Karambit { paths, cfg, caller, run_cmd: None })
    }

    fn require_init(&self) -> Result<()> {
        if !self.paths.initialized() {
            bail!("vault not initialized at {} (run `karambit init`)", self.paths.root.display());
        }
        Ok(())
    }

    /// Key a secret with this policy should be wrapped to in this vault.
    fn key_for(&self, tier: Tier, agent_allowed: bool, public: bool) -> KeyId {
        KeyId::for_policy(tier, agent_allowed, public, self.paths.has_agent_key())
    }

    fn audit(&self, action: &str, secrets: &[String], detail: Value, r: &Result<()>) {
        if let Err(e) = audit::log(
            &self.paths,
            audit::Event { action, secrets, caller: &self.caller, detail, result: r },
        ) { eprintln!("karambit: audit event failed: {e:#}"); }
    }

    /// Require an intent before `f`; containment instead logs best effort after effect.
    fn audited<T>(&self, action: &str, secrets: &[String], detail: Value, f: impl FnOnce() -> Result<T>) -> Result<T> {
        if matches!(action, "revoke" | "sso-logout") {
            audit::containment(&self.paths, action, &self.caller, f)
        } else {
            audit::run(&self.paths, action, secrets, &self.caller, detail, f)
        }
    }

    /// Capability fence lookup: refuse `verb` from an agent caller when
    /// `fence::AGENT_DENIED_VERBS` fences it at `layer`. The only place human-only
    /// refusals are decided.
    pub fn require_human(&self, verb: fence::Verb, layer: fence::Layer) -> Result<()> {
        fence::require_human(&self.caller, verb, layer)
    }

    /// Names for a Touch ID prompt: up to three, else a count. Refused when the list would be
    /// cut at the helper's 120-character field, so an approver never sees a shortened list.
    fn prompt_names(names: &[String]) -> Result<String> {
        let text = if names.len() <= 3 { names.join(", ") } else { format!("{} secrets", names.len()) };
        if platform::helper::prompt_param(&text) != text { bail!("too many secrets for one prompt; use fewer or a narrower pattern"); }
        Ok(text)
    }

    // ---------- setup ----------

    pub fn init(&mut self, backup_recipient: Option<String>) -> Result<Value> {
        self.require_human(fence::Verb::Init, fence::Layer::Cli)?;
        let result = daemon::request(&self.paths, &daemon::Req::Init { backup_recipient })?;
        self.cfg = store::load_config(&self.paths)?;
        Ok(result)
    }

    pub fn status(&self) -> Result<Value> {
        daemon::request(&self.paths, &daemon::Req::StatusSelftest)
    }

    pub fn helper_pin(&self) -> Result<Vec<(std::path::PathBuf, String)>> {
        self.helper_pin_staged(None, None)
    }

    pub fn helper_pin_staged(&self, stage_daemon: Option<std::path::PathBuf>, stage_helper: Option<std::path::PathBuf>) -> Result<Vec<(std::path::PathBuf, String)>> {
        // Resolve relative CLI/library paths in the client's cwd, not the daemon's.
        // The daemon still hashes the files and derives all approval authority.
        let stage_daemon = stage_daemon.map(std::fs::canonicalize).transpose()?;
        let stage_helper = stage_helper.map(std::fs::canonicalize).transpose()?;
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::HelperPin { stage_daemon, stage_helper })?)?)
    }

    /// No-prompt agent/public secrets still on the unlock-only key (pre-upgrade files).
    fn lock_unsafe<'a>(&self, files: &'a [SecretFile]) -> Vec<&'a SecretFile> {
        files
            .iter()
            .filter(|f| f.tier == Tier::Open && (f.agent_allowed || f.is_public()) && f.key_id().ok() != Some(KeyId::Agent))
            .collect()
    }

    /// Make agent-enabled secrets usable while the screen is locked: create the
    /// lock-safe agent key if missing, then rewrap every no-prompt secret agents may
    /// use onto it. Human-only, one Touch ID (it changes when secrets are reachable).
    /// Values, policy and backup copies are unchanged; only the DEK wrap moves.
    /// Returns (created key?, names moved).
    pub fn upgrade_keys(&self) -> Result<(bool, Vec<String>)> {
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::UpgradeKeys)?)?)
    }

    pub(crate) fn upgrade_keys_internal(&self) -> Result<(bool, Vec<String>)> {
        self.require_init()?;
        let files = store::list_secrets(&self.paths)?;
        let todo: Vec<SecretFile> = self.lock_unsafe(&files).into_iter().cloned().collect();
        let names: Vec<String> = todo.iter().map(|f| f.name.clone()).collect();
        let create = !self.paths.has_agent_key();
        if !create && todo.is_empty() {
            return Ok((false, vec![]));
        }
        self.audited("keys-upgrade", &names, json!({"created_agent_key": create}), || {
            platform::helper::auth(&Prompt::UpgradeKeys { names: if names.is_empty() { "no existing secrets".into() } else { Self::prompt_names(&names)? } })?;
            if create {
                let agent = platform::helper::addkey_agent(&self.paths.keys())?;
                let mut pk = platform::helper::pubkeys(&self.paths.keys())?;
                if pk.agent.as_deref() != Some(agent.as_slice()) {
                    bail!("agent key mismatch after creation");
                }
                pk.agent = Some(agent);
                store::write_atomic(&self.paths.pubkeys(), &serde_json::to_vec_pretty(&pk.to_json())?)?;
            }
            // Open-key secrets: no prompt, so the batch unwrap below is silent.
            let deks = self.unwrap_deks_local(&todo, &Prompt::MoveAgentKey {})?;
            let pk = self.pubkeys_local()?;
            for (f, dek) in todo.iter().zip(deks.iter()) {
                let w = crypto::wrap_dek(dek, pk.get(KeyId::Agent)?, &f.name, f.tier, f.agent_allowed, f.is_public())?;
                let mut nf = f.clone();
                nf.v = crypto::CURRENT_V;
                nf.public = f.is_public();
                nf.key = Some(KeyId::Agent);
                nf.eph = w.eph;
                nf.wrap_nonce = w.wrap_nonce;
                nf.wrapped_dek = w.wrapped_dek;
                // Verify the new wrap opens before replacing the old file.
                let check = self.unwrap_deks_local(std::slice::from_ref(&nf), &Prompt::VerifyAgentKey {})?;
                crypto::open(&check[0], &nf)?;
                store::save_secret(&self.paths, &nf)?;
            }
            Ok((create, names.clone()))
        })
    }

    // ---------- read-only ----------

    pub fn list(&self, pattern: Option<&str>) -> Result<Vec<SecretMeta>> {
        self.require_init()?;
        let leases = self.leases();
        Ok(store::list_secrets(&self.paths)?
            .iter()
            .filter(|f| pattern.is_none_or(|p| store::glob_match(p, &f.name)))
            .map(|f| {
                let mut m = SecretMeta::from(f);
                m.lease = leases.iter().find(|l| l.info.name == f.name).cloned();
                m
            })
            .collect())
    }

    fn resolve(&self, patterns: &[String]) -> Result<Vec<SecretFile>> {
        let all = store::list_secrets(&self.paths)?;
        let mut out: Vec<SecretFile> = Vec::new();
        for p in patterns {
            let hits: Vec<&SecretFile> = if p.contains('*') {
                all.iter().filter(|f| store::glob_match(p, &f.name)).collect()
            } else {
                all.iter().filter(|f| &f.name == p).collect()
            };
            if hits.is_empty() {
                bail!("no secret matches {p}");
            }
            for h in hits {
                if !out.iter().any(|o| o.name == h.name) {
                    out.push(h.clone());
                }
            }
        }
        Ok(out)
    }

    // ---------- write ----------

    /// Create or overwrite. Adding a new secret at the default policy (or stricter)
    /// needs no prompt (encryption only uses public keys, and nothing is lost);
    /// creating it Open while the default is Touch ID relaxes policy and needs Touch ID.
    /// Replacing an existing value always needs Touch ID, since it destroys the old one.
    pub fn add(&self, name: &str, value: &[u8], tier: Option<Tier>, agent_allowed: bool, public: bool, overwrite: bool) -> Result<SecretMeta> {
        self.require_human(fence::Verb::Add, fence::Layer::Cli)?;
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::Add { name: name.into(), value: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value), tier, agent_allowed, public, overwrite })?)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_internal(&self, name: &str, value: &[u8], tier: Option<Tier>, agent_allowed: bool, public: bool, overwrite: bool, dispatch: impl Fn(daemon::Req) -> Result<Value>) -> Result<SecretMeta> {
        self.require_init()?;
        store::validate_name(name)?;
        store::require_generic_name(name)?;
        if public && aws::is_aws_entry(name) {
            bail!("AWS credentials can't be public");
        }
        let names = [name.to_string()];
        let tier = tier.unwrap_or(self.cfg.default_tier);
        // No-prompt "Only me" is retired: it doesn't stop a determined same-user agent.
        if tier == Tier::Open && !agent_allowed && !public {
            bail!("no-prompt 'Only me' is retired (it doesn't stop a determined agent). Turn Touch ID on, or allow agents.");
        }
        self.audited("add", &names, json!({"tier": tier, "agent_allowed": agent_allowed, "public": public, "overwrite": overwrite}), || {
            let path = self.paths.secret(name)?;
            let existing = if path.exists() { Some(store::load_secret(&self.paths, name)?) } else { None };
            if existing.is_some() && !overwrite {
                bail!("{name} exists (use --force to overwrite)");
            }
            if value.is_empty() {
                bail!("empty value");
            }
            if self.caller.is_agent() {
                // Agents may add, but never create relaxed-policy secrets.
                if tier == Tier::Open && self.cfg.default_tier == Tier::Bio {
                    bail!("agent callers cannot create Touch-ID-off secrets");
                }
            }
            if existing.is_some() {
                platform::helper::auth(&Prompt::Overwrite { names: Self::prompt_names(&names)?, caller: self.caller.label() })?;
            } else if tier == Tier::Open && self.cfg.default_tier == Tier::Bio {
                let access = if public { "public access" } else { "agent access" };
                platform::helper::auth(&Prompt::AddRelaxed { names: Self::prompt_names(&names)?, caller: self.caller.label(), access: access.into() })?;
            }
            let pk = self.pubkeys_local()?;
            let dek = crypto::new_dek();
            let f = self.build_file(name, tier, agent_allowed, public, &dek, value, &pk, existing.as_ref().map(|e| e.created))?;
            store::save_secret(&self.paths, &f)?;
            // New value = new DEK: end any lease on the old one.
            if existing.is_some() {
                self.end_leases_internal(std::slice::from_ref(&f.name), "value replaced", &dispatch);
            }
            Ok(SecretMeta::from(&f))
        })
    }

    /// Source management only: caller has fresh approval and holds the config lock.
    pub(crate) fn put_source_credential(&self, name: &str, value: &[u8]) -> Result<()> {
        self.require_init()?;
        store::validate_name(name)?;
        anyhow::ensure!(name.starts_with("sources/") && name.ends_with("/cred"), "invalid credential path");
        anyhow::ensure!(!value.is_empty(), "empty credential");
        let pk = self.pubkeys_local()?;
        let file = self.build_file(name, Tier::Bio, false, false, &crypto::new_dek(), value, &pk, None)?;
        store::save_secret(&self.paths, &file)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_file(&self, name: &str, tier: Tier, agent_allowed: bool, public: bool, dek: &Dek, value: &[u8], pk: &PubKeys, created: Option<u64>) -> Result<SecretFile> {
        let key = self.key_for(tier, agent_allowed, public);
        let w = crypto::wrap_dek(dek, pk.get(key)?, name, tier, agent_allowed, public)?;
        let (nonce, ct) = crypto::seal(dek, name, value)?;
        let backup = match &self.cfg.backup_recipient {
            Some(r) => Some(crypto::backup_wrap(dek, r)?),
            None => None,
        };
        let t = store::now();
        Ok(SecretFile {
            v: crypto::CURRENT_V,
            name: name.into(),
            tier,
            agent_allowed,
            public,
            eph: w.eph,
            wrap_nonce: w.wrap_nonce,
            wrapped_dek: w.wrapped_dek,
            nonce,
            ct,
            backup,
            created: created.unwrap_or(t),
            updated: t,
            key: Some(key),
        })
    }

    fn pubkeys_local(&self) -> Result<PubKeys> {
        match platform::helper::pubkeys_cached(&self.paths.pubkeys()) {
            Ok(pk) if pk.agent.is_some() || !self.paths.has_agent_key() => Ok(pk),
            _ => platform::helper::pubkeys(&self.paths.keys()),
        }
    }

    fn unwrap_deks_local(&self, files: &[SecretFile], reason: &Prompt) -> Result<Vec<Dek>> {
        if files.is_empty() { return Ok(vec![]); }
        let pk = self.pubkeys_local()?;
        self.unwrap_deks_with_keys(files, reason, &pk)
    }

    fn unwrap_deks_with_keys(&self, files: &[SecretFile], reason: &Prompt, pk: &PubKeys) -> Result<Vec<Dek>> {
        let keys: Vec<KeyId> = files.iter().map(SecretFile::key_id).collect::<Result<_>>()?;
        let reqs: Vec<(KeyId, &str)> = keys.iter().zip(files).map(|(k, f)| (*k, f.eph.as_str())).collect();
        let shared = platform::helper::ecdh(&self.paths.keys(), reason, &reqs)?;
        files
            .iter()
            .zip(shared.iter())
            .zip(keys)
            .map(|((f, s), k)| crypto::unwrap_dek(f, s, pk.get(k)?))
            .collect()
    }

    /// Decrypt secrets for injection. Enforces per-secret agent policy.
    /// `gate_open`: also demand Touch ID for open-tier secrets (GUI reveal).
    /// A bio secret with an active lease covering this (agent) caller unwraps via
    /// the lease copy, without a prompt.
    pub fn unlock(&self, action: &str, names: &[String], context: Option<&str>, gate_open: bool) -> Result<Vec<Unlocked>> {
        let action = daemon::UnlockAction::parse(action)?;
        Ok(self.unlock_request(action, names, context, gate_open, None)?.0)
    }

    /// Copy one stored secret without delivering its value to this client.
    pub fn copy(&self, name: &str) -> Result<CopyResult> {
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::Copy { name: name.into() })?)?)
    }

    pub fn unlock_run(&self, names: &[String], context: &str, sso_profile: Option<String>) -> Result<(Vec<Unlocked>, Option<Value>)> {
        self.unlock_request(daemon::UnlockAction::Run, names, Some(context), false, sso_profile)
    }

    fn unlock_request(&self, action: daemon::UnlockAction, names: &[String], context: Option<&str>, gate_open: bool, sso_profile: Option<String>) -> Result<(Vec<Unlocked>, Option<Value>)> {
        if action == daemon::UnlockAction::Copy { bail!("use copy() for clipboard delivery; Copy never returns values"); }
        let response = daemon::request(&self.paths, &daemon::Req::Unlock {
            names: names.to_vec(), action, context: context.map(str::to_owned),
            cmd: self.run_cmd.clone(), gate_open, sso_profile, ttl: 12 * 3600,
        })?;
        let values = response["values"].as_array().context("missing unlock values")?.iter().map(|v| {
            Ok(Unlocked {
                name: v["name"].as_str().context("missing name")?.into(),
                value: Zeroizing::new(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v["value"].as_str().context("missing value")?)?),
                public: v["public"].as_bool().context("missing public flag")?,
            })
        }).collect::<Result<Vec<_>>>()?;
        Ok((values, response.get("endpoint").filter(|v| !v.is_null()).cloned()))
    }

    /// Daemon-only implementation; nested requests preserve the kernel Peer without RPC.
    pub(crate) fn unlock_internal(&self, action: &str, names: &[String], context: Option<&str>, gate_open: bool, dispatch: impl Fn(daemon::Req) -> Result<Value>) -> Result<Vec<UnlockedInternal>> {
        let paths = self.paths.clone();
        let caller = self.caller.clone();
        audit::run(&paths, "unlock-operation", &[], &caller, json!({}), || {
            self.require_init()?;
            let files = self.resolve(names)?;
            for file in &files {
                store::require_generic_name(&file.name)?;
                let action = match action {
                    "get" | "reveal" => policy::Action::Get,
                    "copy" => policy::Action::Copy,
                    "view" | "aws-describe" => policy::Action::View,
                    "fixed-call-credential" => policy::Action::Call,
                    _ => policy::Action::Run,
                };
                policy::enforce_args(&paths, &caller, action, policy::Subject::Secret(file.name.clone()), &json!({"names":names,"context":context,"gate_open":gate_open,"cmd":self.run_cmd}))?;
            }
            let resolved: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
            // Leases: only agents use them, and only via the daemon, which identifies
            // the caller from the kernel (not this process's environment).
            let wanted: Vec<String> = files.iter().filter(|f| !f.is_public()).map(|f| f.name.clone()).collect();
            let mut leased: HashMap<String, Dek> = HashMap::new();
            let mut lease_denied: Vec<String> = vec![];
            let mut via: Value = Value::Null;
            if self.caller.is_agent() && !gate_open && !wanted.is_empty() {
                let r = dispatch(daemon::Req::Use { names: wanted, cmd: self.run_cmd.clone() })?;
                if let Some(m) = r["deks"].as_object() {
                    for (n, v) in m {
                        let raw = Zeroizing::new(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v.as_str().unwrap_or(""))?);
                        if raw.len() == 32 {
                            let mut d = Zeroizing::new([0u8; 32]);
                            d.copy_from_slice(&raw);
                            leased.insert(n.clone(), d);
                        }
                    }
                }
                if let Some(m) = r["denied"].as_object() {
                    lease_denied = m.iter().map(|(n, why)| format!("{n}: {}", why.as_str().unwrap_or("denied"))).collect();
                }
                via = r["via"].clone();
            }
            // Human self-lease: "Only me + Touch ID" secrets (bio, agents off, not public).
            // The daemon serves cache hits only within the same kernel terminal/GUI anchor.
            // Cache misses require a daemon-observed Bio unwrap, not a client DEK claim.
            let human_q: Vec<String> = files.iter().filter(|f| human_cache_eligible(&self.caller, &self.cfg, f))
                .map(|f| f.name.clone()).collect();
            if !human_q.is_empty()
                && let Ok(r) = dispatch(daemon::Req::Use { names: human_q.clone(), cmd: self.run_cmd.clone() })
                && let Some(m) = r["deks"].as_object()
            {
                for (n, v) in m {
                    let raw = Zeroizing::new(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v.as_str().unwrap_or(""))?);
                    if raw.len() == 32 {
                        let mut d = Zeroizing::new([0u8; 32]);
                        d.copy_from_slice(&raw);
                        leased.insert(n.clone(), d);
                    }
                }
            }
            let decisions: HashMap<_, _> = files.iter().map(|f| {
                let hit = leased.contains_key(&f.name);
                (f.name.as_str(), run_authorization(&self.caller, f, hit && self.caller.is_agent(), hit && !self.caller.is_agent()))
            }).collect();
            let detail = if leased.is_empty() {
                json!({"context": context})
            } else {
                json!({"context": context, "via_lease": via})
            };
            #[cfg(test)]
            BEFORE_ACTION.with(|h| { if let Some(h) = h.borrow_mut().take() { h(); } });
            self.audited(action, &resolved, detail, || {
                if let Some(a) = &self.caller.agent {
                    // Public entries are readable by agents; agent_allowed governs the rest.
                    // A lease granted to this caller overrides "agents blocked".
                    let blocked: Vec<&str> = files
                        .iter()
                        .filter(|f| decisions[f.name.as_str()] == RunAuthorization::Deny)
                        .map(|f| f.name.as_str())
                        .collect();
                    if !blocked.is_empty() {
                        let why = if lease_denied.is_empty() { String::new() } else { format!("; lease refused: {}", lease_denied.join("; ")) };
                        bail!("agent ({a}) not allowed to use: {} (grant a lease to allow it){why}", blocked.join(", "));
                    }
                }
                // Over SSH with allow-ssh-human off, run_authorization turned every prompt-needing
                // decision into Deny: refuse before any Touch ID prompt or cache read.
                if ssh_without_human(&self.caller)
                    && (decisions.values().any(|d| *d == RunAuthorization::Deny) || (gate_open && files.iter().any(|f| !f.is_public()))) {
                    bail!("{SSH_HUMAN_REFUSAL}");
                }
                let misses: Vec<String> = if !human_q.is_empty() {
                    files.iter().filter(|f| f.tier == Tier::Bio && !leased.contains_key(&f.name)).map(|f| f.name.clone()).collect()
                } else { vec![] };
                let fresh_bio = !misses.is_empty();
                if !misses.is_empty() {
                    let r = dispatch(daemon::Req::HumanUnlock { names: misses })?;
                    if let Some(m) = r["deks"].as_object() {
                        for (name, encoded) in m {
                            let raw = Zeroizing::new(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.as_str().unwrap_or(""))?);
                            if raw.len() != 32 { bail!("bad daemon key"); }
                            let mut dek = Zeroizing::new([0u8; 32]);
                            dek.copy_from_slice(&raw);
                            leased.insert(name.clone(), dek);
                        }
                    }
                }
                let reason = Prompt::Use { names: Self::prompt_names(&resolved)?, caller: self.caller.label(), context: context.unwrap_or("").into() };
                // Only an actual Bio unwrap supplies fresh proof; cached Bio does not.
                let rest: Vec<SecretFile> = files.iter().filter(|f| !leased.contains_key(&f.name)).cloned().collect();
                let needs_open_proof = files.iter().any(|f| {
                    f.tier == Tier::Open && !f.is_public()
                        && (gate_open || run_authorization(&self.caller, f, false, false) == RunAuthorization::NeedsFreshAuth)
                });
                let keys = rest.iter().map(SecretFile::key_id).collect::<Result<Vec<_>>>()?;
                if needs_open_proof && !fresh_bio && !keys.contains(&KeyId::Bio) {
                    platform::helper::auth(&reason)?;
                }
                let mut rest_deks = self.unwrap_deks_local(&rest, &reason)?.into_iter();
                let deks: Vec<Dek> = files
                    .iter()
                    .map(|f| match leased.get(&f.name) {
                        Some(d) => Ok(d.clone()),
                        None => rest_deks.next().ok_or_else(|| anyhow::anyhow!("unwrap count mismatch")),
                    })
                    .collect::<Result<_>>()?;
                files
                    .iter()
                    .zip(deks.iter())
                    .map(|(f, d)| Ok(UnlockedInternal { name: f.name.clone(), value: crypto::open(d, f)?, public: f.is_public(), dek: d.clone() }))
                    .collect()
            })
        })
    }

    // ---------- leases ----------

    /// Let an agent use secrets without a prompt for `hours`. Any non-public secret can
    /// be leased (it also lets the grantee past "agents blocked"). Human-only; one
    /// Touch ID approves the batch. The unwrapped keys go to the daemon's memory only.
    /// Folder grants (`deploy/*`) cover the secrets that exist now, not later ones.
    pub fn grant_lease(&self, patterns: &[String], to: &lease::Grantee, hours: f64, scope: &daemon::Scope) -> Result<Vec<daemon::LeaseView>> {
        self.require_init()?;
        self.require_human(fence::Verb::LeaseGrant, fence::Layer::Cli)?;
        if !(hours > 0.0 && hours <= lease::MAX_HOURS) {
            bail!("lease length must be between 0 and {} hours", lease::MAX_HOURS);
        }
        let files = self.resolve(patterns)?;
        let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
        let expires = store::now() + (hours * 3600.0).round() as u64;
        let mut scope = scope.clone();
        if let Some(c) = &scope.cwd {
            let canon = daemon::canon_dir(c);
            if !std::path::Path::new(&canon).is_dir() {
                bail!("--cwd {c}: no such directory");
            }
            scope.cwd = Some(canon);
        }
        self.audited("lease", &names, json!({"to": to.label(), "hours": hours, "expires": expires, "patterns": patterns, "scope": scope}), || {
            let r = daemon::request(&self.paths, &daemon::Req::GrantLease { names: names.clone(), grantee: to.clone(), hours, scope: scope.clone() })?;
            Ok(serde_json::from_value(r["leases"].clone())?)
        })
    }

    /// End leases early. Agents may revoke (it only tightens); never prompts.
    pub fn revoke_lease(&self, patterns: &[String]) -> Result<Vec<String>> {
        self.require_init()?;
        let r = if daemon::running(&self.paths.root) {
            daemon::request(&self.paths, &daemon::Req::Revoke { patterns: patterns.to_vec() })?
        } else {
            json!({"revoked": []})
        };
        let hit: Vec<String> = serde_json::from_value(r["revoked"].clone()).unwrap_or_default();
        self.audited("revoke", &hit, json!({"patterns": patterns}), || {
            if hit.is_empty() {
                bail!("no active lease matches {}", patterns.join(" "));
            }
            Ok(hit.clone())
        })
    }

    /// Active leases (empty if the daemon isn't running: no daemon = no leases).
    pub fn leases(&self) -> Vec<daemon::LeaseView> {
        daemon::request_if_running(&self.paths, &daemon::Req::List)
            .and_then(|v| serde_json::from_value(v["leases"].clone()).ok())
            .unwrap_or_default()
    }

    /// Silently end leases on `names` (after a tightening change). Logged once.
    fn end_leases_internal(&self, names: &[String], why: &str, dispatch: impl Fn(daemon::Req) -> Result<Value>) {
        if names.is_empty() {
            return;
        }
        if let Ok(r) = dispatch(daemon::Req::Revoke { patterns: names.to_vec() }) {
            let hit: Vec<String> = serde_json::from_value(r["revoked"].clone()).unwrap_or_default();
            if !hit.is_empty() {
                self.audit("lease-ended", &hit, json!({"why": why}), &Ok(()));
            }
        }
    }

    /// Change Touch ID tier and/or agent access by rewrapping the DEK.
    /// Tightening never prompts for open secrets; relaxing is human-only and a bio
    /// source always costs a Touch ID (hardware-enforced by the unwrap).
    pub fn set_policy(&self, patterns: &[String], tier: Option<Tier>, agent_allowed: Option<bool>, public: Option<bool>) -> Result<Vec<SecretMeta>> {
        if self.caller.is_agent() || self.caller.remote {
            // Refuse a relaxation before the request; the daemon decides again from its kernel Peer.
            self.require_init()?;
            if policy_relaxes(&self.resolve(patterns)?, tier, agent_allowed, public) {
                self.require_human(fence::Verb::PolicyRelax, fence::Layer::Cli)?;
            }
        }
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::ChangePolicy { patterns: patterns.to_vec(), tier, agent_allowed, public })?)?)
    }

    pub(crate) fn set_policy_internal(&self, patterns: &[String], tier: Option<Tier>, agent_allowed: Option<bool>, public: Option<bool>, dispatch: impl Fn(daemon::Req) -> Result<Value>) -> Result<Vec<SecretMeta>> {
        self.require_init()?;
        let files = self.resolve(patterns)?;
        for f in &files { store::require_generic_name(&f.name)?; }
        let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
        self.audited("policy", &names, json!({"tier": tier, "agent_allowed": agent_allowed, "public": public}), || {
            if public == Some(true) && files.iter().any(|f| aws::is_aws_entry(&f.name)) {
                bail!("AWS credentials can't be public");
            }
            // No-prompt "Only me" is retired.
            for f in &files {
                let t = tier.unwrap_or(f.tier);
                let a = agent_allowed.unwrap_or(f.agent_allowed);
                let p = public.unwrap_or(f.is_public());
                if t == Tier::Open && !a && !p {
                    bail!("{}: no-prompt 'Only me' is retired. Turn Touch ID on, or allow agents.", f.name);
                }
            }
            let relaxing = policy_relaxes(&files, tier, agent_allowed, public);
            if relaxing {
                self.require_human(fence::Verb::PolicyRelax, fence::Layer::Daemon)?;
            }
            let changed: Vec<&SecretFile> = files
                .iter()
                .filter(|f| {
                    tier.is_some_and(|t| t != f.tier)
                        || agent_allowed.is_some_and(|a| a != f.agent_allowed)
                        || public.is_some_and(|p| p != f.is_public())
                })
                .collect();
            if changed.is_empty() {
                return Ok(files.iter().map(SecretMeta::from).collect());
            }
            let owned: Vec<SecretFile> = changed.iter().map(|f| (*f).clone()).collect();
            let reason = Prompt::ChangePolicy { names: Self::prompt_names(&names)?, caller: self.caller.label() };
            // Relaxing open-tier secrets unwraps without a prompt, so gate explicitly.
            if relaxing && owned.iter().all(|f| f.tier == Tier::Open) {
                platform::helper::auth(&reason)?;
            }
            let deks = self.unwrap_deks_local(&owned, &reason)?;
            let pk = self.pubkeys_local()?;
            for (f, dek) in owned.iter().zip(deks.iter()) {
                let t = tier.unwrap_or(f.tier);
                let a = agent_allowed.unwrap_or(f.agent_allowed);
                let p = public.unwrap_or(f.is_public());
                let key = self.key_for(t, a, p);
                let w = crypto::wrap_dek(dek, pk.get(key)?, &f.name, t, a, p)?;
                let mut nf = f.clone();
                nf.v = crypto::CURRENT_V;
                nf.tier = t;
                nf.agent_allowed = a;
                nf.public = p;
                nf.key = Some(key);
                nf.eph = w.eph;
                nf.wrap_nonce = w.wrap_nonce;
                nf.wrapped_dek = w.wrapped_dek;
                if nf.backup.is_none()
                    && let Some(r) = &self.cfg.backup_recipient {
                        nf.backup = Some(crypto::backup_wrap(dek, r)?);
                    }
                nf.updated = store::now();
                store::save_secret(&self.paths, &nf)?;
                // Last human action wins: blocking agents, turning Touch ID on, or making it
                // public ends any lease on this secret.
                let tightened = (f.agent_allowed && !nf.agent_allowed) || (f.tier == Tier::Open && nf.tier == Tier::Bio) || nf.public;
                if tightened {
                    self.end_leases_internal(std::slice::from_ref(&nf.name), "policy changed", &dispatch);
                }
            }
            // SSO profiles: the daemon enforces access from what a human registered, so
            // tell it now. Tightening applies for anyone; relaxing only via a human.
            let sso_names: Vec<String> = owned.iter().filter(|f| aws::is_aws_entry(&f.name)).map(|f| f.name.clone()).collect();
            if !sso_names.is_empty() {
                if self.caller.is_agent() {
                    let _ = dispatch(daemon::Req::SsoForget { names: sso_names });
                } else {
                    let _ = self.sso_sync_internal(&sso_names, &dispatch);
                }
            }
            Ok(self.resolve(patterns)?.iter().map(SecretMeta::from).collect())
        })
    }

    pub fn remove(&self, patterns: &[String]) -> Result<Vec<String>> {
        self.require_human(fence::Verb::Rm, fence::Layer::Cli)?;
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::Delete { patterns: patterns.to_vec() })?)?)
    }

    pub(crate) fn remove_internal(&self, patterns: &[String], dispatch: impl Fn(daemon::Req) -> Result<Value>) -> Result<Vec<String>> {
        self.require_init()?;
        let files = self.resolve(patterns)?;
        for f in &files { store::require_generic_name(&f.name)?; }
        let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
        self.audited("rm", &names, json!({}), || {
            if self.caller.is_agent() || files.iter().any(|f| f.tier == Tier::Bio) {
                platform::helper::auth(&Prompt::Delete { names: Self::prompt_names(&names)?, caller: self.caller.label() })?;
            }
            for n in &names {
                store::remove_secret(&self.paths, n)?;
            }
            self.end_leases_internal(&names, "deleted", &dispatch);
            let gone: Vec<String> = names.iter().filter(|n| aws::is_aws_entry(n)).cloned().collect();
            if !gone.is_empty() {
                let _ = dispatch(daemon::Req::SsoForget { names: gone });
            }
            Ok(names.clone())
        })
    }

    /// Rename one secret, or move a folder (`from` and `to` ending in `/`), keeping each
    /// value, access level, created time and DEK (so the offline backup copy stays valid).
    /// The name is bound into both AADs, so every file is resealed and rewrapped: one
    /// Touch ID approves the unwrap. New names must be free; leases on old names end.
    pub fn rename(&self, from: &str, to: &str) -> Result<Vec<(String, String)>> {
        self.require_human(fence::Verb::Rename, fence::Layer::Cli)?;
        let r = daemon::request(&self.paths, &daemon::Req::Rename { from: from.into(), to: to.into() })?;
        Ok(serde_json::from_value(r)?)
    }

    /// `(old, new)` pairs for a rename or folder move, validated, before any prompt.
    fn rename_plan(&self, from: &str, to: &str) -> Result<Vec<(SecretFile, String)>> {
        let folder = from.ends_with('/');
        anyhow::ensure!(folder == to.ends_with('/'), "rename a secret to a name, or a folder (ending in /) to a folder");
        let (src, dst) = (from.trim_end_matches('/'), to.trim_end_matches('/'));
        store::validate_name(src)?;
        store::validate_name(dst)?;
        anyhow::ensure!(src != dst, "{from} and {to} are the same");
        if folder {
            anyhow::ensure!(!dst.starts_with(&format!("{src}/")), "can't move {from} into itself");
        }
        let all = store::list_secrets(&self.paths)?;
        let moving: Vec<SecretFile> = if folder {
            all.iter().filter(|f| f.name.starts_with(&format!("{src}/"))).cloned().collect()
        } else {
            all.iter().filter(|f| f.name == src).cloned().collect()
        };
        if moving.is_empty() { bail!("no secret matches {from}"); }
        let plan: Vec<(SecretFile, String)> = moving.into_iter().map(|f| {
            let new = if folder { format!("{dst}{}", &f.name[src.len()..]) } else { dst.to_string() };
            (f, new)
        }).collect();
        for (f, new) in &plan {
            store::validate_name(new)?;
            for n in [&f.name, new] {
                store::require_generic_name(n)?;
                if n.starts_with("aws/") || n == "aws" { bail!("AWS profiles can't be renamed; add the profile again under the new name"); }
            }
            // x.json and the folder x/ are separate paths (as with `add`), so only an exact
            // name clashes; moving test/a to test/a/b is allowed.
            if all.iter().any(|o| &o.name == new) { bail!("{new} already exists"); }
        }
        Ok(plan)
    }

    pub(crate) fn rename_internal(&self, from: &str, to: &str, dispatch: impl Fn(daemon::Req) -> Result<Value>) -> Result<Vec<(String, String)>> {
        self.require_init()?;
        self.require_human(fence::Verb::Rename, fence::Layer::Daemon)?;
        let plan = self.rename_plan(from, to)?;
        // The approver must see both names in full (the helper cuts fields at 120 characters).
        for n in [from, to] {
            if platform::helper::prompt_param(n) != n { bail!("name too long for the Touch ID prompt: {n}"); }
        }
        let old: Vec<String> = plan.iter().map(|(f, _)| f.name.clone()).collect();
        let new: Vec<String> = plan.iter().map(|(_, n)| n.clone()).collect();
        self.audited("rename", &old, json!({"from": from, "to": to, "new": new}), || {
            let files: Vec<SecretFile> = plan.iter().map(|(f, _)| f.clone()).collect();
            let reason = Prompt::Rename { from: from.into(), to: to.into(), caller: self.caller.label() };
            // Open-tier secrets unwrap without a prompt; a rename still needs the human's Touch ID.
            if files.iter().all(|f| f.tier == Tier::Open) {
                platform::helper::auth(&reason)?;
            }
            let deks = self.unwrap_deks_local(&files, &reason)?;
            let pk = self.pubkeys_local()?;
            // Build and check everything before the first write.
            let mut built = Vec::with_capacity(plan.len());
            for ((f, name), dek) in plan.iter().zip(deks.iter()) {
                let value = crypto::open(dek, f)?;
                let public = f.is_public();
                let key = self.key_for(f.tier, f.agent_allowed, public);
                let w = crypto::wrap_dek(dek, pk.get(key)?, name, f.tier, f.agent_allowed, public)?;
                let (nonce, ct) = crypto::seal(dek, name, &value)?;
                let backup = match (&f.backup, &self.cfg.backup_recipient) {
                    (Some(b), _) => Some(b.clone()), // same DEK: the existing backup copy still opens it
                    (None, Some(r)) => Some(crypto::backup_wrap(dek, r)?),
                    (None, None) => None,
                };
                built.push(SecretFile {
                    v: crypto::CURRENT_V, name: name.clone(), tier: f.tier, agent_allowed: f.agent_allowed, public,
                    eph: w.eph, wrap_nonce: w.wrap_nonce, wrapped_dek: w.wrapped_dek, nonce, ct, backup,
                    created: f.created, updated: store::now(), key: Some(key),
                });
            }
            // A file replaced during the Touch ID prompt would otherwise be lost: its newer
            // value would be deleted and the old snapshot written under the new name.
            for (f, _) in &plan {
                if serde_json::to_value(store::load_secret(&self.paths, &f.name)?)? != serde_json::to_value(f)? {
                    bail!("{} changed during approval; retry", f.name);
                }
            }
            // Create-new only: a rename never replaces another secret. Undo on failure.
            let mut written: Vec<String> = Vec::new();
            for nf in &built {
                match store::save_secret_new(&self.paths, nf) {
                    Ok(true) => written.push(nf.name.clone()),
                    other => {
                        for n in &written { let _ = store::remove_secret(&self.paths, n); }
                        other?;
                        bail!("{} already exists", nf.name);
                    }
                }
            }
            for n in &old {
                store::remove_secret(&self.paths, n)?;
            }
            self.end_leases_internal(&old, "renamed", &dispatch);
            Ok(old.iter().cloned().zip(new.iter().cloned()).collect())
        })
    }

    pub fn set_config(&mut self, key: &str, value: &str) -> Result<()> {
        if self.config_relaxes(key, value) {
            self.require_human(fence::Verb::ConfigRelax, fence::Layer::Cli)?;
        }
        daemon::request(&self.paths, &daemon::Req::ChangeConfig { key: key.into(), value: value.into() })?;
        self.cfg = store::load_config(&self.paths)?;
        Ok(())
    }

    /// Whether this config change relaxes protection (longer human self-lease window
    /// counts; shortening or 0 tightens).
    fn config_relaxes(&self, key: &str, value: &str) -> bool {
        let longer_lease = key == "human-lease-hours" && value.parse::<f64>().is_ok_and(|h| h > self.cfg.human_lease_hours);
        let full_argv_on = key == "audit-full-argv" && parse_bool(value).unwrap_or(true) && !self.cfg.audit_full_argv;
        // Allowing SSH callers relaxes; an unparseable value is treated as relaxing too.
        let ssh_on = key == "allow-ssh-human" && parse_on_off(value).is_none_or(|on| on && !self.cfg.allow_ssh_human);
        matches!((key, value), ("default-tier", "off" | "open") | ("backup-recipient", "none"))
            || full_argv_on
            || match key {
                "agent-detection" => agent::settings::DetectionSettings::parse(value).map_or(true, |s| s.relaxes(&self.cfg)),
                "agent-process-names" => agent::settings::removes(&self.cfg.agent_process_names, &csv(value), true),
                "agent-env-markers" => agent::settings::removes(&self.cfg.agent_env_markers, &csv(value), false),
                // Letting a code-loading variable reach agent runs is a relaxation; shrinking the list is not.
                "allow-env" => csv(value).iter().any(|n| !self.cfg.allow_env.contains(n)),
                _ => false,
            }
            || longer_lease
            || ssh_on
    }

    pub(crate) fn set_config_internal(&mut self, key: &str, value: &str) -> Result<()> {
        let paths = self.paths.clone();
        let caller = self.caller.clone();
        audit::run(&paths, "config-operation", &[], &caller, json!({}), || {
            let names: Vec<String> = vec![];
            let (k, v) = (key.to_string(), value.to_string());
            self.cfg = store::load_config(&self.paths)?;
            let approved = serde_json::to_value(&self.cfg)?;
            let field = key.replace('-', "_");
            let relaxing = self.config_relaxes(key, value);
            if relaxing {
                self.require_human(fence::Verb::ConfigRelax, fence::Layer::Daemon)?;
            }
            let mut cfg = self.cfg.clone();
            match key {
                "default-profile" => {
                    cfg.default_profile = if value.is_empty() || value == "none" {
                        None
                    } else {
                        let name = aws::entry_name(value)?;
                        anyhow::ensure!(store::list_secrets(&self.paths)?.iter().any(|m| m.name == name),
                            "no AWS profile {value:?} (see `karambit aws ls`)");
                        Some(value.into())
                    };
                }
                "default-tier" => cfg.default_tier = Tier::parse(value)?,
                "clip-seconds" => cfg.clip_seconds = value.parse::<u32>().context("seconds")?.clamp(5, 600),
                "backup-recipient" => {
                    // Also for `none`: clearing the recipient would strand the half-rotated copies.
                    anyhow::ensure!(cfg.backup_rotation.is_none(), "a backup rotation is unfinished; run `karambit backup rotate` to finish it first");
                    cfg.backup_recipient = if value == "none" {
                        None
                    } else {
                        value.parse::<age::x25519::Recipient>().map_err(|e| anyhow::anyhow!("bad recipient: {e}"))?;
                        Some(value.into())
                    }
                }
                "agent-detection" => agent::settings::DetectionSettings::parse(value)?.apply(&mut cfg),
                "audit-full-argv" => cfg.audit_full_argv = parse_bool(value)?,
                "agent-process-names" => cfg.agent_process_names = csv(value),
                "agent-env-markers" => cfg.agent_env_markers = csv(value),
                "allow-env" => {
                    let mut names = csv(value);
                    names.sort();
                    names.dedup();
                    anyhow::ensure!(names.len() <= 64, "at most 64 allow-env names");
                    for name in &names { valid_var(name)?; }
                    cfg.allow_env = names;
                }
                "allow-ssh-human" => cfg.allow_ssh_human = parse_on_off(value).context("allow-ssh-human takes on or off")?,
                "human-lease-hours" => {
                    let h: f64 = value.parse().context("hours")?;
                    if !(0.0..=3.0).contains(&h) {
                        bail!("human-lease-hours must be 0..{} (0 = Touch ID every time)", 3.0);
                    }
                    cfg.human_lease_hours = h;
                }
                _ => bail!("unknown key {key}"),
            }
            let r = (|| {
                if relaxing {
                    platform::helper::auth(&Prompt::ChangeConfig { key: key.into() })?;
                }
                let lock = store::lock_config(&self.paths)?;
                let mut current = serde_json::to_value(lock.load()?)?;
                let fields = if key == "agent-detection" {
                    vec!["agent_process_names", "agent_env_markers", "removed_defaults"]
                } else { vec![field.as_str()] };
                let updated = serde_json::to_value(&cfg)?;
                for field in fields {
                    anyhow::ensure!(current.get(field) == approved.get(field), "config changed during approval");
                    // A field skipped on serialize (default value) is absent, not null.
                    match updated.get(field) {
                        Some(value) => current[field] = value.clone(),
                        None => { current.as_object_mut().context("config is not an object")?.remove(field); }
                    }
                }
                cfg = serde_json::from_value(current)?;
                lock.save(&cfg)
            })();
            self.audit("config", &names, json!({"key": k, "value": if k == "backup-recipient" { json!("…") } else { json!(v) }}), &r);
            r?;
            self.cfg = cfg;
            Ok(())
        })
    }

    /// Recovery after SE keys are lost (new Mac, fingerprints changed): run `init`
    /// on fresh keys, then rewrap every DEK from its offline backup copy.
    pub fn recover(&self, identity_text: &str) -> Result<(usize, Vec<String>)> {
        let response = daemon::request(&self.paths, &daemon::Req::Recover { identity_text: Zeroizing::new(identity_text.into()) })?;
        Ok(serde_json::from_value(response)?)
    }

    pub(crate) fn recover_internal(&self, identity_text: &str) -> Result<(usize, Vec<String>)> {
        audit::run(&self.paths, "recover-operation", &[], &self.caller, json!({}), || {
            self.require_init()?;
            let id = self.verify_paper(identity_text)?;
            plan_recovery(&store::list_secrets(&self.paths)?, &id, &[])?;
            self.recovery_auth()?;
            self.rewrap_from_paper(&id, &[])
        })
    }

    /// Verify the paper key opens EVERY secret (or exactly the ones named in `accept_loss`)
    /// and get human approval before retiring keys or generating replacements.
    pub fn recover_from_paper(&self, identity_text: &str, accept_loss: &[String]) -> Result<(usize, Vec<String>)> {
        let response = daemon::request(&self.paths, &daemon::Req::RecoverFromPaper {
            identity_text: Zeroizing::new(identity_text.into()), accept_loss: accept_loss.to_vec(),
        })?;
        Ok(serde_json::from_value(response)?)
    }

    pub(crate) fn recover_from_paper_internal(&self, identity_text: &str, accept_loss: &[String]) -> Result<(usize, Vec<String>)> {
        audit::run(&self.paths, "recover-operation", &[], &self.caller, json!({}), || {
            let id = self.verify_paper(identity_text)?;
            // Refuse before auth, retirement or keygen: nothing below may strand a file.
            plan_recovery(&store::list_secrets(&self.paths)?, &id, accept_loss)?;
            self.recovery_auth()?;
            // An interrupted run already replaced the keys: keep them and only finish the rewrap.
            if !self.resuming_recovery() {
                if self.paths.initialized() { self.retire_keys_authorized()?; }
                let pk = platform::helper::keygen(&self.paths.keys())?;
                store::write_atomic(&self.paths.pubkeys(), &serde_json::to_vec_pretty(&pk.to_json())?)?;
                self.save_recovery_progress(&RecoveryProgress { pubkeys_sha256: pubkeys_digest(&self.paths)?, rewrapped: Default::default() })?;
            }
            self.rewrap_from_paper(&id, accept_loss)
        })
    }

    /// True when a previous recovery generated the current keys but did not finish rewrapping.
    fn resuming_recovery(&self) -> bool {
        self.paths.initialized() && self.load_recovery_progress().is_some()
    }

    /// Progress is only trusted while it names the key set it was written for.
    fn load_recovery_progress(&self) -> Option<RecoveryProgress> {
        let p: RecoveryProgress = serde_json::from_slice(&std::fs::read(self.paths.recovery_pending()).ok()?).ok()?;
        (pubkeys_digest(&self.paths).ok()? == p.pubkeys_sha256).then_some(p)
    }

    fn save_recovery_progress(&self, p: &RecoveryProgress) -> Result<()> {
        store::write_atomic(&self.paths.recovery_pending(), &serde_json::to_vec(p)?)
    }

    fn verify_paper(&self, text: &str) -> Result<age::x25519::Identity> {
        let id = crypto::parse_identity(text)?;
        let proven = store::list_secrets(&self.paths)?.iter().any(|f| paper_opens(f, &id).is_ok());
        if !proven { bail!("paper key does not decrypt any existing backup; nothing retired"); }
        Ok(id)
    }

    /// Dry run of recovery for `backup verify`: trial-decrypt every file's backup blob.
    pub fn verify_backup(&self, id: &age::x25519::Identity) -> Result<BackupCheck> {
        let files = store::list_secrets(&self.paths)?;
        let unreadable = unrecoverable(&files, id);
        Ok(BackupCheck {
            total: files.len(),
            opened: files.len() - unreadable.len(),
            unreadable,
            rotation: store::load_config(&self.paths)?.backup_rotation,
        })
    }

    // Called only after verify_paper; unavailable biometrics is not equivalent to cancellation.
    fn recovery_auth(&self) -> Result<()> {
        let bootstrap_tofu = !self.paths.keys().join("helper.sha256").exists();
        let paper_only = match platform::helper::auth(&Prompt::Recover {}) {
            Ok(()) => false,
            Err(e) if e.downcast_ref::<platform::helper::BiometricsUnavailable>().is_some() => true,
            Err(e) => return Err(e),
        };
        audit::run(&self.paths, "recovery-proof", &[], &self.caller,
            json!({"verified_paper": true, "paper_only_biometrics_unavailable": paper_only,
                "bootstrap_tofu": bootstrap_tofu}), || Ok(()))
    }

    fn rewrap_from_paper(&self, id: &age::x25519::Identity, accept_loss: &[String]) -> Result<(usize, Vec<String>)> {
        let snapshot = MaintenanceSnapshot::load(&self.paths)?;
        let files = &snapshot.files;
        // Files may have changed since the first check; decide again before the first write.
        let lost = plan_recovery(files, id, accept_loss)?;
        let names: Vec<String> = files.iter().filter(|f| !lost.contains(&f.name)).map(|f| f.name.clone()).collect();
        let mut progress = self.load_recovery_progress();
        self.audited("recover", &names, json!({"accepted_loss": lost}), || {
            let pk = self.pubkeys_local()?;
            let mut ok = 0;
            let mut missing = Vec::new();
            for f in files {
                if lost.contains(&f.name) { missing.push(f.name.clone()); continue; }
                // Rewrapped by an interrupted run onto the current keys: nothing left to do.
                if progress.as_ref().is_some_and(|p| p.rewrapped.contains(&f.name)) { ok += 1; continue; }
                #[cfg(test)]
                REWRAP_FILE.with(|h| { if let Some(h) = h.borrow_mut().as_mut() { h(&f.name) } else { Ok(()) } })?;
                let b = f.backup.as_ref().context("backup vanished")?;
                let dek = crypto::backup_unwrap(b, id)?;
                crypto::open(&dek, f)?;
                let key = self.key_for(f.tier, f.agent_allowed, f.is_public());
                let w = crypto::wrap_dek(&dek, pk.get(key)?, &f.name, f.tier, f.agent_allowed, f.is_public())?;
                let mut nf = f.clone();
                nf.v = crypto::CURRENT_V;
                nf.public = f.is_public();
                nf.key = Some(key);
                nf.eph = w.eph;
                nf.wrap_nonce = w.wrap_nonce;
                nf.wrapped_dek = w.wrapped_dek;
                nf.updated = store::now();
                let lock = store::lock_config(&self.paths)?;
                snapshot.check_file(&self.paths, &lock.load()?, f)?;
                store::save_secret(&self.paths, &nf)?;
                // Recorded after the write: a crash in between just rewraps this file again.
                if let Some(p) = progress.as_mut() {
                    p.rewrapped.insert(f.name.clone());
                    self.save_recovery_progress(p)?;
                }
                ok += 1;
            }
            match std::fs::remove_file(self.paths.recovery_pending()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
            Ok((ok, missing))
        })
    }

    /// Standalone retirement requires fresh biometric approval.
    pub fn retire_keys(&self) -> Result<std::path::PathBuf> {
        let response = daemon::request(&self.paths, &daemon::Req::RetireKeys)?;
        Ok(serde_json::from_value(response)?)
    }

    pub(crate) fn retire_keys_internal(&self) -> Result<std::path::PathBuf> {
        audit::run(&self.paths, "retire-keys-operation", &[], &self.caller, json!({}), || {
            platform::helper::auth(&Prompt::RetireKeys {})?;
            self.retire_keys_authorized()
        })
    }

    /// Standalone retirement with verified paper proof if biometrics is unavailable.
    pub fn retire_keys_with_paper(&self, identity_text: &str) -> Result<std::path::PathBuf> {
        let response = daemon::request(&self.paths, &daemon::Req::RetireKeysWithPaper { identity_text: Zeroizing::new(identity_text.into()) })?;
        Ok(serde_json::from_value(response)?)
    }

    pub(crate) fn retire_keys_with_paper_internal(&self, identity_text: &str) -> Result<std::path::PathBuf> {
        audit::run(&self.paths, "retire-keys-operation", &[], &self.caller, json!({}), || {
            self.verify_paper(identity_text)?;
            self.recovery_auth()?;
            self.retire_keys_authorized()
        })
    }

    fn retire_keys_authorized(&self) -> Result<std::path::PathBuf> {
        let mut pins = Vec::new();
        for name in ["helper.sha256", "daemon.sha256"] {
            match std::fs::read(self.paths.keys().join(name)) {
                Ok(pin) => pins.push((name, pin)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        // Keep a durable fail-closed barrier outside the directory being renamed.
        let marker = self.paths.root.join("keys.retirement");
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&marker)?;
        file.sync_all()?;
        std::fs::File::open(&self.paths.root)?.sync_all()?;
        let dst = self.paths.root.join(format!("keys.retired-{}", store::now()));
        std::fs::rename(self.paths.keys(), &dst)?;
        store::ensure_dir(&self.paths.keys())?;
        #[cfg(test)]
        RETIRE_PIN_WRITE.with(|h| { if let Some(h) = h.borrow_mut().take() { h() } else { Ok(()) } })?;
        for (name, pin) in pins { store::write_atomic(&self.paths.keys().join(name), &pin)?; }
        std::fs::File::open(self.paths.keys())?.sync_all()?;
        std::fs::File::open(&self.paths.root)?.sync_all()?;
        std::fs::remove_file(marker)?;
        Ok(dst)
    }

    /// Replace the offline backup recipient and re-encrypt every secret's backup DEK copy.
    /// Needs the SE keys (one Touch ID for all bio secrets). Config records the rotation
    /// (`backup_rotation`) before the first file is written and names the new recipient only
    /// after the last one, so an interrupted run is visible and re-running it finishes it.
    pub fn rotate_backup(&mut self, recipient: &str) -> Result<usize> {
        let response = daemon::request(&self.paths, &daemon::Req::RotateBackup { recipient: recipient.into() });
        // Even a failed run may have left the marker in config.
        if let Ok(cfg) = store::load_config(&self.paths) { self.cfg = cfg; }
        Ok(serde_json::from_value(response?)?)
    }

    pub(crate) fn rotate_backup_internal(&mut self, recipient: &str) -> Result<usize> {
        let paths = self.paths.clone();
        let caller = self.caller.clone();
        let snapshot = MaintenanceSnapshot::load(&self.paths)?;
        let files = &snapshot.files;
        let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
        audit::run(&paths, "backup-rotate-operation", &names, &caller, json!({}), || {
            self.require_init()?;
            recipient.parse::<age::x25519::Recipient>().map_err(|e| anyhow::anyhow!("bad recipient: {e}"))?;
            let keys = files.iter().map(SecretFile::key_id).collect::<Result<Vec<_>>>()?;
            if !keys.contains(&KeyId::Bio) {
                platform::helper::auth(&Prompt::RotateBackup { names: Self::prompt_names(&names)?, caller: self.caller.label() })?;
            }
            let n = (|| {
                let deks = self.unwrap_deks_local(files, &Prompt::RewrapBackup { names: Self::prompt_names(&names)?, caller: self.caller.label() })?;
                let mut staged = Vec::with_capacity(files.len());
                for (f, dek) in files.iter().zip(deks.iter()) {
                    let mut nf = f.clone();
                    nf.backup = Some(crypto::backup_wrap(dek, recipient)?);
                    nf.updated = store::now();
                    staged.push(nf);
                }
                let lock = store::lock_config(&self.paths)?;
                let mut cfg = lock.load()?;
                anyhow::ensure!(cfg.backup_recipient == snapshot.config.backup_recipient && cfg.backup_rotation == snapshot.config.backup_rotation, "backup recipient changed during approval");
                for f in files { snapshot.check_file(&self.paths, &cfg, f)?; }
                anyhow::ensure!(cfg.sources == snapshot.config.sources, "maintenance sources changed");
                anyhow::ensure!(MaintenanceSnapshot::source_credential_paths(&self.paths)? == snapshot.source_credentials, "maintenance source credential set changed");
                // Mark the rotation before any file moves to the new recipient, so a crash
                // cannot leave a mix of old and new copies that config still calls "old".
                let from = cfg.backup_rotation.as_ref().map_or_else(|| cfg.backup_recipient.clone(), |p| p.from.clone());
                cfg.backup_rotation = Some(store::BackupRotation { from, to: recipient.to_string() });
                lock.save(&cfg)?;
                for nf in &staged {
                    #[cfg(test)]
                    ROTATE_FILE.with(|h| { if let Some(h) = h.borrow_mut().as_mut() { h(&nf.name) } else { Ok(()) } })?;
                    store::save_secret(&self.paths, nf)?;
                }
                cfg.backup_rotation = None;
                cfg.backup_recipient = Some(recipient.to_string());
                lock.save(&cfg)?;
                self.cfg = cfg;
                Ok::<_, anyhow::Error>(staged.len())
            })()?;
            Ok(n)
        })
    }

    // ---------- AWS profiles ----------

    /// Parse pasted credentials, optionally verify them against STS, and store them
    /// as `aws/<profile>`. Same Touch ID / agent policy as any other secret.
    /// Returns (metadata, "account · arn" if verified).
    pub fn add_aws(&self, profile: &str, pasted: &str, tier: Option<Tier>, agent_allowed: bool, overwrite: bool, verify: bool) -> Result<(SecretMeta, Option<String>)> {
        self.add_aws_session_mint(profile, pasted, tier, agent_allowed, overwrite, verify, false)
    }

    /// `add_aws` with the opt-in `session_mint` flag: runs get a one-hour STS session
    /// from the daemon instead of the key itself (see `aws::AwsCreds::session_mint`).
    #[allow(clippy::too_many_arguments)]
    pub fn add_aws_session_mint(&self, profile: &str, pasted: &str, tier: Option<Tier>, agent_allowed: bool, overwrite: bool, verify: bool, session_mint: bool) -> Result<(SecretMeta, Option<String>)> {
        self.require_human(fence::Verb::Add, fence::Layer::Cli)?;
        let name = aws::entry_name(profile)?;
        self.audited("aws-add", std::slice::from_ref(&name), json!({"verify": verify, "session_mint": session_mint}), || {
            let mut creds = aws::parse(pasted)?;
            if session_mint {
                aws::require_mintable(&creds)?;
            }
            creds.session_mint = session_mint;
            let who = if verify { creds.verify()? } else { None };
            let m = self.add(&name, &creds.to_json()?, tier, agent_allowed, false, overwrite)?;
            Ok((m, who))
        })
    }

    /// Turn `session_mint` on or off for a saved static profile. Both directions are
    /// human-only and rewrite the entry through the overwrite path, so they cost Touch ID
    /// (decrypt, then overwrite). Turning it off relaxes: the child then gets the key.
    pub fn aws_set_session_mint(&self, profile: &str, on: bool) -> Result<bool> {
        self.require_human(fence::Verb::Add, fence::Layer::Cli)?;
        let name = aws::entry_name(profile)?;
        let file = store::load_secret(&self.paths, &name)?;
        let u = self.unlock("aws-describe", std::slice::from_ref(&name), None, false)?;
        if let sso::AwsEntry::Sso(_) = sso::parse_entry(&u[0].value)? {
            bail!("{profile} is an SSO profile: it holds no long-term key to exchange");
        }
        let mut creds = aws::AwsCreds::from_json(&u[0].value)?;
        if creds.session_mint == on {
            return Ok(false);
        }
        if on {
            aws::require_mintable(&creds)?;
        }
        creds.session_mint = on;
        self.audited("aws-session-mint", std::slice::from_ref(&name), json!({"on": on}), || {
            self.add(&name, &creds.to_json()?, Some(file.tier), file.agent_allowed, false, true)
        })?;
        Ok(true)
    }

    /// AWS profiles with non-secret details (key type, region, masked key id).
    /// Decrypts, so it needs Touch ID for bio-tier profiles.
    pub fn aws_describe(&self, profile: &str) -> Result<Value> {
        let name = aws::entry_name(profile)?;
        let u = self.unlock("aws-describe", std::slice::from_ref(&name), None, false)?;
        if let sso::AwsEntry::Sso(p) = sso::parse_entry(&u[0].value)? {
            return Ok(json!({
                "profile": profile,
                "sso": true,
                "portal": p.portal,
                "account": p.account_id,
                "role": p.role_name,
                "region": p.child_region(),
                "temporary": true,
            }));
        }
        let c = aws::AwsCreds::from_json(&u[0].value)?;
        let id = &c.access_key_id;
        Ok(json!({
            "profile": profile,
            "key": aws::mask_key_id(id),
            "temporary": c.temporary(),
            "region": c.region,
            "session_mint": c.session_mint,
        }))
    }

    // ---------- AWS SSO ----------

    /// Add (or change) a named access portal. Human only: a swapped portal URL would
    /// phish the human at the next login. Not secret; stored in config. Keeps the
    /// portal's sign-in limit (re-adding it must not quietly remove one).
    pub fn sso_portal_add(&mut self, name: &str, start_url: &str, region: &str) -> Result<()> {
        daemon::request(&self.paths, &daemon::Req::SsoPortalAdd { name: name.into(), start_url: start_url.into(), region: region.into() })?;
        self.cfg = store::load_config(&self.paths)?;
        Ok(())
    }

    pub(crate) fn sso_portal_add_internal(&mut self, name: &str, start_url: &str, region: &str) -> Result<()> {
        let paths = self.paths.clone();
        let caller = self.caller.clone();
        audit::run(&paths, "sso-portal-operation", &[], &caller, json!({"portal": name, "start_url": start_url, "region": region}), || {
            sso::validate_portal_name(name)?;
            sso::validate_start_url(start_url)?;
            sso::validate_region(region)?;
            let old = {
                let lock = store::lock_config(&self.paths)?;
                lock.load()?.sso_portals.get(name).cloned()
            };
            let changed = old.as_ref().is_none_or(|p| p.start_url != start_url || p.region != region);
            if changed {
                let prompt = if old.is_some() {
                    Prompt::RepointSsoPortal { name: name.into(), url: start_url.into(), region: region.into() }
                } else {
                    Prompt::AddSsoPortal { name: name.into(), url: start_url.into(), region: region.into() }
                };
                platform::helper::auth(&prompt)?;
            }
            let lock = store::lock_config(&self.paths)?;
            let mut cfg = lock.load()?;
            // Limits may tighten during auth. Preserve them, but never apply an
            // approval/no-op classification to a replaced or removed destination.
            let destination = |p: Option<&store::SsoPortal>| p.map(|p| (p.start_url.clone(), p.region.clone()));
            if destination(cfg.sso_portals.get(name)) != destination(old.as_ref()) {
                bail!("config changed, retry: portal destination changed");
            }
            if changed {
                let limit_minutes = cfg.sso_portals.get(name).and_then(|p| p.limit_minutes);
                // Account names belong to an organization: keep them only for the same URL.
                let accounts = cfg.sso_portals.get(name).filter(|p| p.start_url == start_url).map(|p| p.accounts.clone()).unwrap_or_default();
                cfg.sso_portals.insert(name.to_string(), store::SsoPortal {
                    start_url: start_url.to_string(), region: region.to_string(), limit_minutes, accounts });
                lock.save(&cfg)?;
            }
            drop(lock);
            self.audit("sso-portal", &[], json!({"portal": name, "start_url": start_url, "region": region}), &Ok(()));
            self.cfg = cfg;
            Ok(())
        })
    }

    /// Remove a portal from config and sign it out. Its SSO profiles stay in the vault
    /// but stop working until a portal with that name is added again.
    pub fn sso_portal_remove(&mut self, name: &str) -> Result<()> {
        self.require_human(fence::Verb::SsoPortalRemove, fence::Layer::Cli)?;
        sso::validate_portal_name(name)?;
        let _ = self.sso_logout(Some(name));
        let cfg = audit::run(&self.paths, "sso-portal-rm", &[], &self.caller, json!({"portal": name}), || {
            let lock = store::lock_config(&self.paths)?;
            let mut cfg = lock.load()?;
            if cfg.sso_portals.remove(name).is_none() {
                bail!("no SSO portal named {name:?} (see `karambit aws sso portals`)");
            }
            lock.save(&cfg)?;
            Ok(cfg)
        })?;
        self.cfg = cfg;
        Ok(())
    }

    /// Resolve which portal to use: the named one, or the only one configured.
    pub fn sso_portal(&self, name: Option<&str>) -> Result<(String, store::SsoPortal)> {
        let names: Vec<&String> = self.cfg.sso_portals.keys().collect();
        let pick = match name {
            Some(n) => n.to_string(),
            None if names.len() == 1 => names[0].clone(),
            None if names.is_empty() => bail!("no SSO portal yet: karambit aws sso portal add NAME --start-url URL --region REGION"),
            None => bail!("several SSO portals ({}): say which one", names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
        };
        let p = self.cfg.sso_portals.get(&pick).with_context(|| format!("no SSO portal named {pick:?} (see `karambit aws sso portals`)"))?;
        Ok((pick, p.clone()))
    }

    /// Set how long a sign-in to this portal may last before Karambit signs it out
    /// (None = as long as AWS allows). Applies to the current sign-in too, counted from
    /// when it started, so a shorter limit can sign it out right away. It can only end
    /// sign-ins sooner than IAM Identity Center would. Human only; lengthening or
    /// removing it costs one Touch ID in the daemon, including when no sign-in or
    /// daemon was running. Returns whether the current sign-in ended.
    pub fn sso_portal_limit(&mut self, name: &str, minutes: Option<u32>) -> Result<bool> {
        let response = daemon::request(&self.paths, &daemon::Req::SsoPortalLimit { portal: name.into(), minutes })?;
        self.cfg = store::load_config(&self.paths)?;
        Ok(serde_json::from_value(response)?)
    }

    pub(crate) fn sso_portal_limit_internal(&mut self, name: &str, minutes: Option<u32>, dispatch: impl Fn(daemon::Req) -> Result<Value>, deliver: impl FnOnce(bool) -> Result<Value>) -> Result<Value> {
        if let Some(m) = minutes {
            sso::validate_limit_minutes(m)?;
        }
        // Never hold the global config lock across RPC or human authentication.
        let (old_limit, longer, shorter) = {
            let lock = store::lock_config(&self.paths)?;
            let old_limit = lock.load()?.sso_portals.get(name).context("no such SSO portal")?.limit_minutes;
            let longer = match (old_limit, minutes) {
                (None, _) => false,
                (Some(_), None) => true,
                (Some(o), Some(n)) => n > o,
            };
            let shorter = match (old_limit, minutes) {
                (None, Some(_)) => true,
                (Some(old), Some(new)) => new < old,
                _ => false,
            };
            (old_limit, longer, shorter)
        };
        let name = name.to_string();
        let change = || {
            let live = dispatch(daemon::Req::SsoLimit { portal: name.clone(), minutes })?;
            if longer && live["asked"] != json!(true) {
                platform::helper::auth(&Prompt::SsoLimit { portal: name.clone(), duration: sso::limit_words(minutes) })?;
            }
            #[cfg(test)]
            BEFORE_LIMIT_COMMIT.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() { hook(); }
            });
            let lock = store::lock_config(&self.paths)?;
            let mut cfg = lock.load()?;
            let portal = cfg.sso_portals.get_mut(&name).context("config changed, retry: portal vanished")?;
            if portal.limit_minutes != old_limit {
                // One bounded re-classification: only containment may survive a
                // changed snapshot, regardless of earlier intent/authentication.
                let still_shorter = match (portal.limit_minutes, minutes) {
                    (None, Some(_)) => true,
                    (Some(old), Some(new)) => new < old,
                    _ => false,
                };
                if !still_shorter { bail!("config changed, retry: portal sign-in limit changed"); }
            }
            portal.limit_minutes = minutes;
            lock.save(&cfg)?;
            Ok(live["ended"] == json!(true))
        };
        // Classify once for the same barrier that encloses persistence AND delivery.
        // A separate outer classification could race a concurrent shortening.
        let operation = || deliver(change()?);
        if !shorter {
            audit::run(&self.paths, "sso-limit", &[], &self.caller, json!({"portal": name, "limit_minutes": minutes}), operation)
        } else {
            audit::containment(&self.paths, "sso-limit-shortening", &self.caller, operation)
        }
    }

    /// Save an SSO-backed AWS profile (account + role on a named portal). Same access
    /// levels as any secret. If that portal is signed in, it's activated now.
    pub fn add_aws_sso(&self, profile: &str, p: &sso::SsoProfile, tier: Option<Tier>, agent_allowed: bool, overwrite: bool) -> Result<SecretMeta> {
        self.require_human(fence::Verb::Add, fence::Layer::Cli)?;
        let name = aws::entry_name(profile)?;
        p.validate()?;
        let m = self.add(&name, &sso::entry_json(p)?, tier, agent_allowed, false, overwrite)?;
        if !self.caller.is_agent() {
            let _ = self.sso_sync(std::slice::from_ref(&name));
        }
        Ok(m)
    }

    pub fn sso_discover(&self, portal: &str) -> Result<Vec<sso::DiscoveredRole>> {
        self.require_human(fence::Verb::SsoDiscover, fence::Layer::Daemon)?;
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::SsoDiscover { portal: portal.into() })?)?)
    }

    pub fn sso_import_preview(&self, portal: &str, roles: Vec<sso::DiscoveredRole>) -> Result<Vec<sso::ImportPreview>> {
        self.require_human(fence::Verb::SsoDiscover, fence::Layer::Daemon)?;
        Ok(serde_json::from_value(daemon::request(&self.paths, &daemon::Req::SsoImportPreview { portal: portal.into(), roles })?)?)
    }

    pub fn import_aws_sso(&self, portal: &str, items: Vec<sso::ImportItem>, tier: Tier, agent_allowed: bool, region: Option<String>) -> Result<Value> {
        self.require_human(fence::Verb::SsoImport, fence::Layer::Cli)?;
        daemon::request(&self.paths, &daemon::Req::SsoImport { portal: portal.into(), items, tier, agent_allowed, region })
    }

    fn prepare_sso_import(&self, profiles: &[(String, sso::SsoProfile)], tier: Tier, agent_allowed: bool) -> Result<Vec<(SecretFile, sso::SsoReg)>> {
        self.require_init()?;
        let pk = self.pubkeys_local()?;
        profiles.iter().map(|(name, profile)| {
            let dek = crypto::new_dek();
            let file = self.build_file(name, tier, agent_allowed, false, &dek, &sso::entry_json(profile)?, &pk, None)?;
            let reg = sso::SsoReg { name: name.clone(), profile: profile.clone(), tier, agent_allowed, dek_sha256: (tier == Tier::Bio).then(|| sso::sha256_hex(dek.as_ref())) };
            Ok((file, reg))
        }).collect()
    }

    /// SSO profiles in the vault, as a human registers them with the daemon. Decrypts
    /// them: open-tier ones silently, Touch ID ones with one prompt (their DEK hash is
    /// recorded so agents later need a lease, or the human a Touch ID, to use them).
    pub(crate) fn sso_regs_internal(&self, names: Option<&[String]>, portal: Option<&str>) -> Result<Vec<sso::SsoReg>> {
        // Decrypting sink: stays behind its own lookup beside the dispatch one.
        self.require_human(fence::Verb::SsoRegister, fence::Layer::Daemon)?;
        self.sso_regs_with(names, portal, |files, prompt| self.unwrap_deks_local(files, prompt))
    }

    fn sso_regs_with(&self, names: Option<&[String]>, portal: Option<&str>, unwrap: impl Fn(&[SecretFile], &Prompt) -> Result<Vec<Dek>>) -> Result<Vec<sso::SsoReg>> {
        let paths = self.paths.clone();
        let caller = self.caller.clone();
        audit::run(&paths, "sso-register-decrypt", &[], &caller, json!({}), || {
            let all = store::list_secrets(&self.paths)?;
            let files: Vec<SecretFile> = all
                .into_iter()
                .filter(|f| aws::is_aws_entry(&f.name) && names.is_none_or(|n| n.contains(&f.name)))
                .collect();
            if files.is_empty() {
                return Ok(vec![]);
            }
            let deks = unwrap(&files, &Prompt::SsoDecrypt {})?;
            let mut out = vec![];
            for (f, d) in files.iter().zip(deks.iter()) {
                let Ok(v) = crypto::open(d, f) else { continue };
                let Ok(sso::AwsEntry::Sso(p)) = sso::parse_entry(&v) else { continue };
                if portal.is_some_and(|n| n != p.portal) {
                    continue;
                }
                out.push(sso::SsoReg {
                    name: f.name.clone(),
                    profile: p,
                    tier: f.tier,
                    agent_allowed: f.agent_allowed,
                    dek_sha256: (f.tier == Tier::Bio).then(|| sso::sha256_hex(d.as_ref())),
                });
            }
            Ok(out)
        })
    }

    /// Re-register these SSO profiles with a running, signed-in daemon (after add or
    /// policy change). Human callers only; a no-op otherwise. The daemon keeps only the
    /// ones whose portal is signed in.
    fn sso_sync(&self, names: &[String]) -> Result<()> {
        if self.caller.is_agent() || !daemon::running(&self.paths.root) {
            return Ok(());
        }
        daemon::request(&self.paths, &daemon::Req::RefreshSsoRegistrations { names: names.to_vec() })?;
        Ok(())
    }

    fn sso_sync_internal(&self, names: &[String], dispatch: impl Fn(daemon::Req) -> Result<Value>) -> Result<()> {
        if self.caller.is_agent() { return Ok(()); }
        let st = dispatch(daemon::Req::SsoStatus)?;
        if st["logged_in"] != json!(true) { return Ok(()); }
        let regs = self.sso_regs_internal(Some(names), None)?;
        if !regs.is_empty() { dispatch(daemon::Req::SsoRegister { profiles: regs })?; }
        Ok(())
    }

    /// Device-code sign-in to one named portal. Human only, one Touch ID (shown by the
    /// daemon). The token goes to daemon RAM with that portal's SSO profiles; other
    /// portals stay signed in. Nothing on disk. Returns the number of profiles activated.
    /// `ui` can cancel until browser approval (see [`sso::SignInUi::commit`]).
    pub fn sso_login(&self, portal: &str, ui: &sso::SignInUi) -> Result<usize> {
        self.require_init()?;
        self.require_human(fence::Verb::SsoLogin, fence::Layer::Cli)?;
        let (portal, cfg) = self.sso_portal(Some(portal))?;
        self.audited("sso-login", &[], json!({"portal": portal, "start_url": cfg.start_url, "region": cfg.region}), || {
            let session = sso::login(&portal, &cfg.start_url, &cfg.region, ui)?;
            let response = daemon::request(&self.paths, &daemon::Req::CompleteSsoLogin { session })?;
            Ok(serde_json::from_value(response["profiles"].clone())?)
        })
    }

    /// Sign one portal (or all) out of the daemon. Never prompts (it only tightens).
    pub fn sso_logout(&self, portal: Option<&str>) -> Result<()> {
        self.require_human(fence::Verb::SsoLogout, fence::Layer::Cli)?;
        if !daemon::running(&self.paths.root) {
            return Ok(());
        }
        let portal = portal.map(String::from);
        self.audited("sso-logout", &[], json!({"portal": portal}), || {
            daemon::request(&self.paths, &daemon::Req::SsoLogout { portal: portal.clone() }).map(|_| ())
        })
    }

    /// Configured portals + which are signed in (from the daemon), each one's sign-in
    /// limit and, for one that ended by itself, when and why. No secrets.
    pub fn sso_status(&self) -> Result<Value> {
        let live = daemon::request_if_running(&self.paths, &daemon::Req::SsoStatus).unwrap_or_else(|| json!({"portals": []}));
        let empty = vec![];
        let sessions = live["portals"].as_array().unwrap_or(&empty);
        let portals: Vec<Value> = self
            .cfg
            .sso_portals
            .iter()
            .map(|(n, p)| {
                let s = sessions.iter().find(|s| s["portal"] == json!(n) && s["start_url"] == json!(p.start_url));
                let ended = live["ended"].get(n.as_str()).filter(|_| s.is_none()).cloned();
                json!({
                    "portal": n,
                    "start_url": p.start_url,
                    "region": p.region,
                    "limit_minutes": p.limit_minutes,
                    "accounts": p.accounts,
                    "logged_in": s.is_some(),
                    "access_expires_at": s.map(|s| s["access_expires_at"].clone()),
                    "can_refresh": s.is_some_and(|s| s["can_refresh"] == json!(true)),
                    "signed_in_at": s.map(|s| s["signed_in_at"].clone()),
                    "renew_until": s.map(|s| s["renew_until"].clone()),
                    "renew_error": s.map(|s| s["renew_error"].clone()),
                    "ended": ended,
                    "profiles": s.map(|s| s["profiles"].clone()).unwrap_or(json!([])),
                })
            })
            .collect();
        Ok(json!({
            "logged_in": portals.iter().any(|p| p["logged_in"] == json!(true)),
            "portals": portals,
            "profiles": live["profiles"].clone(),
            "registered": live.get("registered").cloned().unwrap_or(json!({})),
        }))
    }

    pub fn audit_log(&self, limit: usize) -> Result<Vec<Value>> {
        audit::read(&self.paths, limit)
    }

    /// Recent audit events that touched `name` (newest last), for per-secret activity.
    pub fn secret_activity(&self, name: &str, limit: usize) -> Result<Vec<Value>> {
        audit::read_matching(&self.paths, limit, |e| e["secrets"].as_array().is_some_and(|a| a.iter().any(|s| s.as_str() == Some(name))))
    }

    pub fn audit_verify(&self) -> Result<(usize, Option<usize>)> {
        audit::verify(&self.paths)
    }

    /// Like `audit_verify`, also saying whether older segments were removed.
    pub fn audit_verify_report(&self) -> Result<audit::Verified> {
        audit::verify_report(&self.paths)
    }
}

fn parse_bool(v: &str) -> Result<bool> {
    match v {
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" => Ok(false),
        _ => bail!("expected true or false"),
    }
}

fn parse_on_off(v: &str) -> Option<bool> {
    match v {
        "on" | "true" => Some(true),
        "off" | "false" => Some(false),
        _ => None,
    }
}

fn csv(v: &str) -> Vec<String> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

/// Classify a client reference without contacting a backend or reading credentials.
/// Only configured source prefixes select backend resolution; unknown prefixes
/// are refused. The reserved `aws:` prefix is never a source.
/// Env-file callers strip their optional `karambit:` wrapper before this call.
/// Clients pass backend references unchanged to daemon Resolve / bound-run delivery.
pub fn classify_reference(config: &Config, input: &str) -> backend::BResult<backend::Reference> {
    if let Some((name, _)) = input.split_once(':') {
        if name == "aws" {
            return Err(backend::BackendError::InvalidRef);
        }
        if config.sources.contains_key(name) {
            return backend::BackendRef::parse(input);
        }
        // C-29/C-30: a colon ref must name a configured source. `karambit:` is the env
        // wrapper (stripped once by parse_env_file); a doubled wrapper stays legacy and
        // fails store validation there.
        if name != "karambit" {
            return Err(backend::BackendError::NotFound);
        }
    }
    Ok(backend::Reference::Legacy(input.to_owned()))
}

#[cfg(test)]
mod reference_routing_tests {
    use super::*;

    fn config() -> Config {
        let mut config = Config::default();
        config.sources.insert("f".into(), backend::SourceConfig {
            name: "f".into(), kind: "fake".into(),
            endpoint: "https://fake.invalid:443/".into(), auth_method: "token".into(),
            credential_ref: "sources/f/cred".into(), credential_revision: "1".repeat(32),
            generation: "2".repeat(32), policy: json!({}),
        });
        config
    }

    #[test]
    fn classify_reference_configured_source_and_first_colon() {
        let config = config();
        assert_eq!(classify_reference(&config, "f:arn:aws:secret#value").unwrap(),
            backend::Reference::Backend(backend::BackendRef {
                source: "f".into(), native: "arn:aws:secret#value".into(),
            }));
        for input in ["f:", "f:ok/../a", "f:ok/%2e%2e/a", "f:ok/a b"] {
            assert_eq!(classify_reference(&config, input).unwrap_err(), backend::BackendError::InvalidRef);
        }
    }

    #[test]
    fn classify_reference_unknown_prefix_rejected_and_legacy_unchanged() {
        for input in ["unknown:ok/a", "unknown:arn:aws:secret"] {
            assert_eq!(classify_reference(&config(), input).unwrap_err(), backend::BackendError::NotFound);
        }
        for input in ["ns/name", "aws/staging"] {
            assert_eq!(classify_reference(&config(), input).unwrap(), backend::Reference::Legacy(input.into()));
        }
    }

    #[test]
    fn classify_reference_aws_is_reserved_even_if_configured() {
        let mut config = config();
        assert_eq!(classify_reference(&config, "aws:ok/a").unwrap_err(), backend::BackendError::InvalidRef);
        let source = config.sources["f"].clone();
        config.sources.insert("aws".into(), source);
        assert_eq!(classify_reference(&config, "aws:ok/a").unwrap_err(), backend::BackendError::InvalidRef);
    }

    #[test]
    fn classify_reference_env_wrapper_is_stripped_once_and_selector_retained() {
        let refs = parse_env_file("# comment\nX=karambit:f:ok/a#password\nY=karambit:karambit:f:ok/a").unwrap();
        assert_eq!(refs[0].1, "f:ok/a#password");
        assert!(matches!(classify_reference(&config(), &refs[0].1).unwrap(), backend::Reference::Backend(_)));
        assert_eq!(refs[1].1, "karambit:f:ok/a");
        assert_eq!(classify_reference(&config(), &refs[1].1).unwrap(), backend::Reference::Legacy(refs[1].1.clone()));
    }
}

/// Parse a `.karambit.env` ref file: `VAR=ns/name` or `VAR=karambit:ns/name`, `#` comments.
/// Refs only — the file is safe to commit.
pub fn parse_env_file(text: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (k, v) = line.split_once('=').with_context(|| format!("line {}: expected VAR=ref", i + 1))?;
        let v = v.trim().trim_matches('"');
        let v = v.strip_prefix("karambit:").unwrap_or(v);
        out.push((valid_var(k.trim())?, v.to_string()));
    }
    Ok(out)
}

pub fn valid_var(k: &str) -> Result<String> {
    let ok = !k.is_empty()
        && !k.as_bytes()[0].is_ascii_digit()
        && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !ok {
        bail!("invalid env var name {k:?}");
    }
    Ok(k.into())
}

/// Default env var for a secret: `stripe/prod-key` -> `STRIPE_PROD_KEY`.
pub fn default_var(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect()
}

pub fn group_by_tier(meta: &[SecretMeta]) -> HashMap<Tier, usize> {
    let mut m = HashMap::new();
    for s in meta {
        *m.entry(s.tier).or_insert(0) += 1;
    }
    m
}

/// "pid:1234@1790770000" / "pi:<uuid>" / "1234" -> (pid, start). Session ids from
/// env (pi:<uuid>) can't be pinned to a process tree, so they're refused here.
fn resolve_session_root(s: &str) -> Result<(i32, u64)> {
    let s = s.strip_prefix("pid:").unwrap_or(s);
    let (pid, start) = match s.split_once('@') {
        Some((p, t)) => (p.parse::<i32>().context("session pid")?, Some(t.parse::<u64>().context("session start")?)),
        None => (s.parse::<i32>().map_err(|_| anyhow::anyhow!("session leases need a process id (pid:<n>@<start> from `karambit audit`, or a pid)"))?, None),
    };
    let live = agent::proc_start(pid).ok_or_else(|| anyhow::anyhow!("process {pid} isn't running"))?;
    if let Some(t) = start
        && t != live
    {
        bail!("process {pid} was restarted since that session (different start time)");
    }
    Ok((pid, live))
}

#[cfg(test)]
type RetirementHook = Box<dyn FnOnce() -> Result<()>>;
#[cfg(test)]
type FileHook = Box<dyn FnMut(&str) -> Result<()>>;
#[cfg(test)]
thread_local! {
    static BEFORE_ACTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static RETIRE_PIN_WRITE: std::cell::RefCell<Option<RetirementHook>> = const { std::cell::RefCell::new(None) };
    static REWRAP_FILE: std::cell::RefCell<Option<FileHook>> = const { std::cell::RefCell::new(None) };
    static ROTATE_FILE: std::cell::RefCell<Option<FileHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod proof_tests {
    use super::*;
    use std::{cell::Cell, fs, rc::Rc};

    struct RecoveryDispatch;
    impl RecoveryDispatch {
        fn install() -> Self { daemon::install_unlock_test_dispatch(); Self }
    }
    impl Drop for RecoveryDispatch {
        fn drop(&mut self) { daemon::REQUEST_HOOK.with(|h| h.borrow_mut().take()); }
    }

    fn fixture(label: &str) -> Karambit {
        let paths = Paths { root: std::env::temp_dir().join(format!("karambit-proof-{label}-{}", std::process::id())) };
        let _ = fs::remove_dir_all(&paths.root);
        store::ensure_dir(&paths.keys()).unwrap();
        for key in ["bio.key", "open.key"] { fs::write(paths.keys().join(key), b"synthetic").unwrap(); }
        let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use base64::Engine;
        let pk = base64::engine::general_purpose::STANDARD.encode(sk.public_key().to_encoded_point(false).as_bytes());
        store::write_atomic(&paths.pubkeys(), &serde_json::to_vec(&json!({"bio": pk, "open": pk})).unwrap()).unwrap();
        let cfg = Config::default();
        store::save_config(&paths, &cfg).unwrap();
        Karambit { paths, cfg, caller: Caller::default(), run_cmd: None }
    }

    fn auth(accept: bool) -> Rc<Cell<usize>> {
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            count.set(count.get() + 1);
            if accept { Ok(()) } else { bail!("synthetic auth refused") }
        })));
        calls
    }

    #[test]
    fn allow_env_additions_need_a_human_and_touch_id_but_removals_do_not() {
        let mut v = fixture("allow-env");
        let calls = auth(true);
        // An agent can't add; nothing is prompted or saved.
        let mut agent = Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller: Caller { agent: Some("synthetic".into()), ..Default::default() }, run_cmd: None };
        let err = agent.set_config_internal("allow-env", "NODE_OPTIONS").unwrap_err();
        assert!(err.to_string().contains("human-only"), "{err:#}");
        assert_eq!(calls.get(), 0);
        assert!(store::load_config(&v.paths).unwrap().allow_env.is_empty());
        // A human adds with Touch ID (names deduplicated and sorted).
        v.set_config_internal("allow-env", "RUBYOPT, NODE_OPTIONS,RUBYOPT").unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(store::load_config(&v.paths).unwrap().allow_env, ["NODE_OPTIONS", "RUBYOPT"]);
        // Shrinking is a tightening: an agent may do it, with no prompt.
        agent.cfg = store::load_config(&v.paths).unwrap();
        agent.set_config_internal("allow-env", "RUBYOPT").unwrap();
        assert_eq!(calls.get(), 1);
        agent.set_config_internal("allow-env", "").unwrap();
        assert!(store::load_config(&v.paths).unwrap().allow_env.is_empty());
        // Empty list is omitted from the file so older builds read it unchanged.
        assert!(!fs::read_to_string(v.paths.root.join("config.json")).unwrap().contains("allow_env"));
        assert!(v.set_config_internal("allow-env", "bad name").is_err());
        let _ = fs::remove_dir_all(&v.paths.root);
    }

    fn secret(v: &Karambit, name: &str, tier: Tier, agents: bool) -> Dek {
        let dek = crypto::new_dek();
        let f = v.build_file(name, tier, agents, false, &dek, b"synthetic proof fixture", &v.pubkeys_local().unwrap(), None).unwrap();
        store::save_secret(&v.paths, &f).unwrap();
        dek
    }

    #[test]
    fn prompt_names_refuses_a_list_the_prompt_would_cut() {
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(Karambit::prompt_names(&names(&["a/x", "b/y"])).unwrap(), "a/x, b/y");
        assert_eq!(Karambit::prompt_names(&names(&["a", "b", "c", "d"])).unwrap(), "4 secrets");
        // Three long names exceed the 120-character field: refused, not shortened.
        let long = "p/".to_string() + &"n".repeat(58);
        let error = Karambit::prompt_names(&[long.clone(), long.clone(), long]).unwrap_err().to_string();
        assert!(error.contains("too many secrets for one prompt"), "{error}");
    }

    #[test]
    fn audit_full_argv_is_a_relaxing_human_only_setting() {
        let mut agent = fixture("full-argv-agent");
        agent.caller.agent = Some("synthetic".into());
        let prompts = auth(true);
        assert!(agent.set_config_internal("audit-full-argv", "true").is_err());
        assert!(!store::load_config(&agent.paths).unwrap().audit_full_argv);
        assert_eq!(prompts.get(), 0);
        let mut human = fixture("full-argv-human");
        let prompts = auth(true);
        human.set_config_internal("audit-full-argv", "true").unwrap();
        assert_eq!(prompts.get(), 1, "turning it on needs Touch ID");
        assert!(store::load_config(&human.paths).unwrap().audit_full_argv);
        // Turning it off tightens: no prompt, and the field leaves the file (older builds ignore it anyway).
        human.set_config_internal("audit-full-argv", "false").unwrap();
        assert_eq!(prompts.get(), 1);
        assert!(!store::load_config(&human.paths).unwrap().audit_full_argv);
        assert!(!String::from_utf8(fs::read(human.paths.config()).unwrap()).unwrap().contains("audit_full_argv"));
        assert!(human.set_config_internal("audit-full-argv", "maybe").is_err());
    }

    #[test]
    fn run_authorization_matches_legacy_unlock_table() {
        use RunAuthorization::*;
        use base64::Engine;
        // Exercise the actual legacy executor, with validated synthetic Use hits
        // and a software ECDH fixture. Existing legacy proof tests stay unchanged.
        for (agent, tier, allowed, public, hit, accept, expected) in [
            (true, Tier::Bio, false, false, true, true, Lease),
            (true, Tier::Open, false, true, false, true, OpenPublic),
            (true, Tier::Open, true, false, false, true, AgentAllowed),
            (false, Tier::Open, true, false, false, true, AgentAllowed),
            (false, Tier::Bio, false, false, true, true, HumanCached),
            (false, Tier::Bio, true, false, false, true, NeedsFreshAuth),
            (false, Tier::Bio, true, false, false, false, NeedsFreshAuth),
            (false, Tier::Open, false, false, false, true, NeedsFreshAuth),
            (false, Tier::Open, false, false, false, false, NeedsFreshAuth),
            (true, Tier::Bio, false, false, false, true, Deny),
        ] {
            let mut v = fixture("run-parity");
            if agent { v.caller.agent = Some("synthetic".into()); }
            let dek = crypto::new_dek();
            let file = v.build_file("test/ref", tier, allowed, public, &dek, b"synthetic", &v.pubkeys_local().unwrap(), None).unwrap();
            store::save_secret(&v.paths, &file).unwrap();
            assert_eq!(run_authorization(&v.caller, &file, agent && hit, !agent && hit), expected);
            let prompts = auth(accept);
            let ecdh_prompts = prompts.clone();
            platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |reqs| {
                if reqs.iter().any(|(key, _)| *key == KeyId::Bio) {
                    ecdh_prompts.set(ecdh_prompts.get() + 1);
                    if !accept { bail!("synthetic auth refused"); }
                }
                let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
                reqs.iter().map(|(_, eph)| {
                    let pk = p256::PublicKey::from_sec1_bytes(&base64::engine::general_purpose::STANDARD.decode(eph)?)?;
                    Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
                }).collect()
            })));
            let result = v.unlock_internal("run", &["test/ref".into()], None, false, |req| {
                assert!(matches!(req, daemon::Req::Use { .. }));
                Ok(if hit { json!({"deks":{"test/ref":base64::engine::general_purpose::STANDARD.encode(dek.as_ref())}}) }
                    else { json!({"deks":{}}) })
            });
            assert_eq!(result.is_ok(), expected != Deny && (expected != NeedsFreshAuth || accept), "{expected:?}");
            assert_eq!(prompts.get(), usize::from(expected == NeedsFreshAuth), "{expected:?}");
            platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
            platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
            fs::remove_dir_all(v.paths.root).unwrap();
        }
    }

    #[test]
    fn relaxed_add_requires_fresh_auth_and_intent_before_write() {
        let v = fixture("add");
        daemon::install_unlock_test_dispatch();
        let calls = auth(false);
        assert!(v.add("test/new", b"fixture", Some(Tier::Open), true, false, false).unwrap_err().to_string().contains("auth refused"));
        assert_eq!(calls.get(), 1);
        assert!(!v.paths.secret("test/new").unwrap().exists());
        let calls = auth(true);
        audit::fail_phase(Some("intent"));
        assert!(v.add("test/new", b"fixture", Some(Tier::Open), true, false, false).is_err());
        audit::fail_phase(None);
        assert_eq!(calls.get(), 0);
        v.add("test/new", b"fixture", Some(Tier::Open), true, false, false).unwrap();
        assert_eq!(calls.get(), 1);
        let calls = auth(true);
        v.add("test/new", b"replacement", Some(Tier::Open), true, false, true).unwrap();
        assert_eq!(calls.get(), 1, "overwrite reuses its existing gate");
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn legacy_open_access_refusal_and_intent_failure_disclose_nothing() {
        let v = fixture("legacy");
        daemon::install_unlock_test_dispatch();
        secret(&v, "test/legacy", Tier::Open, false);
        let names = ["test/legacy".into()];
        let calls = auth(false);
        assert!(v.unlock("run", &names, None, false).err().unwrap().to_string().contains("auth refused"));
        assert_eq!(calls.get(), 1);
        let calls = auth(false);
        audit::fail_phase(Some("intent"));
        assert!(v.unlock("run", &names, None, false).is_err());
        audit::fail_phase(None);
        assert_eq!(calls.get(), 0);
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        daemon::REQUEST_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn open_and_empty_rotation_require_auth_before_any_write() {
        let _dispatch = RecoveryDispatch::install();
        for populated in [false, true] {
            let mut v = fixture(if populated { "rotate-open" } else { "rotate-empty" });
            if populated { secret(&v, "test/open", Tier::Open, true); }
            let before = fs::read(v.paths.config()).unwrap();
            let envelope = populated.then(|| fs::read(v.paths.secret("test/open").unwrap()).unwrap());
            let (_, recipient) = crypto::generate_backup_identity();
            let calls = auth(false);
            assert!(v.rotate_backup(&recipient).unwrap_err().to_string().contains("auth refused"));
            assert_eq!(calls.get(), 1);
            assert_eq!(fs::read(v.paths.config()).unwrap(), before);
            if let Some(bytes) = envelope { assert_eq!(fs::read(v.paths.secret("test/open").unwrap()).unwrap(), bytes); }
            let calls = auth(true);
            audit::fail_phase(Some("intent"));
            assert!(v.rotate_backup(&recipient).is_err());
            audit::fail_phase(None);
            assert_eq!(calls.get(), 0);
            if !populated {
                assert_eq!(v.rotate_backup(&recipient).unwrap(), 0);
                assert_eq!(calls.get(), 1);
                assert_eq!(store::load_config(&v.paths).unwrap().backup_recipient, Some(recipient));
            }
            platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
            fs::remove_dir_all(v.paths.root).unwrap();
        }
    }

    #[test]
    fn cached_bio_does_not_authorize_mixed_open_reveal() {
        use std::{io::{BufRead, BufReader, Write}, os::unix::net::UnixListener, sync::{Arc, atomic::{AtomicBool, Ordering}}};
        use base64::Engine;
        let v = fixture("mixed");
        let dek = secret(&v, "test/bio", Tier::Bio, false);
        secret(&v, "test/open", Tier::Open, true);
        store::ensure_dir(&v.paths.root.join("run")).unwrap();
        // The synthetic daemon is this test binary; an initialized vault now requires its pin.
        fs::write(v.paths.keys().join("daemon.sha256"), platform::helper::sha256_file(&std::env::current_exe().unwrap()).unwrap()).unwrap();
        let listener = UnixListener::bind(daemon::sock_path(&v.paths)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let server = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // macOS: accepted sockets inherit O_NONBLOCK from the listener.
                        stream.set_nonblocking(false).unwrap();
                        let mut line = String::new();
                        BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).unwrap();
                        if line.is_empty() { continue; }
                        let request: Value = serde_json::from_str(&line).unwrap();
                        assert_eq!(request["op"], "use");
                        writeln!(stream, "{}", json!({"deks": {"test/bio": base64::engine::general_purpose::STANDARD.encode(dek.as_ref())}})).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(1)),
                    Err(e) => panic!("synthetic daemon: {e}"),
                }
            }
        });
        let names = ["test/bio".into(), "test/open".into()];
        let calls = auth(false);
        assert!(v.unlock_internal("reveal", &names, None, true, |req| daemon::request(&v.paths, &req)).err().unwrap().to_string().contains("auth refused"));
        assert_eq!(calls.get(), 1);
        let calls = auth(false);
        audit::fail_phase(Some("intent"));
        assert!(v.unlock_internal("reveal", &names, None, true, |req| daemon::request(&v.paths, &req)).is_err());
        audit::fail_phase(None);
        assert_eq!(calls.get(), 0);
        let values = v.unlock_internal("reveal", &["test/bio".into()], None, true, |req| daemon::request(&v.paths, &req)).unwrap();
        assert_eq!(values[0].value.as_slice(), b"synthetic proof fixture");
        assert_eq!(calls.get(), 0, "human-cache cached-only Bio reuse remains unprompted");
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    const URL: &str = "https://example.awsapps.com/start";

    #[test]
    fn portal_add_and_repoint_auth_refused_or_intent_failed_never_save() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("portal");
        for region in ["us-east-1", "us-west-2"] {
            let before = fs::read(v.paths.config()).unwrap();
            let calls = auth(false);
            assert!(v.sso_portal_add("main", URL, region).unwrap_err().to_string().contains("auth refused"));
            assert_eq!(calls.get(), 1);
            assert_eq!(fs::read(v.paths.config()).unwrap(), before);
            let calls = auth(true);
            audit::fail_phase(Some("intent"));
            assert!(v.sso_portal_add("main", URL, region).is_err());
            audit::fail_phase(None);
            assert_eq!(calls.get(), 0);
            v.sso_portal_add("main", URL, region).unwrap();
            assert_eq!(calls.get(), 1);
        }
        let calls = auth(false);
        v.sso_portal_add("main", URL, "us-west-2").unwrap();
        assert_eq!(calls.get(), 0, "exact no-op");
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn stale_portal_add_remove_preserve_persisted_tightening() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("portal-stale");
        auth(true);
        v.sso_portal_add("main", URL, "us-east-1").unwrap();
        let mut cfg = store::load_config(&v.paths).unwrap();
        cfg.sso_portals.get_mut("main").unwrap().limit_minutes = Some(15);
        cfg.clip_seconds = 7;
        cfg.sso_portals.insert("other".into(), cfg.sso_portals["main"].clone());
        store::save_config(&v.paths, &cfg).unwrap();
        v.sso_portal_add("main", URL, "us-east-1").unwrap();
        assert_eq!(store::load_config(&v.paths).unwrap().sso_portals["main"].limit_minutes, Some(15));
        // Make the instance stale again, then remove only the target.
        cfg.sso_portals.get_mut("main").unwrap().limit_minutes = Some(5);
        store::save_config(&v.paths, &cfg).unwrap();
        audit::fail_phase(Some("intent"));
        assert!(v.sso_portal_remove("other").is_err());
        audit::fail_phase(None);
        assert!(store::load_config(&v.paths).unwrap().sso_portals.contains_key("other"));
        v.sso_portal_remove("other").unwrap();
        let current = store::load_config(&v.paths).unwrap();
        assert_eq!(current.sso_portals["main"].limit_minutes, Some(5));
        assert_eq!(current.clip_seconds, 7);
        assert!(!current.sso_portals.contains_key("other"));
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn portal_auth_drops_config_lock_and_revalidates_destination() {
        let _dispatch = RecoveryDispatch::install();
        for retarget in [false, true] {
            let mut v = fixture(if retarget { "portal-race-target" } else { "portal-race-limit" });
            auth(true);
            v.sso_portal_add("main", URL, "us-east-1").unwrap();
            let paths = v.paths.clone();
            platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                let lock = store::lock_config(&paths)?;
                let mut cfg = lock.load()?;
                let p = cfg.sso_portals.get_mut("main").unwrap();
                p.limit_minutes = Some(5);
                if retarget { p.region = "eu-west-1".into(); }
                cfg.clip_seconds = 9;
                lock.save(&cfg)
            })));
            let r = v.sso_portal_add("main", URL, "us-west-2");
            let current = store::load_config(&v.paths).unwrap();
            assert_eq!(current.clip_seconds, 9);
            assert_eq!(current.sso_portals["main"].limit_minutes, Some(5));
            if retarget {
                assert!(r.unwrap_err().to_string().contains("config changed"));
                assert_eq!(current.sso_portals["main"].region, "eu-west-1");
            } else {
                r.unwrap();
                assert_eq!(current.sso_portals["main"].region, "us-west-2");
            }
            fs::remove_dir_all(v.paths.root).unwrap();
        }
    }
    #[test]
    fn stale_missing_pin_after_completed_retirement_refuses_lookup_and_repin() {
        if std::env::var_os("KARAMBIT_TEST_STALE_CHILD").is_none() {
            let root = std::env::temp_dir().join(format!("karambit-stale-child-{}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            let binary = root.join("test");
            fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
            let out = std::process::Command::new(binary)
                .args(["--exact", "proof_tests::stale_missing_pin_after_completed_retirement_refuses_lookup_and_repin", "--nocapture"])
                .env_clear().env("PATH", "/usr/bin:/bin").env("HOME", &root)
                .env("KARAMBIT_DIR", root.join("vault")).env("KARAMBIT_TEST_STALE_CHILD", "1")
                .output().unwrap();
            fs::remove_dir_all(root).unwrap();
            assert!(out.status.success(), "{} {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            return;
        }
        let mut failures = Vec::new();
        for repin in [false, true] {
            for no_directory in [false, true] {
                let v = fixture(&format!("stale-{repin}-{no_directory}"));
                let pf = v.paths.keys().join("helper.sha256");
                let candidate = v.paths.root.join("untrusted-helper");
                fs::write(&candidate, b"untrusted synthetic helper").unwrap();
                if no_directory { fs::remove_dir_all(v.paths.keys()).unwrap(); }
                let root = v.paths.root.clone();
                let restore_pf = pf.clone();
                // Pause immediately after NotFound. Complete a real retirement
                // before returning to the suspended lookup/repin.
                platform::helper::MISSING_PIN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                    store::ensure_dir(&v.paths.keys()).unwrap();
                    fs::write(&restore_pf, b"original trusted pin\n").unwrap();
                    v.retire_keys_authorized().unwrap();
                    assert!(!v.paths.root.join("keys.retirement").exists());
                })));
                let calls = auth(false);
                let refused = if repin { platform::helper::pin_candidates(&pf, vec![candidate]).is_err() }
                    else { platform::helper::verify_pin_at(&candidate, &pf).is_err() };
                if !refused || fs::read(&pf).unwrap() != b"original trusted pin\n" {
                    failures.push(format!("repin={repin}, no_directory={no_directory}: refused={refused}, pin preserved={}", fs::read(&pf).unwrap() == b"original trusted pin\n"));
                }
                assert_eq!(calls.get(), 0, "no helper authentication bypass/execution");
                platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
                fs::remove_dir_all(root).unwrap();
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    }

    #[test]
    fn retirement_pause_and_pin_write_failure_never_enable_tofu() {
        let _dispatch = RecoveryDispatch::install();
        for fail in [false, true] {
            let v = fixture(if fail { "retire-failure" } else { "retire-pause" });
            let pf = v.paths.keys().join("helper.sha256");
            fs::write(&pf, b"synthetic original pin").unwrap();
            let replacement = v.paths.root.join("synthetic-helper");
            fs::write(&replacement, b"not trusted").unwrap();
            let check_pf = pf.clone();
            let check_helper = replacement.clone();
            RETIRE_PIN_WRITE.with(|h| *h.borrow_mut() = Some(Box::new(move || {
                // Retirement is paused after rename, before the pin write. A
                // second thread exercises both lookup and repin in this window.
                std::thread::spawn(move || {
                    assert!(!check_pf.exists());
                    assert!(platform::helper::verify_pin_at(&check_helper, &check_pf).is_err());
                    assert!(platform::helper::pin_candidates(&check_pf, vec![check_helper]).is_err());
                    assert!(!check_pf.exists());
                }).join().unwrap();
                if fail { bail!("injected pin write failure") } else { Ok(()) }
            })));
            auth(true);
            let result = v.retire_keys();
            if fail {
                assert!(result.unwrap_err().to_string().contains("injected"));
                assert!(platform::helper::verify_pin_at(&replacement, &pf).is_err());
                assert!(platform::helper::pin_candidates(&pf, vec![replacement.clone()]).is_err());
                assert!(!pf.exists());
                // Even pre-marker interrupted retirement must never bootstrap.
                fs::remove_file(v.paths.root.join("keys.retirement")).unwrap();
                assert!(platform::helper::verify_pin_at(&replacement, &pf).is_err());
                assert!(platform::helper::pin_candidates(&pf, vec![replacement]).is_err());
                assert!(!pf.exists());
            } else {
                result.unwrap();
                assert_eq!(fs::read(&pf).unwrap(), b"synthetic original pin");
                assert!(!v.paths.root.join("keys.retirement").exists());
            }
            fs::remove_dir_all(v.paths.root).unwrap();
        }
    }

    #[test]
    fn standalone_retirement_requires_verified_paper_and_refuses_cancellation() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("standalone-paper");
        let (identity, recipient) = crypto::generate_backup_identity();
        v.cfg.backup_recipient = Some(recipient);
        secret(&v, "test/recover", Tier::Bio, false);
        let wrong = crypto::generate_backup_identity().0;
        let calls = auth(false);
        assert!(v.retire_keys_with_paper(&wrong).is_err());
        assert_eq!(calls.get(), 0);
        assert!(v.retire_keys_with_paper(&identity).is_err());
        assert_eq!(calls.get(), 1);
        assert!(v.paths.initialized());
        platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Err(platform::helper::unavailable_test_response()))));
        v.retire_keys_with_paper(&identity).unwrap();
        assert!(!v.paths.initialized());
        assert!(audit::read(&v.paths, usize::MAX).unwrap().iter().any(|e| e["detail"]["paper_only_biometrics_unavailable"] == true));
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    /// Software stand-in for the Secure Enclave: unwrap `f` with the P-256 key made from `seed`.
    fn soft_unwrap(f: &SecretFile, seed: u8) -> Result<Dek> {
        use base64::Engine;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::SecretKey::from_slice(&[seed; 32])?;
        let eph = p256::PublicKey::from_sec1_bytes(&base64::engine::general_purpose::STANDARD.decode(&f.eph)?)?;
        let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph.as_affine());
        crypto::unwrap_dek(f, shared.raw_secret_bytes(), sk.public_key().to_encoded_point(false).as_bytes())
    }

    /// The next `keygen` writes marker keys and returns the software key made from `seed`.
    fn soft_keygen(seed: u8) {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        platform::helper::KEYGEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |dir| {
            for key in ["bio.key", "open.key"] { fs::write(dir.join(key), b"synthetic new key")?; }
            let point = p256::SecretKey::from_slice(&[seed; 32])?.public_key().to_encoded_point(false).as_bytes().to_vec();
            Ok(platform::helper::PubKeys { bio: point.clone(), open: point, agent: None })
        })));
    }

    /// Bytes of everything recovery may touch, to prove a refusal changed nothing.
    fn vault_bytes(v: &Karambit) -> Vec<(String, Vec<u8>)> {
        let mut out = vec![];
        let mut stack = vec![v.paths.root.clone()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().map(Result::unwrap) {
                if e.file_type().unwrap().is_dir() { stack.push(e.path()); }
                else if e.file_name() != "audit.jsonl" {
                    out.push((e.path().to_string_lossy().into_owned(), fs::read(e.path()).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    fn retired_dirs(v: &Karambit) -> usize {
        fs::read_dir(&v.paths.root).unwrap().filter_map(Result::ok).filter(|e| e.file_name().to_string_lossy().starts_with("keys.retired-")).count()
    }

    #[test]
    fn partial_paper_key_is_refused_before_anything_changes_and_loss_must_be_named_exactly() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("recover-partial");
        let (identity, recipient) = crypto::generate_backup_identity();
        let (_, other) = crypto::generate_backup_identity();
        v.cfg.backup_recipient = None;
        secret(&v, "test/nobackup", Tier::Open, true);
        v.cfg.backup_recipient = Some(other);
        secret(&v, "test/wrongsheet", Tier::Bio, false);
        v.cfg.backup_recipient = Some(recipient);
        secret(&v, "test/good", Tier::Bio, false);
        let before = vault_bytes(&v);
        let calls = auth(true);
        soft_keygen(9);
        let lost = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();

        let e = v.recover_from_paper(&identity, &[]).unwrap_err().to_string();
        assert!(e.contains("1 of 3") || e.contains("2 of 3"), "{e}");
        assert!(e.contains("test/nobackup (no backup copy)") && e.contains("test/wrongsheet"), "{e}");
        assert!(e.contains("--accept-loss test/nobackup,test/wrongsheet"), "{e}");
        assert!(!e.contains("test/good"), "{e}");
        // Too few, too many, or a recoverable name must all refuse as well.
        for wrong in [lost(&["test/nobackup"]), lost(&["test/nobackup", "test/wrongsheet", "test/good"]), lost(&["test/good"])] {
            assert!(v.recover_from_paper(&identity, &wrong).is_err(), "{wrong:?}");
        }
        assert_eq!(calls.get(), 0, "refused before any authentication");
        assert_eq!(vault_bytes(&v), before, "refusal must change nothing");
        assert_eq!(retired_dirs(&v), 0);
        assert!(!v.paths.recovery_pending().exists());

        let (ok, missing) = v.recover_from_paper(&identity, &lost(&["test/nobackup", "test/wrongsheet"])).unwrap();
        assert_eq!((ok, missing), (1, lost(&["test/nobackup", "test/wrongsheet"])));
        assert_eq!(calls.get(), 1);
        assert_eq!(retired_dirs(&v), 1);
        assert!(!v.paths.recovery_pending().exists());
        soft_unwrap(&store::load_secret(&v.paths, "test/good").unwrap(), 9).unwrap();
        // The given-up files stay as they were, still wrapped to the retired keys.
        assert!(soft_unwrap(&store::load_secret(&v.paths, "test/wrongsheet").unwrap(), 9).is_err());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn interrupted_recovery_resumes_without_retiring_the_new_keys_again() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("recover-resume");
        let (identity, recipient) = crypto::generate_backup_identity();
        v.cfg.backup_recipient = Some(recipient);
        for name in ["test/a", "test/b", "test/c"] { secret(&v, name, Tier::Bio, false); }
        auth(true);
        soft_keygen(9);
        let seen = Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let log = seen.clone();
        REWRAP_FILE.with(|h| *h.borrow_mut() = Some(Box::new(move |name| {
            log.borrow_mut().push(name.to_string());
            if log.borrow().len() == 2 { bail!("injected interruption") } else { Ok(()) }
        })));
        assert!(v.recover_from_paper(&identity, &[]).unwrap_err().to_string().contains("injected interruption"));
        let first = seen.borrow()[0].clone();
        let done_bytes = fs::read(v.paths.secret(&first).unwrap()).unwrap();
        soft_unwrap(&store::load_secret(&v.paths, &first).unwrap(), 9).unwrap();
        assert!(v.paths.recovery_pending().exists());
        assert_eq!(retired_dirs(&v), 1);

        // Second run: no keygen hook is set, so retiring/regenerating again would panic.
        auth(true);
        seen.borrow_mut().clear();
        let log = seen.clone();
        REWRAP_FILE.with(|h| *h.borrow_mut() = Some(Box::new(move |name| { log.borrow_mut().push(name.to_string()); Ok(()) })));
        let (ok, missing) = v.recover_from_paper(&identity, &[]).unwrap();
        assert_eq!((ok, missing.len()), (3, 0));
        assert!(!seen.borrow().contains(&first), "already rewrapped file must be skipped");
        assert_eq!(seen.borrow().len(), 2);
        assert_eq!(fs::read(v.paths.secret(&first).unwrap()).unwrap(), done_bytes);
        assert_eq!(retired_dirs(&v), 1, "new keys must not be retired by the resume");
        assert!(!v.paths.recovery_pending().exists());
        for name in ["test/a", "test/b", "test/c"] { soft_unwrap(&store::load_secret(&v.paths, name).unwrap(), 9).unwrap(); }
        REWRAP_FILE.with(|h| h.borrow_mut().take());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    fn soft_ecdh() {
        use base64::Engine;
        platform::helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|reqs| {
            let sk = p256::SecretKey::from_slice(&[7; 32]).unwrap();
            reqs.iter().map(|(_, eph)| {
                let pk = p256::PublicKey::from_sec1_bytes(&base64::engine::general_purpose::STANDARD.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
    }

    #[test]
    fn interrupted_backup_rotation_is_marked_detected_by_verify_and_finished_by_rerun() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("rotate-partial");
        let (old, old_recipient) = crypto::generate_backup_identity();
        let (new, new_recipient) = crypto::generate_backup_identity();
        let (_, third_recipient) = crypto::generate_backup_identity();
        let old = crypto::parse_identity(&old).unwrap();
        let new = crypto::parse_identity(&new).unwrap();
        v.cfg.backup_recipient = Some(old_recipient.clone());
        store::save_config(&v.paths, &v.cfg).unwrap();
        for name in ["test/a", "test/b", "test/c"] { secret(&v, name, Tier::Open, true); }
        auth(true);
        soft_ecdh();
        let writes = Rc::new(Cell::new(0));
        let count = writes.clone();
        ROTATE_FILE.with(|h| *h.borrow_mut() = Some(Box::new(move |_| {
            count.set(count.get() + 1);
            if count.get() == 2 { bail!("injected crash mid-rotation") } else { Ok(()) }
        })));
        assert!(v.rotate_backup(&new_recipient).unwrap_err().to_string().contains("injected crash"));

        let cfg = store::load_config(&v.paths).unwrap();
        assert_eq!(cfg.backup_recipient, Some(old_recipient.clone()), "config still names the old sheet");
        assert_eq!(cfg.backup_rotation, Some(store::BackupRotation { from: Some(old_recipient.clone()), to: new_recipient.clone() }));
        // Verify must not accept the old sheet as "everything fine".
        let with_old = v.verify_backup(&old).unwrap();
        let with_new = v.verify_backup(&new).unwrap();
        assert_eq!((with_old.total, with_old.opened, with_old.unreadable.len()), (3, 2, 1));
        assert_eq!((with_new.total, with_new.opened, with_new.unreadable.len()), (3, 1, 2));
        assert!(with_old.rotation.is_some() && with_new.rotation.is_some());

        // A different sheet cannot hijack the unfinished rotation.
        auth(true); soft_ecdh();
        assert!(v.set_config("backup-recipient", &third_recipient).unwrap_err().to_string().contains("unfinished"));
        // Nor can the recipient be cleared mid-rotation.
        auth(true); soft_ecdh();
        assert!(v.set_config("backup-recipient", "none").unwrap_err().to_string().contains("unfinished"));
        assert_eq!(store::load_config(&v.paths).unwrap().backup_recipient, Some(old_recipient.clone()));
        assert_eq!(store::load_config(&v.paths).unwrap().backup_rotation.unwrap().to, new_recipient);

        // Lost the new sheet? Rotating again to a different recipient is allowed (every file is
        // rewritten from the SE keys) and keeps the original "from" through another crash.
        ROTATE_FILE.with(|h| *h.borrow_mut() = Some(Box::new(|_| bail!("injected second crash"))));
        assert!(v.rotate_backup(&third_recipient).is_err());
        assert_eq!(store::load_config(&v.paths).unwrap().backup_rotation,
            Some(store::BackupRotation { from: Some(old_recipient.clone()), to: third_recipient }));
        ROTATE_FILE.with(|h| h.borrow_mut().take());

        // Re-running with a recipient completes it.
        auth(true); soft_ecdh();
        assert_eq!(v.rotate_backup(&new_recipient).unwrap(), 3);
        let cfg = store::load_config(&v.paths).unwrap();
        assert_eq!((cfg.backup_recipient, cfg.backup_rotation), (Some(new_recipient), None));
        let done = v.verify_backup(&new).unwrap();
        assert_eq!((done.total, done.opened, done.rotation), (3, 3, None));
        assert_eq!(v.verify_backup(&old).unwrap().opened, 0);
        ROTATE_FILE.with(|h| h.borrow_mut().take());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn finished_rotation_leaves_no_marker_for_older_builds() {
        let json = serde_json::to_value(Config::default()).unwrap();
        assert!(json.get("backup_rotation").is_none());
        let back: Config = serde_json::from_value(json).unwrap();
        assert!(back.backup_rotation.is_none());
    }

    #[test]
    fn recovery_verifies_paper_before_retirement_and_prompts_once() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("recovery");
        let (identity, recipient) = crypto::generate_backup_identity();
        v.cfg.backup_recipient = Some(recipient);
        secret(&v, "test/recover", Tier::Bio, false);
        secret(&v, "test/second", Tier::Open, true);
        let pin = b"synthetic trusted helper hash\n";
        let daemon_pin = b"synthetic trusted daemon hash\n";
        fs::write(v.paths.keys().join("daemon.sha256"), daemon_pin).unwrap();
        fs::write(v.paths.keys().join("helper.sha256"), pin).unwrap();
        let original = fs::read(v.paths.pubkeys()).unwrap();
        let wrong = crypto::generate_backup_identity().0;
        let calls = auth(false);
        assert!(v.recover_from_paper(&wrong, &[]).unwrap_err().to_string().contains("does not decrypt"));
        assert_eq!(calls.get(), 0);
        assert!(v.paths.initialized());
        assert!(v.recover_from_paper(&identity, &[]).unwrap_err().to_string().contains("auth refused"));
        assert_eq!(calls.get(), 1);
        assert_eq!(fs::read(v.paths.pubkeys()).unwrap(), original);
        assert_eq!(fs::read_dir(&v.paths.root).unwrap().filter_map(Result::ok).filter(|e| e.file_name().to_string_lossy().starts_with("keys.retired-")).count(), 0);
        let calls = auth(true);
        let pk_bytes = original.clone();
        platform::helper::KEYGEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |dir| {
            assert_eq!(fs::read(dir.join("helper.sha256"))?, pin);
            assert_eq!(fs::read(dir.join("daemon.sha256"))?, daemon_pin);
            for key in ["bio.key", "open.key"] { fs::write(dir.join(key), b"synthetic new key")?; }
            let path = dir.join("test-pubkeys.json");
            fs::write(&path, pk_bytes)?;
            platform::helper::pubkeys_cached(&path)
        })));
        assert_eq!(v.recover_from_paper(&identity, &[]).unwrap().0, 2);
        assert_eq!(calls.get(), 1, "whole recovery must authenticate exactly once");
        assert_eq!(fs::read(v.paths.keys().join("helper.sha256")).unwrap(), pin);
        assert_eq!(fs::read(v.paths.keys().join("daemon.sha256")).unwrap(), daemon_pin);
        platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| Err(platform::helper::unavailable_test_response()))));
        assert_eq!(v.recover(&identity).unwrap().0, 2);
        for name in ["test/recover", "test/second"] {
            let activity = v.secret_activity(name, usize::MAX).unwrap();
            for phase in ["intent", "outcome"] {
                assert!(activity.iter().any(|e| e["action"] == "recover" && e["phase"] == phase));
            }
        }
        let events = audit::read(&v.paths, usize::MAX).unwrap();
        assert!(!serde_json::to_string(&events).unwrap().contains(identity.lines().find(|line| line.starts_with("AGE-SECRET-KEY-")).unwrap()), "paper identity leaked to audit");
        assert!(events.iter().any(|e| e["detail"]["paper_only_biometrics_unavailable"] == true));
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    fn rename_value(v: &Karambit, name: &str) -> Vec<u8> {
        let f = store::load_secret(&v.paths, name).unwrap();
        crypto::open(&soft_unwrap(&f, 7).unwrap(), &f).unwrap().to_vec()
    }

    #[test]
    fn rename_keeps_value_access_created_and_backup_and_ends_leases() {
        let _dispatch = RecoveryDispatch::install();
        let mut v = fixture("rename-one");
        let (identity, recipient) = crypto::generate_backup_identity();
        v.cfg.backup_recipient = Some(recipient);
        store::save_config(&v.paths, &v.cfg).unwrap();
        let dek = secret(&v, "test/old", Tier::Bio, true);
        let before = store::load_secret(&v.paths, "test/old").unwrap();
        let calls = auth(true);
        soft_ecdh();
        assert_eq!(v.rename("test/old", "moved/new").unwrap(), vec![("test/old".to_string(), "moved/new".to_string())]);
        assert!(!v.paths.secret("test/old").unwrap().exists(), "old file must be gone");
        assert!(!v.paths.secrets().join("test").exists(), "empty folder pruned");
        let after = store::load_secret(&v.paths, "moved/new").unwrap();
        assert_eq!((after.tier, after.agent_allowed, after.is_public(), after.created), (before.tier, before.agent_allowed, before.is_public(), before.created));
        assert_eq!(rename_value(&v, "moved/new"), b"synthetic proof fixture");
        // Same DEK, so the existing paper-backup copy still opens the renamed file.
        let paper = crypto::backup_unwrap(after.backup.as_ref().unwrap(), &crypto::parse_identity(&identity).unwrap()).unwrap();
        assert_eq!(paper.as_ref(), dek.as_ref());
        assert_eq!(calls.get(), 0, "a Touch ID secret is approved by the unwrap itself, not a second prompt");
        let events = audit::read(&v.paths, usize::MAX).unwrap();
        assert!(events.iter().any(|e| e["action"] == "rename" && e["phase"] == "intent" && e["detail"]["new"][0] == "moved/new"));
        assert!(events.iter().any(|e| e["action"] == "rename" && e["phase"] == "outcome" && e["ok"] == true));
        // Leases on the old name end: the daemon is asked to revoke exactly that name.
        let revoked = Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let seen = revoked.clone();
        soft_ecdh();
        v.rename_internal("moved/new", "moved/again", move |req| {
            if let daemon::Req::Revoke { patterns } = req { seen.borrow_mut().extend(patterns); }
            Ok(json!({"revoked": []}))
        }).unwrap();
        assert_eq!(*revoked.borrow(), vec!["moved/new".to_string()]);
        platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn rename_refuses_a_secret_replaced_during_approval() {
        let _dispatch = RecoveryDispatch::install();
        let v = fixture("rename-race");
        secret(&v, "test/a", Tier::Open, true);
        let paths = v.paths.clone();
        let racer = fixture_clone(&v);
        platform::helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || {
            // Another writer replaces the value while the prompt is open.
            secret(&racer, "test/a", Tier::Open, true);
            Ok(())
        })));
        soft_ecdh();
        let error = v.rename("test/a", "test/b").unwrap_err().to_string();
        assert!(error.contains("changed during approval"), "{error}");
        assert!(paths.secret("test/a").unwrap().exists() && !paths.secret("test/b").unwrap().exists());
        platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    fn fixture_clone(v: &Karambit) -> Karambit {
        Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller: Caller::default(), run_cmd: None }
    }

    #[test]
    fn rename_into_a_folder_named_like_the_secret_itself() {
        let _dispatch = RecoveryDispatch::install();
        let v = fixture("rename-under-self");
        secret(&v, "test/me", Tier::Open, true);
        secret(&v, "test/other", Tier::Open, true);
        auth(true);
        soft_ecdh();
        v.rename("test/me", "test/me/inner").unwrap();
        assert!(!v.paths.secret("test/me").unwrap().exists());
        assert_eq!(rename_value(&v, "test/me/inner"), b"synthetic proof fixture");
        // A secret may sit beside a folder of the same name, as `add` allows.
        auth(true);
        soft_ecdh();
        v.rename("test/other", "test/me").unwrap();
        assert!(v.paths.secret("test/me").unwrap().exists() && v.paths.secret("test/me/inner").unwrap().exists());
        platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn folder_move_renames_every_item_under_one_prompt() {
        let _dispatch = RecoveryDispatch::install();
        let v = fixture("rename-folder");
        for name in ["app/a", "app/sub/b", "apple/c"] { secret(&v, name, Tier::Open, true); }
        let calls = auth(true);
        soft_ecdh();
        let mut moved = v.rename("app/", "svc/app/").unwrap();
        moved.sort();
        assert_eq!(moved, vec![("app/a".into(), "svc/app/a".into()), ("app/sub/b".into(), "svc/app/sub/b".into())]);
        assert_eq!(calls.get(), 1, "open-tier items: one explicit Touch ID for the whole move");
        let names: Vec<String> = store::list_secrets(&v.paths).unwrap().into_iter().map(|f| f.name).collect();
        assert!(names.contains(&"apple/c".to_string()), "a sibling with the same prefix is untouched");
        for name in ["svc/app/a", "svc/app/sub/b"] { assert_eq!(rename_value(&v, name), b"synthetic proof fixture"); }
        assert!(!names.iter().any(|n| n.starts_with("app/")));
        platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

    #[test]
    fn rename_refuses_clashes_reserved_names_agents_and_denied_touch_id_without_changing_files() {
        let _dispatch = RecoveryDispatch::install();
        let v = fixture("rename-refuse");
        for name in ["test/a", "test/b", "dir/x"] { secret(&v, name, Tier::Open, true); }
        let snapshot = || { let mut n: Vec<(String, String)> = store::list_secrets(&v.paths).unwrap().into_iter().map(|f| (f.name, f.ct)).collect(); n.sort(); n };
        let before = snapshot();
        let calls = auth(true);
        soft_ecdh();
        for (from, to, want) in [
            ("test/a", "test/b", "already exists"),
            ("test/a", "dir/x", "already exists"),
            ("test/a", "test/a", "the same"),
            ("test/", "test/inner/", "into itself"),
            ("test/a", "other/", "folder (ending in /)"),
            ("test/a", "aws/prod", "AWS profiles"),
            ("test/a", "sources/x/cred", "reserved"),
            ("missing/x", "test/c", "no secret matches"),
            ("test/a", "../escape", "invalid secret name"),
        ] {
            let error = v.rename(from, to).unwrap_err().to_string();
            assert!(error.contains(want), "{from} -> {to}: {error}");
        }
        assert_eq!(calls.get(), 0, "refused before any prompt");
        let agent = Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller: Caller { agent: Some("synthetic".into()), ..Default::default() }, run_cmd: None };
        assert!(agent.rename("test/a", "test/c").unwrap_err().to_string().contains("human-only"));
        assert!(agent.rename_internal("test/a", "test/c", |_| Ok(json!({}))).unwrap_err().to_string().contains("human-only"));
        auth(false);
        assert!(v.rename("test/a", "test/c").unwrap_err().to_string().contains("auth refused"));
        assert_eq!(snapshot(), before, "nothing written or removed");
        platform::helper::ECDH_HOOK.with(|h| h.borrow_mut().take());
        platform::helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
        fs::remove_dir_all(v.paths.root).unwrap();
    }

}
