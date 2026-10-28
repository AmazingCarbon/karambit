//! Snapshots and bounded reference-only launch authority.
// Binding verification and consumption are used by the Bind/Redeem path.
#![allow(dead_code)]

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use crate::lease::{CommandBinding, CommandSnapshot};

/// Immutable launch input captured outside daemon State. Only argv[1] is hashed:
/// not interpreter flags (-m/-c), imports, config, or other arguments. Hashing and
/// exec remain separate steps; files can still be swapped between them.
/// No Deserialize/Clone or mutable accessors: wire input cannot replace a snapshot.
pub(crate) struct LaunchBinding {
    argv: Vec<String>,
    requested_cwd: PathBuf,
    requested_target: PathBuf,
    cwd: PathBuf,
    target: CommandSnapshot,
    script: Option<CommandSnapshot>,
}

impl LaunchBinding {
    pub(crate) fn capture(requested_target: PathBuf, argv: Vec<String>, requested_cwd: PathBuf) -> Result<Self> {
        let target = CommandBinding::capture_target(requested_target.to_str())?;
        if argv.is_empty() { bail!("missing command"); }
        if !requested_cwd.is_absolute() { bail!("launch cwd must be absolute"); }
        if argv.iter().any(|arg| arg.contains('\0')) { bail!("launch argv contains NUL"); }
        let cwd = std::fs::canonicalize(&requested_cwd).context("resolve launch cwd")?;
        if !cwd.is_dir() { bail!("launch cwd is not a directory"); }
        let script = script_snapshot(&argv, &cwd)?;
        Ok(Self { argv, requested_cwd, requested_target, cwd, target, script })
    }

    pub(crate) fn check_scope(&self, cmds: &[CommandBinding]) -> Result<()> {
        if !cmds.is_empty() {
            // Shells never match any scope. Interpreters match only a script pair,
            // which check_launch decides.
            CommandBinding::check_not_shell(&self.requested_target)?;
            CommandBinding::check_not_shell(Path::new(self.target.0.path()))?;
        }
        CommandBinding::check_launch(cmds, &Ok(self.target.clone()), self.script(), &self.argv)
    }

    pub(crate) fn argv(&self) -> &[String] { &self.argv }
    pub(crate) fn cwd(&self) -> &Path { &self.cwd }
    pub(crate) fn target(&self) -> &CommandBinding { &self.target.0 }
    pub(crate) fn script(&self) -> Option<&CommandBinding> { self.script.as_ref().map(|s| &s.0) }

    /// Pure equality only: `cwd` must already be canonical. No filesystem work.
    pub(crate) fn verify_request(&self, argv: &[String], cwd: &Path) -> Result<()> {
        if argv.len() != self.argv.len() { bail!("launch argv changed"); }
        if argv.iter().zip(&self.argv).any(|(a, b)| a != b) { bail!("launch argv changed"); }
        if cwd != self.cwd { bail!("launch cwd changed"); }
        Ok(())
    }

    /// Read-only fresh verification, never under State. Does not mutate authority.
    /// Compare canonical paths, SHA-256 and the hashed fd's dev/inode/size.
    pub(crate) fn verify_unchanged(&self) -> Result<()> {
        let cwd = std::fs::canonicalize(&self.requested_cwd).context("resolve launch cwd")?;
        if cwd != self.cwd || !cwd.is_dir() { bail!("launch cwd changed"); }
        if CommandBinding::capture_target(self.requested_target.to_str())? != self.target {
            bail!("launch target changed");
        }
        if script_snapshot(&self.argv, &self.cwd)? != self.script {
            bail!("launch script changed");
        }
        Ok(())
    }
}

fn script_snapshot(argv: &[String], cwd: &Path) -> Result<Option<CommandSnapshot>> {
    let Some(arg) = argv.get(1).filter(|arg| !arg.is_empty()) else { return Ok(None); };
    let path = cwd.join(arg);
    // lstat distinguishes a missing argument from an unreadable path. Follow
    // symlinks for the recorded binding; dangling links, like missing files,
    // are None, and a later transition to a regular file is refused.
    match std::fs::symlink_metadata(&path) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // O_NONBLOCK + fstat in the shared snapshot prevent FIFO hangs and
    // reject directories/devices before hashing. No file-content cache.
    CommandBinding::snapshot_regular_file(&canonical, false)
}

/// References only: never put plaintext, DEKs, endpoint tokens or auth proofs here.
pub(crate) struct PendingLaunch {
    pub(crate) allow_hosts: Vec<String>,
    pub(crate) jail_requested: bool,
    pub(crate) binding: LaunchBinding,
    /// Owner's canonical executable (pinned at Prepare) plus fstat identity; re-checked at Redeem.
    pub(crate) owner_exe: CommandSnapshot,
    pub(crate) refs: Vec<String>,
    pub(crate) env: std::collections::BTreeMap<String, String>,
    pub(crate) aws: Option<String>,
    pub(crate) sso_binding: Option<crate::daemon::SsoBinding>,
    pub(crate) sso_use: bool,
    pub(crate) lease_revision: u64,
    pub(crate) scopes: std::collections::HashMap<String, crate::daemon::Scope>,
    pub(crate) caller: crate::agent::Caller,
    pub(crate) decisions: std::collections::BTreeMap<String, crate::RunAuthorization>,
    /// `RunUnredacted` was approved for this launch (spent at Prepare); no owner redactor will exist.
    pub(crate) no_redact: bool,
}

pub(crate) const LAUNCH_TTL: u64 = 30;
const LAUNCH_CAPACITY: usize = 256;
const PEER_PENDING_CAPACITY: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum LaunchState {
    Pending,
    Bound(crate::agent::ProcessIdentity),
    /// Session authority taken by Redeem; still cancellable/containable until the
    /// lease-consume critical section finalizes it (never rebindable).
    Redeeming(crate::agent::ProcessIdentity),
    /// Redemption is spent; only the socket may attach its endpoint. Still
    /// containable so Cancel during decrypt cannot resurrect launch authority.
    Finalized(crate::agent::ProcessIdentity),
    Burned,
}

fn live_session(s: LaunchState) -> bool { matches!(s, LaunchState::Bound(_) | LaunchState::Redeeming(_) | LaunchState::Finalized(_)) }

struct LaunchRecord {
    owner: crate::agent::ProcessIdentity,
    created_at: u64,
    expires_at: u64,
    state: LaunchState,
    launch: Option<PendingLaunch>,
    refs: Vec<String>,
}

struct DeliveredLaunch {
    owner: crate::agent::ProcessIdentity,
    shim: crate::agent::ProcessIdentity,
    refs: Vec<String>,
    endpoint_id: String,
    created_at: u64,
    expires_at: u64,
}

#[derive(Default)]
pub(crate) struct PendingLaunches {
    entries: std::collections::HashMap<String, LaunchRecord>,
    contained: Vec<Vec<String>>,
    delivered: std::collections::HashMap<String, DeliveredLaunch>,
    removed_endpoints: Vec<String>,
}

impl PendingLaunches {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool { self.entries.is_empty() }

    #[cfg(test)]
    pub(crate) fn test_deadline(&mut self, id: &str, expires_at: u64) {
        self.entries.get_mut(id).unwrap().expires_at = expires_at;
    }

    /// OS RNG is called outside State, just like filesystem snapshot capture.
    pub(crate) fn new_id() -> Result<String> {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.try_fill_bytes(&mut bytes).context("launch id unavailable")?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// No eviction, including burned tombstones. Caller sweeps first. IDs are
    /// non-secret lookup handles, not authorization or future redemption tokens.
    pub(crate) fn insert(&mut self, id: String, owner: crate::agent::ProcessIdentity, launch: PendingLaunch, now: u64) -> Result<(String, u64)> {
        if self.entries.len() + self.delivered.len() >= LAUNCH_CAPACITY || self.delivered.values().filter(|r| r.owner == owner).count() + self.entries.values().filter(|r| r.owner == owner && r.state != LaunchState::Burned).count() >= PEER_PENDING_CAPACITY {
            bail!("launch refused");
        }
        if self.entries.contains_key(&id) || self.delivered.contains_key(&id) { bail!("launch refused"); }
        let ttl = if launch.sso_use || launch.decisions.values().any(|d| *d == crate::RunAuthorization::NeedsFreshAuth) { 120 } else { LAUNCH_TTL };
        let expires_at = now.saturating_add(ttl);
        self.entries.insert(id.clone(), LaunchRecord { owner, created_at: now, expires_at, state: LaunchState::Pending, refs: launch.refs.clone(), launch: Some(launch) });
        Ok((id, expires_at))
    }

    /// Burn before ANY validation, including owner/expiry errors. The caller
    /// must take under State, then verify outside it; a failed verification cannot
    /// put authority back. Unknown and burned IDs have the same generic error.
    pub(crate) fn take_and_burn(&mut self, id: &str, owner: crate::agent::ProcessIdentity, now: u64) -> Result<TakenLaunch> {
        let record = self.entries.get_mut(id).context("launch refused")?;
        record.state = LaunchState::Burned;
        let launch = record.launch.take().context("launch refused")?;
        if record.owner != owner || now < record.created_at || now >= record.expires_at { bail!("launch refused"); }
        Ok(TakenLaunch { launch, owner: record.owner, created_at: record.created_at, expires_at: record.expires_at })
    }

    /// Cancellation never lets another peer burn the owner's pending launch.
    /// A known owner's tombstone succeeds; unknown/expired IDs are generic errors.
    /// Expiry is checked here, in the same critical section, so a request that
    /// swept before the deadline cannot cancel an already-expired record.
    pub(crate) fn cancel(&mut self, id: &str, owner: crate::agent::ProcessIdentity, now: u64) -> Result<Option<PendingLaunch>> {
        if let Some(record) = self.delivered.get(id) {
            if record.owner != owner || now < record.created_at || now >= record.expires_at { bail!("launch refused"); }
            self.remove_delivered(id);
            return Ok(None);
        }
        let record = self.entries.get_mut(id).context("launch refused")?;
        if record.owner != owner { bail!("launch refused"); }
        if now < record.created_at || now >= record.expires_at { bail!("launch refused"); }
        if live_session(record.state) { self.contained.push(record.refs.clone()); }
        record.state = LaunchState::Burned;
        Ok(record.launch.take())
    }

    pub(crate) fn burn_matching(&mut self, patterns: &[String]) -> Vec<PendingLaunch> {
        let ids: Vec<_> = self.delivered.iter().filter(|(_, r)| r.refs.iter().any(|n| patterns.iter().any(|p| crate::store::glob_match(p, n)))).map(|(id, _)| id.clone()).collect();
        for id in ids { self.remove_delivered(&id); }
        self.burn_pending_matching(patterns)
    }

    // Legacy endpoints survive lease expiry; only pending authority is burned.
    pub(crate) fn burn_pending_matching(&mut self, patterns: &[String]) -> Vec<PendingLaunch> {
        let mut burned = Vec::new();
        for record in self.entries.values_mut() {
            if record.state != LaunchState::Burned && record.refs.iter().any(|r| patterns.iter().any(|p| crate::store::glob_match(p, r))) {
                if live_session(record.state) { self.contained.push(record.refs.clone()); }
                record.state = LaunchState::Burned;
                if let Some(launch) = record.launch.take() { burned.push(launch); }
            }
        }
        burned
    }

    /// Expired entries are burned before removal; removal cannot restore authority.
    /// Return metadata for best-effort containment audit AFTER releasing State.
    pub(crate) fn expire(&mut self, now: u64) -> Vec<PendingLaunch> {
        let ids: Vec<_> = self.delivered.iter().filter(|(_, r)| now < r.created_at || now >= r.expires_at).map(|(id, _)| id.clone()).collect();
        for id in ids { self.remove_delivered(&id); }
        let mut expired = Vec::new();
        self.entries.retain(|_, r| {
            if now < r.created_at || now >= r.expires_at {
                if live_session(r.state) { self.contained.push(r.refs.clone()); }
                r.state = LaunchState::Burned;
                if let Some(l) = r.launch.take() { expired.push(l); }
                false
            } else { true }
        });
        expired
    }

    pub(crate) fn bind_snapshot(&self, id: &str, now: u64, full_argv: bool) -> Result<(crate::agent::ProcessIdentity, serde_json::Value, Vec<String>)> {
        let r = self.entries.get(id).context("launch refused")?;
        if r.state != LaunchState::Pending || now < r.created_at || now >= r.expires_at { bail!("launch refused"); }
        Ok((r.owner, crate::audit::launch_detail(&r.launch.as_ref().context("launch refused")?.binding, full_argv, &[]), r.refs.clone()))
    }

    pub(crate) fn bind(&mut self, id: &str, owner: crate::agent::ProcessIdentity, shim: crate::agent::ProcessIdentity, now: u64) -> Result<TakenLaunch> {
        if self.entries.get(id).is_none_or(|r| r.state != LaunchState::Pending) { bail!("launch refused"); }
        let taken = self.take_and_burn(id, owner, now)?;
        self.entries.get_mut(id).unwrap().state = LaunchState::Bound(shim);
        Ok(taken)
    }

    /// Consume still-Bound metadata, never just a tombstone. Bound leaves the
    /// rebindable/redeemable state before checks: failure burns, success moves to
    /// Redeeming, which Cancel/Revoke/sweeps can still burn until `finalize_redeem`.
    pub(crate) fn redeem(&mut self, id: &str, taken: &TakenLaunch, shim: crate::agent::ProcessIdentity, now: u64) -> Result<()> {
        let r = self.entries.get_mut(id).context("launch refused")?;
        let state = std::mem::replace(&mut r.state, LaunchState::Burned);
        if state != LaunchState::Bound(shim) || r.owner != taken.owner
            || r.created_at != taken.created_at || r.expires_at != taken.expires_at
            || now < r.created_at || now >= r.expires_at { bail!("launch refused"); }
        r.state = LaunchState::Redeeming(shim);
        Ok(())
    }

    /// Metadata-only pre-prompt check; approval cannot revive canceled authority.
    pub(crate) fn check_redeeming(&self, id: &str, owner: crate::agent::ProcessIdentity, created_at: u64, expires_at: u64, shim: crate::agent::ProcessIdentity, now: u64) -> Result<()> {
        let r = self.entries.get(id).context("launch refused")?;
        if r.state != LaunchState::Redeeming(shim) || r.owner != owner
            || r.created_at != created_at || r.expires_at != expires_at
            || now < r.created_at || now >= r.expires_at { bail!("launch refused"); }
        Ok(())
    }

    /// Called inside the same State critical section as lease-use consumption.
    /// Containment that landed during verification (Cancel/Revoke/expiry/death)
    /// has already burned the entry, so this refuses. Successful finalization
    /// spends redemption. Env-only Finalized metadata remains containable for
    /// the owner redaction take, but does not contribute daemon keep-alive.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_redeem(&mut self, id: &str, owner: crate::agent::ProcessIdentity, created_at: u64, expires_at: u64, shim: crate::agent::ProcessIdentity, now: u64, _aws: bool) -> Result<()> {
        let result = self.check_redeeming(id, owner, created_at, expires_at, shim, now);
        if let Some(r) = self.entries.get_mut(id) { r.state = if result.is_ok() { LaunchState::Finalized(shim) } else { LaunchState::Burned }; }
        result
    }

    /// Pure authorization for the separately held, short-lived redaction frame.
    pub(crate) fn redaction_live(&self, id: &str, owner: crate::agent::ProcessIdentity, shim: crate::agent::ProcessIdentity, now: u64) -> bool {
        self.entries.get(id).is_some_and(|r| r.owner == owner && r.state == LaunchState::Finalized(shim) && now >= r.created_at && now < r.expires_at)
            || self.delivered.get(id).is_some_and(|r| r.owner == owner && r.shim == shim && now >= r.created_at && now < r.expires_at)
    }

    pub(crate) fn bound_shims(&self) -> Vec<(String, crate::agent::ProcessIdentity)> {
        self.entries.iter().filter_map(|(id, r)| match r.state {
            LaunchState::Bound(shim) | LaunchState::Redeeming(shim) | LaunchState::Finalized(shim) => Some((id.clone(), shim)), _ => None,
        }).chain(self.delivered.iter().map(|(id, r)| (id.clone(), r.shim))).collect()
    }

    pub(crate) fn burn_bound(&mut self, id: &str) {
        self.remove_delivered(id);
        if let Some(r) = self.entries.get_mut(id)
            && live_session(r.state) {
            r.state = LaunchState::Burned;
            self.contained.push(r.refs.clone());
        }
    }

    pub(crate) fn deliver(&mut self, id: &str, owner: crate::agent::ProcessIdentity, shim: crate::agent::ProcessIdentity, endpoint_id: String, created_at: u64, expires_at: u64) -> Result<()> {
        let r = self.entries.get(id).context("launch refused")?;
        if r.state != LaunchState::Finalized(shim) || r.owner != owner || created_at >= r.expires_at || self.delivered.values().filter(|r| r.owner == owner).count() >= PEER_PENDING_CAPACITY { bail!("launch refused"); }
        let refs = r.refs.clone();
        self.entries.remove(id);
        self.delivered.insert(id.into(), DeliveredLaunch { owner, shim, refs, endpoint_id, created_at, expires_at });
        Ok(())
    }

    fn remove_delivered(&mut self, id: &str) {
        if let Some(r) = self.delivered.remove(id) {
            self.contained.push(r.refs);
            self.removed_endpoints.push(r.endpoint_id);
        }
    }

    pub(crate) fn reconcile_endpoints(&mut self, endpoints: &std::collections::HashSet<String>) -> Vec<String> {
        let gone: Vec<_> = self.delivered.iter().filter(|(_, r)| !endpoints.contains(&r.endpoint_id)).map(|(id, _)| id.clone()).collect();
        for id in gone { self.remove_delivered(&id); }
        std::mem::take(&mut self.removed_endpoints)
    }

    pub(crate) fn drain_contained(&mut self) -> Vec<Vec<String>> { std::mem::take(&mut self.contained) }

    pub(crate) fn has_live_bound(&self, now: u64) -> bool {
        self.entries.values().any(|r| matches!(r.state, LaunchState::Bound(_) | LaunchState::Redeeming(_)) && now >= r.created_at && now < r.expires_at)
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.entries.values().any(|r| r.state == LaunchState::Pending)
    }
}

/// Transition payload belongs to the socket session, never the global Bound metadata.
pub(crate) struct TakenLaunch {
    pub(crate) launch: PendingLaunch,
    pub(crate) owner: crate::agent::ProcessIdentity,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("karambit-launch-binding-{:016x}", rand::random::<u64>()));
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("target"), b"synthetic executable, never run").unwrap();
            std::fs::set_permissions(root.join("target"), std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(std::fs::canonicalize(root).unwrap())
        }
        fn argv(&self, arg: &str) -> Vec<String> { vec![self.0.join("target").to_str().unwrap().into(), arg.into()] }
        fn binding(&self, arg: &str) -> LaunchBinding { LaunchBinding::capture(self.argv(arg)[0].clone().into(), self.argv(arg), self.0.clone()).unwrap() }
    }
    impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

    fn owner() -> crate::agent::ProcessIdentity {
        crate::agent::ProcessIdentity { pid: 42, sec: 100, usec: 5 }
    }
    fn pending(f: &Fixture) -> PendingLaunch {
        PendingLaunch { allow_hosts: vec![], jail_requested: false, binding: f.binding("absent"), owner_exe: CommandBinding::snapshot_regular_file(&f.0.join("target"), false).unwrap().unwrap(), refs: vec!["test/ref".into()], env: [("VALUE".into(), "test/ref".into())].into(), aws: None, sso_binding: None, sso_use: false, lease_revision: 0, scopes: Default::default(), caller: Default::default(), decisions: Default::default(), no_redact: false }
    }
    fn insert(registry: &mut PendingLaunches, f: &Fixture, peer: crate::agent::ProcessIdentity) -> String {
        registry.insert(PendingLaunches::new_id().unwrap(), peer, pending(f), 100).unwrap().0
    }

    fn delivered(registry: &mut PendingLaunches, f: &Fixture, owner: crate::agent::ProcessIdentity) -> (String, String) {
        let id = insert(registry, f, owner);
        let shim = crate::agent::ProcessIdentity { pid: owner.pid + 1, ..owner };
        let taken = registry.bind(&id, owner, shim, 101).unwrap();
        registry.redeem(&id, &taken, shim, 102).unwrap();
        registry.finalize_redeem(&id, owner, 100, 130, shim, 103, true).unwrap();
        let endpoint = format!("endpoint-{id}");
        registry.deliver(&id, owner, shim, endpoint.clone(), 104, 104+4*3600).unwrap();
        (id, endpoint)
    }

    #[test]
    fn owner_cap_counts_bound_redeeming_and_finalized_redaction_slots() {
        let f = Fixture::new();
        for state in ["bound", "redeeming", "finalized"] {
            let mut registry = PendingLaunches::default();
            let mut first = String::new();
            let shim = crate::agent::ProcessIdentity { pid: 43, ..owner() };
            for i in 0..PEER_PENDING_CAPACITY {
                let id = insert(&mut registry, &f, owner());
                if i == 0 { first = id.clone(); }
                let taken = registry.bind(&id, owner(), shim, 101).unwrap();
                if state != "bound" { registry.redeem(&id, &taken, shim, 102).unwrap(); }
                if state == "finalized" { registry.finalize_redeem(&id, owner(), 100, 130, shim, 103, false).unwrap(); }
            }
            assert!(registry.insert("seventeenth".into(), owner(), pending(&f), 104).is_err(), "{state} must consume an owner slot");
            registry.test_deadline(&first, 104);
            registry.expire(104);
            assert!(registry.insert("after-expiry".into(), owner(), pending(&f), 104).is_ok());
        }
        // Moving a slot to Delivered must not allow a second independent quota.
        let mut registry = PendingLaunches::default();
        delivered(&mut registry, &f, owner());
        for _ in 1..PEER_PENDING_CAPACITY { insert(&mut registry, &f, owner()); }
        assert!(registry.insert("combined".into(), owner(), pending(&f), 105).is_err());
    }

    #[test]
    fn delivered_launch_capacity_and_containment() {
        let f = Fixture::new();
        let mut registry = PendingLaunches::default();
        let (first, _) = delivered(&mut registry, &f, owner());
        for _ in 1..PEER_PENDING_CAPACITY { delivered(&mut registry, &f, owner()); }
        assert!(registry.insert("refused".into(), owner(), pending(&f), 105).is_err());
        assert_eq!(registry.delivered.len(), PEER_PENDING_CAPACITY);
        let other = crate::agent::ProcessIdentity { pid: 100, ..owner() };
        assert!(registry.cancel(&first, other, 105).is_err());
        assert_eq!(registry.delivered.len(), PEER_PENDING_CAPACITY);
        registry.cancel(&first, owner(), 105).unwrap();
        delivered(&mut registry, &f, owner());
        for n in PEER_PENDING_CAPACITY..LAUNCH_CAPACITY { delivered(&mut registry, &f, crate::agent::ProcessIdentity { pid: n as i32 + 100, ..owner() }); }
        assert_eq!(registry.delivered.len(), LAUNCH_CAPACITY);
        assert!(registry.insert("refused".into(), other, pending(&f), 105).is_err());
        assert!(registry.entries.is_empty());

        for mode in ["ttl", "cancel", "revoke", "death", "endpoint", "lease"] {
            let mut registry = PendingLaunches::default();
            let (id, endpoint) = delivered(&mut registry, &f, owner());
            assert_eq!(registry.bound_shims().len(), 1);
            assert!(registry.expire(104+4*3600-1).is_empty());
            assert_eq!(registry.delivered.len(), 1);
            let mut endpoints = [endpoint.clone()].into();
            match mode {
                "ttl" => { registry.expire(104+4*3600); }
                "cancel" => { registry.cancel(&id, owner(), 150).unwrap(); }
                "revoke" => { registry.burn_matching(&["test/*".into()]); }
                "death" => registry.burn_bound(&id),
                "endpoint" => endpoints = Default::default(),
                "lease" => { registry.burn_pending_matching(&["test/*".into()]); }
                _ => unreachable!(),
            }
            let removed = registry.reconcile_endpoints(&endpoints);
            if mode == "lease" { assert!(removed.is_empty()); assert_eq!(registry.delivered.len(), 1); }
            else { assert_eq!(removed, vec![endpoint], "{mode}"); assert!(registry.delivered.is_empty()); }
        }
    }

    #[test]
    fn delivered_launch_cannot_revive_contained_finalization() {
        let f = Fixture::new();
        for mode in ["cancel", "revoke", "expiry", "death"] {
            let mut registry = PendingLaunches::default();
            let id = insert(&mut registry, &f, owner());
            let shim = crate::agent::ProcessIdentity { pid: 43, ..owner() };
            let taken = registry.bind(&id, owner(), shim, 101).unwrap();
            registry.redeem(&id, &taken, shim, 102).unwrap();
            registry.finalize_redeem(&id, owner(), 100, 130, shim, 103, true).unwrap();
            match mode {
                "cancel" => { registry.cancel(&id, owner(), 104).unwrap(); }
                "revoke" => { registry.burn_matching(&["test/*".into()]); }
                "expiry" => { registry.expire(130); }
                "death" => registry.burn_bound(&id),
                _ => unreachable!(),
            }
            assert!(registry.deliver(&id, owner(), shim, "ep".into(), 104, 104+4*3600).is_err(), "{mode}");
        }
    }

    #[test]
    fn launch_finalization_retains_containment_not_keepalive() {
        let f = Fixture::new();
        for aws in [false, true] {
            let mut registry = PendingLaunches::default();
            let id = insert(&mut registry, &f, owner());
            let shim = crate::agent::ProcessIdentity { pid: 43, ..owner() };
            let taken = registry.bind(&id, owner(), shim, 101).unwrap();
            registry.redeem(&id, &taken, shim, 102).unwrap();
            registry.finalize_redeem(&id, owner(), 100, 130, shim, 103, aws).unwrap();
            assert!(!registry.has_live_bound(104));
            assert_eq!(registry.bound_shims().len(), 1);
        }
    }

    #[test]
    fn launch_ttl_is_original_and_fresh_only() {
        let f = Fixture::new();
        for fresh in [false, true] {
            let mut registry = PendingLaunches::default();
            let mut launch = pending(&f);
            launch.decisions.insert("test/ref".into(), if fresh { crate::RunAuthorization::NeedsFreshAuth } else { crate::RunAuthorization::OpenPublic });
            let (id, expires) = registry.insert(PendingLaunches::new_id().unwrap(), owner(), launch, 100).unwrap();
            assert_eq!(expires, if fresh { 220 } else { 130 });
            let shim = crate::agent::ProcessIdentity { pid: 43, ..owner() };
            let taken = registry.bind(&id, owner(), shim, 110).unwrap();
            assert_eq!(taken.expires_at, expires);
            registry.redeem(&id, &taken, shim, 120).unwrap();
            assert!(registry.finalize_redeem(&id, owner(), 100, expires, shim, expires, false).is_err());
        }
    }

    #[test]
    fn launch_redeem_registry_requires_bound_identity_deadline_and_burns() {
        let f = Fixture::new();
        let shim = crate::agent::ProcessIdentity { pid: 43, ..owner() };
        for mode in ["ok", "burned", "owner", "shim", "created", "expiry", "expired"] {
            let mut registry = PendingLaunches::default();
            let id = insert(&mut registry, &f, owner());
            let mut taken = registry.bind(&id, owner(), shim, 101).unwrap();
            match mode {
                "burned" => registry.burn_bound(&id),
                "owner" => taken.owner.usec += 1,
                "created" => taken.created_at += 1,
                "expiry" => taken.expires_at += 1,
                _ => (),
            }
            let requested_shim = if mode == "shim" { crate::agent::ProcessIdentity { usec: shim.usec+1, ..shim } } else { shim };
            assert_eq!(registry.redeem(&id, &taken, requested_shim, if mode == "expired" { 130 } else { 101 }).is_ok(), mode == "ok", "{mode}");
            assert!(registry.redeem(&id, &taken, shim, 101).is_err(), "never restore after {mode}");
            assert!(!registry.has_live_bound(101));
        }
    }

    #[test]
    fn pending_launch_capacity_refuses_without_eviction() {
        let f = Fixture::new();
        let mut registry = PendingLaunches::default();
        let first = insert(&mut registry, &f, owner());
        for i in 1..LAUNCH_CAPACITY { insert(&mut registry, &f, crate::agent::ProcessIdentity { pid: i as i32 + 100, ..owner() }); }
        assert!(registry.insert(PendingLaunches::new_id().unwrap(), owner(), pending(&f), 100).is_err());
        assert_eq!(registry.entries.len(), LAUNCH_CAPACITY);
        assert!(registry.take_and_burn(&first, owner(), 101).is_ok());
    }

    #[test]
    fn pending_launch_peer_cap_preserves_other_peers() {
        let f = Fixture::new();
        let mut registry = PendingLaunches::default();
        let first = insert(&mut registry, &f, owner());
        for _ in 1..PEER_PENDING_CAPACITY { insert(&mut registry, &f, owner()); }
        assert!(registry.insert(PendingLaunches::new_id().unwrap(), owner(), pending(&f), 100).is_err());
        insert(&mut registry, &f, crate::agent::ProcessIdentity { usec: 6, ..owner() });
        registry.cancel(&first, owner(), 101).unwrap();
        insert(&mut registry, &f, owner()); // Tombstones do not count per-peer.
    }

    #[test]
    fn pending_launch_cancel_after_deadline_refused() {
        // Sweep ran before the deadline (nothing expired), cancel arrives after it.
        let f = Fixture::new();
        let mut registry = PendingLaunches::default();
        let id = insert(&mut registry, &f, owner());
        assert!(registry.expire(129).is_empty());
        assert!(registry.cancel(&id, owner(), 130).is_err());
        // Expired tombstone: repeat cancel after deadline is refused too.
        let id2 = insert(&mut registry, &f, owner());
        assert!(registry.cancel(&id2, owner(), 101).unwrap().is_some());
        assert!(registry.cancel(&id2, owner(), 130).is_err());
    }

    #[test]
    fn pending_launch_expiry_burns() {
        let f = Fixture::new();
        let mut registry = PendingLaunches::default();
        let id = insert(&mut registry, &f, owner());
        assert!(registry.expire(129).is_empty());
        assert_eq!(registry.expire(130).len(), 1);
        assert!(!registry.has_pending());
        assert!(registry.take_and_burn(&id, owner(), 130).is_err());
        assert!(registry.expire(131).is_empty());
    }

    #[test]
    fn pending_launch_double_take_fails() {
        let f = Fixture::new();
        let mut registry = PendingLaunches::default();
        let id = insert(&mut registry, &f, owner());
        let launch = registry.take_and_burn(&id, owner(), 101).unwrap().launch;
        assert_eq!(launch.refs, vec!["test/ref"]);
        assert_eq!(launch.env["VALUE"], "test/ref");
        assert!(launch.aws.is_none());
        assert_eq!(launch.lease_revision, 0);
        assert!(registry.take_and_burn(&id, owner(), 101).is_err());
    }

    #[test]
    fn pending_launch_failed_take_still_burns() {
        let f = Fixture::new();
        for expired in [false, true] {
            let mut registry = PendingLaunches::default();
            let id = insert(&mut registry, &f, owner());
            let peer = if expired { owner() } else { crate::agent::ProcessIdentity { usec: 6, ..owner() } };
            assert!(registry.take_and_burn(&id, peer, if expired { 130 } else { 101 }).is_err());
            assert!(registry.take_and_burn(&id, owner(), 101).is_err());
        }
    }

    #[test]
    fn pending_launch_cancel_owner_includes_microseconds() {
        let f = Fixture::new();
        let mut registry = PendingLaunches::default();
        let id = insert(&mut registry, &f, owner());
        // Synthetic peer: identical PID/start seconds but different microseconds.
        assert!(registry.cancel(&id, crate::agent::ProcessIdentity { usec: 6, ..owner() }, 101).is_err());
        assert!(registry.has_pending());
        assert!(registry.cancel(&id, owner(), 101).unwrap().is_some());
        assert!(registry.cancel(&id, owner(), 101).unwrap().is_none());
        assert!(registry.cancel("unknown", owner(), 101).is_err());
        assert!(registry.take_and_burn(&id, owner(), 101).is_err());
    }

    #[test]
    fn launch_binding_positive_and_argv_replacement() {
        let f = Fixture::new();
        std::fs::write(f.0.join("script"), b"synthetic script").unwrap();
        let binding = f.binding("script");
        binding.verify_unchanged().unwrap();
        binding.verify_request(binding.argv(), binding.cwd()).unwrap();
        assert_eq!(binding.target().path(), f.0.join("target").to_str().unwrap());
        assert_eq!(binding.script().unwrap().path(), f.0.join("script").to_str().unwrap());
        assert!(binding.verify_request(&f.argv("replacement"), &f.0).is_err());
    }

    #[test]
    fn launch_binding_argv_length_replacement() {
        let f = Fixture::new();
        let binding = f.binding("absent");
        let mut argv = f.argv("absent");
        argv.push("extra".into());
        assert!(binding.verify_request(&argv, &f.0).is_err());
        argv.truncate(1);
        assert!(binding.verify_request(&argv, &f.0).is_err());
    }

    #[test]
    fn launch_binding_cwd_replacement_and_retarget() {
        let f = Fixture::new();
        let other = f.0.join("other");
        std::fs::create_dir(&other).unwrap();
        let link = f.0.join("cwd-link");
        symlink(&f.0, &link).unwrap();
        let binding = LaunchBinding::capture(f.argv("absent")[0].clone().into(), f.argv("absent"), link.clone()).unwrap();
        assert!(binding.verify_request(binding.argv(), &other).is_err());
        binding.verify_unchanged().unwrap();
        std::fs::remove_file(&link).unwrap();
        symlink(&other, &link).unwrap();
        assert!(binding.verify_unchanged().is_err());
    }

    #[test]
    fn launch_binding_target_replacement() {
        let f = Fixture::new();
        let binding = f.binding("absent");
        std::fs::write(f.0.join("target"), b"different executable contents").unwrap();
        assert!(binding.verify_unchanged().is_err());
    }

    #[test]
    fn launch_binding_target_inode_replacement() {
        let f = Fixture::new();
        let binding = f.binding("absent");
        std::fs::copy(f.0.join("target"), f.0.join("replacement")).unwrap();
        std::fs::rename(f.0.join("replacement"), f.0.join("target")).unwrap();
        assert!(binding.verify_unchanged().is_err(), "same bytes on a new inode are not the captured file");
    }

    #[test]
    fn launch_binding_script_edit() {
        let f = Fixture::new();
        std::fs::write(f.0.join("script"), b"original").unwrap();
        let binding = f.binding("script");
        std::fs::write(f.0.join("script"), b"modified").unwrap();
        assert!(binding.verify_unchanged().is_err());
    }

    #[test]
    fn launch_binding_script_transitions() {
        let f = Fixture::new();
        let binding = f.binding("script");
        assert!(binding.script().is_none());
        std::fs::write(f.0.join("script"), b"new file").unwrap();
        assert!(binding.verify_unchanged().is_err());
        let binding = f.binding("script");
        std::fs::remove_file(f.0.join("script")).unwrap();
        assert!(binding.verify_unchanged().is_err());
    }

    #[test]
    fn launch_binding_script_canonical_path() {
        let f = Fixture::new();
        std::fs::write(f.0.join("script-a"), b"same").unwrap();
        std::fs::hard_link(f.0.join("script-a"), f.0.join("script-b")).unwrap();
        symlink("script-a", f.0.join("script")).unwrap();
        let binding = f.binding("script");
        std::fs::remove_file(f.0.join("script")).unwrap();
        symlink("script-b", f.0.join("script")).unwrap();
        assert!(binding.verify_unchanged().is_err(), "even same inode/hash at another canonical path must fail");
    }

    #[test]
    fn launch_binding_fifo_is_not_read() {
        let f = Fixture::new();
        let fifo = std::ffi::CString::new(f.0.join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let cwd = f.0.clone();
        let argv = f.argv("fifo");
        // A mutant that performs a blocking open/read must fail within a bound,
        // not hang the test runner. Worker owns the synthetic root until done.
        std::thread::spawn(move || {
            let _fixture = f;
            let binding = LaunchBinding::capture(argv[0].clone().into(), argv, cwd).unwrap();
            let result = binding.script().is_none() && binding.verify_unchanged().is_ok();
            let _ = tx.send(result);
        });
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).expect("FIFO snapshot hung"));
    }

    #[test]
    fn launch_binding_directory_is_not_script() {
        let f = Fixture::new();
        let binding = f.binding(".");
        assert!(binding.script().is_none());
        binding.verify_unchanged().unwrap();
    }
}
