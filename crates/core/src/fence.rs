//! Capability fence: the single table of verbs an agent caller may never perform.
//!
//! Every human-only refusal in the CLI and the daemon is a lookup in
//! [`AGENT_DENIED_VERBS`]; there is one refusal message. The daemon lookup is
//! authoritative (the caller comes from the kernel-derived `Peer`, never from the
//! wire); the CLI lookup refuses early, before any prompt or request. A row's `cli`
//! and `daemon` flags say which layers check it, and a verb with no row is not fenced.
//!
//! This table only *adds* refusals. Policy-governed access (`agent_allowed`, public
//! entries, leases, fresh Touch ID) is not here: see `run_authorization`.

use crate::agent::Caller;
use crate::daemon::Req;
use anyhow::{Result, bail};

/// A capability that agent callers are denied. Variants mirror the operations, not
/// the wire requests: several `Req` variants and CLI commands can map to one verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    /// Create the vault, keys and backup recipient.
    Init,
    /// Create or overwrite a secret (`add`, `aws add`, `aws add --sso`).
    Add,
    /// Delete secrets (`rm`, `aws rm`).
    Rm,
    /// Rename a secret or move a folder (`mv`).
    Rename,
    /// Relax policy: Touch ID off, agents allowed, public on.
    PolicyRelax,
    /// Relax config: default tier off, backup recipient none, `agent-*`, longer self-lease.
    ConfigRelax,
    /// `get`: disclosure of a non-public secret. The daemon unlock path stays governed
    /// by policy (`agent_allowed` plus fresh approval), so this row is CLI only.
    Get,
    /// Grant a lease (`lease grant`, raw `GrantLease`, legacy wire `Grant`).
    LeaseGrant,
    /// Populate the human self-lease cache.
    HumanUnlock,
    /// `keys upgrade`.
    KeysUpgrade,
    /// `helper pin` / staged repin.
    HelperPin,
    /// `recover` from the offline backup identity.
    Recover,
    /// Retire the Secure Enclave keys.
    RetireKeys,
    /// `backup rotate`.
    BackupRotate,
    /// `backup verify` (local paper-key check).
    BackupVerify,
    /// The paper-key ceremony.
    PaperBackup,
    /// `run --no-redact`.
    NoRedact,
    /// `daemon stop`.
    DaemonStop,
    /// `aws sso login` and the daemon login commit.
    SsoLogin,
    /// `aws sso logout`.
    SsoLogout,
    /// `aws sso portal add`.
    SsoPortalAdd,
    /// `aws sso portal rm`.
    SsoPortalRemove,
    /// `aws sso portal limit`.
    SsoPortalLimit,
    /// Register SSO profiles with the daemon.
    SsoRegister,
    SsoDiscover,
    SsoImport,
    SourceAdd,
    SourceRemove,
    SourceRetarget,
    SourceList,
    ProfileTrust,
    Kill,
    Revive,
}

impl Verb {
    /// Every verb, for table-driven tests. `Revive` must stay the last variant.
    pub const ALL: [Verb; 33] = [
        Verb::Init, Verb::Add, Verb::Rm, Verb::Rename, Verb::PolicyRelax, Verb::ConfigRelax, Verb::Get, Verb::LeaseGrant,
        Verb::HumanUnlock, Verb::KeysUpgrade, Verb::HelperPin, Verb::Recover, Verb::RetireKeys, Verb::BackupRotate,
        Verb::BackupVerify, Verb::PaperBackup, Verb::NoRedact, Verb::DaemonStop, Verb::SsoLogin, Verb::SsoLogout,
        Verb::SsoPortalAdd, Verb::SsoPortalRemove, Verb::SsoPortalLimit, Verb::SsoRegister, Verb::SsoDiscover, Verb::SsoImport,
        Verb::SourceAdd, Verb::SourceRemove, Verb::SourceRetarget, Verb::SourceList, Verb::ProfileTrust, Verb::Kill, Verb::Revive,
    ];
}

/// Where a check runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Cli,
    Daemon,
}

/// One fenced verb. `what` is the text placed in the refusal message.
pub struct Row {
    pub verb: Verb,
    pub what: &'static str,
    /// Checked in the CLI (and client-side library) before any prompt or request.
    pub cli: bool,
    /// Checked in daemon request dispatch (or the daemon-side operation it runs).
    pub daemon: bool,
}

const fn row(verb: Verb, what: &'static str, cli: bool, daemon: bool) -> Row {
    Row { verb, what, cli, daemon }
}

/// Verbs denied to agent callers. Removing a row un-fences the verb at both layers.
pub const AGENT_DENIED_VERBS: &[Row] = &[
    row(Verb::ProfileTrust, "trusting repository profiles", true, true),
    row(Verb::Kill, "blocking agents", true, true),
    row(Verb::Revive, "unblocking agents", true, true),
    row(Verb::SourceAdd, "adding a source", true, true),
    row(Verb::SourceRemove, "removing a source", true, true),
    row(Verb::SourceRetarget, "retargeting a source", true, true),
    row(Verb::SourceList, "listing sources", true, true),
    row(Verb::Init, "initializing the vault", true, true),
    row(Verb::Add, "adding a secret", true, true),
    row(Verb::Rm, "removing a secret", true, true),
    row(Verb::Rename, "renaming a secret", true, true),
    row(Verb::PolicyRelax, "relaxing policy", true, true),
    row(Verb::ConfigRelax, "relaxing config", true, true),
    // Daemon unlock is policy-governed: an agent_allowed secret still needs fresh approval.
    row(Verb::Get, "get", true, false),
    row(Verb::LeaseGrant, "granting a lease", true, true),
    // No CLI command: only the daemon's own unlock path requests it.
    row(Verb::HumanUnlock, "human unlock", false, true),
    row(Verb::KeysUpgrade, "keys upgrade", true, true),
    row(Verb::HelperPin, "pinning the helper", true, true),
    row(Verb::Recover, "recover", true, true),
    // Library/GUI only: there is no CLI command.
    row(Verb::RetireKeys, "retire-keys", false, true),
    row(Verb::BackupRotate, "backup rotate", true, true),
    // Local to the CLI: no daemon request exists.
    row(Verb::BackupVerify, "backup verify", true, false),
    row(Verb::PaperBackup, "paper backup", true, false),
    row(Verb::NoRedact, "--no-redact", true, true),
    row(Verb::DaemonStop, "stopping the daemon", true, true),
    row(Verb::SsoLogin, "AWS SSO login", true, true),
    row(Verb::SsoLogout, "AWS SSO logout", true, true),
    row(Verb::SsoPortalAdd, "adding an SSO portal", true, true),
    // The CLI edits config.json directly; no daemon request exists (same-user-writable file).
    row(Verb::SsoPortalRemove, "removing an SSO portal", true, false),
    row(Verb::SsoPortalLimit, "changing an AWS sign-in limit", true, true),
    // No CLI command: only the daemon-side sync and the login commit request it.
    row(Verb::SsoDiscover, "discovering SSO roles", false, true),
    row(Verb::SsoImport, "importing SSO roles", true, true),
    row(Verb::SsoRegister, "registering SSO profiles", false, true),
];

/// The fenced verb a daemon request performs, or None when the request is not
/// categorically human-only. Deliberately exhaustive: a new `Req` variant does not
/// compile until it is classified here.
///
/// Not categorical, so None: `ChangePolicy` and `ChangeConfig` (agents may tighten;
/// relaxation is the `PolicyRelax`/`ConfigRelax` lookup inside the operation),
/// `Unlock`/`Copy`/`Use` (policy-governed by `run_authorization`), the bound launch
/// requests, `Revoke`, `SsoForget` (only reduce authority) and read-only requests.
pub(crate) fn request_verb(req: &Req) -> Option<Verb> {
    match req {
        Req::ProfileTrust { .. } => Some(Verb::ProfileTrust),
        Req::ProfileRead { .. } => None,
        Req::SsoDiscover { .. } | Req::SsoImportPreview { .. } => Some(Verb::SsoDiscover),
        Req::SsoImport { .. } => Some(Verb::SsoImport),
        Req::Kill { revive, .. } => Some(if *revive { Verb::Revive } else { Verb::Kill }),
        Req::SourceAdd { .. } => Some(Verb::SourceAdd),
        Req::SourceRemove { .. } => Some(Verb::SourceRemove),
        Req::SourceRetarget { .. } => Some(Verb::SourceRetarget),
        Req::SourceList => Some(Verb::SourceList),
        Req::Resolve { .. } => None,
        Req::Init { .. } => Some(Verb::Init),
        Req::Add { .. } => Some(Verb::Add),
        Req::Delete { .. } => Some(Verb::Rm),
        Req::Rename { .. } => Some(Verb::Rename),
        Req::UpgradeKeys => Some(Verb::KeysUpgrade),
        Req::HelperPin { .. } => Some(Verb::HelperPin),
        Req::Recover { .. } | Req::RecoverFromPaper { .. } => Some(Verb::Recover),
        Req::RetireKeys | Req::RetireKeysWithPaper { .. } => Some(Verb::RetireKeys),
        Req::RotateBackup { .. } => Some(Verb::BackupRotate),
        Req::SsoPortalAdd { .. } => Some(Verb::SsoPortalAdd),
        Req::SsoPortalLimit { .. } | Req::SsoLimit { .. } => Some(Verb::SsoPortalLimit),
        Req::RefreshSsoRegistrations { .. } | Req::SsoRegister { .. } => Some(Verb::SsoRegister),
        Req::CompleteSsoLogin { .. } | Req::SsoSet { .. } => Some(Verb::SsoLogin),
        Req::SsoLogout { .. } => Some(Verb::SsoLogout),
        Req::RunUnredacted { .. } => Some(Verb::NoRedact),
        Req::Shutdown => Some(Verb::DaemonStop),
        Req::Grant { .. } | Req::GrantLease { .. } => Some(Verb::LeaseGrant),
        Req::HumanUnlock { .. } => Some(Verb::HumanUnlock),
        Req::Call { .. } | Req::Ping | Req::StatusSelftest | Req::PubKeys | Req::ChangePolicy { .. } | Req::ChangeConfig { .. }
        | Req::Unlock { .. } | Req::Copy { .. } | Req::Use { .. } | Req::LaunchPrepare { .. }
        | Req::LaunchCancel { .. } | Req::LaunchRedaction { .. } | Req::LaunchBind { .. }
        | Req::LaunchRedeem { .. } | Req::Revoke { .. } | Req::List | Req::AwsOpen { .. }
        | Req::AwsClose { .. } | Req::SsoForget { .. } | Req::SsoStatus | Req::SsoOpen { .. } => None,
    }
}

fn lookup(verb: Verb) -> Option<&'static Row> {
    AGENT_DENIED_VERBS.iter().find(|r| r.verb == verb)
}

/// Whether agents are denied `verb` at `layer`.
pub fn agent_denied(verb: Verb, layer: Layer) -> bool {
    lookup(verb).is_some_and(|r| match layer {
        Layer::Cli => r.cli,
        Layer::Daemon => r.daemon,
    })
}

/// The one refusal message.
pub fn refusal(what: &str, agent: &str) -> String {
    format!("{what} is human-only; refused because caller chain includes agent ({agent}). Use the karambit GUI or a plain terminal.")
}

/// The refusal for a caller that came in over SSH.
pub fn remote_refusal(what: &str) -> String {
    format!("{what} is human-only; refused because the caller arrived over SSH (sshd in the process chain or SSH_CONNECTION/SSH_TTY set). Use the karambit GUI or a terminal on this Mac, or a human can run `karambit config allow-ssh-human on` locally.")
}

/// Refuse `verb` when the caller chain includes an agent, or the caller is remote
/// (SSH) and `allow_ssh_human` is off, and the table fences it here.
pub fn require_human(caller: &Caller, verb: Verb, layer: Layer) -> Result<()> {
    if agent_denied(verb, layer)
        && let Some(r) = lookup(verb)
    {
        if let Some(agent) = &caller.agent {
            bail!("{}", refusal(r.what, agent));
        }
        if caller.remote && !caller.remote_allowed {
            bail!("{}", remote_refusal(r.what));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Caller {
        Caller { agent: Some("synthetic".into()), ..Default::default() }
    }

    #[test]
    fn table_has_one_row_per_verb_and_fences_at_least_one_layer() {
        for (i, a) in AGENT_DENIED_VERBS.iter().enumerate() {
            assert!(a.cli || a.daemon, "{:?} fenced nowhere", a.verb);
            assert!(!a.what.is_empty());
            for b in &AGENT_DENIED_VERBS[i + 1..] {
                assert_ne!(a.verb, b.verb, "duplicate row");
            }
        }
    }

    #[test]
    fn every_verb_has_exactly_one_row() {
        assert_eq!(Verb::ALL.len(), Verb::Revive as usize + 1, "Verb::ALL out of date");
        assert_eq!(AGENT_DENIED_VERBS.len(), Verb::ALL.len());
        for (i, verb) in Verb::ALL.iter().enumerate() {
            assert_eq!(*verb as usize, i, "Verb::ALL out of order");
            assert_eq!(AGENT_DENIED_VERBS.iter().filter(|r| r.verb == *verb).count(), 1, "{verb:?}");
        }
    }

    #[test]
    fn remote_caller_is_refused_every_fenced_verb_unless_allowed() {
        let remote = Caller { remote: true, ..Default::default() };
        let allowed = Caller { remote: true, remote_allowed: true, ..Default::default() };
        for r in AGENT_DENIED_VERBS {
            for layer in [Layer::Cli, Layer::Daemon] {
                let fenced = agent_denied(r.verb, layer);
                let result = require_human(&remote, r.verb, layer);
                assert_eq!(result.is_err(), fenced, "{:?} {layer:?}", r.verb);
                if let Err(e) = result {
                    assert_eq!(e.to_string(), remote_refusal(r.what));
                }
                require_human(&allowed, r.verb, layer).unwrap();
            }
        }
        // An agent that is also remote still gets the agent refusal.
        let both = Caller { agent: Some("synthetic".into()), remote: true, remote_allowed: true, ..Default::default() };
        assert_eq!(require_human(&both, Verb::Rm, Layer::Cli).unwrap_err().to_string(), refusal("removing a secret", "synthetic"));
    }

    #[test]
    fn refusal_message_is_byte_exact_and_human_callers_pass() {
        assert_eq!(
            refusal("recover", "pi"),
            "recover is human-only; refused because caller chain includes agent (pi). Use the karambit GUI or a plain terminal."
        );
        for r in AGENT_DENIED_VERBS {
            for layer in [Layer::Cli, Layer::Daemon] {
                require_human(&Caller::default(), r.verb, layer).unwrap();
                let fenced = agent_denied(r.verb, layer);
                let result = require_human(&agent(), r.verb, layer);
                assert_eq!(result.is_err(), fenced, "{:?} {layer:?}", r.verb);
                if let Err(e) = result {
                    assert_eq!(e.to_string(), refusal(r.what, "synthetic"));
                }
            }
        }
    }
}
