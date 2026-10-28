//! Turns an opaque refusal into a reason and a next step, for humans and agents.
//!
//! The daemon deliberately answers every failed launch with the same "launch refused"
//! (no oracle for the integrity checks: pins, process identity, races). This module runs
//! only in the CLI, *after* such a refusal, and reasons from metadata the caller can
//! already read without a prompt: `ls` (names + access level), `lease ls` and the config
//! (`killed`). It never decrypts, prompts, or asks the daemon anything new, so it adds no
//! information an agent couldn't get by running `karambit ls`. When nothing explains the
//! refusal it says so and keeps the generic reason.
//!
//! Every refusal also carries machine fields for agents: `retry` (may the same command
//! be tried again, and when), `actor` (who has to act), an optional narrowly scoped
//! `ask_user` command for the human, and `blockers` (every problem found, not only the
//! first). None of these grant anything; they only describe what the caller can see.

use karambit_core::daemon::LeaseView;
use karambit_core::{Caller, Config, SecretMeta, Tier};
use std::process::ExitCode;

/// Exit code for "karambit refused before your command ran" (126/127 belong to the shell).
pub const EXIT_REFUSED: u8 = 125;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// The secret name doesn't exist.
    NotFound,
    /// Only me · Touch ID (or legacy Only me): agents are refused.
    HumanOnly,
    /// Agents · Touch ID with no usable temporary access.
    NeedsLease,
    /// A temporary access exists but is for someone else, a different folder or program, or used up.
    LeaseMismatch,
    /// `karambit kill` stopped this agent, session or all agents.
    Killed,
    /// A rule in config.json policy denies this (see `karambit policy show`).
    PolicyDenied,
    /// AWS SSO profile whose portal isn't signed in (no lease can help).
    SsoSignedOut,
    /// This karambit binary isn't the one the vault trusts (rebuilt, not reinstalled).
    NotPinned,
    /// No reason found in metadata (integrity check, race, policy rule, daemon state).
    Refused,
    /// Bad command line: unknown flag, missing command, bad `-e` spec.
    Usage,
    /// `run --aws` / `aws PROFILE`: no such saved profile.
    NoProfile,
    /// `.karambit.env` / `.env.schema` could not be read or parsed.
    BadEnvFile,
    /// The profile file is not trusted (new or edited): agents are refused it.
    ProfileUntrusted,
    /// The karambit daemon could not be reached or started.
    DaemonUnavailable,
    /// Something else failed before the command started (e.g. the program was not found).
    LaunchFailed,
}

/// May the same command be tried again?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Not as is: something has to change first (name, flags, access).
    No,
    /// One more time is reasonable (transient state).
    Once,
    /// After the user has done what `next` / `ask_user` says.
    AfterUser,
}

/// Who has to act on the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor { Agent, User }

/// One problem found in metadata (a refusal can have several).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker { pub code: Code, pub secrets: Vec<String> }

#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: Code,
    /// Which secrets this refusal is about (never values).
    pub secrets: Vec<String>,
    pub message: String,
    /// What to do next, phrased for whoever is reading (agent or human).
    pub next: String,
    pub retry: Retry,
    pub actor: Actor,
    /// A command for the human to review and run (never run by karambit), as argv.
    pub ask_user: Option<Vec<String>>,
    /// Every problem found, in priority order; `code` is the first one's. Empty when
    /// there is only the one reason.
    pub blockers: Vec<Blocker>,
}

impl Code {
    /// Every code, in the order `karambit help agent` lists them.
    pub const ALL: &'static [Code] = &[
        Code::NotFound, Code::HumanOnly, Code::NeedsLease, Code::LeaseMismatch, Code::SsoSignedOut,
        Code::PolicyDenied, Code::Killed, Code::NotPinned, Code::ProfileUntrusted, Code::NoProfile,
        Code::BadEnvFile, Code::Usage, Code::DaemonUnavailable, Code::LaunchFailed, Code::Refused,
    ];

    /// One-line meaning and what to do, for `karambit help agent`.
    pub fn help(self) -> (&'static str, &'static str) {
        match self {
            Code::NotFound => ("no secret with that name", "check `karambit ls`; ask the user to add it"),
            Code::HumanOnly => ("Only me · Touch ID, or a human-only command", "ask the user to run it"),
            Code::NeedsLease => ("Agents · Touch ID, no temporary access", "ask the user to run `ask_user`"),
            Code::LeaseMismatch => ("temporary access exists but not for this agent, folder or program, or used up", "ask the user to run `ask_user`"),
            Code::SsoSignedOut => ("AWS SSO portal signed out", "ask the user to sign in; not a lease problem"),
            Code::PolicyDenied => ("a policy rule denies it", "tell the user; only they change rules"),
            Code::Killed => ("the user blocked agents", "stop and tell the user"),
            Code::NotPinned => ("this karambit binary isn't the installed one", "use `karambit` from PATH"),
            Code::ProfileUntrusted => ("the .karambit.env/.env.schema is new or edited", "ask the user to review it and run `ask_user`"),
            Code::NoProfile => ("no such AWS profile", "check `karambit aws ls`"),
            Code::BadEnvFile => ("the env file can't be read or parsed", "fix the file; see the message"),
            Code::Usage => ("bad command line", "fix the command; see `karambit run --help`"),
            Code::DaemonUnavailable => ("karambit daemon unreachable", "retry once, then tell the user"),
            Code::LaunchFailed => ("failed before the command started", "read the message; don't loop"),
            Code::Refused => ("other refusal (integrity check, daemon state)", "check `karambit status`; tell the user"),
        }
    }

    /// Default retry/actor for a code; a refusal may refine them.
    fn defaults(self) -> (Retry, Actor) {
        match self {
            Code::NotFound | Code::NoProfile | Code::BadEnvFile | Code::Usage | Code::LaunchFailed => (Retry::No, Actor::Agent),
            Code::NeedsLease | Code::LeaseMismatch | Code::SsoSignedOut | Code::ProfileUntrusted => (Retry::AfterUser, Actor::User),
            Code::HumanOnly | Code::PolicyDenied | Code::Killed | Code::NotPinned | Code::Refused => (Retry::No, Actor::User),
            Code::DaemonUnavailable => (Retry::Once, Actor::Agent),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Code::NotFound => "not_found",
            Code::HumanOnly => "human_only",
            Code::NeedsLease => "needs_lease",
            Code::LeaseMismatch => "lease_mismatch",
            Code::Killed => "killed",
            Code::PolicyDenied => "policy_denied",
            Code::NotPinned => "not_pinned",
            Code::SsoSignedOut => "sso_signed_out",
            Code::Refused => "refused",
            Code::Usage => "usage",
            Code::NoProfile => "no_profile",
            Code::BadEnvFile => "bad_env_file",
            Code::ProfileUntrusted => "profile_untrusted",
            Code::DaemonUnavailable => "daemon_unavailable",
            Code::LaunchFailed => "launch_failed",
        }
    }
}

impl Retry {
    pub fn as_str(self) -> &'static str {
        match self { Retry::No => "no", Retry::Once => "once", Retry::AfterUser => "after_user" }
    }
}

impl Actor {
    pub fn as_str(self) -> &'static str {
        match self { Actor::Agent => "agent", Actor::User => "user" }
    }
}

/// POSIX shell quoting for a command the human will paste: plain words stay bare,
/// everything else is single-quoted.
pub fn shell_quote(argv: &[String]) -> String {
    argv.iter().map(|a| {
        if !a.is_empty() && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&b)) {
            a.clone()
        } else {
            format!("'{}'", a.replace('\'', "'\\''"))
        }
    }).collect::<Vec<_>>().join(" ")
}

impl Refusal {
    pub fn new(code: Code, secrets: Vec<String>, message: impl Into<String>, next: impl Into<String>) -> Refusal {
        let (retry, actor) = code.defaults();
        Refusal { code, secrets, message: message.into(), next: next.into(), retry, actor, ask_user: None, blockers: vec![] }
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({"v": 1, "code": self.code.as_str(), "secrets": self.secrets, "message": self.message,
            "next": self.next, "retry": self.retry.as_str(), "actor": self.actor.as_str()});
        if let Some(argv) = &self.ask_user {
            v["ask_user"] = serde_json::json!({"argv": argv, "shell": shell_quote(argv)});
        }
        if !self.blockers.is_empty() {
            v["blockers"] = self.blockers.iter().map(|b| serde_json::json!({"code": b.code.as_str(), "secrets": b.secrets})).collect();
        }
        v
    }

    pub fn print(&self, json: bool) -> ExitCode {
        if json {
            // Errors go to stderr in both modes; stdout stays the command's own output.
            eprintln!("{}", serde_json::json!({"error": self.to_json()}));
        } else {
            eprintln!("karambit: {}\n  next: {}", self.message, self.next);
        }
        ExitCode::from(EXIT_REFUSED)
    }
}

/// Access level of a secret in GUI words: public | agents | agents-touch | me-touch | me.
pub fn level(tier: Tier, agent_allowed: bool, public: bool) -> &'static str {
    match (public, tier, agent_allowed) {
        (true, _, _) => "public",
        (false, Tier::Open, true) => "agents",
        (false, Tier::Bio, true) => "agents-touch",
        (false, Tier::Bio, false) => "me-touch",
        (false, Tier::Open, false) => "me",
    }
}

/// Human label for a level id, matching the GUI.
pub fn level_label(id: &str) -> &'static str {
    match id {
        "public" => "Public",
        "agents" => "Agents · no prompt",
        "agents-touch" => "Agents · Touch ID",
        "me-touch" => "Only me · Touch ID",
        "me" => "Only me (retired)",
        _ => "?",
    }
}

/// Could this lease cover `caller` running `program` (canonical path, when known) in `cwd`?
/// Mirrors the daemon's scope checks on metadata only; the daemon still decides
/// (session ancestry, the program's SHA-256, races).
fn lease_fits(lease: &LeaseView, caller: &Caller, cwd: &str, program: Option<&str>, script: Option<&str>) -> bool {
    use karambit_core::lease::{CommandBinding, Grantee};
    let who = match &lease.info.to {
        Grantee::Any => true,
        Grantee::Kind(k) => caller.kind.as_deref() == Some(k.as_str()),
        // Session ancestry is kernel-checked by the daemon; assume it may fit.
        Grantee::Session(_) => true,
        Grantee::Human => false,
    };
    let used_up = lease.scope.max_uses.is_some_and(|m| lease.uses >= m);
    // Same rule as the daemon's `under`.
    let folder = lease.scope.cwd.as_ref().is_none_or(|root| cwd == root || cwd.starts_with(&format!("{root}/")));
    // Program scope: the daemon refuses legacy name-only bindings and compares the
    // canonical path + hash; here only the path. Unknown program: assume it may fit.
    let cmd = lease.scope.cmds.is_empty() || program.is_none_or(|p| lease.scope.cmds.iter().any(|b| match b {
        // A bare interpreter pin is refused by the daemon; a script pair also needs the
        // right script, which only the daemon sees.
        CommandBinding::Pinned { path, .. } => path == p && !karambit_core::lease::is_interpreter_name(path),
        CommandBinding::Script { path, script: held, .. } => path == p && script.is_none_or(|s| s == held),
        CommandBinding::Name(_) => false,
    }));
    who && !used_up && folder && cmd && lease.info.remaining > 0
}

/// AWS SSO state from `sso status` (no prompt): profiles live in a signed-in portal,
/// and the portals that are signed out.
#[derive(Default)]
pub struct Sso { pub active: Vec<String>, pub signed_out: Vec<String> }

/// Why would `caller` be refused `refs` (vault names, as given to `run`)? None when the
/// metadata shows nothing wrong (the refusal came from somewhere this can't see).
#[cfg(test)]
#[allow(clippy::too_many_arguments)] // tests only; a context struct would only rename the inputs
pub fn explain(caller: &Caller, cfg: &Config, items: &[SecretMeta], leases: &[LeaseView], refs: &[String], cwd: &str, pinned: bool, sso: &Sso) -> Refusal {
    explain_for(caller, cfg, items, leases, refs, cwd, pinned, sso, None, None)
}

/// As [`explain`], knowing the canonical path of the program `run` was asked to start
/// and, for an interpreter, its canonical script (argv[1]); used for lease program
/// scopes and the suggested grant.
#[allow(clippy::too_many_arguments)]
pub fn explain_for(caller: &Caller, cfg: &Config, items: &[SecretMeta], leases: &[LeaseView], refs: &[String], cwd: &str, pinned: bool, sso: &Sso, program: Option<&str>, script: Option<&str>) -> Refusal {
    if !pinned {
        return Refusal::new(Code::NotPinned, vec![],
            "this karambit binary isn't the trusted one (rebuilt but not installed?)",
            "use the installed `karambit` on PATH, or ask the user to run ./install.sh in a plain terminal");
    }
    let agent = caller.agent.as_deref().map(|_| caller.label());
    if let (Some(who), Some(k)) = (&agent, cfg.killed.as_ref()) && k.matches(caller) {
        return Refusal::new(Code::Killed, vec![],
            format!("agents are blocked ({who}): the user ran Block agents"),
            "don't retry; tell the user. Only they can unblock (Karambit app, or `karambit unblock` in a plain terminal)");
    }
    // Collect every problem the metadata shows, each secret under its first reason.
    // The first problem is the refusal's code/message/next; the rest go in `blockers`.
    let mut found: Vec<Refusal> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let take = |list: Vec<String>, seen: &mut Vec<String>| -> Vec<String> {
        let out: Vec<String> = list.into_iter().filter(|n| !seen.contains(n)).collect();
        seen.extend(out.iter().cloned());
        out
    };
    // Linked-source refs (source:native) and AWS profiles are explained elsewhere.
    let names: Vec<&String> = refs.iter().filter(|r| !r.contains(':')).collect();
    let missing = take(names.iter().filter(|n| !items.iter().any(|m| m.name == ***n)).map(|n| n.to_string()).collect(), &mut seen);
    if !missing.is_empty() {
        let hint = missing.iter().filter_map(|n| n.split_once('/').map(|(ns, _)| format!("karambit ls '{ns}/*'"))).next()
            .unwrap_or_else(|| "karambit ls".into());
        found.push(Refusal::new(Code::NotFound, missing.clone(),
            format!("no secret named {}", quote_list(&missing)),
            format!("check the name with `{hint}`; agents can't add secrets, so ask the user to add it if it's missing")));
    }
    // An SSO profile needs its portal signed in, whatever its access level. Static-key
    // profiles never appear in `active`, so only claim this while some portal is signed out.
    if !sso.signed_out.is_empty() {
        let aws_inactive = take(names.iter().filter(|n| n.starts_with("aws/") && !sso.active.contains(n)).map(|n| n.to_string()).collect(), &mut seen);
        if !aws_inactive.is_empty() {
            let portals = sso.signed_out.join(", ");
            let login = if sso.signed_out.len() == 1 { format!("karambit login {portals}") } else { "karambit login PORTAL".into() };
            let mut r = Refusal::new(Code::SsoSignedOut, aws_inactive.clone(),
                format!("{} isn't active: AWS SSO portal signed out ({portals})", quote_list(&aws_inactive)),
                format!("this is not an access/lease problem; ask the user to sign in (Karambit app → AWS, or `{login}` in a plain terminal), then retry"));
            if sso.signed_out.len() == 1 { r.ask_user = Some(vec!["karambit".into(), "login".into(), sso.signed_out[0].clone()]); }
            found.push(r);
        }
    }
    if let Some(policy) = &cfg.policy {
        use karambit_core::policy::{Action, Effect, Subject, evaluate};
        let denied = take(names.iter()
            .filter(|n| evaluate(policy, caller, Action::Run, &Subject::Secret(n.to_string())).effect == Effect::Deny)
            .map(|n| n.to_string()).collect(), &mut seen);
        if !denied.is_empty() {
            found.push(Refusal::new(Code::PolicyDenied, denied.clone(),
                format!("a policy rule denies running with {}", quote_list(&denied)),
                "see `karambit policy show` and `karambit policy explain run NAME`; only the user can change rules"));
        }
    }
    if agent.is_some() {
        let mut human = Vec::new();
        let mut needs = Vec::new();
        let mut mismatch = Vec::new();
        for n in &names {
            let Some(m) = items.iter().find(|m| &&m.name == n) else { continue };
            match level(m.tier, m.agent_allowed, m.public) {
                "me-touch" | "me" => human.push(m.name.clone()),
                "agents-touch" => {
                    let held: Vec<&LeaseView> = leases.iter().filter(|l| l.info.name == m.name).collect();
                    if held.is_empty() { needs.push(m.name.clone()); }
                    else if !held.iter().any(|l| lease_fits(l, caller, cwd, program, script)) { mismatch.push(m.name.clone()); }
                }
                _ => {}
            }
        }
        let human = take(human, &mut seen);
        if !human.is_empty() {
            found.push(Refusal::new(Code::HumanOnly, human.clone(),
                format!("{} {} Only me · Touch ID: agents are refused", quote_list(&human), if human.len() == 1 { "is" } else { "are" }),
                "don't retry; ask the user to run the command themselves, or to change its access in the Karambit app if agents should use it"));
        }
        let needs = take(needs, &mut seen);
        if !needs.is_empty() {
            let grant = grant_argv(&needs, caller, cwd, program, script);
            let how = match &grant {
                Some(argv) => format!("Karambit app → secret → Temporary access, or in a plain terminal: `{}`", shell_quote(argv)),
                None => "Karambit app → secret → Temporary access".into(),
            };
            let mut r = Refusal::new(Code::NeedsLease, needs.clone(),
                format!("{} {} Agents · Touch ID and you have no temporary access", quote_list(&needs), if needs.len() == 1 { "is" } else { "are" }),
                format!("ask the user to grant it ({how}), then retry"));
            r.ask_user = grant;
            found.push(r);
        }
        let mismatch = take(mismatch, &mut seen);
        if !mismatch.is_empty() {
            let mut r = Refusal::new(Code::LeaseMismatch, mismatch.clone(),
                format!("temporary access to {} doesn't cover this run (other agent, folder or program, or uses ran out)", quote_list(&mismatch)),
                "run `karambit lease ls` to see its limits; ask the user for a new grant if needed");
            r.ask_user = grant_argv(&mismatch, caller, cwd, program, script);
            found.push(r);
        }
    }
    if !found.is_empty() {
        let mut first = found.remove(0);
        if !found.is_empty() {
            first.blockers = std::iter::once(Blocker { code: first.code, secrets: first.secrets.clone() })
                .chain(found.into_iter().map(|r| Blocker { code: r.code, secrets: r.secrets })).collect();
            // Anything that needs the user makes the whole run wait for the user.
            if first.blockers.iter().any(|b| b.code.defaults().1 == Actor::User) { first.actor = Actor::User; }
        }
        return first;
    }
    if agent.is_none() {
        return generic(refs);
    }
    // Everything requested is usable without asking, yet it was refused: say so, so agents
    // don't ask for temporary access they don't need.
    let free: Vec<String> = refs.iter().filter(|n| items.iter().any(|m| &m.name == *n
        && matches!(level(m.tier, m.agent_allowed, m.public), "agents" | "public"))).cloned().collect();
    let mut r = generic(refs);
    if !free.is_empty() && free.len() == refs.len() {
        r.next = format!("{} {} no-prompt, so temporary access won't help; retry once, then check `karambit status` and tell the user it was refused",
            quote_list(&free), if free.len() == 1 { "is" } else { "are" });
        r.retry = Retry::Once;
    }
    r
}

/// The narrowest grant the human could approve for this run: this agent (kind, else
/// its kernel session), this folder, this program, one hour. None when the caller has
/// neither kind nor session: never suggest `--to any`.
fn grant_argv(names: &[String], caller: &Caller, cwd: &str, program: Option<&str>, script: Option<&str>) -> Option<Vec<String>> {
    let to = caller.kind.clone().or_else(|| caller.session.clone())?;
    let mut argv: Vec<String> = ["karambit", "lease", "grant"].iter().map(|s| s.to_string()).collect();
    argv.extend(names.iter().cloned());
    argv.extend(["--to".into(), to, "--hours".into(), "1".into()]);
    if !cwd.is_empty() { argv.extend(["--cwd".into(), cwd.into()]); }
    // Shells and wrappers can't be lease programs (they would run anything). Neither can a
    // bare interpreter (`node -e`): it is only suggested together with the script it runs.
    if let Some(p) = program && !std::path::Path::new(p).file_name().and_then(|f| f.to_str()).is_some_and(|f| karambit_core::daemon::SHELLS.contains(&f)) {
        if !karambit_core::lease::is_interpreter_name(p) {
            argv.extend(["--cmd".into(), p.into()]);
        } else if let Some(s) = script {
            argv.extend(["--cmd".into(), p.into(), "--script".into(), s.into()]);
        }
    }
    Some(argv)
}

fn generic(refs: &[String]) -> Refusal {
    Refusal::new(Code::Refused, vec![],
        // "bound launch failed" is kept verbatim: scripts and tests match on it.
        if refs.is_empty() { "bound launch failed: launch refused".into() } else { format!("bound launch failed: launch refused for {}", quote_list(refs)) },
        "don't loop on retries; check `karambit status` and `karambit audit -n 5`, or tell the user")
}

/// Carried through anyhow so `main` can print it with its code and exit 125.
#[derive(Debug)]
pub struct Refused(pub Refusal);
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.message)
    }
}
impl std::error::Error for Refused {}

fn quote_list(names: &[String]) -> String {
    names.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, tier: Tier, agent: bool, public: bool) -> SecretMeta {
        SecretMeta { name: name.into(), tier, agent_allowed: agent, public, has_backup: true, created: 0, updated: 0, lease: None }
    }
    fn agent(kind: &str) -> Caller {
        Caller { agent: Some(format!("env:{kind}")), kind: Some(kind.into()), ..Default::default() }
    }
    fn lease(name: &str, to: karambit_core::lease::Grantee, cwd: Option<&str>, max: Option<u32>, uses: u32) -> LeaseView {
        serde_json::from_value(serde_json::json!({
            "name": name, "to": to, "to_label": "x", "granted": 0, "expires": u64::MAX, "remaining": 3600, "by": "test",
            "scope": {"cwd": cwd, "max_uses": max}, "uses": uses,
        })).unwrap()
    }
    fn vault() -> Vec<SecretMeta> {
        vec![
            meta("a/open", Tier::Open, true, false),
            meta("a/pub", Tier::Open, true, true),
            meta("a/touch", Tier::Bio, true, false),
            meta("a/me", Tier::Bio, false, false),
        ]
    }
    fn why(caller: &Caller, leases: &[LeaseView], refs: &[&str]) -> Code {
        let refs: Vec<String> = refs.iter().map(|s| s.to_string()).collect();
        explain(caller, &Config::default(), &vault(), leases, &refs, "/work/repo", true, &Sso::default()).code
    }

    #[test]
    fn levels_match_gui_ids() {
        assert_eq!(level(Tier::Open, true, true), "public");
        assert_eq!(level(Tier::Open, true, false), "agents");
        assert_eq!(level(Tier::Bio, true, false), "agents-touch");
        assert_eq!(level(Tier::Bio, false, false), "me-touch");
        assert_eq!(level(Tier::Open, false, false), "me");
    }

    #[test]
    fn missing_beats_everything_but_kill() {
        assert_eq!(why(&agent("pi"), &[], &["a/me", "nope/x"]), Code::NotFound);
        assert_eq!(why(&Caller::default(), &[], &["nope/x"]), Code::NotFound);
        let cfg = Config { killed: Some(karambit_core::policy::Killed { all: true, ..Default::default() }), ..Default::default() };
        let r = explain(&agent("pi"), &cfg, &vault(), &[], &["nope/x".into()], "/", true, &Sso::default());
        assert_eq!(r.code, Code::Killed);
        // Kill never applies to humans.
        assert_eq!(explain(&Caller::default(), &cfg, &vault(), &[], &["nope/x".into()], "/", true, &Sso::default()).code, Code::NotFound);
    }

    #[test]
    fn agent_levels() {
        let pi = agent("pi");
        assert_eq!(why(&pi, &[], &["a/me"]), Code::HumanOnly);
        assert_eq!(why(&pi, &[], &["a/touch"]), Code::NeedsLease);
        // Open levels have nothing to explain: the refusal came from elsewhere,
        // and the next step says a lease won't help.
        assert_eq!(why(&pi, &[], &["a/open", "a/pub"]), Code::Refused);
        let r = explain(&pi, &Config::default(), &vault(), &[], &["a/open".into()], "/", true, &Sso::default());
        assert!(r.next.contains("temporary access won't help"), "{}", r.next);
        // Human-only wins over needs-lease when both are present.
        assert_eq!(why(&pi, &[], &["a/touch", "a/me"]), Code::HumanOnly);
    }

    #[test]
    fn policy_rule_deny() {
        let cfg = Config { policy: Some(serde_json::from_value(serde_json::json!({"rules": [
            {"subject": {"secret": "a/*"}, "action": "run", "who": "agent", "effect": "deny"}]})).unwrap()), ..Default::default() };
        let r = explain(&agent("pi"), &cfg, &vault(), &[], &["a/open".into()], "/", true, &Sso::default());
        assert_eq!(r.code, Code::PolicyDenied);
        assert_eq!(explain(&Caller::default(), &cfg, &vault(), &[], &["a/open".into()], "/", true, &Sso::default()).code, Code::Refused);
    }

    #[test]
    fn leases() {
        use karambit_core::lease::Grantee;
        let pi = agent("pi");
        let fits = lease("a/touch", Grantee::Any, None, None, 0);
        assert_eq!(why(&pi, &[fits], &["a/touch"]), Code::Refused);
        assert_eq!(why(&pi, &[lease("a/touch", Grantee::Kind("claude".into()), None, None, 0)], &["a/touch"]), Code::LeaseMismatch);
        assert_eq!(why(&pi, &[lease("a/touch", Grantee::Any, Some("/elsewhere"), None, 0)], &["a/touch"]), Code::LeaseMismatch);
        assert_eq!(why(&pi, &[lease("a/touch", Grantee::Any, Some("/work"), None, 0)], &["a/touch"]), Code::Refused);
        assert_eq!(why(&pi, &[lease("a/touch", Grantee::Any, Some("/wor"), None, 0)], &["a/touch"]), Code::LeaseMismatch);
        assert_eq!(why(&pi, &[lease("a/touch", Grantee::Any, None, Some(2), 2)], &["a/touch"]), Code::LeaseMismatch);
    }

    #[test]
    fn humans_get_generic_for_existing_secrets() {
        // A human is never refused for access level here (Touch ID decides), so no guess.
        assert_eq!(why(&Caller::default(), &[], &["a/me", "a/touch"]), Code::Refused);
    }

    #[test]
    fn sso_signed_out_explains_no_prompt_aws() {
        let mut items = vault();
        items.push(meta("aws/prod", Tier::Open, true, false));
        let out = Sso { active: vec![], signed_out: vec!["main".into()] };
        let r = explain(&agent("pi"), &Config::default(), &items, &[], &["aws/prod".into()], "/", true, &out);
        assert_eq!(r.code, Code::SsoSignedOut);
        assert!(r.next.contains("karambit login main") && r.next.contains("not an access/lease problem"));
        // Signed in (profile active), or nothing signed out: not the reason.
        let on = Sso { active: vec!["aws/prod".into()], signed_out: vec!["main".into()] };
        assert_eq!(explain(&agent("pi"), &Config::default(), &items, &[], &["aws/prod".into()], "/", true, &on).code, Code::Refused);
        assert_eq!(explain(&agent("pi"), &Config::default(), &items, &[], &["aws/prod".into()], "/", true, &Sso::default()).code, Code::Refused);
    }

    #[test]
    fn unpinned_binary_first() {
        assert_eq!(explain(&agent("pi"), &Config::default(), &vault(), &[], &["nope/x".into()], "/", false, &Sso::default()).code, Code::NotPinned);
    }

    fn pinned_lease(name: &str, path: &str) -> LeaseView {
        let mut l = lease(name, karambit_core::lease::Grantee::Any, None, None, 0);
        l.scope.cmds = vec![karambit_core::lease::CommandBinding::Pinned { path: path.into(), sha256: "00".into() }];
        l
    }

    #[test]
    fn lease_program_scope_is_checked() {
        let pi = agent("pi");
        let refs = vec!["a/touch".to_string()];
        let run = |program: Option<&str>, l: LeaseView| explain_for(&pi, &Config::default(), &vault(), &[l], &refs, "/w", true, &Sso::default(), program, None).code;
        assert_eq!(run(Some("/usr/bin/curl"), pinned_lease("a/touch", "/usr/bin/curl")), Code::Refused, "same program fits");
        assert_eq!(run(Some("/usr/bin/git"), pinned_lease("a/touch", "/usr/bin/curl")), Code::LeaseMismatch);
        assert_eq!(run(None, pinned_lease("a/touch", "/usr/bin/curl")), Code::Refused, "unknown program: assume it may fit");
        let mut legacy = lease("a/touch", karambit_core::lease::Grantee::Any, None, None, 0);
        legacy.scope.cmds = vec!["curl".into()];
        assert_eq!(run(Some("/usr/bin/curl"), legacy), Code::LeaseMismatch, "daemon refuses legacy name scopes");
    }

    #[test]
    fn lease_script_pair_fits_only_its_script() {
        let pi = agent("pi");
        let refs = vec!["a/touch".to_string()];
        let mut held = lease("a/touch", karambit_core::lease::Grantee::Any, None, None, 0);
        held.scope.cmds = vec![karambit_core::lease::CommandBinding::Script {
            path: "/usr/bin/node".into(), sha256: "00".into(), script: "/w/build.js".into(), script_sha256: "11".into() }];
        let run = |script: Option<&str>| explain_for(&pi, &Config::default(), &vault(), std::slice::from_ref(&held), &refs, "/w", true, &Sso::default(), Some("/usr/bin/node"), script).code;
        assert_eq!(run(Some("/w/build.js")), Code::Refused, "same interpreter and script fits");
        assert_eq!(run(Some("/w/other.js")), Code::LeaseMismatch);
        // A bare interpreter pin (old lease) never fits an interpreter run.
        let mut bare = held.clone();
        bare.scope.cmds = vec![karambit_core::lease::CommandBinding::Pinned { path: "/usr/bin/node".into(), sha256: "00".into() }];
        assert_eq!(explain_for(&pi, &Config::default(), &vault(), &[bare], &refs, "/w", true, &Sso::default(), Some("/usr/bin/node"), Some("/w/build.js")).code, Code::LeaseMismatch);
    }

    #[test]
    fn every_blocker_is_reported_once() {
        let refs: Vec<String> = ["nope/x", "a/me", "a/touch", "a/open"].iter().map(|s| s.to_string()).collect();
        let r = explain(&agent("pi"), &Config::default(), &vault(), &[], &refs, "/w", true, &Sso::default());
        assert_eq!(r.code, Code::NotFound);
        let codes: Vec<(&str, Vec<String>)> = r.blockers.iter().map(|b| (b.code.as_str(), b.secrets.clone())).collect();
        assert_eq!(codes, vec![("not_found", vec!["nope/x".into()]), ("human_only", vec!["a/me".into()]), ("needs_lease", vec!["a/touch".into()])]);
        assert_eq!(r.actor, Actor::User);
        let v = r.to_json();
        assert_eq!(v["blockers"].as_array().unwrap().len(), 3);
        assert_eq!(v["retry"], "no");
        // One reason only: no blockers list.
        let one = explain(&agent("pi"), &Config::default(), &vault(), &[], &["a/me".into()], "/w", true, &Sso::default());
        assert!(one.blockers.is_empty() && one.to_json().get("blockers").is_none());
    }

    #[test]
    fn suggested_grant_is_narrow_and_quoted() {
        let refs = vec!["a/touch".to_string()];
        let r = explain_for(&agent("pi"), &Config::default(), &vault(), &[], &refs, "/w/my repo", true, &Sso::default(), Some("/usr/bin/curl"), None);
        assert_eq!(r.ask_user.as_deref().unwrap(), ["karambit", "lease", "grant", "a/touch", "--to", "pi", "--hours", "1", "--cwd", "/w/my repo", "--cmd", "/usr/bin/curl"]);
        assert_eq!(r.to_json()["ask_user"]["shell"], "karambit lease grant a/touch --to pi --hours 1 --cwd '/w/my repo' --cmd /usr/bin/curl");
        assert_eq!((r.retry, r.actor), (Retry::AfterUser, Actor::User));
        // A shell can't be a lease program: no --cmd.
        let sh = explain_for(&agent("pi"), &Config::default(), &vault(), &[], &refs, "/w", true, &Sso::default(), Some("/bin/zsh"), None);
        assert!(!sh.ask_user.unwrap().contains(&"--cmd".to_string()));
        // Nor can an interpreter on its own: only with the script it was asked to run.
        let node = |script| explain_for(&agent("pi"), &Config::default(), &vault(), &[], &refs, "/w", true, &Sso::default(), Some("/opt/homebrew/bin/node"), script).ask_user.unwrap();
        assert!(!node(None).contains(&"--cmd".to_string()), "no bare interpreter --cmd");
        assert_eq!(node(Some("/w/build.js"))[10..], ["--cmd", "/opt/homebrew/bin/node", "--script", "/w/build.js"]);
        // An agent with no kind falls back to its kernel session; with neither, no command, never --to any.
        let session = Caller { agent: Some("x".into()), session: Some("pid:42@7".into()), ..Default::default() };
        let r = explain(&session, &Config::default(), &vault(), &[], &refs, "/w", true, &Sso::default());
        assert!(r.ask_user.unwrap().contains(&"pid:42@7".to_string()));
        let anon = Caller { agent: Some("x".into()), ..Default::default() };
        let r = explain(&anon, &Config::default(), &vault(), &[], &refs, "/w", true, &Sso::default());
        assert!(r.ask_user.is_none() && !r.next.contains("--to any"), "{}", r.next);
    }

    #[test]
    fn shell_quote_is_posix() {
        let q = |a: &[&str]| shell_quote(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(q(&["karambit", "lease", "grant", "a/b"]), "karambit lease grant a/b");
        assert_eq!(q(&["dev/*", "it's", "", "$HOME", "a;b"]), r"'dev/*' 'it'\''s' '' '$HOME' 'a;b'");
    }

    #[test]
    fn every_code_has_help_and_a_unique_id() {
        for (i, c) in Code::ALL.iter().enumerate() {
            assert!(!c.help().0.is_empty() && !c.help().1.is_empty());
            assert!(Code::ALL[i + 1..].iter().all(|d| d.as_str() != c.as_str()));
        }
        // Retry/actor: user actions wait for the user; integrity refusals are not retried.
        assert_eq!(Code::NeedsLease.defaults(), (Retry::AfterUser, Actor::User));
        assert_eq!(Code::Refused.defaults().0, Retry::No);
        assert_eq!(Code::DaemonUnavailable.defaults().0, Retry::Once);
    }

    #[test]
    fn json_shape_is_stable() {
        let r = explain(&agent("pi"), &Config::default(), &vault(), &[], &["a/touch".into()], "/", true, &Sso::default());
        let v = r.to_json();
        assert_eq!(v["code"], "needs_lease");
        assert_eq!(v["secrets"], serde_json::json!(["a/touch"]));
        assert!(v["next"].as_str().unwrap().contains("karambit lease grant a/touch --to pi"));
        assert_eq!(v["v"], 1);
        assert_eq!(v["actor"], "user");
        assert_eq!(v["ask_user"]["argv"][0], "karambit");
    }
}
