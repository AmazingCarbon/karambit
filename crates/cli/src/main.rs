//! `karambit` CLI. Agent-safe by design: commands an agent needs (`ls`, `run`) never
//! print values; `get` is human-only and prefers the clipboard.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, ExitCode, Stdio};
use karambit_core::fence::{Layer, Verb};
use karambit_core::{Tier, Karambit, default_var, valid_var};
use zeroize::Zeroizing;

mod doctor;
mod explain;
mod secure;
mod source;
mod status;

#[derive(Subcommand)]
enum AgentsCmd { Discover }

#[derive(Parser)]
#[command(name = "karambit", version, about = "Local-first secrets vault (Secure Enclave + Touch ID)",
    help_template = r#"{about-with-newline}
{usage-heading} {usage}

Agents can use: run, ls, aws PROFILE, call, status, lease ls, env check, ref check,
secure --dry-run, doctor. Agent guide: `karambit help agent`.

Everyday:
  run       Run with injected secrets and redacted output
  ls        List secret names and access (no values)
  secure    Move a project's .env into the vault (alias: eat)
  add       Add or overwrite a secret (human-only)
  get       Copy a secret (human-only)
  rm        Delete secrets (human-only)
  policy    Change a secret's access level (relaxing is human-only)
  lease     Grant (human-only), list or revoke temporary agent access
  block     Block agents now: all agent requests refused (human-only)
  unblock   Unblock agents (human-only)
  status    Show vault, helper and caller status
  call      Call a fixed tool; the credential stays in karambit

AWS:
  aws       Run with a profile, or manage profiles
  login     Sign in to an SSO portal (human-only)
  logout    Sign out of one portal, or all (human-only)
  whoami    Check AWS identity (uses default-profile if omitted)
  sso       Manage portals and inspect sign-in status

Projects:
  env       Check a value-free env schema offline
  profile   Trust a .karambit.env / .env.schema (human-only)
  ref       Inspect references offline
  source    Manage linked sources (human-only, beta)

Setup & recovery:
  init      Create keys and the vault directory (human-only)
  config    Show or change config, including default-profile
  agents    Discover installed agent harnesses
  helper    Trust or stage helper binaries (human-only)
  keys      Upgrade Secure Enclave keys (human-only)
  backup    Verify or rotate paper backups (human-only)
  recover   Recover using an offline backup identity (human-only)
  doctor    Probe agent reachability with a synthetic canary
  audit     Show events or verify the audit chain

Options:
{options}"#)]
struct Cli {
    /// Machine-readable output (also: KARAMBIT_FORMAT=json). Errors go to stderr as {"error":{...}}.
    #[arg(long, global = true)]
    json: bool,
    /// Indent JSON output (default: compact, or indented when stdout is a terminal).
    #[arg(long, global = true)]
    pretty: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct AgentTarget {
    /// One agent family, e.g. claude, pi, codex.
    #[arg(long)]
    agent: Option<String>,
    /// One running agent session (id from `karambit audit`).
    #[arg(long)]
    session: Option<String>,
    /// Every agent.
    #[arg(long)]
    all: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Block agents: refuse every agent request until `unblock` (human-only, Touch ID).
    #[command(name = "block", alias = "kill", long_about = "Block agents: from now on every agent request is refused, until `karambit unblock`. Human-only, one Touch ID; survives restarts.\nAlso ends all temporary access, cached AWS credentials and pending runs.\nIt does NOT stop running processes: an agent or command that already started keeps any secret it already has.\n\nExamples:\n  karambit block --all\n  karambit block --agent claude")]
    Kill(AgentTarget),
    /// Pin repository env profiles after fresh human Touch ID.
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Unblock agents blocked with `block`; ended temporary access stays ended (human-only).
    #[command(name = "unblock", alias = "revive")]
    Revive(AgentTarget),
    /// Call a fixed tool; the credential stays in karambit (e.g. CI build status).
    #[command(long_about = "Call a fixed tool configured in config.json `tools`. Karambit makes the one allowed request and returns the body; the credential never leaves the daemon.\n\nExamples:\n  karambit call --list\n  karambit call ci-status my-job")]
    Call {
        /// List configured tools and the arguments they take (no credentials).
        #[arg(long, conflicts_with_all = ["tool", "args"])]
        list: bool,
        /// Tool id from `call --list`.
        #[arg(required_unless_present = "list")]
        tool: Option<String>,
        /// Tool arguments (one job name).
        args: Vec<String>,
    },
    /// Sign in to an SSO portal (human-only).
    #[command(long_about = "Sign in to one portal (human only, one Touch ID): approve the code in your browser. That portal's SSO profiles work until its SSO session ends; other portals are unaffected. PORTAL is optional if you have only one.")]
    Login {
        portal: Option<String>,
        /// Don't open the browser automatically.
        #[arg(long)]
        no_browser: bool,
    },
    /// Sign out of one SSO portal, or all with --all.
    #[command(long_about = "Sign out of one portal, or all with --all (agents lose access immediately).")]
    Logout {
        portal: Option<String>,
        #[arg(long, conflicts_with = "portal")]
        all: bool,
    },
    /// Check AWS identity using a profile or the configured default.
    Whoami { profile: Option<String> },
    /// Manage SSO portals and inspect sign-in status.
    Sso { #[command(subcommand)] cmd: SsoCmd },
    #[command(name = "__aws-whoami", hide = true)]
    AwsWhoami { profile: String, context: String, fix: String },
    /// Move a project's .env files into the vault and leave a value-free .env.schema (human-only).
    #[command(alias = "eat", args_conflicts_with_subcommands = true,
        long_about = "Move a project's plaintext .env files into the vault.\n\nSecrets are stored one by one at the access you choose; the original files are archived whole (Only me + Touch ID) and then deleted. A value-free .env.schema (varlock @env-spec format) takes their place, and package.json dev/start/test/build scripts are prefixed with `karambit run --`, so `npm run dev` keeps working.\n\n`karambit secure rebuild` puts the original files back.\n\nExamples:\n  karambit secure --dry-run\n  karambit secure ~/code/myapp --access agents-touch\n  karambit eat .\n  karambit secure rebuild")]
    Secure(secure::SecureArgs),
    /// Manage backend source bindings (human-only). Beta: may change between versions.
    Source { #[command(subcommand)] cmd: source::SourceCmd },
    /// Discover installed agent harnesses without executing them.
    Agents { #[command(subcommand)] cmd: AgentsCmd },
    /// Inspect references offline.
    Ref { #[command(subcommand)] cmd: source::RefCmd },
    #[command(name = "__launch", hide = true)]
    Launch,
    /// Synthetic sibling the doctor starts to hold its canary; never touches the vault.
    #[command(name = "__doctor-hold", hide = true)]
    DoctorHold,
    /// Probe agent reachability with a synthetic canary.
    #[command(long_about = "Probe what this environment can reach, using a synthetic canary only (no vault secrets, no daemon start, no values printed). Results cover this run only. Exit 0 unless the doctor itself fails. Add --json for machine-readable output.")]
    Doctor {
        /// Check the agent environment (the only mode so far; the default).
        #[arg(long, default_value_t = true)]
        agent_env: bool,
    },
    /// Create Secure Enclave keys (bio + open) and the vault dir.
    Init {
        /// age recipient (age1...) for offline backup of every secret.
        #[arg(long)]
        backup_recipient: Option<String>,
        /// Generate an offline age identity, write it here, and use it as backup recipient.
        #[arg(long, conflicts_with_all = ["backup_recipient", "paper"])]
        gen_backup: Option<std::path::PathBuf>,
        /// Generate a backup key and show it ONCE on screen to write on paper. Never touches disk.
        #[arg(long, conflicts_with = "backup_recipient")]
        paper: bool,
    },
    /// Show vault, helper and caller status (no secrets).
    Status,
    /// Add or overwrite a secret from hidden input or stdin.
    #[command(long_about = "Add or overwrite a secret. Value is read from TTY (hidden) or stdin — never argv.")]
    #[command(long_about = "Add or overwrite a secret. The value is read from a hidden prompt or stdin, never from the command line.\n\nAccess levels (same as the app):\n  agents        Agents · no prompt: you and agents use it freely\n  agents-touch  Agents · Touch ID: each use needs Touch ID, or temporary access (`karambit lease grant`)\n  me-touch      Only me · Touch ID: agents are refused\n  public        Not a secret (email, URL, id): agents may read it, never redacted\n\nExamples:\n  karambit add stripe/live-key --access me-touch\n  echo \"$TOKEN\" | karambit add ci/token --access agents")]
    Add {
        /// Secret name, `namespace/name` (e.g. stripe/live-key).
        name: String,
        /// Access level: agents | agents-touch | me-touch | public (default: from config default-tier, agents allowed).
        #[arg(long, value_parser = parse_level, conflicts_with_all = ["touch", "human_only", "public"])]
        access: Option<Level>,
        #[arg(long, value_parser = parse_tier, hide = true)]
        touch: Option<Tier>,
        #[arg(long, hide = true)]
        human_only: bool,
        #[arg(long, hide = true)]
        public: bool,
        /// Overwrite an existing secret with the same name.
        #[arg(short, long)]
        force: bool,
    },
    /// List secret names + policy (no values, no prompt).
    #[command(name = "ls")]
    List {
        /// Glob filter, e.g. 'stripe/*' (quote it so the shell doesn't expand it).
        pattern: Option<String>,
        /// Short output for agents: `name<TAB>access[<TAB>lease <who> <left>]`; with --json, [{name,access}].
        #[arg(long)]
        brief: bool,
    },
    /// Run with injected secrets and redacted output.
    #[command(long_about = "Run a command with secrets injected into its environment; any secret value in its output is replaced by [REDACTED:name].\nThis is how agents use secrets: they never see the value.\n\nExamples:\n  karambit run -e STRIPE_KEY=stripe/live-key -- ./deploy.sh\n  karambit run -e stripe/live-key -- ./deploy.sh      # VAR becomes STRIPE_LIVE_KEY\n  karambit run -- npm test                           # uses ./.karambit.env\n\nIf karambit refuses or fails before the command starts, it exits 125 and says why and what to do next (--json for a machine-readable reason). Other exit codes are the command's own, but a command can also exit 125: use --status-fd when you must know which.")]
    Run {
        /// VAR=ns/name, or bare ns/name (VAR derived: ns/name -> NS_NAME). Repeatable.
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        /// Also inject a saved AWS profile (AWS_ACCESS_KEY_ID, ...).
        #[arg(long)]
        aws: Option<String>,
        /// Profile: VAR=ref lines, or a .env.schema (default ./.karambit.env, else ./.env.schema, when no -e given).
        #[arg(long)]
        env_file: Option<std::path::PathBuf>,
        /// Do not redact child stdout/stderr (child inherits the terminal directly).
        #[arg(long)]
        no_redact: bool,
        /// Experimental: run inside a macOS sandbox that blocks network and most files (fails closed).
        #[arg(long)]
        jail: bool,
        /// With --jail: allow TCP to this localhost host:port.
        #[arg(long, requires = "jail")]
        allow_host: Vec<String>,
        /// Write one JSON status line to this open file descriptor (3 or higher) when karambit
        /// is done: {"v":1,"started":true,"exit":N} or {"v":1,"started":false,"error":{...}}.
        /// The command never inherits it, so it can't fake the line.
        #[arg(long, value_name = "FD")]
        status_fd: Option<i32>,
        /// The command to run, after `--`.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Copy a secret; use --stdout to print (human-only).
    #[command(long_about = "Human-only: copy value to clipboard (auto-clears), or print with --stdout.")]
    Get {
        /// Secret name, e.g. stripe/live-key.
        name: String,
        /// Print the value instead of copying it (careful: shell history, scrollback).
        #[arg(long)]
        stdout: bool,
    },
    /// Show effective rules with `policy show`, or change secret access (glob ok: 'dev/*').
    #[command(long_about = "Change access for secrets (globs ok: 'dev/*'), or inspect rules with `policy show`.\nRelaxing access (fewer prompts, agents allowed, public) is human-only and needs Touch ID; tightening is always allowed.\n\nExamples:\n  karambit policy 'dev/*' --access agents\n  karambit policy stripe/live-key --access me-touch\n  karambit policy show")]
    Policy {
        #[command(subcommand)]
        cmd: Option<PolicyCmd>,
        /// Secret names or globs, e.g. 'dev/*'.
        patterns: Vec<String>,
        /// New access level: agents | agents-touch | me-touch | public.
        #[arg(long, value_parser = parse_level, conflicts_with_all = ["touch", "agent", "public"])]
        access: Option<Level>,
        /// Touch ID on|off (fine-grained; prefer --access).
        #[arg(long, value_parser = parse_tier)]
        touch: Option<Tier>,
        /// Agents allow|deny (fine-grained; prefer --access).
        #[arg(long, value_parser = parse_agent)]
        agent: Option<bool>,
        /// Public on|off (fine-grained; prefer --access). Turning on needs Touch ID.
        #[arg(long, value_parser = parse_onoff)]
        public: Option<bool>,
    },
    /// Check a value-free env schema offline, without Touch ID.
    Env {
        #[command(subcommand)]
        cmd: EnvCmd,
    },
    /// Rename a secret, or move a folder (both ending in /). Keeps value and access; asks for Touch ID.
    #[command(alias = "rename")]
    Mv {
        /// Current name, e.g. stripe/key, or a folder, e.g. stripe/.
        from: String,
        /// New name, e.g. payments/stripe-key, or a folder, e.g. payments/.
        to: String,
    },
    /// Delete secrets (glob ok).
    Rm {
        /// Secret names or globs, e.g. 'old/*'.
        patterns: Vec<String>,
    },
    /// Show config or set a key, including default-profile.
    #[command(long_about = "Show config or set KEY VALUE. Keys include default-profile, default-tier, clip-seconds, backup-recipient, agent-process-names, agent-env-markers, allow-env, human-lease-hours, audit-full-argv and allow-ssh-human. default-profile must name a saved AWS profile; none clears it.")]
    Config { key: Option<String>, value: Option<String> },
    /// Show recent audit events, or verify the hash chain.
    Audit {
        /// How many recent events to show.
        #[arg(short = 'n', default_value_t = 30)]
        limit: usize,
        /// Check the log's hash chain for tampering.
        #[arg(long)]
        verify: bool,
        /// Only events that touched this secret (who used it, when).
        #[arg(long)]
        secret: Option<String>,
    },
    /// Grant, list or revoke time-limited agent access.
    #[command(long_about = "Let agents use Touch ID secrets without a prompt for a set time.")]
    Lease {
        #[command(subcommand)]
        cmd: LeaseCmd,
    },
    /// Recover secrets using your offline backup identity.
    #[command(long_about = "Recovery: move dead SE keys aside, create new ones, rewrap all secrets from the offline backup identity. Omit FILE to type the paper key. Refuses, changing nothing, unless the key opens every secret; --accept-loss NAME[,NAME] gives up exactly the secrets it lists as unrecoverable. An interrupted recovery is finished by running it again.")]
    Recover {
        identity_file: Option<std::path::PathBuf>,
        /// Unrecoverable secrets to give up (must match the refused list exactly).
        #[arg(long, value_delimiter = ',')]
        accept_loss: Vec<String>,
    },
    /// Trust or stage Secure Enclave helper binaries.
    #[command(long_about = "Trust the currently installed SE helper binaries (after a rebuild/reinstall).")]
    Helper {
        #[command(subcommand)]
        cmd: HelperCmd,
    },
    /// Secure Enclave keys.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Background lease daemon (started automatically; you rarely run this).
    #[command(hide = true)]
    Daemon {
        #[command(subcommand)]
        cmd: Option<DaemonCmd>,
    },
    /// Paper backup tools.
    Backup {
        #[command(subcommand)]
        cmd: BackupCmd,
    },
    /// Run with an AWS profile, or manage saved profiles.
    #[command(long_about = "AWS credential profiles: paste the console's `export AWS_...` block once, then agents run commands with it via `karambit aws PROFILE -- aws ...`.")]
    #[command(disable_help_subcommand = true, override_usage = "karambit aws [OPTIONS] <PROFILE> [--region REGION] -- <COMMAND>...\n       karambit aws <add|ls|show|rm> [OPTIONS]", after_help = "Profile names add, ls, show and rm are reserved.\nExample: karambit aws app-staging -- aws s3 ls")]
    Aws {
        #[command(subcommand)]
        cmd: AwsCmd,
    },
}

#[derive(Subcommand)]
enum AwsCmd {
    /// Import every account/role from a signed-in portal (one Touch ID).
    Import {
        #[arg(long)]
        portal: String,
        /// Access level for every imported profile: agents | agents-touch | me-touch.
        #[arg(long, value_parser = parse_access, default_value = "me-touch")]
        access: (Tier, bool),
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Save pasted AWS credentials, or an SSO account and role.
    #[command(long_about = "Save a profile from pasted export AWS_... lines or stdin. With --sso, save an IAM Identity Center account and role instead of keys.")]
    Add {
        profile: String,
        /// Default region, if the pasted block has none (e.g. us-east-2).
        #[arg(long)]
        region: Option<String>,
        #[arg(long, value_parser = parse_tier, hide = true)]
        touch: Option<Tier>,
        #[arg(long, hide = true)]
        human_only: bool,
        /// Access level: agents | agents-touch | me-touch.
        #[arg(long, value_parser = parse_access, conflicts_with_all = ["touch", "human_only"])]
        access: Option<(Tier, bool)>,
        /// Replace an existing profile (e.g. refreshed console credentials).
        #[arg(short, long)]
        force: bool,
        /// Skip the `aws sts get-caller-identity` check.
        #[arg(long)]
        no_verify: bool,
        /// SSO profile: role credentials come from `karambit login`.
        #[arg(long, requires_all = ["account", "role"])]
        sso: bool,
        /// SSO: 12-digit AWS account id.
        #[arg(long)]
        account: Option<String>,
        /// SSO: permission set (role) name, e.g. ReadOnly.
        #[arg(long)]
        role: Option<String>,
        /// SSO: which access portal (see `karambit sso ls`). Optional if you have one.
        #[arg(long)]
        portal: Option<String>,
        /// Long-term keys only: runs get a one-hour STS session minted by the daemon, never the key.
        #[arg(long, conflicts_with = "sso")]
        session_mint: bool,
    },
    /// Turn session minting on or off for a saved long-term key (human only, Touch ID).
    #[command(long_about = "With on, runs of this profile get a one-hour STS session minted by the daemon instead of the key itself, so the program never holds the long-lived key. Needs an IAM-user key (AKIA...) allowed to call sts:GetSessionToken. Turning it off hands the key to runs again, so it asks for Touch ID.")]
    SessionMint {
        profile: String,
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// List saved profiles (names only, no prompt).
    #[command(name = "ls")]
    List,
    /// Show key type, region and masked key id for a profile.
    Show { profile: String },
    /// Run with a profile: karambit aws PROFILE -- COMMAND...
    #[command(external_subcommand)]
    Profile(Vec<String>),
    /// Delete a profile.
    Rm { profile: String },
}

#[derive(Subcommand)]
enum SsoCmd {
    /// Add, remove or limit named access portals (human-only).
    Portal {
        #[command(subcommand)]
        cmd: PortalCmd,
    },
    /// List portals and whether each is signed in.
    #[command(name = "ls")]
    Ls,
    /// Show portal sign-ins, expiry and active profiles.
    Status,
}

#[derive(Subcommand)]
enum PortalCmd {
    /// Add a named SSO access portal.
    Add {
        name: String,
        #[arg(long)]
        start_url: String,
        /// IAM Identity Center region (where the portal lives), e.g. us-west-2.
        #[arg(long)]
        region: String,
    },
    /// Remove and sign out a portal; keep its saved profiles.
    #[command(alias = "remove")]
    Rm { name: String },
    #[command(about = "Limit sign-in duration (90m, 8h, 2d or none).", long_about = "Sign a portal out this long after each sign-in, even if AWS would keep renewing it. Applies to the current sign-in too. Lengthening or removing the limit asks for Touch ID.")]
    /// Sign a portal out this long after each sign-in, even if AWS would keep renewing
    /// it: 90m, 8h, 2d, or `none` (as long as AWS allows). Applies to the current
    /// sign-in too. It can only end sign-ins sooner than IAM Identity Center would.
    /// Lengthening or removing it asks for Touch ID.
    Limit { name: String, limit: String },
}

#[derive(Subcommand)]
enum HelperCmd {
    /// Pin current helpers or stage replacements (human-only).
    Pin {
        #[arg(long, requires = "stage_helper")]
        stage_daemon: Option<std::path::PathBuf>,
        #[arg(long, requires = "stage_daemon")]
        stage_helper: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    #[command(about = "Upgrade to lock-safe agent keys (human-only).", long_about = "Add the lock-safe agent key and move agent-enabled, no-prompt secrets onto it. Human-only; one Touch ID.")]
    /// Let agent-enabled, no-prompt secrets work while the screen is locked: add the
    /// lock-safe agent key and move those secrets onto it (human only; one Touch ID).
    Upgrade,
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Is it running, how many leases / AWS endpoints.
    Status,
    /// Stop it now (ends every lease).
    Stop,
}

#[derive(Subcommand)]
enum LeaseCmd {
    /// Grant temporary access with Touch ID (human-only, globs ok).
    #[command(long_about = "Let agents use Agents · Touch ID secrets without a prompt for a while (human-only, one Touch ID).\n\nExample:\n  karambit lease grant stripe/live-key --to claude --hours 2 --cwd ~/code/myapp")]
    Grant {
        /// Secret names or globs.
        patterns: Vec<String>,
        /// Hours until it expires (max 168). Fractions ok: 0.5 = 30 min.
        #[arg(long, default_value_t = 3.0)]
        hours: f64,
        /// Who may use it: any | pi | claude | codex | ... | session:pid:<n>@<start> | <pid>
        #[arg(long, default_value = "any")]
        to: String,
        /// Only when the agent's working directory is under this path.
        #[arg(long)]
        cwd: Option<String>,
        /// Pin these programs (comma-separated absolute paths or unambiguous names). Shells are refused;
        /// interpreters (node, python, ...) need --script.
        #[arg(long, value_delimiter = ',')]
        cmd: Vec<String>,
        /// With an interpreter --cmd: only these script files (comma-separated). A launch must be
        /// `<interpreter> <script>` with no -e/-c/-m style flags; the file's hash is pinned.
        #[arg(long, value_delimiter = ',')]
        script: Vec<String>,
        /// End after this many uses.
        #[arg(long)]
        max_uses: Option<u32>,
    },
    /// Show active temporary access.
    #[command(name = "ls")]
    List,
    /// End temporary access now (glob ok; anyone may revoke).
    Revoke {
        /// Secret names or globs.
        patterns: Vec<String>,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Verify your paper key matches the backup recipient.
    Verify,
    /// Rotate the paper key and re-encrypt all backup copies.
    Rotate,
}

fn parse_tier(s: &str) -> Result<Tier, String> {
    Tier::parse(s).map_err(|e| e.to_string())
}

/// One access level, as in the app. `public` only where public makes sense (not AWS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Level { tier: Tier, agent_allowed: bool, public: bool }

fn parse_level(s: &str) -> Result<Level, String> {
    if matches!(s, "public" | "pub") { return Ok(Level { tier: Tier::Open, agent_allowed: true, public: true }); }
    parse_access(s).map(|(tier, agent_allowed)| Level { tier, agent_allowed, public: false })
        .map_err(|_| if matches!(s, "me" | "only-me") { "no-prompt 'Only me' is retired; use me-touch".into() }
            else { "expected agents | agents-touch | me-touch | public".into() })
}

/// Access level -> (tier, agents allowed). No-prompt "Only me" is retired.
pub(crate) fn parse_access(s: &str) -> Result<(Tier, bool), String> {
    match s {
        "agents" => Ok((Tier::Open, true)),
        "agents-touch" | "agents+touch" => Ok((Tier::Bio, true)),
        "me-touch" | "me+touch" | "only-me-touch" => Ok((Tier::Bio, false)),
        "me" | "only-me" => Err("no-prompt 'Only me' is retired; use me-touch".into()),
        _ => Err("expected agents | agents-touch | me-touch".into()),
    }
}

fn parse_agent(s: &str) -> Result<bool, String> {
    match s {
        "allow" | "on" | "yes" => Ok(true),
        "deny" | "off" | "no" => Ok(false),
        _ => Err("expected allow|deny".into()),
    }
}

fn parse_onoff(s: &str) -> Result<bool, String> {
    match s {
        "on" | "yes" | "true" => Ok(true),
        "off" | "no" | "false" => Ok(false),
        _ => Err("expected on|off".into()),
    }
}

/// `ls` / `policy` table: one access column in app words, then name. Empty list says so.
fn print_secret_table(items: &[karambit_core::SecretMeta]) {
    if items.is_empty() {
        eprintln!("no secrets match");
        return;
    }
    let width = items.iter().map(|s| s.name.len()).max().unwrap_or(0).max(4);
    println!("{:<20}  {:<width$}  NOTE", "ACCESS", "NAME");
    for s in items {
        let level = explain::level_label(explain::level(s.tier, s.agent_allowed, s.public));
        let mut note = Vec::new();
        if let Some(l) = &s.lease { note.push(format!("temporary access: {} · {} left", l.info.to_label, dur(l.info.remaining))); }
        if !s.has_backup { note.push("no backup".into()); }
        println!("{level:<20}  {:<width$}  {}", s.name, note.join("; "));
    }
}

fn tier_icon(t: Tier) -> &'static str {
    match t {
        Tier::Bio => "touch",
        Tier::Open => "open ",
    }
}

fn read_value(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    if std::io::stdin().is_terminal() {
        let a = Zeroizing::new(rpassword::prompt_password(format!("value for {name}: "))?);
        let b = Zeroizing::new(rpassword::prompt_password("repeat: ")?);
        if *a != *b {
            bail!("values do not match");
        }
        Ok(Zeroizing::new(a.as_bytes().to_vec()))
    } else {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf)?;
        // Strip exactly one trailing newline (echo / heredoc).
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        Ok(buf)
    }
}

/// Default profile for `run` with no -e: `.karambit.env`, else `.env.schema`.
fn default_profile() -> Option<std::path::PathBuf> {
    [".karambit.env", ".env.schema"].into_iter().map(std::path::PathBuf::from).find(|p| p.exists())
}

/// Secret assignments, plus plain values when the profile is a `.env.schema`.
type RunSpecs = (Vec<(String, String)>, Vec<(String, String)>);

fn env_specs(v: &Karambit, env: &[String], env_file: Option<&std::path::Path>) -> Result<RunSpecs> {
    let mut specs = Vec::new();
    let mut plain = Vec::new();
    let file = match env_file {
        Some(p) => Some(p.to_path_buf()),
        None if env.is_empty() => default_profile(),
        None => None,
    };
    if let Some(p) = file {
        let path = std::env::current_dir()?.join(p);
        let response = karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::ProfileRead {
            path: path.to_str().context("profile path must be UTF-8")?.into(),
        })?;
        if response["trusted"] != true {
            let why = response["detail"].as_str().map(|d| format!(" ({d})")).unwrap_or_default();
            eprintln!("warning: profile.untrusted{why}; review and run the `profile trust [path]` subcommand");
        }
        specs.extend(serde_json::from_value::<Vec<(String, String)>>(response["specs"].clone())?);
        // Plain values come from the exact bytes the daemon checked, expanded here
        // against this environment (an already-set variable wins, like dotenv).
        if let Some(text) = response["schema_text"].as_str() {
            let schema = karambit_core::envspec::compile(&karambit_core::envspec::parse(text)?)?;
            for w in &schema.warnings { eprintln!("karambit: {}: {w}", path.display()); }
            plain = schema.plain(&|k| std::env::var(k).ok())?;
        }
    }
    for e in env {
        match e.split_once('=') {
            // Preserve source/native selectors; launch_bound classifies without resolving.
            Some((k, v)) => specs.push((valid_var(k)?, v.to_string())),
            None => specs.push((default_var(e), e.clone())),
        }
    }
    if specs.is_empty() && plain.is_empty() {
        bail!("no secrets requested (use -e VAR=ns/name, a .karambit.env or a .env.schema file)");
    }
    Ok((specs, plain))
}

struct RunAws<'a> {
    profile: &'a str,
    region: Option<&'a str>,
}

#[cfg(test)]
use karambit_core::env::{scrub_child_env, scrub_child_env_from};

fn cmd_run(v: &mut Karambit, env: &[String], env_file: Option<&std::path::Path>, aws: Option<RunAws>, options: (bool, Option<karambit_core::sandbox::Jail>), command: &[String]) -> Result<ExitCode> {
    let paths = v.paths.clone();
    let caller = v.caller.clone();
    karambit_core::audit::run(&paths, "run-child", &[], &caller, json!({}), || {
        let (specs, plain) = if (aws.is_some() || options.1.is_some()) && env.is_empty() && env_file.is_none() && default_profile().is_none() {
            (vec![], vec![])
        } else {
            env_specs(v, env, env_file).map_err(classify_env_error)?
        };
        let aws_entry = match &aws {
            Some(a) => {
                let n = karambit_core::aws::entry_name(a.profile).map_err(|e| refused(explain::Code::Usage, format!("{e:#}")))?;
                if !v.list(Some(&n))?.iter().any(|m| m.name == n) {
                    return Err(refused(explain::Code::NoProfile, format!("no AWS profile {:?} (see `karambit aws ls`)", a.profile)));
                }
                Some(n)
            }
            None => None,
        };
        if command.is_empty() {
            return Err(refused(explain::Code::Usage, "missing command"));
        }
        // Availability only; all authorization and release occur on the bound path.
        karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::Ping)
            .map_err(|e| refused(explain::Code::DaemonUnavailable, format!("karambit daemon unavailable: {e:#}")))?;
        let refs: Vec<String> = specs.iter().map(|(_, r)| r.clone()).chain(aws_entry.iter().cloned()).collect();
        let status = v.launch_bound_with_plain(specs, plain, command.to_vec(), std::env::current_dir()?, aws_entry,
            aws.as_ref().and_then(|a| a.region).map(str::to_owned), options)
            .context("bound launch failed");
        match status {
            Ok(status) => {
                status::started(raw_exit(status));
                Ok(exit_code(status))
            }
            // The daemon's refusal is deliberately opaque; say why from metadata the caller can already read.
            // A daemon that refuses mid-redeem may just close the channel ("failed to fill whole buffer").
            Err(e) if { let m = format!("{e:#}"); m.ends_with("launch refused") || m.ends_with("failed to fill whole buffer") } =>
                Err(explain::Refused(refusal_for(v, &refs, command)).into()),
            Err(e) => Err(e),
        }
    })
}

/// A pre-launch failure with a code (exit 125, `--json` error object).
fn refused(code: explain::Code, message: impl Into<String>) -> anyhow::Error {
    let next = match code {
        explain::Code::Usage => "fix the command line; see `karambit run --help`",
        explain::Code::NoProfile => "check the name with `karambit aws ls`",
        explain::Code::DaemonUnavailable => "retry once; if it fails again, tell the user (`karambit status`)",
        explain::Code::BadEnvFile => "fix the env file named in the message, or pass secrets with -e VAR=ns/name",
        _ => "read the message; don't retry in a loop",
    };
    explain::Refused(explain::Refusal::new(code, vec![], message, next)).into()
}

/// Errors from reading `-e` specs and the profile file.
fn classify_env_error(e: anyhow::Error) -> anyhow::Error {
    let m = format!("{e:#}");
    if m.contains("profile.untrusted") {
        let scripts = m.contains("package.json scripts");
        let mut r = explain::Refusal::new(explain::Code::ProfileUntrusted, vec![],
            if scripts { "this project's package.json scripts changed since its .env.schema was trusted (profile.untrusted)" }
            else { "this project's .karambit.env/.env.schema is new or was edited since it was trusted (profile.untrusted)" },
            "ask the user to review the file and run the `profile trust FILE` subcommand in a plain terminal, then retry");
        r.ask_user = default_profile().map(|p| vec!["karambit".into(), "profile".into(), "trust".into(), p.to_string_lossy().into_owned()]);
        return explain::Refused(r).into();
    }
    if m.contains("daemon didn't start") { return refused(explain::Code::DaemonUnavailable, m); }
    if m.contains("invalid env var name") || m.contains("no secrets requested") { return refused(explain::Code::Usage, m); }
    refused(explain::Code::BadEnvFile, m)
}

/// Exit status as the shell reports it (128 + signal for a signal).
fn raw_exit(st: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
}

/// Canonical path of argv[1] when `command` is an interpreter running a plain script file
/// (no inline-code flags): what a `--script` lease would pin.
fn script_path(command: &[String], program: Option<&str>) -> Option<String> {
    use karambit_core::lease::{has_inline_code_flag, is_interpreter_name};
    if !is_interpreter_name(program?) || has_inline_code_flag(command) { return None; }
    let path = std::fs::canonicalize(command.get(1)?).ok()?;
    path.is_file().then(|| path.to_string_lossy().into_owned())
}

/// Canonical path of the program `run` starts, for lease program scopes (best effort).
fn program_path(command: &[String]) -> Option<String> {
    let name = command.first()?;
    let path = if name.contains('/') { std::fs::canonicalize(name).ok()? } else {
        std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(name))
            .find(|p| p.is_file()).and_then(|p| std::fs::canonicalize(p).ok())?
    };
    Some(path.to_string_lossy().into_owned())
}

/// Metadata-only diagnosis of a refused launch (see explain.rs); never prompts or decrypts.
fn refusal_for(v: &Karambit, refs: &[String], command: &[String]) -> explain::Refusal {
    let items = v.list(None).unwrap_or_default();
    let cwd = std::env::current_dir().and_then(std::fs::canonicalize).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    // Same check the daemon makes (kernel exe vs daemon.sha256), done locally; unreadable = assume pinned.
    let pinned = (|| {
        let pins = std::fs::read_to_string(v.paths.keys().join("daemon.sha256")).ok()?;
        let hash = karambit_core::helper::sha256_file(&std::env::current_exe().ok()?).ok()?;
        Some(pins.lines().any(|l| l.trim() == hash))
    })().unwrap_or(true);
    let sso = v.sso_status().map(|st| explain::Sso {
        active: st["profiles"].as_array().into_iter().flatten().filter_map(|n| n.as_str().map(str::to_owned)).collect(),
        signed_out: st["portals"].as_array().into_iter().flatten()
            .filter(|p| p["logged_in"] != true).filter_map(|p| p["portal"].as_str().map(str::to_owned)).collect(),
    }).unwrap_or_default();
    let program = program_path(command);
    let script = script_path(command, program.as_deref());
    explain::explain_for(&v.caller, &v.cfg, &items, &v.leases(), refs, &cwd, pinned, &sso, program.as_deref(), script.as_deref())
}

/// `ls --brief`: `name<TAB>access`, plus `<TAB>lease <who> <left>` when one is held.
fn brief_text(items: &[karambit_core::SecretMeta]) -> String {
    if items.is_empty() { eprintln!("no secrets match"); }
    items.iter().map(|m| {
        let access = explain::level(m.tier, m.agent_allowed, m.public);
        match &m.lease {
            Some(l) => format!("{}\t{access}\tlease {} {}\n", m.name, l.info.to_label, dur(l.info.remaining).replace(' ', "")),
            None => format!("{}\t{access}\n", m.name),
        }
    }).collect()
}

/// `ls --brief --json`: `[{name, access, lease?:{to, left_s}}]`.
fn brief_json(items: &[karambit_core::SecretMeta]) -> serde_json::Value {
    json!(items.iter().map(|m| {
        let mut j = json!({"name": m.name, "access": explain::level(m.tier, m.agent_allowed, m.public)});
        if let Some(l) = &m.lease { j["lease"] = json!({"to": l.info.to_label, "left_s": l.info.remaining}); }
        j
    }).collect::<Vec<_>>())
}

fn exit_code(st: std::process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    match (st.code(), st.signal()) {
        (Some(c), _) => ExitCode::from(c as u8),
        (None, Some(sig)) => ExitCode::from(128u8.wrapping_add(sig as u8)),
        _ => ExitCode::FAILURE,
    }
}

fn ask_yes(question: &str) -> Result<bool> {
    eprint!("{question} [y/N] ");
    let mut a = String::new();
    std::io::stdin().read_line(&mut a)?;
    Ok(matches!(a.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Shown by `status`, `backup verify` and `backup rotate` while `backup_rotation` is set.
fn rotation_warning(r: &karambit_core::store::BackupRotation) -> String {
    format!("WARNING: a backup rotation to {} was interrupted. Some secrets need the NEW paper key, the rest still need the old one.\n         Run `karambit backup rotate` again to finish it; until then keep BOTH sheets.", r.to)
}

/// `recover` returns secrets it could not rewrap: no usable backup copy, or given up with
/// `--accept-loss` (those stay wrapped to the retired keys).
fn not_recovered_line(missing: &[String]) -> String {
    format!("not recovered (no usable backup copy, or given up with --accept-loss and still wrapped to the retired keys): {}", missing.join(", "))
}

/// Short human summary of `status`; `--json` has every field.
fn print_status(st: &serde_json::Value) {
    let yes = |b: &serde_json::Value| if b == true { "yes" } else { "no" };
    let h = &st["helper"];
    println!("vault       {} · {} secrets{}", st["root"].as_str().unwrap_or("?"), st["secrets"],
        match st["without_backup"].as_u64() { Some(0) | None => String::new(), Some(n) => format!(" · {n} without backup") });
    println!("hardware    Secure Enclave {} · Touch ID {}", yes(&h["secure_enclave"]), yes(&h["biometrics"]));
    println!("default     new secrets use Touch ID: {}", if st["default_tier"] == "bio" { "yes" } else { "no" });
    match (st["daemon"]["build_id"].as_str(), st["daemon"]["policy_sha256"].as_str()) {
        (Some(build), Some(policy)) => println!("daemon      build {build} · policy sha256 {}", &policy[..policy.len().min(16)]),
        // Older daemons (ui-v1 and earlier) report neither and do not enforce the policy section.
        _ => println!("daemon      older build: no build id or policy hash reported; it does not enforce the policy section (restart it from a current build)"),
    }
    let c = &st["caller"];
    match c["agent"].as_str() {
        Some(_) => println!("you are     agent ({}) · `get`, `add`, `rm` and relaxing access are refused", c["kind"].as_str().unwrap_or("unknown")),
        None => println!("you are     human (no agent detected in {})", c["chain"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" < ")).unwrap_or_default()),
    }
    if st["locked_screen_blocked"].as_u64().unwrap_or(0) > 0 {
        println!("note        {} uses were blocked while the screen was locked", st["locked_screen_blocked"]);
    }
    if let Some(to) = st["backup_rotation"]["to"].as_str() {
        println!("warning     backup rotation to {to} is unfinished: keep both paper sheets, then run `karambit backup rotate` to finish it");
    }
    if st["initialized"] != true { println!("next        karambit init --paper"); }
}

/// `--pretty`, or stdout is a terminal: indent JSON. Otherwise one compact line.
static PRETTY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub(crate) fn print_json(v: &serde_json::Value) {
    let pretty = *PRETTY.get_or_init(|| std::io::stdout().is_terminal());
    let text = if pretty { serde_json::to_string_pretty(v) } else { serde_json::to_string(v) };
    println!("{}", text.unwrap_or_default());
}

/// `KARAMBIT_FORMAT=json` selects JSON like `--json`. It is output format only, and it
/// never reaches a launched command (bound runs drop every `KARAMBIT_` variable).
fn env_wants_json() -> bool {
    std::env::var("KARAMBIT_FORMAT").is_ok_and(|v| v == "json")
}

/// "3h 20m", "45m", "2d 4h".
fn dur(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    match (d, h) {
        (0, 0) => format!("{}m", m.max(1)),
        (0, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

/// Local "YYYY-MM-DD HH:MM" via libc (no chrono dependency).
fn when(ts: u64) -> String {
    let t = ts as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return ts.to_string();
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min)
}

/// "pi · 01a0f0f2" / "claude · pid 4211" / "karambit-gui" / "zsh".
fn who_label(e: &serde_json::Value) -> String {
    if let Some(k) = e["kind"].as_str() {
        let sess = e["session"].as_str().map(|s| {
            let id = s.split_once(':').map(|x| x.1).unwrap_or(s);
            if s.starts_with("pid:") { format!("pid {}", id.split('@').next().unwrap_or(id)) } else { id.chars().take(8).collect() }
        });
        return match sess { Some(s) => format!("{k} · {s}"), None => k.to_string() };
    }
    if let Some(a) = e["agent"].as_str() {
        return format!("agent:{a}");
    }
    e["caller"].get(0).and_then(|c| c.as_str()).unwrap_or("?").to_string()
}

/// Show a fresh backup key once, make the user retype it, then clear the screen.
/// The key only ever lives in this process's memory and the terminal's screen.
fn paper_ceremony(v: &Karambit) -> Result<String> {
    use karambit_core::crypto;
    v.require_human(Verb::PaperBackup, Layer::Cli)?;
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!("--paper needs an interactive terminal");
    }
    let (id, recip) = crypto::generate_paper_identity();
    show_paper(&id)?;
    loop {
        match read_paper_key("CONFIRM: retype the key from your paper") {
            Ok(typed) if typed.to_public().to_string() == recip => break,
            Ok(_) => eprintln!("that is a valid key but not the one shown. Check your sheet."),
            Err(e) => eprintln!("{e}"),
        }
        eprint!("try again? [Y/n/show] ");
        let mut a = String::new();
        std::io::stdin().read_line(&mut a)?;
        match a.trim().to_lowercase().as_str() {
            "n" | "no" => bail!("aborted; nothing saved"),
            "show" => show_paper(&id)?,
            _ => {}
        }
    }
    eprintln!("paper backup confirmed.");
    Ok(recip)
}

fn show_paper(id: &str) -> Result<()> {
    // Alternate screen buffer: not kept in scrollback after we leave it.
    let mut err = std::io::stderr().lock();
    write!(err, "\x1b[?1049h\x1b[2J\x1b[H")?;
    writeln!(err, "KARAMBIT PAPER BACKUP. Write this down exactly, then keep it offline.\n")?;
    writeln!(err, "{}", karambit_core::crypto::paper_format(id))?;
    writeln!(err, "Write each row AND its check code. Keys never contain 1, B, I or O: a round 0 is always zero.")?;
    writeln!(err, "Anyone holding this sheet can decrypt every secret. Do not photograph it.\n")?;
    write!(err, "Press Enter when written down...")?;
    err.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    write!(err, "\x1b[2J\x1b[?1049l")?;
    err.flush()?;
    Ok(())
}

/// Row-by-row entry of a paper key. Input is visible so typos can be seen, but it
/// happens on the alternate screen, which is wiped on exit (no scrollback copy).
/// Each row is checked on Enter; a bad row is re-asked with the exact problem.
fn read_paper_key(title: &str) -> Result<age::x25519::Identity> {
    use karambit_core::crypto;
    let n = crypto::paper_row_count();
    let mut err = std::io::stderr().lock();
    write!(err, "\x1b[?1049h\x1b[2J\x1b[H")?;
    writeln!(err, "{title}\n")?;
    writeln!(err, "Type or paste each row as written on the sheet, or paste the whole key at row 1. Spaces and case don't matter.")?;
    writeln!(err, "Adding the 2-character check code at the end of a row is optional but catches typos early.\n")?;
    err.flush()?;
    let result = (|| -> Result<age::x25519::Identity> {
        let mut rows: Vec<String> = Vec::with_capacity(n);
        while rows.len() < n {
            let i = rows.len();
            write!(err, "  row {} ({} chars): ", i + 1, crypto::paper_row_len(i))?;
            err.flush()?;
            let mut line = Zeroizing::new(String::new());
            if std::io::stdin().read_line(&mut line)? == 0 {
                bail!("input closed");
            }
            if line.trim().is_empty() {
                continue;
            }
            match crypto::check_paper_row(i, &line) {
                Ok(r) => rows.push(r),
                Err(msg) => {
                    // Whole key pasted at row 1 (e.g. from a password manager).
                    if i == 0 {
                        let compact: String = line.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
                        if compact.len() > crypto::PAPER_ROW + 4 {
                            if let Ok(id) = crypto::parse_identity_loose(&line) {
                                return Ok(id);
                            }
                            writeln!(err, "    \u{2717} that looks like a whole key but it didn't validate. Type it row by row to find the typo.")?;
                            continue;
                        }
                    }
                    writeln!(err, "    \u{2717} {msg}. Retype row {}.", i + 1)?;
                }
            }
        }
        let rows = Zeroizing::new(rows);
        crypto::identity_from_rows(&rows).map_err(|_| {
            anyhow::anyhow!("all rows looked valid but the key checksum failed; a row without a check code has a typo")
        })
    })();
    write!(err, "\x1b[2J\x1b[?1049l")?;
    err.flush()?;
    result
}

#[derive(clap::Subcommand, Debug)]
enum PolicyCmd {
    /// Show what policy rules decide for one action (rules can only tighten access).
    Explain {
        action: String,
        subject: String,
        #[arg(long = "as")]
        as_who: Option<String>,
        /// Read the policy from this JSON file (a config.json or a bare {rules,tags}); no vault needed.
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Run a JSON array of action/subject/as/expected cases offline.
    Test {
        file: std::path::PathBuf,
        /// Read the policy from this JSON file (a config.json or a bare {rules,tags}); no vault needed.
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// Also require the running daemon to report the same policy hash (read-only; never starts a daemon).
        #[arg(long)]
        live: bool,
    },
    /// Validate the policy in config.json without prompting.
    Validate {
        /// Read the policy from this JSON file (a config.json or a bare {rules,tags}); no vault needed.
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}
#[derive(clap::Subcommand, Debug)]
enum ProfileCmd {
    /// Trust the exact canonical path and SHA-256 (human only).
    Trust { #[arg(default_value = ".karambit.env")] path: std::path::PathBuf },
}

#[derive(clap::Subcommand, Debug)]
enum EnvCmd {
    /// Check schema and reference metadata; remote existence/types remain unverified.
    Check {
        #[arg(default_value = ".karambit.env")]
        file: std::path::PathBuf,
        /// Syntax and schema only: local refs are reported 'unverified' instead of looked up in the vault.
        #[arg(long)]
        offline_refs: bool,
    },
}

/// Policy for a diagnostic: from `--config FILE` (no vault, daemon or keys touched),
/// otherwise from the vault's config.json.
fn diagnostic_policy(config: Option<&std::path::Path>) -> Result<karambit_core::policy::Policy> {
    use karambit_core::{policy::diagnostics as d, store};
    if let Some(file) = config {
        let text = std::fs::read_to_string(file).context("read policy file")?;
        return d::policy_from_file(&text);
    }
    let paths = karambit_core::Paths::resolve()?;
    let cfg = store::load_config(&paths).map_err(|_| anyhow::anyhow!("invalid config/policy; no changes made"))?;
    Ok(cfg.policy.unwrap_or_default())
}

/// `policy test --live`: the daemon must already be running and report this policy's hash.
fn check_live_policy(policy: &karambit_core::policy::Policy) -> Result<serde_json::Value> {
    use karambit_core::daemon;
    let paths = karambit_core::Paths::resolve()?;
    let reply = daemon::request_if_running(&paths, &daemon::Req::Ping)
        .context("no running daemon to compare with (it starts when needed); nothing is enforcing this policy yet")?;
    karambit_core::policy::diagnostics::check_live(policy, &reply)
}

fn offline_diagnostics(cmd: &Cmd) -> Result<bool> {
    use karambit_core::{policy::diagnostics as d, store};
    match cmd {
        Cmd::Policy { cmd: Some(cmd), patterns, access, touch, agent, public } => {
            if !patterns.is_empty() || access.is_some() || touch.is_some() || agent.is_some() || public.is_some() { bail!("diagnostics cannot change secret access"); }
            match cmd {
                PolicyCmd::Explain { action, subject, as_who, config } => {
                    let policy = diagnostic_policy(config.as_deref())?;
                    let action = d::action(action)?;
                    print_json(&d::explain(&policy, action, &d::subject(action, subject), &d::caller(as_who.as_deref())?));
                }
                PolicyCmd::Test { file, config, live } => {
                    let policy = diagnostic_policy(config.as_deref())?;
                    let text = std::fs::read_to_string(file).context("read policy cases")?;
                    let mut out = json!({"passed":d::test_cases(&policy, &text)?});
                    if *live { out["live"] = check_live_policy(&policy)?; }
                    print_json(&out);
                }
                PolicyCmd::Validate { config } => {
                    let policy = diagnostic_policy(config.as_deref())?;
                    policy.validate().map_err(anyhow::Error::msg)?;
                    print_json(&json!({"valid":true,"rules":policy.rules.len()}));
                }
            }
        }
        Cmd::Env { cmd: EnvCmd::Check { file, offline_refs } } => {
            let text = std::fs::read_to_string(file).context("read env schema")?;
            if *offline_refs {
                // No Paths: the vault directory is never resolved, opened or listed.
                print_json(&karambit_core::env::check_with(None, &store::Config::default(), &text)?);
            } else {
                let paths = karambit_core::Paths::resolve()?;
                let cfg = store::load_config(&paths).map_err(|_| anyhow::anyhow!("invalid config/policy; no changes made"))?;
                print_json(&karambit_core::env::check(&paths, &cfg, &text)?);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn real_main() -> Result<ExitCode> {
    let mut cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return Err(UsageError(e).into()),
    };
    cli.json |= env_wants_json();
    let _ = PRETTY.set(cli.pretty || std::io::stdout().is_terminal());
    match &cli.cmd {
        Cmd::Run { status_fd, .. } => {
            status::enter_run();
            if let Some(fd) = *status_fd { status::claim(fd)?; }
        }
        Cmd::Aws { cmd: AwsCmd::Profile(_) } => status::enter_run(),
        _ => {}
    }
    if offline_diagnostics(&cli.cmd)? { return Ok(ExitCode::SUCCESS); }
    if matches!(cli.cmd, Cmd::Launch) {
        // The shim is outside the foreground group. Never write a failure to
        // the inherited tty (TOSTOP could suspend it); the owner reports refusal.
        return Ok(if karambit_core::shim::launch_shim_main().is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE });
    }
    if matches!(cli.cmd, Cmd::DoctorHold) {
        doctor::hold();
        return Ok(ExitCode::SUCCESS);
    }
    // The daemon runs before anything else and never touches the agent heuristics.
    if let Cmd::Daemon { cmd: None } = &cli.cmd {
        karambit_core::daemon::refuse_dyld_environment()?;
        return karambit_core::daemon::serve(karambit_core::Paths::resolve()?).map(|_| ExitCode::SUCCESS);
    }
    if let Cmd::AwsWhoami { profile, context, fix } = &cli.cmd {
        return format_aws_identity(profile, context, fix, cli.json);
    }
    let v = Karambit::open_cli()?;
    let action = match &cli.cmd {
        Cmd::Init { .. } => Some("cli-init"),
        Cmd::Recover { .. } => Some("cli-recover"),
        Cmd::Backup { cmd: BackupCmd::Rotate } => Some("cli-backup-rotate"),
        Cmd::Run { .. } => Some("cli-run"),
        Cmd::Get { .. } => Some("cli-get"),
        _ => None,
    };
    let paths = v.paths.clone();
    let caller = v.caller.clone();
    let operation = || dispatch(cli, v);
    if let Some(action) = action {
        karambit_core::audit::run(&paths, action, &[], &caller, json!({}), operation)
    } else { operation() }
}

/// The capability-fence verb a command performs, or None when agents may run it.
/// Exhaustive on purpose: a new subcommand does not compile until it is classified.
/// `get` and the relaxing forms of `policy`/`config` are conditional, so they are
/// looked up at their own sites (`Verb::Get`, `PolicyRelax`, `ConfigRelax`, `NoRedact`).
fn command_verb(cmd: &Cmd) -> Option<Verb> {
    match cmd {
        Cmd::Profile { .. } => Some(Verb::ProfileTrust),
        Cmd::Secure(a) if a.cmd.is_none() && a.dry_run => None,
        Cmd::Secure(a) => Some(if a.cmd.is_some() { Verb::Get } else { Verb::Add }),
        Cmd::Kill(_) => Some(Verb::Kill),
        Cmd::Revive(_) => Some(Verb::Revive),
        Cmd::Source { cmd } => Some(cmd.verb()),
        Cmd::Agents { .. } | Cmd::Call { .. } | Cmd::Ref { .. } => None,
        Cmd::Env { .. } | Cmd::Launch | Cmd::DoctorHold | Cmd::Doctor { .. } | Cmd::Status | Cmd::List { .. } | Cmd::Get { .. } | Cmd::Policy { .. } | Cmd::Config { .. }
        | Cmd::Audit { .. } | Cmd::Daemon { cmd: None | Some(DaemonCmd::Status) } => None,
        Cmd::Init { .. } => Some(Verb::Init),
        Cmd::Add { .. } => Some(Verb::Add),
        // `run --no-redact` is looked up in launch_bound, inside the audited run-child intent.
        Cmd::Run { .. } => None,
        Cmd::Rm { .. } => Some(Verb::Rm),
        Cmd::Mv { .. } => Some(Verb::Rename),
        Cmd::Lease { cmd: LeaseCmd::Grant { .. } } => Some(Verb::LeaseGrant),
        Cmd::Lease { cmd: LeaseCmd::List | LeaseCmd::Revoke { .. } } => None,
        Cmd::Recover { .. } => Some(Verb::Recover),
        Cmd::Helper { cmd: HelperCmd::Pin { .. } } => Some(Verb::HelperPin),
        Cmd::Keys { cmd: KeysCmd::Upgrade } => Some(Verb::KeysUpgrade),
        Cmd::Daemon { cmd: Some(DaemonCmd::Stop) } => Some(Verb::DaemonStop),
        Cmd::Backup { cmd: BackupCmd::Verify } => Some(Verb::BackupVerify),
        Cmd::Backup { cmd: BackupCmd::Rotate } => Some(Verb::BackupRotate),
        Cmd::Aws { cmd } => match cmd {
            AwsCmd::Add { .. } | AwsCmd::SessionMint { .. } => Some(Verb::Add),
            AwsCmd::Import { .. } => Some(Verb::SsoImport),
            AwsCmd::Rm { .. } => Some(Verb::Rm),
            AwsCmd::List | AwsCmd::Show { .. } | AwsCmd::Profile(_) => None,
        },
        Cmd::Whoami { .. } | Cmd::AwsWhoami { .. } => None,
        Cmd::Login { .. } => Some(Verb::SsoLogin),
        Cmd::Logout { .. } => Some(Verb::SsoLogout),
        Cmd::Sso { cmd } => match cmd {
            SsoCmd::Portal { cmd: PortalCmd::Add { .. } } => Some(Verb::SsoPortalAdd),
            SsoCmd::Portal { cmd: PortalCmd::Rm { .. } } => Some(Verb::SsoPortalRemove),
            SsoCmd::Portal { cmd: PortalCmd::Limit { .. } } => Some(Verb::SsoPortalLimit),
            SsoCmd::Ls | SsoCmd::Status => None,
        },
    }
}

fn dispatch(cli: Cli, mut v: Karambit) -> Result<ExitCode> {
    // Capability fence, CLI layer: before any prompt, file read or daemon request.
    if let Some(verb) = command_verb(&cli.cmd) {
        v.require_human(verb, Layer::Cli)?;
    }
    let revive = matches!(&cli.cmd, Cmd::Revive(_));
    match cli.cmd {
        Cmd::Secure(args) => return secure::run(&v, args, cli.json),
        Cmd::Profile { cmd: ProfileCmd::Trust { path } } => {
            let path = std::env::current_dir()?.join(path);
            let response = karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::ProfileTrust {
                path: path.to_str().context("profile path must be UTF-8")?.into(),
            })?;
            if cli.json { print_json(&response) } else { println!("profile trusted"); }
        }
        Cmd::Kill(target) | Cmd::Revive(target) => {
            let response = karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::Kill {
                agent: target.agent, session: target.session, all: target.all, revive,
            })?;
            if cli.json { print_json(&response) } else if revive { println!("agents unblocked"); } else { println!("agents blocked: every agent request is refused (running processes aren't stopped); undo with `karambit unblock`"); }
        }
        Cmd::Call { list: true, .. } => {
            // Ids, hosts and argument shapes only: never the credential entry or anything secret.
            let tools: Vec<_> = v.cfg.tools.iter().map(|(id, t)| json!({"tool": id, "host": t.host, "args": ["JOB"],
                "request": format!("{} {}", t.method, t.path_template)})).collect();
            if cli.json { print_json(&json!(tools)); }
            else if tools.is_empty() { eprintln!("no fixed tools configured (config.json `tools`)"); }
            else { for (id, t) in &v.cfg.tools { println!("{id}\t{}\tJOB", t.host); } }
        }
        Cmd::Call { tool, args, .. } => {
            let tool = tool.context("missing tool (see `karambit call --list`)")?;
            let response = karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::Call { tool, args })?;
            if cli.json { print_json(&response) } else { println!("{}", response["body"].as_str().context("missing fixed tool response")?); }
        }
        Cmd::Source { cmd } => source::run(&v, cmd, cli.json)?,
        Cmd::Ref { cmd: source::RefCmd::Check { input } } => source::check(&v, &input, cli.json)?,
        Cmd::Init { backup_recipient, gen_backup, paper } => {
            let recip = match gen_backup {
                _ if paper => {
                    // Refuse before generating anything if init will fail anyway.
                    if v.paths.initialized() {
                        bail!("already initialized at {}", v.paths.root.display());
                    }
                    Some(paper_ceremony(&v)?)
                }
                Some(path) => {
                    if path.exists() {
                        bail!("{} exists", path.display());
                    }
                    let (text, recip) = karambit_core::crypto::generate_backup_identity();
                    karambit_core::store::write_atomic(&path, text.as_bytes())?;
                    eprintln!("backup identity written to {} — move it OFFLINE now, then delete it from this disk.", path.display());
                    Some(recip)
                }
                None => backup_recipient,
            };
            if recip.is_none() {
                eprintln!("WARNING: no backup recipient. If fingerprints change or this Mac dies, every secret is unrecoverable.");
            }
            let r = v.init(recip)?;
            if cli.json { print_json(&r) } else { println!("initialized {}", v.paths.root.display()) }
        }
        Cmd::Status => {
            let st = v.status()?;
            if cli.json { print_json(&st) } else { print_status(&st) }
        }
        Cmd::Add { name, access, touch, human_only, public, force } => {
            let (touch, agent_allowed, public) = match access {
                Some(l) => (Some(l.tier), l.agent_allowed, l.public),
                None => (touch, !human_only, public),
            };
            let val = read_value(&name)?;
            let m = v.add(&name, &val, touch, agent_allowed, public, force)?;
            let kind = if m.public { "public" } else { tier_icon(m.tier).trim() };
            if cli.json { print_json(&json!(m)) } else { println!("saved {} [{}]", m.name, kind) }
        }
        Cmd::List { pattern, brief } => {
            let items = v.list(pattern.as_deref())?;
            match (cli.json, brief) {
                (true, true) => print_json(&brief_json(&items)),
                (true, false) => print_json(&json!(items.iter().map(|m| {
                    let mut j = json!(m);
                    j["access"] = json!(explain::level(m.tier, m.agent_allowed, m.public));
                    j
                }).collect::<Vec<_>>())),
                (false, true) => print!("{}", brief_text(&items)),
                (false, false) => print_secret_table(&items),
            }
        }
        Cmd::Run { env, aws, env_file, no_redact, jail, allow_host, status_fd: _, command } => {
            let policy = if jail {
                let home = std::env::var_os("HOME").context("HOME required for jail")?;
                Some(karambit_core::sandbox::Jail::new(std::path::Path::new(&home), &v.paths.root, &allow_host)?)
            } else { None };
            let a = aws.as_deref().map(|p| RunAws { profile: p, region: None });
            return cmd_run(&mut v, &env, env_file.as_deref(), a, (no_redact, policy), &command);
        }
        Cmd::Get { name, stdout } => {
            // Public entries are readable by agents; real secrets are not.
            let is_public = v.list(Some(&name))?.iter().any(|m| m.name == name && m.public);
            if !is_public {
                v.require_human(Verb::Get, Layer::Cli)?;
            }
            if stdout && !is_public && std::io::stdout().is_terminal() {
                eprintln!("(printing secret to terminal)");
            }
            // gate_open: reveal costs a Touch ID for real secrets (skipped for public).
            if stdout {
                let vals = v.unlock("get", std::slice::from_ref(&name), None, true)?;
                std::io::stdout().write_all(&vals[0].value)?;
                if std::io::stdout().is_terminal() {
                    println!();
                }
            } else {
                let result = v.copy(&name)?;
                eprintln!("copied {name} to clipboard; clears in {}s", result.clears_in);
            }
        }
        Cmd::Env { .. } => unreachable!("offline diagnostics"),
        Cmd::Policy { cmd, patterns, access, touch, agent, public } => {
            if cmd.is_some() { unreachable!("offline diagnostics"); }
            let (touch, agent, public) = match access {
                Some(l) => (Some(l.tier), Some(l.agent_allowed), Some(l.public)),
                None => (touch, agent, public),
            };
            if patterns == ["show"] && touch.is_none() && agent.is_none() && public.is_none() {
                print_json(&json!({
                    "policy": v.cfg.policy.clone().unwrap_or_default(),
                    "defaults": {"base_authorization_required": true, "prod_agents": "deny_unless_explicit_allow", "approval": "refuse_until_request_bound_proof"}
                }));
                return Ok(ExitCode::SUCCESS);
            }
            if touch.is_none() && agent.is_none() && public.is_none() {
                bail!("nothing to change (use --access agents|agents-touch|me-touch|public)");
            }
            let items = v.set_policy(&patterns, touch, agent, public)?;
            if cli.json {
                print_json(&json!(items));
            } else {
                print_secret_table(&items);
            }
        }
        Cmd::Rm { patterns } => {
            for n in v.remove(&patterns)? {
                println!("removed {n}");
            }
        }
        Cmd::Mv { from, to } => {
            for (old, new) in v.rename(&from, &to)? {
                println!("renamed {old} -> {new}");
            }
        }
        Cmd::Config { key, value } => match (key, value) {
            (Some(k), Some(val)) => {
                v.set_config(&k, &val)?;
                print_json(&json!(v.cfg));
            }
            (None, None) => print_json(&json!(v.cfg)),
            _ => bail!("usage: karambit config [KEY VALUE]"),
        },
        Cmd::Audit { limit, verify, secret } => {
            if verify {
                let report = v.audit_verify_report()?;
                let n = report.checked;
                match report.broken {
                    None => match report.older_removed_before {
                        Some(ts) => println!("audit chain ok ({n} events, older part removed before {})", when(ts)),
                        None => println!("audit chain ok ({n} events)"),
                    },
                    Some(l) => {
                        println!("audit chain BROKEN at line {l}");
                        return Ok(ExitCode::from(3));
                    }
                }
            } else {
                let events = match &secret {
                    Some(s) => v.secret_activity(s, limit)?,
                    None => v.audit_log(limit)?,
                };
                for e in events {
                    if cli.json {
                        println!("{e}");
                    } else {
                        let ok = if e["ok"] == json!(true) { "ok " } else { "ERR" };
                        let who = who_label(&e);
                        let secrets = e["secrets"].as_array().map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default();
                        let lease = if e["detail"]["via_lease"].is_array() { "  (via lease)" } else { "" };
                        let err = e["err"].as_str().map(|s| format!("  ({s})")).unwrap_or_default();
                        println!("{}  {ok}  {:<13} {:<28} {secrets}{lease}{err}", when(e["ts"].as_u64().unwrap_or(0)), e["action"].as_str().unwrap_or("?"), who);
                    }
                }
            }
        }
        Cmd::Lease { cmd: LeaseCmd::Grant { patterns, hours, to, cwd, cmd, script, max_uses } } => {
            let g = karambit_core::lease::Grantee::parse(&to)?;
            let cmds = karambit_core::lease::command_bindings(&cmd, &script, &std::env::current_dir()?)?;
            let scope = karambit_core::daemon::Scope { cwd, cmds, max_uses };
            let got = v.grant_lease(&patterns, &g, hours, &scope)?;
            for l in got {
                let sc = if l.scope.is_empty() { String::new() } else { format!(" [{}]", l.scope.label()) };
                println!("leased {} to {}{sc} until {} ({})", l.info.name, l.info.to_label, when(l.info.expires), dur(l.info.remaining));
            }
        }
        Cmd::Lease { cmd: LeaseCmd::List } => {
            let ls = v.leases();
            if cli.json {
                print_json(&json!(ls));
            } else if ls.is_empty() {
                println!("no active leases");
            } else {
                for l in ls {
                    let sc = if l.scope.is_empty() { String::new() } else { format!("  [{}]", l.scope.label()) };
                    println!("{:<32} {:<20} {} left, used {}x{sc}", l.info.name, l.info.to_label, dur(l.info.remaining), l.uses);
                }
            }
        }
        Cmd::Lease { cmd: LeaseCmd::Revoke { patterns } } => {
            for n in v.revoke_lease(&patterns)? {
                println!("revoked lease on {n}");
            }
        }
        Cmd::Recover { identity_file, accept_loss } => {
            let text = match identity_file {
                Some(f) => Zeroizing::new(std::fs::read_to_string(&f)?),
                None => {
                    let id = read_paper_key("RECOVER: type your paper backup key")?;
                    use age::secrecy::ExposeSecret;
                    Zeroizing::new(id.to_string().expose_secret().to_string())
                }
            };
            // Before the call: a refusal lists files this sheet cannot open, and during an
            // unfinished rotation the other sheet may hold exactly those.
            if let Some(r) = &v.cfg.backup_rotation { eprintln!("{}", rotation_warning(r)); }
            let (ok, missing) = v.recover_from_paper(&text, &accept_loss)?;
            println!("recovered {ok} secrets");
            if !missing.is_empty() {
                println!("{}", not_recovered_line(&missing));
            }

        }
        Cmd::Backup { cmd: BackupCmd::Verify } => {
            if v.cfg.backup_recipient.is_none() && v.cfg.backup_rotation.is_none() { bail!("no backup recipient configured") }
            let id = read_paper_key("VERIFY: type your paper backup key")?;
            let check = v.verify_backup(&id)?;
            if let Some(r) = &check.rotation { println!("{}", rotation_warning(r)); }
            if check.total == 0 {
                // Nothing to trial-decrypt: all that can be checked is the configured recipient.
                let want = v.cfg.backup_recipient.as_deref();
                if want == Some(id.to_public().to_string().as_str()) {
                    println!("OK: paper key matches the configured backup recipient (no secrets stored yet).");
                } else {
                    println!("MISMATCH: valid key, but not this vault's backup. Wrong sheet?");
                    return Ok(ExitCode::from(4));
                }
            } else if check.unreadable.is_empty() {
                println!("OK: this paper key opens {} of {} backup copies.", check.opened, check.total);
            } else {
                println!("FAIL: this paper key opens only {} of {} backup copies. It cannot recover:", check.opened, check.total);
                for (name, why) in &check.unreadable { println!("  {name}: {why}"); }
                return Ok(ExitCode::from(4));
            }
        }
        Cmd::Backup { cmd: BackupCmd::Rotate } => {
            // An unfinished rotation is finished with the new sheet it already started.
            // Without that sheet, a fresh one is safe: every file is rewritten from the chip keys.
            let pending = v.cfg.backup_rotation.clone();
            if let Some(r) = &pending { println!("{}", rotation_warning(r)); }
            let recip = match pending {
                Some(r) if ask_yes("Do you still have the NEW paper sheet from the interrupted rotation?")? => loop {
                    let id = read_paper_key("FINISH ROTATION: type the NEW paper backup key from the interrupted rotation")?;
                    if id.to_public().to_string() == r.to { break r.to; }
                    eprintln!("that is a valid key but not the new sheet of the interrupted rotation.");
                },
                _ => paper_ceremony(&v)?,
            };
            let n = v.rotate_backup(&recip)?;
            println!("backup copies re-encrypted for {n} secrets. Destroy the OLD paper sheet.");
        }
        Cmd::Sso { cmd: SsoCmd::Portal { cmd: PortalCmd::Add { name, start_url, region } } } => {
            v.sso_portal_add(&name, &start_url, &region)?;
            println!("portal {name}: {start_url} ({region})");
            println!("next: karambit login {name}");
        }
        Cmd::Sso { cmd: SsoCmd::Portal { cmd: PortalCmd::Rm { name } } } => {
            v.sso_portal_remove(&name)?;
            println!("removed portal {name} (signed out; its SSO profiles stop working until it's added back)");
        }
        Cmd::Sso { cmd: SsoCmd::Portal { cmd: PortalCmd::Limit { name, limit } } } => {
            let minutes = karambit_core::sso::parse_limit(&limit)?;
            let ended = v.sso_portal_limit(&name, minutes)?;
            let words = karambit_core::sso::limit_words(minutes);
            println!("portal {name}: each sign-in lasts {words}");
            if ended {
                println!("its current sign-in was already older than that, so it's signed out now (karambit login {name})");
            }
        }
        Cmd::Login { portal, no_browser } => {
            let (portal, _) = v.sso_portal(portal.as_deref())?;
            let show = |code: &str, url: &str, _expires_in: u64| {
                eprintln!("[{portal}] Approve this sign-in in your browser. Code: {code}");
                eprintln!("  {url}");
                if !no_browser && url.starts_with("https://") {
                    let _ = Command::new("/usr/bin/open").arg(url).stdout(Stdio::null()).stderr(Stdio::null()).status();
                }
                eprintln!("Waiting for approval...");
            };
            // Nothing to cancel here: Ctrl-C ends the process.
            let ui = karambit_core::sso::SignInUi { show: &show, cancelled: &|| false, commit: &|| true };
            let n = v.sso_login(&portal, &ui)?;
            let limit = v.sso_portal(Some(&portal))?.1.limit_minutes;
            let renew = match limit {
                Some(m) => format!("renews automatically for up to {} (sign-in limit)", karambit_core::sso::limit_label(m)),
                None => "renews automatically while AWS allows".to_string(),
            };
            println!("signed in to AWS SSO portal {portal} · {n} profile(s) active · {renew}");
            if n == 0 {
                println!("no SSO profiles on {portal} yet: karambit aws add NAME --sso --portal {portal} --account ID --role ROLE --access agents");
            }
        }
        Cmd::Logout { portal, all } => {
            let portal = if all { None } else { Some(v.sso_portal(portal.as_deref())?.0) };
            v.sso_logout(portal.as_deref())?;
            match portal {
                Some(p) => println!("signed out of AWS SSO portal {p}; agents get no new credentials for it (ones already handed out last until they expire)"),
                None => println!("signed out of every AWS SSO portal"),
            }
        }
        Cmd::Sso { cmd: SsoCmd::Ls | SsoCmd::Status } => {
            let st = v.sso_status()?;
            let empty = vec![];
            let portals = st["portals"].as_array().unwrap_or(&empty);
            if cli.json {
                print_json(&st);
            } else if portals.is_empty() {
                println!("no SSO portals (karambit sso portal add NAME --start-url URL --region REGION)");
            } else {
                for p in portals {
                    let name = p["portal"].as_str().unwrap_or("?");
                    let head = format!("{name:<12} {} ({})", p["start_url"].as_str().unwrap_or("?"), p["region"].as_str().unwrap_or("?"));
                    if p["logged_in"] == json!(true) {
                        let names: Vec<&str> = p["profiles"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
                        let until = p["renew_until"].as_u64();
                        let renew = if p["can_refresh"] == json!(true) {
                            match until {
                                Some(t) => format!("renews automatically until {} (sign-in limit)", when(t)),
                                None => "renews automatically while AWS allows".to_string(),
                            }
                        } else {
                            format!("until {}", p["access_expires_at"].as_u64().map(when).unwrap_or_default())
                        };
                        println!("{head} · signed in · {renew}");
                        if let Some(err) = p["renew_error"].as_str() {
                            println!("{:<12} can't renew right now, retrying: {err}", "");
                        }
                        println!("{:<12} active: {}", "", if names.is_empty() { "(none)".into() } else { names.join(", ") });
                    } else if let Some(e) = p["ended"].as_object() {
                        let at = e.get("at").and_then(|x| x.as_u64()).map(when).unwrap_or_default();
                        let why = e.get("why").and_then(|x| x.as_str()).unwrap_or("?");
                        println!("{head} · signed out {at}: {why} (karambit login {name})");
                    } else {
                        println!("{head} · signed out (karambit login {name})");
                    }
                    if let Some(m) = p["limit_minutes"].as_u64() {
                        println!("{:<12} sign-in limit: {}", "", karambit_core::sso::limit_label(m as u32));
                    }
                }
            }
        }
        Cmd::Whoami { profile } => return cmd_whoami(&mut v, profile, cli.json),
        Cmd::Aws { cmd } => return cmd_aws(&mut v, cmd, cli.json),
        Cmd::Keys { cmd: KeysCmd::Upgrade } => {
            let (created, moved) = v.upgrade_keys()?;
            if created {
                println!("created the lock-safe agent key");
            }
            if moved.is_empty() && !created {
                println!("already up to date: agent-enabled secrets work while the screen is locked");
            }
            for n in &moved {
                println!("moved {n} to the agent key");
            }
            if !moved.is_empty() {
                println!("{} secrets now work for agents while the screen is locked (Mac must be unlocked once after boot).", moved.len());
            }
        }
        Cmd::Helper { cmd: HelperCmd::Pin { stage_daemon, stage_helper } } => {
            for (p, h) in v.helper_pin_staged(stage_daemon, stage_helper)? {
                println!("pinned {} ({}...)", p.display(), &h[..12]);
            }
            v.audit_log(0).ok();
        }
        Cmd::Launch | Cmd::DoctorHold | Cmd::AwsWhoami { .. } | Cmd::Daemon { cmd: None } => unreachable!(),
        Cmd::Agents { cmd: AgentsCmd::Discover } => {
            let home = std::env::var_os("HOME").context("HOME is not set")?;
            let mut rows = karambit_core::agent::discover::discover(std::path::Path::new(&home));
            karambit_core::agent::discover::mark_configured(&mut rows, &v.cfg);
            if cli.json { println!("{}", serde_json::to_string(&rows)?); }
            else {
                println!("KIND\tPROCESS NAMES\tEVIDENCE\tSTATUS");
                for row in rows { println!("{}\t{}\t{}\t{}", row.kind, row.process_names.join(", "), row.evidence.join("; "), if row.already_configured { "configured" } else { "new" }); }
            }
        }
        Cmd::Doctor { agent_env: _ } => doctor::run(&v.paths, &v.caller, cli.json)?,
        Cmd::Daemon { cmd: Some(DaemonCmd::Status) } => {
            use karambit_core::daemon;
            match daemon::request_if_running(&v.paths, &daemon::Req::List) {
                Some(r) => {
                    println!("running \u{b7} {} leases \u{b7} {} AWS endpoints",
                        r["leases"].as_array().map(|a| a.len()).unwrap_or(0), r["aws_endpoints"]);
                    if let Some(ping) = daemon::request_if_running(&v.paths, &daemon::Req::Ping) {
                        match (ping["build_id"].as_str(), ping["policy_sha256"].as_str()) {
                            (Some(build), Some(policy)) => println!("build {build} \u{b7} policy sha256 {policy}"),
                            _ => println!("older build: reports no build id or policy hash; it does not enforce the policy section"),
                        }
                    }
                }
                None => println!("not running (starts when needed)"),
            }
        }
        Cmd::Daemon { cmd: Some(DaemonCmd::Stop) } => {
            use karambit_core::daemon;
            if daemon::running(&v.paths.root) {
                daemon::request(&v.paths, &daemon::Req::Shutdown)?;
                println!("stopped; all leases ended");
            } else {
                println!("not running");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// External subcommands leave profile names unambiguous with management verbs.
fn validate_aws_profile(profile: &str) -> Result<()> {
    if ["add", "import", "ls", "show", "rm", "session-mint"].contains(&profile) {
        bail!("AWS profile name {profile:?} is reserved for profile management");
    }
    karambit_core::aws::entry_name(profile)?;
    Ok(())
}

fn parse_aws_command(args: &[String]) -> Result<(&str, Option<&str>, &[String])> {
    let usage = "usage: karambit aws PROFILE [--region REGION] -- COMMAND...";
    let profile = args.first().context(usage)?;
    let (region, separator) = if args.get(1).map(String::as_str) == Some("--region") {
        (Some(args.get(2).context(usage)?.as_str()), 3)
    } else { (None, 1) };
    anyhow::ensure!(args.get(separator).map(String::as_str) == Some("--") && args.len() > separator + 1, usage);
    Ok((profile, region, &args[separator + 1..]))
}

fn cli_error(error: impl std::fmt::Display) -> String {
    error.to_string().replace("karambit aws sso login", "karambit login")
        .replace("karambit aws sso logout", "karambit logout")
        .replace("karambit aws sso portals", "karambit sso ls")
        .replace("karambit aws sso", "karambit sso")
        .replace("karambit aws run", "karambit aws")
        .replace("AWS SSO login is human-only", "login is human-only")
        .replace("AWS SSO logout is human-only", "logout is human-only")
}

fn one_line_error(error: impl std::fmt::Display) -> String {
    cli_error(error).split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cmd_whoami(v: &mut Karambit, profile: Option<String>, machine: bool) -> Result<ExitCode> {
    let profile = profile.or_else(|| v.cfg.default_profile.clone());
    let Some(profile) = profile else {
        cmd_aws(v, AwsCmd::List, machine)?;
        bail!("no profile or default configured; run: karambit config default-profile NAME (or karambit whoami NAME)");
    };
    let mut fix = format!("karambit aws add {profile} --force");
    let result = (|| {
        let name = karambit_core::aws::entry_name(&profile)?;
        if !v.list(Some(&name))?.iter().any(|m| m.name == name) {
            fix = "karambit aws ls".into();
            bail!("no AWS profile {profile:?}");
        }
        let status = v.sso_status()?;
        // Active registrations already identify the portal without decrypting the profile.
        let active = status["portals"].as_array().and_then(|portals| portals.iter().find(|p| {
            p["profiles"].as_array().is_some_and(|names| names.iter().any(|n| n == &json!(name) || n == &json!(profile)))
        }));
        let detail = if active.is_none() { Some(v.aws_describe(&profile)?) } else { None };
        let portal = active.and_then(|p| p["portal"].as_str())
            .or_else(|| detail.as_ref().and_then(|d| d["portal"].as_str()));
        let context = if let Some(portal) = portal {
            fix = format!("karambit login {portal}");
            let session = status["portals"].as_array().and_then(|ps| ps.iter().find(|p| p["portal"] == portal));
            let session = session.filter(|p| p["logged_in"] == true).context("SSO portal is signed out")?;
            let until = session["renew_until"].as_u64().or_else(|| session["access_expires_at"].as_u64());
            let left = until.map(|t| format!("{:.1}h left", t.saturating_sub(karambit_core::store::now()) as f64 / 3600.0))
                .unwrap_or_else(|| "expiry unknown".into());
            format!("sso {portal}, {left}")
        } else { "static key".into() };
        let mut args = vec![std::env::current_exe()?.to_string_lossy().into_owned(), "__aws-whoami".into(), profile.clone(), context, fix.clone()];
        if machine { args.push("--json".into()); }
        // Keep credential delivery, authorization, output redaction and audit on the bound path.
        cmd_run(v, &[], None, Some(RunAws { profile: &profile, region: None }), (false, None), &args)
    })();
    result.map_err(|e| {
        let reason = one_line_error(format!("{e:#}"));
        // Helper/pin and agent-fence failures have their own fix; don't point at the profile.
        let fix = if reason.contains("pinned helper") || reason.contains("helper pin") {
            "karambit helper pin".to_string()
        } else if reason.contains("human-only") {
            "use a plain terminal (not an agent)".to_string()
        } else { fix };
        let reason = reason.split(" If you just rebuilt").next().unwrap_or(&reason).trim_end_matches('.').to_string();
        anyhow::anyhow!("{profile} ✗ {reason}; run: {fix}")
    })
}

/// Runs only as the bound target; no vault access or credential export is needed.
fn format_aws_identity(profile: &str, context: &str, fix: &str, machine: bool) -> Result<ExitCode> {
    let result = (|| -> Result<serde_json::Value> {
        let output = Command::new("aws").args(["sts", "get-caller-identity", "--output", "json"])
            .env("AWS_PAGER", "").output().context("could not start AWS CLI (install aws and retry)")?;
        if !output.status.success() {
            let reason = one_line_error(String::from_utf8_lossy(&output.stderr));
            // Give our own single-line fix, rather than triggering the generic
            // bound-run expiry hint (which would add a second, multiline error).
            if ["ExpiredToken", "RequestExpired", "security token included in the request is expired"].iter().any(|s| reason.contains(s)) {
                bail!("AWS credentials have expired");
            }
            anyhow::ensure!(!reason.is_empty(), "AWS CLI failed ({})", output.status);
            bail!("{reason}");
        }
        let identity: serde_json::Value = serde_json::from_slice(&output.stdout).context("AWS CLI returned invalid identity JSON")?;
        anyhow::ensure!(identity["Account"].is_string() && identity["Arn"].is_string(), "AWS identity missing Account or Arn");
        Ok(identity)
    })();
    match result {
        Ok(identity) => {
            if machine { print_json(&identity); }
            else {
                let account = identity["Account"].as_str().unwrap_or_default();
                let arn = identity["Arn"].as_str().unwrap_or_default();
                let role = arn.split_once(":assumed-role/").map(|(_, rest)| rest.split('/').next().unwrap_or(rest))
                    .or_else(|| arn.split_once(":user/").map(|(_, user)| user)).unwrap_or(arn);
                println!("{profile} ✓ {account} {role} ({context})");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("{profile} ✗ {}; run: {fix}", one_line_error(e));
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_aws(v: &mut Karambit, cmd: AwsCmd, json_out: bool) -> Result<ExitCode> {
    use karambit_core::aws;
    match cmd {
        AwsCmd::Import { portal, access, include, exclude, region, dry_run, yes } => {
            use karambit_core::sso::glob_matches;
            if let Some(r) = &region { karambit_core::sso::validate_region(r)?; }
            let roles = v.sso_discover(&portal)?;
            let preview = v.sso_import_preview(&portal, roles)?;
            let preview: Vec<_> = preview.into_iter().filter(|r| {
                let pair = format!("{}/{}", r.account_name, r.item.role);
                let matches = |g: &String| glob_matches(g, &r.item.name) || glob_matches(g, &pair);
                (include.is_empty() || include.iter().any(matches)) && !exclude.iter().any(matches)
            }).collect();
            println!("NAME\tACCOUNT NAME\tACCOUNT ID\tROLE\tACTION");
            for r in &preview {
                let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
                println!("{}\t{}\t{}\t{}\t{}", r.item.name, clean(&r.account_name), r.item.account_id, r.item.role, r.action);
            }
            if dry_run { return Ok(ExitCode::SUCCESS); }
            if !yes {
                use std::io::IsTerminal;
                if !std::io::stdin().is_terminal() { bail!("non-TTY import requires --yes (or --dry-run)"); }
                eprint!("Import these profiles (Touch ID required)? [y/N] ");
                std::io::stderr().flush()?;
                let mut answer = String::new(); std::io::stdin().read_line(&mut answer)?;
                if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") { return Ok(ExitCode::SUCCESS); }
            }
            let result = v.import_aws_sso(&portal, preview.into_iter().map(|r| r.item).collect(), access.0, access.1, region)?;
            println!("added {}, skipped {}", result["added"], result["skipped"]);
        }
        AwsCmd::Add { profile, region, touch, human_only, access, force, no_verify, sso, account, role, portal, session_mint } => {
            validate_aws_profile(&profile)?;
            let (touch, agent_allowed) = match access {
                Some((t, a)) => (Some(t), a),
                None => (touch, !human_only),
            };
            if sso {
                let (portal, pc) = v.sso_portal(portal.as_deref())?;
                let p = karambit_core::sso::SsoProfile {
                    portal: portal.clone(),
                    start_url: pc.start_url,
                    sso_region: pc.region,
                    account_id: account.unwrap_or_default(),
                    role_name: role.unwrap_or_default(),
                    region,
                };
                let m = v.add_aws_sso(&profile, &p, touch, agent_allowed, force)?;
                let level = if m.tier == Tier::Open { "Agents" } else if m.agent_allowed { "Agents + Touch ID" } else { "Only me + Touch ID" };
                println!("saved SSO profile {profile} · {portal}: {} / {} · {} · {level}", p.account_id, p.role_name, p.child_region());
                let signed_in = v.sso_status()?["portals"].as_array().is_some_and(|a| a.iter().any(|x| x["portal"] == json!(portal) && x["logged_in"] == json!(true)));
                if !signed_in {
                    println!("next: karambit login {portal}   (then agents can use it until that SSO session ends)");
                }
                return Ok(ExitCode::SUCCESS);
            }
            let mut text = read_aws_paste()?;
            if let Some(r) = region {
                text.push_str(&format!("\nAWS_REGION={r}\n"));
            }
            let (m, who) = v.add_aws_session_mint(&profile, &text, touch, agent_allowed, force, !no_verify, session_mint)?;
            let c = aws::parse(&text)?;
            let kind = if c.temporary() { "temporary (session token)" } else { "long-term" };
            println!("saved AWS profile {profile} [{}] · {kind}{}{}", tier_icon(m.tier).trim(),
                c.region.as_deref().map(|r| format!(" · {r}")).unwrap_or_default(),
                if session_mint { " · session-mint (runs get a 1 h STS session, not the key)" } else { "" });
            match who {
                Some(w) => println!("verified: {w}"),
                None if no_verify => {}
                None => println!("(aws CLI not found; skipped verification)"),
            }
        }
        AwsCmd::List => {
            let items: Vec<_> = v.list(Some("aws/*"))?.into_iter().filter(|m| aws::is_aws_entry(&m.name)).collect();
            if json_out {
                print_json(&json!(items));
            } else if items.is_empty() {
                println!("no AWS profiles (add one: karambit aws add PROFILE)");
            } else {
                for m in items {
                    let age = karambit_core::store::now().saturating_sub(m.updated);
                    let ago = if age < 3600 { format!("{}m ago", age / 60) } else if age < 86400 { format!("{}h ago", age / 3600) } else { format!("{}d ago", age / 86400) };
                    println!("{}  {}  {:<24} saved {ago}", tier_icon(m.tier), if m.agent_allowed { "agent" } else { "human" },
                        m.name.trim_start_matches("aws/"));
                }
            }
        }
        AwsCmd::Show { profile } => print_json(&v.aws_describe(&profile)?),
        AwsCmd::SessionMint { profile, state } => {
            validate_aws_profile(&profile)?;
            let on = state == "on";
            let word = if on { "on" } else { "off" };
            if v.aws_set_session_mint(&profile, on)? {
                println!("{profile}: session-mint {word}");
            } else {
                println!("{profile}: session-mint already {word}");
            }
        }
        AwsCmd::Profile(args) => {
            let (profile, region, command) = parse_aws_command(&args).map_err(|e| refused(explain::Code::Usage, format!("{e:#}")))?;
            return cmd_run(v, &[], None, Some(RunAws { profile, region }), (false, None), command);
        }
        AwsCmd::Rm { profile } => {
            for n in v.remove(&[aws::entry_name(&profile)?])? {
                println!("removed {n}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Read a pasted `export AWS_...` block. On a terminal: input is hidden, and we stop
/// as soon as the block is complete (no Ctrl-D needed). Piped: read all of stdin.
fn read_aws_paste() -> Result<String> {
    use karambit_core::aws;
    if !std::io::stdin().is_terminal() {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        return Ok(s);
    }
    eprintln!("Paste the credentials block (export AWS_ACCESS_KEY_ID=... etc.). Input is hidden.");
    eprintln!("Press Enter on an empty line to finish.");
    let mut all = String::new();
    loop {
        let line = Zeroizing::new(rpassword::prompt_password("")?);
        if line.trim().is_empty() {
            if all.is_empty() {
                continue;
            }
            break;
        }
        all.push_str(&line);
        all.push('\n');
        let fields = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
            .iter()
            .filter(|k| all.to_ascii_uppercase().contains(*k))
            .count();
        eprintln!("  got {fields} of 3 fields");
        if aws::is_complete(&all) && all.to_ascii_uppercase().contains("AWS_SESSION_TOKEN") {
            break;
        }
    }
    Ok(all)
}

/// `--json` anywhere before a `--` (clap's global flag), without re-parsing.
fn wants_json() -> bool {
    std::env::args().skip(1).take_while(|a| a != "--").any(|a| a == "--json")
}

/// A command line clap rejected (help and --version are not errors).
#[derive(Debug)]
struct UsageError(clap::Error);
impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}
impl std::error::Error for UsageError {}

/// The subcommand launches a command (`run`, `aws PROFILE`), judged from raw argv for
/// errors clap raised before a `Cli` existed.
fn argv_is_run() -> bool {
    let args: Vec<String> = std::env::args().skip(1).take_while(|a| a != "--").filter(|a| !a.starts_with('-')).collect();
    match args.first().map(String::as_str) {
        Some("run") => true,
        Some("aws") => args.get(1).is_some_and(|p| !["add", "import", "ls", "show", "rm", "session-mint", "help"].contains(&p.as_str())),
        _ => false,
    }
}

/// `--status-fd N` / `--status-fd=N` from raw argv, for a command line clap rejected.
fn argv_status_fd() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).take_while(|a| a != "--").collect();
    args.iter().enumerate().find_map(|(i, a)| match a.strip_prefix("--status-fd") {
        Some("") => args.get(i + 1)?.parse().ok(),
        Some(rest) => rest.strip_prefix('=')?.parse().ok(),
        None => None,
    })
}

fn main() -> ExitCode {
    // Agent guide: no vault, no daemon, no caller detection.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["help", "agent"] || args == ["--help-agent"] {
        print!("{}", agent_guide());
        return ExitCode::SUCCESS;
    }
    let json = wants_json() || env_wants_json();
    let e = match real_main() {
        Ok(c) => { status::finish_ok(); return c; }
        Err(e) => e,
    };
    if let Some(u) = e.downcast_ref::<UsageError>() {
        use clap::error::ErrorKind;
        if matches!(u.0.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand) {
            u.0.exit();
        }
        let run = argv_is_run();
        if run && let Some(fd) = argv_status_fd() && status::claim(fd).is_ok() { status::enter_run(); }
        if json || run {
            let message = u.0.render().to_string().lines().find(|l| l.starts_with("error:")).unwrap_or("bad command line")
                .trim_start_matches("error: ").to_string();
            let r = explain::Refusal::new(explain::Code::Usage, vec![], message,
                "fix the command line; see `karambit --help` or `karambit help agent`");
            status::finish_err(r.to_json());
            if json { eprintln!("{}", json!({"error": r.to_json()})); } else { let _ = u.0.print(); }
            // Before a launch, a bad command line is karambit's failure: 125, never the command's code.
            return if run { ExitCode::from(explain::EXIT_REFUSED) } else { ExitCode::from(2) };
        }
        u.0.exit();
    }
    let refusal = match e.downcast_ref::<explain::Refused>() {
        Some(r) => Some(r.0.clone()),
        // `run` / `aws PROFILE` failed before the command started: say so with exit 125.
        None if status::before_launch() => {
            let message = cli_error(format!("{e:#}"));
            let code = if message.contains("is human-only; refused") { explain::Code::HumanOnly } else { explain::Code::LaunchFailed };
            Some(explain::Refusal::new(code, vec![], message, if code == explain::Code::HumanOnly {
                "don't retry; ask the user to run the command in a plain terminal"
            } else { "the command did not start; read the message and fix the cause, don't retry in a loop" }))
        }
        None => None,
    };
    if let Some(r) = refusal {
        status::finish_err(r.to_json());
        return r.print(json);
    }
    let message = cli_error(format!("{e:#}"));
    let error = json!({"code": "error", "message": message});
    status::finish_err(error.clone());
    if json {
        eprintln!("{}", json!({"error": error}));
    } else {
        eprintln!("karambit: {message}");
    }
    ExitCode::FAILURE
}

/// Agent-usable commands, as listed at the top of `--help` (tested against the fence).
const AGENT_COMMANDS: &[(&str, &str)] = &[
    ("karambit ls --brief", "names and access levels (no values)"),
    ("karambit run -e VAR=ns/name -- CMD...", "run CMD with a secret in $VAR"),
    ("karambit run -- CMD...", "secrets from ./.karambit.env or ./.env.schema"),
    ("karambit aws PROFILE -- aws ...", "AWS (profiles: karambit aws ls)"),
    ("karambit call --list", "fixed tools; the credential stays in karambit"),
    ("karambit status", "are you detected as an agent? blocked?"),
];

/// `karambit help agent`: everything an agent needs, generated from the code tables.
fn agent_guide() -> String {
    let mut s = String::from("karambit agent guide v1\n\
You never see secret values. A program you start with `karambit run` gets them in its\n\
environment, and karambit replaces any value in its output with [REDACTED:name].\n\nUse:\n");
    let w = AGENT_COMMANDS.iter().map(|(c, _)| c.len()).max().unwrap_or(0);
    for (c, what) in AGENT_COMMANDS { s.push_str(&format!("  {c:<w$}  {what}\n")); }
    s.push_str("\nAccess (ls): public, agents = use now; agents-touch = needs temporary access from the user;\n\
me-touch = never. Never print, encode, copy or send a secret value. get, add, rm, lease grant,\n\
block, unblock and relaxing policy are human-only.\n\n\
Refused or failed before CMD started: exit 125, reason on stderr. With --json (or\n\
KARAMBIT_FORMAT=json): {\"error\":{code,next,retry,actor,ask_user?,blockers?}}.\n\
retry: no = change something first; once = one more try; after_user = wait for the user.\n\
ask_user.shell is for the user to review and run. Never run it yourself. Never loop.\n\
CMD can exit 125 too. To be sure: karambit run --status-fd 3 ... 3>&1 1>&2\n\
(stdout is then one line: {\"v\":1,\"started\":true,\"exit\":N} or started:false + error).\n\nCodes:\n");
    let w = explain::Code::ALL.iter().map(|c| c.as_str().len()).max().unwrap_or(0);
    for c in explain::Code::ALL {
        let (what, todo) = c.help();
        s.push_str(&format!("  {:<w$}  {what}: {todo}\n", c.as_str()));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};

    #[test]
    fn lease_grant_script_flag_and_script_path_suggestion() {
        let grant = |args: &[&str]| match Cli::try_parse_from([&["karambit", "lease", "grant", "a/b"], args].concat()).map(|c| c.cmd) {
            Ok(Cmd::Lease { cmd: LeaseCmd::Grant { cmd, script, .. } }) => (cmd, script),
            _ => unreachable!(),
        };
        assert_eq!(grant(&["--cmd", "node", "--script", "a.js,b.js"]), (vec!["node".into()], vec!["a.js".into(), "b.js".into()]));
        assert!(grant(&["--cmd", "curl"]).1.is_empty());

        let dir = std::env::temp_dir().join(format!("karambit-script-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("run.js");
        std::fs::write(&file, "1").unwrap();
        let file = file.to_str().unwrap().to_string();
        let command = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let canonical = std::fs::canonicalize(&file).unwrap().to_string_lossy().into_owned();
        assert_eq!(script_path(&command(&["node", &file]), Some("/usr/bin/node")), Some(canonical));
        // Inline code, a non-interpreter, or a missing script: nothing to suggest.
        assert_eq!(script_path(&command(&["node", "-e", &file]), Some("/usr/bin/node")), None);
        assert_eq!(script_path(&command(&["node", &file, "-p", "1"]), Some("/usr/bin/node")), None);
        assert_eq!(script_path(&command(&["curl", &file]), Some("/usr/bin/curl")), None);
        assert_eq!(script_path(&command(&["node", "/nonexistent/x.js"]), Some("/usr/bin/node")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn access_flag_and_legacy_aliases() {
        let add = |args: &[&str]| match Cli::try_parse_from([&["karambit", "add", "x/y"], args].concat()).map(|c| c.cmd) {
            Ok(Cmd::Add { access, touch, human_only, public, .. }) => Ok((access, touch, human_only, public)),
            Ok(_) => unreachable!(),
            Err(e) => Err(e.kind()),
        };
        let lvl = |tier, agent_allowed, public| Some(Level { tier, agent_allowed, public });
        assert_eq!(add(&["--access", "agents"]).unwrap().0, lvl(Tier::Open, true, false));
        assert_eq!(add(&["--access", "agents-touch"]).unwrap().0, lvl(Tier::Bio, true, false));
        assert_eq!(add(&["--access", "me-touch"]).unwrap().0, lvl(Tier::Bio, false, false));
        assert_eq!(add(&["--access", "public"]).unwrap().0, lvl(Tier::Open, true, true));
        assert!(add(&["--access", "me"]).is_err());
        // Old flags still parse, and can't be mixed with --access.
        assert_eq!(add(&["--touch", "off", "--human-only"]).unwrap().1, Some(Tier::Open));
        assert!(add(&["--public"]).unwrap().3);
        assert_eq!(add(&["--access", "agents", "--touch", "on"]).unwrap_err(), clap::error::ErrorKind::ArgumentConflict);
        assert!(Cli::try_parse_from(["karambit", "policy", "d/*", "--access", "agents", "--agent", "deny"]).is_err());
        assert!(Cli::try_parse_from(["karambit", "policy", "d/*", "--agent", "deny"]).is_ok());
    }

    #[test]
    fn helper_pin_stage_options_require_both_paths() {
        assert!(Cli::try_parse_from(["karambit", "helper", "pin"]).is_ok());
        assert!(Cli::try_parse_from(["karambit", "helper", "pin", "--stage-daemon", "/tmp/daemon", "--stage-helper", "/tmp/helper"]).is_ok());
        for option in ["--stage-daemon", "--stage-helper"] {
            assert!(Cli::try_parse_from(["karambit", "helper", "pin", option, "/tmp/fixture"]).is_err());
        }
    }

    /// Synthetic vault: key markers plus one Touch ID secret with placeholder ciphertext
    /// (resolve/list never decrypt). No daemon, helper or network is involved.
    fn fence_vault(label: &str, agent: bool) -> Karambit {
        let paths = karambit_core::Paths { root: std::env::temp_dir().join(format!("karambit-cli-fence-{label}-{}", std::process::id())) };
        let _ = std::fs::remove_dir_all(&paths.root);
        karambit_core::store::ensure_dir(&paths.keys()).unwrap();
        for key in ["bio.key", "open.key"] { std::fs::write(paths.keys().join(key), b"synthetic").unwrap(); }
        let file = karambit_core::SecretFile {
            v: 2, name: "test/bio".into(), tier: Tier::Bio, agent_allowed: false, public: false,
            eph: "x".into(), wrap_nonce: "x".into(), wrapped_dek: "x".into(), nonce: "x".into(), ct: "x".into(),
            backup: None, created: 0, updated: 0, key: None,
        };
        karambit_core::store::save_secret(&paths, &file).unwrap();
        let caller = karambit_core::Caller { agent: agent.then(|| "synthetic".into()), ..Default::default() };
        Karambit { paths, cfg: Default::default(), caller, run_cmd: None }
    }

    /// Every CLI-layer row of AGENT_DENIED_VERBS with the command lines that perform it.
    fn cli_cases() -> Vec<(Verb, Vec<&'static str>)> {
        vec![
            (Verb::Init, vec!["init"]),
            (Verb::Init, vec!["init", "--paper"]),
            (Verb::Add, vec!["add", "x/y"]),
            (Verb::Add, vec!["aws", "add", "p"]),
            (Verb::Add, vec!["aws", "session-mint", "p", "off"]),
            (Verb::Add, vec!["aws", "add", "p", "--sso", "--account", "111111111111", "--role", "R"]),
            (Verb::Rm, vec!["rm", "test/bio"]),
            (Verb::Rename, vec!["mv", "test/bio", "test/moved"]),
            (Verb::Rm, vec!["aws", "rm", "p"]),
            (Verb::PolicyRelax, vec!["policy", "test/bio", "--agent", "allow"]),
            (Verb::PolicyRelax, vec!["policy", "test/bio", "--touch", "off"]),
            (Verb::ConfigRelax, vec!["config", "default-tier", "off"]),
            (Verb::ConfigRelax, vec!["config", "agent-process-names", "x"]),
            (Verb::SourceAdd, vec!["source", "add", "f", "--kind", "fake", "--endpoint", "https://fake.invalid"]),
            (Verb::SourceRemove, vec!["source", "rm", "f"]),
            (Verb::SourceRetarget, vec!["source", "retarget", "f", "--credential"]),
            (Verb::SourceList, vec!["source", "ls"]),
            (Verb::ProfileTrust, vec!["profile", "trust"]),
            (Verb::Add, vec!["secure", "."]),
            (Verb::Add, vec!["eat"]),
            (Verb::Kill, vec!["kill", "--all"]),
            (Verb::Revive, vec!["revive", "--all"]),
            (Verb::Get, vec!["get", "test/bio"]),
            (Verb::Get, vec!["get", "test/bio", "--stdout"]),
            (Verb::LeaseGrant, vec!["lease", "grant", "test/bio"]),
            (Verb::KeysUpgrade, vec!["keys", "upgrade"]),
            (Verb::HelperPin, vec!["helper", "pin"]),
            (Verb::Recover, vec!["recover"]),
            (Verb::BackupRotate, vec!["backup", "rotate"]),
            (Verb::BackupVerify, vec!["backup", "verify"]),
            (Verb::DaemonStop, vec!["daemon", "stop"]),
            (Verb::SsoLogin, vec!["login"]),
            (Verb::SsoLogout, vec!["logout", "--all"]),
            (Verb::SsoImport, vec!["aws", "import", "--portal", "main"]),
            (Verb::SsoPortalAdd, vec!["sso", "portal", "add", "w", "--start-url", "https://a.awsapps.com/start", "--region", "us-east-1"]),
            (Verb::SsoPortalRemove, vec!["sso", "portal", "rm", "w"]),
            (Verb::SsoPortalLimit, vec!["sso", "portal", "limit", "w", "none"]),
        ]
    }

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("karambit").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn recover_accept_loss_takes_a_comma_list() {
        match parse(&["recover", "--accept-loss", "a/one,b/two"]).cmd {
            Cmd::Recover { identity_file: None, accept_loss } => assert_eq!(accept_loss, ["a/one", "b/two"]),
            _ => panic!("not recover"),
        }
        assert!(matches!(parse(&["recover"]).cmd, Cmd::Recover { accept_loss, .. } if accept_loss.is_empty()));
    }

    #[test]
    fn unfinished_rotation_warns_in_status_and_verify_text() {
        let r = karambit_core::store::BackupRotation { from: None, to: "age1new".into() };
        let w = rotation_warning(&r);
        assert!(w.contains("age1new") && w.contains("backup rotate") && w.contains("BOTH"));
    }

    #[test]
    fn recover_missing_label_covers_given_up_secrets_too() {
        let line = not_recovered_line(&["a/one".into(), "b/two".into()]);
        assert!(line.contains("--accept-loss") && line.contains("no usable backup copy") && line.ends_with("a/one, b/two"), "{line}");
        assert!(!line.contains("unrecoverable"));
    }

    #[test]
    fn cli_table_rows_each_have_a_command_line() {
        let covered: Vec<Verb> = cli_cases().iter().map(|(verb, _)| *verb).collect();
        for row in karambit_core::fence::AGENT_DENIED_VERBS {
            // Permanently reserved verbs have no standalone command.
            assert_eq!(row.cli, covered.contains(&row.verb) || matches!(row.verb, Verb::PaperBackup | Verb::NoRedact), "{:?}", row.verb);
        }
        // Categorical commands classify through command_verb; the conditional ones
        // (get, policy, config) and the paper ceremony are looked up at their own site.
        for (verb, args) in cli_cases() {
            let conditional = matches!(verb, Verb::Get | Verb::PolicyRelax | Verb::ConfigRelax);
            let expected = if conditional { None } else { Some(verb) };
            assert_eq!(command_verb(&parse(&args).cmd), expected, "{args:?}");
        }
    }

    #[test]
    fn agent_caller_is_refused_at_the_cli_for_every_cli_fenced_verb() {
        let v = fence_vault("agent", true);
        let before = std::fs::read(v.paths.secret("test/bio").unwrap()).unwrap();
        for (verb, args) in cli_cases() {
            let what = karambit_core::fence::AGENT_DENIED_VERBS.iter().find(|r| r.verb == verb).unwrap().what;
            let agent = Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller: v.caller.clone(), run_cmd: None };
            let error = dispatch(parse(&args), agent).err().unwrap_or_else(|| panic!("{args:?} was not refused"));
            // A refusal here means no prompt, no stdin read and no daemon request happened.
            assert_eq!(error.to_string(), karambit_core::fence::refusal(what, "synthetic"), "{args:?}");
        }
        assert_eq!(std::fs::read(v.paths.secret("test/bio").unwrap()).unwrap(), before);
        assert!(!v.paths.root.join("run").exists(), "a daemon request was attempted");
        assert!(!v.paths.audit().exists());
        std::fs::remove_dir_all(&v.paths.root).unwrap();
    }

    /// A caller that arrived over SSH is refused at the CLI for every CLI-fenced verb
    /// (no daemon request, no audit), and passes when allow_ssh_human is on.
    #[test]
    fn remote_caller_is_refused_at_the_cli_for_every_cli_fenced_verb() {
        let v = fence_vault("remote", false);
        let before = std::fs::read(v.paths.secret("test/bio").unwrap()).unwrap();
        for (verb, args) in cli_cases() {
            let what = karambit_core::fence::AGENT_DENIED_VERBS.iter().find(|r| r.verb == verb).unwrap().what;
            let caller = karambit_core::Caller { remote: true, ..Default::default() };
            let remote = Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller, run_cmd: None };
            let error = dispatch(parse(&args), remote).err().unwrap_or_else(|| panic!("{args:?} was not refused"));
            assert_eq!(error.to_string(), karambit_core::fence::remote_refusal(what), "{args:?}");
        }
        assert_eq!(std::fs::read(v.paths.secret("test/bio").unwrap()).unwrap(), before);
        assert!(!v.paths.root.join("run").exists(), "a daemon request was attempted");
        assert!(!v.paths.audit().exists());
        let allowed = karambit_core::Caller { remote: true, remote_allowed: true, ..Default::default() };
        let allowed = Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller: allowed, run_cmd: None };
        for (verb, _) in cli_cases() {
            allowed.require_human(verb, Layer::Cli).unwrap();
        }
        std::fs::remove_dir_all(&v.paths.root).unwrap();
    }

    #[test]
    fn aws_session_mint_flags_parse_and_reserve_the_subcommand_name() {
        match parse(&["aws", "add", "p", "--session-mint"]).cmd {
            Cmd::Aws { cmd: AwsCmd::Add { session_mint, .. } } => assert!(session_mint),
            _ => panic!("not aws add"),
        }
        match parse(&["aws", "add", "p"]).cmd {
            Cmd::Aws { cmd: AwsCmd::Add { session_mint, .. } } => assert!(!session_mint, "off unless asked"),
            _ => panic!("not aws add"),
        }
        assert!(Cli::try_parse_from(["karambit", "aws", "add", "p", "--sso", "--account", "111111111111", "--role", "R", "--session-mint"]).is_err());
        assert!(Cli::try_parse_from(["karambit", "aws", "session-mint", "p", "maybe"]).is_err());
        assert!(matches!(parse(&["aws", "session-mint", "p", "off"]).cmd, Cmd::Aws { cmd: AwsCmd::SessionMint { .. } }));
        assert!(validate_aws_profile("session-mint").is_err());
        assert_eq!(command_verb(&parse(&["aws", "session-mint", "p", "on"]).cmd), Some(Verb::Add));
    }

    #[test]
    fn allow_ssh_human_on_is_refused_from_a_remote_caller_at_the_cli() {
        let v = fence_vault("remote-config", false);
        let mut remote = Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller: karambit_core::Caller { remote: true, ..Default::default() }, run_cmd: None };
        let e = remote.set_config("allow-ssh-human", "on").unwrap_err();
        assert_eq!(e.to_string(), karambit_core::fence::remote_refusal("relaxing config"));
        assert!(!v.paths.root.join("run").exists(), "refused before any daemon request");
        std::fs::remove_dir_all(&v.paths.root).unwrap();
    }

    #[test]
    fn ref_check_is_offline_and_reports_invalid_lines() {
        let v = fence_vault("ref-check", true);
        assert!(source::check(&v, "test/bio", false).is_ok());
        assert!(source::check(&v, "missing:ok/a", false).is_err());
        let file = v.paths.root.join("refs.env");
        std::fs::write(&file, "# comment\nX=karambit:test/bio\nBAD LINE\nY=missing:ok/a\n").unwrap();
        assert!(source::check(&v, file.to_str().unwrap(), true).is_err());
        assert!(!v.paths.root.join("run").exists());
        assert!(!v.paths.audit().exists());
        std::fs::remove_dir_all(&v.paths.root).unwrap();
    }

    #[test]
    fn agent_cli_add_x_y_is_refused() {
        let v = fence_vault("add-xy", true);
        let error = dispatch(parse(&["add", "x/y"]), v).err().unwrap();
        assert_eq!(error.to_string(), "adding a secret is human-only; refused because caller chain includes agent (synthetic). Use the karambit GUI or a plain terminal.");
    }

    #[test]
    fn library_client_entry_points_are_fenced_for_agents_before_any_request() {
        let mut v = fence_vault("library", true);
        let refused = |e: anyhow::Error, what: &str| assert_eq!(e.to_string(), karambit_core::fence::refusal(what, "synthetic"));
        refused(v.add("x/y", b"v", None, true, false, false).unwrap_err(), "adding a secret");
        refused(v.add_aws("p", "x", None, true, false, false).unwrap_err(), "adding a secret");
        refused(v.add_aws_session_mint("p", "x", None, true, false, false, true).unwrap_err(), "adding a secret");
        refused(v.aws_set_session_mint("p", false).unwrap_err(), "adding a secret");
        refused(v.remove(&["test/bio".into()]).unwrap_err(), "removing a secret");
        refused(v.init(None).unwrap_err(), "initializing the vault");
        refused(v.set_config("default-tier", "off").unwrap_err(), "relaxing config");
        refused(v.set_policy(&["test/bio".into()], None, Some(true), None).unwrap_err(), "relaxing policy");
        refused(v.sso_logout(None).unwrap_err(), "AWS SSO logout");
        refused(v.launch_bound(vec![], vec!["/usr/bin/true".into()], std::env::temp_dir(), None, None, true).unwrap_err(), "--no-redact");
        assert!(!v.paths.root.join("run").exists(), "a daemon request was attempted");
        std::fs::remove_dir_all(&v.paths.root).unwrap();
    }

    #[test]
    fn paper_ceremony_is_fenced_independently_of_its_callers() {
        let v = fence_vault("paper", true);
        let error = paper_ceremony(&v).unwrap_err();
        assert_eq!(error.to_string(), karambit_core::fence::refusal("paper backup", "synthetic"));
    }

    #[test]
    fn human_caller_is_not_refused_by_the_cli_fence() {
        // Commands that would read stdin or prompt are checked through the lookup only.
        let v = fence_vault("human", false);
        for (verb, args) in cli_cases() {
            assert_eq!(v.require_human(verb, Layer::Cli).map_err(|e| e.to_string()), Ok(()), "{args:?}");
            let conditional = matches!(verb, Verb::Get | Verb::PolicyRelax | Verb::ConfigRelax);
            let interactive = matches!(verb, Verb::Add | Verb::SourceAdd | Verb::SourceRetarget | Verb::Init | Verb::Recover | Verb::BackupVerify | Verb::BackupRotate);
            if !conditional && !interactive && !matches!(verb, Verb::HelperPin | Verb::DaemonStop) {
                let human = Karambit { paths: v.paths.clone(), cfg: v.cfg.clone(), caller: v.caller.clone(), run_cmd: None };
                if let Err(e) = dispatch(parse(&args), human) {
                    assert!(!e.to_string().contains("is human-only; refused because caller chain"), "{args:?}: {e:#}");
                }
            }
        }
        // Tightening and policy-governed reads stay reachable for agents.
        let agent = fence_vault("agent-allowed", true);
        for args in [&["policy", "test/bio", "--touch", "on"][..], &["policy", "test/bio", "--agent", "deny"], &["config", "clip-seconds", "30"]] {
            if let Err(e) = dispatch(parse(args), Karambit { paths: agent.paths.clone(), cfg: agent.cfg.clone(), caller: agent.caller.clone(), run_cmd: None }) {
                assert!(!e.to_string().contains("is human-only"), "{args:?}: {e:#}");
            }
        }
        for args in [&["ls"][..], &["status"], &["lease", "ls"], &["lease", "revoke", "x"], &["audit"], &["daemon", "status"],
            &["aws", "ls"], &["aws", "show", "p"], &["aws", "p", "--", "true"], &["whoami", "p"],
            &["sso", "ls"], &["sso", "status"], &["run", "-e", "X=a/b", "--", "true"], &["run", "--no-redact", "-e", "X=a/b", "--", "true"]] {
            assert_eq!(command_verb(&parse(args).cmd), None, "{args:?}");
        }
        std::fs::remove_dir_all(&v.paths.root).unwrap();
        std::fs::remove_dir_all(&agent.paths.root).unwrap();
    }

    #[test]
    fn agent_guide_and_help_list_only_unfenced_commands() {
        // Every command the guide and the root help's "Agents can use" line offer must
        // pass the capability fence; placeholders get concrete values.
        let concrete = |c: &str| c.replace("VAR=ns/name", "X=a/b").replace("CMD...", "true").replace("PROFILE", "p")
            .replace("aws ...", "true").split_whitespace().skip(1).map(str::to_owned).collect::<Vec<_>>();
        let mut cases: Vec<Vec<String>> = AGENT_COMMANDS.iter().map(|(c, _)| concrete(c)).collect();
        for c in [&["lease", "ls"][..], &["env", "check"], &["ref", "check", "a/b"], &["secure", "--dry-run"], &["doctor"], &["call", "t", "j"]] {
            cases.push(c.iter().map(|s| s.to_string()).collect());
        }
        for args in cases {
            let cli = Cli::try_parse_from(std::iter::once("karambit".to_string()).chain(args.iter().cloned()))
                .unwrap_or_else(|e| panic!("{args:?}: {e}"));
            assert_eq!(command_verb(&cli.cmd), None, "{args:?} is fenced but offered to agents");
        }
        let guide = agent_guide();
        for c in explain::Code::ALL { assert!(guide.contains(c.as_str()), "guide lacks {}", c.as_str()); }
    }

    #[test]
    fn cmd_run_missing_command_guard() {
        let paths = karambit_core::Paths { root: std::env::temp_dir().join(format!("karambit-missing-command-{}", std::process::id())) };
        karambit_core::store::ensure_dir(&paths.root).unwrap();
        let mut v = Karambit { paths: paths.clone(), cfg: Default::default(), caller: Default::default(), run_cmd: None };
        let e = cmd_run(&mut v, &["X=test/ref".into()], None, None, (false, None), &[]).unwrap_err();
        assert_eq!(e.to_string(), "missing command");
        assert_eq!(e.downcast_ref::<explain::Refused>().unwrap().0.code, explain::Code::Usage);
        std::fs::remove_dir_all(paths.root).unwrap();
    }

    /// Names the Command will remove from the child's environment.
    fn removed(cmd: &Command) -> Vec<String> {
        let mut v: Vec<String> = cmd.get_envs().filter(|(_, val)| val.is_none()).map(|(k, _)| k.to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    fn ambient(names: &[&str]) -> Vec<OsString> {
        names.iter().map(OsString::from).collect()
    }

    #[test]
    fn scrub_child_env_removes_every_listed_name() {
        let mut cmd = Command::new("true");
        scrub_child_env_from(&mut cmd, [], ambient(&[]));
        let gone = removed(&cmd);
        for k in [
            "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "npm_config_proxy", "npm_config_https_proxy", "VAULT_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN",
            "BWS_ACCESS_TOKEN", "DOPPLER_TOKEN", "INFISICAL_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
        ] {
            assert!(gone.iter().any(|g| g == k), "{k} not scrubbed");
        }
        for k in karambit_core::aws::AwsCreds::env_clear() {
            assert!(gone.iter().any(|g| g == k), "{k} not scrubbed");
        }
    }

    #[test]
    fn scrub_child_env_matches_op_session_by_prefix_over_actual_environment() {
        let mut cmd = Command::new("true");
        scrub_child_env_from(&mut cmd, [], ambient(&["OP_SESSION_my", "OP_SESSION_", "OP_SESSIONX", "OP_SERVICE", "HOME", "xOP_SESSION_a"]));
        let gone = removed(&cmd);
        assert!(gone.iter().any(|g| g == "OP_SESSION_my"));
        assert!(gone.iter().any(|g| g == "OP_SESSION_"));
        for keep in ["OP_SESSIONX", "OP_SERVICE", "HOME", "xOP_SESSION_a"] {
            assert!(!gone.iter().any(|g| g == keep), "{keep} wrongly scrubbed");
        }
    }

    #[test]
    fn scrub_child_env_leaves_explicitly_injected_names_alone() {
        let mut cmd = Command::new("true");
        scrub_child_env_from(&mut cmd, ["VAULT_TOKEN", "OP_SESSION_my", "AWS_ACCESS_KEY_ID", "AWS_PROFILE"], ambient(&["OP_SESSION_my", "OP_SESSION_other"]));
        let gone = removed(&cmd);
        for k in ["VAULT_TOKEN", "OP_SESSION_my", "AWS_ACCESS_KEY_ID", "AWS_PROFILE"] {
            assert!(!gone.iter().any(|g| g == k), "{k} injected but scrubbed");
        }
        assert!(gone.iter().any(|g| g == "OP_SESSION_other"));
        assert!(gone.iter().any(|g| g == "DOPPLER_TOKEN"));
    }

    #[test]
    fn scrub_child_env_from_real_environment_scrubs_inherited_names() {
        // PATH is always set; it must never be touched.
        let mut cmd = Command::new("true");
        scrub_child_env(&mut cmd, []);
        assert!(!removed(&cmd).iter().any(|g| g == "PATH"));
        assert!(removed(&cmd).iter().any(|g| g == "VAULT_TOKEN"));
    }

    /// Spawn a real child: scrubbed names vanish, an injected (-e style) name set after
    /// the scrub survives, unrelated names pass through.
    #[test]
    fn scrubbed_child_sees_no_ambient_token_but_keeps_injected_and_unrelated() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", r#"printf '[%s][%s][%s][%s]' "${VAULT_TOKEN-unset}" "${OP_SESSION_a-unset}" "${DOPPLER_TOKEN-unset}" "${KEEP_ME-unset}""#]);
        cmd.env_clear().env("VAULT_TOKEN", "ambient").env("OP_SESSION_a", "ambient").env("DOPPLER_TOKEN", "ambient").env("KEEP_ME", "yes");
        // Model the shared owner scrub: explicit DOPPLER_TOKEN is exempt; the others are scrubbed.
        scrub_child_env_from(&mut cmd, ["DOPPLER_TOKEN"], [OsStr::new("OP_SESSION_a").to_owned()]);
        cmd.env("DOPPLER_TOKEN", "injected");
        let out = cmd.output().expect("spawn sh");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "[unset][unset][injected][yes]");
    }
}
