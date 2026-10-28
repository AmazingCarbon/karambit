//! Caller-chain detection. Walks parent processes and checks env markers to decide
//! whether an AI agent is (transitively) invoking karambit.
//!
//! This is a speed bump, not a security boundary: a hostile process can double-fork
//! to reparent onto launchd and scrub its env. The hardware boundary is the bio tier.

pub mod discover;
pub mod settings;

use crate::store::Config;
use serde::Serialize;

/// Who is asking. `agent` is the detection hit ("env:PI_CODING_AGENT", "claude");
/// `kind` is the normalized agent family ("pi", "claude", ...); `session` is the
/// kernel-derived process identity for that agent run.
#[derive(Serialize, Clone, Debug, Default)]
pub struct Caller {
    /// Nearest parent first, e.g. ["zsh", "pi", "node", "ghostty"].
    pub chain: Vec<String>,
    /// Name of the marker that matched, if any.
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Kernel identity only: "pid:1234@1790770000" (agent pid + start time).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Untrusted environment attribution, never used for authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Model the agent is running, when it exposes it (PI_MODEL, ANTHROPIC_MODEL...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Git branch of the working directory, if any (which feature branch/worktree).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Telemetry only: no agent was recognised, but the chain holds a script
    /// interpreter with no terminal/GUI ancestor. Audited as "unknown agent".
    /// Never read by `is_agent()`, `label()` or any privilege decision.
    #[serde(skip_serializing_if = "is_false")]
    pub suspect: bool,
    /// Kernel initial environment unavailable; never eligible for human caching.
    #[serde(skip_serializing_if = "is_false")]
    pub env_unknown: bool,
    /// Arrived over SSH: an sshd ancestor, or SSH_CONNECTION/SSH_TTY in the environment.
    /// `ssh localhost karambit ...` has no agent in its chain, so without this it would
    /// pass for the human at the keyboard. Human-only verbs refuse it (see `fence`).
    #[serde(skip_serializing_if = "is_false")]
    pub remote: bool,
    /// Config `allow_ssh_human` at detection time: lets a remote caller do human-only
    /// verbs. Not an identity fact, so never serialized.
    #[serde(skip)]
    pub remote_allowed: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Caller {
    pub fn is_agent(&self) -> bool {
        self.agent.is_some()
    }
    /// Short label for Touch ID prompts / audit, e.g. "pi" or "zsh".
    pub fn label(&self) -> String {
        self.kind
            .clone()
            .or_else(|| self.agent.clone())
            .or_else(|| self.chain.first().cloned())
            .unwrap_or_else(|| "unknown".into())
    }
    /// For callers that are known not to be agents (the GUI launched by launchd).
    pub fn gui() -> Caller {
        Caller { chain: vec!["karambit-gui".into()], ..Default::default() }
    }
}

/// Env marker -> (agent kind, env var that holds a session id for that agent).
const ENV_KINDS: &[(&str, &str, Option<&str>)] = &[
    ("PI_CODING_AGENT", "pi", Some("PI_SESSION_ID")),
    ("CLAUDECODE", "claude", Some("CLAUDE_SESSION_ID")),
    ("CLAUDE_CODE_ENTRYPOINT", "claude", Some("CLAUDE_SESSION_ID")),
    ("CODEX_SANDBOX", "codex", None),
    ("CURSOR_AGENT", "cursor", None),
    ("AIDER_MODEL", "aider", None),
    ("GEMINI_CLI", "gemini", None),
    ("OPENCODE", "opencode", None),
];

/// Bounded printable attribution only. Values are self-asserted even when read
/// from a kernel snapshot; keep them separate from the session authority field.
pub(crate) fn session_label(kind: Option<&str>, mut get: impl FnMut(&str) -> Option<String>) -> Option<String> {
    let kind = kind?;
    ENV_KINDS.iter().filter(|(_, k, _)| *k == kind).find_map(|(_, _, var)| {
        let value = get((*var)?)?;
        if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) { return None; }
        Some(format!("{kind}:{value}"))
    })
}

fn normalize_kind(hit: &str) -> String {
    let h = hit.to_lowercase();
    for (m, kind, _) in ENV_KINDS {
        if h == format!("env:{}", m.to_lowercase()) {
            return kind.to_string();
        }
    }
    match h.as_str() {
        "kiro-cli" | "kiro-cli-chat" => "kiro".into(),
        "cn" => "continue".into(),
        "q" => "amazon-q".into(),
        "cursor-agent" => "cursor".into(),
        "hermes-agent" | "hermes-acp" => "hermes".into(),
        other => other.trim_start_matches("env:").to_string(),
    }
}

/// First candidate (comm, path segment, argv word) that names a known agent.
/// `names` must already be lowercase; the comparison is case-insensitive, so a process
/// titled "Hermes" matches the default "hermes".
fn find_agent_hit(candidates: &[String], names: &[String]) -> Option<String> {
    candidates.iter().find(|c| names.contains(&c.to_lowercase())).cloned()
}

/// comm, exec path segments and the first words of argv[0..2] as match candidates.
/// `args` = [exec_path, argv0, argv1, ...].
#[cfg(any(target_os = "macos", test))]
pub(crate) fn build_candidates(comm: &str, args: &[String]) -> Vec<String> {
    let mut cands = vec![comm.to_string()];
    for a in args.iter().take(3) {
        cands.extend(a.split('/').filter(|s| !s.is_empty()).map(String::from));
        // `claude --flag` style argv0 with spaces from process.title
        if let Some(first) = a.split_whitespace().next() {
            cands.push(first.rsplit('/').next().unwrap_or(first).to_string());
        }
    }
    cands
}

/// One process in the caller chain, reduced to what the `suspect` heuristic needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hop {
    interpreter: bool,
    /// A terminal app, multiplexer/login daemon, or a launchd-started .app GUI.
    anchored: bool,
}

const INTERPRETERS: &[&str] = &["node", "ruby", "perl"];
const TERMINALS: &[&str] = &[
    "terminal", "iterm2", "ghostty", "kitty", "alacritty", "wezterm", "wezterm-gui", "warp",
    "hyper", "tabby", "tmux", "screen", "zellij", "sshd", "login",
];

/// The SSH server process (`sshd`, or `sshd-session` on newer OpenSSH).
fn is_ssh_server(comm: &str, exe_name: &str) -> bool {
    [comm, exe_name].iter().any(|n| n.to_lowercase().starts_with("sshd"))
}

/// Environment names that only an SSH login sets.
const SSH_ENV_MARKERS: &[&str] = &["SSH_CONNECTION", "SSH_TTY"];

fn is_interpreter(name: &str) -> bool {
    let n = name.to_lowercase();
    INTERPRETERS.contains(&n.as_str())
        || n.strip_prefix("python").is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// `comm` and `exe_name` (basename of the executable) identify the process itself;
/// `app_bundle` = the executable lives in `X.app/Contents/`.
fn classify(comm: &str, exe_name: &str, app_bundle: bool) -> Hop {
    let terminal = [comm, exe_name].iter().any(|n| TERMINALS.contains(&n.to_lowercase().as_str()));
    Hop { interpreter: is_interpreter(comm) || is_interpreter(exe_name), anchored: terminal || app_bundle }
}

/// Nearest-first chain: suspect when some interpreter has no terminal/GUI above it.
fn chain_is_suspect(hops: &[Hop]) -> bool {
    hops.iter().enumerate().any(|(i, h)| h.interpreter && !hops[i + 1..].iter().any(|a| a.anchored))
}

pub fn detect(cfg: &Config) -> Caller {
    let names: Vec<String> = cfg.agent_process_names.iter().map(|s| s.to_lowercase()).collect();
    let mut hops = Vec::new();
    let mut chain = Vec::new();
    let mut agent = None;
    let mut agent_proc: Option<(i32, u64)> = None;
    let mut remote = SSH_ENV_MARKERS.iter().any(|m| std::env::var_os(m).is_some());

    for m in &cfg.agent_env_markers {
        if std::env::var_os(m).is_some() {
            agent = Some(format!("env:{m}"));
            break;
        }
    }

    let mut pid = unsafe { libc::getppid() };
    for _ in 0..64 {
        if pid <= 1 {
            break;
        }
        let Some(p) = sys::info(pid) else { break };
        chain.push(p.display.clone());
        hops.push(classify(&p.comm, &p.exe_name, p.app_bundle));
        remote |= is_ssh_server(&p.comm, &p.exe_name);
        if let Some(hit) = find_agent_hit(&p.candidates, &names) {
            if agent.is_none() {
                agent = Some(hit);
            }
            // Nearest agent process in the chain = the agent run we're inside.
            if agent_proc.is_none() {
                agent_proc = Some((pid, p.start));
            }
        }
        pid = p.ppid;
    }

    let kind = agent.as_deref().map(normalize_kind);
    let session_label = session_label(kind.as_deref(), |key| std::env::var(key).ok());
    let session = agent_proc.map(|(p, t)| format!("pid:{p}@{t}"));
    let cwd = std::env::current_dir().ok().map(|d| {
        let s = d.to_string_lossy().into_owned();
        match std::env::var("HOME") {
            Ok(h) if s.starts_with(&h) => format!("~{}", &s[h.len()..]),
            _ => s,
        }
    });
    let model = ["PI_MODEL", "ANTHROPIC_MODEL", "CLAUDE_MODEL", "OPENAI_MODEL", "CODEX_MODEL", "AIDER_MODEL", "GEMINI_MODEL"]
        .iter()
        .filter(|_| agent.is_some())
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
        .map(|m| m.chars().take(80).collect());
    let suspect = agent.is_none() && chain_is_suspect(&hops);
    Caller { chain, agent, kind, session, session_label, pid: agent_proc.map(|(p, _)| p), cwd, model, branch: git_branch(), suspect, env_unknown: false, remote, remote_allowed: cfg.allow_ssh_human }
}

/// Kernel-only identity for a socket peer (used by the daemon). Nothing here comes
/// from client RPC fields. Initial environment markers are read from the kernel;
/// ancestry detection is retained if that read is unavailable.
/// `ancestors` = [(pid, start_secs)] from the peer upward, for session-tree checks.
#[derive(Clone, Debug, Default)]
pub struct Peer {
    pub caller: Caller,
    pub pid: i32,
    pub ancestors: Vec<(i32, u64)>,
    /// Selected only by detect_peer from kernel executable paths. Never deserialized.
    pub anchor: Option<(i32, u64)>,
    /// Real executable path of the peer process itself (e.g. /opt/homebrew/bin/aws).
    pub exe: Option<String>,
}

/// Marker that `.cargo/config.toml` puts in every test process's initial environment.
/// Tests that need an agent caller list it in their config; the kernel-read initial
/// environment is what `detect_peer` inspects, so it cannot be set from inside a test.
#[cfg(test)]
pub(crate) const SYNTHETIC_AGENT_MARKER: &str = "KARAMBIT_SYNTHETIC_AGENT";

pub fn detect_peer(cfg: &Config, peer_pid: i32) -> Peer {
    let names: Vec<String> = cfg.agent_process_names.iter().map(|s| s.to_lowercase()).collect();
    let mut chain = Vec::new();
    let mut hops = Vec::new();
    let mut ancestors = Vec::new();
    let mut anchor = None;
    let mut agent = None;
    let mut agent_proc: Option<(i32, u64)> = None;
    let mut remote = false;
    let mut pid = peer_pid;
    for depth in 0..64 {
        if pid <= 1 {
            break;
        }
        let Some(p) = sys::info(pid) else { break };
        ancestors.push((pid, p.start));
        if anchor.is_none() && sys::exe(pid).is_some_and(|exe| human_anchor_executable(&exe)) {
            anchor = Some((pid, p.start));
        }
        if depth > 0 {
            chain.push(p.display.clone());
            hops.push(classify(&p.comm, &p.exe_name, p.app_bundle));
            remote |= is_ssh_server(&p.comm, &p.exe_name);
            if let Some(hit) = find_agent_hit(&p.candidates, &names) {
                if agent.is_none() {
                    agent = Some(hit);
                }
                if agent_proc.is_none() {
                    agent_proc = Some((pid, p.start));
                }
            }
        }
        pid = p.ppid;
    }
    // Detection reads only marker names; labels below are separate untrusted telemetry.
    // A failed read must not erase an ancestry hit.
    let markers = sys::env_names(peer_pid);
    let env_unknown = markers.is_none();
    remote |= markers.as_ref().is_some_and(|m| SSH_ENV_MARKERS.iter().any(|s| m.iter().any(|n| n == s)));
    if let Some(markers) = markers
        && let Some(marker) = cfg.agent_env_markers.iter().find(|m| markers.contains(m)) {
        agent = Some(format!("env:{marker}"));
    }
    let kind = agent.as_deref().map(normalize_kind);
    let session = agent_proc.map(|(p, t)| format!("pid:{p}@{t}"));
    let session_label = sys::session_label(peer_pid, kind.as_deref());
    let abs = sys::cwd(peer_pid);
    let cwd = abs.clone().map(|s| match std::env::var("HOME") {
        Ok(h) if s.starts_with(&h) => format!("~{}", &s[h.len()..]),
        _ => s,
    });
    let branch = abs.and_then(|d| git_branch_at(std::path::PathBuf::from(d)));
    let suspect = agent.is_none() && chain_is_suspect(&hops);
    Peer {
        caller: Caller { chain, agent, kind, session, session_label, pid: agent_proc.map(|(p, _)| p), cwd, model: None, branch, suspect, env_unknown, remote, remote_allowed: cfg.allow_ssh_human },
        pid: peer_pid,
        ancestors,
        anchor,
        exe: sys::exe(peer_pid),
    }
}

impl Peer {
    /// Is (root_pid, root_start) this peer or one of its ancestors?
    pub fn descends_from(&self, root: (i32, u64)) -> bool {
        self.ancestors.contains(&root)
    }
    /// Nearest kernel-resolved terminal application or Karambit GUI, never a shell,
    /// multiplexer, login process, arbitrary app bundle, or launchd.
    pub fn human_anchor(&self) -> Option<(i32, u64)> {
        self.anchor.filter(|_| !self.caller.env_unknown).filter(|&(pid, start)| pid > 1 && self.descends_from((pid, start)))
    }
    /// Absolute cwd for scope checks.
    pub fn cwd_abs(&self) -> Option<String> {
        sys::cwd(self.pid)
    }
}

pub(crate) use crate::platform::{ProcessIdentity, process_identity, process_parent_identity};

pub fn proc_start(pid: i32) -> Option<u64> {
    sys::info(pid).map(|p| p.start)
}

pub fn proc_cwd(pid: i32) -> Option<String> {
    sys::cwd(pid)
}

pub fn proc_exe(pid: i32) -> Option<String> {
    sys::exe(pid)
}

/// Names (including applev) of `pid`'s initial environment; None if unreadable.
pub(crate) fn proc_env_names(pid: i32) -> Option<Vec<String>> {
    sys::env_names(pid)
}

/// Current branch from .git/HEAD, walking up from cwd. No git binary needed.
/// Handles worktrees (`.git` file with `gitdir:`).
fn git_branch() -> Option<String> {
    git_branch_at(std::env::current_dir().ok()?)
}

fn git_branch_at(mut d: std::path::PathBuf) -> Option<String> {
    for _ in 0..40 {
        let g = d.join(".git");
        let head = if g.is_dir() {
            std::fs::read_to_string(g.join("HEAD")).ok()
        } else if g.is_file() {
            let t = std::fs::read_to_string(&g).ok()?;
            let gd = t.trim().strip_prefix("gitdir:")?.trim().to_string();
            let gd = if std::path::Path::new(&gd).is_absolute() { std::path::PathBuf::from(gd) } else { d.join(gd) };
            std::fs::read_to_string(gd.join("HEAD")).ok()
        } else {
            None
        };
        if let Some(h) = head {
            let h = h.trim();
            return Some(match h.strip_prefix("ref: refs/heads/") {
                Some(b) => b.to_string(),
                None => format!("detached@{}", h.chars().take(8).collect::<String>()),
            });
        }
        if !d.pop() {
            break;
        }
    }
    None
}

/// Parse environment/applev names only from the bounded KERN_PROCARGS2 snapshot.
/// Invalid/truncated snapshots are unknown, never evidence that a marker is absent.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn procargs_env_names(buf: &[u8]) -> Option<Vec<String>> {
    procargs_environment(buf, |_, _| {})
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn procargs_environment(buf: &[u8], mut entry_fn: impl FnMut(&str, &[u8])) -> Option<Vec<String>> {
    if !(4..=1024 * 1024).contains(&buf.len()) { return None; }
    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?);
    if !(1..=65536).contains(&argc) { return None; }
    fn take<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
        let end = rest.iter().position(|&b| b == 0)?;
        if end > 65536 { return None; }
        let word = &rest[..end];
        *rest = &rest[end + 1..];
        Some(word)
    }
    let mut rest = &buf[4..];
    let path_len = take(&mut rest)?.len();
    if path_len == 0 { return None; }
    // KERN_PROCARGS2 aligns the exec-path region (excluding argc) to 8 bytes.
    // Do not skip arbitrary zero bytes: argv[0] is allowed to be empty.
    let argv_start = 4 + (path_len + 1).checked_next_multiple_of(8)?;
    if buf.get(4 + path_len + 1..argv_start)?.iter().any(|&b| b != 0) { return None; }
    rest = buf.get(argv_start..)?;
    for _ in 0..argc { take(&mut rest)?; }
    let mut names = Vec::new();
    // Include applev names as a conservative superset; empty env words are not
    // a reliable boundary and must not hide markers later in the snapshot.
    while !rest.is_empty() {
        let entry = take(&mut rest)?;
        if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            let name = std::str::from_utf8(&entry[..eq]).ok()?;
            entry_fn(name, &entry[eq + 1..]);
            names.push(name.to_owned());
        }
    }
    // A readable snapshot always carries applev assignments (executable_path=...).
    // None after argv means the kernel hid env+applev (SIP/platform binaries): unknown.
    (!names.is_empty()).then_some(names)
}

use crate::platform::process as sys;

#[cfg(test)]
mod tests {
    use super::*;

    fn default_names() -> Vec<String> {
        Config::default().agent_process_names.iter().map(|s| s.to_lowercase()).collect()
    }

    fn hit_kind(comm: &str, args: &[&str]) -> Option<String> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        find_agent_hit(&build_candidates(comm, &args), &default_names()).map(|h| normalize_kind(&h))
    }

    /// Shape of the audited chain ["bash","python3","Hermes"]: the Hermes app process, and
    /// the python3 child whose argv names the /hermes-agent/ checkout.
    #[test]
    fn hermes_chain_is_detected_as_kind_hermes() {
        assert_eq!(
            hit_kind("python3", &["/opt/homebrew/bin/python3", "python3", "/home/u/.hermes/hermes-agent/run_agent.py"]).as_deref(),
            Some("hermes"),
            "path segment /hermes-agent/ in argv"
        );
        assert_eq!(hit_kind("Hermes", &["/Applications/Hermes.app/Contents/MacOS/Hermes", "Hermes"]).as_deref(), Some("hermes"), "case-insensitive comm");
        assert_eq!(hit_kind("python3", &["/x/python3", "python3", "/x/hermes-acp"]).as_deref(), Some("hermes"));
        assert_eq!(hit_kind("bash", &["/bin/bash", "bash", "-lc"]), None, "the bash hop alone is not an agent");
    }

    #[test]
    fn plain_shell_chain_is_not_agent_or_suspect() {
        assert_eq!(hit_kind("zsh", &["/bin/zsh", "-zsh"]), None);
        let ghostty = classify("ghostty", "ghostty", true);
        let zsh = classify("zsh", "zsh", false);
        assert!(!chain_is_suspect(&[zsh, ghostty]));
        assert!(!chain_is_suspect(&[]));
    }

    #[test]
    fn suspect_requires_interpreter_without_terminal_or_gui_ancestor() {
        let bash = classify("bash", "bash", false);
        let py = classify("python3", "python3", false);
        let node = classify("node", "node", false);
        let term = classify("Terminal", "Terminal", true);
        let gui = classify("SomeApp", "SomeApp", true);
        // The audited shape: bash <- python3 <- nothing anchored.
        assert!(chain_is_suspect(&[bash, py, bash]));
        assert!(chain_is_suspect(&[bash, node]));
        assert!(chain_is_suspect(&[classify("Python", "Python3.12", false)]));
        // A human script run from a terminal, or under a launchd-started .app.
        assert!(!chain_is_suspect(&[py, bash, term]));
        assert!(!chain_is_suspect(&[py, bash, gui]));
        assert!(!chain_is_suspect(&[node, classify("tmux", "tmux", false)]));
        // An interpreter is not its own anchor.
        assert!(chain_is_suspect(&[classify("Python", "Python", true)]));
        assert!(!is_interpreter("pythonista") && !is_interpreter("nodemon"));
    }

    #[test]
    fn suspect_is_telemetry_only() {
        let suspect = Caller { chain: vec!["bash".into(), "python3".into()], suspect: true, ..Default::default() };
        assert!(!suspect.is_agent());
        assert_eq!(suspect.label(), "bash");
        assert!(suspect.kind.is_none() && suspect.agent.is_none());
        let clean = Caller::default();
        assert!(serde_json::to_value(&clean).unwrap().get("suspect").is_none());
        assert_eq!(serde_json::to_value(&suspect).unwrap()["suspect"], true);
    }
}

fn human_anchor_executable(exe: &str) -> bool {
    let name = std::path::Path::new(exe).file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
    (TERMINALS.contains(&name.as_str()) && !["tmux", "screen", "zellij", "sshd", "login"].contains(&name.as_str()))
        || exe.ends_with("/Karambit.app/Contents/MacOS/karambit-gui")
}

#[cfg(test)]
mod anchor_tests {
    use super::*;
    #[test]
    fn only_supported_terminal_or_karambit_executables_anchor() {
        for path in ["/Applications/iTerm.app/Contents/MacOS/iTerm2", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "/Applications/Karambit.app/Contents/MacOS/karambit-gui", "/opt/homebrew/bin/kitty"] {
            assert!(human_anchor_executable(path));
        }
        for path in ["/Applications/Other.app/Contents/MacOS/other", "/bin/zsh", "/sbin/launchd", "/usr/bin/login", "/opt/homebrew/bin/tmux"] {
            assert!(!human_anchor_executable(path));
        }
        let peer = Peer { anchor: Some((10, 20)), ancestors: vec![(10, 21)], ..Default::default() };
        assert_eq!(peer.human_anchor(), None);
    }
}

#[cfg(test)]
mod peer_env_tests {
    use super::*;

    #[test]
    fn procargs_environment_parser_is_bounded_and_skips_all_arguments() {
        let label = session_label(Some("pi"), |key| (key == "PI_SESSION_ID").then(|| "synthetic-session".into()));
        assert_eq!(label.as_deref(), Some("pi:synthetic-session"));
        assert_eq!(session_label(Some("pi"), |_| Some("bad\nlabel".into())), None);
        let label_snapshot = snapshot(b"/bin/tool", 1, b"tool\0PI_SESSION_ID=synthetic-session\0");
        let mut extracted = None;
        procargs_environment(&label_snapshot, |name, bytes| {
            if name == "PI_SESSION_ID" { extracted = std::str::from_utf8(bytes).ok().map(str::to_owned); }
        }).unwrap();
        assert_eq!(extracted.as_deref(), Some("synthetic-session"));
        let mut buf = snapshot(b"/bin/tool", 4, b"tool\0arg\0PI_CODING_AGENT=fake-argument\0last\0PI_CODING_AGENT=1\0EMPTY=\0OTHER=a=b\0\0");
        assert_eq!(procargs_env_names(&buf).unwrap(), ["PI_CODING_AGENT", "EMPTY", "OTHER"]);
        buf.extend_from_slice(b"unterminated");
        assert!(procargs_env_names(&buf).is_none());
        assert!(procargs_env_names(&[]).is_none());
        assert!(procargs_env_names(&vec![0; 1024*1024+1]).is_none());
        buf[..4].copy_from_slice(&(-1i32).to_ne_bytes());
        assert!(procargs_env_names(&buf).is_none());
    }

    fn snapshot(path: &[u8], argc: i32, words: &[u8]) -> Vec<u8> {
        let mut buf = argc.to_ne_bytes().to_vec();
        buf.extend_from_slice(path);
        buf.resize(4 + (path.len() + 1).next_multiple_of(8), 0);
        buf.extend_from_slice(words);
        buf
    }

    #[test]
    fn procargs_empty_words_cannot_hide_markers() {
        for argv in [b"tool\0".as_slice(), b"\0"] {
            let mut words = argv.to_vec();
            words.extend_from_slice(b"\0PI_CODING_AGENT=1\0\0executable_path=/synthetic\0ignored\0\0");
            for len in [10, 15, 16] {
                let buf = snapshot(&vec![b'x'; len], 1, &words);
                assert!(procargs_env_names(&buf).unwrap().iter().any(|n| n == "PI_CODING_AGENT"));
            }
        }
        // The original unaligned counterexamples must never be known marker-free.
        for words in [b"/bin/tool\0\0tool\0\0PI_CODING_AGENT=1\0\0".as_slice(), b"/bin/tool\0\0\0PI_CODING_AGENT=1\0\0"] {
            let mut buf = 1i32.to_ne_bytes().to_vec();
            buf.extend_from_slice(words);
            assert!(procargs_env_names(&buf).is_none_or(|names| names.iter().any(|n| n == "PI_CODING_AGENT")));
        }
        let mut buf = snapshot(b"/bin/tool", 1, b"tool\0\0MARKER=1\0");
        buf[14] = 1;
        assert!(procargs_env_names(&buf).is_none());
        assert!(procargs_env_names(&snapshot(b"/bin/tool", 1, b"tool\0\0BAD\xff=1\0")).is_none());
        assert!(procargs_env_names(&snapshot(b"/bin/tool", 2, b"tool\0")).is_none());
        assert!(procargs_env_names(&snapshot(b"/bin/tool", 1, &vec![b'x'; 65538])).is_none());
        // Argv-only snapshot (observed for SIP/platform binaries) is unavailable, not empty.
        assert!(procargs_env_names(&snapshot(b"/bin/tool", 1, b"tool\0")).is_none());
        assert!(procargs_env_names(&snapshot(b"/bin/tool", 1, b"tool\0\0\0\0")).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hidden_platform_environment_is_unknown() {
        let mut child = std::process::Command::new("/bin/sleep").arg("30")
            .env_clear().env("KARAMBIT_SYNTHETIC_AGENT", "1").spawn().unwrap();
        let cfg = Config { agent_env_markers: vec!["KARAMBIT_SYNTHETIC_AGENT".into()], ..Config::default() };
        let peer = detect_peer(&cfg, child.id() as i32);
        // Whether macOS hides a platform binary's environment depends on the host
        // (System Integrity Protection; it is off on GitHub's macOS runners).
        let visible = sys::env_names(child.id() as i32).is_some();
        let _ = child.kill();
        let _ = child.wait();
        if visible {
            // Readable environment: detection must use it, not report it unknown.
            assert!(!peer.caller.env_unknown, "readable platform env must not be unknown");
            assert_eq!(peer.caller.agent.as_deref(), Some("env:KARAMBIT_SYNTHETIC_AGENT"));
        } else {
            assert!(peer.caller.env_unknown, "hidden platform env must be unknown");
        }
    }

    #[test]
    fn unavailable_environment_disables_human_anchor() {
        let mut peer = Peer { anchor: Some((10, 20)), ancestors: vec![(10, 20)], ..Default::default() };
        assert_eq!(peer.human_anchor(), Some((10, 20)));
        peer.caller.env_unknown = true;
        assert!(!peer.caller.is_agent());
        assert_eq!(peer.human_anchor(), None);
    }

    #[test]
    fn sshd_processes_mark_the_chain_remote() {
        assert!(is_ssh_server("sshd", "sshd"));
        assert!(is_ssh_server("sshd-session", "sshd-session"));
        assert!(is_ssh_server("SSHD", ""));
        assert!(is_ssh_server("", "sshd-auth"));
        assert!(!is_ssh_server("ssh", "ssh") && !is_ssh_server("zsh", "zsh") && !is_ssh_server("ssh-agent", "ssh-agent"));
    }

    #[test]
    fn remote_is_audited_and_default_is_not_serialized() {
        assert!(serde_json::to_value(Caller::default()).unwrap().get("remote").is_none());
        let remote = Caller { remote: true, remote_allowed: true, ..Default::default() };
        let v = serde_json::to_value(&remote).unwrap();
        assert_eq!(v["remote"], true);
        assert!(v.get("remote_allowed").is_none(), "the allow flag is policy, not identity");
        assert!(!remote.is_agent());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn peer_ssh_environment_marks_the_peer_remote() {
        let dir = std::env::temp_dir().join(format!("karambit-peer-ssh-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("spin.c");
        let exe = dir.join("spin");
        std::fs::write(&source, "#include <unistd.h>\nint main(void) { sleep(30); return 0; }\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/cc").arg(&source).arg("-o").arg(&exe).status().unwrap().success());
        // This test may itself run under an agent: detect against empty agent lists.
        let cfg = Config { agent_process_names: vec![], agent_env_markers: vec![], ..Config::default() };
        for (var, expect) in [("SSH_CONNECTION", true), ("SSH_TTY", true), ("UNRELATED", false)] {
            let mut child = std::process::Command::new(&exe).env_clear().env(var, "synthetic").spawn().unwrap();
            let peer = detect_peer(&cfg, child.id() as i32);
            let _ = child.kill();
            let _ = child.wait();
            assert_eq!(peer.caller.remote, expect, "{var}");
            assert!(!peer.caller.is_agent(), "ssh alone is not an agent");
            assert!(!peer.caller.remote_allowed);
        }
        let allow = Config { allow_ssh_human: true, ..cfg.clone() };
        let mut child = std::process::Command::new(&exe).env_clear().env("SSH_TTY", "synthetic").spawn().unwrap();
        let peer = detect_peer(&allow, child.id() as i32);
        let _ = child.kill();
        let _ = child.wait();
        assert!(peer.caller.remote && peer.caller.remote_allowed);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn peer_initial_environment_marker_is_kernel_read() {
        let dir = std::env::temp_dir().join(format!("karambit-peer-env-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("spin.c");
        let exe = dir.join("spin");
        std::fs::write(&source, "#include <unistd.h>\nint main(void) { sleep(30); return 0; }\n").unwrap();
        let status = std::process::Command::new("/usr/bin/cc").arg(&source).arg("-o").arg(&exe).status().unwrap();
        assert!(status.success());
        let mut child = std::process::Command::new(exe)
            .env_clear().env("KARAMBIT_SYNTHETIC_AGENT", "1").spawn().unwrap();
        // Command::spawn waits for exec; use a unique synthetic marker, never read
        // or print the invoking process's environment values.
        let cfg = Config { agent_env_markers: vec!["KARAMBIT_SYNTHETIC_AGENT".into()], ..Config::default() };
        let peer = detect_peer(&cfg, child.id() as i32);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(peer.caller.agent.as_deref(), Some("env:KARAMBIT_SYNTHETIC_AGENT"));
        std::fs::remove_dir_all(dir).unwrap();
        assert!(!peer.caller.env_unknown);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod process_identity_tests {
    use super::*;

    #[test]
    fn full_process_identity_preserves_parent_relation() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
        }
        let child = Child(std::process::Command::new("/bin/sleep").arg("10").spawn().unwrap());
        let identity = process_identity(child.0.id() as i32).unwrap();
        assert_eq!(process_parent_identity(identity).unwrap(), process_identity(std::process::id() as i32).unwrap());
        assert_eq!(process_identity(identity.pid).unwrap(), identity);
        assert!(process_parent_identity(ProcessIdentity { usec: identity.usec + 1, ..identity }).is_err());
        assert!(process_parent_identity(ProcessIdentity { sec: identity.sec + 1, ..identity }).is_err());
    }
}
