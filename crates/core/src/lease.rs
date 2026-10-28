//! Lease types. Leases themselves live only in the daemon's memory (see daemon.rs):
//! the unwrapped DEK, who it's for, when it ends, and its scope. Nothing on disk.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::agent::Caller;
use crate::store::Paths;

pub const MAX_HOURS: f64 = 24.0 * 7.0;

/// Who a lease is for.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase", tag = "type", content = "value")]
pub enum Grantee {
    /// Any agent caller.
    Any,
    /// One agent family, e.g. "pi", "claude" (kernel-detected from the process tree).
    Kind(String),
    /// One running agent process and its descendants: "pid:1234@<start>".
    Session(String),
    /// Human cache: daemon-observed Bio unwrap, bound to a kernel terminal/GUI
    /// ancestor (pid + start), for at most 3 hours or until screen lock/revoke.
    /// Same-anchor undetected agents remain a limit; this tag alone grants nothing.
    Human,
}

impl Grantee {
    pub fn parse(s: &str) -> Result<Grantee> {
        let s = s.trim();
        if s.is_empty() || s == "any" || s == "*" {
            return Ok(Grantee::Any);
        }
        if let Some(rest) = s.strip_prefix("session:") {
            if rest.is_empty() {
                bail!("session: needs an id (see `karambit audit` for session ids)");
            }
            return Ok(Grantee::Session(rest.to_string()));
        }
        if s.contains(':') {
            return Ok(Grantee::Session(s.to_string()));
        }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            bail!("agent kind must be a plain name like pi, claude, codex");
        }
        Ok(Grantee::Kind(s.to_lowercase()))
    }

    /// Kind/Any coverage for a caller (session coverage needs the process tree,
    /// which only the daemon checks).
    pub fn covers(&self, c: &Caller) -> bool {
        match self {
            Grantee::Human => !c.is_agent(), // Eligibility only; the daemon additionally checks the anchor.
            _ if !c.is_agent() => false,
            Grantee::Any => true,
            Grantee::Kind(k) => c.kind.as_deref() == Some(k.as_str()),
            Grantee::Session(s) => c.session.as_deref() == Some(s.as_str()),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Grantee::Any => "any agent".into(),
            Grantee::Kind(k) => format!("{k} agents"),
            Grantee::Session(s) => format!("session {s}"),
            Grantee::Human => "you (human)".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LeaseInfo {
    pub name: String,
    pub to: Grantee,
    pub to_label: String,
    pub granted: u64,
    pub expires: u64,
    pub remaining: u64,
    pub by: String,
}

/// Where pre-daemon builds kept lease files; removed by the daemon on start.
pub fn dir(p: &Paths) -> PathBuf {
    p.root.join("leases")
}

/// Wire grant requests may name a command. Held grants contain only daemon-derived
/// canonical paths and hashes. Legacy name-only entries remain decodable so they
/// can be explicitly refused at use, never interpreted as wildcard permissions.
///
/// `Script` is an (interpreter, script) pair: the launch target must be that
/// interpreter and argv[1] that exact script. It is listed first because untagged
/// decoding tries variants in order and `Pinned` would otherwise swallow it, dropping
/// the script. Old name/pinned JSON has no `script` key and still decodes as before.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum CommandBinding {
    Script { path: String, sha256: String, script: String, script_sha256: String },
    Name(String),
    Pinned { path: String, sha256: String },
}

/// Program names that run whatever code they are handed (`node -e`, `python -c`).
/// A bare one as a command scope would be close to no limit, so it needs `--script`.
const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "python", "ruby", "perl", "php", "deno", "bun", "java",
    "osascript", "lua", "luajit", "rscript", "pwsh",
];

/// Arguments that hand the interpreter code on the command line or load extra code.
const INLINE_CODE_FLAGS: &[&str] = &["-e", "-E", "-c", "-m", "-M", "-p", "-r", "--eval", "--print", "--require", "--import"];

/// True for `node`, `python3.12`, `ruby3.3`, `Rscript`, ... by basename. Trailing version
/// digits and dots are ignored so versioned binaries from nvm/Homebrew are covered.
pub fn is_interpreter_name(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    INTERPRETERS.contains(&base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'))
}

/// Does argv carry inline code (`-e`, `-c`, `--eval=...`) after argv[0]?
pub fn has_inline_code_flag(argv: &[String]) -> bool {
    argv.iter().skip(1).any(|arg| INLINE_CODE_FLAGS.contains(&arg.as_str())
        || ["--eval=", "--print=", "--require=", "--import="].iter().any(|p| arg.starts_with(p)))
}

/// Turn `--cmd`/`--script` input into grant bindings. Each interpreter is paired with
/// every script (relative scripts made absolute against `cwd`; the daemon re-resolves
/// and hashes them); other programs stay plain pins. An interpreter without a script is
/// refused here so the CLI explains it before any prompt; the daemon refuses it too.
pub fn command_bindings(cmds: &[String], scripts: &[String], cwd: &std::path::Path) -> Result<Vec<CommandBinding>> {
    let scripts: Vec<String> = scripts.iter().map(|s| cwd.join(s).to_string_lossy().into_owned()).collect();
    let interpreter = |cmd: &str| is_interpreter_name(cmd)
        || std::fs::canonicalize(cmd).is_ok_and(|real| is_interpreter_name(&real.to_string_lossy()));
    let mut out = Vec::new();
    let mut paired = false;
    for cmd in cmds {
        if !interpreter(cmd) { out.push(cmd.as_str().into()); continue; }
        if scripts.is_empty() {
            bail!("--cmd {cmd}: interpreters run any code (`-e`, `-c`); bind them to a file with --script FILE");
        }
        paired = true;
        out.extend(scripts.iter().map(|script| CommandBinding::Script {
            path: cmd.clone(), sha256: String::new(), script: script.clone(), script_sha256: String::new() }));
    }
    if !scripts.is_empty() && !paired { bail!("--script needs an interpreter in --cmd (node, python3, ...)"); }
    Ok(out)
}

impl From<String> for CommandBinding {
    fn from(name: String) -> Self { Self::Name(name) }
}
impl From<&str> for CommandBinding {
    fn from(name: &str) -> Self { Self::Name(name.into()) }
}

/// Fresh canonical binding plus fstat device, inode and size from the hashed fd.
pub(crate) type CommandSnapshot = (CommandBinding, (u64, u64, u64));

impl CommandBinding {
    pub fn path(&self) -> &str {
        match self { Self::Name(name) => name, Self::Pinned { path, .. } | Self::Script { path, .. } => path }
    }

    /// Human label: the program, plus its script for a pair. A pair shows the interpreter
    /// by name only, so the script path (what matters) fits the 120-character prompt.
    pub fn label(&self) -> String {
        match self {
            Self::Script { path, script, .. } => format!("{} {script}", path.rsplit('/').next().unwrap_or(path)),
            _ => self.path().into(),
        }
    }

    /// Recompute even for object-shaped requests: a client hash is never authority.
    pub(crate) fn pin(&self) -> Result<Self> {
        let search = std::env::var_os("PATH");
        let Self::Script { path, script, .. } = self else {
            return Ok(Self::resolve(self.path(), search.as_deref(), true)?.0);
        };
        // The interpreter is allowed here (that is the point of a pair); shells are not.
        let (Self::Pinned { path: path_real, sha256 }, _) = Self::resolve(path, search.as_deref(), false)? else { bail!("command is not an executable regular file"); };
        Self::check_not_shell(std::path::Path::new(path))?;
        Self::check_not_shell(std::path::Path::new(&path_real))?;
        let script = std::path::Path::new(script);
        if !script.is_absolute() { bail!("script must be an absolute path"); }
        let canonical = std::fs::canonicalize(script).map_err(|e| anyhow::anyhow!("resolve script: {e}"))?;
        let Some((Self::Pinned { path: script, sha256: script_sha256 }, _)) = Self::snapshot_regular_file(&canonical, false)? else { bail!("script is not a regular file"); };
        Ok(Self::Script { path: path_real, sha256, script, script_sha256 })
    }

    fn resolve(name: &str, search: Option<&std::ffi::OsStr>, command_scope: bool) -> Result<CommandSnapshot> {
        use anyhow::Context;
        use std::path::Path;
        let path = Path::new(name);
        if name.is_empty() { bail!("empty command"); }
        let canonical = if path.is_absolute() {
            std::fs::canonicalize(path).context("resolve command")?
        } else {
            if path.components().count() != 1 || name.contains('/') {
                bail!("command must be an absolute path or unambiguous name");
            }
            let mut found = Vec::new();
            for dir in std::env::split_paths(search.context("command PATH unavailable")?) {
                // Do not resolve relative PATH entries against the daemon's cwd.
                if !dir.is_absolute() { continue; }
                let candidate = dir.join(name);
                if executable(&candidate) {
                    let candidate = std::fs::canonicalize(candidate)?;
                    if !found.contains(&candidate) { found.push(candidate); }
                }
            }
            if found.len() != 1 { bail!("command name is ambiguous or unresolvable; use an absolute path"); }
            found.remove(0)
        };
        if command_scope {
            Self::check_scope_path(path)?;
            Self::check_scope_path(&canonical)?;
        }
        Self::snapshot(&canonical)
    }

    /// Pure scope restriction, separate from target identity capture. A shell is
    /// a valid bound target when authority does not come from a command scope.
    pub(crate) fn check_scope_path(path: &std::path::Path) -> Result<()> {
        Self::check_not_shell(path)?;
        if path.file_name().and_then(|s| s.to_str()).is_some_and(is_interpreter_name) {
            bail!("interpreters are not permitted as bare command scopes; bind them to a script with --script FILE");
        }
        Ok(())
    }

    /// Shells and wrappers are refused in every scope form, including script pairs.
    pub(crate) fn check_not_shell(path: &std::path::Path) -> Result<()> {
        if path.file_name().and_then(|s| s.to_str()).is_some_and(|s| crate::daemon::SHELLS.contains(&s)) {
            bail!("shells and command wrappers are not permitted in command scopes");
        }
        Ok(())
    }

    /// Capture any executable target, including shells, without granting it
    /// command-scope authority. Called outside State, with a fresh hash.
    pub(crate) fn capture_target(target: Option<&str>) -> Result<CommandSnapshot> {
        use anyhow::Context;
        let target = target.context("missing launch target")?;
        if !std::path::Path::new(target).is_absolute() { bail!("launch target must be absolute"); }
        Self::resolve(target, None, false)
    }

    fn snapshot(path: &std::path::Path) -> Result<CommandSnapshot> {
        use anyhow::Context;
        Self::snapshot_regular_file(path, true)?.context("command is not an executable regular file")
    }

    /// Shared fd snapshot for launch scripts. Non-regular files are never read.
    pub(crate) fn snapshot_regular_file(path: &std::path::Path, require_executable: bool) -> Result<Option<CommandSnapshot>> {
        use anyhow::Context;
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // NONBLOCK prevents a concurrently replaced FIFO from hanging the daemon.
        let mut file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path).context("open command")?;
        let meta = file.metadata()?;
        if !meta.is_file() { return Ok(None); }
        if require_executable && meta.permissions().mode() & 0o111 == 0 { bail!("command is not an executable regular file"); }
        let mut hash = Sha256::new();
        std::io::copy(&mut file, &mut hash)?;
        let identity = (meta.dev(), meta.ino(), meta.len());
        let after = file.metadata()?;
        if identity != (after.dev(), after.ino(), after.len()) { bail!("command changed while hashing; retry"); }
        Ok(Some((Self::Pinned { path: path.to_str().context("command path is not UTF-8")?.into(), sha256: format!("{:x}", hash.finalize()) }, identity)))
    }

    /// Read outside the daemon State lock. No cache; same fd supplies fstat/hash.
    #[cfg(test)]
    pub(crate) fn prepare(target: Option<&str>) -> Result<CommandSnapshot> {
        use anyhow::Context;
        let target = target.context("command-scoped lease requires an absolute target")?;
        if !std::path::Path::new(target).is_absolute() { bail!("command-scoped lease requires an absolute target"); }
        Self::resolve(target, None, true)
    }

    /// Pure comparison under State lock. The reported target is advisory until
    /// Actual-child binding; this does not bind exec or close TOCTOU.
    #[cfg(test)]
    pub(crate) fn check_snapshot(cmds: &[Self], target: &Result<CommandSnapshot>) -> Result<()> {
        Self::check_launch(cmds, target, None, &[])
    }

    /// Compare a launch with the lease scope, given the hashed argv[1] (`script`) and argv. A bare
    /// pin never matches an interpreter; a script pair needs the same interpreter, the
    /// same script path and hash, and no inline-code flag anywhere in argv.
    pub(crate) fn check_launch(cmds: &[Self], target: &Result<CommandSnapshot>, script: Option<&Self>, argv: &[String]) -> Result<()> {
        if cmds.is_empty() { return Ok(()); }
        if cmds.iter().any(|cmd| matches!(cmd, Self::Name(_))) {
            bail!("legacy command scope: re-grant required");
        }
        let (actual, _file_identity) = target.as_ref().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let Self::Pinned { path: actual_path, sha256: actual_sha } = actual else { bail!("lease command path/hash mismatch; re-grant required if the target changed"); };
        let script_pin = match script { Some(Self::Pinned { path, sha256 }) => Some((path, sha256)), _ => None };
        let mut refused = None;
        let matched = cmds.iter().any(|cmd| match cmd {
            Self::Pinned { path, sha256 } if path == actual_path && sha256 == actual_sha => {
                if is_interpreter_name(path) { refused = Some("interpreters are not permitted as bare command scopes; re-grant with --script FILE"); false } else { true }
            }
            Self::Script { path, sha256, script, script_sha256 } if path == actual_path && sha256 == actual_sha => {
                if has_inline_code_flag(argv) { refused = Some("inline code flags (-e, -c, -m, ...) are not covered by a script lease"); false }
                else { script_pin == Some((script, script_sha256)) }
            }
            _ => false,
        });
        if let Some(why) = refused.filter(|_| !matched) { bail!("{why}"); }
        if !matched { bail!("lease command path/hash mismatch; re-grant required if the target changed"); }
        Ok(())
    }

    #[cfg(test)]
    fn check(cmds: &[Self], target: Option<&str>) -> Result<()> {
        Self::check_snapshot(cmds, &Self::prepare(target))
    }

}

fn executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod command_binding_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("karambit-command-{label}-{}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn copy(&self, source: &str, name: &str) -> String {
            let path = self.0.join(name);
            std::fs::copy(source, &path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path.to_str().unwrap().into()
        }
    }
    impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

    #[test]
    fn command_binding_shell_capture_does_not_grant_scope() {
        for path in ["/bin/sh", "/bin/bash", "/usr/bin/env", "/usr/bin/xargs"] {
            let snapshot = CommandBinding::capture_target(Some(path)).unwrap();
            assert_eq!(snapshot.0.path(), std::fs::canonicalize(path).unwrap().to_str().unwrap());
            assert!(CommandBinding::from(path).pin().unwrap_err().to_string().contains("not permitted in command scopes"));
            assert!(CommandBinding::prepare(Some(path)).is_err());
            let binding = crate::launch::LaunchBinding::capture(path.into(), vec![path.into()], std::env::temp_dir()).unwrap();
            binding.verify_unchanged().unwrap();
            binding.check_scope(&[]).unwrap();
            // Even a manually constructed matching pin cannot authorize a shell.
            assert!(binding.check_scope(&[snapshot.0]).unwrap_err().to_string().contains("not permitted in command scopes"));
        }
        let fixture = Fixture::new("shell-alias");
        let alias = fixture.0.join("native-name");
        symlink("/bin/sh", &alias).unwrap();
        let binding = crate::launch::LaunchBinding::capture(alias.clone(), vec![alias.to_str().unwrap().into()], fixture.0.clone()).unwrap();
        binding.verify_unchanged().unwrap();
        assert!(binding.check_scope(&[binding.target().clone()]).is_err());
        assert!(CommandBinding::from(alias.to_str().unwrap()).pin().is_err());
    }

    #[test]
    fn bound_scope_uses_target_not_spoofed_argv_zero() {
        let shell = crate::launch::LaunchBinding::capture(
            "/bin/sh".into(), vec!["terraform".into()], std::env::temp_dir()).unwrap();
        assert!(shell.check_scope(&[shell.target().clone()]).is_err());
        let native = crate::launch::LaunchBinding::capture(
            "/usr/bin/true".into(), vec!["/bin/sh".into()], std::env::temp_dir()).unwrap();
        native.check_scope(&[native.target().clone()]).unwrap();
        native.verify_unchanged().unwrap();
        assert_eq!(native.argv(), &["/bin/sh"]);
    }

    #[test]
    fn command_binding_rejects_shell_copy_under_permitted_basename() {
        let fixture = Fixture::new("shell-copy");
        let permitted = CommandBinding::from("/usr/bin/true").pin().unwrap();
        let copy = fixture.copy("/bin/sh", "true");
        let error = CommandBinding::check(&[permitted], Some(&copy)).unwrap_err();
        assert!(error.to_string().contains("path/hash mismatch"));
    }

    #[test]
    fn command_binding_rejects_changed_target_after_grant() {
        let fixture = Fixture::new("replacement");
        let target = fixture.copy("/usr/bin/true", "tool");
        let pin = CommandBinding::from(target.clone()).pin().unwrap();
        CommandBinding::check(std::slice::from_ref(&pin), Some(&target)).unwrap();
        fixture.copy("/bin/sh", "tool");
        assert!(CommandBinding::check(&[pin], Some(&target)).unwrap_err().to_string().contains("path/hash mismatch"));
    }

    #[test]
    fn command_binding_legacy_names_require_regrant() {
        let scope: crate::daemon::Scope = serde_json::from_str(r#"{"cmds":["true"]}"#).unwrap();
        assert!(!scope.is_empty());
        assert!(CommandBinding::check(&scope.cmds, Some("/usr/bin/true")).unwrap_err().to_string().contains("re-grant required"));
        // Mixed legacy + pinned must not silently drop the legacy entry either.
        let mut mixed = scope.cmds;
        mixed.push(CommandBinding::from("/usr/bin/true").pin().unwrap());
        assert!(CommandBinding::check(&mixed, Some("/usr/bin/true")).is_err());
        CommandBinding::check(&[], None).unwrap();
    }

    #[test]
    fn command_binding_native_fixture_and_system_executable() {
        let fixture = Fixture::new("native");
        let source = fixture.0.join("canary.c");
        let target = fixture.0.join("canary");
        std::fs::write(&source, "#include <stdlib.h>\n#include <string.h>\nint main(void) { const char *v=getenv(\"KARAMBIT_TEST_CANARY\"); return !(v && !strcmp(v,\"synthetic-command-canary\")); }\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/cc").arg(&source).arg("-o").arg(&target).status().unwrap().success());
        for path in [target.to_str().unwrap(), "/usr/bin/true"] {
            let pin = CommandBinding::from(path).pin().unwrap();
            let canonical = std::fs::canonicalize(path).unwrap();
            assert_eq!(pin.path(), canonical.to_str().unwrap());
            CommandBinding::check(std::slice::from_ref(&pin), Some(path)).unwrap();
            assert!(std::process::Command::new(pin.path()).env_clear().env("KARAMBIT_TEST_CANARY", "synthetic-command-canary").status().unwrap().success());
            let decoded: CommandBinding = serde_json::from_str(&serde_json::to_string(&pin).unwrap()).unwrap();
            assert_eq!(pin, decoded);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn command_binding_installed_native_matches_kernel_path() {
        let pin = CommandBinding::from("/bin/sleep").pin().unwrap();
        let mut child = std::process::Command::new("/bin/sleep").arg("30").env_clear().spawn().unwrap();
        let kernel = crate::agent::proc_exe(child.id() as i32);
        let _ = child.kill();
        let _ = child.wait();
        let kernel = std::fs::canonicalize(kernel.expect("kernel executable identity")).unwrap();
        assert_eq!(pin.path(), kernel.to_str().unwrap());
        let prepared = CommandBinding::prepare(kernel.to_str()).unwrap();
        assert_ne!(prepared.1.1, 0, "fstat inode recorded");
        assert!(prepared.1.2 > 0, "fstat size recorded");
        CommandBinding::check_snapshot(&[pin], &Ok(prepared)).unwrap();
    }

    #[test]
    fn command_binding_resolution_is_unambiguous_and_daemon_derived() {
        let fixture = Fixture::new("resolution");
        let a = fixture.0.join("a");
        let b = fixture.0.join("b");
        std::fs::create_dir(&a).unwrap(); std::fs::create_dir(&b).unwrap();
        symlink("/usr/bin/true", a.join("tool")).unwrap();
        symlink("/usr/bin/true", b.join("tool")).unwrap();
        let path = std::env::join_paths([&a, &b]).unwrap();
        let pin = CommandBinding::resolve("tool", Some(&path), true).unwrap().0;
        assert_eq!(pin, CommandBinding::from("/usr/bin/true").pin().unwrap());
        std::fs::remove_file(b.join("tool")).unwrap();
        std::fs::copy("/usr/bin/true", b.join("tool")).unwrap();
        assert!(CommandBinding::resolve("tool", Some(&path), true).unwrap_err().to_string().contains("ambiguous"));
        assert!(CommandBinding::resolve("absent", Some(&path), true).is_err());
        assert!(CommandBinding::from("./tool").pin().is_err());
        assert!(CommandBinding::from("/bin/sh").pin().is_err());
        assert!(CommandBinding::from(fixture.0.to_str().unwrap()).pin().is_err());
        let forged = CommandBinding::Pinned { path: "/usr/bin/true".into(), sha256: "forged".into() };
        assert_ne!(forged.pin().unwrap(), forged);
        assert!(CommandBinding::check(&[pin], Some("true")).is_err());
    }

    // ---- interpreters

    fn script_fixture(label: &str) -> (Fixture, String, String) {
        let fixture = Fixture::new(label);
        let node = fixture.copy("/usr/bin/true", "node");
        let script = fixture.0.join("build.js");
        std::fs::write(&script, "console.log('hi')\n").unwrap();
        (fixture, node, script.to_str().unwrap().into())
    }

    fn capture(node: &str, argv: &[&str], cwd: &std::path::Path) -> crate::launch::LaunchBinding {
        crate::launch::LaunchBinding::capture(node.into(), argv.iter().map(|a| a.to_string()).collect(), cwd.into()).unwrap()
    }

    fn pair(node: &str, script: &str) -> CommandBinding {
        CommandBinding::Script { path: node.into(), sha256: String::new(), script: script.into(), script_sha256: String::new() }.pin().unwrap()
    }

    #[test]
    fn interpreter_names_are_recognised_by_basename_and_version() {
        for name in ["node", "/opt/homebrew/bin/node", "nodejs", "python", "python3", "python3.12", "ruby", "ruby3.3", "perl", "perl5.34",
            "php", "php8.3", "deno", "bun", "java", "osascript", "lua", "lua5.4", "Rscript", "pwsh"] {
            assert!(is_interpreter_name(name), "{name}");
        }
        for name in ["curl", "terraform", "nodemon", "pythonista", "javac", "/usr/bin/true", "git"] {
            assert!(!is_interpreter_name(name), "{name}");
        }
    }

    #[test]
    fn bare_interpreter_is_refused_as_command_scope() {
        let fixture = Fixture::new("bare-interpreter");
        for name in ["node", "python3.12", "ruby", "perl", "php", "deno", "bun", "java", "osascript", "lua", "Rscript", "pwsh"] {
            let path = fixture.copy("/usr/bin/true", name);
            let error = CommandBinding::from(path.clone()).pin().unwrap_err().to_string();
            assert!(error.contains("interpreters are not permitted"), "{name}: {error}");
            assert!(CommandBinding::prepare(Some(&path)).is_err(), "{name}");
            // A hand-built matching pin cannot authorize one at launch time either.
            let launch = capture(&path, &[&path], &fixture.0);
            let pin = launch.target().clone();
            assert!(launch.check_scope(std::slice::from_ref(&pin)).is_err(), "{name}");
            assert!(CommandBinding::check_launch(&[pin], &Ok((launch.target().clone(), (0, 0, 0))), None, &[]).is_err(), "{name}");
        }
        // Symlinked name: the canonical target decides, like shells.
        let alias = fixture.0.join("tool");
        symlink(fixture.0.join("node"), &alias).unwrap();
        assert!(CommandBinding::from(alias.to_str().unwrap()).pin().is_err());
    }

    #[test]
    fn script_lease_matches_only_its_interpreter_and_script() {
        let (fixture, node, script) = script_fixture("script-pair");
        let held = pair(&node, &script);
        assert!(matches!(&held, CommandBinding::Script { script_sha256, .. } if script_sha256.len() == 64));
        capture(&node, &[&node, &script], &fixture.0).check_scope(std::slice::from_ref(&held)).unwrap();
        // Relative argv[1] resolves against the launch cwd to the same script.
        capture(&node, &[&node, "build.js", "--prod"], &fixture.0).check_scope(std::slice::from_ref(&held)).unwrap();

        // Another script, no script, another interpreter: all refused.
        let other = fixture.0.join("other.js");
        std::fs::write(&other, "x").unwrap();
        assert!(capture(&node, &[&node, other.to_str().unwrap()], &fixture.0).check_scope(std::slice::from_ref(&held)).is_err());
        assert!(capture(&node, &[&node], &fixture.0).check_scope(std::slice::from_ref(&held)).is_err());
        let python = fixture.copy("/usr/bin/true", "python3");
        assert!(capture(&python, &[&python, &script], &fixture.0).check_scope(std::slice::from_ref(&held)).is_err());

        // Editing the script after the grant breaks the match.
        std::fs::write(&script, "console.log(process.env)\n").unwrap();
        assert!(capture(&node, &[&node, &script], &fixture.0).check_scope(std::slice::from_ref(&held)).unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn script_lease_refuses_inline_code_flags() {
        let (fixture, node, script) = script_fixture("script-inline");
        let held = pair(&node, &script);
        for flag in ["-e", "-c", "-m", "-p", "-r", "--eval", "--print", "--eval=1"] {
            let error = capture(&node, &[&node, &script, flag, "x"], &fixture.0).check_scope(std::slice::from_ref(&held)).unwrap_err().to_string();
            assert!(error.contains("inline code"), "{flag}: {error}");
            // The flag in front shifts the script out of argv[1]; also refused.
            assert!(capture(&node, &[&node, flag, "x", &script], &fixture.0).check_scope(std::slice::from_ref(&held)).is_err(), "{flag}");
        }
    }

    #[test]
    fn script_pair_still_refuses_shells_and_relative_scripts() {
        let (fixture, _node, script) = script_fixture("script-shell");
        for shell in ["/bin/sh", "/usr/bin/env"] {
            let bad = CommandBinding::Script { path: shell.into(), sha256: String::new(), script: script.clone(), script_sha256: String::new() };
            assert!(bad.pin().unwrap_err().to_string().contains("not permitted in command scopes"), "{shell}");
        }
        let rel = CommandBinding::Script { path: "/usr/bin/true".into(), sha256: String::new(), script: "build.js".into(), script_sha256: String::new() };
        assert!(rel.pin().unwrap_err().to_string().contains("absolute"));
        let dir = CommandBinding::Script { path: "/usr/bin/true".into(), sha256: String::new(), script: fixture.0.to_str().unwrap().into(), script_sha256: String::new() };
        assert!(dir.pin().is_err());
        // A client-supplied hash is never trusted.
        let forged = CommandBinding::Script { path: "/usr/bin/true".into(), sha256: "f".into(), script: script.clone(), script_sha256: "f".into() };
        assert!(matches!(forged.pin().unwrap(), CommandBinding::Script { sha256, script_sha256, .. } if sha256.len() == 64 && script_sha256.len() == 64));
    }

    #[test]
    fn command_binding_wire_format_stays_backward_compatible() {
        let old: Vec<CommandBinding> = serde_json::from_str(r#"["curl",{"path":"/usr/bin/true","sha256":"ab"}]"#).unwrap();
        assert_eq!(old, [CommandBinding::Name("curl".into()), CommandBinding::Pinned { path: "/usr/bin/true".into(), sha256: "ab".into() }]);
        let pinned = serde_json::to_string(&CommandBinding::Pinned { path: "/p".into(), sha256: "ab".into() }).unwrap();
        assert_eq!(pinned, r#"{"path":"/p","sha256":"ab"}"#, "old shape unchanged");
        let script = CommandBinding::Script { path: "/n".into(), sha256: "a".into(), script: "/s.js".into(), script_sha256: "b".into() };
        let round: CommandBinding = serde_json::from_str(&serde_json::to_string(&script).unwrap()).unwrap();
        assert_eq!(round, script, "the script half survives a round trip");
        assert_eq!(script.label(), "n /s.js");
    }

    #[test]
    fn command_bindings_pairs_interpreters_with_scripts() {
        let cwd = std::path::Path::new("/work");
        let node = "/opt/homebrew/bin/node".to_string();
        let e = command_bindings(std::slice::from_ref(&node), &[], cwd).unwrap_err().to_string();
        assert!(e.contains("--script"), "{e}");
        assert!(command_bindings(&["python3".into()], &[], cwd).is_err());
        assert!(command_bindings(&["/usr/bin/curl".into()], &["a.js".into()], cwd).unwrap_err().to_string().contains("interpreter"));
        assert_eq!(command_bindings(&["curl".into()], &[], cwd).unwrap(), [CommandBinding::Name("curl".into())]);
        let got = command_bindings(&[node.clone(), "curl".into()], &["a.js".into(), "/abs/b.js".into()], cwd).unwrap();
        assert_eq!(got.len(), 3, "two pairs and one plain command");
        assert!(matches!(&got[0], CommandBinding::Script { path, script, .. } if path == &node && script == "/work/a.js"));
        assert!(matches!(&got[1], CommandBinding::Script { script, .. } if script == "/abs/b.js"));
        assert_eq!(got[2], CommandBinding::Name("curl".into()));
    }
}
