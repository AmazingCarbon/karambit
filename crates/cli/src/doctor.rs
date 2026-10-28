//! `karambit doctor --agent-env`: probes what the *current* environment can reach, using a
//! synthetic canary only. It never opens the live vault's contents, never writes to the vault,
//! never starts a daemon, never sends a daemon request and never prints a value. Results cover
//! this run only. The one row that runs code (`key-blob-use`) compiles and runs a standalone
//! Swift probe on a synthetic Secure Enclave key; see `key_use_probe.swift`.
//!
//! Exit code: 0 whatever the rows say (a `fail` row is a finding, not an error); non-zero only if
//! the doctor itself cannot run (no scratch dir, no entropy, bad config, ...).

use anyhow::{Context, Result, bail};
use karambit_core::redact::Redactor;
use karambit_core::{Caller, Paths};
use serde_json::json;
use std::ffi::{CString, OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const SCOPE: &str = "this run only";
/// argv word that identifies the synthetic sibling in `ps` output (a positive control).
pub const HOLD_ARG: &str = "__doctor-hold";
const CANARY_ENV: &str = "KARAMBIT_DOCTOR_CANARY";
const SCRATCH_PREFIX: &str = "karambit-doctor-";
const HOLD_WATCHDOG: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Inconclusive,
    Unsupported,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Inconclusive => "inconclusive",
            Status::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    pub name: &'static str,
    pub status: Status,
    pub why: String,
}

fn row(name: &'static str, status: Status, why: impl Into<String>) -> Row {
    Row { name, status, why: why.into() }
}

// ------------------------------------------------------------------ canary

/// Random synthetic secret. Deliberately not `Debug`/`Clone`: it must not be formattable.
pub struct Canary {
    name: String,
    value: Zeroizing<String>,
}

impl Canary {
    pub fn generate() -> Result<Canary> {
        let mut raw = Zeroizing::new([0u8; 32]);
        fill_random(raw.as_mut())?;
        let mut tag = [0u8; 6];
        fill_random(&mut tag)?;
        Ok(Canary { name: format!("doctor/canary-{}", hex(&tag)), value: Zeroizing::new(hex(raw.as_ref())) })
    }
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    // getentropy: at most 256 bytes per call, no fd to leak.
    if unsafe { libc::getentropy(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        bail!("no system entropy for the doctor canary");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64_std(data: &[u8]) -> Zeroizing<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Zeroizing::new(Vec::with_capacity(data.len().div_ceil(3) * 4));
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63]);
        out.push(T[(n >> 12) as usize & 63]);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] } else { b'=' });
        out.push(if c.len() > 2 { T[n as usize & 63] } else { b'=' });
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------------ scratch dir

const MARKER_FILE: &str = ".karambit-doctor";
const MARKER_MAGIC: &str = "karambit-doctor v1";

/// 0700 scratch dir `karambit-doctor-<pid>-<12 hex>` holding a marker file that proves doctor made it;
/// removed on Drop (normal exit, error, panic unwind).
pub struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    pub fn create(tmp_root: &Path) -> Result<Scratch> {
        Self::create_with(tmp_root, write_marker)
    }

    /// `marker` writes the ownership marker; injectable so tests can prove the guard covers its failure.
    fn create_with(tmp_root: &Path, marker: impl FnOnce(&Path, &str) -> std::io::Result<()>) -> Result<Scratch> {
        let mut tag = [0u8; 6];
        fill_random(&mut tag)?;
        let tag = hex(&tag);
        let dir = tmp_root.join(format!("{SCRATCH_PREFIX}{}-{tag}", std::process::id()));
        // Created 0700 atomically (never visible with wider bits); the guard exists from here on.
        std::fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("create {}", dir.display()))?;
        let scratch = Scratch { dir };
        marker(&scratch.dir, &tag).with_context(|| format!("mark {}", scratch.dir.display()))?;
        Ok(scratch)
    }
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Scratch {
    /// Never recursive: by the time this runs the scratch dir only holds the marker (the sibling
    /// uses it as cwd and writes nothing; the key probe's files are removed by name by `ProbeFiles`).
    /// Removing exactly that one entry and then `rmdir` means that if the pathname was swapped for
    /// another directory (another process able to rename entries in TMPDIR), only non-directory
    /// entries with the four exact names `.karambit-doctor`, `probe.swift`, `probe` and
    /// `probe-key.blob` may be unlinked (the last three by `ProbeFiles`); the replacement directory
    /// itself is removed only if nothing else was in it.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.dir.join(MARKER_FILE));
        let _ = std::fs::remove_dir(&self.dir);
    }
}

fn marker_text(pid: u32, start: u64, nonce: &str) -> String {
    format!("{MARKER_MAGIC} pid={pid} start={start} nonce={nonce}\n")
}

/// First file written into a new scratch dir: pid, creation time and the nonce from the dir name.
fn write_marker(dir: &Path, nonce: &str) -> std::io::Result<()> {
    let start = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join(MARKER_FILE))?;
    f.write_all(marker_text(std::process::id(), start, nonce).as_bytes())
}

/// `karambit-doctor-<decimal pid>-<12 lowercase hex>` exactly as `Scratch::create` generates it.
fn parse_scratch_name(name: &str) -> Option<(i32, &str)> {
    let (pid, nonce) = name.strip_prefix(SCRATCH_PREFIX)?.split_once('-')?;
    let pid_ok = !pid.is_empty() && pid.len() <= 10 && pid.bytes().all(|b| b.is_ascii_digit());
    let nonce_ok = nonce.len() == 12 && nonce.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !(pid_ok && nonce_ok) {
        return None;
    }
    Some((pid.parse().ok().filter(|p| *p > 0)?, nonce))
}

/// True only for a real (non-symlink) directory we own, named by the exact grammar, holding a
/// regular marker file we own whose pid and nonce agree with the name. Returns the creating pid.
fn doctor_owned(path: &Path, name: &str, me: libc::uid_t) -> Option<i32> {
    let (pid, nonce) = parse_scratch_name(name)?;
    let dir = std::fs::symlink_metadata(path).ok()?;
    if !dir.is_dir() || dir.uid() != me {
        return None;
    }
    let marker_path = path.join(MARKER_FILE);
    let marker = std::fs::symlink_metadata(&marker_path).ok()?;
    if !marker.file_type().is_file() || marker.uid() != me || marker.len() > 256 {
        return None;
    }
    let text = std::fs::read_to_string(&marker_path).ok()?;
    let mut fields = text.trim_end().split(' ');
    let magic = format!("{} {}", fields.next()?, fields.next()?);
    let (p, _start, n) = (fields.next()?, fields.next()?.strip_prefix("start=")?.parse::<u64>().ok()?, fields.next()?);
    (magic == MARKER_MAGIC && fields.next().is_none() && p == format!("pid={pid}") && n == format!("nonce={nonce}")).then_some(pid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeftoverAction {
    /// A crashed doctor run's scratch dir (grammar + marker + our uid + creating pid gone).
    CrashLeftover,
    NotDoctorOwned,
}

impl LeftoverAction {
    pub fn as_str(self) -> &'static str {
        match self {
            LeftoverAction::CrashLeftover => "crash leftover from an earlier doctor run; delete it by hand",
            LeftoverAction::NotDoctorOwned => "not doctor-owned, left in place",
        }
    }
}

/// Earlier crashed runs are IDENTIFIED, never deleted: a check-then-delete by pathname cannot
/// be bound to the validated directory's identity (another process able to rename entries in
/// TMPDIR could swap in an unrelated directory between the check and the delete), and the plan
/// only requires leftovers to be identified for cleanup. Doctor removes only the scratch dir it
/// created in this run (Drop). A live concurrent doctor's directory is skipped.
pub fn clean_leftovers(tmp_root: &Path) -> Vec<(String, LeftoverAction)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(tmp_root) else { return found };
    let me = unsafe { libc::geteuid() };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(SCRATCH_PREFIX) {
            continue;
        }
        let action = match doctor_owned(&entry.path(), &name, me) {
            None => LeftoverAction::NotDoctorOwned,
            Some(pid) if pid_alive(pid) => continue,
            Some(_) => LeftoverAction::CrashLeftover,
        };
        found.push((name, action));
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

fn pid_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
}

// ------------------------------------------------------------------ sibling

/// How to start the synthetic sibling. Production: this executable with `__doctor-hold`.
pub struct SiblingCmd {
    pub exe: PathBuf,
    pub args: Vec<OsString>,
    /// Must appear in the sibling's argv; proves `ps` listed that process (positive control).
    pub marker: String,
    pub extra_env: Vec<(String, String)>,
}

impl SiblingCmd {
    pub fn production() -> Result<SiblingCmd> {
        Ok(SiblingCmd {
            exe: std::env::current_exe().context("locate this executable")?,
            args: vec![HOLD_ARG.into()],
            marker: HOLD_ARG.into(),
            extra_env: vec![],
        })
    }
}

/// Child holding the canary in its environment. Killed and reaped on Drop (every path); it also
/// exits by itself when the doctor dies, because its stdin pipe closes.
struct Sibling {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl Sibling {
    fn spawn(cmd: &SiblingCmd, canary: &Canary, cwd: &Path) -> std::io::Result<Sibling> {
        let mut c = Command::new(&cmd.exe);
        c.args(&cmd.args).env_clear().env(CANARY_ENV, canary.value.as_str()).current_dir(cwd)
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
        for (k, v) in &cmd.extra_env {
            c.env(k, v);
        }
        let mut child = c.spawn()?;
        let stdin = child.stdin.take();
        Ok(Sibling { child, stdin })
    }
}

impl Drop for Sibling {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Body of the hidden `__doctor-hold` command: sit idle until the doctor closes our stdin.
pub fn hold() {
    std::thread::spawn(|| {
        std::thread::sleep(HOLD_WATCHDOG);
        std::process::exit(0);
    });
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

fn judge_ps_output(out: &[u8], canary: &Canary, marker: &str) -> Row {
    const NAME: &str = "sibling-env-ps";
    if contains(out, canary.value.as_bytes()) {
        row(NAME, Status::Fail, "`ps -E` run from this environment shows a sibling process's environment (canary visible)")
    } else if contains(out, marker.as_bytes()) {
        row(NAME, Status::Pass, "`ps -E` ran and listed the sibling process, but its environment (canary) was not visible")
    } else {
        row(NAME, Status::Inconclusive, "`ps -E` ran but did not list the sibling process, so visibility cannot be judged")
    }
}

pub fn check_sibling_env(ps: &Path, cmd: &SiblingCmd, canary: &Canary, cwd: &Path) -> Row {
    const NAME: &str = "sibling-env-ps";
    let sibling = match Sibling::spawn(cmd, canary, cwd) {
        Ok(s) => s,
        Err(e) => return row(NAME, Status::Inconclusive, format!("could not start the synthetic sibling: {}", e.kind())),
    };
    let pid = sibling.child.id().to_string();
    let output = karambit_core::platform::sibling_environment(ps, &pid);
    // `sibling` is killed and reaped when it drops below, whichever branch returns.
    match output {
        Err(e) => row(NAME, Status::Inconclusive, format!("could not run {}: {}", ps.display(), e.kind())),
        Ok(o) => {
            let stdout = Zeroizing::new(o.stdout);
            if !o.status.success() {
                row(NAME, Status::Inconclusive, format!("`ps -E` failed ({})", o.status))
            } else {
                judge_ps_output(&stdout, canary, &cmd.marker)
            }
        }
    }
}

// ------------------------------------------------------------------ ~/.vault-token

/// Metadata and access(2) only: the token file is never opened or read.
pub fn check_vault_token(home: Option<&Path>) -> Row {
    const NAME: &str = "vault-token";
    let Some(home) = home else { return row(NAME, Status::Inconclusive, "HOME is not set") };
    let path = home.join(".vault-token");
    match std::fs::metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => row(NAME, Status::Pass, "no ~/.vault-token"),
        Err(e) => row(NAME, Status::Inconclusive, format!("cannot stat ~/.vault-token: {}", e.kind())),
        Ok(m) if m.is_dir() => row(NAME, Status::Pass, "~/.vault-token is a directory, not a token file"),
        Ok(_) if access_ok(&path, libc::R_OK) => {
            row(NAME, Status::Fail, "~/.vault-token exists and is readable by this environment (contents not read)")
        }
        Ok(_) => row(NAME, Status::Pass, "~/.vault-token exists but is not readable by this environment (contents not read)"),
    }
}

fn access_ok(path: &Path, mode: libc::c_int) -> bool {
    CString::new(path.as_os_str().as_bytes()).is_ok_and(|c| unsafe { libc::access(c.as_ptr(), mode) } == 0)
}

// ------------------------------------------------------------------ key-blob use

/// The standalone probe program (never the production helper, never talks to Karambit).
pub const KEY_USE_PROBE_SOURCE: &str = karambit_core::platform::key_probe_source();
/// `KARAMBIT_DOCTOR_SKIP_KEY_PROBE=1` skips this row (reported as `unsupported`, in the output).
/// The CLI integration tests set it so they never reach the Secure Enclave.
pub const SKIP_KEY_PROBE_ENV: &str = "KARAMBIT_DOCTOR_SKIP_KEY_PROBE";
const PROBE_SOURCE_FILE: &str = "probe.swift";
const PROBE_BINARY_FILE: &str = "probe";
/// Must match `blobName` in `key_use_probe.swift` (asserted by a test).
const PROBE_BLOB_FILE: &str = "probe-key.blob";
const PROBE_STDOUT_CAP: usize = 256;
/// Environment variables the compiler and the probe may see; everything else is cleared.
const PROBE_ENV_ALLOWED: [&str; 4] = ["PATH", "HOME", "TMPDIR", "DEVELOPER_DIR"];

/// The key-use probe seam: given the doctor's scratch dir, produce the `key-blob-use` row.
pub type KeyProbe = fn(&Path) -> Row;

/// How to compile and run the probe. Production: `xcrun swiftc`, then `/usr/bin/swiftc` if
/// `/usr/bin/xcrun` does not exist. Injectable so tests use fake compilers and never run the probe.
pub struct ProbeTools {
    /// (executable, leading args), tried in order; the next entry is tried only if the executable is missing.
    pub compilers: Vec<(PathBuf, Vec<OsString>)>,
    pub compile_timeout: Duration,
    pub run_timeout: Duration,
}

impl ProbeTools {
    pub fn production() -> ProbeTools {
        ProbeTools {
            compilers: karambit_core::platform::key_probe_compilers(),
            compile_timeout: Duration::from_secs(120),
            run_timeout: Duration::from_secs(15),
        }
    }
}

pub fn skip_key_probe_requested(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

pub fn production_key_probe(scratch: &Path) -> Row {
    key_probe_or_skip(std::env::var_os(SKIP_KEY_PROBE_ENV).as_deref(), scratch, &ProbeTools::production())
}

pub fn key_probe_or_skip(skip_env: Option<&OsStr>, scratch: &Path, tools: &ProbeTools) -> Row {
    if skip_key_probe_requested(skip_env) {
        return row(KEY_ROW, Status::Unsupported, format!("key-use probe skipped by {SKIP_KEY_PROBE_ENV}"));
    }
    run_key_probe(scratch, tools)
}

const KEY_ROW: &str = "key-blob-use";

/// What `run_bounded` observed. Never carries stderr; stdout is capped.
#[derive(Debug)]
enum Ran {
    /// `overflow`: the child wrote more than the cap; the kept prefix is then never interpreted.
    Exited { status: ExitStatus, stdout: Vec<u8>, overflow: bool },
    /// The child exited but something it left behind kept stdout open past the grace period; the
    /// process group was killed. Never interpreted as a result.
    Lingered,
    TimedOut,
    Failed(std::io::ErrorKind),
}

fn apply_probe_env(cmd: &mut Command) {
    cmd.env_clear();
    for key in PROBE_ENV_ALLOWED {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
}

/// Bytes collected from a child's stdout so far.
#[derive(Default)]
struct DrainState {
    kept: Vec<u8>,
    overflow: bool,
    eof: bool,
}

/// Read attempts per `drain_some` call: a writer that keeps the pipe full cannot starve the
/// caller's clocks.
const DRAIN_READS: usize = 64;

/// Read what is available from a non-blocking `r`, keeping at most `cap` bytes, and return after at
/// most `DRAIN_READS` attempts, at EOF, or at `WouldBlock`/an error (retried on the next poll).
fn drain_some(r: &mut impl Read, cap: usize, st: &mut DrainState) {
    let mut buf = [0u8; 512];
    for _ in 0..DRAIN_READS {
        if st.eof {
            return;
        }
        match r.read(&mut buf) {
            Ok(0) => st.eof = true,
            Ok(n) => {
                let room = cap - st.kept.len();
                st.overflow |= n > room;
                st.kept.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Run `cmd` with no stdin, stderr discarded, at most `cap` stdout bytes kept, in its own process
/// group. Single-threaded and bounded: stdout is a non-blocking pipe drained by polling on this
/// thread, so nothing ever blocks on a writer that escaped the group (e.g. via `setsid`). However
/// it ends, the whole group is SIGKILLed while the child's pid is still held by its unreaped
/// zombie (exit is observed with `WNOWAIT`), so the signal can never reach a reused pid; only then
/// is the child reaped. A process that left the group is not killed (it is outside the doctor's
/// reach), but its held stdout makes the run `Lingered`, never interpreted.
fn run_bounded(cmd: &mut Command, timeout: Duration, cap: usize) -> Ran {
    use std::os::fd::AsRawFd;
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Ran::Failed(e.kind()),
    };
    let pid = child.id() as libc::pid_t;
    let kill_group_and_reap = |child: &mut Child| {
        unsafe { libc::killpg(pid, libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
    };
    let Some(mut out) = child.stdout.take() else {
        kill_group_and_reap(&mut child);
        return Ran::Failed(std::io::ErrorKind::Other);
    };
    let fd = out.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        kill_group_and_reap(&mut child);
        return Ran::Failed(std::io::ErrorKind::Other);
    }
    let mut st = DrainState::default();
    let mut drain = |st: &mut DrainState| drain_some(&mut out, cap, st);
    let deadline = Instant::now() + timeout;
    let exited = loop {
        drain(&mut st);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT | libc::WNOHANG) };
        if rc == 0 && unsafe { info.si_pid() } == pid {
            break Ok(());
        }
        if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break Err(std::io::Error::last_os_error().kind());
        }
        if Instant::now() >= deadline {
            break Err(std::io::ErrorKind::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let ran = match exited {
        Err(std::io::ErrorKind::TimedOut) => Ran::TimedOut,
        Err(kind) => Ran::Failed(kind),
        // Exited, not yet reaped. Give stdout a short, bounded grace period to reach EOF; a
        // leftover process still holding it makes the run untrusted. The group is killed below
        // either way (pid still held by the zombie).
        Ok(()) => {
            let grace = Instant::now() + Duration::from_secs(2);
            while !st.eof && Instant::now() < grace {
                drain(&mut st);
                if !st.eof {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            if st.eof { Ran::Exited { status: ExitStatus::from_raw(0), stdout: Vec::new(), overflow: false } } else { Ran::Lingered }
        }
    };
    kill_group_and_reap(&mut child);
    drop(out);
    match ran {
        Ran::Exited { .. } => match child.try_wait() {
            Ok(Some(status)) => Ran::Exited { status, stdout: st.kept, overflow: st.overflow },
            _ => Ran::Failed(std::io::ErrorKind::Other),
        },
        other => other,
    }
}

fn describe_exit(status: ExitStatus) -> String {
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit status {code}"),
        (None, Some(sig)) => format!("signal {sig}"),
        _ => "unknown exit".to_string(),
    }
}

/// The three files the probe path can leave in the scratch dir. Removed by exact name on every
/// path (the real probe also removes its own blob); the scratch dir's non-recursive Drop then
/// only ever has the marker left.
struct ProbeFiles {
    source: PathBuf,
    binary: PathBuf,
    blob: PathBuf,
}

impl ProbeFiles {
    fn new(scratch: &Path) -> ProbeFiles {
        ProbeFiles {
            source: scratch.join(PROBE_SOURCE_FILE),
            binary: scratch.join(PROBE_BINARY_FILE),
            blob: scratch.join(PROBE_BLOB_FILE),
        }
    }
}

impl Drop for ProbeFiles {
    fn drop(&mut self) {
        for f in [&self.blob, &self.binary, &self.source] {
            let _ = std::fs::remove_file(f);
        }
    }
}

/// Compile the embedded probe into `scratch` and run it there. Never `pass`: Karambit has no
/// software-only way to stop a same-user process from using a no-prompt key blob.
pub fn run_key_probe(scratch: &Path, tools: &ProbeTools) -> Row {
    // Absolute, because the compiler and probe run with the scratch dir as cwd (a relative TMPDIR
    // would otherwise resolve inside itself).
    let scratch = match std::path::absolute(scratch) {
        Ok(p) => p,
        Err(e) => return row(KEY_ROW, Status::Inconclusive, format!("could not resolve the scratch dir: {}", e.kind())),
    };
    let scratch = scratch.as_path();
    let files = ProbeFiles::new(scratch);
    let written = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&files.source)
        .and_then(|mut f| f.write_all(KEY_USE_PROBE_SOURCE.as_bytes()));
    if let Err(e) = written {
        return row(KEY_ROW, Status::Inconclusive, format!("could not write the probe source: {}", e.kind()));
    }
    let mut compiled = false;
    for (exe, lead) in &tools.compilers {
        let mut cmd = Command::new(exe);
        cmd.current_dir(scratch).args(lead).arg("-O").arg("-o").arg(&files.binary).arg(&files.source);
        apply_probe_env(&mut cmd);
        match run_bounded(&mut cmd, tools.compile_timeout, PROBE_STDOUT_CAP) {
            Ran::Failed(std::io::ErrorKind::NotFound) => continue,
            Ran::Failed(kind) => {
                return row(KEY_ROW, Status::Unsupported, format!("could not start the swift compiler {}: {kind}", exe.display()));
            }
            Ran::TimedOut => {
                return row(KEY_ROW, Status::Inconclusive, format!("swift compile timed out after {}s", tools.compile_timeout.as_secs()));
            }
            Ran::Lingered => {
                return row(KEY_ROW, Status::Inconclusive, "swift compiler left a process holding its output open after exit (its process group was killed)");
            }
            Ran::Exited { overflow: true, .. } => {
                return row(KEY_ROW, Status::Inconclusive, "swift compiler output exceeded the expected size");
            }
            Ran::Exited { status, .. } if !status.success() => {
                return row(KEY_ROW, Status::Unsupported, format!("swift compiler unavailable or failed ({})", describe_exit(status)));
            }
            Ran::Exited { .. } => {
                compiled = true;
                break;
            }
        }
    }
    if !compiled {
        return row(KEY_ROW, Status::Unsupported, "no swift compiler found (tried /usr/bin/xcrun and /usr/bin/swiftc)");
    }
    let mut probe = Command::new(&files.binary);
    probe.current_dir(scratch).arg(scratch);
    apply_probe_env(&mut probe);
    judge_probe_run(run_bounded(&mut probe, tools.run_timeout, PROBE_STDOUT_CAP), tools.run_timeout)
}

/// Only the fixed tokens `match` / `mismatch` (exit 0) and exit status 3 are interpreted; nothing the
/// probe wrote is ever copied into the row.
fn judge_probe_run(ran: Ran, run_timeout: Duration) -> Row {
    match ran {
        Ran::Failed(kind) => row(KEY_ROW, Status::Inconclusive, format!("could not run the compiled probe: {kind}")),
        Ran::TimedOut => row(KEY_ROW, Status::Inconclusive, format!("probe timed out after {}s", run_timeout.as_secs())),
        Ran::Lingered => row(KEY_ROW, Status::Inconclusive, "probe left a process holding its output open after exit (its process group was killed)"),
        Ran::Exited { overflow: true, .. } => row(KEY_ROW, Status::Inconclusive, "probe output exceeded the expected size"),
        Ran::Exited { status, stdout, overflow: false } => match (status.code(), stdout.trim_ascii()) {
            (Some(0), b"match") => row(
                KEY_ROW,
                Status::Fail,
                "a no-prompt Secure Enclave key blob was usable from this environment without Karambit (synthetic key; limit #6)",
            ),
            (Some(0), b"mismatch") => {
                row(KEY_ROW, Status::Inconclusive, "the synthetic key agreement did not verify (shared secrets differed)")
            }
            (Some(3), _) => row(KEY_ROW, Status::Unsupported, "no Secure Enclave available on this host"),
            (Some(0), _) => row(KEY_ROW, Status::Inconclusive, "probe exited 0 with unrecognised output"),
            _ => row(KEY_ROW, Status::Inconclusive, format!("probe failed ({})", describe_exit(status))),
        },
    }
}

// ------------------------------------------------------------------ daemon socket

/// Connect to the live socket path, then shut down and close without writing a byte. No request is
/// sent, so nothing in the daemon's request path (dispatch-time expiry, audit, state) runs. Never
/// spawns a daemon (deliberately not `daemon::request`, which autostarts one).
pub fn check_daemon_socket(sock: &Path, timeout: Duration) -> Row {
    const NAME: &str = "daemon-socket";
    if std::fs::symlink_metadata(sock).is_err() {
        return row(NAME, Status::Inconclusive, "no daemon socket (daemon not running; doctor never starts one)");
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let path = sock.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(connect_only(&path));
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(())) => row(NAME, Status::Pass, "socket accepted a connection; no request sent"),
        Ok(Err(why)) => row(NAME, Status::Inconclusive, why),
        Err(_) => row(NAME, Status::Inconclusive, "connecting to the daemon socket timed out"),
    }
}

fn connect_only(path: &Path) -> std::result::Result<(), String> {
    let stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| format!("socket exists but connect failed: {}", e.kind()))?;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

// ------------------------------------------------------------------ audit / config / pin writable

enum Tamper {
    /// The file can be written, replaced or created from here.
    Possible(&'static str),
    Blocked,
    /// Neither the file nor its directory exists.
    Absent,
    /// A metadata or access error other than a plain "no"; the outcome cannot be judged.
    Unknown(String),
}

/// Ok(true) = allowed, Ok(false) = the kernel said no (EACCES/EPERM/EROFS), Err = anything else.
fn access_decision(path: &Path, mode: libc::c_int) -> std::result::Result<bool, String> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| "path contains NUL".to_string())?;
    if unsafe { libc::access(c.as_ptr(), mode) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EACCES | libc::EPERM | libc::EROFS) => Ok(false),
        _ => Err(e.kind().to_string()),
    }
}

/// Can this process replace (unlink/rename) `entry` in `parent`, given the parent is W+X for us?
/// In a sticky directory only the entry's owner, the directory's owner or root may.
fn replaceable_in(parent: &Path, entry: &std::fs::Metadata) -> bool {
    match std::fs::metadata(parent) {
        Ok(pm) if pm.mode() & libc::S_ISVTX as u32 != 0 => {
            let me = unsafe { libc::geteuid() };
            me == 0 || entry.uid() == me || pm.uid() == me
        }
        Ok(_) => true,
        Err(_) => false,
    }
}

fn tamper_of(path: &Path) -> Tamper {
    let Some(parent) = path.parent() else { return Tamper::Unknown("no parent directory".into()) };
    let parent_writable = match access_decision(parent, libc::W_OK | libc::X_OK) {
        Ok(w) => w,
        Err(_) if matches!(std::fs::symlink_metadata(parent), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) => {
            return Tamper::Absent;
        }
        Err(e) => return Tamper::Unknown(format!("cannot check directory access: {e}")),
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let replaceable = parent_writable && replaceable_in(parent, &meta);
            match access_decision(path, libc::W_OK) {
                Ok(true) => Tamper::Possible("file writable"),
                Ok(false) if replaceable => Tamper::Possible("replaceable via writable directory"),
                Ok(false) => Tamper::Blocked,
                // Proven replaceable through the parent, whatever the entry's own access reports.
                Err(_) if replaceable => Tamper::Possible("replaceable via writable directory"),
                Err(e) => Tamper::Unknown(format!("cannot check file access: {e}")),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if parent_writable { Tamper::Possible("absent but creatable in writable directory") } else { Tamper::Blocked }
        }
        Err(e) => Tamper::Unknown(format!("cannot stat file: {}", e.kind())),
    }
}

/// Metadata + access(2) only: nothing is opened for writing, nothing is created or changed.
/// `fail` if any discovered target is tamperable; else `inconclusive` if anything could not be
/// judged (including a failed directory listing); else `pass`.
pub fn check_writable(paths: &Paths) -> Row {
    const NAME: &str = "audit-config-pin-writable";
    let mut targets: Vec<(String, PathBuf)> = vec![
        ("audit.jsonl".into(), paths.audit()),
        ("config.json".into(), paths.config()),
    ];
    let mut unknown: Vec<String> = vec![];
    let mut pins: Vec<String> = vec![];
    match std::fs::read_dir(paths.keys()) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => {
                        let n = e.file_name().to_string_lossy().into_owned();
                        if n.ends_with(".sha256") {
                            pins.push(n);
                        }
                    }
                    Err(e) => unknown.push(format!("keys/ entry unreadable: {}", e.kind())),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => unknown.push(format!("keys/ cannot be listed, extra pins unknown: {}", e.kind())),
    }
    for canonical in ["helper.sha256", "daemon.sha256"] {
        if !pins.iter().any(|p| p == canonical) {
            pins.push(canonical.into());
        }
    }
    pins.sort();
    targets.extend(pins.into_iter().map(|n| (format!("keys/{n}"), paths.keys().join(&n))));

    let (mut writable, mut blocked) = (vec![], vec![]);
    for (label, path) in &targets {
        match tamper_of(path) {
            Tamper::Possible(how) => writable.push(format!("{label} ({how})")),
            Tamper::Blocked => blocked.push(label.as_str()),
            Tamper::Absent => {}
            Tamper::Unknown(why) => unknown.push(format!("{label}: {why}")),
        }
    }
    if !writable.is_empty() {
        row(NAME, Status::Fail, format!("tamperable from this environment: {}", writable.join(", ")))
    } else if !unknown.is_empty() {
        row(NAME, Status::Inconclusive, format!("could not judge everything: {}", unknown.join("; ")))
    } else if blocked.is_empty() {
        row(NAME, Status::Inconclusive, "no vault files found at this location; nothing to judge")
    } else {
        row(NAME, Status::Pass, format!("not writable from this environment: {}", blocked.join(", ")))
    }
}

// ------------------------------------------------------------------ redaction

pub type MakeRedactor = fn(&[(String, &[u8])]) -> Redactor;

/// Same construction as a bound launch (`Redactor::new` over the named raw value).
pub fn production_redactor(secrets: &[(String, &[u8])]) -> Redactor {
    Redactor::new(secrets)
}

pub fn check_redaction(canary: &Canary, make: MakeRedactor) -> Row {
    const NAME: &str = "redaction";
    let value = canary.value.as_bytes();
    let secrets = [(canary.name.clone(), value)];
    let red = make(&secrets);
    let forms: [(&str, Zeroizing<Vec<u8>>); 3] = [
        ("echo", Zeroizing::new(value.to_vec())),
        ("base64", base64_std(value)),
        ("20-char truncation", Zeroizing::new(value[..20].to_vec())),
    ];
    let (mut redacted, mut leaked) = (vec![], vec![]);
    for (label, form) in &forms {
        let mut buf = Zeroizing::new(Vec::with_capacity(form.len() + 16));
        buf.extend_from_slice(b"out: ");
        buf.extend_from_slice(form);
        buf.push(b'\n');
        let out = Zeroizing::new(red.process(&mut buf, true));
        if contains(&out, form) { leaked.push(*label) } else { redacted.push(*label) }
    }
    if leaked.is_empty() {
        return row(NAME, Status::Pass, "echo, base64 and 20-char truncation forms were all redacted");
    }
    let known = if leaked.contains(&"base64") {
        " (known limit #9, encoding-aware redaction planned)"
    } else {
        ""
    };
    let kept = if redacted.is_empty() { String::new() } else { format!("; redacted: {}", redacted.join(", ")) };
    row(NAME, Status::Fail, format!("{} form not redacted{known}{kept}", leaked.join(", ")))
}

// ------------------------------------------------------------------ caller

pub fn check_caller(caller: &Caller) -> Row {
    const NAME: &str = "caller-agent";
    let chain = caller.chain.iter().take(4).cloned().collect::<Vec<_>>().join(" < ");
    if caller.remote && !caller.is_agent() {
        row(NAME, Status::Pass, format!("no agent detected, but this caller arrived over SSH (remote); human-only commands are refused unless allow_ssh_human is on (chain: {chain})"))
    } else if caller.is_agent() {
        row(NAME, Status::Pass, format!("agent detected: {} (chain: {chain})", caller.label()))
    } else if caller.suspect {
        row(NAME, Status::Pass, format!("no agent detected (script interpreter without terminal ancestor, telemetry only; chain: {chain})"))
    } else {
        row(NAME, Status::Pass, format!("no agent detected (human shell; detection is a heuristic, chain: {chain})"))
    }
}

// ------------------------------------------------------------------ orchestration

pub struct Env<'a> {
    pub home: Option<PathBuf>,
    pub paths: &'a Paths,
    pub caller: &'a Caller,
    pub tmp_root: PathBuf,
    pub ps: PathBuf,
    pub sibling: SiblingCmd,
    pub make_redactor: MakeRedactor,
    pub key_probe: KeyProbe,
}

pub struct Report {
    pub checks: Vec<Row>,
    /// `karambit-doctor-*` entries found in TMPDIR and what was done with them.
    pub leftovers: Vec<(String, LeftoverAction)>,
}

pub fn run_checks(env: &Env, canary: &Canary, scratch: &Path) -> Vec<Row> {
    vec![
        check_sibling_env(&env.ps, &env.sibling, canary, scratch),
        check_vault_token(env.home.as_deref()),
        (env.key_probe)(scratch),
        check_daemon_socket(&karambit_core::daemon::sock_path(env.paths), Duration::from_secs(2)),
        check_writable(env.paths),
        check_redaction(canary, env.make_redactor),
        check_caller(env.caller),
        check_jail(),
        check_remote_login(),
    ]
}

// ------------------------------------------------------------------ Remote Login

/// Read-only. `systemsetup -getremotelogin` needs admin rights, so it is only believed when
/// it answers; otherwise a loaded sshd launchd job or a listener on loopback port 22 counts.
pub fn check_remote_login() -> Row {
    let setup = Command::new("/usr/sbin/systemsetup").arg("-getremotelogin")
        .stdin(Stdio::null()).stderr(Stdio::null()).output().ok()
        .and_then(|o| o.status.success().then(|| parse_systemsetup(&String::from_utf8_lossy(&o.stdout))).flatten());
    let launchd = Command::new("/bin/launchctl").args(["print", "system/com.openssh.sshd"])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    let loopback = std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], 22)), Duration::from_millis(500)).is_ok();
    judge_remote_login(setup, launchd, loopback)
}

/// "Remote Login: On" / "Remote Login: Off" -> Some(on).
fn parse_systemsetup(out: &str) -> Option<bool> {
    let v = out.trim().strip_prefix("Remote Login:")?.trim().to_ascii_lowercase();
    match v.as_str() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

fn judge_remote_login(setup: Option<bool>, launchd_loaded: bool, loopback_open: bool) -> Row {
    const NAME: &str = "remote-login";
    let on = setup.unwrap_or(launchd_loaded || loopback_open);
    if on {
        let how = match setup {
            Some(_) => "systemsetup reports Remote Login on",
            None if launchd_loaded => "the sshd launchd job is loaded",
            None => "loopback port 22 accepts connections",
        };
        row(NAME, Status::Fail, format!("macOS Remote Login is on ({how}): a process that adds a key to ~/.ssh/authorized_keys can `ssh localhost karambit ...` with no agent in its process chain. Karambit marks SSH callers remote and refuses human-only commands from them (allow_ssh_human is off by default), but secrets an agent may use stay reachable. Turn Remote Login off in System Settings > General > Sharing unless you need it"))
    } else if setup.is_some() {
        row(NAME, Status::Pass, "Remote Login is off (systemsetup)")
    } else {
        row(NAME, Status::Pass, "Remote Login looks off (no sshd launchd job, nothing on loopback port 22; systemsetup needs admin so it was not used)")
    }
}

fn check_jail() -> Row {
    use karambit_core::sandbox::{NativeSandbox, Sandbox};
    if NativeSandbox.available() {
        row("jail-availability", Status::Inconclusive,
            "capability (6): Seatbelt SPI linked; run --jail installs fail-closed. Availability is not enforcement proof; deprecated sandbox-exec mechanism, paired probes required; remote egress needs a loopback proxy")
    } else {
        row("jail-availability", Status::Unsupported,
            "capability (6) missing: Mode B refused; Mode A only")
    }
}

pub fn collect(env: &Env) -> Result<Report> {
    let leftovers = clean_leftovers(&env.tmp_root);
    let canary = Canary::generate()?;
    #[cfg(test)]
    LAST_CANARY.with(|c| *c.borrow_mut() = Some(canary.value.to_string()));
    let scratch = Scratch::create(&env.tmp_root)?;
    let checks = run_checks(env, &canary, scratch.path());
    Ok(Report { checks, leftovers })
}

// Unit tests only: the canary of the latest `collect` on this thread, so tests can prove it never
// reaches rendered output. No environment variable or file is involved; compiled out of every
// non-test build.
#[cfg(test)]
thread_local! {
    static LAST_CANARY: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

pub fn render_table(report: &Report) -> String {
    let w = report.checks.iter().map(|r| r.name.len()).max().unwrap_or(0).max("check".len());
    let s = report.checks.iter().map(|r| r.status.as_str().len()).max().unwrap_or(0).max("status".len());
    let mut out = format!("{:<w$}  {:<s$}  why\n", "check", "status");
    for r in &report.checks {
        out.push_str(&format!("{:<w$}  {:<s$}  {}\n", r.name, r.status.as_str(), r.why));
    }
    for (name, action) in &report.leftovers {
        out.push_str(&format!("leftover {name}: {}\n", action.as_str()));
    }
    out.push_str(&format!("scope: {SCOPE}\n"));
    out
}

pub fn render_json(report: &Report) -> serde_json::Value {
    json!({
        "checks": report.checks.iter().map(|r| json!({"name": r.name, "status": r.status.as_str(), "why": r.why})).collect::<Vec<_>>(),
        "leftovers": report.leftovers.iter().map(|(n, action)| json!({"name": n, "action": action.as_str()})).collect::<Vec<_>>(),
        "scope": SCOPE,
    })
}

/// CLI entry. `paths` and `caller` come from the normal CLI startup; nothing else is opened.
pub fn run(paths: &Paths, caller: &Caller, as_json: bool) -> Result<()> {
    let env = Env {
        home: std::env::var_os("HOME").map(PathBuf::from),
        paths,
        caller,
        tmp_root: std::env::temp_dir(),
        ps: PathBuf::from("/bin/ps"),
        sibling: SiblingCmd::production()?,
        make_redactor: production_redactor,
        key_probe: production_key_probe,
    };
    let report = collect(&env)?;
    if as_json {
        crate::print_json(&render_json(&report));
    } else {
        print!("{}", render_table(&report));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    const HOLD_TEST: &str = "doctor::tests::hold_helper";

    /// Re-run as the synthetic sibling: `--exact doctor::tests::hold_helper` with the env flag set.
    #[test]
    fn hold_helper() {
        if std::env::var_os("KARAMBIT_DOCTOR_HOLD").is_some() {
            hold();
        }
    }

    fn test_sibling() -> SiblingCmd {
        SiblingCmd {
            exe: std::env::current_exe().unwrap(),
            args: vec!["--exact".into(), HOLD_TEST.into(), "--nocapture".into()],
            marker: "hold_helper".into(),
            extra_env: vec![("KARAMBIT_DOCTOR_HOLD".into(), "1".into())],
        }
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(label: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!("kd-{label}-{}-{}", std::process::id(), hex(&{
                let mut b = [0u8; 3];
                fill_random(&mut b).unwrap();
                b
            })));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            // Restore permissions so cleanup works after read-only fixtures.
            fn unlock(p: &Path) {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
                if let Ok(rd) = std::fs::read_dir(p) {
                    for e in rd.flatten() {
                        if e.file_type().is_ok_and(|t| t.is_dir()) {
                            unlock(&e.path());
                        } else {
                            let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o600));
                        }
                    }
                }
            }
            unlock(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    // ---- sibling env via ps -E

    #[test]
    fn ps_sibling_check_runs_for_real_and_cleans_up() {
        let tmp = Tmp::new("ps");
        let canary = Canary::generate().unwrap();
        let r = check_sibling_env(Path::new("/bin/ps"), &test_sibling(), &canary, tmp.path());
        // Same-user ps -E shows a non-platform sibling's environment: the honest result here is fail.
        assert_eq!(r.status, Status::Fail, "{}", r.why);
        assert!(!r.why.contains(canary.value.as_str()));
    }

    #[test]
    fn ps_output_judgement_is_fail_pass_or_inconclusive() {
        let canary = Canary::generate().unwrap();
        let mut seen = b"cmd marker FOO=1 ".to_vec();
        seen.extend_from_slice(canary.value.as_bytes());
        let rows = [
            (judge_ps_output(&seen, &canary, "marker"), Status::Fail),
            (judge_ps_output(b"cmd marker FOO=1", &canary, "marker"), Status::Pass),
            (judge_ps_output(b"", &canary, "marker"), Status::Inconclusive),
            (judge_ps_output(b"other process", &canary, "marker"), Status::Inconclusive),
        ];
        for (row, want) in rows {
            assert_eq!(row.status, want, "{}", row.why);
            assert!(!row.why.contains(canary.value.as_str()), "canary in a why string");
        }
    }

    #[test]
    fn ps_failure_or_missing_ps_is_inconclusive_and_sibling_is_reaped() {
        let tmp = Tmp::new("psfail");
        let canary = Canary::generate().unwrap();
        for ps in ["/usr/bin/false", "/nonexistent/ps"] {
            assert_eq!(check_sibling_env(Path::new(ps), &test_sibling(), &canary, tmp.path()).status, Status::Inconclusive, "{ps}");
        }
        let bad = SiblingCmd { exe: "/nonexistent/sibling".into(), args: vec![], marker: "x".into(), extra_env: vec![] };
        assert_eq!(check_sibling_env(Path::new("/bin/ps"), &bad, &canary, tmp.path()).status, Status::Inconclusive);
    }

    #[test]
    fn sibling_is_killed_and_reaped_on_drop() {
        let tmp = Tmp::new("reap");
        let canary = Canary::generate().unwrap();
        let s = Sibling::spawn(&test_sibling(), &canary, tmp.path()).unwrap();
        let pid = s.child.id() as i32;
        assert!(pid_alive(pid));
        drop(s);
        // Reaped: the pid is no longer our child nor alive.
        assert!(!pid_alive(pid));
    }

    // ---- ~/.vault-token

    #[test]
    fn vault_token_absent_readable_unreadable() {
        let home = Tmp::new("home");
        assert_eq!(check_vault_token(Some(home.path())).status, Status::Pass);
        assert_eq!(check_vault_token(None).status, Status::Inconclusive);
        let token = home.path().join(".vault-token");
        std::fs::write(&token, b"hvs.SYNTHETIC").unwrap();
        let r = check_vault_token(Some(home.path()));
        assert_eq!(r.status, Status::Fail);
        assert!(!r.why.contains("hvs"));
        if !is_root() {
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o000)).unwrap();
            let r = check_vault_token(Some(home.path()));
            assert_eq!(r.status, Status::Pass);
            assert!(r.why.contains("not readable"));
        }
    }

    #[test]
    fn vault_token_is_never_opened() {
        // A FIFO with no writer blocks any open-for-read forever; the check must return promptly.
        let home = Tmp::new("fifo");
        let token = CString::new(home.path().join(".vault-token").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(token.as_ptr(), 0o600) }, 0);
        let path = home.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(check_vault_token(Some(&path))).unwrap());
        let r = rx.recv_timeout(Duration::from_secs(5)).expect("check blocked: it opened ~/.vault-token");
        assert_eq!(r.status, Status::Fail);
    }

    // ---- key-blob use

    /// Fake toolchain: `/bin/sh -c` "compilers" write a fake probe script (`body`) to the `-o` path.
    /// The real probe is never built or executed by any unit test.
    fn fake_tools(body: &str) -> ProbeTools {
        assert!(!body.contains('\''));
        let script = format!("printf '%s\\n' '#!/bin/sh' '{body}' > \"$3\" && chmod 700 \"$3\"");
        ProbeTools {
            compilers: vec![("/bin/sh".into(), vec!["-c".into(), script.into(), "fakecc".into()])],
            compile_timeout: Duration::from_secs(20),
            run_timeout: Duration::from_secs(20),
        }
    }

    fn missing_tools() -> ProbeTools {
        ProbeTools {
            compilers: vec![("/nonexistent/xcrun".into(), vec!["swiftc".into()]), ("/nonexistent/swiftc".into(), vec![])],
            compile_timeout: Duration::from_secs(20),
            run_timeout: Duration::from_secs(20),
        }
    }

    fn random_hex(n: usize) -> String {
        let mut b = vec![0u8; n];
        fill_random(&mut b).unwrap();
        hex(&b)
    }

    fn probe_in_scratch(tools: &ProbeTools) -> (Row, usize) {
        let tmp = Tmp::new("kp");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let r = run_key_probe(scratch.path(), tools);
        let left = std::fs::read_dir(scratch.path()).unwrap().flatten().filter(|e| e.file_name() != MARKER_FILE).count();
        drop(scratch);
        assert_eq!(scratch_count(tmp.path()), 0);
        (r, left)
    }

    const MATCH_WHY: &str = "a no-prompt Secure Enclave key blob was usable from this environment without Karambit (synthetic key; limit #6)";

    #[test]
    fn probe_match_is_fail() {
        let (r, left) = probe_in_scratch(&fake_tools("echo match"));
        assert_eq!((r.name, r.status, r.why.as_str()), ("key-blob-use", Status::Fail, MATCH_WHY));
        assert_eq!(left, 0, "source, binary and blob are removed on every path");
    }

    #[test]
    fn probe_mismatch_is_inconclusive() {
        let (r, _) = probe_in_scratch(&fake_tools("echo mismatch"));
        assert_eq!(r.status, Status::Inconclusive);
        assert!(r.why.contains("did not verify"), "{}", r.why);
    }

    #[test]
    fn probe_unavailable_exit_3_is_unsupported() {
        let (r, _) = probe_in_scratch(&fake_tools("echo unavailable; exit 3"));
        assert_eq!((r.status, r.why.as_str()), (Status::Unsupported, "no Secure Enclave available on this host"));
    }

    #[test]
    fn probe_nonzero_exit_is_inconclusive_with_the_exit_code_only() {
        let (r, _) = probe_in_scratch(&fake_tools("echo match; exit 1"));
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe failed (exit status 1)"));
        let (r, _) = probe_in_scratch(&fake_tools("kill -9 $$"));
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe failed (signal 9)"));
    }

    #[test]
    fn probe_garbage_is_inconclusive_and_never_echoed() {
        let secret = random_hex(32);
        for body in [
            format!("echo {secret}"),
            format!("echo {secret}; exit 1"),
            format!("echo {secret}; exit 3"),
            format!("echo match {secret}"),
            format!("echo {secret} >&2; exit 1"),
            "exit 0".to_string(),
            "echo MATCH".to_string(),
        ] {
            let (r, _) = probe_in_scratch(&fake_tools(&body));
            assert!(!r.why.contains(&secret), "{body}: {}", r.why);
            assert!(!r.why.contains("match ") && !r.why.contains(&secret[..12]), "{}", r.why);
            assert_ne!(r.status, Status::Pass);
            assert_ne!(r.status, Status::Fail, "{body}");
        }
        let (r, _) = probe_in_scratch(&fake_tools(&format!("echo {secret}")));
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe exited 0 with unrecognised output"));
    }

    #[test]
    fn probe_huge_output_is_bounded_and_never_pass() {
        let (r, _) = probe_in_scratch(&fake_tools("yes match | head -c 3000000"));
        assert_eq!(r.status, Status::Inconclusive);
        assert!(r.why.len() < 200);
    }

    #[test]
    fn overflowing_output_with_a_match_prefix_is_inconclusive_not_fail() {
        // Regression: `match` + padding past the cap + garbage must not be read as `match`.
        let body = format!("printf match; printf \"%{}s\" \"\"; echo garbage", PROBE_STDOUT_CAP);
        let (r, left) = probe_in_scratch(&fake_tools(&body));
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe output exceeded the expected size"));
        assert_eq!(left, 0);
    }

    #[test]
    fn early_parent_exit_with_a_descendant_holding_stdout_kills_the_group() {
        // Regression: the probe prints `match` and exits 0, but a background child keeps
        // stdout open. Not trusted, and the descendant is killed.
        let tmp = Tmp::new("kplinger");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let pids = tmp.path().join("pids");
        let body = format!("/bin/sleep 30 & echo $! > {}; echo match; exit 0", pids.display());
        let started = Instant::now();
        let r = run_key_probe(scratch.path(), &fake_tools(&body));
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe left a process holding its output open after exit (its process group was killed)"));
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: i32 = std::fs::read_to_string(&pids).unwrap().trim().parse().unwrap();
        assert!(pid_gone(pid), "descendant {pid} outlived the probe");
    }

    #[test]
    fn exited_parent_descendants_are_killed_even_when_stdout_closes() {
        // A descendant that closed stdout but is still running is killed with the group too.
        let tmp = Tmp::new("kpdesc");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let pids = tmp.path().join("pids");
        let body = format!("/bin/sleep 30 >/dev/null & echo $! > {}; echo match; exit 0", pids.display());
        let r = run_key_probe(scratch.path(), &fake_tools(&body));
        assert_eq!(r.status, Status::Fail);
        let pid: i32 = std::fs::read_to_string(&pids).unwrap().trim().parse().unwrap();
        assert!(pid_gone(pid), "descendant {pid} outlived the probe");
    }

    #[test]
    fn escaped_writer_holding_stdout_does_not_hang_the_doctor() {
        // Regression: a descendant that leaves the process group (setsid) and keeps
        // stdout open is out of killpg's reach; the doctor must still return, bounded, and not
        // trust the run.
        let tmp = Tmp::new("kpesc");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let pidfile = tmp.path().join("esc.pid");
        let body = format!(
            "/usr/bin/perl -MPOSIX -e \"exit if fork; setsid(); open F, q(>), q({}); print F \\$\\$; close F; sleep 30\"; sleep 0.3; echo match; exit 0",
            pidfile.display()
        );
        let started = Instant::now();
        let r = run_key_probe(scratch.path(), &fake_tools(&body));
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        unsafe { libc::kill(pid, libc::SIGKILL) };
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe left a process holding its output open after exit (its process group was killed)"));
        assert!(started.elapsed() < Duration::from_secs(10), "doctor waited on an escaped writer");
    }

    #[test]
    fn drain_some_is_bounded_against_an_endless_reader() {
        // Regression: an always-ready reader must not keep drain_some
        // from returning. Also: EINTR counts toward the bound.
        struct Endless(usize);
        impl Read for Endless {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                b.fill(b'x');
                Ok(b.len())
            }
        }
        struct Eintr(usize);
        impl Read for Eintr {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                Err(std::io::ErrorKind::Interrupted.into())
            }
        }
        let mut st = DrainState::default();
        let mut r = Endless(0);
        drain_some(&mut r, PROBE_STDOUT_CAP, &mut st);
        assert_eq!(r.0, DRAIN_READS);
        assert!(st.overflow && !st.eof && st.kept.len() == PROBE_STDOUT_CAP);
        let mut r = Eintr(0);
        drain_some(&mut r, PROBE_STDOUT_CAP, &mut DrainState::default());
        assert_eq!(r.0, DRAIN_READS);
    }

    #[test]
    fn sustained_output_cannot_starve_the_timeout() {
        // Regression: a probe that writes forever must still time out on schedule.
        let mut tools = fake_tools("exec /usr/bin/yes");
        tools.run_timeout = Duration::from_secs(2);
        let started = Instant::now();
        let (r, left) = probe_in_scratch(&tools);
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe timed out after 2s"));
        assert!(started.elapsed() < Duration::from_secs(10), "drain starved the run clock");
        assert_eq!(left, 0);
    }

    #[test]
    fn escaped_active_writer_cannot_starve_the_grace_period() {
        // Regression: after the probe exits, an escaped (setsid) writer that keeps the
        // pipe full must not keep the doctor in the grace-period drain.
        let tmp = Tmp::new("kpescw");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let pidfile = tmp.path().join("esc.pid");
        let body = format!(
            "/usr/bin/perl -MPOSIX -e \"exit if fork; setsid(); open F, q(>), q({}); print F \\$\\$; close F; alarm 30; exec q(/usr/bin/yes)\"; sleep 0.3; echo match; exit 0",
            pidfile.display()
        );
        let started = Instant::now();
        let r = run_key_probe(scratch.path(), &fake_tools(&body));
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        unsafe { libc::kill(pid, libc::SIGKILL) };
        assert_eq!(r.status, Status::Inconclusive, "{}", r.why);
        assert!(started.elapsed() < Duration::from_secs(10), "drain starved the grace clock");
    }

    #[test]
    fn relative_scratch_dir_still_compiles_and_runs() {
        // Regression: a relative TMPDIR must not break the cwd-relative paths.
        let tmp = Tmp::new("kprel");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let cwd = std::env::current_dir().unwrap();
        let rel = pathdiff_rel(&cwd, scratch.path());
        assert!(rel.is_relative());
        // The fake compiler records its -o / source arguments: they must be absolute (a relative
        // path that climbs to `/` can resolve by accident, so check the arguments, not just success).
        let args = tmp.path().join("cc.args");
        let script = format!(
            "printf '%s\\n' \"$3\" \"$4\" > {} && printf '%s\\n' '#!/bin/sh' 'echo match' > \"$3\" && chmod 700 \"$3\"",
            args.display()
        );
        let tools = ProbeTools { compilers: vec![("/bin/sh".into(), vec!["-c".into(), script.into(), "cc".into()])], ..missing_tools() };
        let r = run_key_probe(&rel, &tools);
        assert_eq!(r.status, Status::Fail, "{}", r.why);
        for a in std::fs::read_to_string(&args).unwrap().lines() {
            assert!(Path::new(a).is_absolute(), "compiler got a relative path {a}");
        }
        let left = std::fs::read_dir(scratch.path()).unwrap().flatten().filter(|e| e.file_name() != MARKER_FILE).count();
        assert_eq!(left, 0);
    }

    /// `target` relative to `base` using `..` components (both absolute).
    fn pathdiff_rel(base: &Path, target: &Path) -> PathBuf {
        let (b, t): (Vec<_>, Vec<_>) = (base.components().collect(), target.components().collect());
        let common = b.iter().zip(&t).take_while(|(x, y)| x == y).count();
        let mut out = PathBuf::new();
        for _ in common..b.len() {
            out.push("..");
        }
        for c in &t[common..] {
            out.push(c);
        }
        out
    }

    #[test]
    fn compiler_overflow_is_inconclusive() {
        let script = format!(
            "head -c {} /dev/zero | tr '\\0' x; printf '%s\\n' '#!/bin/sh' 'echo match' > \"$3\" && chmod 700 \"$3\"",
            PROBE_STDOUT_CAP + 1
        );
        let tools = ProbeTools { compilers: vec![("/bin/sh".into(), vec!["-c".into(), script.into(), "cc".into()])], ..missing_tools() };
        let (r, left) = probe_in_scratch(&tools);
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "swift compiler output exceeded the expected size"));
        assert_eq!(left, 0);
    }

    #[test]
    fn compiler_and_probe_run_with_the_scratch_dir_as_cwd() {
        let tmp = Tmp::new("kpcwd");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let cc_cwd = tmp.path().join("cc.cwd");
        let probe_cwd = tmp.path().join("probe.cwd");
        let script = format!(
            "/bin/pwd -P > {} && printf '%s\\n' '#!/bin/sh' '/bin/pwd -P > {}' 'echo match' > \"$3\" && chmod 700 \"$3\"",
            cc_cwd.display(),
            probe_cwd.display()
        );
        let tools = ProbeTools { compilers: vec![("/bin/sh".into(), vec!["-c".into(), script.into(), "cc".into()])], ..missing_tools() };
        assert_eq!(run_key_probe(scratch.path(), &tools).status, Status::Fail);
        let want = std::fs::canonicalize(scratch.path()).unwrap();
        for f in [&cc_cwd, &probe_cwd] {
            assert_eq!(PathBuf::from(std::fs::read_to_string(f).unwrap().trim()), want, "{}", f.display());
        }
    }

    #[test]
    fn no_compiler_is_unsupported() {
        let (r, left) = probe_in_scratch(&missing_tools());
        assert_eq!(r.status, Status::Unsupported);
        assert_eq!(r.why, "no swift compiler found (tried /usr/bin/xcrun and /usr/bin/swiftc)");
        assert_eq!(left, 0);
        let (r, _) = probe_in_scratch(&ProbeTools { compilers: vec![], ..missing_tools() });
        assert_eq!(r.status, Status::Unsupported);
    }

    #[test]
    fn compiler_error_is_unsupported_and_fallback_runs_only_when_the_first_is_missing() {
        let failing = ProbeTools {
            compilers: vec![("/usr/bin/false".into(), vec![])],
            ..missing_tools()
        };
        let (r, _) = probe_in_scratch(&failing);
        assert_eq!((r.status, r.why.as_str()), (Status::Unsupported, "swift compiler unavailable or failed (exit status 1)"));
        // First compiler missing: the second one is used.
        let mut tools = fake_tools("echo match");
        tools.compilers.insert(0, ("/nonexistent/xcrun".into(), vec![]));
        assert_eq!(probe_in_scratch(&tools).0.status, Status::Fail);
        // First compiler present but failing: no fallback (a broken xcrun is not retried as swiftc).
        let mut tools = fake_tools("echo match");
        tools.compilers.insert(0, ("/usr/bin/false".into(), vec![]));
        assert_eq!(probe_in_scratch(&tools).0.status, Status::Unsupported);
    }

    #[test]
    fn production_tools_are_xcrun_then_swiftc_with_the_specified_timeouts() {
        let t = ProbeTools::production();
        assert_eq!(t.compilers, vec![
            (PathBuf::from("/usr/bin/xcrun"), vec![OsString::from("swiftc")]),
            (PathBuf::from("/usr/bin/swiftc"), vec![]),
        ]);
        assert_eq!((t.compile_timeout, t.run_timeout), (Duration::from_secs(120), Duration::from_secs(15)));
    }

    #[test]
    fn probe_sees_only_the_allowed_environment() {
        let tmp = Tmp::new("kpenv");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let dump = tmp.path().join("env.txt");
        let body = format!("/usr/bin/env > {}; echo mismatch", dump.display());
        let r = run_key_probe(scratch.path(), &fake_tools(&body));
        assert_eq!(r.status, Status::Inconclusive);
        let text = std::fs::read_to_string(&dump).unwrap();
        for line in text.lines() {
            let key = line.split('=').next().unwrap();
            // PWD, SHLVL and _ are added by /bin/sh itself.
            assert!(PROBE_ENV_ALLOWED.contains(&key) || ["PWD", "SHLVL", "_", "OLDPWD"].contains(&key), "leaked env var {key}");
        }
    }

    #[test]
    fn probe_runs_in_scratch_dir_and_its_blob_is_removed_even_if_it_leaks_it() {
        let tmp = Tmp::new("kpblob");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let body = format!(": > \"$1/{PROBE_BLOB_FILE}\"; echo match");
        let r = run_key_probe(scratch.path(), &fake_tools(&body));
        assert_eq!(r.status, Status::Fail);
        assert!(!scratch.path().join(PROBE_BLOB_FILE).exists());
        assert!(!scratch.path().join(PROBE_SOURCE_FILE).exists());
        assert!(!scratch.path().join(PROBE_BINARY_FILE).exists());
    }

    #[test]
    fn probe_source_is_written_0600_exactly_as_embedded() {
        let tmp = Tmp::new("kpsrc");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let seen = tmp.path().join("seen.swift");
        // Fake compiler copies its source argument (and reports its mode) before "compiling".
        let script = format!("cp \"$4\" {0} && stat -f %Lp \"$4\" > {0}.mode && printf '#!/bin/sh\\necho match\\n' > \"$3\" && chmod 700 \"$3\"", seen.display());
        let tools = ProbeTools { compilers: vec![("/bin/sh".into(), vec!["-c".into(), script.into(), "cc".into()])], ..missing_tools() };
        assert_eq!(run_key_probe(scratch.path(), &tools).status, Status::Fail);
        assert_eq!(std::fs::read_to_string(&seen).unwrap(), KEY_USE_PROBE_SOURCE);
        assert_eq!(std::fs::read_to_string(tmp.path().join("seen.swift.mode")).unwrap().trim(), "600");
    }

    fn pid_gone(pid: i32) -> bool {
        (0..60).any(|_| {
            let gone = unsafe { libc::kill(pid, 0) } != 0;
            if !gone {
                std::thread::sleep(Duration::from_millis(50));
            }
            gone
        })
    }

    #[test]
    fn run_bounded_times_out_and_kills_a_fake_sleep() {
        let started = Instant::now();
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("20");
        assert!(matches!(run_bounded(&mut cmd, Duration::from_millis(300), 16), Ran::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(10), "waited for the child instead of killing it");
    }

    #[test]
    fn probe_timeout_is_inconclusive_and_kills_the_probe_and_its_children() {
        let tmp = Tmp::new("kpto");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let pids = tmp.path().join("pids");
        // Probe = sh; it records its own pid and a background grandchild's, then waits.
        let body = format!("echo $$ > {0}; /bin/sleep 20 & echo $! >> {0}; wait", pids.display());
        let mut tools = fake_tools(&body);
        // 3 s: long enough for the fake probe to record both pids under parallel test load
        // (700 ms flaked), still far below the 20 s sleep it is killed out of.
        tools.run_timeout = Duration::from_secs(3);
        let started = Instant::now();
        let r = run_key_probe(scratch.path(), &tools);
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "probe timed out after 3s"));
        assert!(started.elapsed() < Duration::from_secs(10));
        let recorded: Vec<i32> = std::fs::read_to_string(&pids).unwrap().lines().map(|l| l.trim().parse().unwrap()).collect();
        assert_eq!(recorded.len(), 2);
        for pid in recorded {
            assert!(pid_gone(pid), "pid {pid} survived the probe timeout");
        }
        assert!(!scratch.path().join(PROBE_BINARY_FILE).exists());
    }

    #[test]
    fn compile_timeout_is_inconclusive_and_kills_the_compiler() {
        let tmp = Tmp::new("kpcto");
        let scratch = Scratch::create(tmp.path()).unwrap();
        let pidfile = tmp.path().join("cc.pid");
        let script = format!("echo $$ > {}; exec /bin/sleep 20", pidfile.display());
        let tools = ProbeTools {
            compilers: vec![("/bin/sh".into(), vec!["-c".into(), script.into(), "cc".into()])],
            compile_timeout: Duration::from_secs(3), // 700 ms could race the pid write under load
            run_timeout: Duration::from_secs(5),
        };
        let r = run_key_probe(scratch.path(), &tools);
        assert_eq!((r.status, r.why.as_str()), (Status::Inconclusive, "swift compile timed out after 3s"));
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        assert!(pid_gone(pid), "compiler pid {pid} survived the compile timeout");
    }

    #[test]
    fn judged_rows_are_never_pass() {
        let ok = |code: i32, out: &str| Ran::Exited { status: ExitStatus::from_raw(code << 8), stdout: out.as_bytes().to_vec(), overflow: false };
        let cases = vec![
            ok(0, "match\n"), ok(0, "mismatch\n"), ok(0, "unavailable\n"), ok(3, "unavailable\n"), ok(1, "match\n"),
            ok(0, ""), ok(0, "\0\u{1}garbage"), Ran::TimedOut, Ran::Failed(std::io::ErrorKind::PermissionDenied),
            Ran::Exited { status: ExitStatus::from_raw(9), stdout: b"match".to_vec(), overflow: false },
            Ran::Exited { status: ExitStatus::from_raw(0), stdout: b"match".to_vec(), overflow: true },
            Ran::Lingered,
        ];
        for c in cases {
            let dbg = format!("{c:?}");
            let r = judge_probe_run(c, Duration::from_secs(15));
            assert_ne!(r.status, Status::Pass, "{dbg}");
            assert_eq!(r.name, "key-blob-use");
        }
    }

    #[test]
    fn skip_env_reports_unsupported_in_the_output_and_touches_nothing() {
        let tmp = Tmp::new("kpskip");
        let scratch = Scratch::create(tmp.path()).unwrap();
        // A toolchain that would leave a trace if it ran at all.
        let trace = tmp.path().join("ran");
        let tools = ProbeTools {
            compilers: vec![("/usr/bin/touch".into(), vec![trace.clone().into_os_string()])],
            ..missing_tools()
        };
        let r = key_probe_or_skip(Some(OsStr::new("1")), scratch.path(), &tools);
        assert_eq!((r.name, r.status), ("key-blob-use", Status::Unsupported));
        assert_eq!(r.why, "key-use probe skipped by KARAMBIT_DOCTOR_SKIP_KEY_PROBE");
        assert!(!trace.exists());
        assert!(!scratch.path().join(PROBE_SOURCE_FILE).exists());
        // Only the exact value `1` skips.
        for v in [None, Some(OsStr::new("")), Some(OsStr::new("0")), Some(OsStr::new("true"))] {
            assert!(!skip_key_probe_requested(v));
            let r = key_probe_or_skip(v, scratch.path(), &missing_tools());
            assert_eq!(r.why, "no swift compiler found (tried /usr/bin/xcrun and /usr/bin/swiftc)");
        }
    }

    #[test]
    fn env_key_probe_seam_is_called_with_the_marked_scratch_dir_and_its_row_is_reported() {
        fn seam(scratch: &Path) -> Row {
            let marked = scratch.join(MARKER_FILE).is_file();
            row("key-blob-use", if marked { Status::Inconclusive } else { Status::Fail }, "seam saw the doctor scratch dir")
        }
        let tmp = Tmp::new("kpseam");
        let (_v, paths) = vault("kpseamv");
        let caller = Caller::default();
        let mut env = test_env(&tmp, &paths, &caller);
        env.key_probe = seam;
        let report = collect(&env).unwrap();
        let kp = report.checks.iter().find(|r| r.name == "key-blob-use").unwrap();
        assert_eq!((kp.status, kp.why.as_str()), (Status::Inconclusive, "seam saw the doctor scratch dir"));
    }

    // ---- the embedded Swift source

    #[test]
    fn probe_source_has_no_prompt_flags_keychain_or_outside_paths_and_removes_its_blob() {
        let src = KEY_USE_PROBE_SOURCE;
        // Strip comments: the header documents what is NOT done.
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        for banned in [
            ".biometry", "userPresence", "devicePasscode", "SecAccessControl", "SecItem", "Keychain", "kSec", "LocalAuthentication",
            "import Security", "authenticationContext", "NSHomeDirectory", "homeDirectoryForCurrentUser", "~/", "/Users", "URLSession",
            "Process()", "KARAMBIT", ".vault", "ProcessInfo",
        ] {
            assert!(!code.contains(banned), "probe source mentions {banned}");
        }
        assert!(code.contains("SecureEnclave.isAvailable"));
        assert!(code.contains("print(\"unavailable\")") && code.contains("return 3"));
        assert!(code.contains("SecureEnclave.P256.KeyAgreement.PrivateKey()"), "no access-control argument");
        assert!(code.contains("PrivateKey(dataRepresentation:"), "the key is reloaded from the blob file");
        assert!(code.contains("defer {\n        close(fd)\n        unlink(path)\n    }"), "the blob is removed on every path after creation");
        assert!(code.contains("unlink(path)"));
        assert!(code.contains("O_EXCL") && code.contains("O_NOFOLLOW"));
        // Regression: the blob is read back through the creating descriptor, never by pathname.
        for by_path in ["contents(atPath", "FileHandle(forReadingAtPath", "forReadingFrom", "Data(contentsOf", "fopen(", "open(path, O_RDONLY"] {
            assert!(!code.contains(by_path), "probe reopens the blob by pathname: {by_path}");
        }
        assert_eq!(code.matches("open(path").count(), 1, "the blob path is opened exactly once (O_EXCL create)");
        assert!(code.contains("lseek(fd, 0, SEEK_SET)") && code.contains("readToEnd()"));
        assert!(code.contains("let blobName = \"probe-key.blob\"") && PROBE_BLOB_FILE == "probe-key.blob");
        // Prints only the fixed tokens.
        let prints: Vec<&str> = code.lines().filter(|l| l.contains("print(")).map(str::trim).collect();
        assert_eq!(prints, vec!["print(\"unavailable\")", "print(a == b ? \"match\" : \"mismatch\")"]);
        // Only argv[1] is used as a directory.
        assert_eq!(code.matches("CommandLine.arguments").count(), 2);
    }

    #[test]
    fn probe_source_typechecks_with_swiftc_without_building_or_running_it() {
        let xcrun = Path::new("/usr/bin/xcrun");
        if !xcrun.exists() || !has_swiftc(xcrun) {
            eprintln!("skipped: no /usr/bin/xcrun with a swiftc; embedded probe source not type-checked");
            return;
        }
        let tmp = Tmp::new("kptc");
        let src = tmp.path().join("probe.swift");
        std::fs::write(&src, KEY_USE_PROBE_SOURCE).unwrap();
        let mut cmd = Command::new(xcrun);
        cmd.args(["swiftc", "-typecheck"]).arg(&src);
        apply_probe_env(&mut cmd);
        match run_bounded(&mut cmd, Duration::from_secs(120), PROBE_STDOUT_CAP) {
            Ran::Exited { status, .. } if status.success() => {}
            other => panic!("embedded probe source does not type-check: {other:?}"),
        }
        assert!(std::fs::read_dir(tmp.path()).unwrap().flatten().count() == 1, "typecheck must not build anything");
    }

    fn has_swiftc(xcrun: &Path) -> bool {
        Command::new(xcrun).args(["--find", "swiftc"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    }

    // ---- daemon socket (test listener only; no real daemon)

    fn short_sock_dir() -> Tmp {
        Tmp::new("s")
    }

    #[test]
    fn daemon_socket_absent_is_inconclusive() {
        let d = short_sock_dir();
        let r = check_daemon_socket(&d.path().join("d.sock"), Duration::from_secs(1));
        assert_eq!(r.status, Status::Inconclusive);
        assert!(!d.path().join("d.sock").exists(), "doctor must not create a socket");
    }

    #[test]
    fn daemon_socket_accepting_connection_passes_and_doctor_writes_zero_bytes() {
        let d = short_sock_dir();
        let sock = d.path().join("d.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let _ = c.set_read_timeout(Some(Duration::from_secs(5))); // macOS may refuse this once the peer closed
            let mut received = Vec::new();
            // Ends at EOF because the doctor closes without writing; a byte would land here.
            c.read_to_end(&mut received).unwrap();
            received
        });
        let r = check_daemon_socket(&sock, Duration::from_secs(2));
        assert_eq!(r.status, Status::Pass, "{}", r.why);
        assert_eq!(r.why, "socket accepted a connection; no request sent");
        assert_eq!(server.join().unwrap(), Vec::<u8>::new(), "the doctor sent bytes to the daemon socket");
    }

    #[test]
    fn daemon_socket_stale_or_refused_is_inconclusive() {
        let d = short_sock_dir();
        let sock = d.path().join("d.sock");
        drop(UnixListener::bind(&sock).unwrap()); // stale socket file, nobody listening
        // Sibling tests fork children; until such a child execs it still holds the dropped listener's
        // fd and the socket stays connectable. Wait for the kernel to actually close it.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let r = loop {
            let r = check_daemon_socket(&sock, Duration::from_secs(1));
            if r.status == Status::Inconclusive || std::time::Instant::now() > deadline {
                break r;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(r.status, Status::Inconclusive, "{}", r.why);
        assert!(r.why.contains("connect failed"), "{}", r.why);
    }

    // ---- audit / config / pin writable

    fn vault(label: &str) -> (Tmp, Paths) {
        let t = Tmp::new(label);
        let paths = Paths { root: t.path().join("v") };
        std::fs::create_dir_all(paths.keys()).unwrap();
        std::fs::write(paths.audit(), b"{}\n").unwrap();
        std::fs::write(paths.config(), b"{}").unwrap();
        std::fs::write(paths.keys().join("helper.sha256"), b"00").unwrap();
        std::fs::write(paths.keys().join("daemon.sha256"), b"00").unwrap();
        (t, paths)
    }

    #[test]
    fn writable_vault_files_fail_and_are_not_modified() {
        let (_t, paths) = vault("w");
        let before = std::fs::read(paths.audit()).unwrap();
        let r = check_writable(&paths);
        assert_eq!(r.status, Status::Fail);
        for name in ["audit.jsonl", "config.json", "keys/helper.sha256", "keys/daemon.sha256"] {
            assert!(r.why.contains(name), "{name} in {}", r.why);
        }
        assert_eq!(std::fs::read(paths.audit()).unwrap(), before);
    }

    #[test]
    fn read_only_vault_files_and_directories_pass() {
        if is_root() {
            return;
        }
        let (_t, paths) = vault("ro");
        for f in [paths.audit(), paths.config(), paths.keys().join("helper.sha256"), paths.keys().join("daemon.sha256")] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        // Files alone are not enough: a writable directory lets the file be replaced.
        assert_eq!(check_writable(&paths).status, Status::Fail);
        std::fs::set_permissions(paths.keys(), std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(&paths.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = check_writable(&paths);
        assert_eq!(r.status, Status::Pass, "{}", r.why);
    }

    #[test]
    fn missing_vault_is_inconclusive() {
        let t = Tmp::new("nov");
        let paths = Paths { root: t.path().join("none") };
        assert_eq!(check_writable(&paths).status, Status::Inconclusive);
        assert!(!paths.root.exists(), "doctor must not create the vault dir");
    }

    #[test]
    fn unlistable_keys_dir_with_writable_extra_pin_is_inconclusive_not_pass() {
        if is_root() {
            return;
        }
        let (_t, paths) = vault("search-only");
        let extra = paths.keys().join("extra.sha256");
        std::fs::write(&extra, b"00").unwrap();
        for f in [paths.audit(), paths.config(), paths.keys().join("helper.sha256"), paths.keys().join("daemon.sha256")] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        // extra.sha256 stays 0644 (writable) but cannot be discovered: keys/ is search-only.
        std::fs::set_permissions(paths.keys(), std::fs::Permissions::from_mode(0o111)).unwrap();
        std::fs::set_permissions(&paths.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = check_writable(&paths);
        assert_eq!(r.status, Status::Inconclusive, "{}", r.why);
        assert!(r.why.contains("keys/ cannot be listed"), "{}", r.why);
        // Once the writable extra pin is discoverable the same row is a fail.
        std::fs::set_permissions(paths.keys(), std::fs::Permissions::from_mode(0o511)).unwrap();
        let r = check_writable(&paths);
        assert_eq!(r.status, Status::Fail, "{}", r.why);
        assert!(r.why.contains("keys/extra.sha256"), "{}", r.why);
    }

    #[test]
    fn unjudgeable_pin_makes_the_row_inconclusive_not_pass() {
        if is_root() {
            return;
        }
        let (_t, paths) = vault("eloop");
        for f in [paths.audit(), paths.config(), paths.keys().join("daemon.sha256")] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        std::fs::set_permissions(paths.keys(), std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(&paths.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        // A self-referential symlink: lstat works, access(2) fails with ELOOP (not a plain "no").
        let loop_pin = paths.keys().join("helper.sha256");
        std::fs::set_permissions(paths.keys(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_file(&loop_pin).unwrap();
        symlink(&loop_pin, &loop_pin).unwrap();
        std::fs::set_permissions(paths.keys(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = check_writable(&paths);
        assert_eq!(r.status, Status::Inconclusive, "{}", r.why);
        assert!(r.why.contains("keys/helper.sha256"), "{}", r.why);
    }

    #[test]
    fn looping_pins_in_a_writable_keys_dir_are_replaceable_so_fail() {
        if is_root() {
            return;
        }
        // Regression: read-only root, blocked audit/config, WRITABLE keys/, both
        // canonical pins self-referential symlinks. access(2) on the pins fails with ELOOP, but
        // the writable directory makes them replaceable, so the row must be `fail`, not unknown.
        let (_t, paths) = vault("eloop-w");
        for f in [paths.audit(), paths.config()] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        for name in ["helper.sha256", "daemon.sha256"] {
            let pin = paths.keys().join(name);
            let _ = std::fs::remove_file(&pin);
            symlink(&pin, &pin).unwrap();
        }
        std::fs::set_permissions(paths.keys(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&paths.root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = check_writable(&paths);
        std::fs::set_permissions(&paths.root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(r.status, Status::Fail, "{}", r.why);
        assert!(r.why.contains("helper.sha256") && r.why.contains("daemon.sha256"), "{}", r.why);
    }

    #[test]
    fn access_errors_other_than_denial_are_unknown() {
        assert!(matches!(tamper_of(Path::new("/nonexistent-doctor-root/keys/x.sha256")), Tamper::Absent));
        let tmp = Tmp::new("eacc");
        let file = tmp.path().join("plain");
        std::fs::write(&file, b"x").unwrap();
        // ENOTDIR (a path through a regular file) is neither "writable" nor "blocked".
        assert!(matches!(tamper_of(&file.join("x.sha256")), Tamper::Unknown(_)));
    }

    #[test]
    fn symlinked_pin_is_judged_without_following_into_a_write() {
        let (_t, paths) = vault("ln");
        let target = paths.root.join("elsewhere");
        std::fs::write(&target, b"x").unwrap();
        std::fs::remove_file(paths.keys().join("helper.sha256")).unwrap();
        symlink(&target, paths.keys().join("helper.sha256")).unwrap();
        assert_eq!(check_writable(&paths).status, Status::Fail);
        assert_eq!(std::fs::read(&target).unwrap(), b"x");
    }

    // ---- redaction

    fn mutant_skipping_base64(secrets: &[(String, &[u8])]) -> Redactor {
        // What the production redactor already does; named so the base64 expectation has a referent.
        Redactor::new(secrets)
    }

    fn redactor_that_also_registers_base64(secrets: &[(String, &[u8])]) -> Redactor {
        let encoded = base64_std(secrets[0].1);
        let mut all = secrets.to_vec();
        all.push((format!("{}-b64", secrets[0].0), encoded.as_slice()));
        Redactor::new(&all)
    }

    #[test]
    fn production_redactor_leaks_only_base64() {
        let canary = Canary::generate().unwrap();
        for make in [production_redactor as MakeRedactor, mutant_skipping_base64] {
            let r = check_redaction(&canary, make);
            assert_eq!(r.status, Status::Fail);
            assert_eq!(
                r.why,
                "base64 form not redacted (known limit #9, encoding-aware redaction planned); redacted: echo, 20-char truncation"
            );
            assert!(!r.why.contains(canary.value.as_str()));
        }
    }

    #[test]
    fn redaction_row_can_pass_when_base64_is_also_registered() {
        let canary = Canary::generate().unwrap();
        let r = check_redaction(&canary, redactor_that_also_registers_base64);
        assert_eq!(r.status, Status::Pass, "{}", r.why);
    }

    #[test]
    fn redaction_row_reports_each_leaking_form() {
        fn nothing(_: &[(String, &[u8])]) -> Redactor {
            Redactor::new(&[])
        }
        let canary = Canary::generate().unwrap();
        let r = check_redaction(&canary, nothing);
        assert_eq!(r.status, Status::Fail);
        assert!(r.why.starts_with("echo, base64, 20-char truncation form not redacted"), "{}", r.why);
    }

    #[test]
    fn base64_matches_the_standard_alphabet() {
        for (plain, enc) in [(&b""[..], ""), (b"f", "Zg=="), (b"fo", "Zm8="), (b"foo", "Zm9v"), (b"foob", "Zm9vYg=="), (b"fooba", "Zm9vYmE="), (b"foobar", "Zm9vYmFy")] {
            assert_eq!(base64_std(plain).as_slice(), enc.as_bytes());
        }
    }

    // ---- caller

    #[test]
    fn caller_row_reports_what_was_detected() {
        let agent = Caller { agent: Some("env:PI_CODING_AGENT".into()), kind: Some("pi".into()), chain: vec!["zsh".into()], ..Default::default() };
        let r = check_caller(&agent);
        assert_eq!((r.status, r.why.contains("agent detected: pi")), (Status::Pass, true));
        let human = Caller { chain: vec!["zsh".into(), "ghostty".into()], ..Default::default() };
        let r = check_caller(&human);
        assert_eq!(r.status, Status::Pass);
        assert!(r.why.starts_with("no agent detected (human shell"), "{}", r.why);
    }

    // ---- scratch dir guard + leftovers

    #[test]
    fn scratch_dir_is_0700_marked_and_removed_on_normal_drop() {
        let tmp = Tmp::new("g1");
        let s = Scratch::create(tmp.path()).unwrap();
        let dir = s.path().to_path_buf();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(dir.join(MARKER_FILE).is_file());
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(parse_scratch_name(&name).is_some(), "{name}");
        drop(s);
        assert!(!dir.exists());
    }

    #[test]
    fn scratch_dir_is_created_0700_even_under_a_permissive_umask() {
        let tmp = Tmp::new("umask");
        let old = unsafe { libc::umask(0) };
        // The marker writer observes the mode at creation time, before any later chmod could fix it.
        let mut seen = 0;
        let s = Scratch::create_with(tmp.path(), |dir, _| {
            seen = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            Ok(())
        });
        unsafe { libc::umask(old) };
        assert!(s.is_ok());
        assert_eq!(seen, 0o700);
    }

    #[test]
    fn scratch_dir_is_removed_when_marker_setup_fails() {
        let tmp = Tmp::new("g3");
        let r = Scratch::create_with(tmp.path(), |_, _| Err(std::io::Error::other("marker failed")));
        assert!(r.is_err());
        let left: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().flatten().collect();
        assert!(left.is_empty(), "guard did not cover a post-creation failure");
    }

    #[test]
    fn scratch_drop_never_empties_a_swapped_in_directory() {
        // Regression: rename the scratch dir aside and move an unrelated, non-empty
        // directory into its pathname before Drop. Drop must not delete the replacement's contents.
        let tmp = Tmp::new("swap");
        let s = Scratch::create(tmp.path()).unwrap();
        let path = s.path().to_path_buf();
        let aside = tmp.path().join("aside");
        std::fs::rename(&path, &aside).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("precious"), b"keep").unwrap();
        std::fs::create_dir(path.join("sub")).unwrap();
        std::fs::write(path.join("sub/data"), b"keep").unwrap();
        drop(s);
        assert_eq!(std::fs::read(path.join("precious")).unwrap(), b"keep");
        assert_eq!(std::fs::read(path.join("sub/data")).unwrap(), b"keep");
        assert!(aside.join(MARKER_FILE).exists(), "the renamed-away original is not chased");
    }

    #[test]
    fn scratch_drop_bound_for_a_marker_only_swap_in() {
        // Documented bound: a swap-in whose ONLY entry is `.karambit-doctor`
        // loses that entry and is then removed by rmdir. Nothing else can ever be deleted.
        let tmp = Tmp::new("swap1");
        let s = Scratch::create(tmp.path()).unwrap();
        let path = s.path().to_path_buf();
        std::fs::rename(&path, tmp.path().join("aside")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join(MARKER_FILE), b"someone else's").unwrap();
        drop(s);
        assert!(!path.exists(), "marker-only swap-in: marker unlinked, then empty dir removed");
        assert!(tmp.path().join("aside").join(MARKER_FILE).exists());
    }

    #[test]
    fn probe_files_bound_for_a_swap_in() {
        // Regression: with the key-use row, the exact names `.karambit-doctor`, `probe.swift`,
        // `probe` and `probe-key.blob` may be unlinked from a swapped-in directory (never
        // recursively). Anything else in it, including a directory with one of those names, stays.
        let tmp = Tmp::new("swap2");
        let s = Scratch::create(tmp.path()).unwrap();
        let path = s.path().to_path_buf();
        std::fs::rename(&path, tmp.path().join("aside")).unwrap();
        std::fs::create_dir(&path).unwrap();
        for f in [MARKER_FILE, PROBE_SOURCE_FILE, PROBE_BINARY_FILE] {
            std::fs::write(path.join(f), b"theirs").unwrap();
        }
        std::fs::create_dir(path.join(PROBE_BLOB_FILE)).unwrap();
        std::fs::write(path.join(PROBE_BLOB_FILE).join("inner"), b"keep").unwrap();
        std::fs::write(path.join("other"), b"keep").unwrap();
        drop(ProbeFiles::new(&path));
        drop(s);
        for f in [MARKER_FILE, PROBE_SOURCE_FILE, PROBE_BINARY_FILE] {
            assert!(!path.join(f).exists(), "{f} is one of the four documented names");
        }
        assert_eq!(std::fs::read(path.join(PROBE_BLOB_FILE).join("inner")).unwrap(), b"keep");
        assert_eq!(std::fs::read(path.join("other")).unwrap(), b"keep");
    }

    #[test]
    fn sticky_writable_parent_does_not_make_foreign_entries_replaceable() {
        // In a sticky dir only the entry/dir owner may replace an entry. Ownership by another uid
        // can't be created unprivileged, so check the decision function directly with a sticky
        // dir we own (replaceable) and the rule itself for a foreign owner.
        let tmp = Tmp::new("sticky");
        let dir = tmp.path().join("k");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let f = dir.join("x.sha256");
        std::fs::write(&f, b"x").unwrap();
        let meta = std::fs::symlink_metadata(&f).unwrap();
        assert!(replaceable_in(&dir, &meta), "own entry in own sticky dir is replaceable");
        if !is_root() {
            // /private/tmp is sticky and root-owned; "/" stands in for a root-owned entry there.
            let sticky_root = Path::new("/private/tmp");
            let pm = std::fs::metadata(sticky_root).unwrap();
            assert!(pm.mode() & libc::S_ISVTX as u32 != 0 && pm.uid() == 0, "fixture assumption");
            let foreign = std::fs::symlink_metadata("/").unwrap();
            assert_eq!(foreign.uid(), 0);
            assert!(!replaceable_in(sticky_root, &foreign), "foreign entry in a sticky dir we don't own");
        }
    }

    #[test]
    fn scratch_dir_is_removed_on_panic() {
        let tmp = Tmp::new("g2");
        let root = tmp.path().to_path_buf();
        let dir = std::sync::Mutex::new(PathBuf::new());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let s = Scratch::create(&root).unwrap();
            *dir.lock().unwrap() = s.path().to_path_buf();
            assert!(s.path().exists());
            panic!("doctor check panicked");
        }));
        assert!(r.is_err());
        let dir = dir.lock().unwrap().clone();
        assert!(!dir.as_os_str().is_empty() && !dir.exists(), "scratch dir survived a panic");
    }

    /// A directory exactly as a crashed doctor would have left it.
    fn plant_doctor_dir(root: &Path, pid: u32, nonce: &str) -> PathBuf {
        let dir = root.join(format!("{SCRATCH_PREFIX}{pid}-{nonce}"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        std::fs::write(dir.join(MARKER_FILE), marker_text(pid, 1, nonce)).unwrap();
        std::fs::write(dir.join("junk"), b"x").unwrap();
        dir
    }

    #[test]
    fn marked_stale_scratch_dirs_are_identified_not_deleted_and_live_ones_are_skipped() {
        let tmp = Tmp::new("lo");
        let stale = plant_doctor_dir(tmp.path(), 999999, "aaaaaaaaaaaa");
        let live = plant_doctor_dir(tmp.path(), std::process::id(), "bbbbbbbbbbbb");
        let other = tmp.path().join("unrelated-dir");
        std::fs::create_dir(&other).unwrap();
        let removed = clean_leftovers(tmp.path());
        assert_eq!(removed, vec![("karambit-doctor-999999-aaaaaaaaaaaa".to_string(), LeftoverAction::CrashLeftover)]);
        assert!(stale.join("junk").exists(), "leftovers are reported, never deleted");
        assert!(live.exists() && other.exists());
    }

    #[test]
    fn prefixed_directories_doctor_did_not_create_are_preserved() {
        let tmp = Tmp::new("np");
        // Malformed names never come from Scratch::create.
        let malformed = tmp.path().join("karambit-doctor-crashed");
        let short_nonce = tmp.path().join("karambit-doctor-999999-dead");
        let upper = tmp.path().join("karambit-doctor-999999-AAAAAAAAAAAA");
        // Correct name, but no marker file.
        let unmarked = tmp.path().join("karambit-doctor-999999-cccccccccccc");
        // Correct name, marker for a different pid / nonce / garbage.
        let wrong_pid = plant_doctor_dir(tmp.path(), 999998, "dddddddddddd");
        std::fs::write(wrong_pid.join(MARKER_FILE), marker_text(1234, 1, "dddddddddddd")).unwrap();
        let wrong_nonce = plant_doctor_dir(tmp.path(), 999997, "eeeeeeeeeeee");
        std::fs::write(wrong_nonce.join(MARKER_FILE), marker_text(999997, 1, "ffffffffffff")).unwrap();
        let garbage = plant_doctor_dir(tmp.path(), 999996, "111111111111");
        std::fs::write(garbage.join(MARKER_FILE), b"hello").unwrap();
        // Marker that is a symlink, and a symlinked scratch dir.
        let marker_link = tmp.path().join("karambit-doctor-999995-222222222222");
        std::fs::create_dir(&marker_link).unwrap();
        let real_marker = tmp.path().join("real-marker");
        std::fs::write(&real_marker, marker_text(999995, 1, "222222222222")).unwrap();
        symlink(&real_marker, marker_link.join(MARKER_FILE)).unwrap();
        let link_target = plant_doctor_dir(tmp.path(), 999994, "333333333333");
        symlink(&link_target, tmp.path().join("karambit-doctor-999993-444444444444")).unwrap();
        for d in [&malformed, &short_nonce, &upper, &unmarked] {
            std::fs::create_dir(d).unwrap();
            std::fs::write(d.join("precious"), b"keep").unwrap();
        }
        let _ = link_target;
        let results = clean_leftovers(tmp.path());
        for (name, action) in &results {
            if name == "karambit-doctor-999994-333333333333" {
                assert_eq!(*action, LeftoverAction::CrashLeftover, "the genuinely marked dir is identified");
            } else {
                assert_eq!(*action, LeftoverAction::NotDoctorOwned, "{name}");
            }
        }
        assert_eq!(results.len(), 10, "{results:?}");
        for d in [&malformed, &short_nonce, &upper, &unmarked] {
            assert_eq!(std::fs::read(d.join("precious")).unwrap(), b"keep", "{}", d.display());
        }
        for d in [&wrong_pid, &wrong_nonce, &garbage, &marker_link] {
            assert!(d.exists(), "{}", d.display());
        }
        assert!(real_marker.exists());
        assert!(tmp.path().join("karambit-doctor-999993-444444444444").symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn scratch_name_grammar_is_exactly_what_create_generates() {
        let tmp = Tmp::new("gram");
        let s = Scratch::create(tmp.path()).unwrap();
        let name = s.path().file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(parse_scratch_name(&name).map(|(p, _)| p), Some(std::process::id() as i32));
        for bad in ["karambit-doctor-", "karambit-doctor-1-abc", "karambit-doctor--aaaaaaaaaaaa", "karambit-doctor-x-aaaaaaaaaaaa",
            "karambit-doctor-1-aaaaaaaaaaaaa", "karambit-doctor-1-aaaaaaaaaaaa-x", "karambit-doctor-0-aaaaaaaaaaaa", "other-1-aaaaaaaaaaaa"] {
            assert_eq!(parse_scratch_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn remote_login_row_warns_when_any_signal_says_on() {
        assert_eq!(parse_systemsetup("Remote Login: On\n"), Some(true));
        assert_eq!(parse_systemsetup("Remote Login: Off"), Some(false));
        assert_eq!(parse_systemsetup("You need administrator access to run this tool... exiting!"), None);
        for (setup, launchd, loopback, status) in [
            (Some(true), false, false, Status::Fail), (Some(false), true, true, Status::Pass),
            (None, true, false, Status::Fail), (None, false, true, Status::Fail), (None, false, false, Status::Pass),
        ] {
            let r = judge_remote_login(setup, launchd, loopback);
            assert_eq!((r.name, r.status), ("remote-login", status), "{setup:?} {launchd} {loopback}");
        }
        assert!(judge_remote_login(None, false, true).why.contains("authorized_keys"));
    }

    #[test]
    fn caller_row_names_ssh_callers() {
        let remote = Caller { remote: true, ..Default::default() };
        assert!(check_caller(&remote).why.contains("over SSH"));
        assert!(!check_caller(&Caller::default()).why.contains("SSH"));
    }

    // ---- whole run: nothing printed, nothing left behind

    fn test_env<'a>(tmp: &Tmp, paths: &'a Paths, caller: &'a Caller) -> Env<'a> {
        Env {
            home: Some(tmp.path().to_path_buf()),
            paths,
            caller,
            tmp_root: tmp.path().to_path_buf(),
            ps: "/bin/ps".into(),
            sibling: test_sibling(),
            make_redactor: production_redactor,
            key_probe: fake_key_probe,
        }
    }

    /// Unit tests never reach the real probe through `collect`.
    fn fake_key_probe(_scratch: &Path) -> Row {
        row("key-blob-use", Status::Unsupported, "fake probe (unit test)")
    }

    fn scratch_count(dir: &Path) -> usize {
        std::fs::read_dir(dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with(SCRATCH_PREFIX)).count()
    }

    #[test]
    fn collect_never_renders_the_canary_and_leaves_no_scratch_dir() {
        let tmp = Tmp::new("full");
        let (_v, paths) = vault("fullv");
        let caller = Caller::default();
        let report = collect(&test_env(&tmp, &paths, &caller)).unwrap();
        // The canary of this very collect() run (test-only thread-local; no env var, no file).
        let canary = LAST_CANARY.with(|c| c.borrow().clone()).unwrap();
        assert_eq!(canary.len(), 64);
        assert_eq!(report.checks.len(), 9);
        let b64 = String::from_utf8(base64_std(canary.as_bytes()).to_vec()).unwrap();
        for text in [render_table(&report), render_json(&report).to_string()] {
            assert!(!text.contains(&canary));
            assert!(!text.contains(&b64));
            assert!(!text.contains(&canary[..20]));
            assert!(text.contains("scope: this run only") || text.contains("\"scope\":\"this run only\""));
        }
        assert_eq!(scratch_count(tmp.path()), 0);
    }

    #[test]
    fn collect_reports_marked_leftovers_and_deletes_nothing() {
        let tmp = Tmp::new("col");
        let (_v, paths) = vault("colv");
        plant_doctor_dir(tmp.path(), 999999, "aaaaaaaaaaaa");
        let foreign = tmp.path().join("karambit-doctor-notmine");
        std::fs::create_dir(&foreign).unwrap();
        let caller = Caller::default();
        let report = collect(&test_env(&tmp, &paths, &caller)).unwrap();
        assert_eq!(report.leftovers, vec![
            ("karambit-doctor-999999-aaaaaaaaaaaa".to_string(), LeftoverAction::CrashLeftover),
            ("karambit-doctor-notmine".to_string(), LeftoverAction::NotDoctorOwned),
        ]);
        let table = render_table(&report);
        assert!(table.contains("leftover karambit-doctor-999999-aaaaaaaaaaaa: crash leftover from an earlier doctor run; delete it by hand"), "{table}");
        assert!(table.contains("leftover karambit-doctor-notmine: not doctor-owned, left in place"), "{table}");
        assert!(foreign.exists());
        assert_eq!(scratch_count(tmp.path()), 2, "both leftovers remain (report-only); this run's scratch dir is gone");
    }
}
