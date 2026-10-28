//! Bound owner launcher and private execution shim.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::{Read, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::{net::UnixStream, process::CommandExt}}, path::{Path, PathBuf}, process::{Command, ExitStatus, Stdio}, time::Duration};
use serde_json::{json, value::RawValue};
use zeroize::{Zeroize, Zeroizing};
use crate::{daemon, lease::CommandBinding, Karambit};
use crate::sandbox::{Jail, NativeSandbox, Sandbox};

const CHANNEL: i32 = 3;
/// Write end of the owner's exec-report pipe; close-on-exec, so a successful execve closes it.
const EXEC_REPORT: i32 = 4;
const MAX_FRAME: usize = 1024 * 1024;
/// Set once the shim (or its forked child) has reached execve; later failures are not "exec failed".
static PAST_EXEC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Exec report wire format: `P` = about to execve, then `E` + errno (i32 LE) if it failed.
/// No `P` at all means the launcher never got that far. Async-signal-safe: stack bytes and write(2) only.
fn report_exec_attempt() { unsafe { libc::write(EXEC_REPORT, b"P".as_ptr().cast(), 1); } }
fn report_exec_failure(errno: i32) {
    let e = errno.to_le_bytes();
    let bytes = [b'E', e[0], e[1], e[2], e[3]];
    unsafe { libc::write(EXEC_REPORT, bytes.as_ptr().cast(), bytes.len()); }
}

/// Owner side: turn what the shim wrote before it exited into "did the program start?".
fn check_exec_report(bytes: &[u8]) -> Result<()> {
    let failure = bytes.strip_prefix(b"P").unwrap_or(bytes);
    match failure {
        [] if bytes.is_empty() => bail!("the launcher stopped before it ran the program"),
        [] => Ok(()),
        [b'E', rest @ ..] => match rest.first_chunk::<4>().map(|e| i32::from_le_bytes(*e)) {
            Some(libc::E2BIG) => bail!("exec failed: arguments plus environment are over the system limit (keep big values in a file the program reads)"),
            Some(errno) if errno > 0 => bail!("exec failed: {}", std::io::Error::from_raw_os_error(errno)),
            _ => bail!("the launcher refused to run the program"),
        },
        _ => bail!("unreadable launcher report"),
    }
}

/// Close-on-exec descriptor >= 10, so it can't collide with the fixed numbers 3/4 used in the shim.
fn high_fd(fd: std::os::fd::OwnedFd) -> Result<std::os::fd::OwnedFd> {
    let high = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if high < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(high) })
}

/// (non-blocking read end, write end). Reading after the shim exited can't hang on a stray writer.
fn exec_report_pipe() -> Result<(std::fs::File, std::os::fd::OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    let (read, write) = unsafe { (std::os::fd::OwnedFd::from_raw_fd(fds[0]), std::os::fd::OwnedFd::from_raw_fd(fds[1])) };
    let (read, write) = (high_fd(read)?, high_fd(write)?);
    if unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok((read.into(), write))
}

fn read_exec_report(mut read: std::fs::File) -> Vec<u8> {
    let mut bytes = [0u8; 16];
    let mut used = 0;
    while used < bytes.len() {
        match read.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(n) => used += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(_) => break, // WouldBlock: nothing more was written
        }
    }
    bytes[..used].to_vec()
}

/// Decodes one JSON string literal (quotes included) by appending to `out`.
/// serde_json would decode escapes through its non-zeroizing scratch buffer;
/// this never allocates. A decoded string is never longer than its literal,
/// so `out` must have room for the literal and never reallocates.
fn unescape_into(raw: &[u8], out: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    let [b'"', body @ .., b'"'] = raw else { bail!("invalid env"); };
    if out.capacity() - out.len() < body.len() { bail!("invalid env"); }
    let capacity = out.capacity();
    fn hex(digits: Option<&[u8]>) -> Result<u32> {
        let digits = digits.context("invalid env")?;
        digits.iter().try_fold(0u32, |acc, d| Ok(acc << 4 | (*d as char).to_digit(16).context("invalid env")?))
    }
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'\\' { out.push(body[i]); i += 1; continue; }
        let escape = *body.get(i + 1).context("invalid env")?;
        i += 2;
        let byte = match escape {
            b'"' => b'"', b'\\' => b'\\', b'/' => b'/', b'b' => 8, b'f' => 12, b'n' => b'\n', b'r' => b'\r', b't' => b'\t',
            b'u' => {
                let mut cp = hex(body.get(i..i + 4))?; i += 4;
                if (0xD800..0xDC00).contains(&cp) {
                    if body.get(i..i + 2) != Some(b"\\u".as_slice()) { bail!("invalid env"); }
                    let low = hex(body.get(i + 2..i + 6))?; i += 6;
                    if !(0xDC00..0xE000).contains(&low) { bail!("invalid env"); }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                }
                let ch = char::from_u32(cp).context("invalid env")?;
                let mut utf8 = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes());
                utf8.zeroize();
                continue;
            }
            _ => bail!("invalid env"),
        };
        out.push(byte);
    }
    debug_assert_eq!(out.capacity(), capacity, "env buffer reallocated");
    Ok(())
}

use crate::platform::{fd_buffer, cloexec_open_fds};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Instruction { #[serde(default)] jail: Option<Jail>, socket: PathBuf, id: String, expires_at: u64, #[serde(default)] region: Option<String>, #[serde(default)] ambient: Vec<(Vec<u8>, Vec<u8>)> }

// Fixed allocation: no plaintext-bearing reallocations or buffered read-ahead.
fn frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0; MAX_FRAME]);
    for i in 0..MAX_FRAME {
        stream.read_exact(&mut bytes[i..i+1])?;
        if bytes[i] == b'\n' { bytes.truncate(i); return Ok(bytes); }
    }
    bail!("launch frame too large")
}

fn send(stream: &mut UnixStream, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *stream, value)?;
    stream.write_all(b"\n")?;
    Ok(())
}

fn request(socket: &Path, req: &daemon::Req) -> Result<serde_json::Value> {
    // Deliberately never starts a daemon (including in tests).
    let mut stream = UnixStream::connect(socket)?;
    daemon::verify_daemon(socket, &stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    send(&mut stream, req)?;
    let response = serde_json::from_slice::<serde_json::Value>(&frame(&mut stream)?)?;
    if let Some(error) = response.get("error") {
        return Err(PrepareRefused(error.as_str().unwrap_or_default().to_owned()).into());
    }
    Ok(response)
}

/// The daemon's prepare refusals are opaque, except the size one: it names no secret and
/// tells the caller what to change.
fn prepare_error(error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<PrepareRefused>() {
        Ok(refused) if refused.0.starts_with(daemon::LAUNCH_TOO_LARGE) || refused.0 == crate::SSH_HUMAN_REFUSAL => anyhow::anyhow!(refused.0),
        Ok(_) => anyhow::anyhow!("launch refused"),
        Err(other) => other,
    }
}

#[derive(Debug)]
struct PrepareRefused(String);
impl std::fmt::Display for PrepareRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("launch refused") }
}
impl std::error::Error for PrepareRefused {}

struct Cancel<'a> { socket: &'a Path, id: String }
impl Drop for Cancel<'_> {
    fn drop(&mut self) { let _ = request(self.socket, &daemon::Req::LaunchCancel { id: self.id.clone() }); }
}

/// Resolve against the owner's cwd/PATH, never the daemon's environment.
fn resolve_owner_target(name: &str, cwd: &Path) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let resolve = || -> Result<PathBuf> {
        if name.contains('/') { return Ok(std::fs::canonicalize(cwd.join(name))?); }
        let mut denied = false;
        for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into())) {
            let path = cwd.join(dir).join(name);
            let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())?;
            // Check the owner's access, including ACLs, rather than only permission bits.
            if unsafe { libc::access(cpath.as_ptr(), libc::X_OK) } == 0 {
                if std::fs::metadata(&path)?.is_file() { return Ok(std::fs::canonicalize(path)?); }
                denied = true;
            } else {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EACCES) => denied = true,
                    Some(libc::ENOENT | libc::ENOTDIR) => (),
                    _ => return Err(error.into()),
                }
            }
        }
        Err(std::io::Error::from_raw_os_error(if denied { libc::EACCES } else { libc::ENOENT }).into())
    };
    resolve().with_context(|| format!("exec {name}"))
}

impl Karambit {
    /// Bound launch. Requires a running daemon and a pinned current
    /// executable implementing `__launch`. AWS endpoints live until child exit.
    /// Assignments are ordered: last name wins, and overwritten refs are not prepared.
    /// The owner's scrubbed ambient snapshot travels only over the private channel.
    pub fn launch_bound(&self, assignments: Vec<(String, String)>, argv: Vec<String>, cwd: PathBuf,
        aws: Option<String>, region_override: Option<String>, no_redact: bool) -> Result<ExitStatus> {
        self.launch_bound_with_jail(assignments, argv, cwd, aws, region_override, (no_redact, None))
    }

    /// Opt-in Mode B spike; the policy is installed by the authenticated shim.
    pub fn launch_bound_with_jail(&self, assignments: Vec<(String, String)>, argv: Vec<String>, cwd: PathBuf,
        aws: Option<String>, region_override: Option<String>, options: (bool, Option<Jail>)) -> Result<ExitStatus> {
        self.launch_bound_with_plain(assignments, Vec::new(), argv, cwd, aws, region_override, options)
    }

    /// As `launch_bound_with_jail`, plus non-secret `plain` values (from a `.env.schema`)
    /// added to the child's ambient environment. They are not redacted and never
    /// override a secret assignment, a scrubbed credential name or a `KARAMBIT_` variable.
    #[allow(clippy::too_many_arguments)]
    pub fn launch_bound_with_plain(&self, assignments: Vec<(String, String)>, plain: Vec<(String, String)>, argv: Vec<String>, cwd: PathBuf,
        aws: Option<String>, region_override: Option<String>, options: (bool, Option<Jail>)) -> Result<ExitStatus> {
        let (no_redact, jail) = options;
        for (name, _) in &plain {
            if crate::env::is_scrubbed(name) || name.starts_with("KARAMBIT_") {
                bail!("{name} can't be a plain value; store it with `karambit secure` and use karambit(ns/name)");
            }
            // Humans too: a schema is auto-trusted, so a planted code-loading line would run everywhere.
            crate::env::refuse_code_loading_plain(name)?;
        }
        let socket = daemon::sock_path(&self.paths);
        if no_redact {
            self.require_human(crate::fence::Verb::NoRedact, crate::fence::Layer::Cli)?;
            request(&socket, &daemon::Req::RunUnredacted { command: argv.first().context("missing command")?.clone() })?;
        }
        let config = crate::store::load_config(&self.paths)?;
        let mut env = BTreeMap::new();
        let mut overwritten = std::collections::BTreeSet::new();
        for (name, reference) in assignments {
            // Offline classification only: backend values belong to bound redemption.
            crate::classify_reference(&config, &reference)?;
            if env.insert(name.clone(), reference).is_some() { overwritten.insert(name); }
        }
        for name in overwritten { eprintln!("karambit: -e {name} given more than once; using the last"); }
        let mut refs: Vec<_> = env.values().cloned().collect();
        refs.extend(aws.iter().cloned());
        refs.sort(); refs.dedup();
        let profile = aws.as_ref().and_then(|n| n.strip_prefix("aws/")).map(str::to_owned);
        let target = resolve_owner_target(argv.first().context("missing command")?, &cwd)?;
        // Jail serializes canonical loopback host:port entries. Forward all equivalent
        // host spellings because Seatbelt permits both address families at each port.
        let mut allow_hosts = Vec::new();
        if let Some(jail) = &jail {
            let metadata = serde_json::to_value(jail)?;
            for host in metadata["allowed"].as_array().context("missing jail egress")? {
                let address: std::net::SocketAddr = host.as_str().context("invalid jail egress")?.parse()?;
                for name in ["localhost", "127.0.0.1", "[::1]"] {
                    allow_hosts.push(format!("{name}:{}", address.port()));
                }
            }
        }
        // Sized here, before the ambient snapshot is sent to the shim, so the daemon can refuse early.
        let (mut ambient, dropped) = crate::env::bound_ambient(self.caller.is_agent(), &config.allow_env);
        if !dropped.is_empty() {
            // Names only. The run proceeds without them; the human's `allow_env` can let them through.
            eprintln!("karambit: dropped code-loading variables from the agent's environment: {}", dropped.join(", "));
            self.audit("launch-env-dropped", &[], json!({"names": dropped}), &Ok(()));
        }
        ambient.extend(plain.into_iter().map(|(k, v)| (k.into_bytes(), v.into_bytes())));
        let ambient_bytes = ambient.iter().map(|(k, v)| k.len() + v.len() + 2 + std::mem::size_of::<usize>()).sum::<usize>() as u64;
        let prepared = request(&socket, &daemon::Req::LaunchPrepare { allow_hosts, jail: jail.is_some(), refs, env, target, argv, cwd, aws, ambient_bytes, no_redact })
            .map_err(prepare_error)?;
        let id = prepared["id"].as_str().context("missing launch id")?.to_owned();
        #[cfg(test)]
        if socket.parent().unwrap().join("redaction-probe").exists() {
            assert!(request(&socket, &daemon::Req::LaunchRedaction { id: id.clone() }).is_err(), "before redeem");
        }
        let _cancel = Cancel { socket: &socket, id: id.clone() };
        let expires_at = prepared["expires_at"].as_u64().context("missing launch expiry")?;
        let exe = std::fs::canonicalize(std::env::current_exe()?)?;
        let hash = crate::platform::helper::sha256_file(&exe)?;
        let pins = std::fs::read_to_string(self.paths.keys().join("daemon.sha256"))?;
        if !pins.lines().any(|p| p.trim() == hash) { bail!("launch executable is not pinned"); }
        let mut command = Command::new(exe);
        #[cfg(not(test))]
        command.arg("__launch");
        #[cfg(test)]
        command.args(["--exact", "daemon::launch_prepare_tests::production_shim_child", "--nocapture"]);
        spawn_bound(command, Instruction { jail, socket: socket.clone(), id, expires_at, region: region_override, ambient }, no_redact, profile.as_deref())
    }
}

#[cfg(test)]
pub(crate) fn test_spawn(command: Command, socket: PathBuf, prepared: &serde_json::Value) -> Result<ExitStatus> {
    test_spawn_region(command, socket, prepared, None)
}

#[cfg(test)]
pub(crate) fn test_spawn_region(command: Command, socket: PathBuf, prepared: &serde_json::Value, region: Option<String>) -> Result<ExitStatus> {
    // Low-level fixtures intentionally have no ambient environment. Owner API
    // process tests exercise the real snapshot with synthetic ambient values.
    spawn_bound(command, Instruction { jail: None, socket, id: prepared["id"].as_str().unwrap().into(), expires_at: prepared["expires_at"].as_u64().unwrap(), region, ambient: vec![] }, true, None)
}

fn spawn_bound(mut command: Command, instruction: Instruction, no_redact: bool, profile: Option<&str>) -> Result<ExitStatus> {
    let (mut owner, child) = UnixStream::pair()?;
    let (report_read, report_write) = exec_report_pipe()?;
    owner.set_write_timeout(Some(Duration::from_secs(10)))?;
    owner.set_read_timeout(Some(remaining(instruction.expires_at)?))?;
    if !no_redact { command.stdin(Stdio::inherit()).stdout(Stdio::piped()).stderr(Stdio::piped()); }
    let fd = child.as_raw_fd();
    let report = report_write.as_raw_fd();
    // Allocate before fork; only async-signal-safe libc calls inside pre_exec.
    let mut fds = fd_buffer()?;
    // Debug builds only: a caller may keep KARAMBIT_DEV=1 for the shim, whose daemon check then
    // accepts a test-process "daemon" that cargo started with DYLD_* set (`daemon::dev_allows_dyld_daemon`).
    #[cfg(debug_assertions)]
    let dev = std::env::var_os("KARAMBIT_DEV").is_some_and(|v| v == "1")
        || command.get_envs().any(|(k, v)| k == "KARAMBIT_DEV" && v.is_some_and(|v| v == "1"));
    command.env_clear();
    #[cfg(debug_assertions)]
    if dev { command.env("KARAMBIT_DEV", "1"); }
    unsafe { command.pre_exec(move || {
        if libc::dup2(fd, CHANNEL) < 0 { return Err(std::io::Error::last_os_error()); }
        if libc::dup2(report, EXEC_REPORT) < 0 { return Err(std::io::Error::last_os_error()); }
        if libc::fcntl(CHANNEL, libc::F_SETFD, 0) < 0 { return Err(std::io::Error::last_os_error()); }
        // Preserve Rust's exec-error pipe, but never inherit it into the shim.
        cloexec_open_fds(&mut fds, CHANNEL)?;
        // The sweep also marked the report pipe; the shim holds it open until its own execve closes it.
        if libc::fcntl(EXEC_REPORT, libc::F_SETFD, 0) < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(())
    }); }
    let mut process = command.spawn()?;
    drop(child);
    drop(report_write); // only the shim (and then the target's exec) holds a write end
    let setup = (|| -> Result<_> {
        send(&mut owner, &instruction)?;
        let mut ready = [0]; owner.read_exact(&mut ready)?;
        if ready != *b"R" { bail!("launch refused"); }
        if no_redact {
            // Test-only: <run>/go-byte overrides GO to prove the shim refuses anything
            // but exactly "G": empty = EOF, "T" = withhold (shim times out), else that byte.
            #[cfg(test)]
            if let Ok(over) = std::fs::read(instruction.socket.parent().unwrap().join("go-byte")) {
                match over.as_slice() {
                    [] => owner.shutdown(std::net::Shutdown::Write)?,
                    b"T" => (),
                    [b, ..] => owner.write_all(&[*b])?,
                }
                return Ok(None);
            }
            owner.write_all(b"G")?; return Ok(None);
        }
        let (red, static_aws, updates) = fetch_redaction(&instruction.socket, &instruction.id)?;
        #[cfg(test)]
        if instruction.socket.parent().unwrap().join("redaction-probe").exists() {
            assert!(fetch_redaction(&instruction.socket, &instruction.id).is_err(), "single use");
        }
        let out = process.stdout.take().context("stdout")?;
        let err = process.stderr.take().context("stderr")?;
        let red = std::sync::Arc::new(red);
        // SSO: role credentials are minted after this point; learn them before the target can.
        let updates = updates.map(|stream| -> Result<_> {
            let keep = stream.try_clone()?;
            let red = red.clone();
            std::thread::spawn(move || learn_redactions(stream, &red));
            Ok(keep)
        }).transpose()?;
        let r1 = red.clone();
        const EXPIRED: &[&str] = &["ExpiredToken", "RequestExpired", "security token included in the request is expired"];
        let watch = if static_aws { EXPIRED } else { &[] };
        let t1 = std::thread::spawn(move || r1.pump_watch(out, std::io::stdout().lock(), watch));
        let t2 = std::thread::spawn(move || red.pump_watch(err, std::io::stderr().lock(), watch));
        // Both streams have pumps before the shim is permitted to exec anything.
        owner.write_all(b"G")?;
        Ok(Some((t1, t2, updates)))
    })();
    let pumps = match setup {
        Ok(pumps) => pumps,
        Err(error) => { drop(owner); let _ = process.kill(); let _ = process.wait(); return Err(error); }
    };
    let status = process.wait();
    drop(owner);
    if let Some((t1, t2, updates)) = pumps {
        let e1 = t1.join().ok().and_then(Result::ok).unwrap_or(false);
        let e2 = t2.join().ok().and_then(Result::ok).unwrap_or(false);
        // Pumps are done: no output is left to redact, so end the update listener.
        if let Some(stream) = updates { let _ = stream.shutdown(std::net::Shutdown::Both); }
        if e1 || e2 {
            let p = profile.unwrap_or("?");
            eprintln!("karambit: AWS profile {p:?} has expired. Get fresh credentials from the AWS console and run:\n  karambit aws add {p} --force");
        }
    }
    let status = match status {
        Ok(status) => status,
        Err(error) => { let _ = process.kill(); let _ = process.wait(); return Err(error.into()); }
    };
    // `status` alone can't tell the target's exit 1 from a shim that never ran it.
    check_exec_report(&read_exec_report(report_read)).context("the program did not start")?;
    Ok(status)
}

fn remaining(expires_at: u64) -> Result<Duration> {
    Duration::from_secs(expires_at).checked_sub(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
        .filter(|v| !v.is_zero()).context("launch expired")
}

/// The stream is returned open only when the daemon will send later redaction additions.
fn fetch_redaction(socket: &Path, id: &str) -> Result<(crate::redact::Redactor, bool, Option<UnixStream>)> {
    let mut stream = UnixStream::connect(socket)?;
    daemon::verify_daemon(socket, &stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    send(&mut stream, &daemon::Req::LaunchRedaction { id: id.into() })?;
    let bytes = frame(&mut stream)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Redaction<'a> { #[serde(borrow)] values: Vec<(String, &'a RawValue)>, static_aws: bool, #[serde(default)] updates: bool }
    let data: Redaction<'_> = serde_json::from_slice(&bytes)?;
    let values = data.values.iter().map(|(name, raw)| {
        let mut value = Zeroizing::new(Vec::with_capacity(raw.get().len()));
        unescape_into(raw.get().as_bytes(), &mut value)?;
        Ok((name.clone(), value))
    }).collect::<Result<Vec<_>>>()?;
    let named = values.iter().map(|(n,v)| (n.clone(), v.as_slice())).collect::<Vec<_>>();
    let redactor = crate::redact::Redactor::new(&named);
    // Additions arrive whenever the target fetches new credentials: wait without a deadline.
    if data.updates { stream.set_read_timeout(None)?; }
    Ok((redactor, data.static_aws, data.updates.then_some(stream)))
}

/// Adds each pushed value set to the redactor, then acknowledges it. The daemon withholds
/// the credentials from the target until this ack, so the add must complete first.
/// Ends when the daemon closes the stream or the owner shuts it down.
pub(crate) fn learn_redactions(mut stream: UnixStream, redactor: &crate::redact::Redactor) {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Update<'a> { seq: u64, #[serde(borrow)] values: Vec<(String, &'a RawValue)> }
    while let Ok(bytes) = frame(&mut stream) {
        let learned = (|| -> Result<u64> {
            let update: Update<'_> = serde_json::from_slice(&bytes)?;
            let values = update.values.iter().map(|(name, raw)| {
                let mut value = Zeroizing::new(Vec::with_capacity(raw.get().len()));
                unescape_into(raw.get().as_bytes(), &mut value)?;
                Ok((name.clone(), value))
            }).collect::<Result<Vec<_>>>()?;
            let named = values.iter().map(|(n, v)| (n.clone(), v.as_slice())).collect::<Vec<_>>();
            redactor.add(&named);
            Ok(update.seq)
        })();
        // An undecodable update is never acknowledged: the daemon then refuses to serve.
        let Ok(seq) = learned else { return };
        if send(&mut stream, &serde_json::json!({"ack": seq})).is_err() { return; }
    }
}

/// CLI-only entry: fd 3 is a private inherited Unix socket, not a bearer token.
/// Never opens the default vault or starts a daemon. Errors contain no payload.
pub fn launch_shim_main() -> Result<()> {
    // Validate before taking ownership; a random invocation is fail-closed.
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&kind) as libc::socklen_t;
    unsafe {
        if libc::getsockopt(CHANNEL, libc::SOL_SOCKET, libc::SO_TYPE, (&mut kind as *mut libc::c_int).cast(), &mut len) != 0 || kind != libc::SOCK_STREAM {
            bail!("missing private launch channel");
        }
        if libc::fcntl(CHANNEL, libc::F_SETFD, libc::FD_CLOEXEC) < 0 { bail!("launch channel setup failed"); }
        // fd 4 is the owner's exec-report pipe; without it the owner could not tell a failed exec from a run.
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(EXEC_REPORT, &mut st) != 0 || st.st_mode & libc::S_IFMT != libc::S_IFIFO
            || libc::fcntl(EXEC_REPORT, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            bail!("missing exec report channel");
        }
    }
    let channel = unsafe { UnixStream::from_raw_fd(CHANNEL) };
    run(channel).map_err(|_| {
        // Failed before execve was attempted (bad GO, changed target, sandbox...). Errno 0: the
        // cause isn't an exec error, and run()'s error text must not carry payload anyway.
        if !PAST_EXEC.swap(true, std::sync::atomic::Ordering::SeqCst) { report_exec_failure(0); }
        anyhow::anyhow!("bound launch failed")
    })
}

fn run(mut channel: UnixStream) -> Result<()> {
    channel.set_read_timeout(Some(Duration::from_secs(10))).context("channel timeout")?;
    let mut instruction: Instruction = serde_json::from_slice(&frame(&mut channel).context("instruction frame")?).context("instruction decode")?;
    // The shim alone leaves the foreground process group. The target rejoins
    // it before exec, so tty/killpg signals never get forwarded twice.
    let owner_pgid = unsafe { libc::getpgrp() };
    if unsafe { libc::setpgid(0, 0) } != 0 { bail!("shim process group"); }
    let timeout = remaining(instruction.expires_at)?;
    let mut control = UnixStream::connect(&instruction.socket).context("daemon connect")?;
    daemon::verify_daemon(&instruction.socket, &control)?;
    control.set_read_timeout(Some(timeout))?;
    control.set_write_timeout(Some(timeout))?;
    send(&mut control, &daemon::Req::LaunchBind { id: instruction.id.clone() })?;
    let token_frame = frame(&mut control)?;
    #[derive(Deserialize)]
    struct Token<'a> { #[serde(borrow)] token: &'a str }
    let token: Token<'_> = serde_json::from_slice(&token_frame)?;
    #[derive(Serialize)]
    struct Redeem<'a> { op: &'static str, token: &'a str }
    send(&mut control, &Redeem { op: "launch_redeem", token: token.token })?;
    drop(token_frame);
    let bundle_frame = frame(&mut control)?;
    // Env values stay borrowed raw literals inside the zeroizing frame and are
    // decoded below straight into zeroizing exec buffers, including AWS tokens.
    let bundle: Bundle<'_> = serde_json::from_slice(&bundle_frame)?;
    #[cfg(test)]
    assert!(std::env::vars_os().next().is_none(), "shim environment changed during redemption");
    let CommandBinding::Pinned { path, .. } = &bundle.target else { bail!("unbound target"); };
    if bundle.argv.is_empty() || !Path::new(path).is_absolute() { bail!("invalid target"); }
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let executable = CString::new(path.as_bytes())?;
    let cwd = CString::new(bundle.cwd.as_os_str().as_bytes())?;
    let argv = bundle.argv.iter().map(|a| CString::new(a.as_bytes())).collect::<std::result::Result<Vec<_>, _>>()?;
    let mut argv_ptrs: Vec<_> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env = Vec::with_capacity(bundle.env.len() + 8);
    let aws_reserved = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
        "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CREDENTIAL_EXPIRATION", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
        "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_SDK_LOAD_CONFIG", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION"];
    for (key, raw) in &bundle.env {
        if *key == "KARAMBIT_INJECTED" || (bundle.aws.is_some() && aws_reserved.contains(key)) { continue; }
        if crate::valid_var(key).is_err() { bail!("invalid env"); }
        let raw = raw.get().as_bytes();
        let mut entry = Zeroizing::new(Vec::with_capacity(key.len() + raw.len() + 2));
        entry.extend_from_slice(key.as_bytes()); entry.push(b'=');
        let start = entry.len();
        unescape_into(raw, &mut entry)?;
        if entry[start..].contains(&0) { bail!("invalid env"); }
        entry.push(0);
        env.push(entry);
    }
    fn entry(key: &str, value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if value.contains(&0) { bail!("invalid env"); }
        let mut out = Zeroizing::new(Vec::with_capacity(key.len() + value.len() + 2));
        out.extend_from_slice(key.as_bytes()); out.push(b'='); out.extend_from_slice(value); out.push(0);
        Ok(out)
    }
    for (key, value) in &instruction.ambient {
        if key.is_empty() || key.contains(&0) || key.contains(&b'=') { bail!("invalid env"); }
        if key.starts_with(b"KARAMBIT_") || bundle.env.keys().any(|k| k.as_bytes() == key)
            || (bundle.aws.is_some() && aws_reserved.iter().any(|k| k.as_bytes() == key)) { continue; }
        let mut out = Zeroizing::new(Vec::with_capacity(key.len() + value.len() + 2));
        if value.contains(&0) { bail!("invalid env"); }
        out.extend_from_slice(key); out.push(b'='); out.extend_from_slice(value); out.push(0);
        env.push(out);
    }
    env.push(entry("KARAMBIT_INJECTED", b"1")?);
    if let Some(aws) = &bundle.aws {
        // Production socket is <root>/run/d.sock; use its parent so the
        // shim never consults ambient HOME/config or opens a default vault.
        // A jailed target cannot read the vault, including run/aws-empty.
        let empty = if instruction.jail.is_some() { PathBuf::from("/dev/null") }
            else { instruction.socket.parent().context("invalid socket")?.join("aws-empty") };
        if instruction.jail.is_none() { std::fs::write(&empty, b"")?; }
        if let Some(jail) = &mut instruction.jail { jail.allow_endpoint(&aws.url)?; }
        for key in ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"] {
            env.push(entry(key, empty.as_os_str().as_bytes())?);
        }
        env.push(entry("AWS_SDK_LOAD_CONFIG", b"0")?);
        env.push(entry("AWS_CONTAINER_CREDENTIALS_FULL_URI", aws.url.as_bytes())?);
        let raw = aws.token.get().as_bytes();
        let mut token = Zeroizing::new(Vec::with_capacity(raw.len()));
        unescape_into(raw, &mut token)?;
        env.push(entry("AWS_CONTAINER_AUTHORIZATION_TOKEN", &token)?);
        if let Some(region) = instruction.region.as_ref().or(aws.region.as_ref()) {
            for key in ["AWS_REGION", "AWS_DEFAULT_REGION"] { env.push(entry(key, region.as_bytes())?); }
        }
    }
    let mut env_ptrs: Vec<_> = env.iter().map(|e| e.as_ptr().cast::<libc::c_char>()).collect();
    env_ptrs.push(std::ptr::null());
    #[cfg(test)]
    if instruction.socket.parent().unwrap().join("redaction-probe").exists() {
        assert!(request(&instruction.socket, &daemon::Req::LaunchRedaction { id: instruction.id.clone() }).is_err(), "shim is not owner");
    }
    channel.set_read_timeout(Some(remaining(instruction.expires_at)?))?;
    channel.write_all(b"R")?;
    let mut go = [0]; channel.read_exact(&mut go)?;
    if go != *b"G" { bail!("launch refused"); }
    drop(channel);
    // Fresh canonical path and SHA-256, never a basename or mtime cache.
    if CommandBinding::capture_target(Some(path))?.0 != bundle.target { bail!("target changed"); }
    if std::fs::canonicalize(&bundle.cwd)? != bundle.cwd { bail!("cwd changed"); }
    // Install before fork (AWS) or direct exec. The existing connected control
    // socket remains private/CLOEXEC; there is no Unix socket or blanket loopback allow.
    if let Some(jail) = &instruction.jail { NativeSandbox.apply(jail)?; }
    if bundle.aws.is_some() {
        let mut fds = fd_buffer()?;
        // Block forwarding signals across fork/handler installation. The child
        // restores the original mask before exec; the parent drains pending
        // signals only once the child pid is published.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            for signal in FORWARDED { libc::sigaddset(&mut mask, signal); }
            if libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut old) != 0 { bail!("signal mask"); }
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()); }
            bail!("fork failed");
        }
        if pid == 0 {
            // No Rust destruction, allocation, formatting or unwinding here.
            unsafe {
                if libc::setpgid(0, owner_pgid) != 0 { exec_child_fail(last_errno()); }
                libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
                if libc::chdir(cwd.as_ptr()) != 0 { exec_child_fail(last_errno()); }
                if let Err(e) = cloexec_open_fds(&mut fds, -1) { exec_child_fail(e.raw_os_error().unwrap_or(0)); }
                report_exec_attempt();
                libc::execve(executable.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
                exec_child_fail(last_errno());
            }
        }
        if unsafe { libc::setpgid(pid, owner_pgid) } != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EACCES) {
            unsafe { libc::kill(pid, libc::SIGKILL); libc::waitpid(pid, std::ptr::null_mut(), 0); }
            bail!("target process group");
        }
        // From here the child owns exec; its P/E report decides, not a later shim error.
        PAST_EXEC.store(true, std::sync::atomic::Ordering::SeqCst);
        CHILD.store(pid, std::sync::atomic::Ordering::SeqCst);
        unsafe {
            for signal in FORWARDED { libc::signal(signal, forward as *const () as libc::sighandler_t); }
        }
        // The waiting shim needs only the child pid and control fd, never the
        // redeemed frame or envp. Zeroizing Drop wipes these before unblocking.
        drop(bundle);
        drop(bundle_frame);
        drop(env);
        drop(env_ptrs);
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()); }
        // Observe termination WITHOUT reaping (WNOWAIT): the pid stays owned by
        // this zombie, so a forwarded signal can never reach a reused pid. Only
        // after forwarding is blocked and CHILD cleared do we reap.
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) } == 0 { break; }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) { bail!("wait failed"); }
        }
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()); }
        CHILD.store(0, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        reap_boundary_hook(pid, instruction.socket.parent());
        let mut status = 0;
        loop {
            if unsafe { libc::waitpid(pid, &mut status, 0) } == pid { break; }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) { bail!("wait failed"); }
        }
        drop(control);
        if libc::WIFSIGNALED(status) {
            let signal = libc::WTERMSIG(status);
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::sigemptyset(&mut mask); libc::sigaddset(&mut mask, signal);
                libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut());
                libc::raise(signal);
                libc::_exit(128 + signal);
            }
        }
        unsafe { libc::_exit(libc::WEXITSTATUS(status)); }
    }
    drop(control); // closes the env-only redaction/containment session.
    // Defense in depth: only stdio survives into the target.
    unsafe { cloexec_open_fds(&mut fd_buffer()?, -1)?; }
    // execve, not execvp: an ENOEXEC target must never fall back to /bin/sh.
    unsafe {
        if libc::setpgid(0, owner_pgid) != 0 { return Err(std::io::Error::last_os_error().into()); }
        if libc::chdir(cwd.as_ptr()) != 0 { return Err(std::io::Error::last_os_error().into()); }
        PAST_EXEC.store(true, std::sync::atomic::Ordering::SeqCst);
        report_exec_attempt();
        libc::execve(executable.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    let error = std::io::Error::last_os_error();
    report_exec_failure(error.raw_os_error().unwrap_or(0));
    Err(error.into())
}

fn last_errno() -> i32 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) }

/// Forked child could not exec: say why (async-signal-safe) and leave with the shell's "not run" status.
unsafe fn exec_child_fail(errno: i32) -> ! {
    report_exec_failure(errno);
    unsafe { libc::_exit(127) }
}

/// Test-only: at the observed-exit / not-yet-reaped boundary, prove that a
/// forwarding signal is blocked and no longer targets the pid. Active only when
/// the test created `<run>/reap-probe-enable`; writes `<run>/reap-probe`.
#[cfg(test)]
fn reap_boundary_hook(pid: i32, run: Option<&Path>) {
    let Some(run) = run else { return };
    if !run.join("reap-probe-enable").exists() { return; }
    let path = run.join("reap-probe");
    // The signal is blocked now; raising it must not invoke `forward`.
    unsafe { libc::raise(libc::SIGTERM); }
    let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigpending(&mut pending); }
    let blocked = unsafe { libc::sigismember(&pending, libc::SIGTERM) } == 1;
    let cleared = CHILD.load(std::sync::atomic::Ordering::SeqCst) == 0;
    // Still a zombie: kill(pid, 0) succeeds, proving waitid did not reap.
    let zombie = unsafe { libc::kill(pid, 0) } == 0;
    let _ = std::fs::write(path, format!("blocked:{blocked}\ncleared:{cleared}\nzombie:{zombie}\n"));
}

// Delivered bundle shape. deny_unknown_fields on both levels: any field the
// shim does not understand refuses before exec.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Aws<'a> {
    url: String,
    #[serde(borrow)] token: &'a RawValue,
    region: Option<String>,
    #[serde(rename = "endpoint_id")] _endpoint_id: String,
    #[serde(rename = "account")] _account: Option<String>,
    #[serde(rename = "role")] _role: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle<'a> {
    target: CommandBinding, argv: Vec<String>, cwd: PathBuf,
    #[serde(borrow)] env: BTreeMap<&'a str, &'a RawValue>,
    #[serde(borrow)] aws: Option<Aws<'a>>,
}

const FORWARDED: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
static CHILD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
extern "C" fn forward(signal: i32) {
    let pid = CHILD.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe { crate::platform::forward_signal(pid, signal); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(literal: &str) -> Result<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(literal.len()));
        unescape_into(literal.as_bytes(), &mut out)?;
        Ok(out.to_vec())
    }

    #[test]
    fn instruction_refuses_unknown_fields() {
        let wire = r#"{"socket":"/tmp/synthetic","id":"synthetic","expires_at":1,"replacement_target":"/bin/sh"}"#;
        assert!(serde_json::from_str::<Instruction>(wire).is_err());
    }

    #[test]
    fn secret_env_decodes_json_escapes_without_reallocation() {
        assert_eq!(decode(r#""line\nquote\"slash\\\/tab\t\b\f\r""#).unwrap(), b"line\nquote\"slash\\/tab\t\x08\x0c\r");
        assert_eq!(decode(r#""\u00e9\u20ac\ud83d\ude00""#).unwrap(), "é€😀".as_bytes());
        // Long escaped value: exact-capacity buffer, debug-asserted no reallocation.
        let long = format!("\"{}\"", r#"a\"\\\n\u0041"#.repeat(20_000));
        assert_eq!(decode(&long).unwrap(), b"a\"\\\nA".repeat(20_000));
        // Round-trips whatever serde_json emits for arbitrary values.
        let value = "\u{1}\u{1f}\"\\\n\u{7f}é😀";
        assert_eq!(decode(&serde_json::to_string(value).unwrap()).unwrap(), value.as_bytes());
        for bad in [r#""\x""#, r#""\u12""#, r#""\ud83d""#, r#""\ud83d\u0041""#, r#""\udc00""#, r#""\""#, "nope", r#""\"#] {
            assert!(decode(bad).is_err(), "{bad}");
        }
        let mut tight = Zeroizing::new(Vec::with_capacity(2));
        assert!(unescape_into(br#""abc""#, &mut tight).is_err());
    }

    #[test]
    fn bundle_refuses_unknown_fields_at_both_levels() {
        let target = r#""target":{"path":"/usr/bin/true","sha256":"00"},"argv":["/usr/bin/true"],"cwd":"/tmp","env":{}"#;
        let aws = r#""url":"http://127.0.0.1:1/x","token":"t","endpoint_id":"e""#;
        let parse = |json: &str| serde_json::from_str::<Bundle<'_>>(json).map(|_| ());
        assert!(parse(&format!("{{{target}}}")).is_ok());
        assert!(parse(&format!("{{{target},\"aws\":{{{aws}}}}}")).is_ok());
        assert!(parse(&format!("{{{target},\"extra\":1}}")).is_err(), "unknown top-level field");
        assert!(parse(&format!("{{{target},\"aws\":{{{aws},\"secret_access_key\":\"x\"}}}}")).is_err(), "unknown aws field");
    }

    #[test]
    fn exec_report_decides_whether_the_program_started() {
        let errno = |e: i32| [b"E".as_slice(), &e.to_le_bytes()].concat();
        let message = |bytes: &[u8]| format!("{:#}", check_exec_report(bytes).unwrap_err());
        // execve succeeded: the pipe closed after the attempt marker only.
        assert!(check_exec_report(b"P").is_ok());
        // Nothing at all: the launcher died before it tried to exec.
        assert!(message(b"").contains("stopped before"));
        // Refused before exec (errno 0), or exec itself failed.
        assert!(message(&errno(0)).contains("refused"));
        assert!(message(&errno(libc::ENOEXEC)).starts_with("exec failed:"));
        assert!(message(&errno(libc::E2BIG)).contains("over the system limit"));
        assert!(message(&[b"P".as_slice(), &errno(libc::EACCES)].concat()).starts_with("exec failed:"));
        assert!(message(b"E").contains("refused"), "truncated errno");
        assert!(message(b"X").contains("unreadable"));
    }

    /// Runs `body` as the shim stand-in: fd 3 handshake, then whatever it writes to fd 4.
    fn spawn_stand_in(body: &str) -> Result<ExitStatus> {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("read -r _ <&3; printf R >&3; dd bs=1 count=1 <&3 >/dev/null 2>/dev/null; {body}")]);
        let expires_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 30;
        spawn_bound(command, Instruction { jail: None, socket: "/nonexistent".into(), id: "synthetic".into(), expires_at, region: None, ambient: vec![] }, true, None)
    }

    #[test]
    fn owner_errors_when_the_launcher_never_reached_exec() {
        // Exit 1 with no report is what a shim that bailed before exec looks like.
        let error = spawn_stand_in("exit 1").unwrap_err();
        assert!(format!("{error:#}").contains("the program did not start"), "{error:#}");
        // Reported exec failure: the errno text reaches the caller.
        let error = spawn_stand_in(r"printf 'E\007\000\000\000' >&4; exit 127").unwrap_err();
        assert!(format!("{error:#}").contains("over the system limit"), "{error:#}");
        // exec reached: exit 1 is then the program's own status.
        assert_eq!(spawn_stand_in("printf P >&4; exit 1").unwrap().code(), Some(1));
    }

    #[test]
    fn spawn_marks_descriptors_above_soft_limit() {
        const HIGH: i32 = 917;
        if std::env::var_os("KARAMBIT_TEST_HIGH_FD_CHILD").is_none() {
            // Isolate the RLIMIT change from the parallel suite.
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "shim::tests::spawn_marks_descriptors_above_soft_limit", "--nocapture"])
                .env("KARAMBIT_TEST_HIGH_FD_CHILD", "1").status().unwrap();
            assert!(status.success());
            return;
        }
        unsafe {
            let mut limit: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
            if limit.rlim_cur <= HIGH as libc::rlim_t {
                limit.rlim_cur = limit.rlim_max.min(4096);
                assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
            }
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            assert!(null >= 0);
            assert_eq!(libc::dup2(null, HIGH), HIGH); // dup2 clears CLOEXEC
            libc::close(null);
            limit.rlim_cur = 128;
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
            assert!(libc::sysconf(libc::_SC_OPEN_MAX) <= HIGH as libc::c_long);
        }
        // The child reads the instruction (no write race), proves the channel is
        // inherited and the high descriptor is not.
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("read -r _ <&3; printf R >&3; dd bs=1 count=1 <&3 >/dev/null 2>/dev/null; printf P >&4; [ -e /dev/fd/3 ] || exit 8; [ -e /dev/fd/{HIGH} ] && exit 7; exit 0")]);
        let status = spawn_bound(command, Instruction { jail: None, socket: "/nonexistent".into(), id: "synthetic".into(), expires_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 30, region: None, ambient: vec![] }, true, None).unwrap();
        assert_eq!(status.code(), Some(0), "7 = high descriptor inherited, 8 = channel missing");
    }


}
