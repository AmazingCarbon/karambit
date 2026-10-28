//! macOS capability implementation. Keep kernel APIs out of authorization logic.
use anyhow::{Result, bail};
use std::os::unix::net::UnixStream;
use super::ProcessIdentity;
fn process_identity_and_parent(pid: i32) -> anyhow::Result<(ProcessIdentity, i32)> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if n != size { anyhow::bail!("launch channel: process identity unavailable"); }
    let info = unsafe { info.assume_init() };
    Ok((ProcessIdentity { pid, sec: info.pbi_start_tvsec, usec: info.pbi_start_tvusec }, info.pbi_ppid as i32))
}

pub(crate) fn process_identity(pid: i32) -> anyhow::Result<ProcessIdentity> {
    Ok(process_identity_and_parent(pid)?.0)
}

/// Read the kernel parent, then recheck the child's full start identity and parent
/// relation. Read-only prerequisite; no wire-supplied parent PID is trusted.
#[allow(dead_code)] // Pending daemon binding, not used for authorization yet.
pub(crate) fn process_parent_identity(child: ProcessIdentity) -> anyhow::Result<ProcessIdentity> {
    let (current, ppid) = process_identity_and_parent(child.pid)?;
    if current != child || ppid <= 1 { anyhow::bail!("launch channel: identity mismatch"); }
    let parent = process_identity(ppid)?;
    if process_identity_and_parent(child.pid)? != (child, ppid) {
        anyhow::bail!("launch channel: identity mismatch");
    }
    Ok(parent)
}

pub(crate) mod process {
    use std::ffi::CStr;
    use std::mem::{MaybeUninit, size_of};

    pub struct Proc {
        pub ppid: i32,
        pub display: String,
        /// basenames / path components of comm, exec path and argv[0..2].
        pub candidates: Vec<String>,
        /// Kernel process name and basename of the executable path.
        pub comm: String,
        pub exe_name: String,
        /// Executable is inside an `X.app/Contents/` bundle (a GUI app).
        pub app_bundle: bool,
        /// Process start time (unix seconds): pid + start is unique across pid reuse.
        pub start: u64,
    }

    fn cstr(buf: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn info(pid: i32) -> Option<Proc> {
        let mut bsd = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let sz = size_of::<libc::proc_bsdinfo>() as i32;
        let n = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, bsd.as_mut_ptr().cast(), sz)
        };
        if n != sz {
            return None;
        }
        let bsd = unsafe { bsd.assume_init() };
        let comm = cstr(&bsd.pbi_comm);
        let args = procargs(pid);
        // argv[0] carries process.title for node-based agents (pi, claude, codex).
        let display = args
            .get(1)
            .map(|a0| a0.rsplit('/').next().unwrap_or(a0).to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| comm.clone());
        let cands = crate::agent::build_candidates(&comm, &args);
        let exec = args.first().map(String::as_str).unwrap_or("");
        let exe_name = exec.rsplit('/').next().unwrap_or("").to_string();
        let app_bundle = exec.contains(".app/Contents/");
        Some(Proc { ppid: bsd.pbi_ppid as i32, display, candidates: cands, comm, exe_name, app_bundle, start: bsd.pbi_start_tvsec })
    }

    /// Current working directory of `pid` (kernel, not the process's own claim).
    pub fn cwd(pid: i32) -> Option<String> {
        let mut vp = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
        let sz = size_of::<libc::proc_vnodepathinfo>() as i32;
        let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDVNODEPATHINFO, 0, vp.as_mut_ptr().cast(), sz) };
        if n != sz {
            return None;
        }
        let vp = unsafe { vp.assume_init() };
        let flat: Vec<libc::c_char> = vp.pvi_cdir.vip_path.iter().flatten().copied().collect();
        let s = cstr(&flat);
        (!s.is_empty()).then_some(s)
    }

    /// Real executable path of `pid`.
    pub fn exe(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        String::from_utf8(buf).ok()
    }

    pub fn env_names(pid: i32) -> Option<Vec<String>> {
        crate::agent::procargs_env_names(&procargs_snapshot(pid)?)
    }

    pub fn session_label(pid: i32, kind: Option<&str>) -> Option<String> {
        let buf = procargs_snapshot(pid)?;
        crate::agent::session_label(kind, |key| {
            let mut value = None;
            crate::agent::procargs_environment(&buf, |name, bytes| {
                if name == key && bytes.len() <= 128 {
                    value = std::str::from_utf8(bytes).ok().map(str::to_owned);
                }
            })?;
            value
        })
    }

    fn procargs_snapshot(pid: i32) -> Option<Vec<u8>> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut size: libc::size_t = 0;
        unsafe {
            if libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) != 0 {
                return None;
            }
        }
        if !(4..=1024 * 1024).contains(&size) { return None; }
        let mut buf = vec![0u8; size];
        unsafe {
            if libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) != 0 {
                return None;
            }
        }
        buf.truncate(size);
        Some(buf)
    }

    /// [exec_path, argv0, argv1, ...] via KERN_PROCARGS2. Empty on failure.
    fn procargs(pid: i32) -> Vec<String> {
        let Some(buf) = procargs_snapshot(pid) else { return vec![]; };
        if buf.len() < 4 {
            return vec![];
        }
        let argc = i32::from_ne_bytes(buf[..4].try_into().unwrap()).max(0) as usize;
        let mut rest = &buf[4..];
        let mut out = Vec::new();
        // exec path
        if let Ok(c) = CStr::from_bytes_until_nul(rest) {
            out.push(c.to_string_lossy().into_owned());
            rest = &rest[c.to_bytes().len()..];
        }
        while let Some((&0, r)) = rest.split_first() {
            rest = r;
        }
        for _ in 0..argc.min(3) {
            let Ok(c) = CStr::from_bytes_until_nul(rest) else { break };
            out.push(c.to_string_lossy().into_owned());
            rest = &rest[(c.to_bytes().len() + 1).min(rest.len())..];
        }
        out
    }
}

pub(crate) fn peer_token_of(c: &UnixStream, me_uid: libc::uid_t) -> Result<(i32, u32)> {
    use std::os::fd::AsRawFd;
    // audit_token_t is 8 x u32: [auid, euid, egid, ruid, rgid, pid, asid, pidversion].
    let mut tok = [0u32; 8];
    let mut len = std::mem::size_of_val(&tok) as libc::socklen_t;
    let r = unsafe { libc::getsockopt(c.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERTOKEN, tok.as_mut_ptr().cast(), &mut len) };
    if r != 0 {
        bail!("can't identify caller (LOCAL_PEERTOKEN failed)");
    }
    if tok[1] != me_uid {
        bail!("caller is a different user");
    }
    Ok((tok[5] as i32, tok[7]))
}

/// Live pidversion of `pid` from its task audit token. Fails for a dead/zombie
/// pid or one we cannot inspect, so the caller fails closed.
pub(crate) fn live_pidversion(pid: i32) -> Result<u32> {
    unsafe extern "C" {
        fn task_name_for_pid(target: libc::mach_port_t, pid: libc::c_int, task: *mut libc::mach_port_t) -> libc::kern_return_t;
        fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> libc::kern_return_t;
    }
    const TASK_AUDIT_TOKEN: libc::task_flavor_t = 15;
    let mut task: libc::mach_port_t = 0;
    #[allow(deprecated)]
    let me = unsafe { libc::mach_task_self() };
    if unsafe { task_name_for_pid(me, pid, &mut task) } != 0 { bail!("launch refused"); }
    let mut tok = [0u32; 8];
    let mut count: libc::mach_msg_type_number_t = 8;
    let kr = unsafe { libc::task_info(task, TASK_AUDIT_TOKEN, tok.as_mut_ptr().cast(), &mut count) };
    unsafe { mach_port_deallocate(me, task); }
    if kr != 0 || count != 8 || tok[5] as i32 != pid { bail!("launch refused"); }
    Ok(tok[7])
}

pub(crate) fn bound_peer_pid(c: &UnixStream, peer_pid: i32) -> Result<i32> {
    use std::os::fd::AsRawFd;
    let mut pid: i32 = 0;
    let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
    if unsafe { libc::getsockopt(c.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERPID, (&mut pid as *mut i32).cast(), &mut len) } != 0 || pid != peer_pid { bail!("launch refused"); }
    Ok(pid)
}
pub(crate) fn peer_pid(fd: std::os::fd::RawFd) -> Result<i32> {
    let mut pid: i32 = 0;
    let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
    let result = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, (&mut pid as *mut i32).cast(), &mut len) };
    if result != 0 || len as usize != std::mem::size_of_val(&pid) {
        bail!("launch channel: peer identity unavailable");
    }
    Ok(pid)
}

/// Buffer for every open descriptor of this process, sized before fork so the
/// post-fork sweep never allocates. Slack covers descriptors opened by other
/// threads before the fork; a full buffer fails closed.
pub(crate) fn fd_buffer() -> Result<Vec<libc::proc_fdinfo>> {
    let need = unsafe { libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 { bail!("cannot list descriptors"); }
    let count = need as usize / std::mem::size_of::<libc::proc_fdinfo>() * 2 + 64;
    Ok(vec![libc::proc_fdinfo { proc_fd: 0, proc_fdtype: 0 }; count])
}

/// Marks every OPEN descriptor above stderr except `keep` close-on-exec. It
/// enumerates the real descriptor table: a soft-limit sweep misses descriptors
/// above a lowered RLIMIT_NOFILE. Async-signal-safe (syscalls only, no allocation).
pub(crate) unsafe fn cloexec_open_fds(fds: &mut [libc::proc_fdinfo], keep: i32) -> std::io::Result<()> {
    let size = std::mem::size_of_val(fds) as libc::c_int;
    let got = unsafe { libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), size) };
    if got <= 0 || got >= size { return Err(std::io::Error::from_raw_os_error(libc::EMFILE)); }
    for info in &fds[..got as usize / std::mem::size_of::<libc::proc_fdinfo>()] {
        if info.proc_fd > 2 && info.proc_fd != keep && unsafe { libc::fcntl(info.proc_fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn connect_cleanup(path: &std::path::Path) -> std::io::Result<UnixStream> {
    use std::os::{fd::{AsRawFd, FromRawFd, OwnedFd}, unix::ffi::OsStrExt};
    let bytes = path.as_os_str().as_bytes();
    // sockaddr_un is zeroed so the pathname is NUL-terminated.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "daemon socket path too long"));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    addr.sun_len = std::mem::size_of_val(&addr) as u8;
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) { *dst = *src as libc::c_char; }
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 { return Err(std::io::Error::last_os_error()); }
    // Own the descriptor immediately, including every error path below.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let one: libc::c_int = 1;
    if unsafe { libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_NOSIGPIPE,
        (&one as *const libc::c_int).cast(), std::mem::size_of_val(&one) as libc::socklen_t) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::connect(fd.as_raw_fd(), (&addr as *const libc::sockaddr_un).cast(), std::mem::size_of_val(&addr) as libc::socklen_t) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(UnixStream::from(fd))
}

#[cfg(not(test))]
pub(crate) fn spawn_daemon(p: &Paths) -> Result<()> {
    let exe = daemon_exe()?;
    store::ensure_dir(&crate::daemon::run_dir(p))?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(crate::daemon::run_dir(p).join("daemon.log"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon")
        .env("KARAMBIT_DIR", &p.root)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // The daemon refuses to start with DYLD_* set; a client that has some must not block it.
    for (name, _) in std::env::vars_os().filter(|(name, _)| name.as_encoded_bytes().starts_with(b"DYLD_")) { cmd.env_remove(name); }
    // Own session: not killed with the terminal or the agent that triggered it.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().context("start karambit daemon")?;
    Ok(())
}

/// The `karambit` CLI binary hosts the daemon. From the GUI, look next to the
/// bundle's exe, then ~/.local/bin.
#[cfg(not(test))]
fn daemon_exe() -> Result<PathBuf> {
    let me = std::env::current_exe()?;
    if !me.file_name().is_some_and(|n| n == "karambit" || n == "karambit-gui") {
        bail!("test executable: refusing to spawn a daemon; use an in-process server");
    }
    if me.file_name().is_some_and(|n| n == "karambit") {
        return Ok(me);
    }
    let mut cands = vec![];
    if let Some(d) = me.parent() {
        cands.push(d.join("karambit"));
    }
    if let Some(h) = std::env::var_os("HOME") {
        cands.push(PathBuf::from(h).join(".local/bin/karambit"));
    }
    cands.into_iter().find(|p| p.is_file()).ok_or_else(|| anyhow!("karambit CLI not found (needed to run the lease daemon)"))
}

#[cfg(not(test))]
use crate::{store, Paths};
#[cfg(not(test))]
use std::path::PathBuf;
#[cfg(not(test))]
use anyhow::{Context, anyhow};

/// Signal-handler operation: preserve errno, allocate nothing.
pub(crate) unsafe fn forward_signal(pid: i32, signal: i32) {
    unsafe {
        let errno = *libc::__error();
        libc::kill(pid, signal);
        *libc::__error() = errno;
    }
}

pub(crate) fn require_helper() -> Result<()> { Ok(()) }

pub const fn key_probe_source() -> &'static str { include_str!("../../../cli/src/key_use_probe.swift") }
pub fn key_probe_compilers() -> Vec<(std::path::PathBuf, Vec<std::ffi::OsString>)> {
    vec![("/usr/bin/xcrun".into(), vec!["swiftc".into()]), ("/usr/bin/swiftc".into(), vec![])]
}
pub fn sibling_environment(ps: &std::path::Path, pid: &str) -> std::io::Result<std::process::Output> {
    use std::process::{Command, Stdio};
    Command::new(ps).args(["-E", "-ww", "-p", pid, "-o", "command="])
        .stdin(Stdio::null()).stderr(Stdio::null()).output()
}
