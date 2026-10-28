//! `run --status-fd N`: one JSON line on a descriptor the launched command never holds.
//!
//! Exit 125 and stderr can't prove a refusal: the command shares stderr and may exit 125
//! itself. The status descriptor can. karambit moves it to a close-on-exec descriptor
//! before anything is spawned (daemon, shim, the command), so only this process can
//! write it. Use a pipe: a file path would let the command open and write it too.
//!
//! The line is written once, when karambit is done:
//! `{"v":1,"started":true,"exit":0}` or `{"v":1,"started":false,"error":{...}}`.
//! `started` means the launcher reached `execve` for the command: a failure before or at
//! exec (changed program, sandbox error, "argument list too long") is `started:false`.
//! A command that was exec'd and then exits 1 or 127 is `started:true`.

use anyhow::{Result, bail};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::sync::Mutex;

#[derive(Default)]
struct State {
    /// Close-on-exec copy of the caller's descriptor.
    fd: Option<i32>,
    /// `run` / `aws PROFILE`: errors before the launch become exit-125 refusals.
    run: bool,
    /// The command's exit code, once karambit released the launch.
    exit: Option<i32>,
}

static STATE: Mutex<State> = Mutex::new(State { fd: None, run: false, exit: None });

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Take ownership of `fd` for the status line. Refuses stdin/stdout/stderr and closed fds.
pub fn claim(fd: i32) -> Result<()> {
    if fd < 3 { bail!("--status-fd must be 3 or higher (0-2 are shared with the command)"); }
    // SAFETY: plain fcntl/close on a caller-named descriptor number.
    let id = |n: i32| {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(n, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    };
    let Some(target) = id(fd) else { bail!("--status-fd {fd} is not an open file descriptor") };
    // The command inherits stdout and stderr: a status pipe shared with them is forgeable.
    if [1, 2].into_iter().any(|n| id(n) == Some(target)) {
        bail!("--status-fd {fd} is the same file as stdout/stderr, so the command could write it; use e.g. `3>&1 1>&2`");
    }
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if copy < 0 { bail!("--status-fd {fd} is not an open file descriptor"); }
    unsafe { libc::close(fd) };
    state().fd = Some(copy);
    Ok(())
}

/// This invocation launches a command (`run`, `aws PROFILE`).
pub fn enter_run() { state().run = true; }

/// Errors now are "before the command started": they exit 125.
pub fn before_launch() -> bool {
    let s = state();
    s.run && s.exit.is_none()
}

/// karambit released the launch and the command exited with `code`.
pub fn started(code: i32) { state().exit = Some(code); }

fn write(line: serde_json::Value) {
    let Some(fd) = state().fd.take() else { return };
    // SAFETY: `fd` came from F_DUPFD_CLOEXEC in `claim` and is owned only here.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let _ = writeln!(f, "{line}");
}

/// Success: the command ran (exit code known).
pub fn finish_ok() {
    let exit = state().exit;
    match exit {
        Some(code) => write(serde_json::json!({"v": 1, "started": true, "exit": code})),
        None => write(serde_json::json!({"v": 1, "started": false})),
    }
}

/// Failure: `error` is the refusal/error JSON object.
pub fn finish_err(error: serde_json::Value) {
    let started = state().exit.is_some();
    write(serde_json::json!({"v": 1, "started": started, "error": error}));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn status_line_goes_to_a_cloexec_copy() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        assert!(claim(1).is_err() && claim(-1).is_err());
        claim(w).unwrap();
        // The original number is closed; the copy is close-on-exec.
        assert!(unsafe { libc::fcntl(w, libc::F_GETFD) } < 0);
        let copy = state().fd.unwrap();
        assert_ne!(unsafe { libc::fcntl(copy, libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
        enter_run();
        assert!(before_launch());
        started(7);
        assert!(!before_launch());
        finish_ok();
        let mut out = String::new();
        unsafe { std::fs::File::from_raw_fd(r) }.read_to_string(&mut out).unwrap();
        assert_eq!(out, "{\"exit\":7,\"started\":true,\"v\":1}\n");
        *state() = State::default();
    }
}
