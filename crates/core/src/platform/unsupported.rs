//! Refusing capability stubs; Linux/Windows ports are not implemented.
use anyhow::{Result, bail};
use std::os::unix::net::UnixStream;
use super::ProcessIdentity;
pub(crate) mod process {
    pub struct Proc {
        pub ppid: i32,
        pub display: String,
        pub candidates: Vec<String>,
        pub comm: String,
        pub exe_name: String,
        pub app_bundle: bool,
        pub start: u64,
    }
    pub fn session_label(_pid: i32, _kind: Option<&str>) -> Option<String> { None }
    pub fn env_names(_pid: i32) -> Option<Vec<String>> { None }
    pub fn info(_pid: i32) -> Option<Proc> {
        None
    }
    pub fn cwd(_pid: i32) -> Option<String> {
        None
    }
    pub fn exe(_pid: i32) -> Option<String> {
        None
    }
}

pub(crate) fn process_identity(_: i32) -> Result<ProcessIdentity> { bail!("process identity unavailable on this platform") }
pub(crate) fn process_parent_identity(_: ProcessIdentity) -> Result<ProcessIdentity> { bail!("process identity unavailable on this platform") }
pub(crate) fn peer_token_of(_: &UnixStream, _: libc::uid_t) -> Result<(i32,u32)> { bail!("caller identity unavailable on this platform") }
pub(crate) fn live_pidversion(_: i32) -> Result<u32> { bail!("caller identity unavailable on this platform") }
pub(crate) fn bound_peer_pid(_: &UnixStream, _: i32) -> Result<i32> { bail!("caller identity unavailable on this platform") }
pub(crate) fn peer_pid(_: std::os::fd::RawFd) -> Result<i32> { bail!("caller identity unavailable on this platform") }
pub(crate) fn fd_buffer() -> Result<Vec<()>> { bail!("descriptor sweep unavailable on this platform") }
pub(crate) unsafe fn cloexec_open_fds(_: &mut [()], _: i32) -> std::io::Result<()> { Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "descriptor sweep unavailable on this platform")) }
pub(crate) fn connect_cleanup(_: &std::path::Path) -> std::io::Result<UnixStream> { Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "local service unavailable on this platform")) }
#[cfg(not(test))]
pub(crate) fn spawn_daemon(_: &crate::Paths) -> Result<()> { bail!("local service unavailable on this platform") }
pub(crate) unsafe fn forward_signal(_: i32, _: i32) { std::process::abort(); }
pub(crate) fn require_helper() -> Result<()> { bail!("secure helper unavailable on this platform") }

pub const fn key_probe_source() -> &'static str { "" }
pub fn key_probe_compilers() -> Vec<(std::path::PathBuf, Vec<std::ffi::OsString>)> { vec![] }
pub fn sibling_environment(_: &std::path::Path, _: &str) -> std::io::Result<std::process::Output> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "process inspection unavailable on this platform"))
}
