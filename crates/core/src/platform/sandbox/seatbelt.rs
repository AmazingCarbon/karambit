//! macOS Seatbelt SPI, also used by deprecated sandbox-exec. No subprocess wrapper:
//! the authenticated shim installs the policy before untrusted code executes.
use super::{Jail, Sandbox};
use anyhow::{Context, Result, bail};
use std::ffi::CString;

pub struct Seatbelt;
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, error: *mut *mut libc::c_char) -> libc::c_int;
    fn sandbox_free_error(error: *mut libc::c_char);
}

fn quoted(path: &std::path::Path) -> Result<String> {
    let text = path.to_str().context("sandbox path must be UTF-8")?;
    if text.chars().any(char::is_control) { bail!("invalid sandbox path"); }
    Ok(format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")))
}

fn profile(policy: &Jail) -> Result<CString> {
    // Empty mach-lookup allowlist deliberately denies LaunchServices, AppleEvents,
    // credential services and arbitrary out-of-sandbox service execution.
    let mut text = String::from("(version 1)\n(deny default)\n\
        (allow file-read* file-write* process-exec process-fork sysctl-read)\n\
        (allow process-info* (target self))\n\
        (allow signal (target same-sandbox))\n\
        (deny process-exec (literal \"/usr/bin/open\") (literal \"/usr/bin/osascript\"))\n");
    for path in &policy.denied_paths {
        text.push_str(&format!("(deny file-read* file-write* (subpath {}))\n", quoted(path)?));
    }
    for address in &policy.allowed {
        text.push_str(&format!("(allow network-outbound (remote tcp \"localhost:{}\"))\n", address.port()));
    }
    Ok(CString::new(text)?)
}

impl Sandbox for Seatbelt {
    fn available(&self) -> bool { true } // linked SPI; installation may still refuse
    fn apply(&self, policy: &Jail) -> Result<()> {
        let profile = profile(policy)?;
        let mut error = std::ptr::null_mut();
        let status = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
        if !error.is_null() { unsafe { sandbox_free_error(error); } }
        if status != 0 { bail!("Seatbelt policy installation failed; target not executed"); }
        Ok(())
    }
}
