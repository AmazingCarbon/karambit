//! Platform capability boundary. Unsupported targets never substitute weaker identity.
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod unsupported;
#[cfg(target_os = "macos")]
pub(crate) use macos::*;
#[cfg(not(target_os = "macos"))]
pub(crate) use unsupported::*;
/// Full kernel start identity; seconds-only ancestry is not a substitute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessIdentity { pub(crate) pid: i32, pub(crate) sec: u64, pub(crate) usec: u64 }

/// Swift bridge shared types; invocation is gated by the selected platform.
pub(crate) use crate::helper;

pub mod sandbox;

#[cfg(target_os = "macos")]
pub use macos::{key_probe_source, key_probe_compilers, sibling_environment};
#[cfg(not(target_os = "macos"))]
pub use unsupported::{key_probe_source, key_probe_compilers, sibling_environment};
