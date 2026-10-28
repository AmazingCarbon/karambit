//! Opt-in child confinement. Configuration travels over the private shim channel,
//! never target argv/environment. This is not daemon policy or broker custody.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{net::{SocketAddr}, path::{Path, PathBuf}};

#[cfg(target_os = "macos")]
mod seatbelt;
#[cfg(target_os = "macos")]
pub use seatbelt::Seatbelt as NativeSandbox;
#[cfg(not(target_os = "macos"))]
mod unsupported;
#[cfg(not(target_os = "macos"))]
pub use unsupported::Unsupported as NativeSandbox;

pub trait Sandbox {
    fn available(&self) -> bool;
    /// Irreversibly confines this process and its descendants; errors must abort launch.
    fn apply(&self, policy: &Jail) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jail {
    denied_paths: Vec<PathBuf>,
    allowed: Vec<SocketAddr>,
}

impl Jail {
    pub fn new(home: &Path, vault: &Path, hosts: &[String]) -> Result<Self> {
        if !NativeSandbox.available() { bail!("child sandbox unavailable on this platform"); }
        let mut denied_paths = Vec::new();
        for path in [vault.to_path_buf(), home.join(".local/share/karambit"), home.join(".vault-token"),
            home.join(".aws"), home.join(".ssh"), home.join(".kube")] {
            denied_paths.push(resolve_path(&path)?);
        }
        let mut allowed = Vec::new();
        for host in hosts {
            let (name, port) = host.rsplit_once(':').context("allow-host requires host:port")?;
            if !matches!(name, "localhost" | "127.0.0.1" | "[::1]") {
                bail!("Seatbelt spike only permits localhost, 127.0.0.1 or [::1]:port; remote egress requires a loopback proxy");
            }
            let port: u16 = port.parse().context("allow-host requires a numeric port")?;
            if port == 0 { bail!("allow-host requires a nonzero port"); }
            // Seatbelt's localhost filter covers IPv4 AND IPv6 loopback.
            allowed.push(SocketAddr::from(([127, 0, 0, 1], port)));
        }
        allowed.sort(); allowed.dedup();
        Ok(Self { denied_paths, allowed })
    }

    /// The daemon-minted AWS endpoint is the only implicit network exception.
    pub(crate) fn allow_endpoint(&mut self, url: &str) -> Result<()> {
        let authority = url.strip_prefix("http://").context("invalid credential endpoint")?
            .split('/').next().context("invalid credential endpoint")?;
        let address: SocketAddr = authority.parse().context("invalid credential endpoint")?;
        if !address.ip().is_loopback() || address.port() == 0 { bail!("invalid credential endpoint"); }
        self.allowed.push(address);
        Ok(())
    }
}

// Resolve existing ancestors too: the protected file need not exist yet. Do not
// interpolate raw caller text into SBPL, or permit '..' to weaken a subpath rule.
fn resolve_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    let mut tail = Vec::new();
    let mut parent = absolute.as_path();
    while !parent.exists() {
        tail.push(parent.file_name().context("invalid protected path")?.to_owned());
        parent = parent.parent().context("invalid protected path")?;
    }
    let mut resolved = parent.canonicalize()?;
    for part in tail.into_iter().rev() { resolved.push(part); }
    Ok(resolved)
}
