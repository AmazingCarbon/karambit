//! AWS credential profiles stored as one vault entry `aws/<profile>`, whose
//! encrypted value is JSON. Accepts whatever the AWS console / `aws configure
//! export-credentials` hands out: `export ...` (macOS/Linux), `set ...` (cmd),
//! `$Env:... = "..."` (PowerShell), or an INI `[profile]` block.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const NS: &str = "aws";

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AwsCreds {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Opt-in: the daemon swaps this long-term key for a one-hour STS session and
    /// serves only that to the child. Absent when off, so older builds still read it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub session_mint: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Lifetime asked of `sts:GetSessionToken` for `session_mint` profiles.
pub const MINT_SECONDS: u64 = 3600;
/// The endpoint ends this long before the minted session does.
const MINT_MARGIN: u64 = 60;

impl std::fmt::Debug for AwsCreds {
    // Never print credential values, even in debug output or panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCreds")
            .field("access_key_id", &"[redacted]")
            .field("secret_access_key", &"[redacted]")
            .field("session_token", &self.session_token.as_ref().map(|_| "[redacted]"))
            .field("region", &self.region)
            .field("session_mint", &self.session_mint)
            .finish()
    }
}

impl Drop for AwsCreds {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_access_key.zeroize();
        if let Some(t) = &mut self.session_token {
            t.zeroize();
        }
    }
}

pub fn entry_name(profile: &str) -> Result<String> {
    let ok = !profile.is_empty()
        && profile.len() <= 64
        && !profile.starts_with('.')
        && profile.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !ok {
        bail!("invalid profile name {profile:?}: use [A-Za-z0-9._-]");
    }
    Ok(format!("{NS}/{profile}"))
}

pub fn is_aws_entry(name: &str) -> bool {
    name.strip_prefix("aws/").is_some_and(|p| !p.contains('/'))
}

/// Which fields a pasted block has so far (for stop-when-complete input loops).
pub fn is_complete(text: &str) -> bool {
    match parse(text) {
        Ok(c) => c.session_token.is_some() || c.access_key_id.starts_with("AKIA"),
        Err(_) => false,
    }
}

pub fn parse(text: &str) -> Result<AwsCreds> {
    let mut c = AwsCreds::default();
    for raw in text.lines() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
            continue;
        }
        for p in ["export ", "set ", "SET ", "$Env:", "$env:", "$ENV:", "setx "] {
            if let Some(rest) = line.strip_prefix(p) {
                line = rest.trim_start();
            }
        }
        let Some((k, v)) = line.split_once('=').or_else(|| line.split_once(' ')) else { continue };
        let k = k.trim().to_ascii_uppercase();
        let v = v.trim().trim_end_matches(';').trim().trim_matches(|ch| ch == '"' || ch == '\'').to_string();
        if v.is_empty() {
            continue;
        }
        match k.as_str() {
            "AWS_ACCESS_KEY_ID" => c.access_key_id = v,
            "AWS_SECRET_ACCESS_KEY" => c.secret_access_key = v,
            "AWS_SESSION_TOKEN" | "AWS_SECURITY_TOKEN" => c.session_token = Some(v),
            "AWS_REGION" | "AWS_DEFAULT_REGION" | "REGION" => c.region = Some(v),
            _ => {}
        }
    }
    if c.access_key_id.is_empty() {
        bail!("no AWS_ACCESS_KEY_ID found in the pasted text");
    }
    if c.secret_access_key.is_empty() {
        bail!("no AWS_SECRET_ACCESS_KEY found in the pasted text");
    }
    let id = &c.access_key_id;
    if !(16..=128).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
        bail!("AWS_ACCESS_KEY_ID doesn't look like an access key (expected AKIA…/ASIA…)");
    }
    if id.starts_with("ASIA") && c.session_token.is_none() {
        bail!("ASIA… is a temporary key: paste AWS_SESSION_TOKEN too");
    }
    if let Some(r) = &c.region
        && !r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("region {r:?} doesn't look like an AWS region");
    }
    Ok(c)
}

impl AwsCreds {
    pub fn to_json(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        Ok(zeroize::Zeroizing::new(serde_json::to_vec(self)?))
    }

    pub fn from_json(b: &[u8]) -> Result<AwsCreds> {
        serde_json::from_slice(b).context("stored AWS profile is not valid JSON")
    }

    pub fn temporary(&self) -> bool {
        self.session_token.is_some()
    }

    /// Env vars to set in the child.
    pub fn env(&self) -> Vec<(&'static str, &str)> {
        let mut v = vec![
            ("AWS_ACCESS_KEY_ID", self.access_key_id.as_str()),
            ("AWS_SECRET_ACCESS_KEY", self.secret_access_key.as_str()),
        ];
        if let Some(t) = &self.session_token {
            v.push(("AWS_SESSION_TOKEN", t));
        }
        if let Some(r) = &self.region {
            v.push(("AWS_REGION", r));
            v.push(("AWS_DEFAULT_REGION", r));
        }
        v
    }

    /// Env vars to clear first so a stale token or a config profile can't mix in.
    pub fn env_clear() -> &'static [&'static str] {
        &["AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_CREDENTIAL_EXPIRATION"]
    }

    /// Values to redact from output (region is not secret).
    pub fn secret_parts(&self) -> Vec<(&'static str, &[u8])> {
        let mut v = vec![("access-key-id", self.access_key_id.as_bytes()), ("secret-access-key", self.secret_access_key.as_bytes())];
        if let Some(t) = &self.session_token {
            v.push(("session-token", t.as_bytes()));
        }
        v
    }

    /// Run `aws sts ARGS` with these creds handed over by environment only (no argv
    /// secrets, no files). Nothing is inherited: the daemon keeps the environment of
    /// whichever process started it, and a profile, config file, endpoint override,
    /// CA bundle or credential helper from there must not reach the key. HOME is an
    /// empty scratch directory so the CLI finds no `~/.aws`.
    fn run_sts(&self, aws: &Path, args: &[&str]) -> Result<Vec<u8>> {
        let home = ScratchHome::new()?;
        let mut cmd = Command::new(aws);
        cmd.arg("sts").args(args).args(["--output", "json"]);
        cmd.env_clear().env("PATH", "/usr/bin:/bin").env("HOME", &home.0);
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        if self.region.is_none() {
            cmd.env("AWS_REGION", "us-east-1");
        }
        cmd.env("AWS_CONFIG_FILE", "/dev/null").env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null").env("AWS_EC2_METADATA_DISABLED", "true");
        cmd.env("AWS_PAGER", "").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let out = output_within(cmd, STS_TIMEOUT).context("run aws sts")?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let msg = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("unknown error").trim();
            return Err(anyhow!("{msg}"));
        }
        Ok(out.stdout)
    }

    /// `aws sts get-caller-identity` with these creds -> "account · arn".
    /// Returns Ok(None) if the aws CLI isn't installed.
    pub fn verify(&self) -> Result<Option<String>> {
        let Some(aws) = find_aws() else { return Ok(None) };
        let stdout = self.run_sts(&aws, &["get-caller-identity"]).map_err(|e| anyhow!("AWS rejected these credentials: {e}"))?;
        let v: serde_json::Value = serde_json::from_slice(&stdout).context("parse sts output")?;
        let acct = v["Account"].as_str().unwrap_or("?");
        let arn = v["Arn"].as_str().unwrap_or("?");
        Ok(Some(format!("{acct} · {arn}")))
    }

    /// What a run's credential endpoint may serve for this static profile, and for how
    /// long (seconds). Normally the key itself. With `session_mint` the daemon swaps the
    /// long-term key for a one-hour STS session, so the child never holds the key. If
    /// the exchange fails the run is refused: the key is never served as a fallback.
    pub fn endpoint_credentials(self) -> Result<EndpointCredentials> {
        if !self.session_mint {
            return Ok(EndpointCredentials { creds: self, ttl: STATIC_ENDPOINT_SECONDS, minted: false });
        }
        let creds = mint_session(&self).context("session_mint: could not exchange the key for an STS session; launch refused")?;
        Ok(EndpointCredentials { creds, ttl: MINT_SECONDS - MINT_MARGIN, minted: true })
    }
}

/// Endpoint lifetime for a pasted key that is served as is.
pub const STATIC_ENDPOINT_SECONDS: u64 = 4 * 3600;

pub struct EndpointCredentials {
    pub creds: AwsCreds,
    pub ttl: u64,
    pub minted: bool,
}

/// `session_mint` needs a long-term key: AWS refuses GetSessionToken from temporary credentials.
pub fn require_mintable(c: &AwsCreds) -> Result<()> {
    if c.session_token.is_some() {
        bail!("session_mint needs a long-term key (AKIA…); this one is temporary (it has a session token)");
    }
    Ok(())
}

/// Is this stored `aws/<profile>` value a long-term key whose `session_mint` is on?
/// Such a key must never reach a program (or an agent) as a plain value.
pub fn session_mint_enabled(value: &[u8]) -> bool {
    AwsCreds::from_json(value).is_ok_and(|c| c.session_mint)
}

/// `AKIA…1234`: enough to tell keys apart, not enough to use one. Idempotent, so a value
/// the daemon already masked (see `describe_only`) passes through unchanged.
pub fn mask_key_id(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 8 || id.contains('…') {
        return id.to_owned();
    }
    format!("{}…{}", chars[..4].iter().collect::<String>(), chars[chars.len() - 4..].iter().collect::<String>())
}

/// What `aws show` prints about a stored profile and nothing more: masked key id,
/// region, key type, `session_mint`. The daemon returns this instead of the stored value
/// when an agent asks to describe a `session_mint` profile, so the long-lived key never
/// leaves it (the secret and token are blanked; a token's presence is kept for `temporary`).
pub fn describe_only(value: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let c = AwsCreds::from_json(value)?;
    AwsCreds {
        access_key_id: mask_key_id(&c.access_key_id), secret_access_key: String::new(),
        session_token: c.session_token.as_ref().map(|_| String::new()), region: c.region.clone(), session_mint: c.session_mint,
    }.to_json()
}

/// `sts:GetSessionToken` for a long-term key. Only IAM-user (or root) keys can call it;
/// temporary credentials cannot, so a profile that holds a session token is refused.
fn mint_session(src: &AwsCreds) -> Result<AwsCreds> {
    require_mintable(src)?;
    // Unit tests never reach AWS: the real exchange is covered with a fake `aws` binary.
    #[cfg(test)]
    return mint_test_double(src);
    #[cfg(not(test))]
    mint_via(&find_aws().context("the aws CLI is required for session_mint but none was found at /opt/homebrew/bin, /usr/local/bin or /usr/bin (owned by you or root, not group/world-writable)")?, src)
}

/// The exchange itself, against a given `aws` executable.
fn mint_via(aws: &Path, src: &AwsCreds) -> Result<AwsCreds> {
    let duration = MINT_SECONDS.to_string();
    let stdout = src.run_sts(aws, &["get-session-token", "--duration-seconds", &duration])?;
    let v: serde_json::Value = serde_json::from_slice(&stdout).context("parse sts output")?;
    let c = &v["Credentials"];
    let field = |k: &str| c[k].as_str().filter(|s| !s.is_empty()).map(String::from).with_context(|| format!("STS reply has no {k}"));
    Ok(AwsCreds { access_key_id: field("AccessKeyId")?, secret_access_key: field("SecretAccessKey")?,
        session_token: Some(field("SessionToken")?), region: src.region.clone(), session_mint: false })
}

/// Stand-in for the STS exchange in daemon tests.
#[cfg(test)]
pub(crate) fn mint_test_double(src: &AwsCreds) -> Result<AwsCreds> {
    if src.access_key_id.starts_with("AKIAFAILMINT") {
        bail!("fake STS refused the key");
    }
    Ok(AwsCreds { access_key_id: "ASIAMINTEDSESSION".into(), secret_access_key: "minted-secret-canary".into(),
        session_token: Some("minted-token-canary".into()), region: src.region.clone(), session_mint: false })
}

const STS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `Command::output` that kills the child at `limit`: the daemon calls this while a
/// launch is waiting, so a hung `aws` must not hang the launch forever.
fn output_within(mut cmd: Command, limit: std::time::Duration) -> Result<std::process::Output> {
    let mut child = cmd.spawn()?;
    let end = std::time::Instant::now() + limit;
    while child.try_wait()?.is_none() {
        if std::time::Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out after {}s", limit.as_secs());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(child.wait_with_output()?)
}

/// Empty private HOME for one `aws` run; removed afterwards.
struct ScratchHome(PathBuf);

impl ScratchHome {
    fn new() -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("karambit-aws-home-{:016x}", rand::random::<u64>()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).context("create scratch HOME for aws")?;
        Ok(Self(dir))
    }
}

impl Drop for ScratchHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The only places the aws CLI is looked up, never the inherited PATH: a planted `aws`
/// earlier on the PATH of whoever started the daemon would be handed the long-lived key
/// (`session_mint`, `verify`).
const AWS_CLI_LOCATIONS: [&str; 3] = ["/opt/homebrew/bin/aws", "/usr/local/bin/aws", "/usr/bin/aws"];

fn find_aws() -> Option<PathBuf> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    AWS_CLI_LOCATIONS.iter().find_map(|path| trusted_cli(Path::new(path), euid))
}

/// The canonical path of `path` if its target is an executable regular file owned by root
/// or `euid` that group and other cannot write. Symlinks (Homebrew) are resolved first, so
/// the target is what gets checked and what gets run.
fn trusted_cli(path: &Path, euid: u32) -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let real = std::fs::canonicalize(path).ok()?;
    let meta = std::fs::metadata(&real).ok()?;
    let mode = meta.permissions().mode();
    (meta.is_file() && mode & 0o100 != 0 && mode & 0o022 == 0 && (meta.uid() == 0 || meta.uid() == euid)).then_some(real)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_term(mint: bool) -> AwsCreds {
        AwsCreds { access_key_id: "AKIASYNTHETICKEY001".into(), secret_access_key: "long-term-secret-canary".into(), session_token: None, region: None, session_mint: mint }
    }

    #[test]
    fn session_mint_is_optional_in_the_stored_json() {
        // Off: the field is absent, so older builds read the entry unchanged.
        let off = String::from_utf8(long_term(false).to_json().unwrap().to_vec()).unwrap();
        assert!(!off.contains("session_mint"), "{off}");
        // An entry written by an older build has no field and means off.
        let old = AwsCreds::from_json(br#"{"access_key_id":"AKIASYNTHETICKEY001","secret_access_key":"x"}"#).unwrap();
        assert!(!old.session_mint);
        let on = long_term(true).to_json().unwrap();
        assert!(AwsCreds::from_json(&on).unwrap().session_mint);
        assert!(session_mint_enabled(&on) && !session_mint_enabled(off.as_bytes()));
    }

    #[test]
    fn session_mint_refuses_temporary_credentials() {
        let mut temp = long_term(true);
        temp.session_token = Some("tok".into());
        assert!(require_mintable(&temp).is_err());
        assert!(temp.endpoint_credentials().is_err(), "a temporary key can't be exchanged and is never served instead");
    }

    #[test]
    fn endpoint_credentials_pass_the_key_through_when_mint_is_off() {
        let served = long_term(false).endpoint_credentials().unwrap();
        assert!(!served.minted);
        assert_eq!(served.creds.secret_access_key, "long-term-secret-canary");
        assert_eq!(served.ttl, STATIC_ENDPOINT_SECONDS);
    }

    #[test]
    fn endpoint_credentials_swap_the_key_for_the_minted_session() {
        let served = long_term(true).endpoint_credentials().unwrap();
        assert!(served.minted);
        assert_eq!(served.creds.access_key_id, "ASIAMINTEDSESSION");
        assert!(served.creds.session_token.is_some());
        assert_eq!(served.ttl, MINT_SECONDS - 60, "endpoint ends before the 1 h session");
        let mut failing = long_term(true);
        failing.access_key_id = "AKIAFAILMINT000001".into();
        assert!(failing.endpoint_credentials().is_err(), "no fallback to the key");
    }

    /// The real exchange against a fake `aws` executable: the key goes by environment
    /// only, never argv, and the reply is parsed into a session credential.
    #[test]
    fn mint_via_hands_the_key_over_by_environment_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("karambit-mint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("seen");
        let fake = dir.join("aws");
        std::fs::write(&fake, format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" \"$AWS_ACCESS_KEY_ID\" \"$AWS_SECRET_ACCESS_KEY\" \"[$AWS_PROFILE]\" \"$AWS_CONFIG_FILE\" > {}\n\
             echo '{{\"Credentials\":{{\"AccessKeyId\":\"ASIAFAKE\",\"SecretAccessKey\":\"fake-secret\",\"SessionToken\":\"fake-token\",\"Expiration\":\"x\"}}}}'\n",
            log.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
        let minted = mint_via(&fake, &long_term(true)).unwrap();
        assert_eq!((minted.access_key_id.as_str(), minted.session_token.as_deref()), ("ASIAFAKE", Some("fake-token")));
        assert!(!minted.session_mint);
        let seen = std::fs::read_to_string(&log).unwrap();
        let mut lines = seen.lines();
        let argv = lines.next().unwrap();
        assert_eq!(argv, "sts get-session-token --duration-seconds 3600 --output json");
        assert!(!argv.contains("canary") && !argv.contains("AKIA"), "no secret in argv");
        assert_eq!(lines.next(), Some("AKIASYNTHETICKEY001"));
        assert_eq!(lines.next(), Some("long-term-secret-canary"));
        assert_eq!(lines.next(), Some("[]"), "ambient profile dropped");
        assert_eq!(lines.next(), Some("/dev/null"), "no ambient config file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The daemon inherits the environment of whoever started it. None of that may reach
    /// the `aws` child that holds the long-lived key; HOME is an empty scratch directory
    /// that is gone afterwards.
    #[test]
    fn sts_child_gets_a_cleared_environment_and_an_empty_home() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("karambit-mint-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (log, fake) = (dir.join("seen"), dir.join("aws"));
        std::fs::write(&fake, format!(
            "#!/bin/sh\n/usr/bin/env > {}\nls -A \"$HOME\" | wc -l >> {}\n\
             echo '{{\"Credentials\":{{\"AccessKeyId\":\"ASIAFAKE\",\"SecretAccessKey\":\"s\",\"SessionToken\":\"t\",\"Expiration\":\"x\"}}}}'\n",
            log.display(), log.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Only these tests read these names, so setting them cannot disturb other tests.
        let leaks = [("KARAMBIT_TEST_LEAK_CANARY", "x"), ("AWS_CA_BUNDLE", "/tmp/evil.pem"), ("AWS_ENDPOINT_URL", "http://127.0.0.1:1"),
            ("AWS_WEB_IDENTITY_TOKEN_FILE", "/tmp/evil"), ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1:1/x"), ("AWS_PROFILE", "evil")];
        for (k, v) in leaks { unsafe { std::env::set_var(k, v) }; }
        mint_via(&fake, &long_term(true)).unwrap();
        for (k, _) in leaks { unsafe { std::env::remove_var(k) }; }
        let seen = std::fs::read_to_string(&log).unwrap();
        let names: Vec<&str> = seen.lines().filter_map(|l| l.split_once('=').map(|(k, _)| k)).collect();
        for (k, _) in leaks { assert!(!names.contains(&k), "{k} leaked into the aws child:\n{seen}"); }
        assert!(seen.lines().any(|l| l == "PATH=/usr/bin:/bin"), "{seen}");
        let home = seen.lines().find_map(|l| l.strip_prefix("HOME=")).unwrap();
        assert!(home.contains("karambit-aws-home-") && !Path::new(home).exists(), "scratch HOME must be removed: {home}");
        assert_eq!(seen.lines().last().map(str::trim), Some("0"), "HOME was not empty:\n{seen}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An `aws` planted earlier on the PATH of whoever started the daemon must never
    /// be chosen; only the fixed locations count.
    #[test]
    fn find_aws_ignores_a_planted_aws_on_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("karambit-planted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let planted = dir.join("aws");
        std::fs::write(&planted, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();
        let old = std::env::var_os("PATH").unwrap_or_default();
        let mut path = std::ffi::OsString::from(dir.as_os_str());
        path.push(":");
        path.push(&old);
        unsafe { std::env::set_var("PATH", &path) };
        let found = find_aws();
        unsafe { std::env::set_var("PATH", &old) };
        let canon_dir = std::fs::canonicalize(&dir).unwrap();
        assert!(found.as_ref().is_none_or(|f| !f.starts_with(&canon_dir) && !f.starts_with(&dir)), "picked the planted aws: {found:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn trusted_cli_requires_a_regular_executable_that_only_root_or_me_can_write() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = std::env::temp_dir().join(format!("karambit-trusted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let euid = unsafe { libc::geteuid() };
        let make = |name: &str, mode: u32| {
            let f = dir.join(name);
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            f
        };
        let good = make("good", 0o755);
        assert_eq!(trusted_cli(&good, euid), Some(std::fs::canonicalize(&good).unwrap()));
        assert!(trusted_cli(&make("group-writable", 0o775), euid).is_none());
        assert!(trusted_cli(&make("world-writable", 0o757), euid).is_none());
        assert!(trusted_cli(&make("not-executable", 0o644), euid).is_none());
        assert!(trusted_cli(&good, euid.wrapping_add(1)).is_none(), "owned by someone who is neither root nor the caller");
        assert!(trusted_cli(&dir, euid).is_none(), "a directory is not a CLI");
        assert!(trusted_cli(&dir.join("absent"), euid).is_none());
        // Homebrew-style symlink: the target is what is checked and returned.
        symlink(&good, dir.join("link-good")).unwrap();
        assert_eq!(trusted_cli(&dir.join("link-good"), euid), Some(std::fs::canonicalize(&good).unwrap()));
        symlink(dir.join("group-writable"), dir.join("link-bad")).unwrap();
        assert!(trusted_cli(&dir.join("link-bad"), euid).is_none(), "symlink to a writable target");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn describe_only_drops_the_secret_and_masks_the_key_id() {
        let described = describe_only(&long_term(true).to_json().unwrap()).unwrap();
        let text = String::from_utf8(described.to_vec()).unwrap();
        assert!(!text.contains("long-term-secret-canary") && !text.contains("AKIASYNTHETICKEY001"), "{text}");
        let c = AwsCreds::from_json(&described).unwrap();
        assert_eq!((c.access_key_id.as_str(), c.secret_access_key.as_str(), c.session_mint), ("AKIA…Y001", "", true));
        assert_eq!(mask_key_id("AKIA…Y001"), "AKIA…Y001", "masking is idempotent");
    }

    #[test]
    fn mint_via_reports_a_denied_exchange_without_the_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("karambit-mint-deny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("aws");
        std::fs::write(&fake, "#!/bin/sh\necho 'AccessDenied: not authorized to perform sts:GetSessionToken' >&2\nexit 254\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
        let err = format!("{:#}", mint_via(&fake, &long_term(true)).unwrap_err());
        assert!(err.contains("AccessDenied") && !err.contains("canary"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
