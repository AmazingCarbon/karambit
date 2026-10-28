//! AWS IAM Identity Center (SSO) for agent runs.
//!
//! - `karambit aws sso login` (human, one Touch ID) runs the OIDC device-code flow and
//!   hands the token to the daemon. The token lives only in daemon RAM: never on disk,
//!   never in ~/.aws, never in a child's environment.
//! - An SSO profile is a normal vault entry `aws/<name>` whose value is
//!   `{"sso": {start_url, sso_region, account_id, role_name, region?}}`, with the usual
//!   access levels (Agents / Agents + Touch ID / Only me + Touch ID).
//! - Which profiles exist is told to the daemon by a human (at login, or on add /
//!   policy change). Vault files are writable by any same-user process, so the daemon
//!   never trusts a profile it only read from disk.
//! - Child processes get short-lived role credentials from the daemon's per-run
//!   loopback endpoint; the daemon refreshes the SSO token and role credentials as
//!   they expire, so long agent runs keep working for the whole SSO session.
//!
//! HTTP goes through /usr/bin/curl (SIP-protected, macOS trust store, honours proxy
//! env). Every request is passed as a curl config on stdin, so tokens never appear in
//! argv. These AWS calls are unsigned (no SigV4), per the service models.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

use crate::aws::AwsCreds;
use crate::store::{Tier, now};

const CURL: &str = "/usr/bin/curl";
const SCOPE: &str = "sso:account:access";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

// ---------------------------------------------------------------- profile

/// The non-secret description of one account + role. Stored encrypted anyway, so
/// its access level is enforced like any other secret. `portal` names an entry in
/// config `sso_portals`; the URL and region are copied in at save time so a later
/// config edit can't silently re-point this profile at a different portal.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SsoProfile {
    #[serde(default)]
    pub portal: String,
    pub start_url: String,
    pub sso_region: String,
    pub account_id: String,
    pub role_name: String,
    /// Region for the child process (defaults to the SSO region).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl SsoProfile {
    pub fn validate(&self) -> Result<()> {
        validate_portal_name(&self.portal)?;
        validate_start_url(&self.start_url)?;
        validate_region(&self.sso_region)?;
        if let Some(r) = &self.region {
            validate_region(r)?;
        }
        validate_account(&self.account_id)?;
        validate_role(&self.role_name)
    }
    /// Region the child process should use.
    pub fn child_region(&self) -> &str {
        self.region.as_deref().unwrap_or(&self.sso_region)
    }
}

pub fn validate_account(account: &str) -> Result<()> {
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) { bail!("account id must be 12 digits"); }
    Ok(())
}

pub fn validate_role(r: &str) -> Result<()> {
        if r.is_empty() || r.len() > 64 || !r.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b)) {
            bail!("role name {r:?} doesn't look like an IAM Identity Center permission set name");
        }
        Ok(())
}
pub fn validate_start_url(u: &str) -> Result<()> {
    if !u.starts_with("https://") || u.len() > 512 || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("start URL must be an https:// URL (your AWS access portal, e.g. https://<org>.awsapps.com/start)");
    }
    Ok(())
}

/// Portal names are short labels you choose, e.g. `main`, `client-a`.
pub fn validate_portal_name(n: &str) -> Result<()> {
    if n.is_empty() || n.len() > 32 || n.starts_with('-') || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) {
        bail!("portal name {n:?}: use a short label like main or client-a ([A-Za-z0-9_-])");
    }
    Ok(())
}

pub fn validate_region(r: &str) -> Result<()> {
    if r.is_empty() || r.len() > 32 || !r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        bail!("region {r:?} doesn't look like an AWS region (e.g. us-west-2)");
    }
    Ok(())
}

/// What an `aws/<name>` vault entry holds.
pub enum AwsEntry {
    Static(AwsCreds),
    Sso(SsoProfile),
}

pub fn parse_entry(b: &[u8]) -> Result<AwsEntry> {
    let v: Value = serde_json::from_slice(b).context("stored AWS profile is not valid JSON")?;
    match v.get("sso") {
        Some(s) => Ok(AwsEntry::Sso(serde_json::from_value(s.clone()).context("bad SSO profile")?)),
        None => Ok(AwsEntry::Static(serde_json::from_value(v).context("bad AWS profile")?)),
    }
}

pub fn entry_json(p: &SsoProfile) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(serde_json::to_vec(&json!({ "sso": p }))?))
}

/// One profile as registered with the daemon by a human. `dek_sha256` is set for
/// Touch ID profiles: using them needs the DEK (Touch ID or a lease).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SsoReg {
    pub name: String,
    pub profile: SsoProfile,
    pub tier: Tier,
    pub agent_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dek_sha256: Option<String>,
}

pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------- session

/// SSO sign-in state for one portal. Sent once from the human CLI to the daemon,
/// then kept in RAM, keyed by `portal`.
#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    #[serde(default)]
    pub portal: String,
    pub start_url: String,
    pub region: String,
    pub client_id: String,
    pub client_secret: String,
    pub client_expires_at: u64,
    pub access_token: String,
    #[serde(default)]
    pub access_issued_at: u64,
    pub access_expires_at: u64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// When the daemon accepted this sign-in, and when it signs the portal out by
    /// itself (the portal's sign-in limit, if any). Set by the daemon, never trusted
    /// from the caller.
    #[serde(default)]
    pub signed_in_at: u64,
    #[serde(default)]
    pub renew_until: Option<u64>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("portal", &self.portal)
            .field("start_url", &self.start_url)
            .field("region", &self.region)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh", &self.refresh_token.is_some())
            .field("signed_in_at", &self.signed_in_at)
            .field("renew_until", &self.renew_until)
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_secret.zeroize();
        self.access_token.zeroize();
        if let Some(t) = &mut self.refresh_token {
            t.zeroize();
        }
    }
}

impl Session {
    /// Does this signed-in portal serve this profile? Name, URL and region must all
    /// match, so a renamed or edited config entry can't redirect a profile to another org.
    pub fn serves(&self, p: &SsoProfile) -> bool {
        self.portal == p.portal && self.start_url == p.start_url && self.region == p.sso_region
    }

    /// Renew the access token with the refresh token, in place. Fails with
    /// [`SessionEnded`] when only a new sign-in can help (AWS refused the refresh
    /// token, or there is none). Network trouble, throttling and AWS server errors fail
    /// with a plain error, so the caller keeps the sign-in and retries later.
    pub fn refresh(&mut self) -> Result<()> {
        let Some(rt) = self.refresh_token.clone().map(Zeroizing::new) else {
            bail!(self.ended("it can't be renewed"));
        };
        if self.client_expires_at <= now() {
            bail!(self.ended("Karambit's AWS client registration expired"));
        }
        let body = Zeroizing::new(
            json!({"clientId": self.client_id, "clientSecret": self.client_secret, "grantType": "refresh_token", "refreshToken": *rt})
                .to_string(),
        );
        let r = http("POST", &format!("{}/token", oidc_base(&self.region)), &[], Some(&body))?;
        if r.status != 200 {
            let err = oidc_error(&r.body);
            if refusal_is_final(r.status, &r.body) {
                bail!(self.ended(&format!("AWS refused to renew it: {err}")));
            }
            bail!("AWS SSO couldn't renew portal {} right now (HTTP {}: {err}); Karambit retries shortly", self.portal, r.status);
        }
        self.apply_token(&r.body)
    }

    /// The error for "this sign-in is over", with the reason.
    pub fn ended(&self, why: &str) -> SessionEnded {
        SessionEnded { portal: self.portal.clone(), why: why.to_string(), limit: false }
    }

    /// Past the portal's sign-in limit?
    pub fn limit_passed(&self) -> bool {
        self.renew_until.is_some_and(|t| t <= now())
    }

    /// [`SessionEnded`] if the portal's sign-in limit has passed.
    pub fn limit_reached(&self) -> Option<SessionEnded> {
        let until = self.renew_until.filter(|_| self.limit_passed())?;
        let mins = (until.saturating_sub(self.signed_in_at) / 60) as u32;
        Some(SessionEnded { portal: self.portal.clone(), why: format!("its sign-in limit of {} was reached", limit_label(mins)), limit: true })
    }

    /// Copy renewed tokens from `other`, a refreshed copy of this same sign-in. Only
    /// the tokens: a limit tightened while that copy was renewing stays.
    pub fn update_tokens(&mut self, other: &Session) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.access_token = other.access_token.clone();
        self.access_issued_at = other.access_issued_at;
        self.access_expires_at = other.access_expires_at;
        if let Some(t) = &mut self.refresh_token {
            t.zeroize();
        }
        self.refresh_token = other.refresh_token.clone();
    }

    fn apply_token(&mut self, v: &Value) -> Result<()> {
        self.access_token = v["accessToken"].as_str().context("no accessToken")?.to_string();
        self.access_issued_at = now();
        self.access_expires_at = now() + v["expiresIn"].as_u64().unwrap_or(3600);
        if let Some(rt) = v["refreshToken"].as_str() {
            self.refresh_token = Some(rt.to_string());
        }
        Ok(())
    }
}

/// UI hooks for a device-code sign-in: the CLI prints, the GUI shows a dialog.
pub struct SignInUi<'a> {
    /// Show the user code and the browser URL that approves it, plus seconds until
    /// the code expires. The code isn't secret: it's meant to be read on screen.
    pub show: &'a dyn Fn(&str, &str, u64),
    /// Polled about every 250 ms while waiting for browser approval.
    pub cancelled: &'a dyn Fn() -> bool,
    /// Called once, right after browser approval. Returning false aborts with
    /// [`Cancelled`]. Once it returns true the sign-in can no longer be cancelled from
    /// the UI (the Touch ID prompts that follow have their own Cancel), so a UI never
    /// reports "cancelled" for a sign-in that then goes on to activate.
    pub commit: &'a dyn Fn() -> bool,
}

/// A portal's sign-in is over: AWS refused to renew it, rejected the renewed token,
/// or the portal's sign-in limit passed. Only signing in again helps, so the daemon
/// signs the portal out when it sees this.
#[derive(Debug)]
pub struct SessionEnded {
    pub portal: String,
    pub why: String,
    /// Ended by the portal's sign-in limit (not by AWS).
    pub limit: bool,
}
impl std::fmt::Display for SessionEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AWS SSO sign-in for portal {} has ended ({}): sign in again from the Karambit app, or run `karambit aws sso login {}`",
            self.portal, self.why, self.portal
        )
    }
}
impl std::error::Error for SessionEnded {}

/// Sign-in limits run from 15 minutes to 90 days: IAM Identity Center's own range
/// for its session duration, also in minutes.
pub const LIMIT_MINUTES: std::ops::RangeInclusive<u32> = 15..=129_600;

pub fn validate_limit_minutes(m: u32) -> Result<()> {
    if !LIMIT_MINUTES.contains(&m) {
        bail!("sign-in limit must be 15 minutes to 90 days, or none");
    }
    Ok(())
}

/// A limit in seconds. Out-of-range values (a hand-edited config) round toward
/// shorter or the nearest allowed value, never to "no limit".
pub fn limit_secs(m: u32) -> u64 {
    u64::from(m.clamp(*LIMIT_MINUTES.start(), *LIMIT_MINUTES.end())) * 60
}

/// "30 minutes", "1 hour", "1 h 30 min", "8 hours", "3 days".
pub fn limit_label(m: u32) -> String {
    let plural = |n: u32, one: &str| format!("{n} {one}{}", if n == 1 { "" } else { "s" });
    match m {
        _ if m >= 1440 && m.is_multiple_of(1440) => plural(m / 1440, "day"),
        _ if m >= 60 && m.is_multiple_of(60) => plural(m / 60, "hour"),
        _ if m < 60 => plural(m, "minute"),
        _ => format!("{} h {} min", m / 60, m % 60),
    }
}

/// "for up to 8 hours" / "as long as AWS allows".
pub fn limit_words(m: Option<u32>) -> String {
    match m {
        Some(m) => format!("for up to {}", limit_label(m)),
        None => "as long as AWS allows".into(),
    }
}

/// Parse a limit: `90m`, `8h`, `1.5h`, `2d`, a bare number of hours, or `none`.
pub fn parse_limit(s: &str) -> Result<Option<u32>> {
    let s = s.trim().to_ascii_lowercase();
    if matches!(s.as_str(), "none" | "off" | "no") {
        return Ok(None);
    }
    let (num, mult) = if let Some(n) = s.strip_suffix("min").or(s.strip_suffix('m')) {
        (n, 1.0)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 60.0)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 1440.0)
    } else {
        (s.as_str(), 60.0)
    };
    let v: f64 = num.trim().parse().map_err(|_| anyhow!("sign-in limit {s:?}: use e.g. 90m, 8h, 2d or none"))?;
    let m = (v * mult).round();
    if !m.is_finite() || m < 0.0 || m > f64::from(u32::MAX) {
        bail!("sign-in limit must be 15 minutes to 90 days, or none");
    }
    validate_limit_minutes(m as u32)?;
    Ok(Some(m as u32))
}

/// The user cancelled a sign-in before approving it.
#[derive(Debug)]
pub struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AWS SSO sign-in cancelled")
    }
}
impl std::error::Error for Cancelled {}

/// Sleep `secs` (the AWS poll interval), checking for cancel every 250 ms.
fn wait(secs: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if cancelled() {
            bail!(Cancelled);
        }
        let left = end.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        std::thread::sleep(left.min(std::time::Duration::from_millis(250)));
    }
}

/// Device-code sign-in: register a client, show the user a code, poll until they
/// approve in the browser. `ui.show` gets (user_code, verification URL with code,
/// seconds until it expires).
pub fn login(portal: &str, start_url: &str, region: &str, ui: &SignInUi) -> Result<Session> {
    validate_portal_name(portal)?;
    validate_start_url(start_url)?;
    validate_region(region)?;
    let base = oidc_base(region);
    let reg = http(
        "POST",
        &format!("{base}/client/register"),
        &[],
        Some(&json!({"clientName": "karambit", "clientType": "public", "scopes": [SCOPE]}).to_string()),
    )?;
    if reg.status != 200 {
        bail!("AWS SSO client registration failed in {region}: {} (is {region} your Identity Center region?)", oidc_error(&reg.body));
    }
    let client_id = reg.body["clientId"].as_str().context("no clientId")?.to_string();
    let client_secret = Zeroizing::new(reg.body["clientSecret"].as_str().context("no clientSecret")?.to_string());
    let client_expires_at = reg.body["clientSecretExpiresAt"].as_u64().unwrap_or(now() + 86400);

    let dev = http(
        "POST",
        &format!("{base}/device_authorization"),
        &[],
        Some(&Zeroizing::new(json!({"clientId": client_id, "clientSecret": *client_secret, "startUrl": start_url}).to_string())),
    )?;
    if dev.status != 200 {
        bail!("AWS SSO sign-in could not start: {} (check the start URL and region)", oidc_error(&dev.body));
    }
    let device_code = Zeroizing::new(dev.body["deviceCode"].as_str().context("no deviceCode")?.to_string());
    let user_code = dev.body["userCode"].as_str().unwrap_or("?").to_string();
    let url = dev.body["verificationUriComplete"].as_str().or(dev.body["verificationUri"].as_str()).unwrap_or("").to_string();
    let mut interval = dev.body["interval"].as_u64().unwrap_or(5).max(1);
    let expires_in = dev.body["expiresIn"].as_u64().unwrap_or(600);
    let deadline = now() + expires_in;
    if (ui.cancelled)() {
        bail!(Cancelled);
    }
    (ui.show)(&user_code, &url, expires_in);

    let body = Zeroizing::new(
        json!({"clientId": client_id, "clientSecret": *client_secret, "grantType": DEVICE_GRANT, "deviceCode": *device_code}).to_string(),
    );
    loop {
        if now() > deadline {
            bail!("AWS SSO sign-in timed out (code not approved in time)");
        }
        wait(interval, ui.cancelled)?;
        let r = http("POST", &format!("{base}/token"), &[], Some(&body))?;
        if r.status == 200 {
            // Atomic hand-off: either the UI cancelled first, or from here on it can't.
            if !(ui.commit)() {
                bail!(Cancelled);
            }
            let mut s = Session {
                portal: portal.to_string(),
                start_url: start_url.to_string(),
                region: region.to_string(),
                client_id: client_id.clone(),
                client_secret: client_secret.to_string(),
                client_expires_at,
                access_token: String::new(),
                access_issued_at: 0,
                access_expires_at: 0,
                refresh_token: None,
                signed_in_at: now(),
                renew_until: None,
            };
            s.apply_token(&r.body)?;
            return Ok(s);
        }
        match r.body["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            _ => bail!("AWS SSO sign-in failed: {}", oidc_error(&r.body)),
        }
    }
}

/// Short-lived role credentials for one account + role. Returns (creds, expires_at).
pub fn role_credentials(s: &Session, account: &str, role: &str, region: &str) -> Result<(AwsCreds, u64)> {
    let url = format!("{}/federation/credentials?account_id={}&role_name={}", portal_base(&s.region), pct(account), pct(role));
    let hdr = Zeroizing::new(s.access_token.clone());
    let r = http("GET", &url, &[("x-amz-sso_bearer_token", &hdr)], None)?;
    if r.status == 401 {
        bail!(Unauthorized);
    }
    if r.status != 200 {
        let m = r.body["message"].as_str().or(r.body["Message"].as_str()).unwrap_or("unknown error");
        bail!("AWS SSO refused {role} in {account}: {m}");
    }
    let c = &r.body["roleCredentials"];
    let creds = AwsCreds {
        access_key_id: c["accessKeyId"].as_str().context("no accessKeyId")?.to_string(),
        secret_access_key: c["secretAccessKey"].as_str().context("no secretAccessKey")?.to_string(),
        session_token: c["sessionToken"].as_str().map(String::from),
        region: Some(region.to_string()),
        session_mint: false,
    };
    let exp = c["expiration"].as_u64().map(|ms| ms / 1000).unwrap_or(now() + 900);
    Ok((creds, exp))
}

/// The SSO access token was rejected (expired or revoked): caller may refresh once.
#[derive(Debug)]
pub struct Unauthorized;
impl std::fmt::Display for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AWS SSO token rejected")
    }
}
impl std::error::Error for Unauthorized {}

/// Did AWS refuse a token refresh for good? Only a 4xx carrying an OAuth error that
/// a retry can't fix counts: invalid_grant is what an ended or revoked Identity Center
/// session returns. Anything else (5xx, throttling, a proxy's error page) is retried.
fn refusal_is_final(status: u16, body: &Value) -> bool {
    let code = body["error"].as_str().or(body["__type"].as_str()).unwrap_or("");
    let code = code.rsplit('#').next().unwrap_or(code).to_ascii_lowercase().replace('_', "");
    let code = code.strip_suffix("exception").unwrap_or(&code);
    (400..500).contains(&status)
        && matches!(
            code,
            "invalidgrant" | "expiredtoken" | "invalidclient" | "unauthorizedclient" | "accessdenied" | "invalidrequest" | "unsupportedgranttype" | "invalidscope"
        )
}

fn oidc_error(v: &Value) -> String {
    let e = v["error"].as_str().or(v["__type"].as_str()).unwrap_or("error");
    match v["error_description"].as_str().or(v["message"].as_str()) {
        Some(d) => format!("{e}: {d}"),
        None => e.to_string(),
    }
}

// ---------------------------------------------------------------- http

fn oidc_base(region: &str) -> String {
    test_base(region).unwrap_or_else(|| format!("https://oidc.{region}.amazonaws.com"))
}

fn portal_base(region: &str) -> String {
    test_base(region).unwrap_or_else(|| format!("https://portal.sso.{region}.amazonaws.com"))
}

#[cfg(test)]
thread_local! {
    // Per-thread transport selection lets bound-launch fixtures reuse the existing
    // loopback SSO fake without racing the legacy process-wide test override.
    pub(crate) static TEST_BASE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Debug builds only: point SSO at local fake servers for tests, either one base URL
/// or `region=url,region=url` (one fake per region). Release builds never honour it.
#[cfg(any(debug_assertions, test))]
fn test_base(region: &str) -> Option<String> {
    #[cfg(test)]
    if let Some(base) = TEST_BASE.with(|b| b.borrow().clone()) { return Some(base); }
    let v = std::env::var("KARAMBIT_SSO_TEST_BASE").ok().filter(|s| !s.is_empty())?;
    if !v.contains('=') {
        return Some(v);
    }
    v.split(',').find_map(|kv| kv.split_once('=').filter(|(r, _)| *r == region).map(|(_, u)| u.to_string()))
}
#[cfg(not(any(debug_assertions, test)))]
fn test_base(_region: &str) -> Option<String> {
    None
}

/// Quote a value for a curl config file (inside double quotes: \" \\ \n \r \t).
pub fn curl_quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Percent-encode a query value (unreserved chars pass through).
pub fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

struct Resp {
    status: u16,
    body: Value,
}

fn http(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> Result<Resp> {
    let mut cfg = Zeroizing::new(String::new());
    cfg.push_str(&format!("url = {}\nrequest = {}\n", curl_quote(url), curl_quote(method)));
    for (k, v) in headers {
        cfg.push_str(&format!("header = {}\n", curl_quote(&format!("{k}: {v}"))));
    }
    if let Some(b) = body {
        cfg.push_str("header = \"Content-Type: application/json\"\n");
        cfg.push_str(&format!("data-binary = {}\n", curl_quote(b)));
    }
    cfg.push_str("silent\nshow-error\nmax-time = 30\n");
    cfg.push_str(&format!("write-out = {}\n", curl_quote("\n%{http_code}")));
    // Real AWS endpoints are always https; only debug-build test fakes use http.
    if url.starts_with("https://") {
        cfg.push_str("proto = \"=https\"\n");
    } else if !cfg!(debug_assertions) {
        bail!("refusing non-https AWS SSO URL");
    }
    // -q first: ignore ~/.curlrc. Secrets only ever travel on stdin.
    let mut child = Command::new(CURL)
        .args(["-q", "--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run /usr/bin/curl")?;
    child.stdin.take().context("curl stdin")?.write_all(cfg.as_bytes())?;
    let out = child.wait_with_output()?;
    let text = Zeroizing::new(String::from_utf8_lossy(&out.stdout).into_owned());
    let Some((b, code)) = text.rsplit_once('\n') else {
        bail!("AWS SSO request failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    };
    let status: u16 = code.trim().parse().unwrap_or(0);
    if status == 0 {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("AWS SSO request to {} failed: {}", url.split('?').next().unwrap_or(url), err.trim()));
    }
    let body = if b.trim().is_empty() { json!({}) } else { serde_json::from_str(b).unwrap_or_else(|_| json!({"message": b.chars().take(200).collect::<String>()})) };
    Ok(Resp { status, body })
}

// Discovery returns metadata only. Invalid assignments are counted, never imported.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub account_id: String,
    pub account_name: String,
    pub email_address: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredRole {
    pub account_id: String,
    pub account_name: String,
    pub role: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportItem {
    pub account_id: String,
    pub role: String,
    pub name: String,
    /// Display label from the portal's account list (not authority, not secret).
    /// Wire name differs from ImportPreview.account_name, which flattens this struct.
    #[serde(default, rename = "account_label", skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
}

/// A portal-listed account name, cleaned for display: printable, bounded.
pub fn clean_account_name(name: &str) -> Option<String> {
    let s: String = name.chars().filter(|c| !c.is_control()).take(80).collect();
    let s = s.trim().to_owned();
    (!s.is_empty()).then_some(s)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportPreview {
    #[serde(flatten)]
    pub item: ImportItem,
    pub account_name: String,
    pub action: String,
}
pub struct Assignments<T> {
    pub entries: Vec<T>,
    pub skipped: usize,
}

fn assignment_pages(s: &Session, path: &str, list: &str) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..50 {
        let mut url = format!("{}/assignment/{path}", portal_base(&s.region));
        if let Some(t) = &token { url.push_str(&format!("&next_token={}", pct(t))); }
        let hdr = Zeroizing::new(s.access_token.clone());
        let r = http("GET", &url, &[("x-amz-sso_bearer_token", &hdr)], None)?;
        if r.status == 401 { bail!(Unauthorized); }
        if r.status != 200 { bail!("AWS SSO discovery failed (HTTP {})", r.status); }
        let page = r.body[list].as_array().context("invalid SSO assignment list")?;
        if entries.len() + page.len() > 2000 { bail!("SSO discovery entry cap exceeded (2000)"); }
        entries.extend(page.iter().cloned());
        token = match r.body.get("nextToken") {
            None | Some(Value::Null) => None,
            Some(Value::String(t)) if t.is_empty() => None,
            Some(Value::String(t)) => Some(t.clone()),
            _ => bail!("invalid SSO pagination token"),
        };
        if token.is_none() { return Ok(entries); }
    }
    bail!("SSO discovery pagination cap exceeded (50 pages)")
}

pub fn list_accounts(s: &Session) -> Result<Assignments<Account>> {
    let mut out = Assignments { entries: vec![], skipped: 0 };
    for v in assignment_pages(s, "accounts?max_result=100", "accountList")? {
        let id = v["accountId"].as_str().unwrap_or("");
        if validate_account(id).is_err() { out.skipped += 1; continue; }
        out.entries.push(Account { account_id: id.into(), account_name: v["accountName"].as_str().unwrap_or("").into(), email_address: v["emailAddress"].as_str().unwrap_or("").into() });
    }
    Ok(out)
}
pub fn list_account_roles(s: &Session, account_id: &str) -> Result<Assignments<String>> {
    validate_account(account_id)?;
    let mut out = Assignments { entries: vec![], skipped: 0 };
    for v in assignment_pages(s, &format!("roles?account_id={account_id}&max_result=100"), "roleList")? {
        let role = v["roleName"].as_str().unwrap_or("");
        if v["accountId"].as_str() != Some(account_id) || validate_role(role).is_err() { out.skipped += 1; continue; }
        out.entries.push(role.into());
    }
    Ok(out)
}

pub fn discover(s: &Session) -> Result<Vec<DiscoveredRole>> {
    let accounts = list_accounts(s)?;
    let mut skipped = accounts.skipped;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for account in accounts.entries {
        if !seen.insert(account.account_id.clone()) { continue; }
        let roles = list_account_roles(s, &account.account_id)?;
        skipped += roles.skipped;
        for role in roles.entries {
            if out.len() >= 2000 { bail!("SSO discovery entry cap exceeded (2000 roles)"); }
            out.push(DiscoveredRole { account_id: account.account_id.clone(), account_name: account.account_name.clone(), role });
        }
    }
    if skipped > 0 { eprintln!("SSO discovery skipped {skipped} invalid assignments"); }
    Ok(out)
}

fn slug(s: &str) -> String {
    s.to_ascii_lowercase().split(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit())
        .filter(|s| !s.is_empty()).collect::<Vec<_>>().join("-")
}
fn suffix(name: &str, suffix: &str) -> String {
    format!("{}-{suffix}", name[..name.len().min(63 - suffix.len())].trim_end_matches('-'))
}

/// Shared CLI/GUI naming; existing tuple wins over any proposed name.
pub fn import_preview(portal: &str, roles: &[DiscoveredRole], existing: &[SsoReg], taken: &[String]) -> Result<Vec<ImportPreview>> {
    if roles.len() > 2000 { bail!("too many SSO import entries"); }
    let mut used: std::collections::HashSet<String> = taken.iter().cloned().collect();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for r in roles {
        validate_account(&r.account_id)?;
        validate_role(&r.role)?;
        if !seen.insert((&r.account_id, &r.role)) { continue; }
        // `<account id>-<role>`: sorts by account like the AWS access portal, and the id
        // is unique, so names don't need a suffix. Existing profiles keep their names.
        let base = format!("{}-{}", r.account_id, slug(&r.role));
        let base = base[..base.len().min(64)].trim_end_matches('-').to_string();
        let (name, action) = if let Some(e) = existing.iter().find(|e| e.profile.portal == portal && e.profile.account_id == r.account_id && e.profile.role_name == r.role) {
            (e.name.trim_start_matches("aws/").to_string(), "exists")
        } else {
            let mut name = base.clone();
            let mut n = 2;
            while used.contains(&crate::aws::entry_name(&name)?) {
                name = suffix(&base, &n.to_string()); n += 1;
            }
            let action = if name == base { "new" } else { "renamed" };
            (name, action)
        };
        used.insert(crate::aws::entry_name(&name)?);
        out.push(ImportPreview { item: ImportItem { name, account_id: r.account_id.clone(), role: r.role.clone(), account_name: clean_account_name(&r.account_name) }, account_name: r.account_name.clone(), action: action.into() });
    }
    Ok(out)
}

/// Simple bounded-memory wildcard matcher, shared by import include/exclude filters.
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    let text: Vec<char> = value.chars().collect();
    let mut row = vec![false; text.len() + 1]; row[0] = true;
    for p in pattern.chars() {
        let mut next = vec![false; row.len()];
        if p == '*' { next[0] = row[0]; }
        for i in 1..row.len() { next[i] = if p == '*' { row[i] || next[i-1] } else { row[i-1] && (p == '?' || p == text[i-1]) }; }
        row = next;
    }
    row[text.len()]
}
