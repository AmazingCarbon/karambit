//! Fixed CI build-status call (Jenkins-compatible API) only. Credential policy supplies the tool's access level.
use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{io::{Read, Write}, net::{IpAddr, ToSocketAddrs}, process::{Command, Stdio}};
use zeroize::Zeroizing;

const LIMIT: usize = 1024 * 1024;
const HEADER_LIMIT: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    /// DNS hostname only; HTTPS and the effective port are fixed by configuration.
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path_template: String,
    /// Exact encrypted entry; its existing tier/public/agent_allowed policy applies.
    pub credential_ref: String,
    /// Explicit host binding, checked before credential access.
    pub credential_host: String,
}

impl Tool {
    pub fn validate(&self, args: &[String]) -> Result<String> {
        ensure!(self.host.len() <= 253 && self.host.split('.').all(|part| !part.is_empty()
            && !part.starts_with('-') && !part.ends_with('-')
            && part.len() <= 63 && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')),
            "invalid fixed tool host");
        ensure!(self.port != 0 && self.credential_host == self.host, "fixed tool credential host mismatch");
        ensure!(self.method == "GET" && self.path_template == "/job/{job}/lastBuild/api/json", "unsupported fixed tool template");
        crate::store::require_generic_name(&self.credential_ref)?;
        ensure!(args.len() == 1 && !args[0].is_empty() && args[0].len() <= 128
            && args[0].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'), "expected one simple job name");
        Ok(self.path_template.replace("{job}", &args[0]))
    }
}

/// Deliberately conservative: IPv6 permits ordinary global unicast only, excluding
/// transition/translation ranges. IPv4 excludes private, shared, special and docs ranges.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a,b,c,_] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255) || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254) || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002 && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

// Only debug binaries recognize this exact endpoint + CA pair; no config switch.
fn fixture_ca(tool: &Tool, ip: IpAddr) -> Option<String> {
    #[cfg(debug_assertions)]
    if ip == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        && tool.host == "localhost"
        && std::env::var("KARAMBIT_TEST_FIXED_ENDPOINT").ok().as_deref() == Some(&format!("localhost:{}", tool.port))
        && let Ok(ca) = std::env::var("KARAMBIT_TEST_FIXED_CA")
        && std::path::Path::new(&ca).is_absolute()
        && std::fs::metadata(&ca).is_ok_and(|m| m.is_file())
    { return Some(ca); }
    let _ = (tool, ip);
    None
}

/// Resolve once, then connect only to the checked address using curl --resolve.
/// All answers must be acceptable; no private-address fallback or redirect.
pub fn call(tool: &Tool, args: &[String], credential: &[u8]) -> Result<String> {
    let path = tool.validate(args)?;
    let addresses: Vec<_> = (tool.host.as_str(), tool.port).to_socket_addrs()
        .map_err(|_| anyhow::anyhow!("fixed tool DNS failed"))?.collect();
    ensure!(!addresses.is_empty(), "fixed tool DNS failed");
    // localhost often has ::1 too: the fixture uses exactly 127.0.0.1, never ::1.
    let fixture = addresses.iter().find_map(|a| fixture_ca(tool, a.ip()).map(|ca| (a.ip(), ca)));
    let (ip, ca) = if let Some((ip, ca)) = fixture { (ip, Some(ca)) } else {
        ensure!(addresses.iter().all(|a| public_ip(a.ip())), "fixed tool SSRF address refused");
        (addresses[0].ip(), None)
    };
    ensure!(!credential.is_empty() && credential.len() <= 8192 && credential.iter().all(|b| (0x21..=0x7e).contains(b)), "invalid fixed tool credential");
    // API tokens are stored as username:token; only Basic is supported.
    let parts: Vec<_> = credential.split(|b| *b == b':').collect();
    ensure!(parts.len() == 2 && parts.iter().all(|p| !p.is_empty()), "expected username:token credential");
    let auth = Zeroizing::new(STANDARD.encode(credential));
    let addr = match ip { IpAddr::V4(ip) => ip.to_string(), IpAddr::V6(ip) => format!("[{ip}]") };
    let quote = crate::sso::curl_quote;
    let mut config = Zeroizing::new(format!(
        "url = {}\nrequest = \"GET\"\nresolve = {}\nheader = {}\nheader = \"Accept-Encoding: identity\"\n",
        quote(&format!("https://{}:{}{path}", tool.host, tool.port)),
        quote(&format!("{}:{}:{addr}", tool.host, tool.port)),
        quote(&format!("Authorization: Basic {}", *auth))));
    if let Some(ca) = ca { config.push_str(&format!("cacert = {}\n", quote(&ca))); }
    let mut child = Command::new("/usr/bin/curl")
        .args(["-q", "--config", "-", "--proto", "=https", "--noproxy", "*", "--silent", "--include",
            "--http1.1", "--max-time", "30", "--connect-timeout", "10", "--max-filesize", "1048576"])
        .env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()
        .map_err(|_| anyhow::anyhow!("fixed tool transport unavailable"))?;
    let result = (|| {
        child.stdin.take().unwrap().write_all(config.as_bytes())?;
        let mut raw = Zeroizing::new(Vec::with_capacity(LIMIT + HEADER_LIMIT + 1));
        child.stdout.take().unwrap().take((LIMIT + HEADER_LIMIT + 1) as u64).read_to_end(&mut raw)?;
        ensure!(raw.len() <= LIMIT + HEADER_LIMIT, "fixed tool response too large");
        ensure!(child.wait()?.success(), "fixed tool request failed");
        scrub_response(&raw, credential)
    })();
    // Reap even on write/read/limit failures; stdout is closed before killing.
    let _ = child.kill();
    let _ = child.wait();
    result.map_err(|_| anyhow::anyhow!("fixed tool request or response refused"))
}

fn scrub_response(raw: &[u8], credential: &[u8]) -> Result<String> {
    let split = raw.windows(4).position(|s| s == b"\r\n\r\n").ok_or_else(|| anyhow::anyhow!("invalid headers"))?;
    ensure!(split <= HEADER_LIMIT && raw.len() - split - 4 <= LIMIT, "response too large");
    let header = std::str::from_utf8(&raw[..split])?;
    let mut lines = header.split("\r\n");
    let status = lines.next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");
    ensure!(status.len() == 3 && status.starts_with('2'), "HTTP status refused");
    for line in lines {
        let (key, value) = line.split_once(':').ok_or_else(|| anyhow::anyhow!("invalid header"))?;
        if key.eq_ignore_ascii_case("content-encoding") && !value.trim().eq_ignore_ascii_case("identity") { bail!("encoding refused"); }
        if key.eq_ignore_ascii_case("location") { bail!("redirect refused"); }
    }
    let body = std::str::from_utf8(&raw[split + 4..])?;
    let mut patterns = Vec::new();
    // Scrub the combined Basic credential and both components (servers may echo
    // only the token), including standard/base64url and URL-encoded variants.
    for part in std::iter::once(credential).chain(credential.split(|b| *b == b':')) {
        if part.is_empty() { continue; }
        patterns.push(Zeroizing::new(std::str::from_utf8(part)?.to_owned()));
        for engine in [&STANDARD, &base64::engine::general_purpose::STANDARD_NO_PAD,
            &base64::engine::general_purpose::URL_SAFE, &base64::engine::general_purpose::URL_SAFE_NO_PAD] {
            patterns.push(Zeroizing::new(engine.encode(part)));
        }
        for lower in [false, true] {
            for all in [false, true] {
                patterns.push(Zeroizing::new(part.iter().map(|b| {
                    if !all && (b.is_ascii_alphanumeric() || b"-._~".contains(b)) { (*b as char).to_string() }
                    else if lower { format!("%{b:02x}") } else { format!("%{b:02X}") }
                }).collect::<String>()));
            }
        }
    }
    patterns.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
    patterns.dedup();
    let mut covered = vec![false; body.len()];
    for pattern in &patterns {
        for (start, _) in body.match_indices(pattern.as_str()) { covered[start..start + pattern.len()].fill(true); }
    }
    let mut output = Vec::new();
    let mut at = 0;
    while at < body.len() {
        if covered[at] {
            output.extend_from_slice(b"[REDACTED]");
            while at < body.len() && covered[at] { at += 1; }
        } else {
            output.push(body.as_bytes()[at]);
            at += 1;
        }
        ensure!(output.len() <= LIMIT, "scrubbed response too large");
    }
    let output = String::from_utf8(output)?;
    // Short credentials can themselves occur in the marker, or be formed at a
    // replacement boundary. Refuse rather than release a surviving encoding.
    ensure!(!patterns.iter().any(|p| output.contains(p.as_str())), "scrubbing incomplete");
    Ok(output)
}
