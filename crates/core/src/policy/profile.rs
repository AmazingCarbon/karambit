//! Repository profiles are input, not authority. Pin exactly the bytes parsed.
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, os::unix::fs::OpenOptionsExt, path::Path};
use crate::{agent::Caller, audit, store::{self, Paths}};

/// Stored in `trusted_scripts` when the schema has no sibling package.json.
const NO_PACKAGE_JSON: &str = "none";
/// Stored when package.json is a FIFO, device or directory: never read, so it can't hang the daemon.
const NONREGULAR_PACKAGE_JSON: &str = "nonregular";

#[derive(PartialEq, Eq)]
struct Snapshot {
    path: String, sha256: String, text: String,
    /// Schemas only: SHA-256 of the sibling package.json `scripts`, or "none". `secure` wires
    /// `karambit run --` into those scripts, so editing them redirects a human's Touch ID.
    scripts: Option<String>,
}

/// JSON text with object keys sorted at every level, so the digest ignores key order and formatting.
fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => {
            let sorted: std::collections::BTreeMap<_, _> = m.iter().collect();
            let items: Vec<String> = sorted.into_iter().map(|(k, v)| format!("{}:{}", serde_json::Value::from(k.as_str()), canonical_json(v))).collect();
            format!("{{{}}}", items.join(","))
        }
        serde_json::Value::Array(a) => format!("[{}]", a.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

/// Digest of the `scripts` object of the package.json next to `schema` ("none" if absent).
/// A package.json that isn't JSON is pinned by its raw bytes, so any edit still shows.
pub fn scripts_digest(schema: &Path) -> Result<String> {
    let Some(dir) = schema.parent() else { return Ok(NO_PACKAGE_JSON.into()) };
    let mut bytes = Vec::new();
    // NONBLOCK: opening a FIFO named package.json must not wait for a writer.
    match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(dir.join("package.json")) {
        Ok(f) => {
            if !f.metadata()?.is_file() { return Ok(NONREGULAR_PACKAGE_JSON.into()); }
            f.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(NO_PACKAGE_JSON.into()),
        Err(e) => return Err(e).context("open package.json"),
    }
    if bytes.len() > 1024 * 1024 { bail!("profile.package_json_too_large"); }
    let canonical = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(json) => format!("scripts:{}", canonical_json(json.get("scripts").unwrap_or(&serde_json::Value::Null))),
        Err(_) => format!("raw:{}", super::hex(&Sha256::digest(&bytes).into())),
    };
    Ok(super::hex(&Sha256::digest(canonical.as_bytes()).into()))
}

fn snapshot(path: &Path) -> Result<Snapshot> {
    if !path.is_absolute() { bail!("profile.absolute_path_required"); }
    let canonical = path.canonicalize().context("profile canonical path")?;
    let path = canonical.to_str().context("profile path must be UTF-8")?.to_owned();
    if !canonical.metadata()?.is_file() { bail!("profile.regular_file_required"); }
    let file = File::open(&canonical).context("open profile")?;
    if !file.metadata()?.is_file() { bail!("profile.regular_file_required"); }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 { bail!("profile.too_large"); }
    let sha256 = super::hex(&Sha256::digest(&bytes).into());
    let text = String::from_utf8(bytes).context("profile must be UTF-8")?;
    crate::envspec::profile_specs(&canonical, &text)?;
    let scripts = if crate::envspec::is_schema_path(&canonical) { Some(scripts_digest(&canonical)?) } else { None };
    Ok(Snapshot { path, sha256, text, scripts })
}

pub(crate) fn trust(p: &Paths, caller: &Caller, path: &Path) -> Result<()> {
    crate::fence::require_human(caller, crate::fence::Verb::ProfileTrust, crate::fence::Layer::Daemon)?;
    let before = snapshot(path)?;
    // Refuse truncation: the human must see the exact path and content hash.
    if crate::helper::prompt_param(&before.path) != before.path { bail!("profile.path_prompt_too_long"); }
    audit::run(p, "profile-trust", &[], caller,
        serde_json::json!({"reason_code":"profile.pin_requested","path":before.path,"sha256":before.sha256,"scripts_sha256":before.scripts}), || {
        crate::helper::auth(&crate::helper::Prompt::Use {
            names: before.path.clone(), caller: caller.label(), context: format!("trust profile SHA-256 {}{}", before.sha256,
                before.scripts.as_deref().map(|d| format!(" scripts {}", d.get(..12).unwrap_or(d))).unwrap_or_default()),
        })?;
        if snapshot(path)? != before { bail!("profile.changed_during_approval"); }
        let lock = store::lock_config(p)?;
        let mut cfg = lock.load()?;
        cfg.trusted_profiles.insert(before.path.clone(), before.sha256.clone());
        match &before.scripts {
            Some(d) => { cfg.trusted_scripts.insert(before.path.clone(), d.clone()); }
            None => { cfg.trusted_scripts.remove(&before.path); }
        }
        lock.save(&cfg)
    })
}

/// Why a schema whose own bytes are pinned is still untrusted: its package.json scripts differ
/// from the pin. A pin from before scripts were recorded counts as "none".
fn scripts_note(cfg: &store::Config, snapshot: &Snapshot) -> Option<&'static str> {
    let now = snapshot.scripts.as_deref()?;
    match cfg.trusted_scripts.get(&snapshot.path) {
        Some(pinned) if pinned == now => None,
        Some(_) => Some("package.json scripts changed since trust"),
        None if now == NO_PACKAGE_JSON => None,
        None => Some("package.json scripts were not pinned when this profile was trusted"),
    }
}

pub(crate) fn read(p: &Paths, caller: &Caller, path: &Path) -> Result<serde_json::Value> {
    let snapshot = snapshot(path)?;
    let cfg = store::load_config(p)?;
    let file_pinned = cfg.trusted_profiles.get(&snapshot.path) == Some(&snapshot.sha256);
    let scripts_note = scripts_note(&cfg, &snapshot);
    let trusted = file_pinned && scripts_note.is_none();
    let reason = if trusted { "profile.trusted" } else { "profile.untrusted" };
    // Only name package.json when the schema itself still matches; otherwise the schema edit is the news.
    let detail = if file_pinned { scripts_note } else { None };
    let result = if !trusted && caller.is_agent() {
        Err(anyhow::anyhow!(match detail { Some(d) => format!("{reason}: {d}"), None => reason.into() }))
    } else { Ok(()) };
    audit::log(p, audit::Event { action: "profile-decision", secrets: &[], caller,
        detail: serde_json::json!({"reason_code":reason,"path":snapshot.path,"sha256":snapshot.sha256,"scripts_sha256":snapshot.scripts,"detail":detail}), result: &result })?;
    result?;
    let path = std::path::Path::new(&snapshot.path);
    let mut out = serde_json::json!({"trusted":trusted,"detail":detail,"specs":crate::envspec::profile_specs(path, &snapshot.text)?});
    // Schemas also carry plain values; the CLI expands them against its own environment.
    if crate::envspec::is_schema_path(path) { out["schema_text"] = snapshot.text.clone().into(); }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_digest_ignores_formatting_and_other_fields_but_not_scripts() {
        let dir = std::env::temp_dir().join(format!("karambit-profile-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let schema = dir.join(".env.schema");
        assert_eq!(scripts_digest(&schema).unwrap(), "none");
        let digest = |text: &str| { std::fs::write(dir.join("package.json"), text).unwrap(); scripts_digest(&schema).unwrap() };
        let a = digest(r#"{"scripts":{"dev":"a","test":"b"},"name":"x"}"#);
        assert_eq!(a.len(), 64);
        assert_eq!(a, digest("{\n  \"version\": \"9\",\n  \"scripts\": {\"test\": \"b\", \"dev\": \"a\"}\n}"));
        assert_ne!(a, digest(r#"{"scripts":{"dev":"a","test":"c"}}"#));
        assert_ne!(a, digest(r#"{"scripts":{"dev":"a"}}"#));
        assert_ne!(digest(r#"{"name":"x"}"#), "none", "package.json without scripts differs from no package.json");
        assert_ne!(digest("{not json"), digest("{not json!"), "unparseable files are pinned by bytes");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn scripts_digest_pins_fifo_package_json_without_blocking() {
        let dir = std::env::temp_dir().join(format!("karambit-profile-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = std::ffi::CString::new(dir.join("package.json").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let schema = dir.join(".env.schema");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || { let _ = tx.send(scripts_digest(&schema).unwrap()); });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("scripts_digest blocked on a FIFO");
        assert_eq!(got, NONREGULAR_PACKAGE_JSON);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
