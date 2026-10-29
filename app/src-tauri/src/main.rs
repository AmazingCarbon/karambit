// Tauri backend. Secret values never reach the webview: "reveal" copies to the
// clipboard via the SE helper (Touch ID every time). Values only flow webview -> Rust on add.
// Sole exception: `public_values`, for entries marked public (not secrets by definition:
// agents read them and they are never redacted), so the GUI can show them inline.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::{Value, json};
use karambit_core::{Caller, Tier, Karambit};
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use zeroize::Zeroizing;

type R<T> = Result<T, String>;

fn karambit() -> R<Karambit> {
    // GUI is launched by the user (launchd parent) and every sensitive action is
    // Touch-ID gated, so it acts as the human caller.
    Karambit::open_with(Caller::gui()).map_err(e)
}

fn e(err: anyhow::Error) -> String {
    format!("{err:#}")
}

fn tier(s: Option<String>) -> R<Option<Tier>> {
    s.map(|t| Tier::parse(&t).map_err(e)).transpose()
}

#[tauri::command]
async fn status() -> R<Value> {
    karambit()?.status().map_err(e)
}

#[tauri::command]
async fn init(backup_recipient: Option<String>) -> R<Value> {
    let r = backup_recipient.filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string());
    karambit()?.init(r).map_err(e)
}

#[tauri::command]
async fn list() -> R<Value> {
    Ok(json!(karambit()?.list(None).map_err(e)?))
}

#[tauri::command]
async fn add(name: String, value: String, touch: Option<String>, agent_allowed: bool, public: bool, overwrite: bool) -> R<Value> {
    let value = Zeroizing::new(value);
    let m = karambit()?
        .add(name.trim(), value.as_bytes(), tier(touch)?, agent_allowed, public, overwrite)
        .map_err(e)?;
    Ok(json!(m))
}

#[tauri::command]
async fn set_policy(names: Vec<String>, touch: Option<String>, agent_allowed: Option<bool>, public: Option<bool>) -> R<Value> {
    Ok(json!(karambit()?.set_policy(&names, tier(touch)?, agent_allowed, public).map_err(e)?))
}

#[tauri::command]
async fn rename(from: String, to: String) -> R<Value> {
    Ok(json!(karambit()?.rename(from.trim(), to.trim()).map_err(e)?))
}

#[tauri::command]
async fn remove(names: Vec<String>) -> R<Value> {
    Ok(json!(karambit()?.remove(&names).map_err(e)?))
}

#[tauri::command]
async fn copy_secret(name: String) -> R<u32> {
    let v = karambit()?;
    karambit_core::audit::run(&v.paths, "gui-copy", std::slice::from_ref(&name), &v.caller, json!({}), || {
        Ok(v.copy(&name)?.clears_in)
    }).map_err(e)
}

#[tauri::command]
async fn audit(limit: usize) -> R<Value> {
    let v = karambit()?;
    let (n, broken) = v.audit_verify().map_err(e)?;
    let mut events = v.audit_log(limit.min(1000)).map_err(e)?;
    events.reverse();
    Ok(json!({"events": events, "checked": n, "broken_at": broken}))
}

#[tauri::command]
async fn get_config() -> R<Value> {
    let mut value = json!(karambit()?.cfg);
    value["default_agent_process_names"] = json!(karambit_core::store::DEFAULT_AGENT_PROCESS_NAMES);
    value["default_agent_env_markers"] = json!(karambit_core::store::DEFAULT_AGENT_ENV_MARKERS);
    Ok(value)
}

#[tauri::command]
async fn agents_discover() -> R<Value> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let mut rows = karambit_core::agent::discover::discover(std::path::Path::new(&home));
    karambit_core::agent::discover::mark_configured(&mut rows, &karambit()?.cfg);
    Ok(json!(rows))
}

/// Everything the Status page shows, from no-prompt sources: vault/helper status,
/// daemon state, all temporary access, and the block flags.
#[tauri::command]
async fn status_full() -> R<Value> {
    let v = karambit()?;
    let status = v.status().unwrap_or_else(|err| json!({"error": format!("{err:#}")}));
    let daemon = karambit_core::daemon::request_if_running(&v.paths, &karambit_core::daemon::Req::List);
    let pins = |f: &str| std::fs::read_to_string(v.paths.keys().join(f)).map(|t| t.lines().filter(|l| !l.trim().is_empty()).count()).unwrap_or(0);
    Ok(json!({
        "status": status,
        "daemon": daemon.as_ref().map(|d| json!({"running": true, "leases": d["leases"].as_array().map_or(0, |a| a.len()), "aws_endpoints": d["aws_endpoints"]}))
            .unwrap_or(json!({"running": false})),
        "leases": v.leases(),
        "killed": v.cfg.killed,
        "pins": {"daemon": pins("daemon.sha256"), "helper": pins("helper.sha256")},
    }))
}

/// The installed CLI, for features that are the CLI's bound-run path (doctor, whoami).
fn installed_cli() -> Result<std::path::PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let cli = std::path::Path::new(&home).join(".local/bin/karambit");
    if cli.is_file() { Ok(cli) } else { Err(format!("karambit CLI not found at {}", cli.display())) }
}

/// Run the installed CLI with a timeout, draining stdout/stderr on threads.
fn run_cli(args: &[&str], timeout: std::time::Duration) -> Result<(bool, String, String), String> {
    let mut child = std::process::Command::new(installed_cli()?).args(args)
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
        .spawn().map_err(|err| format!("couldn't start karambit: {err}"))?;
    let drain = |mut r: Box<dyn std::io::Read + Send>| std::thread::spawn(move || { let mut s = String::new(); let _ = r.read_to_string(&mut s); s });
    let out = drain(Box::new(child.stdout.take().ok_or("no output")?));
    let err = drain(Box::new(child.stderr.take().ok_or("no output")?));
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|err| err.to_string())? { break st; }
        if std::time::Instant::now() > deadline { let _ = child.kill(); let _ = child.wait(); return Err(format!("took longer than {} s", timeout.as_secs())); }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    Ok((status.success(), out.join().unwrap_or_default(), err.join().unwrap_or_default()))
}

/// Test an AWS profile (CLI `whoami --json`): calls STS through the normal bound run,
/// so Touch ID / SSO rules apply. Returns account + ARN, or the CLI's one-line reason.
#[tauri::command]
async fn aws_whoami(profile: String) -> R<Value> {
    if profile.is_empty() || profile.starts_with('-') || profile.len() > 64 { return Err("Bad profile name.".into()); }
    let (ok, out, err) = run_cli(&["whoami", &profile, "--json"], std::time::Duration::from_secs(120))?;
    if ok { return serde_json::from_str(&out).map_err(|_| "Unexpected output from whoami.".to_string()); }
    let reason = err.lines().map(|l| l.trim_start_matches("karambit: ").trim()).find(|l| !l.is_empty()).unwrap_or("Check failed.");
    // whoami says "<profile> ✗ <reason>"; the panel already names the profile.
    Err(reason.strip_prefix(&format!("{profile} ✗ ")).unwrap_or(reason).to_string())
}

/// Run `karambit doctor --json` (read-only: synthetic canary, no vault secrets, no
/// prompts) using the installed CLI next to the app's helper, with a hard timeout.
#[tauri::command]
async fn doctor() -> R<Value> {
    let (_, out, _) = run_cli(&["doctor", "--json"], std::time::Duration::from_secs(60)).map_err(|err| format!("doctor: {err}"))?;
    serde_json::from_str(&out).map_err(|_| "doctor output wasn't JSON".to_string())
}

/// Expand a leading `~/` and require an absolute `.karambit.env`-style file path.
fn profile_path(path: &str) -> Result<std::path::PathBuf, String> {
    let path = path.trim();
    let p = match path.strip_prefix("~/") {
        Some(rest) => std::path::Path::new(&std::env::var_os("HOME").ok_or("HOME is not set")?).join(rest),
        None => std::path::PathBuf::from(path),
    };
    if !p.is_absolute() { return Err("Use the full path, e.g. ~/code/app/.karambit.env".into()); }
    // A folder means its .karambit.env.
    Ok(if p.is_dir() { p.join(".karambit.env") } else { p })
}

/// Preview a project env file before trusting it: canonical path, SHA-256, VAR -> ref
/// lines (refs only: these files never hold values), and whether it's trusted now.
#[tauri::command]
async fn profile_preview(path: String) -> R<Value> {
    use std::io::Read;
    let v = karambit()?;
    let p = profile_path(&path)?;
    let canonical = p.canonicalize().map_err(|_| format!("No file at {}", p.display()))?;
    if !canonical.is_file() { return Err("That's not a file.".into()); }
    let mut bytes = Vec::new();
    std::fs::File::open(&canonical).map_err(|err| err.to_string())?.take(1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|err| err.to_string())?;
    if bytes.len() > 1024 * 1024 { return Err("File is larger than 1 MB.".into()); }
    let text = String::from_utf8(bytes.clone()).map_err(|_| "File isn't UTF-8 text.".to_string())?;
    let specs = karambit_core::parse_env_file(&text).map_err(e)?;
    let sha256: String = karambit_core::sso::sha256_hex(&bytes);
    let path = canonical.to_string_lossy().into_owned();
    let trusted = v.cfg.trusted_profiles.get(&path) == Some(&sha256);
    let pinned_other = !trusted && v.cfg.trusted_profiles.contains_key(&path);
    Ok(json!({"path": path, "sha256": sha256, "specs": specs, "trusted": trusted, "changed_since_trust": pinned_other}))
}

/// Trust a project env file (CLI `profile trust`): the daemon asks for Touch ID,
/// showing the path and hash, and refuses if the file changes during approval.
#[tauri::command]
async fn profile_trust(path: String) -> R<Value> {
    let v = karambit()?;
    let p = profile_path(&path)?;
    let path = p.to_str().ok_or("Path must be UTF-8.")?.to_string();
    karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::ProfileTrust { path }).map_err(e)
}

/// Trusted project env files, from config (path -> SHA-256).
#[tauri::command]
async fn profile_list() -> R<Value> {
    let v = karambit()?;
    Ok(json!(v.cfg.trusted_profiles.iter().map(|(path, sha)| {
        let current = std::fs::read(path).ok().map(|b| karambit_core::sso::sha256_hex(&b));
        json!({"path": path, "sha256": sha, "state": match current { None => "missing", Some(c) if &c == sha => "trusted", Some(_) => "changed" }})
    }).collect::<Vec<_>>()))
}

/// Simulate policy rules (CLI `policy explain`): offline, no prompt, never authority.
/// `as_who` is "agent:KIND" or empty for a human.
#[tauri::command]
async fn policy_explain(action: String, subject: String, as_who: Option<String>) -> R<Value> {
    use karambit_core::policy::diagnostics as d;
    let v = karambit()?;
    let policy = v.cfg.policy.clone().unwrap_or_default();
    let action = d::action(&action).map_err(e)?;
    let who = as_who.filter(|s| !s.trim().is_empty());
    Ok(d::explain(&policy, action, &d::subject(action, &subject), &d::caller(who.as_deref()).map_err(e)?))
}

/// Block or unblock agents (CLI `block`/`unblock`): same daemon request, which needs Touch ID.
/// Exactly one target: `all`, an agent kind, or a session.
#[tauri::command]
async fn block_agents(all: bool, agent: Option<String>, session: Option<String>, unblock: bool) -> R<Value> {
    let v = karambit()?;
    karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::Kill { agent, session, all, revive: unblock }).map_err(e)?;
    Ok(json!(karambit()?.cfg.killed))
}

#[tauri::command]
async fn set_config(key: String, value: String) -> R<Value> {
    let mut v = karambit()?;
    v.set_config(&key, &value).map_err(e)?;
    Ok(json!(v.cfg))
}

/// Save pasted AWS credentials as aws/<profile>. Verifies with STS unless told not to.
#[tauri::command]
async fn aws_add(profile: String, pasted: String, region: Option<String>, touch: Option<String>, agent_allowed: bool, overwrite: bool, verify: bool) -> R<Value> {
    let mut text = Zeroizing::new(pasted);
    if let Some(r) = region.map(|r| r.trim().to_string()).filter(|r| !r.is_empty()) {
        text.push_str(&format!("\nAWS_REGION={r}\n"));
    }
    let (m, who) = karambit()?
        .add_aws(profile.trim(), &text, tier(touch)?, agent_allowed, overwrite, verify)
        .map_err(e)?;
    Ok(json!({ "meta": m, "identity": who }))
}

#[tauri::command]
async fn aws_show(profile: String) -> R<Value> {
    karambit()?.aws_describe(&profile).map_err(e)
}

/// Save an SSO-backed AWS profile (account + role on a named portal). No secrets cross the IPC.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn aws_add_sso(profile: String, account: String, role: String, region: Option<String>, portal: String,
    touch: Option<String>, agent_allowed: bool, overwrite: bool) -> R<Value> {
    let v = karambit()?;
    let (portal, pc) = v.sso_portal(Some(portal.trim())).map_err(e)?;
    let p = karambit_core::sso::SsoProfile {
        portal,
        start_url: pc.start_url,
        sso_region: pc.region,
        account_id: account.trim().to_string(),
        role_name: role.trim().to_string(),
        region: region.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
    };
    Ok(json!(v.add_aws_sso(profile.trim(), &p, tier(touch)?, agent_allowed, overwrite).map_err(e)?))
}

#[tauri::command]
async fn sso_discover(portal: String) -> R<Value> {
    let v = karambit()?;
    let roles = v.sso_discover(&portal).map_err(e)?;
    Ok(json!(v.sso_import_preview(&portal, roles).map_err(e)?))
}

#[tauri::command]
async fn aws_import_sso(portal: String, items: Vec<karambit_core::sso::ImportItem>, access: String) -> R<Value> {
    let (tier, agents) = match access.as_str() {
        "agents" => (karambit_core::store::Tier::Open, true),
        "agents-touch" => (karambit_core::store::Tier::Bio, true),
        "me-touch" => (karambit_core::store::Tier::Bio, false),
        _ => return Err("invalid access level".into()),
    };
    karambit()?.import_aws_sso(&portal, items, tier, agents, None).map_err(e)
}

/// Add or repoint a named access portal (human GUI caller; repointing costs Touch ID).
#[tauri::command]
async fn sso_portal_add(name: String, start_url: String, region: String) -> R<Value> {
    let mut v = karambit()?;
    v.sso_portal_add(name.trim(), start_url.trim(), region.trim()).map_err(e)?;
    Ok(json!({"ok": true}))
}

/// Portals (configured + signed-in state) and active profiles. No secrets.
#[tauri::command]
async fn sso_status() -> R<Value> {
    karambit()?.sso_status().map_err(e)
}

#[tauri::command]
async fn sso_logout(portal: Option<String>) -> R<Value> {
    karambit()?.sso_logout(portal.as_deref()).map_err(e)?;
    Ok(json!({"ok": true}))
}

/// Remove a portal (signs it out). Its profiles stay saved but stop working.
#[tauri::command]
async fn sso_portal_remove(name: String) -> R<Value> {
    karambit()?.sso_portal_remove(name.trim()).map_err(e)?;
    Ok(json!({"ok": true}))
}

/// Set a portal's sign-in limit in minutes (null = as long as AWS allows). Lengthening
/// or removing it asks for Touch ID. `ended`: the current sign-in was already older.
#[tauri::command]
async fn sso_portal_limit(name: String, minutes: Option<u32>) -> R<Value> {
    let ended = karambit()?.sso_portal_limit(name.trim(), minutes).map_err(e)?;
    Ok(json!({"ok": true, "ended": ended}))
}

/// A paper key being set up (init or rotate). The secret half is generated here, shown to
/// the page once as rows, and dropped (zeroized); the user retypes it and only the matching
/// *public* recipient is kept and sent to the daemon.
#[derive(Default)]
struct Paper(Mutex<Option<PaperPending>>);
// Only the public recipient is kept: confirming compares the retyped key against it, so the
// secret key needn't outlive paper_new (its Zeroizing buffer is wiped when that returns).
struct PaperPending { id: String, recipient: String, created: std::time::Instant }
const PAPER_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

fn paper_lock(m: &Mutex<Option<PaperPending>>) -> std::sync::MutexGuard<'_, Option<PaperPending>> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Check a typed key (all rows, any spacing) against an identity: returns the recipient it derives to.
fn typed_recipient(rows: &[String]) -> Result<String, String> {
    let mut clean = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        clean.push(karambit_core::crypto::check_paper_row(i, row).map_err(|m| format!("Row {}: {m}", i + 1))?);
    }
    let id = karambit_core::crypto::identity_from_rows(&clean).map_err(|_| "The key didn't validate: check for a typo.".to_string());
    clean.iter_mut().for_each(zeroize::Zeroize::zeroize);
    Ok(id?.to_public().to_string())
}

/// Start a paper key: generate it here, return rows to display and an opaque id.
#[tauri::command]
async fn paper_new(state: tauri::State<'_, Paper>) -> R<Value> {
    use karambit_core::crypto;
    let (identity, recipient) = crypto::generate_paper_identity();
    let id = karambit_core::sso::sha256_hex(&crypto::new_dek()[..])[..16].to_string();
    let body = identity.strip_prefix(crypto::PAPER_PREFIX).unwrap_or(&identity);
    let rows: Vec<Value> = (0..crypto::paper_row_count()).map(|i| {
        let start = i * crypto::PAPER_ROW;
        let row = &body[start..start + crypto::paper_row_len(i)];
        let groups: Vec<&str> = row.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
        json!({"text": groups.join(" "), "check": crypto::row_check(i, row), "len": crypto::paper_row_len(i)})
    }).collect();
    *paper_lock(&state.0) = Some(PaperPending { id: id.clone(), recipient, created: std::time::Instant::now() });
    Ok(json!({"id": id, "rows": rows}))
}

/// Confirm the retyped key, then use it: `init` (new vault) or `rotate` (re-encrypt backups).
/// Touch ID comes from the daemon for rotate; init creates the Secure Enclave keys.
#[tauri::command]
async fn paper_confirm(id: String, rows: Vec<String>, purpose: String, state: tauri::State<'_, Paper>) -> R<Value> {
    let rows: Vec<zeroize::Zeroizing<String>> = rows.into_iter().map(zeroize::Zeroizing::new).collect();
    let recipient = {
        let g = paper_lock(&state.0);
        let p = g.as_ref().filter(|p| p.id == id && p.created.elapsed() < PAPER_TTL).ok_or("This paper key expired. Start again.")?;
        let typed = typed_recipient(&rows.iter().map(|r| r.to_string()).collect::<Vec<_>>())?;
        if typed != p.recipient { return Err("That's a valid key, but not the one shown. Check your sheet.".into()); }
        p.recipient.clone()
    };
    let result = match purpose.as_str() {
        "init" => karambit()?.init(Some(recipient)).map_err(e)?,
        "rotate" => json!({"rotated": karambit()?.rotate_backup(&recipient).map_err(e)?}),
        _ => return Err("unknown purpose".into()),
    };
    // Gone from memory once used (Zeroizing wipes it on drop).
    *paper_lock(&state.0) = None;
    Ok(result)
}

/// Throw away a pending paper key (dialog closed).
#[tauri::command]
async fn paper_cancel(state: tauri::State<'_, Paper>) -> R<Value> {
    *paper_lock(&state.0) = None;
    Ok(json!({}))
}

/// Retype the paper key; check it matches the vault's backup recipient. Nothing is stored.
#[tauri::command]
async fn backup_verify(rows: Vec<String>) -> R<Value> {
    let rows: Vec<zeroize::Zeroizing<String>> = rows.into_iter().map(zeroize::Zeroizing::new).collect();
    let v = karambit()?;
    let want = v.cfg.backup_recipient.clone().ok_or("No backup is set up yet.")?;
    let typed = typed_recipient(&rows.iter().map(|r| r.to_string()).collect::<Vec<_>>())?;
    Ok(json!({"matches": typed == want}))
}

/// Recover (CLI `recover`): rebuild the key from the typed rows, then the core checks it
/// decrypts an existing backup copy BEFORE asking for Touch ID and retiring old keys.
/// Returns how many secrets were restored and which had no backup copy.
#[tauri::command]
async fn recover(rows: Vec<String>) -> R<Value> {
    let rows: Vec<zeroize::Zeroizing<String>> = rows.into_iter().map(zeroize::Zeroizing::new).collect();
    let mut clean = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        clean.push(karambit_core::crypto::check_paper_row(i, row).map_err(|m| format!("Row {}: {m}", i + 1))?);
    }
    let text = karambit_core::crypto::identity_text_from_rows(&clean).map_err(|_| "The key didn't validate: check for a typo.".to_string());
    clean.iter_mut().for_each(zeroize::Zeroize::zeroize);
    let text = text?;
    let (restored, missing) = karambit()?.recover_from_paper(&text, &[]).map_err(e)?;
    Ok(json!({"restored": restored, "missing": missing}))
}

/// Check one typed row as the user goes (no secrets kept).
#[tauri::command]
async fn paper_check_row(index: usize, row: String) -> R<Value> {
    let row = zeroize::Zeroizing::new(row);
    Ok(match karambit_core::crypto::check_paper_row(index, &row) {
        // The row's 2-char check code, so the page can show "✓ check 4H" against the sheet.
        Ok(clean) => { let clean = zeroize::Zeroizing::new(clean); json!({"ok": true, "check": karambit_core::crypto::row_check(index, &clean)}) }
        Err(m) => json!({"ok": false, "error": m}),
    })
}

/// The GUI's AWS SSO sign-in (one at a time). Rust keeps the browser URL, so the page
/// can ask to re-open what AWS returned but never supply a URL of its own.
#[derive(Default)]
struct SignIn(Arc<Mutex<SignInState>>);

#[derive(Default)]
struct SignInState {
    active: bool,
    cancelled: bool,
    /// Browser approval received: from here the UI can no longer cancel.
    committed: bool,
    url: Option<String>,
}

/// Lock the sign-in state, recovering from a poisoned mutex (a panicked worker must
/// not leave sign-in stuck as "in progress" forever).
fn lock(m: &Mutex<SignInState>) -> std::sync::MutexGuard<'_, SignInState> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Same rule as the CLI: only ever hand an https URL to `open`.
fn open_https(url: &str) {
    if url.starts_with("https://") {
        let _ = std::process::Command::new("/usr/bin/open")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Device-code sign-in to one portal. Progress goes over `on_event`:
/// `{phase: "code", userCode, url, expiresIn}` once AWS issues the code (the browser is
/// opened here), then `{phase: "approved"}` after browser approval, when the daemon's
/// Touch ID prompt follows. Resolves with `{profiles: n}`; rejects with exactly
/// "cancelled" only if cancelled before approval. No token or credential crosses the IPC.
#[tauri::command]
async fn sso_login(portal: String, on_event: Channel<Value>, state: tauri::State<'_, SignIn>) -> R<Value> {
    let st = state.0.clone();
    {
        let mut g = lock(&st);
        if g.active {
            return Err("another AWS sign-in is already in progress".into());
        }
        *g = SignInState { active: true, ..Default::default() };
    }
    let worker = st.clone();
    let res = tauri::async_runtime::spawn_blocking(move || -> R<usize> {
        let v = karambit()?;
        let show = |code: &str, url: &str, expires_in: u64| {
            lock(&worker).url = Some(url.to_string());
            open_https(url);
            let _ = on_event.send(json!({"phase": "code", "userCode": code, "url": url, "expiresIn": expires_in}));
        };
        let cancelled = || lock(&worker).cancelled;
        // Atomic with sso_login_cancel: whichever takes the lock first wins.
        let commit = || {
            let mut g = lock(&worker);
            if g.cancelled {
                return false;
            }
            g.committed = true;
            g.url = None;
            drop(g);
            let _ = on_event.send(json!({"phase": "approved"}));
            true
        };
        let ui = karambit_core::sso::SignInUi { show: &show, cancelled: &cancelled, commit: &commit };
        v.sso_login(portal.trim(), &ui)
            .map_err(|err| if err.is::<karambit_core::sso::Cancelled>() { "cancelled".to_string() } else { e(err) })
    })
    .await;
    *lock(&st) = SignInState::default();
    let n = res.map_err(|err| format!("AWS sign-in stopped unexpectedly: {err}"))??;
    Ok(json!({"profiles": n}))
}

/// Cancel the sign-in if it's still waiting for browser approval. After approval it
/// can't be cancelled here (the Touch ID prompt's Cancel stops it instead).
#[tauri::command]
async fn sso_login_cancel(state: tauri::State<'_, SignIn>) -> R<Value> {
    let mut g = lock(&state.0);
    let cancelling = g.active && !g.committed;
    if cancelling {
        g.cancelled = true;
    }
    Ok(json!({"cancelling": cancelling, "approved": g.committed}))
}

/// Re-open AWS's approval page for the sign-in in progress.
#[tauri::command]
async fn sso_open_browser(state: tauri::State<'_, SignIn>) -> R<Value> {
    let url = lock(&state.0).url.clone();
    let url = url.ok_or("no AWS sign-in is waiting for approval")?;
    open_https(&url);
    Ok(json!({"ok": true}))
}

#[tauri::command]
async fn lease_grant(names: Vec<String>, to: String, hours: f64, cwd: Option<String>, cmds: Option<Vec<String>>, max_uses: Option<u32>) -> R<Value> {
    let g = karambit_core::lease::Grantee::parse(&to).map_err(e)?;
    let scope = karambit_core::daemon::Scope {
        cwd: cwd.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()),
        cmds: cmds.unwrap_or_default().into_iter().map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).map(Into::into).collect(),
        max_uses: max_uses.filter(|n| *n > 0),
    };
    Ok(json!(karambit()?.grant_lease(&names, &g, hours, &scope).map_err(e)?))
}

#[tauri::command]
async fn lease_revoke_all() -> R<Value> {
    Ok(json!(karambit()?.revoke_lease(&["*".to_string()]).unwrap_or_default()))
}

#[tauri::command]
async fn lease_revoke(names: Vec<String>) -> R<Value> {
    Ok(json!(karambit()?.revoke_lease(&names).map_err(e)?))
}

/// Recent audit events for one secret, newest first.
#[tauri::command]
async fn activity(name: String, limit: usize) -> R<Value> {
    let mut ev = karambit()?.secret_activity(&name, limit.min(200)).map_err(e)?;
    ev.reverse();
    Ok(json!(ev))
}

/// Values of the requested entries that are public AND on the open tier (so showing
/// them never prompts). Anything else is silently skipped: real secrets stay
/// clipboard-only. Exact names only (no globs); one audited "view" per call.
#[tauri::command]
async fn public_values(names: Vec<String>) -> R<Value> {
    let v = karambit()?;
    let want: Vec<String> = v
        .list(None)
        .map_err(e)?
        .into_iter()
        .filter(|m| m.public && m.tier == Tier::Open && names.contains(&m.name))
        .map(|m| m.name)
        .collect();
    if want.is_empty() {
        return Ok(json!({}));
    }
    let mut out = serde_json::Map::new();
    for u in v.unlock("view", &want, Some("karambit GUI"), false).map_err(e)? {
        // Defense in depth: never let a non-public value through, whatever unlock returns.
        if u.public && u.value.len() <= 4096 {
            out.insert(u.name, json!(String::from_utf8_lossy(&u.value)));
        }
    }
    Ok(Value::Object(out))
}

#[tauri::command]
async fn keys_upgrade() -> R<Value> {
    let (created, moved) = karambit()?.upgrade_keys().map_err(e)?;
    Ok(json!({"created": created, "moved": moved}))
}

/// Backend kinds this build registers; the UI hides linked sources when the list is empty.
#[tauri::command]
async fn source_kinds() -> R<Vec<String>> {
    Ok(karambit_core::backend::production_registry().kinds())
}

// Source credentials are zeroized and sent only to the daemon, never returned or logged.
#[tauri::command]
async fn source_list() -> R<Value> {
    let v = karambit()?;
    karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::SourceList).map_err(e)
}

#[tauri::command]
async fn source_add(name: String, kind: String, endpoint: String, auth_method: String, policy: Value, credential: String) -> R<Value> {
    let credential = karambit_core::daemon::SourceCredential(Zeroizing::new(credential));
    let v = karambit()?;
    karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::SourceAdd {
        name, kind, endpoint, auth_method, policy, credential,
    }).map_err(e)
}

#[tauri::command]
async fn source_retarget(name: String, endpoint: Option<String>, policy: Option<Value>, credential: Option<String>) -> R<Value> {
    let credential = credential.map(|s| karambit_core::daemon::SourceCredential(Zeroizing::new(s)));
    let v = karambit()?;
    karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::SourceRetarget {
        name, endpoint, policy, credential,
    }).map_err(e)
}

#[tauri::command]
async fn source_remove(name: String) -> R<Value> {
    let v = karambit()?;
    karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::SourceRemove { name }).map_err(e)
}

/// Offline classification only: no backend connection, credential read or value resolution.
#[tauri::command]
async fn classify_reference(reference: String) -> R<Value> {
    let v = karambit()?;
    match karambit_core::classify_reference(&v.cfg, &reference).map_err(|err| err.to_string())? {
        karambit_core::backend::Reference::Backend(parsed) => {
            karambit_core::backend::production_registry().validate_kind(&v.cfg.sources[&parsed.source].kind)
                .map_err(|err| err.to_string())?;
            Ok(json!({"classification": "backend", "source": parsed.source}))
        }
        karambit_core::backend::Reference::Legacy(_) => Err("enter a configured source reference (source:native-ref)".into()),
    }
}

fn main() {
    tauri::Builder::default()
        .manage(SignIn::default())
        .manage(Paper::default())
        .invoke_handler(tauri::generate_handler![
            status, status_full, doctor, aws_whoami, policy_explain, profile_preview, profile_trust, profile_list, init, list, add, block_agents, paper_new, paper_confirm, paper_cancel, backup_verify, paper_check_row, recover, set_policy, rename, remove, copy_secret, audit, get_config, set_config, agents_discover, aws_add, aws_show,
            lease_grant, lease_revoke, lease_revoke_all, activity, public_values, keys_upgrade, aws_add_sso, sso_discover, aws_import_sso, sso_status, sso_logout, sso_portal_add,
            sso_portal_remove, sso_portal_limit, sso_login, sso_login_cancel, sso_open_browser,
            source_kinds, source_list, source_add, source_retarget, source_remove, classify_reference
        ])
        .run(tauri::generate_context!())
        .expect("error while running Karambit GUI");
}
