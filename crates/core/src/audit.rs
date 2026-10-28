//! Append-only, hash-chained JSONL audit log. Never contains secret values.
//! Each line carries `prev` (hash of previous line) and `h` (hash of this line
//! without `h`), so deletions/edits in the middle are detectable via `verify`.
//!
//! The log is segmented: once `audit.jsonl` reaches `SEGMENT_MAX_BYTES` it is renamed to
//! `audit-<unix ts>.jsonl` and a new `audit.jsonl` continues the chain from its last hash.
//! Old segments can be archived or deleted; `verify` then reports the chain as starting
//! mid-way rather than broken.

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use crate::agent::Caller;
use crate::store::{Paths, ensure_dir, now};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn hash(line: &str) -> String {
    let d = Sha256::digest(line.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Rotate `audit.jsonl` once it reaches this size.
const SEGMENT_MAX_BYTES: u64 = 16 * 1024 * 1024;

fn segment_cap() -> u64 {
    #[cfg(test)]
    if let Some(cap) = SEGMENT_CAP.with(|c| c.get()) { return cap; }
    SEGMENT_MAX_BYTES
}

/// Rotated segments, oldest first, as (unix ts in the name, path).
fn segments(p: &Paths) -> Vec<(u64, PathBuf)> {
    let Ok(dir) = fs::read_dir(&p.root) else { return vec![] };
    let mut found: Vec<(u64, PathBuf)> = dir.filter_map(|e| {
        let e = e.ok()?;
        let ts = e.file_name().to_str()?.strip_prefix("audit-")?.strip_suffix(".jsonl")?.parse().ok()?;
        Some((ts, e.path()))
    }).collect();
    found.sort();
    found
}

/// Run one read pass over `segments + audit.jsonl`. The listing and the reads are not atomic:
/// a writer that rotates in between moves the newest events into a segment the listing missed,
/// so the fresh `audit.jsonl` would not chain from the last listed file. If the segment list
/// changed during the pass, list again and redo it (a few times; a lasting change is accepted).
fn read_pass<T>(p: &Paths, mut pass: impl FnMut(&[PathBuf]) -> Result<T>) -> Result<T> {
    for attempt in 1.. {
        let listed = segments(p);
        let files: Vec<PathBuf> = listed.iter().map(|(_, path)| path.clone()).chain([p.audit()]).collect();
        #[cfg(test)]
        if let Some(hook) = AFTER_LISTING.with(|h| h.borrow_mut().take()) { hook(); }
        let out = pass(&files)?;
        if attempt >= 3 || segments(p) == listed { return Ok(out); }
    }
    unreachable!()
}

/// Hash of the last non-blank line of one file, if it has any.
fn tail_hash(path: &std::path::Path) -> Result<Option<String>> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("read audit chain"),
    };
    let mut last = None;
    for line in BufReader::new(f).lines() {
        let line = line?;
        if !line.trim().is_empty() { last = Some(line); }
    }
    let Some(line) = last else { return Ok(None) };
    let value: Value = serde_json::from_str(&line).context("invalid audit tail")?;
    value.get("h").and_then(Value::as_str).map(|h| Some(h.to_string())).context("audit tail missing hash")
}

/// The current file's tail, else (right after a rotation) the newest segment's.
fn last_hash(p: &Paths) -> Result<String> {
    if let Some(h) = tail_hash(&p.audit())? { return Ok(h); }
    for (_, path) in segments(p).iter().rev() {
        if let Some(h) = tail_hash(path)? { return Ok(h); }
    }
    Ok(GENESIS.into())
}

/// Move a full `audit.jsonl` aside. The name's timestamp is kept strictly increasing so a
/// clock step backwards or two rotations in one second still sort in chain order.
fn rotate(p: &Paths) -> Result<()> {
    let ts = segments(p).last().map_or(now(), |(newest, _)| now().max(newest + 1));
    fs::rename(p.audit(), p.root.join(format!("audit-{ts}.jsonl"))).context("rotate audit log")
}

pub struct Event<'a> {
    pub action: &'a str,
    pub secrets: &'a [String],
    pub caller: &'a Caller,
    pub detail: Value,
    pub result: &'a Result<()>,
}

pub fn log(p: &Paths, ev: Event) -> Result<()> {
    append(p, ev, None, None).map(|_| ())
}

/// Open `audit.jsonl` and take its flock, retrying briefly (see `append`). If the path
/// now names a different file than the one locked (another process rotated), start over.
fn lock_current(p: &Paths) -> Result<fs::File> {
    use std::os::fd::AsRawFd;
    for _ in 0..8 {
        let f = OpenOptions::new().create(true).append(true).mode(0o600).open(p.audit())?;
        let mut tries = 0;
        while unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            tries += 1;
            if tries >= 50 {
                anyhow::bail!("audit lock unavailable");
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let (held, named) = (f.metadata()?, fs::metadata(p.audit()));
        if named.is_ok_and(|m| (m.dev(), m.ino()) == (held.dev(), held.ino())) { return Ok(f); }
    }
    anyhow::bail!("audit lock unavailable")
}

fn append(p: &Paths, ev: Event, phase: Option<&str>, intent: Option<&str>) -> Result<String> {
    ensure_dir(&p.root)?;
    #[cfg(test)]
    if FAIL_PHASE.with(|f| (f.get() == phase && phase.is_some()) || f.get() == Some("all")) {
        anyhow::bail!("injected audit append failure");
    }
    // Bounded, never indefinite: containment must never wait for audit. Threads of one
    // process serialize on APPEND_MUTEX; across processes flock is retried briefly,
    // because a sibling thread's fork() holds an inherited fd (and so the flock) until
    // exec, which would otherwise make LOCK_NB fail spuriously.
    let _guard = APPEND_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut lock = lock_current(p)?;
    // Full: move it aside and lock the fresh file. A writer still holding the renamed
    // file notices in `lock_current` and reopens, so nobody appends to a closed segment.
    if lock.metadata()?.len() >= segment_cap() {
        rotate(p)?;
        lock = lock_current(p)?;
    }
    let mut obj = Map::new();
    // Random 128-bit event id, also used for intent correlation.
    let mut rnd = [0u8; 16];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut rnd);
    }
    obj.insert("id".into(), json!(format!("ev-{}", rnd.iter().map(|b| format!("{b:02x}")).collect::<String>())));
    let id = obj["id"].as_str().unwrap().to_string();
    if let Some(phase) = phase { obj.insert("phase".into(), json!(phase)); }
    if let Some(intent) = intent { obj.insert("intent".into(), json!(intent)); }
    if let Some(parent) = PARENTS.with(|s| s.borrow().last().cloned()) {
        obj.insert("parent".into(), json!(parent));
    }
    obj.insert("ts".into(), json!(now()));
    obj.insert("action".into(), json!(ev.action));
    obj.insert("secrets".into(), json!(ev.secrets));
    obj.insert("caller".into(), json!(ev.caller.chain));
    obj.insert("agent".into(), json!(ev.caller.agent));
    // Attribution: which agent family, which run, from where. Omitted for humans/GUI.
    if let Some(k) = &ev.caller.kind {
        obj.insert("kind".into(), json!(k));
    }
    if let Some(s) = &ev.caller.session {
        obj.insert("session".into(), json!(s));
    }
    if let Some(label) = &ev.caller.session_label {
        obj.insert("session_label".into(), json!(label));
    }
    if let Some(p) = ev.caller.pid {
        obj.insert("pid".into(), json!(p));
    }
    if let Some(c) = &ev.caller.cwd {
        obj.insert("cwd".into(), json!(c));
    }
    if let Some(m) = &ev.caller.model {
        obj.insert("model".into(), json!(m));
    }
    if let Some(b) = &ev.caller.branch {
        obj.insert("branch".into(), json!(b));
    }
    if ev.caller.remote {
        obj.insert("remote".into(), json!(true));
    }
    if ev.caller.env_unknown {
        obj.insert("env_unknown".into(), json!(true));
        if ev.caller.is_agent() {
            obj.insert("label".into(), json!(ev.caller.label()));
        } else if !ev.caller.suspect {
            obj.insert("label".into(), json!("env unavailable"));
        }
    }
    if ev.caller.suspect {
        obj.insert("suspect".into(), json!(true));
        if !ev.caller.is_agent() {
            obj.insert("label".into(), json!("unknown agent"));
        }
    }
    obj.insert("detail".into(), ev.detail);
    match ev.result {
        Ok(()) => obj.insert("ok".into(), json!(true)),
        Err(e) => obj.insert("ok".into(), json!(false)).or(obj.insert("err".into(), json!(e.to_string()))),
    };
    obj.insert("prev".into(), json!(last_hash(p)?));
    let body = serde_json::to_string(&Value::Object(obj.clone()))?;
    obj.insert("h".into(), json!(hash(&body)));
    let line = serde_json::to_string(&Value::Object(obj))? + "\n";
    let mut f = lock;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(id)
}

pub fn read(p: &Paths, limit: usize) -> Result<Vec<Value>> {
    read_matching(p, limit, |_| true)
}

/// The newest `limit` events satisfying `keep`, oldest first. Walks segments newest-first
/// and stops as soon as enough events are found.
pub fn read_matching(p: &Paths, limit: usize, keep: impl Fn(&Value) -> bool) -> Result<Vec<Value>> {
    read_pass(p, |files| {
        let mut newest_first: Vec<Value> = Vec::new();
        for path in files.iter().rev() {
            let Ok(f) = fs::File::open(path) else { continue };
            let events: Vec<Value> = BufReader::new(f).lines().map_while(Result::ok)
                .filter_map(|l| serde_json::from_str(&l).ok()).filter(|e| keep(e)).collect();
            newest_first.extend(events.into_iter().rev());
            if newest_first.len() >= limit { break; }
        }
        newest_first.truncate(limit);
        newest_first.reverse();
        Ok(newest_first)
    })
}

/// Result of walking every segment in order.
#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    /// Events checked.
    pub checked: usize,
    /// First bad line, counted across the remaining segments from 1.
    pub broken: Option<usize>,
    /// The first remaining event does not chain from GENESIS: older segments were removed.
    /// Holds that event's timestamp.
    pub older_removed_before: Option<u64>,
}

/// Returns (lines checked, first broken line number if any).
pub fn verify(p: &Paths) -> Result<(usize, Option<usize>)> {
    let v = verify_report(p)?;
    Ok((v.checked, v.broken))
}

/// Walk `audit-*.jsonl` oldest first, then `audit.jsonl`. A first line whose `prev` is not
/// GENESIS is accepted as the start of what remains if it is self-consistent; everything
/// after it must still chain.
pub fn verify_report(p: &Paths) -> Result<Verified> {
    read_pass(p, verify_files)
}

fn verify_files(files: &[PathBuf]) -> Result<Verified> {
    let mut prev: Option<String> = None;
    let mut out = Verified { checked: 0, broken: None, older_removed_before: None };
    let mut line_no = 0;
    for path in files {
        let Ok(f) = fs::File::open(path) else { continue };
        for line in BufReader::new(f).lines() {
            let line = line?;
            line_no += 1;
            if line.trim().is_empty() {
                continue;
            }
            out.checked += 1;
            let bad = Verified { broken: Some(line_no), checked: out.checked, older_removed_before: out.older_removed_before };
            let Ok(Value::Object(mut obj)) = serde_json::from_str::<Value>(&line) else { return Ok(bad) };
            let h = obj.remove("h").and_then(|v| v.as_str().map(String::from));
            let body = serde_json::to_string(&Value::Object(obj.clone()))?;
            let this_prev = obj.get("prev").and_then(Value::as_str).map(String::from);
            if prev.is_none() && this_prev.as_deref() != Some(GENESIS) && this_prev.is_some() {
                out.older_removed_before = Some(obj.get("ts").and_then(Value::as_u64).unwrap_or(0));
            } else if this_prev != Some(prev.clone().unwrap_or_else(|| GENESIS.to_string())) {
                return Ok(bad);
            }
            if h.as_deref() != Some(hash(&body).as_str()) {
                return Ok(bad);
            }
            prev = h;
        }
    }
    Ok(out)
}


static APPEND_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

thread_local! {
    static PARENTS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    #[cfg(test)]
    static AFTER_LISTING: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    #[cfg(test)]
    static SEGMENT_CAP: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    #[cfg(test)]
    static FAIL_PHASE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// An identifier can only be created by a successfully appended local intent.
/// It is not deserializable; remote claims never suppress a daemon intent.
pub struct IntentId {
    paths: Paths,
    id: String,
    action: String,
    secrets: Vec<String>,
    caller: Caller,
}

pub fn intent(p: &Paths, ev: Event<'_>) -> Result<IntentId> {
    let action = ev.action.to_owned();
    let secrets = ev.secrets.to_vec();
    let caller = ev.caller.clone();
    let id = append(p, ev, Some("intent"), None).context("audit intent refused operation")?;
    Ok(IntentId { paths: p.clone(), id, action, secrets, caller })
}

pub fn outcome(id: &IntentId, result: &Result<()>) -> Result<()> {
    append(&id.paths, Event { action: &id.action, secrets: &id.secrets,
        caller: &id.caller, detail: json!({}), result }, Some("outcome"), Some(&id.id)).map(|_| ())
}

/// Execute exactly once. Outcome failure is diagnostic, never a reason to replay.
pub fn run<T>(p: &Paths, action: &str, secrets: &[String], caller: &Caller, detail: Value,
    f: impl FnOnce() -> Result<T>) -> Result<T> {
    let id = intent(p, Event { action, secrets, caller, detail, result: &Ok(()) })?;
    PARENTS.with(|s| s.borrow_mut().push(id.id.clone()));
    struct Pop;
    impl Drop for Pop { fn drop(&mut self) { PARENTS.with(|s| { s.borrow_mut().pop(); }); } }
    let pop = Pop;
    let r = f();
    drop(pop);
    let status = r.as_ref().map(|_| ()).map_err(|e| anyhow::anyhow!("{e:#}"));
    if let Err(e) = outcome(&id, &status) { eprintln!("karambit: audit outcome failed (operation not replayed): {e:#}"); }
    r
}

/// Containment executes first, irrespective of audit availability.
pub fn containment<T>(p: &Paths, action: &str, caller: &Caller, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let r = f();
    let status = r.as_ref().map(|_| ()).map_err(|e| anyhow::anyhow!("{e:#}"));
    if let Err(e) = log(p, Event { action, secrets: &[], caller, detail: json!({"exemption": "containment"}), result: &status }) {
        eprintln!("karambit: containment audit failed: {e:#}");
    }
    r
}

/// Test-only: rotate at `cap` bytes instead of `SEGMENT_MAX_BYTES` on this thread.
#[cfg(test)]
pub(crate) fn set_segment_cap(cap: Option<u64>) { SEGMENT_CAP.with(|c| c.set(cap)); }

/// Test-only, thread-local injection; absent even from non-test debug builds.
#[cfg(test)]
pub(crate) fn fail_phase(phase: Option<&'static str>) { FAIL_PHASE.with(|f| f.set(phase)); }

pub(crate) fn current_intent() -> Option<String> { PARENTS.with(|s| s.borrow().last().cloned()) }

/// Exact launch snapshot, secrets and all. For hashing and binding only: never write it
/// to the audit log (see `launch_detail`).
pub(crate) fn launch_snapshot(binding: &crate::launch::LaunchBinding) -> Value {
    json!({"target": binding.target(), "argv": binding.argv(), "cwd": binding.cwd(), "script": binding.script()})
}

/// Additive launch snapshot fields for the audit log. argv is operational metadata the
/// caller typed, so it may hold credentials: values of `known` secrets become
/// `[REDACTED:name]` and obvious credentials are masked (`env::mask_argv`, best effort).
/// `argv_sha256` is of the exact argv, so someone holding the real command can confirm it.
/// `full_argv` (config `audit-full-argv`) stores argv as typed.
pub(crate) fn launch_detail(binding: &crate::launch::LaunchBinding, full_argv: bool, known: &[(String, &[u8])]) -> Value {
    let argv = binding.argv();
    let shown = if full_argv { argv.to_vec() } else { crate::env::mask_argv(&crate::env::redact_known_values(argv, known)) };
    let context = crate::env::audit_context(argv, &shown);
    let mut detail = launch_snapshot(binding);
    detail["argv_sha256"] = json!(crate::env::argv_sha256(argv));
    detail["argv"] = json!(shown);
    detail["context"] = json!(context);
    detail
}

/// Containment has already burned authority. Audit unavailability cannot undo it.
pub(crate) fn launch_contained(p: &Paths, action: &str, launch: &crate::launch::PendingLaunch, caller: &Caller) {
    let full_argv = crate::store::load_config(p).is_ok_and(|c| c.audit_full_argv);
    let mut detail = launch_detail(&launch.binding, full_argv, &[]);
    detail["kind"] = json!("containment");
    detail["exemption"] = json!("containment");
    let _ = log(p, Event { action, secrets: &launch.refs, caller, detail, result: &Ok(()) });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn outcome_failure_never_replays_effect() {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-audit-outcome-{}", std::process::id())) };
        let _ = fs::remove_dir_all(&p.root);
        let mut effects = 0;
        fail_phase(Some("outcome"));
        run(&p, "one-effect", &[], &Caller::default(), json!({}), || { effects += 1; Ok(()) }).unwrap();
        assert_eq!(effects, 1);
        let events = read(&p, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["phase"], "intent");
        let id = intent(&p, Event { action: "explicit", secrets: &[], caller: &Caller::default(), detail: json!({}), result: &Ok(()) }).unwrap();
        assert!(outcome(&id, &Ok(())).is_err());
        fail_phase(None);
        assert_eq!(verify(&p).unwrap(), (2, None));
        fs::remove_dir_all(p.root).unwrap();
    }

    fn tmp(tag: &str) -> Paths {
        let p = Paths { root: std::env::temp_dir().join(format!("karambit-audit-{tag}-{}", std::process::id())) };
        let _ = fs::remove_dir_all(&p.root);
        p
    }

    fn log_n(p: &Paths, n: usize) {
        for i in 0..n {
            log(p, Event { action: "probe", secrets: &["s/one".to_string()], caller: &Caller::default(), detail: json!({"i": i}), result: &Ok(()) }).unwrap();
        }
    }

    /// Rotate and keep logging right after the next `segments` listing: what a writer in another
    /// process can do between a reader's listing and its reads.
    fn rotate_after_listing(p: &Paths) {
        let p = p.clone();
        AFTER_LISTING.with(|h| *h.borrow_mut() = Some(Box::new(move || { rotate(&p).unwrap(); log_n(&p, 1); })));
    }

    #[test]
    fn verify_survives_a_rotation_between_listing_and_reading() {
        let p = tmp("racing-verify");
        set_segment_cap(Some(600));
        log_n(&p, 8);
        set_segment_cap(None);
        assert!(!segment_files(&p).is_empty());
        rotate_after_listing(&p);
        // The listing predates the rotated file; without a relist the new audit.jsonl would not chain.
        let v = verify_report(&p).unwrap();
        assert_eq!((v.broken, v.checked, v.older_removed_before), (None, 9, None));
        assert_eq!(verify(&p).unwrap(), (9, None));
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn read_survives_a_rotation_between_listing_and_reading() {
        let p = tmp("racing-read");
        set_segment_cap(Some(600));
        log_n(&p, 8);
        set_segment_cap(None);
        rotate_after_listing(&p);
        assert_eq!(read(&p, 100).unwrap().len(), 9, "the just-rotated file must not be skipped");
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn a_real_break_is_still_reported_after_the_relist() {
        let p = tmp("racing-real-break");
        set_segment_cap(Some(600));
        log_n(&p, 12);
        set_segment_cap(None);
        let old = segment_files(&p);
        fs::remove_file(&old[1]).unwrap();
        assert!(old.len() >= 3);
        assert!(verify_report(&p).unwrap().broken.is_some());
        fs::remove_dir_all(p.root).unwrap();
    }

    fn segment_files(p: &Paths) -> Vec<PathBuf> { segments(p).into_iter().map(|(_, path)| path).collect() }

    #[test]
    fn log_rotates_and_chain_continues_across_segments() {
        let p = tmp("rotate");
        set_segment_cap(Some(600));
        log_n(&p, 12);
        set_segment_cap(None);
        let old = segment_files(&p);
        assert!(old.len() >= 2, "expected rotation, got {old:?}");
        // The fresh file chains from the last line of the newest segment.
        let first_new: Value = serde_json::from_str(fs::read_to_string(p.audit()).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(Some(first_new["prev"].as_str().unwrap().to_string()), tail_hash(old.last().unwrap()).unwrap());
        assert_eq!(verify(&p).unwrap(), (12, None));
        let all = read(&p, 100).unwrap();
        assert_eq!(all.iter().map(|e| e["detail"]["i"].as_u64().unwrap()).collect::<Vec<_>>(), (0..12).collect::<Vec<_>>());
        // Newest-first across segment boundaries, returned oldest first.
        assert_eq!(read(&p, 7).unwrap().iter().map(|e| e["detail"]["i"].as_u64().unwrap()).collect::<Vec<_>>(), (5..12).collect::<Vec<_>>());
        let hits = read_matching(&p, 3, |e| e["detail"]["i"].as_u64().is_some_and(|i| i % 2 == 0)).unwrap();
        assert_eq!(hits.iter().map(|e| e["detail"]["i"].as_u64().unwrap()).collect::<Vec<_>>(), [6, 8, 10]);
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn no_rotation_below_cap() {
        let p = tmp("norotate");
        log_n(&p, 5);
        assert!(segment_files(&p).is_empty());
        assert_eq!(verify(&p).unwrap(), (5, None));
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn verify_reports_removed_older_segments_but_not_gaps() {
        let p = tmp("removed");
        set_segment_cap(Some(600));
        log_n(&p, 24);
        set_segment_cap(None);
        let old = segment_files(&p);
        assert!(old.len() >= 4, "{old:?}");
        // Intact: nothing removed.
        assert_eq!(verify_report(&p).unwrap().older_removed_before, None);
        // Backup the middle segment, then remove the oldest: remainder still chains.
        let oldest_lines = fs::read_to_string(&old[0]).unwrap().lines().count();
        fs::remove_file(&old[0]).unwrap();
        let r = verify_report(&p).unwrap();
        assert_eq!((r.checked, r.broken), (24 - oldest_lines, None));
        assert!(r.older_removed_before.is_some());
        // A gap inside what remains is still BROKEN, at the first line after the gap.
        // (Removing the *oldest* remaining segment would just be more removed history.)
        let middle = old[2].clone();
        let saved = fs::read(&middle).unwrap();
        fs::remove_file(&middle).unwrap();
        assert!(verify_report(&p).unwrap().broken.is_some());
        fs::write(&middle, &saved).unwrap();
        assert_eq!(verify_report(&p).unwrap().broken, None);
        // So is an edit inside a segment.
        fs::write(&middle, String::from_utf8(saved).unwrap().replacen("probe", "pr0be", 1)).unwrap();
        assert!(verify_report(&p).unwrap().broken.is_some());
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn verify_still_flags_a_first_line_that_is_not_self_consistent() {
        let p = tmp("badfirst");
        log_n(&p, 3);
        let text = fs::read_to_string(p.audit()).unwrap();
        // Dropping line 1 is "older part removed"; editing line 2's body is not.
        let rest: Vec<&str> = text.lines().skip(1).collect();
        fs::write(p.audit(), rest.join("\n") + "\n").unwrap();
        assert!(verify_report(&p).unwrap().older_removed_before.is_some());
        assert_eq!(verify(&p).unwrap(), (2, None));
        fs::write(p.audit(), rest.join("\n").replacen("probe", "pr0be", 1) + "\n").unwrap();
        assert_eq!(verify(&p).unwrap().1, Some(1));
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn launch_detail_masks_argv_and_hashes_the_real_one() {
        let dir = std::env::temp_dir().join(format!("karambit-audit-detail-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let argv: Vec<String> = ["/usr/bin/curl", "-H", "Authorization: Bearer abcd1234efgh", "--password", "hunter22", "https://u:pw12@h/x", "typed-secret-value"]
            .iter().map(|s| s.to_string()).collect();
        let binding = crate::launch::LaunchBinding::capture("/usr/bin/curl".into(), argv.clone(), dir.clone()).unwrap();
        let known = [("p/s".to_string(), b"typed-secret-value".as_slice())];
        let masked = launch_detail(&binding, false, &known);
        let text = masked.to_string();
        for leaked in ["abcd1234efgh", "hunter22", "pw12", "typed-secret-value"] { assert!(!text.contains(leaked), "{leaked} leaked: {text}"); }
        assert!(text.contains("[REDACTED:p/s]"));
        assert_eq!(masked["argv_sha256"], json!(crate::env::argv_sha256(&argv)));
        let full = launch_detail(&binding, true, &known);
        assert_eq!(full["argv"], json!(argv));
        assert_eq!(full["argv_sha256"], masked["argv_sha256"]);
        fs::remove_dir_all(dir).unwrap();
    }
}
