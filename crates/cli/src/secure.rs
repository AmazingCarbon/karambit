//! `karambit secure [path]` (alias `eat`): move a project's plaintext `.env` files into
//! the vault, leave a value-free `.env.schema`, and wire npm scripts.
//! `karambit secure rebuild [path]` puts the original files back, byte for byte.
//!
//! Each `.env*` file is archived whole as one "Only me + Touch ID" entry
//! (`<folder>/_archive/<n>/<leaf>`, a new `n` every run, never overwritten), so rebuild
//! restores comments, order and formatting exactly. Each sensitive variable is also
//! stored on its own, at the access level you pick, and the schema refers to it with
//! `karambit(ns/name)`. Plain values (PORT, NODE_ENV, ...) stay in the schema.
//!
//! The schema format is varlock's @env-spec (MIT, see THIRD_PARTY_NOTICES.md).
use anyhow::{Context, Result, bail};
use karambit_core::{Karambit, Tier, envspec};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = ".env.schema";
const ARCHIVE_TAG: &str = "karambit-archive:";
/// A plaintext file being deleted is first renamed to `<name>` + this suffix.
const DELETING_SUFFIX: &str = ".karambit-deleting";

#[derive(clap::Subcommand)]
pub enum SecureCmd {
    /// Put the original .env files back from the vault (human-only, Touch ID).
    Rebuild {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Overwrite files that already exist.
        #[arg(long)]
        force: bool,
    },
}

#[derive(clap::Args)]
pub struct SecureArgs {
    #[command(subcommand)]
    pub cmd: Option<SecureCmd>,
    /// Project directory holding .env files.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Vault folder for this project (default: the directory name).
    #[arg(long)]
    pub name: Option<String>,
    /// Access for the secrets: agents | agents-touch | me-touch.
    #[arg(long, value_parser = crate::parse_access, default_value = "agents-touch")]
    pub access: (Tier, bool),
    /// Preview only: show what would happen, change nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Don't ask; apply the plan (including package.json script wiring).
    #[arg(long)]
    pub yes: bool,
    /// Leave package.json alone.
    #[arg(long)]
    pub no_scripts: bool,
}

// ---------------------------------------------------------------- plan (pure)

pub use karambit_core::env::looks_sensitive;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanItem {
    pub key: String,
    pub sensitive: bool,
    /// Vault name for a sensitive value (`<folder>/<KEY>`).
    pub secret: Option<String>,
    /// Value text (plain items only), quotes removed, for checks and display.
    pub value: Option<String>,
    /// Exact source token for plain items, so quoting and `${VAR}` expansion are kept.
    pub raw: Option<String>,
    pub from: String,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub files: Vec<(PathBuf, String)>,
    pub items: Vec<PlanItem>,
    pub archives: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

/// `.env`, `.env.local`, `.env.development`, ... but not `.env.schema` or examples.
pub fn is_env_file(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && !matches!(name, ".env.schema" | ".env.example" | ".env.sample" | ".env.template" | ".env.dist")
        && !name.ends_with(".schema") && !name.ends_with(".example") && !name.ends_with(".bak")
        && !name.ends_with(DELETING_SUFFIX)
}

pub fn folder_name(dir: &Path, explicit: Option<&str>) -> Result<String> {
    let raw = match explicit {
        Some(n) => n.to_owned(),
        None => dir.file_name().and_then(|n| n.to_str()).context("can't name the project; use --name")?.to_owned(),
    };
    let clean: String = raw.chars().map(|c| if c.is_ascii_alphanumeric() || "._-/".contains(c) { c } else { '-' }).collect();
    let clean = clean.trim_matches(|c| c == '.' || c == '-' || c == '/').to_owned();
    karambit_core::store::validate_name(&format!("{clean}/x")).with_context(|| format!("bad project name {raw:?}; use --name"))?;
    Ok(clean)
}

/// `<folder>/_archive/<n>/<leaf>`: every run gets a fresh `n`, so an archive is never overwritten.
fn archive_name(folder: &str, n: u32, file: &str) -> String {
    let leaf = file.trim_start_matches('.').replace('.', "-");
    format!("{folder}/_archive/{n}/{}", if leaf.is_empty() { "env".into() } else { leaf })
}

/// Next unused archive number under `<folder>/_archive/<n>/`. Older unnumbered archives
/// (`<folder>/_archive/<leaf>`) don't count; they live beside the numbered ones.
fn next_archive_number(folder: &str, existing: &std::collections::HashSet<String>) -> u32 {
    let prefix = format!("{folder}/_archive/");
    existing.iter().filter_map(|n| n.strip_prefix(&prefix)?.split_once('/')?.0.parse::<u32>().ok())
        .max().map_or(1, |n| n.saturating_add(1))
}

/// Two projects with the same folder name would share secrets and archives. Refuse to
/// store anything unless every vault entry under `<folder>/` is one this directory's
/// existing `.env.schema` refers to (a `karambit(...)` ref or a `# karambit-archive:` line).
fn ensure_folder_is_ours(folder: &str, existing: &std::collections::HashSet<String>, schema: Option<&str>) -> Result<()> {
    let mut ours: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(text) = schema {
        ours.extend(archives_in(text).into_iter().map(|(name, _)| name));
        ours.extend(envspec::compile(&envspec::parse(text)?)?.secrets()?.into_iter().map(|(_, reference)| reference));
    }
    let mut foreign: Vec<&str> = existing.iter().filter(|n| !ours.contains(*n)).map(String::as_str).collect();
    if foreign.is_empty() { return Ok(()); }
    foreign.sort_unstable();
    let shown = foreign.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    let more = if foreign.len() > 3 { format!(" and {} more", foreign.len() - 3) } else { String::new() };
    bail!("vault folder {folder}/ already holds entries this directory's {SCHEMA} doesn't refer to ({shown}{more}); \
        another project may use that name. Re-run with --name <unique-name> (for example --name client-a/{folder}). \
        If they are leftovers from an interrupted run, remove them with `karambit rm` first")
}

/// Build the plan from file contents. Later files override earlier ones (`.env` <
/// `.env.local` < `.env.<mode>`); the plan records where each value came from.
pub fn plan(folder: &str, archive_n: u32, files: Vec<(PathBuf, String)>) -> Result<Plan> {
    let mut p = Plan::default();
    let mut order: Vec<(PathBuf, String)> = files;
    order.sort_by_key(|(path, _)| {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_owned();
        (if n == ".env" { 0 } else if n == ".env.local" { 1 } else { 2 }, n)
    });
    for (path, text) in &order {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(".env").to_owned();
        let parsed = envspec::parse(text).with_context(|| format!("{}", path.display()))?;
        p.archives.push((name.clone(), archive_name(folder, archive_n, &name)));
        for item in &parsed.items {
            // Even `# @sensitive` or a stored secret would still inject the planted value
            // into every trusted run, so these names never enter the schema or the vault.
            if karambit_core::env::is_code_loading(&item.key) {
                p.warnings.push(format!("{name}: {} makes programs load code, so it is left out of {SCHEMA}; set it in your shell instead", item.key));
                continue;
            }
            let (value, raw, call) = match &item.value {
                None => (None, None, false),
                Some(envspec::Value::Static { text, raw, .. }) => (Some(text.clone()), Some(raw.clone()), false),
                Some(envspec::Value::Call { raw, .. }) => (Some(raw.clone()), Some(schema_literal(raw)), true),
            };
            if call { p.warnings.push(format!("{name}: {} = {} looks like a function call; it is stored as text", item.key, value.as_deref().unwrap_or(""))); }
            let declared = item.decorators.iter().find(|d| d.name == "sensitive").map(|d| !matches!(&d.value, Some(envspec::Value::Static { text, .. }) if text == "false"));
            let sensitive = declared.unwrap_or_else(|| looks_sensitive(&item.key, value.as_deref().unwrap_or("")));
            let sensitive = sensitive && value.as_deref().is_some_and(|v| !v.is_empty());
            karambit_core::valid_var(&item.key).with_context(|| format!("{name}: line {}", item.line))?;
            let entry = PlanItem {
                key: item.key.clone(),
                sensitive,
                secret: sensitive.then(|| format!("{folder}/{}", item.key)),
                raw: if sensitive { None } else { raw },
                value: if sensitive { None } else { value },
                from: name.clone(),
            };
            match p.items.iter_mut().find(|x| x.key == item.key) {
                Some(prev) => *prev = entry,
                None => p.items.push(entry),
            }
        }
    }
    p.files = order;
    Ok(p)
}

/// Quote literal text for the schema so it parses back to the same text, with no
/// expansion (single quotes are literal). Multi-line text uses `"""`.
fn schema_literal(v: &str) -> String {
    let plain = !v.is_empty() && !v.contains(['#', '"', '\'', '`', '\n', '$', '\\']) && v.trim() == v
        && !v.starts_with(['{', '[']) && !v.contains('(');
    if plain { return v.to_owned(); }
    if !v.contains('\n') { return format!("'{}'", v.replace('\'', "\\'")); }
    format!("\"\"\"{}\"\"\"", v.replace("\"\"\"", "\\\"\"\"").replace('$', "\\$"))
}

/// Merge into an existing schema: keep it, add only missing keys.
pub fn render_schema(p: &Plan, existing: Option<&str>) -> Result<String> {
    let have: Vec<String> = match existing { Some(t) => envspec::parse(t)?.items.into_iter().map(|i| i.key).collect(), None => vec![] };
    let mut out = String::new();
    match existing {
        Some(t) => { out.push_str(t.trim_end()); out.push('\n'); }
        None => {
            out.push_str("# Environment schema: safe to commit, holds no secret values.\n");
            out.push_str("# Secrets live in Karambit; `karambit run -- <cmd>` injects them.\n");
            out.push_str("# Format: @env-spec (https://varlock.dev/env-spec), compatible with varlock.\n");
        }
    }
    let known: Vec<String> = existing.map(|t| t.lines().filter_map(|l| l.trim().strip_prefix('#')?.trim().strip_prefix(ARCHIVE_TAG).map(|s| s.trim().to_owned())).collect()).unwrap_or_default();
    let new_archives: Vec<_> = p.archives.iter().filter(|(_, n)| !known.contains(n)).collect();
    if !new_archives.is_empty() || existing.is_none() {
        for (file, name) in &new_archives { out.push_str(&format!("# {ARCHIVE_TAG} {name} {file}\n")); }
    }
    if existing.is_none() { out.push_str("# ---\n"); }
    for item in p.items.iter().filter(|i| !have.contains(&i.key)) {
        out.push('\n');
        match &item.secret {
            Some(name) => out.push_str(&format!("# @sensitive\n{}=karambit({name})\n", item.key)),
            None => {
                out.push_str("# @sensitive=false\n");
                let token = item.raw.clone().or_else(|| item.value.as_deref().map(schema_literal)).unwrap_or_default();
                out.push_str(&format!("{}={token}\n", item.key));
            }
        }
    }
    // Round-trip check: what we wrote must parse back to the same plan.
    let compiled = envspec::compile(&envspec::parse(&out).context("internal: generated schema does not parse")?)?;
    for item in &p.items {
        let Some(e) = compiled.entries.iter().find(|e| e.key == item.key) else { bail!("internal: {} missing from schema", item.key) };
        if have.contains(&item.key) { continue; }
        let ok = match (&item.secret, &e.source) {
            (Some(n), envspec::Source::Secret(r)) => n == r,
            // A copied source token keeps its own meaning; a quoted literal must expand to itself.
            (None, envspec::Source::Plain(Some((t, q)))) if item.raw.is_none() =>
                envspec::expand(t, *q, &mut |_| bail!("literal")).ok().as_deref() == item.value.as_deref(),
            (None, envspec::Source::Plain(Some((t, _)))) => Some(t.as_str()) == item.value.as_deref(),
            (None, envspec::Source::Plain(None)) => item.value.as_deref().is_none_or(str::is_empty),
            _ => false,
        };
        if !ok { bail!("internal: schema round-trip changed {}", item.key); }
    }
    Ok(out)
}

/// Archive entries recorded in a schema: (vault name, original file name).
pub fn archives_in(schema: &str) -> Vec<(String, String)> {
    schema.lines().filter_map(|l| {
        let rest = l.trim().strip_prefix('#')?.trim().strip_prefix(ARCHIVE_TAG)?.trim();
        let (name, file) = rest.split_once(char::is_whitespace)?;
        let file = file.trim();
        (is_env_file(file) && !file.contains('/')).then(|| (name.to_owned(), file.to_owned()))
    }).collect()
}

/// The newest archive for each original file: later `# karambit-archive:` lines win, so
/// rebuild restores what the latest run deleted (old unnumbered and numbered names mix).
pub fn latest_archives(schema: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, file) in archives_in(schema) {
        match out.iter_mut().find(|(_, f)| *f == file) {
            Some(slot) => slot.0 = name,
            None => out.push((name, file)),
        }
    }
    out
}

// ---------------------------------------------------------------- npm scripts

const WIRED: &[&str] = &["dev", "start", "serve", "test", "build", "preview"];
const PREFIX: &str = "karambit run -- ";

/// Prefix the usual scripts with `karambit run --`, keeping the file's formatting.
/// Returns (new text, script names changed). Already-wired scripts are left alone.
pub fn wire_package_json(text: &str) -> Result<(String, Vec<String>)> {
    let json: serde_json::Value = serde_json::from_str(text).context("package.json is not valid JSON")?;
    let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) else { return Ok((text.to_owned(), vec![])) };
    let mut out = text.to_owned();
    let mut changed = Vec::new();
    for name in WIRED {
        let Some(cmd) = scripts.get(*name).and_then(|c| c.as_str()) else { continue };
        if cmd.contains("karambit run") || cmd.contains("varlock run") || cmd.trim().is_empty() { continue; }
        let old = format!("{}: {}", serde_json::to_string(name)?, serde_json::to_string(cmd)?);
        let old_tight = format!("{}:{}", serde_json::to_string(name)?, serde_json::to_string(cmd)?);
        let new_cmd = serde_json::to_string(&format!("{PREFIX}{cmd}"))?;
        if out.matches(&old).count() == 1 { out = out.replacen(&old, &format!("{}: {new_cmd}", serde_json::to_string(name)?), 1); }
        else if out.matches(&old_tight).count() == 1 { out = out.replacen(&old_tight, &format!("{}:{new_cmd}", serde_json::to_string(name)?), 1); }
        else { continue; }
        changed.push((*name).to_owned());
    }
    // Must still be JSON with exactly those scripts changed.
    let after: serde_json::Value = serde_json::from_str(&out).context("internal: package.json rewrite broke JSON")?;
    for name in &changed {
        let want = format!("{PREFIX}{}", scripts[name].as_str().unwrap_or_default());
        if after["scripts"][name] != serde_json::Value::String(want) { bail!("internal: package.json rewrite changed {name} unexpectedly"); }
    }
    Ok((out, changed))
}

/// Bun loads `.env` itself; varlock sets `env = false` in bunfig.toml. Same here.
pub fn bunfig(existing: Option<&str>) -> Option<String> {
    match existing {
        Some(t) if t.lines().any(|l| l.trim().replace(' ', "") == "env=false") => None,
        Some(t) => Some(format!("env = false\n{t}")),
        None => Some("env = false\n".into()),
    }
}

// ---------------------------------------------------------------- command

fn ask(prompt: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() { bail!("not a terminal: re-run with --yes (or --dry-run)"); }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn git_state(dir: &Path, file: &str) -> (bool, bool, bool) {
    let git = |args: &[&str]| std::process::Command::new("git").arg("-C").arg(dir).args(args)
        .stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output().ok();
    let inside = git(&["rev-parse", "--is-inside-work-tree"]).is_some_and(|o| o.status.success());
    if !inside { return (false, false, false); }
    let tracked = git(&["ls-files", "--error-unmatch", file]).is_some_and(|o| o.status.success());
    let history = git(&["log", "--all", "--format=%H", "-1", "--", file]).is_some_and(|o| o.status.success() && !o.stdout.is_empty());
    let ignored = git(&["check-ignore", "-q", file]).is_some_and(|o| o.status.success());
    (tracked, history, ignored)
}

pub fn run(v: &Karambit, args: SecureArgs, json: bool) -> Result<std::process::ExitCode> {
    if let Some(SecureCmd::Rebuild { path, force }) = args.cmd { return rebuild(v, &path, force, json); }
    // A dry run reads names only (never values to the screen, no vault writes), so
    // agents may preview; everything that stores or deletes is human-only.
    if !args.dry_run { v.require_human(karambit_core::fence::Verb::Add, karambit_core::fence::Layer::Cli)?; }
    let dir = std::fs::canonicalize(&args.path).with_context(|| format!("{}", args.path.display()))?;
    anyhow::ensure!(dir.is_dir(), "{} is not a directory", dir.display());
    let folder = folder_name(&dir, args.name.as_deref())?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_env_file(&name) || !entry.file_type()?.is_file() { continue; }
        let text = std::fs::read_to_string(entry.path()).with_context(|| format!("{name} is not UTF-8 text"))?;
        files.push((entry.path(), text));
    }
    let schema_path = dir.join(SCHEMA);
    let existing_schema = std::fs::read_to_string(&schema_path).ok();
    if files.is_empty() {
        if existing_schema.is_some() { eprintln!("already secured: no plaintext .env files in {} (schema: {SCHEMA})", dir.display()); return Ok(std::process::ExitCode::SUCCESS); }
        bail!("no .env files in {}", dir.display());
    }
    let existing_names: std::collections::HashSet<String> = v.list(Some(&format!("{folder}/*")))?.into_iter().map(|m| m.name).collect();
    ensure_folder_is_ours(&folder, &existing_names, existing_schema.as_deref())?;
    for (path, _) in &files { ensure_no_leftover(&aside_path(path))?; }
    let mut p = plan(&folder, next_archive_number(&folder, &existing_names), files)?;
    for (file, _) in &p.files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or(".env");
        let (tracked, history, ignored) = git_state(&dir, name);
        if tracked { p.warnings.push(format!("{name} is tracked by git: after this, commit its deletion, and rotate these keys (they are in git history)")); }
        else if history { p.warnings.push(format!("{name} is in git history: rotate these keys, deleting the file doesn't remove old commits")); }
        else if !ignored && std::process::Command::new("git").arg("-C").arg(&dir).args(["rev-parse", "--git-dir"]).stderr(std::process::Stdio::null()).output().is_ok_and(|o| o.status.success()) {
            p.warnings.push(format!("{name} is not in .gitignore"));
        }
    }
    let (access_tier, access_agents) = args.access;
    let level = match (access_tier, access_agents) { (Tier::Open, true) => "Agents · no prompt", (Tier::Bio, true) => "Agents · Touch ID", _ => "Only me · Touch ID" };

    // Preview: names only.
    println!("Project {} → vault folder {folder}/", dir.display());
    println!("Files:  {}", p.files.iter().map(|(f, _)| f.file_name().unwrap_or_default().to_string_lossy().into_owned()).collect::<Vec<_>>().join(", "));
    println!();
    println!("{:<32} {:<10} WHERE", "VARIABLE", "KIND");
    for item in &p.items {
        let where_ = match &item.secret {
            Some(n) if existing_names.contains(n) => format!("{n} (exists, kept)"),
            Some(n) => format!("{n} ({level})"),
            None => format!("{SCHEMA} (plain)"),
        };
        println!("{:<32} {:<10} {where_}", item.key, if item.sensitive { "secret" } else { "plain" });
    }
    println!();
    for (file, name) in &p.archives { println!("archive {file} → {name} (Only me · Touch ID, for `karambit secure rebuild`)"); }
    for w in &p.warnings { eprintln!("warning: {w}"); }

    let pkg_path = dir.join("package.json");
    let pkg = if args.no_scripts { None } else { std::fs::read_to_string(&pkg_path).ok() };
    let wired = match &pkg { Some(t) => Some(wire_package_json(t)?), None => None };
    if let Some((_, changed)) = &wired && !changed.is_empty() { println!("package.json: prefix {} with `{}`", changed.join(", "), PREFIX.trim_end()); }
    let bun = (dir.join("bun.lockb").exists() || dir.join("bun.lock").exists() || dir.join("bunfig.toml").exists()) && !args.no_scripts;
    let bun_text = if bun { bunfig(std::fs::read_to_string(dir.join("bunfig.toml")).ok().as_deref()) } else { None };
    if bun_text.is_some() { println!("bunfig.toml: set `env = false` (Bun would load .env itself)"); }
    println!("Then delete the plaintext files above; `karambit secure rebuild` puts them back.");
    if args.dry_run { return Ok(std::process::ExitCode::SUCCESS); }
    if !args.yes && !ask("Secure this project?")? { return Ok(std::process::ExitCode::SUCCESS); }

    // 1. Archive each original file whole (Only me + Touch ID, never agents).
    for ((path, text), (_, name)) in p.files.iter().zip(&p.archives) {
        // Never overwrite: the number is fresh, so an existing name is an error, not a refresh.
        v.add(name, text.as_bytes(), Some(Tier::Bio), false, false, false).with_context(|| format!("archive {}", path.display()))?;
    }
    // 2. Each secret on its own; an existing entry with the same name is kept, not overwritten.
    let mut stored = 0;
    for item in &p.items {
        let Some(name) = &item.secret else { continue };
        if existing_names.contains(name) { continue; }
        let (_, text) = p.files.iter().find(|(f, _)| f.file_name().and_then(|n| n.to_str()) == Some(item.from.as_str())).context("source file")?;
        let parsed = envspec::parse(text)?;
        let Some(envspec::Value::Static { text: value, .. }) = parsed.get(&item.key).and_then(|i| i.value.clone()) else { continue };
        let value = zeroize::Zeroizing::new(value);
        v.add(name, value.as_bytes(), Some(access_tier), access_agents, false, false).with_context(|| format!("store {}", item.key))?;
        stored += 1;
    }
    // 3. Schema (merged if one exists), written atomically.
    let schema = render_schema(&p, existing_schema.as_deref())?;
    karambit_core::store::write_atomic(&schema_path, schema.as_bytes())?;
    set_mode(&schema_path, 0o644)?;
    // 4. Verify every archive decrypts back to the exact bytes before deleting anything.
    let names: Vec<String> = p.archives.iter().map(|(_, n)| n.clone()).collect();
    let back = v.unlock("get", &names, Some("karambit secure: verify archive before deleting .env"), true)?;
    for ((path, text), got) in p.files.iter().zip(&back) {
        if got.value.as_slice() != text.as_bytes() { bail!("archive of {} did not verify; nothing deleted", path.display()); }
    }
    delete_verified(&p.files)?;
    // 5. Script wiring.
    if let Some((text, changed)) = wired && !changed.is_empty() { karambit_core::store::write_atomic(&pkg_path, text.as_bytes())?; set_mode(&pkg_path, 0o644)?; }
    if let Some(text) = bun_text { let path = dir.join("bunfig.toml"); karambit_core::store::write_atomic(&path, text.as_bytes())?; set_mode(&path, 0o644)?; }
    // 6. Trust the new schema so agents can run with it (one more Touch ID).
    let trusted = karambit_core::daemon::request(&v.paths, &karambit_core::daemon::Req::ProfileTrust {
        path: schema_path.to_str().context("schema path must be UTF-8")?.into(),
    }).is_ok();
    if json {
        println!("{}", serde_json::json!({"folder": folder, "secrets": stored, "schema": schema_path, "trusted": trusted,
            "deleted": p.files.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>()}));
    } else {
        println!("secured: {stored} secrets in {folder}/, {SCHEMA} written{}, plaintext .env deleted", if trusted { " and trusted" } else { "" });
        println!("run as usual: npm run dev (or `karambit run -- <cmd>`); undo: karambit secure rebuild");
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// Delete the plaintext files, but only those still holding the bytes that were archived.
/// The archive was made from a read at the start of the run, before the preview, the
/// confirmation and Touch ID; an editor may have saved since. Each file is first renamed
/// aside (so a later save creates a new file instead of vanishing), re-read and compared.
/// If any differs, every file is put back and nothing is deleted.
fn delete_verified(files: &[(PathBuf, String)]) -> Result<()> {
    let mut staged: Vec<(&Path, PathBuf)> = Vec::new();
    if let Err(e) = stage_verified(files, &mut staged) {
        let stuck: Vec<String> = staged.iter().rev().filter_map(|(path, aside)| restore(path, aside).err()
            .map(|err| format!("{} (kept at {}: {err})", path.display(), aside.display()))).collect();
        if stuck.is_empty() { return Err(e.context("nothing was deleted")); }
        return Err(e.context(format!("nothing was deleted, but could not put back: {}", stuck.join("; "))));
    }
    for (_, aside) in &staged { std::fs::remove_file(aside).with_context(|| format!("delete {}", aside.display()))?; }
    Ok(())
}

fn stage_verified<'a>(files: &'a [(PathBuf, String)], staged: &mut Vec<(&'a Path, PathBuf)>) -> Result<()> {
    for (path, text) in files {
        let aside = aside_path(path);
        ensure_no_leftover(&aside)?;
        std::fs::rename(path, &aside).with_context(|| format!("move {} aside", path.display()))?;
        staged.push((path, aside.clone()));
        if std::fs::read(&aside).with_context(|| format!("re-read {}", aside.display()))? != text.as_bytes() {
            bail!("{} changed after it was archived, so it was kept. The vault archive holds the older version; \
                re-run `karambit secure` to archive the current one (secrets already stored keep \
                their old values; replace those with `karambit add --force`)", path.display());
        }
    }
    Ok(())
}

fn aside_path(path: &Path) -> PathBuf {
    let mut aside = path.to_path_buf().into_os_string();
    aside.push(DELETING_SUFFIX);
    PathBuf::from(aside)
}

/// A leftover may be the only copy of an earlier edit: never rename over it.
fn ensure_no_leftover(aside: &Path) -> Result<()> {
    if aside.symlink_metadata().is_ok() {
        bail!("{} is left over from an interrupted `karambit secure`; check it, remove it, then re-run", aside.display());
    }
    Ok(())
}

/// Put a staged file back without replacing anything that was saved at `path` since.
fn restore(path: &Path, aside: &Path) -> std::io::Result<()> {
    std::fs::hard_link(aside, path)?;
    std::fs::remove_file(aside)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?)
}

fn rebuild(v: &Karambit, path: &Path, force: bool, json: bool) -> Result<std::process::ExitCode> {
    v.require_human(karambit_core::fence::Verb::Get, karambit_core::fence::Layer::Cli)?;
    let dir = std::fs::canonicalize(path).with_context(|| format!("{}", path.display()))?;
    let schema = std::fs::read_to_string(dir.join(SCHEMA)).with_context(|| format!("no {SCHEMA} in {}", dir.display()))?;
    let archives = latest_archives(&schema);
    anyhow::ensure!(!archives.is_empty(), "{SCHEMA} has no `# {ARCHIVE_TAG}` lines: nothing to rebuild");
    for (_, file) in &archives {
        if dir.join(file).exists() && !force { bail!("{file} already exists (use --force to overwrite)"); }
    }
    let names: Vec<String> = archives.iter().map(|(n, _)| n.clone()).collect();
    let values = v.unlock("get", &names, Some("karambit secure rebuild: restore .env files"), true)?;
    let mut restored = Vec::new();
    for ((_, file), value) in archives.iter().zip(&values) {
        let target = dir.join(file);
        karambit_core::store::write_atomic(&target, &value.value)?;
        set_mode(&target, 0o600)?;
        restored.push(file.clone());
    }
    if json { println!("{}", serde_json::json!({"restored": restored})); }
    else { println!("restored {} in {} (mode 0600); the vault copies are kept", restored.join(", "), dir.display()); }
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitivity_guess() {
        for k in ["STRIPE_SECRET_KEY", "API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "SENTRY_DSN", "JWT_SECRET", "OPENAI_API_KEY", "SESSION_SECRET", "PRIVATE_KEY"] {
            assert!(looks_sensitive(k, "x"), "{k}");
        }
        for k in ["PORT", "NODE_ENV", "APP_URL", "NEXT_PUBLIC_API_KEY", "STRIPE_PUBLISHABLE_KEY", "LOG_LEVEL", "KEYBOARD_LAYOUT", "MONKEY"] {
            assert!(!looks_sensitive(k, "x"), "{k}");
        }
        assert!(looks_sensitive("DATABASE_URL", "postgres://u:p@db:5432/app"));
        assert!(!looks_sensitive("DATABASE_URL", "postgres://db:5432/app"));
        assert!(!looks_sensitive("APP_URL", "http://localhost:3000"));
    }

    #[test]
    fn env_file_names() {
        for n in [".env", ".env.local", ".env.development", ".env.production.local"] { assert!(is_env_file(n), "{n}"); }
        for n in [".env.schema", ".env.example", ".env.sample", ".envrc", "env", ".env.bak", ".env.local.example"] { assert!(!is_env_file(n), "{n}"); }
    }

    fn files() -> Vec<(PathBuf, String)> {
        vec![
            (".env".into(), "# app\nHOST=localhost\nAPP_URL=http://${HOST}:3000\nPORT=3000\nNODE_ENV=development\nSTRIPE_SECRET_KEY=SYNTHETIC-STRIPE\nDATABASE_URL=postgres://u:p@localhost/app\nGREETING=\"hi #there\"\nEMPTY=\n# @sensitive=false\nAPI_TOKEN=not-really-secret\n".into()),
            (".env.local".into(), "PORT=4000\nexport GITHUB_TOKEN='ghp_SYNTHETIC'\n".into()),
        ]
    }

    #[test]
    fn plan_leaves_code_loading_variables_out_of_the_schema() {
        let planted = vec![(".env.local".into(), "PORT=3000\nNODE_OPTIONS=--require ./x.js\nDYLD_INSERT_LIBRARIES=/tmp/x.dylib\n# @sensitive\nPYTHONPATH=/tmp/evil\n".into())];
        let p = plan("myapp", 1, planted).unwrap();
        assert_eq!(p.items.iter().map(|i| i.key.as_str()).collect::<Vec<_>>(), ["PORT"]);
        assert_eq!(p.warnings.iter().filter(|w| w.contains("set it in your shell")).count(), 3, "{:?}", p.warnings);
        let schema = render_schema(&p, None).unwrap();
        assert!(!schema.contains("NODE_OPTIONS") && !schema.contains("DYLD_") && !schema.contains("PYTHONPATH"), "{schema}");
        // The whole original file is still archived, so `secure rebuild` restores it.
        assert_eq!(p.archives.len(), 1);
    }

    #[test]
    fn plan_and_schema_round_trip() {
        let p = plan("myapp", 1, files()).unwrap();
        let get = |k: &str| p.items.iter().find(|i| i.key == k).unwrap().clone();
        assert_eq!(get("PORT").value.as_deref(), Some("4000"), ".env.local overrides .env");
        assert_eq!(get("PORT").from, ".env.local");
        assert_eq!(get("STRIPE_SECRET_KEY").secret.as_deref(), Some("myapp/STRIPE_SECRET_KEY"));
        assert!(get("DATABASE_URL").sensitive);
        assert!(get("GITHUB_TOKEN").sensitive);
        assert!(!get("API_TOKEN").sensitive, "@sensitive=false is respected");
        assert!(!get("EMPTY").sensitive);
        assert_eq!(p.archives, [(".env".to_owned(), "myapp/_archive/1/env".to_owned()), (".env.local".to_owned(), "myapp/_archive/1/env-local".to_owned())]);
        let schema = render_schema(&p, None).unwrap();
        assert!(!schema.contains("SYNTHETIC") && !schema.contains("u:p@"), "no secret values in schema:\n{schema}");
        assert!(schema.contains("STRIPE_SECRET_KEY=karambit(myapp/STRIPE_SECRET_KEY)"));
        assert!(schema.contains("GREETING=\"hi #there\""), "plain values keep their source token");
        let compiled = envspec::compile(&envspec::parse(&schema).unwrap()).unwrap();
        assert!(compiled.warnings.is_empty(), "{:?}", compiled.warnings);
        assert_eq!(archives_in(&schema), [("myapp/_archive/1/env".to_owned(), ".env".to_owned()), ("myapp/_archive/1/env-local".to_owned(), ".env.local".to_owned())]);
        let plain = compiled.plain(&|_| None).unwrap();
        assert!(plain.contains(&("GREETING".into(), "hi #there".into())));
        assert!(plain.contains(&("PORT".into(), "4000".into())));
        assert!(plain.contains(&("APP_URL".into(), "http://localhost:3000".into())), "expansion kept: {plain:?}");
        assert!(schema.contains("APP_URL=http://${HOST}:3000"));
        assert_eq!(compiled.secrets().unwrap().len(), 3);
        // Re-running only appends new keys and keeps the existing schema.
        let mut more = files();
        more[0].1.push_str("NEW_SECRET=SYNTHETIC2\n");
        let again = render_schema(&plan("myapp", 1, more).unwrap(), Some(&schema)).unwrap();
        assert!(again.starts_with(schema.trim_end()));
        assert_eq!(again.matches("STRIPE_SECRET_KEY=").count(), 1);
        assert!(again.contains("NEW_SECRET=karambit(myapp/NEW_SECRET)"));
    }

    #[test]
    fn schema_literals_round_trip() {
        for v in ["plain", "with space", "a#b", "it's", "say \"hi\"", "$HOME", "multi\nline", "multi\n$X\n\"\"\"", "back`tick", "x(1)", "{json}", "trail "] {
            let p = Plan { items: vec![PlanItem { key: "K".into(), sensitive: false, secret: None, value: Some(v.into()), raw: None, from: ".env".into() }], ..Default::default() };
            render_schema(&p, None).unwrap_or_else(|e| panic!("{v:?}: {e}"));
        }
    }

    #[test]
    fn package_json_wiring() {
        let text = "{\n  \"name\": \"x\",\n  \"scripts\": {\n    \"dev\": \"next dev\",\n    \"start\": \"karambit run -- node .\",\n    \"lint\": \"eslint .\",\n    \"test\": \"vitest\"\n  }\n}\n";
        let (out, changed) = wire_package_json(text).unwrap();
        assert_eq!(changed, ["dev", "test"]);
        assert!(out.contains("\"dev\": \"karambit run -- next dev\""));
        assert!(out.contains("\"lint\": \"eslint .\""), "unrelated scripts untouched");
        assert!(out.contains("\"start\": \"karambit run -- node .\""), "already wired: not doubled");
        assert_eq!(wire_package_json(&out).unwrap().1, Vec::<String>::new(), "idempotent");
        assert_eq!(wire_package_json("{\"name\":\"x\"}").unwrap().1, Vec::<String>::new());
        assert!(wire_package_json("{nope").is_err());
        assert_eq!(bunfig(None).as_deref(), Some("env = false\n"));
        assert_eq!(bunfig(Some("env = false\n")), None);
        assert_eq!(bunfig(Some("[install]\n")).as_deref(), Some("env = false\n[install]\n"));
    }

    fn names(list: &[&str]) -> std::collections::HashSet<String> { list.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn archive_numbers_never_reuse_a_name() {
        assert_eq!(next_archive_number("app", &names(&[])), 1);
        // Old unnumbered archives and other projects' numbers don't count.
        assert_eq!(next_archive_number("app", &names(&["app/_archive/env", "other/_archive/7/env", "app/STRIPE"])), 1);
        assert_eq!(next_archive_number("app", &names(&["app/_archive/env", "app/_archive/1/env", "app/_archive/3/env-local"])), 4);
        assert_eq!(archive_name("app", 4, ".env.local"), "app/_archive/4/env-local");
    }

    #[test]
    fn same_folder_name_from_another_project_is_refused() {
        let schema = "# karambit-archive: app/_archive/env .env\n# karambit-archive: app/_archive/2/env .env\n# ---\n# @sensitive\nA=karambit(app/A)\nB=karambit(team-vault:secret/b#x)\n";
        // Everything under app/ is referenced by this directory's schema: fine.
        ensure_folder_is_ours("app", &names(&["app/A", "app/_archive/env", "app/_archive/2/env"]), Some(schema)).unwrap();
        ensure_folder_is_ours("app", &names(&[]), None).unwrap();
        // First project's entries, no schema here (a second project with the same folder name).
        let err = ensure_folder_is_ours("app", &names(&["app/A", "app/_archive/1/env"]), None).unwrap_err().to_string();
        assert!(err.contains("--name") && err.contains("app/A"), "{err}");
        // A schema that doesn't mention one of the entries is also refused.
        let err = ensure_folder_is_ours("app", &names(&["app/A", "app/OTHER"]), Some(schema)).unwrap_err().to_string();
        assert!(err.contains("app/OTHER") && !err.contains("app/A,"), "{err}");
    }

    #[test]
    fn rebuild_picks_the_newest_archive_for_each_file_in_old_and_new_names() {
        let schema = "# karambit-archive: app/_archive/env .env\n# karambit-archive: app/_archive/env-local .env.local\n# karambit-archive: app/_archive/2/env .env\n";
        assert_eq!(latest_archives(schema), [("app/_archive/2/env".to_owned(), ".env".to_owned()), ("app/_archive/env-local".to_owned(), ".env.local".to_owned())]);
        let old_only = "# karambit-archive: app/_archive/env .env\n";
        assert_eq!(latest_archives(old_only), archives_in(old_only), "old unnumbered names still rebuild");
    }

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("karambit-secure-unit-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn delete_removes_files_that_still_match_the_archive() {
        let dir = scratch("del-ok");
        let files: Vec<_> = [(".env", "A=1\n"), (".env.local", "B=2\n")].iter().map(|(n, t)| { std::fs::write(dir.join(n), t).unwrap(); (dir.join(n), t.to_string()) }).collect();
        delete_verified(&files).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "plaintext and aside copies are gone");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_keeps_a_file_edited_after_it_was_archived() {
        let dir = scratch("del-edit");
        let archived = vec![(dir.join(".env"), "A=1\n".to_owned()), (dir.join(".env.local"), "B=2\n".to_owned())];
        for (path, text) in &archived { std::fs::write(path, text).unwrap(); }
        // The editor saves between the archive read and the delete.
        std::fs::write(dir.join(".env.local"), "B=2\nC=NEW-EDIT\n").unwrap();
        let err = format!("{:#}", delete_verified(&archived).unwrap_err());
        assert!(err.contains(".env.local") && err.contains("changed after it was archived") && err.contains("nothing was deleted"), "{err}");
        assert_eq!(std::fs::read_to_string(dir.join(".env.local")).unwrap(), "B=2\nC=NEW-EDIT\n", "edit kept in place");
        assert_eq!(std::fs::read_to_string(dir.join(".env")).unwrap(), "A=1\n", "files staged earlier are put back too");
        let mut left: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, [".env", ".env.local"], "no aside copies left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_never_overwrites_a_save_made_while_checking() {
        let dir = scratch("del-race");
        let (path, aside) = (dir.join(".env"), aside_path(&dir.join(".env")));
        std::fs::write(&aside, "OLD\n").unwrap();
        std::fs::write(&path, "NEWER-SAVE\n").unwrap();
        assert!(restore(&path, &aside).is_err(), "a file saved at the original path is not replaced");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "NEWER-SAVE\n");
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), "OLD\n", "the staged copy is kept");
        // A leftover from an interrupted run blocks a new run instead of being overwritten.
        let err = delete_verified(&[(path.clone(), "NEWER-SAVE\n".to_owned())]).unwrap_err().root_cause().to_string();
        assert!(err.contains("left over"), "{err}");
        assert!(!is_env_file(".env.karambit-deleting"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn folder_names() {
        assert_eq!(folder_name(Path::new("/x/my app"), None).unwrap(), "my-app");
        assert_eq!(folder_name(Path::new("/x/y"), Some("team/web")).unwrap(), "team/web");
        assert!(folder_name(Path::new("/x/y"), Some("..")).is_err());
    }
}
