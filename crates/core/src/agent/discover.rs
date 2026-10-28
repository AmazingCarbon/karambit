// Catalog and detection approach adapted from agentic-detector (MIT, (c) 2026 Karmine).
/*
MIT License

Copyright (c) 2026 Karmine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
//! Bounded filesystem hints, not proof of a running agent. Never executes discovered code.
use std::{fs, io::Read, path::{Path, PathBuf}};
use serde::Serialize;
use crate::store::Config;

#[derive(Debug, Serialize)]
pub struct Discovered {
    pub kind: String,
    pub process_names: Vec<String>,
    pub env_markers: Vec<String>,
    pub evidence: Vec<String>,
    pub already_configured: bool,
}

struct Known {
    kind: &'static str,
    bins: &'static [&'static str],
    npm: &'static [&'static str],
    pipx: &'static str,
    homes: &'static [&'static str],
    state: &'static [&'static str],
}

const CATALOG: &[Known] = &[
    Known { kind: "claude", bins: &["claude"], npm: &["@anthropic-ai/claude-code"], pipx: "", homes: &[".claude"], state: &[".claude/projects", ".claude.json"] },
    Known { kind: "codex", bins: &["codex"], npm: &["@openai/codex"], pipx: "", homes: &[".codex"], state: &[".codex/sessions", ".codex/auth.json", ".codex/config.toml"] },
    Known { kind: "gemini", bins: &["gemini"], npm: &["@google/gemini-cli"], pipx: "", homes: &[".gemini"], state: &[".gemini/tmp", ".gemini/settings.json", ".gemini/oauth_creds.json"] },
    Known { kind: "pi", bins: &["pi"], npm: &["@earendil-works/pi-coding-agent", "@mariozechner/pi-coding-agent"], pipx: "", homes: &[".pi"], state: &[".pi/agent"] },
    Known { kind: "kiro", bins: &["kiro", "kiro-cli", "kiro-cli-chat"], npm: &[], pipx: "", homes: &[".kiro"], state: &[".kiro/sessions", ".kiro/settings", "Library/Application Support/kiro-cli"] },
    Known { kind: "amazon-q", bins: &["q"], npm: &[], pipx: "", homes: &[], state: &[".aws/amazonq"] },
    Known { kind: "aider", bins: &["aider"], npm: &[], pipx: "aider-chat", homes: &[".aider"], state: &[".aider.conf.yml"] },
    Known { kind: "goose", bins: &["goose"], npm: &[], pipx: "", homes: &[], state: &[".config/goose", ".local/share/goose"] },
    Known { kind: "opencode", bins: &["opencode"], npm: &["opencode-ai"], pipx: "", homes: &[".opencode", ".config/opencode"], state: &[".local/share/opencode"] },
    Known { kind: "cline", bins: &["cline"], npm: &["cline"], pipx: "", homes: &[".cline"], state: &[] },
    Known { kind: "continue", bins: &["cn", "continue"], npm: &["@continuedev/cli"], pipx: "", homes: &[".continue"], state: &[] },
    Known { kind: "cursor", bins: &["cursor-agent", "cursor"], npm: &[], pipx: "", homes: &[".cursor"], state: &[".cursor/cli-config.json", ".cursor/chats"] },
    Known { kind: "hermes", bins: &["hermes", "hermes-agent", "hermes-acp"], npm: &["hermes"], pipx: "hermes", homes: &[".hermes", ".config/hermes"], state: &[] },
    Known { kind: "openclaw", bins: &["openclaw"], npm: &["openclaw"], pipx: "openclaw", homes: &[".openclaw"], state: &[] },
    Known { kind: "grok", bins: &["grok"], npm: &[], pipx: "", homes: &[".grok"], state: &[] },
 ];

// Shared install locations are platform-specific; unsupported targets compile.
fn system_dirs() -> (Vec<PathBuf>, Vec<PathBuf>) {
    #[cfg(target_os = "macos")]
    let prefixes = ["/usr/local", "/opt/homebrew", "/usr"];
    #[cfg(not(target_os = "macos"))]
    let prefixes: [&str; 0] = [];
    (prefixes.iter().map(|p| Path::new(p).join("bin")).collect(),
     prefixes.iter().map(|p| Path::new(p).join("lib/node_modules")).collect())
}

fn has_content(path: &Path) -> bool {
    fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some_and(|e| e.is_ok()))
}

fn version(path: &Path) -> Option<String> {
    // Only regular manifests, at most 64 KiB. Never read tool config/credentials.
    if !fs::metadata(path).ok()?.is_file() { return None; }
    let mut bytes = Vec::new();
    fs::File::open(path).ok()?.take(65537).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 65536 { return None; }
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let v = value.get("version")?.as_str()?;
    (v.len() <= 128 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b)))
        .then(|| v.to_owned())
}

pub fn mark_configured(rows: &mut [Discovered], cfg: &Config) {
    for row in rows {
        row.already_configured = row.process_names.iter().all(|n| cfg.agent_process_names.iter().any(|v| v.eq_ignore_ascii_case(n)))
            && row.env_markers.iter().all(|n| cfg.agent_env_markers.contains(n));
    }
}

pub fn discover(home: &Path) -> Vec<Discovered> {
    discover_with_system(home, system_dirs())
}

fn discover_with_system(home: &Path, system: (Vec<PathBuf>, Vec<PathBuf>)) -> Vec<Discovered> {
    let mut bins: Vec<_> = [".local/bin", "bin", ".bun/bin", ".cargo/bin", ".deno/bin", ".opencode/bin", ".npm-global/bin", "go/bin", ".grok/bin", ".hermes/bin", ".openclaw/bin"]
        .iter().map(|p| home.join(p)).collect();
    let mut npm: Vec<_> = [".npm-global/lib/node_modules", ".bun/install/global/node_modules"].iter().map(|p| home.join(p)).collect();
    if let Ok(entries) = fs::read_dir(home.join(".nvm/versions/node")) {
        for entry in entries.take(64).flatten() {
            bins.push(entry.path().join("bin"));
            npm.push(entry.path().join("lib/node_modules"));
        }
    }
    bins.extend(system.0);
    npm.extend(system.1);
    let display = |p: &Path| p.strip_prefix(home).map(|p| format!("~/{}", p.display())).unwrap_or_else(|_| p.display().to_string());
    let mut out = Vec::new();
    for k in CATALOG {
        let mut evidence = Vec::new();
        for bin in k.bins {
            let mut dirs = bins.clone();
            for root in k.homes { dirs.push(home.join(root)); dirs.push(home.join(root).join("bin")); }
            for dir in dirs {
                let path = dir.join(bin);
                if path.is_file() { evidence.push(format!("bin:{}", display(&path))); }
            }
        }
        for pkg in k.npm {
            for root in &npm {
                if let Some(v) = version(&root.join(pkg).join("package.json")) {
                    evidence.push(format!("npm:{pkg}@{v}"));
                }
            }
        }
        if !k.pipx.is_empty() {
            for root in [".local/pipx/venvs", ".local/share/pipx/venvs"] {
                let path = home.join(root).join(k.pipx);
                if has_content(&path) { evidence.push(format!("pipx:{}", display(&path))); }
            }
        }
        for root in k.homes {
            if has_content(&home.join(root)) { evidence.push(format!("home:~/{root}")); }
        }
        for state in k.state {
            let path = home.join(state);
            // Explicit nested state directories count, but empty tool roots do not.
            if path.is_file() || path.is_dir() { evidence.push(format!("state:{state}")); }
        }
        evidence.sort(); evidence.dedup();
        if !evidence.is_empty() {
            out.push(Discovered {
                kind: k.kind.into(), process_names: k.bins.iter().map(|v| (*v).into()).collect(),
                env_markers: super::ENV_KINDS.iter().filter(|(_, kind, _)| *kind == k.kind).map(|(v, _, _)| (*v).into()).collect(),
                evidence, already_configured: false,
            });
        }
    }
    mark_configured(&mut out, &Config::default());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discover_smoke_and_never_execute() {
        let home = std::env::temp_dir().join(format!("karambit-discover-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        for dir in [".local/bin", ".npm-global/lib/node_modules/@openai/codex", ".pi/agent", ".kiro/settings", ".grok"] {
            fs::create_dir_all(home.join(dir)).unwrap();
        }
        let marker = home.join("executed");
        fs::write(home.join(".local/bin/claude"), format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(home.join(".local/bin/claude"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(home.join(".npm-global/lib/node_modules/@openai/codex/package.json"), r#"{"version":"1.2.3"}"#).unwrap();
        let rows = discover_with_system(&home, (vec![], vec![]));
        for kind in ["claude", "codex", "pi", "kiro"] { assert!(rows.iter().any(|r| r.kind == kind)); }
        assert!(rows.iter().find(|r| r.kind == "codex").unwrap().evidence.contains(&"npm:@openai/codex@1.2.3".into()));
        assert!(!rows.iter().any(|r| r.kind == "grok"), "empty tool home is not evidence");
        assert!(!marker.exists(), "discovered binary must never execute");
        fs::remove_dir_all(home).unwrap();
    }
}
