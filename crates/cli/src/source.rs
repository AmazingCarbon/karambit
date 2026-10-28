//! Source administration and offline reference linting. Never print credential material.
use anyhow::{Result, bail};
use clap::Subcommand;
use karambit_core::{Karambit, backend::Reference, daemon::{self, Req, SourceCredential}, fence::Verb};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum SourceCmd {
    /// Register a source with hidden input or stdin credentials.
    Add {
        name: String,
        #[arg(long)] kind: String,
        #[arg(long)] endpoint: String,
        #[arg(long, default_value = "token")] auth_method: String,
        #[arg(long)] policy: Option<String>,
    },
    /// List non-secret source metadata.
    Ls,
    /// Remove a source.
    Rm { name: String },
    /// Change a binding; --credential reads new credentials.
    Retarget {
        name: String,
        #[arg(long)] endpoint: Option<String>,
        #[arg(long)] credential: bool,
        #[arg(long)] policy: Option<String>,
    },
}
impl SourceCmd {
    pub fn verb(&self) -> Verb {
        match self { Self::Add { .. } => Verb::SourceAdd, Self::Ls => Verb::SourceList,
            Self::Rm { .. } => Verb::SourceRemove, Self::Retarget { .. } => Verb::SourceRetarget }
    }
}
#[derive(Subcommand)]
pub enum RefCmd {
    /// Lint an env file or reference offline (no values resolved).
    Check { input: String },
}
fn credential(name: &str) -> Result<SourceCredential> {
    let bytes = super::read_value(name)?;
    let text = std::str::from_utf8(&bytes)?;
    Ok(SourceCredential(Zeroizing::new(text.to_owned())))
}
fn policy(text: Option<String>) -> Result<Option<Value>> {
    text.map(|s| serde_json::from_str(&s).map_err(Into::into)).transpose()
}
pub fn run(v: &Karambit, cmd: SourceCmd, machine: bool) -> Result<()> {
    v.require_human(cmd.verb(), karambit_core::fence::Layer::Cli)?;
    let req = match cmd {
        SourceCmd::Add { name, kind, endpoint, auth_method, policy: p } => {
            if karambit_core::backend::production_registry().validate_kind(&kind).is_err() {
                bail!("unknown source kind '{kind}': this build has no built-in source backends (see docs/backend-contract.md)");
            }
            if !machine { eprintln!("note: linked sources are beta; kinds, config and ref syntax may change between versions"); }
            let policy = policy(p)?.unwrap_or_else(|| json!({}));
            let credential = credential(&name)?;
            Req::SourceAdd { name, kind, endpoint, auth_method, policy, credential }
        }
        SourceCmd::Ls => Req::SourceList,
        SourceCmd::Rm { name } => Req::SourceRemove { name },
        SourceCmd::Retarget { name, endpoint, credential: replace, policy: p } => {
            let policy = policy(p)?;
            let credential = if replace { Some(credential(&name)?) } else { None };
            Req::SourceRetarget { name, endpoint, credential, policy }
        }
    };
    let listing = matches!(req, Req::SourceList);
    let result = daemon::request(&v.paths, &req)?;
    if machine { super::print_json(&result); }
    else if listing {
        println!("NAME\tKIND\tENDPOINT\tAUTH");
        for row in result["sources"].as_array().into_iter().flatten() {
            println!("{}\t{}\t{}\t{}", row["name"].as_str().unwrap_or(""), row["kind"].as_str().unwrap_or(""), row["endpoint"].as_str().unwrap_or(""), row["auth_method"].as_str().unwrap_or(""));
        }
    }
    Ok(())
}
pub fn check(v: &Karambit, input: &str, machine: bool) -> Result<()> {
    let lines: Vec<(usize, Result<String>)> = if std::path::Path::new(input).is_file() {
        std::fs::read_to_string(input)?.lines().enumerate().filter_map(|(i, line)| {
            if line.trim().is_empty() || line.trim_start().starts_with('#') { return None; }
            Some((i + 1, karambit_core::parse_env_file(line).and_then(|mut refs| {
                refs.pop().map(|(_, r)| r).ok_or_else(|| anyhow::anyhow!("invalid env line"))
            })))
        }).collect()
    } else { vec![(1, Ok(input.strip_prefix("karambit:").unwrap_or(input).to_owned()))] };
    let mut invalid = false;
    let mut rows = Vec::new();
    for (line, reference) in lines {
        let classification = reference.and_then(|r| {
            match karambit_core::classify_reference(&v.cfg, &r)? {
                Reference::Legacy(name) => { karambit_core::store::validate_name(&name)?; Ok("legacy") }
                Reference::Backend(parsed) => {
                    // Validate against the same adapters the daemon registers.
                    let source = &v.cfg.sources[&parsed.source];
                    karambit_core::backend::production_registry().validate_kind(&source.kind)?;
                    Ok("backend")
                }
            }
        });
        let (kind, error) = match classification { Ok(k) => (k, None), Err(e) => { invalid = true; ("invalid", Some(e.to_string())) } };
        rows.push(json!({"line":line,"classification":kind,"error":error}));
        if !machine { println!("{line}: {kind}{}", error.map(|e| format!(" ({e})")).unwrap_or_default()); }
    }
    if machine { super::print_json(&json!({"lines":rows})); }
    if invalid { bail!("invalid references"); }
    Ok(())
}
