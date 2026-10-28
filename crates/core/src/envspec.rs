//! `.env.schema` and dotenv parsing in the @env-spec format, plus run planning.
//!
//! Hand-ported subset of varlock's @env-spec grammar
//! (`packages/env-spec-parser/grammar.peggy` and `src/classes.ts`, varlock 1.23.0),
//! Copyright (c) 2026 DMNO Inc., MIT License. See THIRD_PARTY_NOTICES.md.
//!
//! Supported: items (`KEY=value`, `export KEY=value`), comments, `# ---` dividers, a
//! header block, decorators (`@name`, `@name=value`, `@name(args)`), unquoted, quoted
//! (`"` `'` `` ` ``), multi-line and triple-quoted values, function calls with
//! positional and `key=value` args, `${VAR}` / `$VAR` / `${VAR:-default}` expansion.
//! Refused: object/array literals and `$(...)` command expansion (nothing is executed).
//!
//! Secrets are `KEY=karambit(ns/name)`: the reference goes to the daemon, which applies
//! the usual policy. Plain values are set as-is. Nothing here reads a secret value.
use anyhow::{Context, Result, anyhow, bail};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quote { Double, Single, Backtick, TripleDouble, TripleBacktick }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `text` has quotes removed and `\<quote>` unescaped; expansion happens later.
    Static { text: String, quote: Option<Quote>, raw: String },
    Call { name: String, args: Vec<Arg>, raw: String },
}

impl Value {
    pub fn raw(&self) -> &str { match self { Value::Static { raw, .. } | Value::Call { raw, .. } => raw } }
    fn text(&self) -> Option<&str> { match self { Value::Static { text, .. } => Some(text), Value::Call { .. } => None } }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg { Pos(Value), Kw(String, Value) }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decorator {
    pub name: String,
    /// `@name=value`
    pub value: Option<Value>,
    /// `@name(args)`
    pub args: Option<Vec<Arg>>,
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub key: String,
    /// None = no value (`KEY=`), distinct from an empty string (`KEY=""`).
    pub value: Option<Value>,
    pub decorators: Vec<Decorator>,
    /// Plain comment lines directly above the item, without the leading `#`.
    pub comments: Vec<String>,
    pub line: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct File {
    pub header: Vec<Decorator>,
    pub header_comments: Vec<String>,
    /// Every plain comment line in the file, in order (header, item and standalone).
    pub all_comments: Vec<String>,
    pub items: Vec<Item>,
}

impl File {
    pub fn get(&self, key: &str) -> Option<&Item> { self.items.iter().rev().find(|i| i.key == key) }
}

// ---------------------------------------------------------------- parser

enum Line { Divider, Comment(String), Decorators(Vec<Decorator>) }

struct P<'a> { b: &'a [u8], s: &'a str, i: usize }

type R<T> = std::result::Result<T, ()>;

impl<'a> P<'a> {
    fn peek(&self) -> Option<u8> { self.b.get(self.i).copied() }
    fn at(&self, lit: &str) -> bool { self.b[self.i..].starts_with(lit.as_bytes()) }
    fn eof(&self) -> bool { self.i >= self.b.len() }
    fn line(&self) -> usize { self.s[..self.i.min(self.s.len())].matches('\n').count() + 1 }
    fn ws(&mut self) { while matches!(self.peek(), Some(b' ' | b'\t')) { self.i += 1; } }
    fn rest_of_line(&mut self) -> &'a str {
        let start = self.i;
        while !matches!(self.peek(), None | Some(b'\n')) { self.i += 1; }
        &self.s[start..self.i]
    }
    /// `_n`: trailing horizontal whitespace then newline or EOF.
    fn eol(&mut self) -> R<()> {
        self.ws();
        match self.peek() { None => Ok(()), Some(b'\n') => { self.i += 1; Ok(()) } _ => Err(()) }
    }
    fn ident(&mut self, extra: &[u8], first_underscore: bool) -> Option<&'a str> {
        let start = self.i;
        match self.peek() { Some(c) if c.is_ascii_alphabetic() || (first_underscore && c == b'_') => self.i += 1, _ => return None }
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || extra.contains(&c)) { self.i += 1; }
        Some(&self.s[start..self.i])
    }

    // ---- comments and decorators

    fn comment_line(&mut self) -> R<Line> {
        debug_assert_eq!(self.peek(), Some(b'#'));
        self.i += 1;
        self.ws();
        let markers = self.b[self.i..].iter().take_while(|c| b"-=*#".contains(c)).count();
        if markers >= 3 { self.rest_of_line(); return Ok(Line::Divider); }
        if self.peek() == Some(b'@') {
            let save = self.i;
            if let Ok(decs) = self.decorators() { return Ok(Line::Decorators(decs)); }
            self.i = save;
        }
        Ok(Line::Comment(self.rest_of_line().trim_end().to_owned()))
    }

    fn decorators(&mut self) -> R<Vec<Decorator>> {
        let mut out = vec![self.decorator()?];
        loop {
            let before = self.i;
            self.ws();
            match self.peek() {
                None | Some(b'\n') => return Ok(out),
                Some(b'#') => { self.rest_of_line(); return Ok(out); }
                Some(b'@') if self.i > before => out.push(self.decorator()?),
                Some(_) if self.i > before => {
                    // Stray text between decorators is ignored, like varlock.
                    while !matches!(self.peek(), None | Some(b' ' | b'\t' | b'\n')) { self.i += 1; }
                }
                Some(_) => return Err(()),
            }
        }
    }

    fn decorator(&mut self) -> R<Decorator> {
        let line = self.line();
        if self.peek() != Some(b'@') { return Err(()); }
        self.i += 1;
        let start = self.i;
        if !matches!(self.peek(), Some(c) if c.is_ascii_alphabetic()) { return Err(()); }
        while !matches!(self.peek(), None | Some(b' ' | b'\t' | b'\n' | b'=' | b'(' | b')' | b'#' | b'@')) { self.i += 1; }
        let name = self.s[start..self.i].to_owned();
        let (value, args) = match self.peek() {
            Some(b'(') => (None, Some(self.args(true)?)),
            Some(b'=') => { self.i += 1; (Some(self.decorator_value()?), None) }
            _ => (None, None),
        };
        Ok(Decorator { name, value, args, line })
    }

    fn decorator_value(&mut self) -> R<Value> {
        if matches!(self.peek(), Some(b'{' | b'[')) { return Err(()); }
        let save = self.i;
        if let Ok(v) = self.call(true) { return Ok(v); }
        self.i = save;
        if let Some(v) = self.quoted()? { return Ok(v); }
        let start = self.i;
        while !matches!(self.peek(), None | Some(b'#' | b' ' | b'\t' | b'\n')) { self.i += 1; }
        if self.i == start { return Err(()); }
        let raw = &self.s[start..self.i];
        Ok(Value::Static { text: raw.to_owned(), quote: None, raw: raw.to_owned() })
    }

    // ---- function calls

    fn call(&mut self, decorator: bool) -> R<Value> {
        let start = self.i;
        let name = self.ident(&[], false).ok_or(())?.to_owned();
        if self.peek() != Some(b'(') { return Err(()); }
        let args = self.args(decorator)?;
        Ok(Value::Call { name, args, raw: self.s[start..self.i].to_owned() })
    }

    /// Whitespace inside args: plain newlines and `#` comments (value context), or
    /// newline + `#` continuation (decorator context).
    fn arg_ws(&mut self, decorator: bool) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t') => self.i += 1,
                Some(b'\n') if !decorator => self.i += 1,
                Some(b'#') if !decorator => { self.rest_of_line(); }
                Some(b'\n' | b'#') if decorator => {
                    let save = self.i;
                    if self.peek() == Some(b'#') {
                        // `# comment` to end of line (but `#tag` is a value).
                        if matches!(self.b.get(self.i + 1), Some(c) if c.is_ascii_alphanumeric()) { return; }
                        self.rest_of_line();
                    }
                    if self.peek() != Some(b'\n') { self.i = save; return; }
                    self.i += 1;
                    self.ws();
                    if self.peek() != Some(b'#') { self.i = save; return; }
                    self.i += 1;
                    self.ws();
                }
                _ => return,
            }
        }
    }

    fn args(&mut self, decorator: bool) -> R<Vec<Arg>> {
        debug_assert_eq!(self.peek(), Some(b'('));
        self.i += 1;
        self.arg_ws(decorator);
        let mut out = Vec::new();
        loop {
            if self.peek() == Some(b')') { self.i += 1; return Ok(out); }
            let save = self.i;
            let kw = match self.ident(&[], false) {
                Some(k) if self.peek() == Some(b'=') => { self.i += 1; Some(k.to_owned()) }
                _ => { self.i = save; None }
            };
            let value = self.arg_value(decorator)?;
            out.push(match kw { Some(k) => Arg::Kw(k, value), None => Arg::Pos(value) });
            self.arg_ws(decorator);
            match self.peek() {
                Some(b',') => { self.i += 1; self.arg_ws(decorator); }
                Some(b')') => {}
                _ => return Err(()),
            }
        }
    }

    fn arg_value(&mut self, decorator: bool) -> R<Value> {
        if matches!(self.peek(), Some(b'{' | b'[')) { return Err(()); }
        let save = self.i;
        if let Ok(v) = self.call(decorator) { return Ok(v); }
        self.i = save;
        if let Some(v) = self.quoted()? { return Ok(v); }
        let start = self.i;
        while !matches!(self.peek(), None | Some(b' ' | b'\n' | b',' | b')')) { self.i += 1; }
        if self.i == start { return Err(()); }
        let raw = &self.s[start..self.i];
        Ok(Value::Static { text: raw.to_owned(), quote: None, raw: raw.to_owned() })
    }

    // ---- strings

    /// Single-line quoted string, or Ok(None) if not at a quote.
    fn quoted(&mut self) -> R<Option<Value>> {
        let (q, quote) = match self.peek() {
            Some(b'"') => (b'"', Quote::Double),
            Some(b'\'') => (b'\'', Quote::Single),
            Some(b'`') => (b'`', Quote::Backtick),
            _ => return Ok(None),
        };
        let start = self.i;
        self.i += 1;
        loop {
            match self.peek() {
                None | Some(b'\n') => return Err(()),
                Some(b'\\') if self.b.get(self.i + 1) == Some(&q) => self.i += 2,
                Some(c) if c == q => { self.i += 1; break; }
                _ => self.i += 1,
            }
        }
        let raw = &self.s[start..self.i];
        let qs = (q as char).to_string();
        let text = raw[1..raw.len() - 1].replace(&format!("\\{qs}"), &qs);
        Ok(Some(Value::Static { text, quote: Some(quote), raw: raw.to_owned() }))
    }

    /// Multi-line strings: `"""…"""`, ```` ```…``` ````, or `"`/`'` spanning lines.
    fn multiline(&mut self) -> R<Option<Value>> {
        let start = self.i;
        for (open, quote) in [("\"\"\"", Quote::TripleDouble), ("```", Quote::TripleBacktick)] {
            if !self.at(open) { continue; }
            self.i += 3;
            let mut newline = false;
            loop {
                if self.eof() { self.i = start; return Ok(None); }
                if self.at(&format!("\\{open}")) { self.i += 4; continue; }
                if self.at(open) { self.i += 3; break; }
                if self.peek() == Some(b'\n') { newline = true; }
                self.i += 1;
            }
            if !newline { self.i = start; return Ok(None); }
            let raw = &self.s[start..self.i];
            let first = &open[..1];
            let text = raw[3..raw.len() - 3].replace(&format!("\\{first}"), first);
            return Ok(Some(Value::Static { text, quote: Some(quote), raw: raw.to_owned() }));
        }
        let (q, quote) = match self.peek() { Some(b'"') => (b'"', Quote::Double), Some(b'\'') => (b'\'', Quote::Single), _ => return Ok(None) };
        self.i += 1;
        let mut newline = false;
        loop {
            match self.peek() {
                None => { self.i = start; return Ok(None); }
                Some(b'\\') if self.b.get(self.i + 1) == Some(&q) => self.i += 2,
                Some(c) if c == q => { self.i += 1; break; }
                Some(b'\n') => { newline = true; self.i += 1; }
                _ => self.i += 1,
            }
        }
        if !newline { self.i = start; return Ok(None); }
        let raw = &self.s[start..self.i];
        let qs = (q as char).to_string();
        let text = raw[1..raw.len() - 1].replace(&format!("\\{qs}"), &qs);
        Ok(Some(Value::Static { text, quote: Some(quote), raw: raw.to_owned() }))
    }

    fn item_value(&mut self) -> R<Option<Value>> {
        self.ws();
        let save = self.i;
        if let Ok(v) = self.call(false) { return Ok(Some(v)); }
        self.i = save;
        if matches!(self.peek(), Some(b'{' | b'[')) {
            // varlock would parse a literal here; we refuse rather than guess.
            let probe = &self.s[self.i..];
            if probe.trim_end().ends_with('}') || probe.trim_end().ends_with(']') { return Err(()); }
        }
        if let Some(v) = self.multiline()? { return Ok(Some(v)); }
        if let Some(v) = self.quoted()? { return Ok(Some(v)); }
        let start = self.i;
        while !matches!(self.peek(), None | Some(b'#' | b'\n')) { self.i += 1; }
        let raw = self.s[start..self.i].trim();
        if raw.is_empty() { return Ok(None); }
        Ok(Some(Value::Static { text: raw.to_owned(), quote: None, raw: raw.to_owned() }))
    }

    fn item(&mut self) -> R<Item> {
        let line = self.line();
        if self.at("export ") { self.i += 7; self.ws(); }
        let key = self.ident(b".-", true).ok_or(())?.to_owned();
        self.ws();
        if self.peek() != Some(b'=') { return Err(()); }
        self.i += 1;
        let value = self.item_value()?;
        self.ws();
        let mut decorators = Vec::new();
        if self.peek() == Some(b'#') && let Line::Decorators(d) = self.comment_line()? { decorators = d; }
        self.eol()?;
        Ok(Item { key, value, decorators, comments: Vec::new(), line })
    }
}

/// Parse a `.env` / `.env.schema` file. Errors carry the line number.
pub fn parse(text: &str) -> Result<File> {
    let normalized = text.replace("\r\n", "\n");
    let s = normalized.as_str();
    let mut p = P { b: s.as_bytes(), s, i: 0 };
    let mut file = File::default();
    // Comment block since the last blank line/divider: (comment text, decorators).
    let mut pending: Vec<Line> = Vec::new();
    let flush_header = |file: &mut File, pending: &mut Vec<Line>, seen_item: bool| {
        for l in pending.drain(..) {
            if seen_item { continue; }
            match l { Line::Comment(c) => file.header_comments.push(c), Line::Decorators(d) => file.header.extend(d), _ => {} }
        }
    };
    let mut seen_item = false;
    loop {
        p.ws();
        let Some(c) = p.peek() else { flush_header(&mut file, &mut pending, seen_item); break; };
        let line = p.line();
        match c {
            b'\n' => { p.i += 1; flush_header(&mut file, &mut pending, seen_item); }
            b'#' => {
                let l = p.comment_line().map_err(|_| anyhow!("line {line}: invalid comment"))?;
                p.eol().map_err(|_| anyhow!("line {line}: unexpected text after comment"))?;
                match l {
                    Line::Divider => flush_header(&mut file, &mut pending, seen_item),
                    Line::Comment(c) => { file.all_comments.push(c.clone()); pending.push(Line::Comment(c)); }
                    other => pending.push(other),
                }
            }
            _ => {
                let mut item = p.item().map_err(|_| anyhow!("line {line}: invalid line (expected KEY=value)"))?;
                let mut decorators = Vec::new();
                for l in pending.drain(..) {
                    match l { Line::Comment(c) => item.comments.push(c), Line::Decorators(d) => decorators.extend(d), _ => {} }
                }
                decorators.append(&mut item.decorators);
                item.decorators = decorators;
                file.items.push(item);
                seen_item = true;
            }
        }
    }
    Ok(file)
}

// ---------------------------------------------------------------- schema

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeSpec { String, Number, Boolean, Url, Port, Email, Enum(Vec<String>) }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub source: Source,
    pub sensitive: bool,
    pub required: bool,
    pub kind: Option<TypeSpec>,
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// `karambit(ref)`: resolved by the daemon under policy.
    Secret(String),
    /// Plain value (expanded at run time), or None for `KEY=`.
    Plain(Option<(String, Option<Quote>)>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schema {
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
    /// `# karambit-archive: ns/name` comments written by `karambit secure`.
    pub archives: Vec<String>,
}

const KNOWN_ROOT_IGNORED: &[&str] = &["plugin", "import", "currentEnv", "envFlag", "generateTypes", "generateTsTypes",
    "redactLogs", "preventLeaks", "disable", "defaultDynamic", "injectUndefinedAsEmpty", "cache", "setValuesBulk"];
const KNOWN_ITEM_IGNORED: &[&str] = &["docs", "docsUrl", "example", "description", "icon", "deprecated", "tag", "dynamic", "internal"];

fn bool_of(d: &Decorator, warnings: &mut Vec<String>) -> bool {
    match &d.value {
        None => true,
        Some(Value::Static { text, .. }) => match text.as_str() { "true" => true, "false" => false, other => {
            warnings.push(format!("line {}: @{}={other} is not true/false; treated as true", d.line, d.name));
            true
        } },
        Some(Value::Call { name, .. }) => {
            warnings.push(format!("line {}: @{}={name}(...) is not supported; treated as false", d.line, d.name));
            false
        }
    }
}

fn type_of(d: &Decorator) -> Result<Option<TypeSpec>> {
    let (name, args) = match &d.value {
        Some(Value::Static { text, .. }) => (text.as_str(), Vec::new()),
        Some(Value::Call { name, args, .. }) => (name.as_str(), args.clone()),
        None => bail!("line {}: @type needs a value", d.line),
    };
    Ok(match name {
        "string" => Some(TypeSpec::String),
        "number" | "integer" => Some(TypeSpec::Number),
        "boolean" => Some(TypeSpec::Boolean),
        "url" => Some(TypeSpec::Url),
        "port" => Some(TypeSpec::Port),
        "email" => Some(TypeSpec::Email),
        "enum" => Some(TypeSpec::Enum(args.iter().filter_map(|a| match a { Arg::Pos(v) => v.text().map(str::to_owned), Arg::Kw(..) => None }).collect())),
        _ => None,
    })
}

/// Turn a parsed file into run entries. Pure: no environment, no I/O.
pub fn compile(file: &File) -> Result<Schema> {
    let archives = file.all_comments.iter().filter_map(|c| c.strip_prefix("karambit-archive:")).map(|r| r.trim().to_owned()).collect();
    let mut schema = Schema { archives, ..Default::default() };
    let mut default_required = false;
    for d in &file.header {
        match d.name.as_str() {
            "defaultRequired" => default_required = bool_of(d, &mut schema.warnings),
            "defaultSensitive" => {}
            n if KNOWN_ROOT_IGNORED.contains(&n) => {
                let karambit_plugin = n == "plugin" && d.args.as_ref().is_some_and(|a| matches!(a.first(), Some(Arg::Pos(v)) if v.raw().contains("karambit")));
                if !karambit_plugin { schema.warnings.push(format!("line {}: @{n} is ignored by Karambit", d.line)); }
            }
            n => schema.warnings.push(format!("line {}: unknown root decorator @{n}", d.line)),
        }
    }
    let mut seen = std::collections::BTreeMap::new();
    for item in &file.items {
        let mut entry = Entry { key: item.key.clone(), source: Source::Plain(None), sensitive: false, required: default_required, kind: None, line: item.line };
        for d in &item.decorators {
            match d.name.as_str() {
                "sensitive" => entry.sensitive = bool_of(d, &mut schema.warnings),
                "required" => entry.required = bool_of(d, &mut schema.warnings),
                "optional" => entry.required = !bool_of(d, &mut schema.warnings),
                "type" => {
                    entry.kind = type_of(d)?;
                    if entry.kind.is_none() { schema.warnings.push(format!("line {}: @type={} is not checked by Karambit", d.line, d.value.as_ref().map_or("", Value::raw))); }
                }
                n if KNOWN_ITEM_IGNORED.contains(&n) => {}
                n => schema.warnings.push(format!("line {}: unknown decorator @{n} on {}", d.line, item.key)),
            }
        }
        entry.source = match &item.value {
            None => Source::Plain(None),
            Some(Value::Static { text, quote, .. }) => Source::Plain(Some((text.clone(), *quote))),
            Some(Value::Call { name, args, .. }) if name == "karambit" => {
                let [Arg::Pos(Value::Static { text, .. })] = args.as_slice() else {
                    bail!("line {}: {}: karambit() takes one reference, e.g. karambit(myapp/{})", item.line, item.key, item.key);
                };
                if text.contains('$') { bail!("line {}: {}: karambit() references can't use $ expansion", item.line, item.key); }
                Source::Secret(text.clone())
            }
            Some(Value::Call { name, .. }) => bail!("line {}: {}: {name}() is not supported; store the value with `karambit secure` and use karambit(ns/name)", item.line, item.key),
        };
        if entry.sensitive && matches!(&entry.source, Source::Plain(Some((t, _))) if !t.is_empty()) {
            schema.warnings.push(format!("line {}: {} is @sensitive but has a plaintext value in this file; move it into Karambit", item.line, item.key));
        }
        if let Some(prev) = seen.insert(item.key.clone(), schema.entries.len()) {
            schema.warnings.push(format!("line {}: {} is set again; the last one wins", item.line, item.key));
            schema.entries[prev] = entry;
        } else {
            schema.entries.push(entry);
        }
    }
    Ok(schema)
}

impl Schema {
    /// `(VAR, reference)` pairs for the daemon.
    pub fn secrets(&self) -> Result<Vec<(String, String)>> {
        self.entries.iter().filter_map(|e| match &e.source { Source::Secret(r) => Some((e, r)), Source::Plain(_) => None })
            .map(|(e, r)| Ok((crate::valid_var(&e.key).with_context(|| format!("line {}", e.line))?, r.clone())))
            .collect()
    }

    /// Plain values to set, after expansion and checks. `ambient` wins over the file
    /// (like dotenv: an already-set variable is not overwritten), so ambient keys are
    /// left out of the result.
    pub fn plain(&self, ambient: &dyn Fn(&str) -> Option<String>) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        for e in &self.entries {
            let Source::Plain(declared) = &e.source else { continue; };
            // Refused even if the ambient value would win: the schema is auto-trusted, so a
            // planted line must fail loudly instead of being inert only until the shell changes.
            if declared.is_some() { crate::env::refuse_code_loading_plain(&e.key).with_context(|| format!("line {}", e.line))?; }
            let value = match ambient(&e.key) {
                Some(v) => { check_type(e, &v)?; continue; }
                None => self.resolve(&e.key, ambient, &mut Vec::new())?,
            };
            match value {
                None if e.required => bail!("line {}: {} is required but has no value", e.line, e.key),
                None => {}
                Some(v) => { check_type(e, &v)?; out.push((crate::valid_var(&e.key).with_context(|| format!("line {}", e.line))?, v)); }
            }
        }
        Ok(out)
    }

    fn resolve(&self, key: &str, ambient: &dyn Fn(&str) -> Option<String>, stack: &mut Vec<String>) -> Result<Option<String>> {
        if stack.iter().any(|k| k == key) { bail!("{key}: circular ${{}} reference ({})", stack.join(" -> ")); }
        let Some(e) = self.entries.iter().find(|e| e.key == key) else { return Ok(ambient(key)); };
        match &e.source {
            Source::Secret(_) => bail!("line {}: a plain value can't reference the secret {key}", e.line),
            Source::Plain(None) => Ok(None),
            Source::Plain(Some((text, quote))) => {
                stack.push(key.to_owned());
                let v = expand(text, *quote, &mut |name: &str| {
                    if self.entries.iter().any(|x| x.key == name) {
                        if let Some(v) = ambient(name) { return Ok(Some(v)); }
                        self.resolve(name, ambient, stack)
                    } else { Ok(ambient(name)) }
                }).with_context(|| format!("line {}: {key}", e.line))?;
                stack.pop();
                Ok(Some(v))
            }
        }
    }
}

fn check_type(e: &Entry, v: &str) -> Result<()> {
    let ok = match &e.kind {
        None | Some(TypeSpec::String) => true,
        Some(TypeSpec::Number) => v.trim().parse::<f64>().is_ok_and(f64::is_finite),
        Some(TypeSpec::Boolean) => matches!(v.to_ascii_lowercase().as_str(), "true" | "false" | "1" | "0"),
        Some(TypeSpec::Url) => v.split_once("://").is_some_and(|(s, rest)| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b)) && !rest.is_empty()),
        Some(TypeSpec::Port) => v.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p)),
        Some(TypeSpec::Email) => v.split_once('@').is_some_and(|(a, d)| !a.is_empty() && d.contains('.')),
        Some(TypeSpec::Enum(opts)) => opts.iter().any(|o| o == v),
    };
    if !ok { bail!("line {}: {} = {v:?} does not match @type", e.line, e.key); }
    Ok(())
}

/// `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `$VAR`; `\$` is a literal `$`.
/// Single-quoted values are literal. `\n` becomes a newline in `"…"` and `` `…` ``.
pub fn expand(text: &str, quote: Option<Quote>, lookup: &mut dyn FnMut(&str) -> Result<Option<String>>) -> Result<String> {
    if quote == Some(Quote::Single) { return Ok(text.to_owned()); }
    let newlines = matches!(quote, Some(Quote::Double | Quote::Backtick));
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let name_at = |i: usize, dots: bool| {
        let mut j = i;
        if j < b.len() && (b[j].is_ascii_alphabetic() || b[j] == b'_') { j += 1; } else { return i; }
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || (dots && b[j] == b'.')) { j += 1; }
        j
    };
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1) == Some(&b'$') => { out.push('$'); i += 2; }
            b'\\' if newlines && b.get(i + 1) == Some(&b'n') => { out.push('\n'); i += 2; }
            b'$' if b.get(i + 1) == Some(&b'(') => bail!("$(...) command expansion is not supported"),
            b'$' if b.get(i + 1) == Some(&b'{') => {
                let end = text[i..].find('}').map(|e| i + e).context("unclosed ${")?;
                let inner = &text[i + 2..end];
                let n = name_at(i + 2, true) - (i + 2);
                if n == 0 { bail!("invalid ${{{inner}}}"); }
                let (name, rest) = inner.split_at(n);
                let value = lookup(name)?;
                out.push_str(&match rest {
                    "" => value.unwrap_or_default(),
                    r if r.starts_with(":-") => value.filter(|v| !v.is_empty()).unwrap_or_else(|| r[2..].to_owned()),
                    r if r.starts_with('-') => value.unwrap_or_else(|| r[1..].to_owned()),
                    _ => bail!("invalid ${{{inner}}}"),
                });
                i = end + 1;
            }
            b'$' if name_at(i + 1, false) > i + 1 => {
                let end = name_at(i + 1, false);
                out.push_str(&lookup(&text[i + 1..end])?.unwrap_or_default());
                i = end;
            }
            _ => {
                let ch = text[i..].chars().next().unwrap_or_default();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    Ok(out)
}

/// Load a profile file for `run`: `.schema` files use @env-spec, others the legacy
/// `VAR=ref` format. Returns secret assignments.
pub fn profile_specs(path: &std::path::Path, text: &str) -> Result<Vec<(String, String)>> {
    if is_schema_path(path) { compile(&parse(text)?)?.secrets() } else { crate::parse_env_file(text) }
}

pub fn is_schema_path(path: &std::path::Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".schema"))
}

#[cfg(test)]
mod tests {
    //! Cases ported from varlock's env-spec-parser tests (values/decorators/header).
    use super::*;

    fn val(input: &str) -> std::result::Result<Option<String>, ()> {
        let f = parse(&format!("VAL={input}")).map_err(|_| ())?;
        Ok(match &f.items[0].value {
            None => None,
            Some(Value::Static { text, .. }) => Some(text.clone()),
            Some(Value::Call { name, args, .. }) => Some(format!("{name}({})", args.iter().map(|a| match a {
                Arg::Pos(v) => v.text().unwrap_or("?").to_owned(),
                Arg::Kw(k, v) => format!("{k}={}", v.text().unwrap_or("?")),
            }).collect::<Vec<_>>().join("|"))),
        })
    }
    fn ok(input: &str, want: &str) { assert_eq!(val(input), Ok(Some(want.to_owned())), "{input:?}"); }
    fn none(input: &str) { assert_eq!(val(input), Ok(None), "{input:?}"); }
    fn err(input: &str) { assert!(val(input).is_err(), "{input:?} should fail"); }

    #[test]
    fn strings_and_quotes() {
        none("");
        ok("\"\"", "");
        ok("unquoted", "unquoted");
        ok("inner\"'`quotes", "inner\"'`quotes");
        ok("'squote'", "squote");
        ok("\"dquote\"", "dquote");
        ok("`backtick`", "backtick");
        ok("\"this has spaces\"", "this has spaces");
        ok("\"mixed`quote\"", "mixed`quote");
        ok("\"escaped\\\"quote\"", "escaped\"quote");
        ok("unquoted spaces", "unquoted spaces");
        ok("  extra-spaces  ", "extra-spaces");
        err("'not'escaped'");
        err("\"not ok");
        err(" \"not ok");
    }

    #[test]
    fn multi_line_strings() {
        ok("\"this\nhas\nmultiple\nlines\"", "this\nhas\nmultiple\nlines");
        ok("\"with\\\"escaped\nquotes\"", "with\"escaped\nquotes");
        ok("\"with #comments\ninside\" # and after", "with #comments\ninside");
        ok("\"\"\"triple quotes\nalso work\"\"\"", "triple quotes\nalso work");
        ok("\"\"\"\n  hello\n\"\"\"", "\n  hello\n");
        ok("```triple backticks\nalso work```", "triple backticks\nalso work");
        ok("```check `internal` quotes \\```\nare ok```", "check `internal` quotes ```\nare ok");
        err("\"\"\"triple quotes on one line are not ok\"\"\"");
        err("\"\"\"no end");
        err("\"\"\"no end\nagain");
    }

    #[test]
    fn function_calls() {
        ok("foo()", "foo()");
        ok("foo( )", "foo()");
        ok("\"foo()\"", "foo()");
        ok("bad-fn-name()", "bad-fn-name()");
        ok("0badFn()", "0badFn()");
        ok("foo(abc,true,123)", "foo(abc|true|123)");
        ok("foo( 1 , 2 , 3 )", "foo(1|2|3)");
        ok("foo( 'sq' , \"dq\" , `bt`, nq )", "foo(sq|dq|bt|nq)");
        ok("foo(unq#uoted)", "foo(unq#uoted)");
        ok("foo(key1=foo, key2=bar)", "foo(key1=foo|key2=bar)");
        ok("foo(key1=123, key2=\"\\\")#\")", "foo(key1=123|key2=\")#)");
        ok("karambit(myapp/STRIPE_KEY)", "karambit(myapp/STRIPE_KEY)");
        ok("karambit(team-vault:secret/app#db)", "karambit(team-vault:secret/app#db)");
    }

    #[test]
    fn post_comments_and_paths() {
        none("#comment");
        none(" #comment");
        none("#");
        ok("foo#comment", "foo");
        ok("\"foo\" #comment", "foo");
        ok("\"foo#comment\"#more", "foo#comment");
        ok("123 # @dec", "123");
        ok("foo(fn#arg) #post-comment", "foo(fn#arg)");
        ok("/folder/foo/bar", "/folder/foo/bar");
        ok("foo(/some/path, bar)", "foo(/some/path|bar)");
    }

    #[test]
    fn decorators_and_header() {
        let f = parse("# header text\n# @defaultRequired\n# ---\nVAL=foo").unwrap();
        assert_eq!(f.header.len(), 1);
        assert_eq!(f.header[0].name, "defaultRequired");
        let f = parse("# header text\n# @defaultRequired\n\nVAL=foo").unwrap();
        assert_eq!(f.header.len(), 1, "header without divider");
        assert!(parse("VAL=foo").unwrap().header.is_empty());
        let f = parse("# desc line\n# this @decorator is ignored\n# @sensitive=false @required # trailing\n# @type=enum(dev, test)\nVAL=dev").unwrap();
        assert!(f.header.is_empty(), "comments directly above an item belong to it");
        let names: Vec<_> = f.items[0].decorators.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["sensitive", "required", "type"]);
        assert_eq!(f.items[0].comments, ["desc line", "this @decorator is ignored"]);
        let d = &parse("# @dec=foo#bar\nX=1").unwrap().items[0].decorators[0];
        assert_eq!(d.value.as_ref().unwrap().text(), Some("foo"));
        let d = &parse("# @dec=\"@#\\\"()\"\nX=1").unwrap().items[0].decorators[0];
        assert_eq!(d.value.as_ref().unwrap().text(), Some("@#\"()"));
        let d = &parse("# @import(../some/path)\n\nX=1").unwrap().header[0];
        assert!(matches!(d.args.as_deref(), Some([Arg::Pos(v)]) if v.text() == Some("../some/path")));
        let f = parse("# @docs(https://x.dev,\n#   https://y.dev)\nX=1").unwrap();
        assert!(matches!(f.items[0].decorators[0].args.as_deref(), Some([_, _])), "decorator args continue with #");
        let f = parse("export A=1\r\nB = two # @sensitive\n").unwrap();
        assert_eq!((f.items[0].key.as_str(), f.items[1].key.as_str()), ("A", "B"));
        assert_eq!(f.items[1].decorators[0].name, "sensitive");
    }

    #[test]
    fn compile_secrets_and_plain() {
        let s = compile(&parse("# karambit-archive: app/_archive/1/env\n# @defaultRequired=false\n# ---\nPORT=3000\n# @sensitive\nSTRIPE_KEY=karambit(app/STRIPE_KEY)\n").unwrap()).unwrap();
        assert_eq!(s.archives, ["app/_archive/1/env"]);
        assert_eq!(s.secrets().unwrap(), [("STRIPE_KEY".to_owned(), "app/STRIPE_KEY".to_owned())]);
        assert_eq!(s.plain(&|_| None).unwrap(), [("PORT".to_owned(), "3000".to_owned())]);
        assert!(s.warnings.is_empty(), "{:?}", s.warnings);
        assert!(compile(&parse("A=op(op://x/y)").unwrap()).unwrap_err().to_string().contains("op() is not supported"));
        assert!(compile(&parse("A=karambit(a, b)").unwrap()).is_err());
        assert!(compile(&parse("A=karambit(${X})").unwrap()).is_err());
    }

    #[test]
    fn expansion_ambient_and_checks() {
        let s = compile(&parse("HOST=localhost\nPORT=8080\nURL=http://${HOST}:$PORT/x\nLIT='$HOST'\nESC=\\$HOST\nDEF=${NOPE:-fallback}\nNL=\"a\\nb\"\n").unwrap()).unwrap();
        let env = s.plain(&|_| None).unwrap();
        let get = |k: &str| env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
        assert_eq!(get("URL").as_deref(), Some("http://localhost:8080/x"));
        assert_eq!(get("LIT").as_deref(), Some("$HOST"));
        assert_eq!(get("ESC").as_deref(), Some("$HOST"));
        assert_eq!(get("DEF").as_deref(), Some("fallback"));
        assert_eq!(get("NL").as_deref(), Some("a\nb"));
        // Ambient wins and is left out; expansion sees the ambient value.
        let env = s.plain(&|k| (k == "HOST").then(|| "prod.example".to_owned())).unwrap();
        assert!(env.iter().all(|(k, _)| k != "HOST"));
        assert!(env.contains(&("URL".into(), "http://prod.example:8080/x".into())));
        assert!(compile(&parse("A=$(whoami)").unwrap()).unwrap().plain(&|_| None).is_err(), "no command execution");
        assert!(compile(&parse("A=$B\nB=$A").unwrap()).unwrap().plain(&|_| None).is_err(), "cycle");
        assert!(compile(&parse("S=karambit(a/b)\nA=${S}").unwrap()).unwrap().plain(&|_| None).is_err(), "no secret in plain");
        assert!(compile(&parse("# @required\nA=").unwrap()).unwrap().plain(&|_| None).is_err());
        assert!(compile(&parse("# @type=port\nA=99999").unwrap()).unwrap().plain(&|_| None).is_err());
        assert!(compile(&parse("# @type=enum(dev, prod)\nA=dev").unwrap()).unwrap().plain(&|_| None).is_ok());
        assert!(compile(&parse("# @type=url\nA=nope").unwrap()).unwrap().plain(&|_| None).is_err());
    }

    #[test]
    fn plain_code_loading_names_are_refused_even_when_ambient_is_set() {
        for name in ["NODE_OPTIONS", "PYTHONPATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "npm_config_node_options"] {
            let s = compile(&parse(&format!("{name}=--require ./x.js")).unwrap()).unwrap();
            let err = s.plain(&|_| None).unwrap_err();
            assert!(format!("{err:#}").contains("can't be a plain value"), "{name}: {err:#}");
            assert!(s.plain(&|k| (k == name).then(|| "set".to_owned())).is_err(), "{name} with ambient");
        }
        // A bare declaration injects nothing; a secret reference is a human-stored value.
        let s = compile(&parse("NODE_OPTIONS=\n# @sensitive\nRUBYOPT=karambit(app/RUBYOPT)\nNODE_ENV=dev").unwrap()).unwrap();
        assert_eq!(s.plain(&|_| None).unwrap(), [("NODE_ENV".to_owned(), "dev".to_owned())]);
    }

    #[test]
    fn warnings() {
        let s = compile(&parse("# @plugin(@varlock/1password-plugin)\n# ---\n# @sensitive\nA=plain-secret\n# @whatever\nB=1\nB=2").unwrap()).unwrap();
        let all = s.warnings.join("\n");
        assert!(all.contains("@plugin is ignored"));
        assert!(all.contains("A is @sensitive but has a plaintext value"));
        assert!(all.contains("unknown decorator @whatever"));
        assert!(all.contains("B is set again"));
        assert_eq!(s.entries.len(), 2);
        let s = compile(&parse("# @plugin(@karambit/varlock-plugin)\n# ---\nA=1").unwrap()).unwrap();
        assert!(s.warnings.is_empty());
    }
}
