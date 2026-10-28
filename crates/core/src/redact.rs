//! Streaming redaction: replaces every known secret value in a byte stream with
//! `[REDACTED:name]`, including matches split across read boundaries.

use aho_corasick::{AhoCorasick, MatchKind};
use std::io::{Read, Write};
use std::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

/// Values shorter than this are not redacted (would shred normal output).
pub const MIN_REDACT_LEN: usize = 4;

/// Long secrets are also matched as overlapping fragments, so a truncated or
/// wrapped copy (e.g. `cut -c1-70`, a log line cut at N chars) is still caught.
/// With CHUNK=16 / STRIDE=8, any substring of >= CHUNK+STRIDE-1 chars contains
/// a whole fragment, so at most ~STRIDE-1 chars can survive at each edge.
const CHUNK: usize = 16;
const STRIDE: usize = 8;
const CHUNK_FROM: usize = 32;

/// The automaton and its per-pattern tables, rebuilt as a unit when values are added.
struct Matcher {
    ac: Option<AhoCorasick>,
    repl: Vec<Vec<u8>>,
    /// Which secret each pattern belongs to (fragments share their parent's id).
    owner: Vec<usize>,
    keep: usize,
}

pub struct Redactor {
    matcher: RwLock<Matcher>,
    /// Every usable value ever registered, kept to rebuild the automaton in `add`.
    known: Mutex<Vec<(String, Zeroizing<Vec<u8>>)>>,
}

impl Matcher {
    fn build(secrets: &[(String, &[u8])]) -> Matcher {
        let usable: Vec<&(String, &[u8])> =
            secrets.iter().filter(|(_, v)| v.len() >= MIN_REDACT_LEN).collect();
        if usable.is_empty() {
            return Matcher { ac: None, repl: vec![], owner: vec![], keep: 0 };
        }
        let mut pats: Vec<&[u8]> = Vec::new();
        let mut owner = Vec::new();
        // Whole values first; LeftmostLongest still prefers a full match over a fragment.
        for (i, (_, v)) in usable.iter().enumerate() {
            pats.push(v);
            owner.push(i);
        }
        for (i, (_, v)) in usable.iter().enumerate() {
            if v.len() >= CHUNK_FROM {
                let mut s = 0;
                while s + CHUNK <= v.len() {
                    pats.push(&v[s..s + CHUNK]);
                    owner.push(i);
                    s += STRIDE;
                }
                pats.push(&v[v.len() - CHUNK..]);
                owner.push(i);
            }
        }
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&pats)
            .expect("aho-corasick build");
        let keep = usable.iter().map(|(_, v)| v.len()).max().unwrap_or(1) - 1;
        let repl = usable.iter().map(|(n, _)| format!("[REDACTED:{n}]").into_bytes()).collect();
        Matcher { ac: Some(ac), repl, owner, keep }
    }
}

impl Redactor {
    pub fn new(secrets: &[(String, &[u8])]) -> Redactor {
        let known = secrets.iter().filter(|(_, v)| v.len() >= MIN_REDACT_LEN)
            .map(|(n, v)| (n.clone(), Zeroizing::new(v.to_vec()))).collect();
        Redactor { matcher: RwLock::new(Matcher::build(secrets)), known: Mutex::new(known) }
    }

    /// Learn more values while output is being pumped (e.g. role credentials minted
    /// mid-run). Returns once the new automaton is live, so a caller that acknowledges
    /// afterwards guarantees any later `process` call already redacts them.
    pub fn add(&self, secrets: &[(String, &[u8])]) {
        let mut known = self.known.lock().unwrap();
        for (name, value) in secrets.iter().filter(|(_, v)| v.len() >= MIN_REDACT_LEN) {
            if !known.iter().any(|(n, v)| n == name && v.as_slice() == *value) {
                known.push((name.clone(), Zeroizing::new(value.to_vec())));
            }
        }
        let all: Vec<(String, &[u8])> = known.iter().map(|(n, v)| (n.clone(), v.as_slice())).collect();
        *self.matcher.write().unwrap() = Matcher::build(&all);
    }

    /// Consume `buf`, returning bytes safe to emit. Holds back `keep` bytes unless `eof`.
    pub fn process(&self, buf: &mut Vec<u8>, eof: bool) -> Vec<u8> {
        let matcher = self.matcher.read().unwrap();
        let Some(ac) = &matcher.ac else { return std::mem::take(buf) };
        let limit = if eof { buf.len() } else { buf.len().saturating_sub(matcher.keep) };
        let mut out = Vec::with_capacity(buf.len());
        let mut pos = 0;
        let mut last: Option<usize> = None;
        // Any match starting before `limit` fits entirely inside buf (len <= keep+1).
        for hit in ac.find_iter(buf.as_slice()) {
            if hit.start() >= limit {
                break;
            }
            let who = matcher.owner[hit.pattern().as_usize()];
            out.extend_from_slice(&buf[pos..hit.start()]);
            // Back-to-back fragments of the same secret collapse into one marker.
            if !(hit.start() == pos && last == Some(who)) {
                out.extend_from_slice(&matcher.repl[who]);
            }
            last = Some(who);
            pos = hit.end();
        }
        let flush_to = pos.max(limit);
        out.extend_from_slice(&buf[pos..flush_to]);
        buf.drain(..flush_to);
        out
    }

    /// Pump `r` -> `w` until EOF, redacting. Flushes eagerly so interactive output stays live.
    pub fn pump(&self, r: impl Read, w: impl Write) -> std::io::Result<()> {
        self.pump_watch(r, w, &[]).map(|_| ())
    }

    /// Like `pump`, but also reports whether any of `watch` appeared in the
    /// (redacted) output, e.g. "ExpiredToken" so the caller can add a hint.
    pub fn pump_watch(&self, mut r: impl Read, mut w: impl Write, watch: &[&str]) -> std::io::Result<bool> {
        let mut chunk = [0u8; 16 * 1024];
        let mut buf = Vec::new();
        let mut seen = false;
        let mut tail: Vec<u8> = Vec::new();
        let mut scan = |out: &[u8]| {
            if seen || watch.is_empty() {
                return;
            }
            tail.extend_from_slice(out);
            let s = String::from_utf8_lossy(&tail);
            seen = watch.iter().any(|p| s.contains(p));
            let keep = tail.len().saturating_sub(64);
            tail.drain(..keep);
        };
        loop {
            let n = match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            buf.extend_from_slice(&chunk[..n]);
            let out = self.process(&mut buf, false);
            if !out.is_empty() {
                scan(&out);
                w.write_all(&out)?;
                w.flush()?;
            }
        }
        let out = self.process(&mut buf, true);
        scan(&out);
        w.write_all(&out)?;
        w.flush()?;
        Ok(seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(r: &Redactor, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        r.pump(input, &mut out).unwrap();
        out
    }

    #[test]
    fn add_teaches_new_values_without_forgetting_old_ones() {
        let r = Redactor::new(&[("first".into(), b"first-secret".as_slice())]);
        assert_eq!(run(&r, b"role-secret-value"), b"role-secret-value");
        r.add(&[("role".into(), b"role-secret-value".as_slice())]);
        assert_eq!(run(&r, b"a first-secret b role-secret-value c"), b"a [REDACTED:first] b [REDACTED:role] c");
        // Re-adding is harmless and too-short values stay ignored.
        r.add(&[("role".into(), b"role-secret-value".as_slice()), ("tiny".into(), b"abc".as_slice())]);
        assert_eq!(run(&r, b"abc role-secret-value"), b"abc [REDACTED:role]");
    }

    #[test]
    fn add_to_an_empty_redactor_and_across_split_reads() {
        let r = Redactor::new(&[]);
        let long = b"ASIAEXAMPLEEXAMPLEEXAMPLEEXAMPLE0123456789abcdef";
        r.add(&[("late".into(), long.as_slice())]);
        // A value split across read boundaries is held back until it can be decided.
        let mut buf = Vec::new();
        let mut out = Vec::new();
        for part in [&long[..10], &long[10..30], &long[30..]] {
            buf.extend_from_slice(part);
            out.extend(r.process(&mut buf, false));
        }
        out.extend(r.process(&mut buf, true));
        assert_eq!(out, b"[REDACTED:late]");
    }

    #[test]
    fn add_while_another_thread_pumps() {
        let r = std::sync::Arc::new(Redactor::new(&[("first".into(), b"first-secret".as_slice())]));
        let adder = { let r = r.clone(); std::thread::spawn(move || for i in 0..50 { r.add(&[(format!("v{i}"), format!("late-value-{i:03}").as_bytes())]); }) };
        for _ in 0..50 { assert_eq!(run(&r, b"x first-secret y"), b"x [REDACTED:first] y"); }
        adder.join().unwrap();
        assert_eq!(run(&r, b"late-value-049"), b"[REDACTED:v49]");
    }
}
