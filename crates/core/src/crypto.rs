//! Envelope crypto.
//!
//! secret plaintext --ChaCha20-Poly1305(DEK)--> ct
//! DEK --ChaCha20-Poly1305(KEK)--> wrapped_dek
//! KEK = HKDF-SHA256(ECDH(eph, SE tier key), salt = eph_pub || se_pub, info = "karambit/v1/wrap")
//! DEK --age x25519--> backup   (offline recovery when SE keys are lost)
//!
//! Wrapping only needs the SE *public* key, so upgrading a secret to the bio tier
//! never prompts; unwrapping needs the SE private key (Touch ID for bio).

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use p256::{PublicKey, ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

use crate::store::{SecretFile, Tier};

pub type Dek = Zeroizing<[u8; 32]>;

pub fn new_dek() -> Dek {
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k.as_mut());
    k
}

fn cipher(k: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(*k))
}

fn nonce_of(b: &[u8]) -> Result<Nonce> {
    let a: [u8; 12] = b.try_into().map_err(|_| anyhow!("bad nonce"))?;
    Ok(Nonce::from(a))
}

fn nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    OsRng.fill_bytes(&mut n);
    n
}

/// Version written by this build. v2 binds `public` into the wrap AAD so it can't
/// be flipped on by editing the JSON; v1 files (no `public`) still decrypt.
pub const CURRENT_V: u32 = 2;

/// Wrap AAD binds the DEK to policy fields. Editing `tier`, `agent_allowed` or
/// (v2) `public` in the JSON makes unwrap fail, so relaxing policy requires a
/// real rewrap (= Touch ID for a bio secret).
fn aad(v: u32, name: &str, tier: Tier, agent_allowed: bool, public: bool) -> Vec<u8> {
    if v >= 2 {
        format!("karambit/v2/dek/{}/{}/{}/{name}", tier.as_str(), agent_allowed as u8, public as u8)
            .into_bytes()
    } else {
        format!("karambit/v1/dek/{}/{}/{name}", tier.as_str(), agent_allowed as u8).into_bytes()
    }
}

fn kek(shared: &[u8], eph_pub: &[u8], se_pub: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut salt = Vec::with_capacity(eph_pub.len() + se_pub.len());
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(se_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(b"karambit/v1/wrap", out.as_mut()).expect("hkdf len");
    out
}

pub struct Wrapped {
    pub eph: String,
    pub wrap_nonce: String,
    pub wrapped_dek: String,
}

/// Wrap a DEK to an SE public key (x963 / SEC1 uncompressed). No SE access needed.
#[allow(clippy::too_many_arguments)]
pub fn wrap_dek(
    dek: &Dek,
    se_pub_x963: &[u8],
    name: &str,
    tier: Tier,
    agent_allowed: bool,
    public: bool,
) -> Result<Wrapped> {
    wrap_with_aad(dek, se_pub_x963, &aad(CURRENT_V, name, tier, agent_allowed, public))
}

/// Wrap a DEK to an SE public key under an arbitrary AAD (used for leases).
pub fn wrap_with_aad(dek: &Dek, se_pub_x963: &[u8], aad_bytes: &[u8]) -> Result<Wrapped> {
    let se_pub = PublicKey::from_sec1_bytes(se_pub_x963).context("bad SE public key")?;
    let eph = EphemeralSecret::random(&mut OsRng);
    let eph_pub = eph.public_key().to_encoded_point(false);
    let shared = eph.diffie_hellman(&se_pub);
    let k = kek(shared.raw_secret_bytes(), eph_pub.as_bytes(), se_pub_x963);
    let n = nonce();
    let ct = cipher(&k)
        .encrypt(&Nonce::from(n), Payload { msg: dek.as_ref(), aad: aad_bytes })
        .map_err(|_| anyhow!("wrap failed"))?;
    Ok(Wrapped {
        eph: B64.encode(eph_pub.as_bytes()),
        wrap_nonce: B64.encode(n),
        wrapped_dek: B64.encode(ct),
    })
}

/// Inverse of `wrap_with_aad`, given the SE-computed shared secret for `w.eph`.
pub fn unwrap_with_aad(w: &Wrapped, shared: &[u8], se_pub_x963: &[u8], aad_bytes: &[u8]) -> Result<Dek> {
    let eph = B64.decode(&w.eph)?;
    let k = kek(shared, &eph, se_pub_x963);
    let n = B64.decode(&w.wrap_nonce)?;
    let ct = B64.decode(&w.wrapped_dek)?;
    let mut pt = cipher(&k)
        .decrypt(&nonce_of(&n)?, Payload { msg: &ct, aad: aad_bytes })
        .map_err(|_| anyhow!("unwrap failed (wrong key or tampered file)"))?;
    to_dek(&mut pt)
}

/// Unwrap using the shared secret the SE helper computed for `f.eph`.
pub fn unwrap_dek(f: &SecretFile, shared: &[u8], se_pub_x963: &[u8]) -> Result<Dek> {
    let eph = B64.decode(&f.eph)?;
    let k = kek(shared, &eph, se_pub_x963);
    let n = B64.decode(&f.wrap_nonce)?;
    let ct = B64.decode(&f.wrapped_dek)?;
    let mut pt = cipher(&k)
        .decrypt(
            &nonce_of(&n)?,
            Payload { msg: &ct, aad: &aad(f.v, &f.name, f.tier, f.agent_allowed, f.public) },
        )
        .map_err(|_| anyhow!("{}: unwrap failed (wrong key or tampered file)", f.name))?;
    to_dek(&mut pt)
}

fn to_dek(pt: &mut Vec<u8>) -> Result<Dek> {
    if pt.len() != 32 {
        pt.zeroize();
        bail!("bad DEK length");
    }
    let mut d = Zeroizing::new([0u8; 32]);
    d.copy_from_slice(pt);
    pt.zeroize();
    Ok(d)
}

/// Content AAD deliberately excludes the tier: toggling tiers only rewraps the DEK.
fn content_aad(name: &str) -> Vec<u8> {
    format!("karambit/v1/content/{name}").into_bytes()
}

pub fn seal(dek: &Dek, name: &str, value: &[u8]) -> Result<(String, String)> {
    let n = nonce();
    let ct = cipher(dek)
        .encrypt(&Nonce::from(n), Payload { msg: value, aad: &content_aad(name) })
        .map_err(|_| anyhow!("seal failed"))?;
    Ok((B64.encode(n), B64.encode(ct)))
}

pub fn open(dek: &Dek, f: &SecretFile) -> Result<Zeroizing<Vec<u8>>> {
    let n = B64.decode(&f.nonce)?;
    let ct = B64.decode(&f.ct)?;
    cipher(dek)
        .decrypt(&nonce_of(&n)?, Payload { msg: &ct, aad: &content_aad(&f.name) })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("{}: decrypt failed (tampered file?)", f.name))
}

// ---- offline backup (age x25519) ----

pub fn backup_wrap(dek: &Dek, recipient: &str) -> Result<String> {
    let r = age::x25519::Recipient::from_str(recipient)
        .map_err(|e| anyhow!("bad backup recipient: {e}"))?;
    let ct = age::encrypt(&r, dek.as_ref()).map_err(|e| anyhow!("backup encrypt: {e}"))?;
    Ok(B64.encode(ct))
}

pub fn backup_unwrap(backup_b64: &str, identity: &age::x25519::Identity) -> Result<Dek> {
    let ct = B64.decode(backup_b64)?;
    let mut pt = age::decrypt(identity, &ct).map_err(|e| anyhow!("backup decrypt: {e}"))?;
    to_dek(&mut pt)
}

pub fn parse_identity(text: &str) -> Result<age::x25519::Identity> {
    text.lines()
        .map(str::trim)
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .ok_or_else(|| anyhow!("no AGE-SECRET-KEY line in identity file"))?
        .parse::<age::x25519::Identity>()
        .map_err(|e| anyhow!("bad identity: {e}"))
}

pub const PAPER_PREFIX: &str = "AGE-SECRET-KEY-1";

/// Accepts a key retyped from paper: any case, spaces/newlines/dashes between
/// groups, with or without the `AGE-SECRET-KEY-1` prefix. The bech32 checksum
/// rejects typos instead of yielding a wrong key.
pub fn parse_identity_loose(text: &str) -> Result<age::x25519::Identity> {
    let s: String = text.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    let body = s.strip_prefix("AGE-SECRET-KEY-1").unwrap_or(&s).replace('-', "");
    format!("{PAPER_PREFIX}{body}")
        .parse::<age::x25519::Identity>()
        .map_err(|_| anyhow!("key did not validate (checksum mismatch: check for a typo)"))
}

/// Paper layout: rows of 5 groups of 4, each row followed by a 2-char check code
/// so a typo is caught on the row where it happens, not only at the very end.
pub fn paper_format(identity: &str) -> String {
    let body = identity.strip_prefix(PAPER_PREFIX).unwrap_or(identity);
    let mut out = String::new();
    for (i, row) in paper_rows(body).iter().enumerate() {
        let groups: Vec<&str> = row.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
        out.push_str(&format!("  row {}   {:<24}  check {}\n", i + 1, groups.join(" "), row_check(i, row)));
    }
    out
}

/// age x25519 secret keys: 58 bech32 chars after the prefix. Rows of 20 -> 20, 20, 18.
pub const PAPER_BODY: usize = 58;
pub const PAPER_ROW: usize = 20;
const BECH32: &[u8] = b"QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";

pub fn paper_row_count() -> usize {
    PAPER_BODY.div_ceil(PAPER_ROW)
}

pub fn paper_row_len(i: usize) -> usize {
    PAPER_ROW.min(PAPER_BODY - i * PAPER_ROW)
}

fn paper_rows(body: &str) -> Vec<String> {
    body.as_bytes().chunks(PAPER_ROW).map(|c| String::from_utf8_lossy(c).into_owned()).collect()
}

/// 2-char check code for row `i` (bech32 alphabet). Binds the row number so
/// swapped rows are caught too. 1-in-1024 false accept per row; the key's own
/// bech32 checksum backs it up.
pub fn row_check(i: usize, row: &str) -> String {
    use sha2::Digest;
    let d = Sha256::digest(format!("karambit-paper-row/{i}/{row}").as_bytes());
    [d[0], d[1]].iter().map(|b| BECH32[(*b as usize) % 32] as char).collect()
}

/// Validate one typed row. Forgives case, spaces, dashes, a typed row label
/// ("row 1", "1:"). If the 2-char check code is typed too ("... check 7Q" or
/// just appended), it must match. Returns the clean row or a precise message.
pub fn check_paper_row(i: usize, input: &str) -> std::result::Result<String, String> {
    let mut s = input.trim().to_uppercase();
    let mut typed_check: Option<String> = None;
    if let Some(p) = s.find("CHECK") {
        let c: String = s[p + 5..].chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        if !c.is_empty() {
            typed_check = Some(c);
        }
        s.truncate(p);
    }
    let s = s.trim_start_matches("ROW").trim_start();
    let label = (i + 1).to_string();
    let s = s.strip_prefix(&format!("{label}:")).or_else(|| s.strip_prefix(&format!("{label} "))).unwrap_or(s);
    let mut row: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    let want = paper_row_len(i);
    // Row number glued on the front ("1F2TK...").
    if row.len() == want + label.len() && row.starts_with(&label) && row_ok_chars(&row[label.len()..]) {
        row.drain(..label.len());
    }
    // Check code appended without the word "check".
    if typed_check.is_none() && row.len() == want + 2 {
        typed_check = Some(row.split_off(want));
    }
    for (pos, b) in row.bytes().enumerate() {
        if !BECH32.contains(&b) {
            let c = b as char;
            let hint = match c {
                'O' => " (did you mean zero, 0?)",
                'B' => " (did you mean 8?)",
                'I' | '1' => " (keys never contain I or 1)",
                _ => "",
            };
            return Err(format!("character {} is '{c}', which never appears in a key{hint}", pos + 1));
        }
    }
    if row.len() != want {
        return Err(format!("expected {want} characters, got {}", row.len()));
    }
    if let Some(c) = typed_check
        && c != row_check(i, &row)
    {
        return Err("row doesn't match its check code: look for a typo in this row".into());
    }
    Ok(row)
}

fn row_ok_chars(s: &str) -> bool {
    s.bytes().all(|b| BECH32.contains(&b))
}

/// Validated paper rows -> identity text (`AGE-SECRET-KEY-1…`) for `recover_from_paper`,
/// zeroized. For callers that don't link `age` themselves (the GUI).
pub fn identity_text_from_rows(rows: &[String]) -> Result<Zeroizing<String>> {
    use age::secrecy::ExposeSecret;
    let id = identity_from_rows(rows)?;
    Ok(Zeroizing::new(id.to_string().expose_secret().to_string()))
}

/// Assemble validated rows into an identity (final bech32 checksum).
pub fn identity_from_rows(rows: &[String]) -> Result<age::x25519::Identity> {
    parse_identity_loose(&rows.concat())
}

/// Generate a backup identity for paper: returns (identity string, recipient).
pub fn generate_paper_identity() -> (Zeroizing<String>, String) {
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    (Zeroizing::new(id.to_string().expose_secret().to_string()), id.to_public().to_string())
}

/// Returns (identity file text, recipient).
pub fn generate_backup_identity() -> (Zeroizing<String>, String) {
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    let recip = id.to_public().to_string();
    let text = Zeroizing::new(format!(
        "# karambit offline backup identity — keep OFFLINE (paper/USB), never on this Mac long-term\n# public key: {recip}\n{}\n",
        id.to_string().expose_secret()
    ));
    (text, recip)
}
