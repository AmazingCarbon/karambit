use super::BackendError;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
pub type BResult<T> = Result<T, BackendError>;
pub type BindingHash = String; // validated 64 lowercase hex bytes
#[derive(Debug, PartialEq, Eq)]
pub struct BackendRef {
    pub source: String,
    pub native: String,
}
pub struct NativeRef {
    pub issuance: String,
    pub field: Option<String>,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SourceConfig {
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub auth_method: String,
    pub credential_ref: String,
    pub credential_revision: String,
    pub generation: String,
    pub policy: serde_json::Value, // C-18/C-19, non-secret
}
pub enum SecretField {
    Text(Zeroizing<String>),
    Bytes(Zeroizing<Vec<u8>>),
}
pub struct ChangeToken {
    pub version: Option<String>,
    pub etag: Option<String>,
}
/// Validated upstream lease ID (adapter `parse`-checked, bounded length, no
/// control chars). The only revoke argument; carries no lifetime claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseId(String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamLease {
    pub id: LeaseId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub server_ttl: Duration,
    pub renewable: bool,
}
pub struct Bundle {
    fields: BTreeMap<String, SecretField>,
    pub change: ChangeToken,
    pub lease: Option<UpstreamLease>,
    pub fresh_for: Duration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveKind {
    StaticRead,
    DynamicIssue,
}
/// What upstream may hold after a resolve attempt, independent of success.
pub enum IssueEffect {
    None,                    // nothing issued (static read, or refused before send)
    Known(UpstreamLease),    // an issued lease the daemon must own and clean up
    KnownId { id: LeaseId }, // lease ID seen but TTL/fields unusable (C-36)
    Unknown,                 // request sent, outcome lost (Indeterminate)
}
pub struct Resolved {
    pub result: BResult<Bundle>,
    pub effect: IssueEffect,
}
pub struct ResolveOpts {
    pub requested_ttl: Duration,
}
pub struct Meta {
    pub change: ChangeToken,
    pub credential_expires_at: Option<u64>,
}
pub struct AuthState {
    pub expires_at: Option<u64>,
    pub renewable: bool,
    pub needs_human: bool,
}
pub struct AuthUpdate {
    pub state: AuthState,
    pub replacement: Option<Zeroizing<Vec<u8>>>,
}
pub struct Capabilities {
    pub metadata: bool,
    pub list: bool,
    pub renew: bool,
    pub revoke: bool,
    pub interactive_auth: bool,
    pub refresh_auth: bool,
}
pub struct RefMeta {
    pub native: String,
    pub change: ChangeToken,
}
pub struct Page {
    pub refs: Vec<RefMeta>,
    pub next: Option<String>,
}
pub struct Health {
    pub reachable: bool,
    pub authenticated: bool,
    pub sealed: Option<bool>,
}
pub struct CallContext<'a> {
    pub credential: &'a [u8],
    pub deadline: Instant,
    pub cancelled: &'a (dyn Fn() -> bool + Send + Sync),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reference {
    Legacy(String),
    Backend(BackendRef),
}

pub fn valid_source_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name != "aws"
        && name != "karambit"
}
pub fn credential_name(name: &str) -> BResult<String> {
    if !valid_source_name(name) {
        return Err(BackendError::InvalidConfig);
    }
    Ok(format!("sources/{name}/cred"))
}
fn decoded_native(native: &str) -> BResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = native.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(|b| (b as char).to_digit(16));
            let lo = bytes.next().and_then(|b| (b as char).to_digit(16));
            out.push(match (hi, lo) {
                (Some(h), Some(l)) => (h * 16 + l) as u8,
                _ => return Err(BackendError::InvalidRef),
            });
        } else {
            out.push(b);
        }
    }
    Ok(out)
}
fn validate_native(native: &str) -> BResult<()> {
    let allowed = |b: u8| b.is_ascii_graphic() && b != b'\\';
    if native.is_empty() || !native.bytes().all(allowed) {
        return Err(BackendError::InvalidRef);
    }
    let decoded = decoded_native(native)?;
    if !decoded.iter().copied().all(allowed)
        || decoded
            .split(|b| matches!(b, b'/' | b'#' | b'?'))
            .any(|s| s == b"..")
    {
        return Err(BackendError::InvalidRef);
    }
    Ok(())
}
impl BackendRef {
    pub fn parse(input: &str) -> BResult<Reference> {
        let Some((source, native)) = input.split_once(':') else {
            return Ok(Reference::Legacy(input.into()));
        };
        if !valid_source_name(source) {
            return Err(BackendError::InvalidRef);
        }
        validate_native(native)?;
        Ok(Reference::Backend(Self {
            source: source.into(),
            native: native.into(),
        }))
    }
    /// Envelope projection only; adapter parsing owns query semantics.
    pub fn native_ref(&self) -> BResult<NativeRef> {
        validate_native(&self.native)?;
        let (issuance, field) = match self.native.split_once('#') {
            Some((path, tail)) => {
                let (field, query) = tail
                    .split_once('?')
                    .map_or((tail, None), |(f, q)| (f, Some(q)));
                if field.is_empty() || field.contains('#') {
                    return Err(BackendError::InvalidRef);
                }
                (
                    match query {
                        Some(q) => format!("{path}?{q}"),
                        None => path.into(),
                    },
                    Some(field.into()),
                )
            }
            None => (self.native.clone(), None),
        };
        if issuance.is_empty() {
            return Err(BackendError::InvalidRef);
        }
        Ok(NativeRef { issuance, field })
    }
}
/// C-27: printable ASCII only (0x20..=0x7E). An allowlist, not `!is_control()`, so Unicode
/// line/paragraph separators and bidi/format characters (U+2028, U+2029, U+202E, ...) are refused.
fn valid_metadata(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
impl LeaseId {
    pub fn parse(id: &str) -> BResult<Self> {
        if !valid_metadata(id) {
            return Err(BackendError::InvalidResponse);
        }
        Ok(Self(id.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl ChangeToken {
    pub fn validate(&self) -> BResult<()> {
        if self
            .version
            .iter()
            .chain(self.etag.iter())
            .all(|s| valid_metadata(s))
        {
            Ok(())
        } else {
            Err(BackendError::InvalidResponse)
        }
    }
}
impl std::fmt::Debug for SecretField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretField([REDACTED])")
    }
}
impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bundle([REDACTED])")
    }
}
impl Bundle {
    pub fn new(
        fields: impl IntoIterator<Item = (String, SecretField)>,
        change: ChangeToken,
        lease: Option<UpstreamLease>,
        fresh_for: Duration,
    ) -> BResult<Self> {
        let mut map = BTreeMap::new();
        for (name, value) in fields {
            if name.is_empty() || map.insert(name, value).is_some() {
                return Err(BackendError::InvalidResponse);
            }
        }
        if map.is_empty() {
            return Err(BackendError::InvalidResponse);
        }
        change.validate()?;
        Ok(Self {
            fields: map,
            change,
            lease,
            fresh_for,
        })
    }
    pub fn fields(&self) -> &BTreeMap<String, SecretField> {
        &self.fields
    }
}
impl Resolved {
    /// Call only AFTER taking ownership of effect for cleanup, even if this fails.
    pub fn validate(&self, kind: ResolveKind) -> BResult<()> {
        let Ok(bundle) = &self.result else {
            return Ok(());
        };
        bundle.change.validate()?;
        match (kind, &self.effect, &bundle.lease) {
            (ResolveKind::StaticRead, IssueEffect::None, None) => Ok(()),
            (ResolveKind::DynamicIssue, IssueEffect::Known(effect), Some(lease))
                if effect == lease =>
            {
                Ok(())
            }
            _ => Err(BackendError::InvalidResponse),
        }
    }
}

fn canonical_policy(value: &serde_json::Value) -> BResult<serde_json::Value> {
    use serde_json::Value;
    Ok(match value {
        Value::Number(n) if !n.is_i64() && !n.is_u64() => return Err(BackendError::InvalidConfig),
        Value::Array(a) => Value::Array(a.iter().map(canonical_policy).collect::<BResult<_>>()?),
        Value::Object(o) => {
            let sorted: BTreeMap<_, _> = o.iter().collect();
            let mut map = serde_json::Map::new();
            for (k, v) in sorted {
                map.insert(k.clone(), canonical_policy(v)?);
            }
            Value::Object(map)
        }
        other => other.clone(),
    })
}
/// Strict HTTPS DNS endpoint canonicalization; rejects rather than normalizes dot segments.
pub fn canonical_endpoint(endpoint: &str) -> BResult<String> {
    let invalid = || BackendError::InvalidConfig;
    let rest = endpoint.strip_prefix("https://").ok_or_else(invalid)?;
    if rest
        .bytes()
        .any(|b| !b.is_ascii_graphic() || matches!(b, b'\\' | b'?' | b'#' | b'@'))
    {
        return Err(invalid());
    }
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(a, _)| (a, &rest[a.len()..]));
    let (host, port) = authority.split_once(':').unwrap_or((authority, "443"));
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if port == 0
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid());
    }
    let decoded = decoded_native(path).map_err(|_| invalid())?;
    if decoded.iter().any(|b| !b.is_ascii_graphic() || *b == b'\\')
        || decoded
            .split(|b| *b == b'/')
            .any(|s| s == b"." || s == b"..")
    {
        return Err(invalid());
    }
    // Trailing slashes are not significant; a path that is only slashes (or empty) is the root
    // `/`. Idempotent: canonicalising the output yields the same string.
    let trimmed = path.trim_end_matches('/');
    let path = if trimmed.is_empty() { "/" } else { trimmed };
    Ok(format!(
        "https://{}:{port}{path}",
        host.to_ascii_lowercase()
    ))
}
impl SourceConfig {
    pub fn validate(&self) -> BResult<()> {
        if !valid_source_name(&self.name)
            || self.kind.is_empty()
            || self.auth_method.is_empty()
            || self.credential_ref != credential_name(&self.name)?
            || self.credential_revision.is_empty()
            || self.generation.len() != 32
            || !self
                .generation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BackendError::InvalidConfig);
        }
        canonical_endpoint(&self.endpoint)?;
        canonical_policy(&self.policy)?;
        Ok(())
    }
    pub fn binding_hash(&self) -> BResult<BindingHash> {
        use sha2::{Digest, Sha256};
        self.validate()?;
        let endpoint = canonical_endpoint(&self.endpoint)?;
        let policy = serde_json::to_string(&canonical_policy(&self.policy)?)
            .map_err(|_| BackendError::InvalidConfig)?;
        let mut hash = Sha256::new();
        for field in [
            "karambit-source-v1",
            &self.kind,
            &endpoint,
            &self.auth_method,
            &self.credential_ref,
            &self.credential_revision,
            &policy,
            &self.generation,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn config() -> SourceConfig {
        SourceConfig {
            name: "f".into(),
            kind: "fake".into(),
            endpoint: "https://fake.invalid:443/".into(),
            auth_method: "token".into(),
            credential_ref: "sources/f/cred".into(),
            credential_revision: "r1".into(),
            generation: "0123456789abcdef0123456789abcdef".into(),
            policy: serde_json::json!({"ttl":300}),
        }
    }
    #[test]
    fn grammar_table() {
        for input in [
            "f:ok/a",
            "f:ok/a#value",
            "vault-prod:secret/data/app#db_pass?version=3",
            "arn:arn:aws:service:eu-west-1:123456789012:secret:app#key?stage=CURRENT",
            "op:op://Prod/db/password",
            "missing:ok/a",
            "f:ok/%252e%252e/a",
        ] {
            let Reference::Backend(r) = BackendRef::parse(input).unwrap() else {
                panic!()
            };
            assert_eq!(r.native, input.split_once(':').unwrap().1);
        }
        for input in ["ns/name", "aws/staging", "../unchanged", ""] {
            assert_eq!(
                BackendRef::parse(input).unwrap(),
                Reference::Legacy(input.into())
            );
        }
        for input in [
            ":ok/a",
            ":x",
            "f:",
            "f:..",
            "f:%2e%2e",
            "f:ok/../a",
            "f:ok/%2e%2e/a",
            "f:ok/%2F../a",
            "f:ok/%ZZ",
            "F:ok/a",
            "aws:ok/a",
            "aws:x",
            "karambit:x",
            "f:ok/a b",
            "f:ok\\a",
            "f:a\n",
            "f:a\0",
            "f:a%00",
            "f:a%20",
            "f:a%5c",
            "f:%zz",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:x",
        ] {
            assert_eq!(
                BackendRef::parse(input).unwrap_err(),
                BackendError::InvalidRef,
                "{input:?}"
            );
        }
        // Assignment/wrapper stripping belongs to the existing env parser, not this envelope.
        for assignment in ["X=f:ok/a", "X=karambit:f:ok/a"] {
            let (_, value) = assignment.split_once('=').unwrap();
            assert!(BackendRef::parse(value.strip_prefix("karambit:").unwrap_or(value)).is_ok());
        }
        let Reference::Backend(r) = BackendRef::parse("f:ok/a#user").unwrap() else {
            panic!()
        };
        let n = r.native_ref().unwrap();
        assert_eq!(n.issuance, "ok/a");
        assert_eq!(n.field.as_deref(), Some("user"));
        assert_eq!(
            credential_name("karambit"),
            Err(BackendError::InvalidConfig)
        );
    }
    #[test]
    fn binding_vectors_and_canonicalization() {
        let c = config();
        assert_eq!(
            c.binding_hash().unwrap(),
            "033f2c5aba0281f52d82cc26fc015421b8bff7afff6b756dab874ccda618c0d9"
        );
        let mut a = config();
        let mut b = config();
        a.credential_revision = "ab".into();
        a.policy = serde_json::json!(12);
        b.credential_revision = "ab1".into();
        b.policy = serde_json::json!(2);
        assert_eq!(
            format!("{}{}", a.credential_revision, a.policy),
            format!("{}{}", b.credential_revision, b.policy)
        );
        assert_ne!(a.binding_hash().unwrap(), b.binding_hash().unwrap());
        for i in 0..7 {
            let mut changed = config();
            match i {
                0 => changed.kind.push('x'),
                1 => changed.endpoint = "https://other.invalid/".into(),
                2 => changed.auth_method.push('x'),
                3 => {
                    changed.name = "g".into();
                    changed.credential_ref = "sources/g/cred".into()
                }
                4 => changed.credential_revision.push('x'),
                5 => changed.policy = serde_json::json!({"ttl":301}),
                _ => changed.generation = "1123456789abcdef0123456789abcdef".into(),
            }
            assert_ne!(c.binding_hash().unwrap(), changed.binding_hash().unwrap());
        }
        assert_eq!(
            canonical_endpoint("https://EXAMPLE.com/a/").unwrap(),
            "https://example.com:443/a"
        );
        // Idempotence: canonical(canonical(x)) == canonical(x), and the binding
        // hash does not change when the endpoint is replaced by its own canonical form.
        for raw in ["https://host", "https://host/", "https://host//", "https://host///", "https://HOST:443/a//", "https://host:8200/v1/"] {
            let once = canonical_endpoint(raw).unwrap();
            assert_eq!(canonical_endpoint(&once).unwrap(), once, "{raw}");
            let mut a = config();
            a.endpoint = raw.into();
            let mut b = config();
            b.endpoint = once.clone();
            assert_eq!(a.binding_hash().unwrap(), b.binding_hash().unwrap(), "{raw}");
        }
        assert_eq!(canonical_endpoint("https://host//").unwrap(), "https://host:443/");
        for endpoint in [
            "http://example.com",
            "https://u@host/",
            "https://host/?q=1",
            "https://host/#x",
            "https://host/a/../b",
            "https://host/%2e/",
            "https://host:0/",
            "https://host:bad/",
            "https:///",
            "https://host/\\",
        ] {
            assert!(canonical_endpoint(endpoint).is_err(), "{endpoint}");
        }
        let mut c = config();
        c.policy = serde_json::json!({"n":1.5});
        assert!(c.binding_hash().is_err());
        c.policy = serde_json::json!({"z":{"b":2,"a":1},"a":[2,1]});
        assert_eq!(
            serde_json::to_string(&canonical_policy(&c.policy).unwrap()).unwrap(),
            r#"{"a":[2,1],"z":{"a":1,"b":2}}"#
        );
    }
    fn lease() -> UpstreamLease {
        UpstreamLease {
            id: LeaseId::parse("L").unwrap(),
            issued_at: 1,
            expires_at: 301,
            server_ttl: Duration::from_secs(300),
            renewable: false,
        }
    }
    fn bundle(l: Option<UpstreamLease>) -> Bundle {
        Bundle::new(
            vec![(
                "value".into(),
                SecretField::Text(Zeroizing::new("secret".into())),
            )],
            ChangeToken {
                version: None,
                etag: None,
            },
            l,
            Duration::ZERO,
        )
        .unwrap()
    }
    #[test]
    fn metadata_is_printable_ascii_only() {
        // Regression: is_control() misses Unicode separators and bidi overrides.
        for bad in ["L\u{2028}forged", "L\u{2029}x", "v\u{202E}1", "a\u{200B}b", "\u{00A0}", "é", "a\nb", "a\u{7f}"] {
            assert!(LeaseId::parse(bad).is_err(), "{bad:?}");
            assert!(ChangeToken { version: Some(bad.into()), etag: None }.validate().is_err(), "{bad:?}");
            assert!(ChangeToken { version: None, etag: Some(bad.into()) }.validate().is_err(), "{bad:?}");
        }
        for good in ["L-1", "auth/token/create/abc.DEF_123", "W/\"etag\"", " spaced ok "] {
            assert!(LeaseId::parse(good).is_ok(), "{good:?}");
        }
        assert!(LeaseId::parse(&"x".repeat(256)).is_ok());
        assert!(LeaseId::parse(&"x".repeat(257)).is_err());
        assert!(LeaseId::parse("").is_err());
    }

    #[test]
    fn bundle_invariants_and_zeroizing() {
        for names in [vec!["a", "a"], vec![""]] {
            assert!(
                Bundle::new(
                    names.into_iter().map(|n| (
                        n.into(),
                        SecretField::Text(Zeroizing::new("private".into()))
                    )),
                    ChangeToken {
                        version: None,
                        etag: None
                    },
                    None,
                    Duration::ZERO
                )
                .is_err()
            );
        }
        let value: [u8; 32] = rand::random();
        let text = value.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let b = Bundle::new(
            vec![
                (
                    "text".into(),
                    SecretField::Text(Zeroizing::new(text.clone())),
                ),
                (
                    "bytes".into(),
                    SecretField::Bytes(Zeroizing::new(value.to_vec())),
                ),
            ],
            ChangeToken {
                version: None,
                etag: None,
            },
            None,
            Duration::ZERO,
        )
        .unwrap();
        assert!(!format!("{b:?}").contains(&text));
        assert!(!format!("{b:?}").contains(&format!("{value:?}")));
        for field in b.fields().values() {
            match field {
                SecretField::Text(v) => {
                    let _: &Zeroizing<String> = v;
                    assert!(!format!("{field:?}").contains(&text));
                }
                SecretField::Bytes(v) => {
                    let _: &Zeroizing<Vec<u8>> = v;
                }
            }
        }
        assert!(LeaseId::parse("bad\n").is_err());
        assert!(LeaseId::parse(&"x".repeat(257)).is_err());
    }
    #[test]
    fn effect_validator_matrix() {
        for kind in [ResolveKind::StaticRead, ResolveKind::DynamicIssue] {
            for effect_case in 0..4 {
                for has_lease in [false, true] {
                    for success in [false, true] {
                        let effect = match effect_case {
                            0 => IssueEffect::None,
                            1 => IssueEffect::Known(lease()),
                            2 => IssueEffect::KnownId {
                                id: LeaseId::parse("L").unwrap(),
                            },
                            _ => IssueEffect::Unknown,
                        };
                        let resolved = Resolved {
                            result: if success {
                                Ok(bundle(has_lease.then(lease)))
                            } else {
                                Err(BackendError::TtlExceeded)
                            },
                            effect,
                        };
                        let valid = !success
                            || match kind {
                                ResolveKind::StaticRead => effect_case == 0 && !has_lease,
                                ResolveKind::DynamicIssue => effect_case == 1 && has_lease,
                            };
                        assert_eq!(
                            resolved.validate(kind).is_ok(),
                            valid,
                            "{kind:?}/{effect_case}/{has_lease}/{success}"
                        );
                    }
                }
            }
        }
        let mut other = lease();
        other.expires_at += 1;
        assert!(
            Resolved {
                result: Ok(bundle(Some(other))),
                effect: IssueEffect::Known(lease())
            }
            .validate(ResolveKind::DynamicIssue)
            .is_err()
        );
    }
}
