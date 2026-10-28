//! Synthetic adversarial backend, `kind = "fake"` (backend contract C-15).
//!
//! Test-only in intent: this module is compiled into the library (integration tests cannot see
//! `cfg(test)` items and no Cargo feature is allowed), but NOTHING registers it. Only an explicit
//! call to [`register`] makes `kind = "fake"` resolvable, and production code never makes that
//! call (guarded by `tests/backend_fakes.rs::production_sources_never_register_the_fake`).
//!
//! No I/O, no sleeping, no real clock reads after construction. All time flows through an
//! injected [`FakeClock`]; pauses use [`Gate`]s. Behaviour is selected by the native ref path:
//!
//! | issuance        | kind         | result / effect                                          |
//! |-----------------|--------------|----------------------------------------------------------|
//! | `ok/<n>`        | DynamicIssue | Ok, `Known(lease)` matching `Bundle.lease`               |
//! | `flap/<n>`      | DynamicIssue | as ok; user, value and version change on every call      |
//! | `revokefail/<n>`| DynamicIssue | as ok; `revoke` fails N times, then succeeds             |
//! | `slow/<n>`      | DynamicIssue | server issues; reply never comes: Indeterminate/Unknown  |
//! | `diesmid/<n>`   | DynamicIssue | server issues, reply lost: Indeterminate/Unknown         |
//! | `diesmid-nottl/<n>` | DynamicIssue | reply has lease ID, no TTL: TtlExceeded/KnownId      |
//! | `throttle/<n>`  | StaticRead   | RateLimited (clamped), effect None                       |
//! | `throttledyn/<n>` | DynamicIssue | RateLimited (clamped), effect None, nothing issued     |
//! | `static/<n>`    | StaticRead   | Ok, effect None, no lease                                |
//! | `slowstatic/<n>`| StaticRead   | never answers: Timeout, effect None                      |
use super::Meta;

use super::{
    AuthState, BResult, BackendError, BackendRef, Bundle, CallContext, Capabilities, ChangeToken,
    IssueEffect, LeaseId, NativeRef, Registry, ResolveKind, ResolveOpts, Resolved, SecretBackend,
    SecretField, SourceConfig, UpstreamLease, canonical_endpoint,
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const KIND: &str = "fake";

/// Register `kind = "fake"`. Explicit, test-only; production never calls this.
pub fn register(registry: &mut Registry) -> BResult<()> {
    registry.register(KIND, factory)
}

static SERVERS: OnceLock<Mutex<BTreeMap<String, Arc<FakeServer>>>> = OnceLock::new();
static NEXT_TAG: AtomicU64 = AtomicU64::new(1);

fn servers() -> MutexGuard<'static, BTreeMap<String, Arc<FakeServer>>> {
    SERVERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Bind `server` to `endpoint` (canonicalised) so `add_source` for that endpoint reaches it.
/// Different endpoints are different servers (old/new endpoint proofs, C-14).
pub fn attach(endpoint: &str, server: &Arc<FakeServer>) -> BResult<()> {
    let key = canonical_endpoint(endpoint)?;
    let mut map = servers();
    if map.contains_key(&key) {
        return Err(BackendError::InvalidConfig);
    }
    map.insert(key, server.clone());
    Ok(())
}

pub fn detach(endpoint: &str) {
    if let Ok(key) = canonical_endpoint(endpoint) {
        servers().remove(&key);
    }
}

fn factory(config: &SourceConfig) -> BResult<Arc<dyn SecretBackend>> {
    let key = canonical_endpoint(&config.endpoint)?;
    let server = servers().get(&key).cloned().ok_or(BackendError::InvalidConfig)?;
    Ok(Arc::new(FakeBackend::new(server)))
}

/// Injected clock: a monotonic offset from a base `Instant` plus wall-clock seconds. Moved by the
/// test, or by a simulated wait (`slow*`) that ends exactly at the call deadline.
#[derive(Debug)]
pub struct FakeClock {
    base: Instant,
    state: Mutex<(Duration, Duration)>, // (monotonic offset, wall since epoch)
}
impl FakeClock {
    pub fn new(wall_secs: u64) -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            state: Mutex::new((Duration::ZERO, Duration::from_secs(wall_secs))),
        })
    }
    fn lock(&self) -> MutexGuard<'_, (Duration, Duration)> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn now(&self) -> Instant {
        self.base + self.lock().0
    }
    pub fn wall(&self) -> u64 {
        self.lock().1.as_secs()
    }
    /// Simulated wait that ends exactly at `deadline` (never a real sleep).
    pub fn advance_to(&self, deadline: Instant) {
        let mut s = self.lock();
        let now = self.base + s.0;
        if deadline > now {
            let remaining = deadline - now;
            s.0 += remaining;
            s.1 += remaining;
        }
    }
    /// Normal passage of time: monotonic and wall move together.
    pub fn advance(&self, by: Duration) {
        let mut s = self.lock();
        s.0 += by;
        s.1 += by;
    }
    /// Set wall time in either direction without moving monotonic time.
    pub fn set_wall(&self, seconds: u64) {
        self.lock().1 = Duration::from_secs(seconds);
    }
    /// Sleep/wake or clock step: wall jumps, monotonic stays frozen.
    pub fn advance_wall(&self, by: Duration) {
        self.lock().1 += by;
    }
}

/// Test-controlled pause point. The fake calls `pass` and blocks until the test calls `release`;
/// the test uses `wait_reached` to know the fake is paused. One-shot: once released it stays open.
#[derive(Default)]
pub struct Gate {
    state: Mutex<(usize, bool)>, // (arrivals, open)
    cv: Condvar,
}
impl Gate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn lock(&self) -> MutexGuard<'_, (usize, bool)> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn wait_reached(&self) {
        let mut s = self.lock();
        while s.0 == 0 {
            s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
    pub fn arrivals(&self) -> usize {
        self.lock().0
    }
    pub fn release(&self) {
        self.lock().1 = true;
        self.cv.notify_all();
    }
    fn pass(&self) {
        let mut s = self.lock();
        s.0 += 1;
        self.cv.notify_all();
        while !s.1 {
            s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// One `revoke` call that reached the server. ID only: nothing else is ever passed to revoke.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeAttempt {
    pub lease_id: String,
    pub succeeded: bool,
    /// None means no expectation configured; never contains credential material.
    pub credential_matches: Option<bool>,
}

struct ServerLease {
    expires_at: u64,
    revoked: bool,
    revoke_failures_left: u32,
}
#[derive(Clone, Copy)]
pub enum MetadataMode { Unchanged, Changed, Unsupported, Error }
#[derive(Clone)]
struct MetadataToken {
    version: Option<String>,
    etag: Option<String>,
    credential_expires_at: Option<u64>,
}
struct State {
    metadata_enabled: bool,
    metadata_mode: MetadataMode,
    metadata_calls: u64,
    metadata_gate: Option<Arc<Gate>>,
    metadata_tokens: BTreeMap<String, MetadataToken>,
    calls: u64,
    expected_credential: Option<Zeroizing<Vec<u8>>>,
    resolve_credentials: Vec<Option<bool>>,
    issue_count: u64,
    leases: BTreeMap<String, ServerLease>,
    revoke_log: Vec<RevokeAttempt>,
    static_values: BTreeMap<String, Zeroizing<String>>,
    max_ttl: Duration,
    revokefail_count: u32,
    throttles_left: Option<u32>, // None = throttle forever
    throttle_retry_after: Duration,
    fresh_for: Duration,
    before_issue: Option<Arc<Gate>>,
    after_issue: Option<Arc<Gate>>,
}

/// Shared synthetic upstream. Survives backend/registry/daemon drops (crash proofs).
pub struct FakeServer {
    tag: u64,
    clock: Arc<FakeClock>,
    state: Mutex<State>,
}
impl fmt::Debug for FakeServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.lock();
        f.debug_struct("FakeServer")
            .field("issue_count", &s.issue_count)
            .field("leases", &s.leases.len())
            .finish_non_exhaustive()
    }
}

struct Issued {
    lease: UpstreamLease,
    n: u64,
    fresh_for: Duration,
}
enum Reply {
    Full,
    NoTtl,
    Lost,
}

fn hex_random() -> Zeroizing<String> {
    let bytes = Zeroizing::new(rand::random::<[u8; 32]>());
    Zeroizing::new(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl FakeServer {
    pub fn new(clock: Arc<FakeClock>) -> Arc<Self> {
        Arc::new(Self {
            tag: NEXT_TAG.fetch_add(1, Ordering::Relaxed),
            clock,
            state: Mutex::new(State {
                metadata_enabled: false,
                metadata_mode: MetadataMode::Unchanged,
                metadata_calls: 0,
                metadata_gate: None,
                metadata_tokens: BTreeMap::new(),
                calls: 0,
                expected_credential: None,
                resolve_credentials: Vec::new(),
                issue_count: 0,
                leases: BTreeMap::new(),
                revoke_log: Vec::new(),
                static_values: BTreeMap::new(),
                max_ttl: Duration::from_secs(900),
                revokefail_count: 2,
                throttles_left: None,
                throttle_retry_after: Duration::from_secs(7),
                fresh_for: Duration::from_secs(30),
                before_issue: None,
                after_issue: None,
            }),
        })
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn set_metadata(&self, enabled: bool, mode: MetadataMode) {
        let mut s = self.lock();
        s.metadata_enabled = enabled;
        s.metadata_mode = mode;
    }
    pub fn metadata_call_count(&self) -> u64 { self.lock().metadata_calls }
    pub fn gate_metadata(&self, gate: Arc<Gate>) { self.lock().metadata_gate = Some(gate); }
    pub fn clock(&self) -> &Arc<FakeClock> {
        &self.clock
    }
    /// Resolve calls received, including refused and pre-send failures.
    pub fn call_count(&self) -> u64 {
        self.lock().calls
    }
    /// Leases the server created, regardless of whether the client ever heard about them.
    pub fn issue_count(&self) -> u64 {
        self.lock().issue_count
    }
    pub fn lease_ids(&self) -> Vec<String> {
        self.lock().leases.keys().cloned().collect()
    }
    pub fn lease_expires_at(&self, id: &str) -> Option<u64> {
        self.lock().leases.get(id).map(|l| l.expires_at)
    }
    pub fn is_revoked(&self, id: &str) -> bool {
        self.lock().leases.get(id).is_some_and(|l| l.revoked)
    }
    /// Live = not revoked and not past its server-side expiry on the injected wall clock.
    pub fn is_live(&self, id: &str) -> bool {
        let wall = self.clock.wall();
        self.lock()
            .leases
            .get(id)
            .is_some_and(|l| !l.revoked && l.expires_at > wall)
    }
    pub fn live_lease_count(&self) -> usize {
        let wall = self.clock.wall();
        self.lock()
            .leases
            .values()
            .filter(|l| !l.revoked && l.expires_at > wall)
            .count()
    }
    pub fn revoke_log(&self) -> Vec<RevokeAttempt> {
        self.lock().revoke_log.clone()
    }
    /// Upstream maximum TTL (C-35): the server never grants more, whatever is requested.
    pub fn set_max_ttl(&self, max: Duration) -> BResult<()> {
        if max.as_secs() == 0 || max > Duration::from_secs(900) {
            return Err(BackendError::InvalidConfig);
        }
        self.lock().max_ttl = max;
        Ok(())
    }
    /// Observe identity without retaining the presented credential or logging its bytes.
    pub fn set_expected_credential(&self, credential: Zeroizing<Vec<u8>>) {
        self.lock().expected_credential = Some(credential);
    }
    pub fn resolve_credentials(&self) -> Vec<Option<bool>> {
        self.lock().resolve_credentials.clone()
    }
    /// Override retries for any issued lease, including an ID-only response.
    pub fn set_lease_revoke_failures(&self, id: &LeaseId, n: u32) -> BResult<()> {
        let mut s = self.lock();
        let lease = s.leases.get_mut(id.as_str()).ok_or(BackendError::NotFound)?;
        lease.revoke_failures_left = n;
        Ok(())
    }
    /// Failures `revokefail/*` leases will return before revoke succeeds (default 2).
    pub fn set_revoke_failures(&self, n: u32) {
        self.lock().revokefail_count = n;
    }
    /// `throttle*` refs return RateLimited this many times, then behave normally. Default: forever.
    pub fn set_throttles(&self, n: u32) {
        self.lock().throttles_left = Some(n);
    }
    /// Raw hint; the adapter clamps it to 1..300s (C-28).
    pub fn set_throttle_retry_after(&self, d: Duration) {
        self.lock().throttle_retry_after = d;
    }
    pub fn set_fresh_for(&self, d: Duration) {
        self.lock().fresh_for = d;
    }
    pub fn set_static_value(&self, name: &str, value: Zeroizing<String>) {
        self.lock().static_values.insert(name.into(), value);
    }
    /// Pause every dynamic resolve just before the server creates the lease.
    pub fn gate_before_issue(&self, gate: Arc<Gate>) {
        self.lock().before_issue = Some(gate);
    }
    /// Pause every dynamic resolve after the server created the lease, before the client sees it.
    pub fn gate_after_issue(&self, gate: Arc<Gate>) {
        self.lock().after_issue = Some(gate);
    }
    fn expired(&self, c: &CallContext<'_>) -> bool {
        c.deadline <= self.clock.now()
    }
    fn issue(&self, behaviour: Behaviour, requested: Duration) -> Option<Issued> {
        let mut s = self.lock();
        s.issue_count += 1;
        let n = s.issue_count;
        let secs = requested.min(s.max_ttl).as_secs();
        let issued_at = self.clock.wall();
        let id = format!("fake-{}-{n}", self.tag);
        let lease = UpstreamLease {
            id: LeaseId::parse(&id).ok()?,
            issued_at,
            expires_at: issued_at + secs,
            server_ttl: Duration::from_secs(secs),
            renewable: false,
        };
        let revoke_failures_left = if behaviour == Behaviour::RevokeFail {
            s.revokefail_count
        } else {
            0
        };
        s.leases.insert(
            id,
            ServerLease {
                expires_at: lease.expires_at,
                revoked: false,
                revoke_failures_left,
            },
        );
        Some(Issued {
            lease,
            n,
            fresh_for: s.fresh_for,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    Ok,
    Flap,
    RevokeFail,
    Slow,
    DiesMid,
    DiesMidNoTtl,
    Throttle,
    ThrottleDyn,
    Static,
    SlowStatic,
}
impl Behaviour {
    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "ok" => Self::Ok,
            "flap" => Self::Flap,
            "revokefail" => Self::RevokeFail,
            "slow" => Self::Slow,
            "diesmid" => Self::DiesMid,
            "diesmid-nottl" => Self::DiesMidNoTtl,
            "throttle" => Self::Throttle,
            "throttledyn" => Self::ThrottleDyn,
            "static" => Self::Static,
            "slowstatic" => Self::SlowStatic,
            _ => return None,
        })
    }
    fn kind(self) -> ResolveKind {
        match self {
            Self::Static | Self::SlowStatic | Self::Throttle => ResolveKind::StaticRead,
            _ => ResolveKind::DynamicIssue,
        }
    }
    fn fields(self) -> &'static [&'static str] {
        match self.kind() {
            ResolveKind::StaticRead => &["value"],
            ResolveKind::DynamicIssue => &["user", "password"],
        }
    }
}
fn parse_issuance(issuance: &str) -> BResult<(Behaviour, &str)> {
    let (word, name) = issuance.split_once('/').ok_or(BackendError::InvalidRef)?;
    let behaviour = Behaviour::parse(word).ok_or(BackendError::InvalidRef)?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(BackendError::InvalidRef);
    }
    Ok((behaviour, name))
}
fn fail(error: BackendError, effect: IssueEffect) -> Resolved {
    Resolved {
        result: Err(error),
        effect,
    }
}

/// The `kind = "fake"` adapter: one shared [`FakeServer`], behaviour chosen per ref.
pub struct FakeBackend {
    server: Arc<FakeServer>,
}
impl FakeBackend {
    pub fn new(server: Arc<FakeServer>) -> Self {
        Self { server }
    }
    fn dynamic_bundle(
        &self,
        behaviour: Behaviour,
        name: &str,
        issued: &Issued,
    ) -> BResult<Bundle> {
        let user = match behaviour {
            Behaviour::Flap => format!("u-{}-{}", self.server.tag, issued.n),
            _ => format!("svc-{name}"),
        };
        Bundle::new(
            [
                ("user".into(), SecretField::Text(Zeroizing::new(user))),
                ("password".into(), SecretField::Text(hex_random())),
            ],
            ChangeToken {
                version: Some(format!("v{}", issued.n)),
                etag: None,
            },
            Some(issued.lease.clone()),
            issued.fresh_for,
        )
    }
    fn static_resolved(&self, name: &str) -> Resolved {
        let (value, fresh_for) = {
            let mut s = self.server.lock();
            let v = s
                .static_values
                .entry(name.into())
                .or_insert_with(hex_random)
                .clone();
            (v, s.fresh_for)
        };
        Resolved {
            result: Bundle::new(
                [("value".into(), SecretField::Text(value))],
                ChangeToken {
                    version: Some("static-1".into()),
                    etag: Some("\"e1\"".into()),
                },
                None,
                fresh_for,
            ),
            effect: IssueEffect::None,
        }
    }
    fn dynamic(
        &self,
        c: &CallContext<'_>,
        behaviour: Behaviour,
        name: &str,
        o: &ResolveOpts,
    ) -> Resolved {
        let server = &self.server;
        let gates = {
            let s = server.lock();
            (s.before_issue.clone(), s.after_issue.clone())
        };
        if let Some(g) = gates.0 {
            g.pass();
        }
        // Not yet sent: refusing here is a zero-effect outcome.
        if (c.cancelled)() {
            return fail(BackendError::Cancelled, IssueEffect::None);
        }
        if server.expired(c) {
            return fail(BackendError::Timeout, IssueEffect::None);
        }
        // From here the request is on the wire: the server records a lease whatever we hear back.
        let Some(issued) = server.issue(behaviour, o.requested_ttl) else {
            return fail(BackendError::InvalidResponse, IssueEffect::Unknown);
        };
        if let Some(g) = gates.1 {
            g.pass();
        }
        if behaviour == Behaviour::Slow {
            server.clock.advance_to(c.deadline); // waited out the deadline, no reply ever came
        }
        let reply = match behaviour {
            Behaviour::Slow | Behaviour::DiesMid => Reply::Lost,
            Behaviour::DiesMidNoTtl => Reply::NoTtl,
            _ => Reply::Full,
        };
        // Lost reply, or deadline passed while waiting for it: sent dynamic issue is
        // Indeterminate (C-27), never Timeout, and never auto-retried.
        if matches!(reply, Reply::Lost) || server.expired(c) {
            return fail(BackendError::Indeterminate, IssueEffect::Unknown);
        }
        let known_id = || IssueEffect::KnownId {
            id: issued.lease.id.clone(),
        };
        if (c.cancelled)() {
            // C-11: response collection continues after cancel, so the lease is discovered.
            let effect = match reply {
                Reply::NoTtl => known_id(),
                _ => IssueEffect::Known(issued.lease.clone()),
            };
            return fail(BackendError::Cancelled, effect);
        }
        if matches!(reply, Reply::NoTtl) {
            return fail(BackendError::TtlExceeded, known_id());
        }
        match self.dynamic_bundle(behaviour, name, &issued) {
            Ok(bundle) => Resolved {
                result: Ok(bundle),
                effect: IssueEffect::Known(issued.lease),
            },
            Err(e) => fail(e, IssueEffect::Known(issued.lease)),
        }
    }
}

impl SecretBackend for FakeBackend {
    fn id(&self) -> &str {
        KIND
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            metadata: self.server.lock().metadata_enabled,
            list: false,
            renew: false,
            revoke: true,
            interactive_auth: false,
            refresh_auth: false,
        }
    }
    fn parse_ref(&self, native: &str) -> BResult<NativeRef> {
        let parsed = BackendRef {
            source: String::new(),
            native: native.into(),
        }
        .native_ref()?;
        let (behaviour, _) = parse_issuance(&parsed.issuance)?;
        if parsed
            .field
            .as_deref()
            .is_some_and(|f| !behaviour.fields().contains(&f))
        {
            return Err(BackendError::InvalidRef);
        }
        Ok(parsed)
    }
    fn resolve_kind(&self, r: &NativeRef) -> BResult<ResolveKind> {
        Ok(parse_issuance(&r.issuance)?.0.kind())
    }
    fn auth_status(&self) -> AuthState {
        AuthState {
            expires_at: None,
            renewable: false,
            needs_human: false,
        }
    }
    fn resolve(&self, c: &CallContext<'_>, r: &NativeRef, o: &ResolveOpts) -> Resolved {
        let server = &self.server;
        {
            let mut s = server.lock();
            s.calls += 1;
            let matched = s.expected_credential.as_ref().map(|v| v.as_slice() == c.credential);
            s.resolve_credentials.push(matched);
        }
        let Ok((behaviour, name)) = parse_issuance(&r.issuance) else {
            return fail(BackendError::InvalidRef, IssueEffect::None);
        };
        if (c.cancelled)() {
            return fail(BackendError::Cancelled, IssueEffect::None);
        }
        if server.expired(c) {
            return fail(BackendError::Timeout, IssueEffect::None);
        }
        if o.requested_ttl.as_secs() == 0 && behaviour.kind() == ResolveKind::DynamicIssue {
            // C-4 rounds down; C-36 requires positive lifetime. Refuse before issue.
            return fail(BackendError::TtlExceeded, IssueEffect::None);
        }
        if matches!(behaviour, Behaviour::Throttle | Behaviour::ThrottleDyn) {
            let mut s = server.lock();
            let throttled = match &mut s.throttles_left {
                None => true,
                Some(0) => false,
                Some(n) => {
                    *n -= 1;
                    true
                }
            };
            if throttled {
                let hint = s.throttle_retry_after;
                return fail(BackendError::rate_limited(hint), IssueEffect::None);
            }
        }
        let resolved = match behaviour {
            Behaviour::Static | Behaviour::Throttle => self.static_resolved(name),
            // Safe read that never answers: the deadline ends the wait (no sleeping).
            Behaviour::SlowStatic => {
                server.clock.advance_to(c.deadline);
                fail(BackendError::Timeout, IssueEffect::None)
            }
            _ => self.dynamic(c, behaviour, name, o),
        };
        if let Ok(bundle) = &resolved.result {
            server.lock().metadata_tokens.insert(r.issuance.clone(), MetadataToken { version: bundle.change.version.clone(), etag: bundle.change.etag.clone(), credential_expires_at: bundle.lease.as_ref().map(|l| l.expires_at) });
        }
        resolved
    }
    fn metadata(&self, c: &CallContext<'_>, r: &NativeRef) -> BResult<Meta> {
        let (enabled, mode, gate, token) = {
            let mut s = self.server.lock();
            s.metadata_calls += 1;
            (s.metadata_enabled, s.metadata_mode, s.metadata_gate.clone(), s.metadata_tokens.get(&r.issuance).cloned())
        };
        if let Some(gate) = gate { gate.pass(); }
        if (c.cancelled)() { return Err(BackendError::Cancelled); }
        if self.server.expired(c) { return Err(BackendError::Timeout); }
        if !enabled { return Err(BackendError::Unsupported); }
        let MetadataToken { version, etag, credential_expires_at } = token.ok_or(BackendError::NotFound)?;
        match mode {
            MetadataMode::Unsupported => Err(BackendError::Unsupported),
            MetadataMode::Error => Err(BackendError::Transient),
            MetadataMode::Changed => Ok(Meta { change: ChangeToken { version: Some("metadata-changed".into()), etag: None }, credential_expires_at }),
            MetadataMode::Unchanged => Ok(Meta { change: ChangeToken { version, etag }, credential_expires_at }),
        }
    }
    fn revoke(&self, c: &CallContext<'_>, lease_id: &LeaseId) -> BResult<()> {
        let server = &self.server;
        if (c.cancelled)() {
            return Err(BackendError::Cancelled);
        }
        if server.expired(c) {
            return Err(BackendError::Timeout);
        }
        let mut s = server.lock();
        let outcome = match s.leases.get_mut(lease_id.as_str()) {
            None => Err(BackendError::NotFound),
            Some(l) if l.revoke_failures_left > 0 => {
                l.revoke_failures_left -= 1;
                Err(BackendError::Transient)
            }
            Some(l) => {
                l.revoked = true;
                Ok(())
            }
        };
        let credential_matches = s.expected_credential.as_ref().map(|v| v.as_slice() == c.credential);
        s.revoke_log.push(RevokeAttempt {
            lease_id: lease_id.as_str().into(),
            succeeded: outcome.is_ok(),
            credential_matches,
        });
        outcome
    }
}
