//! Daemon-internal, RAM-only backend lifecycle. No wire types or ambient credentials.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrantId(u64);
static NEXT_GRANT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionId(u64);
impl SessionId {
    /// Only the daemon may construct this from its verified kernel session identity.
    pub fn from_kernel(id: u64) -> Self {
        Self(id)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Time {
    pub monotonic: Instant,
    pub wall: u64,
}
pub trait Clock: Send + Sync {
    fn now(&self) -> Time;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    At(u64),
    Unknown,
    NotApplicable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    None,
    Pending,
    Acknowledged,
    ExpiredUnconfirmed,
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct FiveClocks {
    pub permission_expires_at: Expiry,
    pub login_expires_at: Expiry,
    pub credential_expires_at: Expiry,
    pub cache_fresh_until: Expiry,
    pub revocation: Revocation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditPhase {
    Intent,
    Result,
    Outcome,
    Containment,
}
#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub operation: u64,
    pub phase: AuditPhase,
    pub action: &'static str,
    pub mode: &'static str,
    pub source: String,
    pub kind: String,
    pub binding: BindingHash,
    pub grant: Option<GrantId>,
    pub session: Option<SessionId>,
    pub issuance: Option<String>,
    pub selectors: Vec<String>,
    pub cache_hit: bool,
    pub clocks: Option<FiveClocks>,
    pub version: Option<String>,
    pub etag: Option<String>,
    pub lease_id: Option<LeaseId>,
    pub error: Option<BackendError>,
}
pub trait AuditSink: Send + Sync {
    fn append(&self, record: &AuditRecord) -> BResult<()>;
}
/// Called outside the service lock. The daemon must validate its entire grant scope here.
/// The service atomically consumes optional grant use limits after the final revision recheck.
pub trait Authorize: Send + Sync {
    fn allow(&self, grant: GrantId, session: SessionId, issuance: &str, selector: &str) -> bool;
}
pub struct Binding {
    pub source: String,
    pub hash: BindingHash,
    pub backend: Arc<dyn SecretBackend>,
    pub credential: Zeroizing<Vec<u8>>,
    pub login_expires_at: Expiry,
    /// Verified upstream maximum, not merely a requested local cap. None refuses dynamic issue.
    pub upstream_max_ttl: Option<Duration>,
    pub requested_ttl: Duration,
    pub freshness: Duration,
}
impl Binding {
    pub fn new(
        config: &SourceConfig,
        backend: Arc<dyn SecretBackend>,
        credential: Zeroizing<Vec<u8>>,
        upstream_max_ttl: Option<Duration>,
    ) -> BResult<Self> {
        Ok(Self {
            source: config.name.clone(),
            hash: config.binding_hash()?,
            backend,
            credential,
            login_expires_at: Expiry::Unknown,
            upstream_max_ttl,
            requested_ttl: Duration::from_secs(300),
            freshness: Duration::from_secs(30),
        })
    }
}
#[derive(Clone, Copy)]
struct Window {
    wall: u64,
    mono: Instant,
}
impl Window {
    fn new(now: Time, seconds: u64) -> Self {
        Self {
            wall: now.wall.saturating_add(seconds),
            mono: now.monotonic + Duration::from_secs(seconds),
        }
    }
    fn remaining(self, now: Time) -> u64 {
        self.wall
            .saturating_sub(now.wall)
            .min(self.mono.saturating_duration_since(now.monotonic).as_secs())
    }
    fn live(self, now: Time) -> bool {
        now.wall < self.wall && now.monotonic < self.mono
    }
}
struct Grant {
    session: SessionId,
    revision: u64,
    permission: Window,
    consumers: BTreeSet<u64>,
    remaining_uses: Option<u32>,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    binding: BindingHash,
    issuance: String,
    grant: GrantId,
}
#[derive(Clone)]
struct Entry {
    session: SessionId,
    bundle: Arc<Bundle>,
    fresh: Window,
    credential: Option<Window>,
    lease: Option<u64>,
}
struct Flight {
    id: u64,
    session: SessionId,
    participants: BTreeMap<u64, Participant>,
    membership_revision: u64,
}
#[derive(Clone)]
struct Participant {
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    selectors: Vec<String>,
}
struct Completed {
    entry: Entry,
    cohort: BTreeSet<u64>,
}
struct Lease {
    id: LeaseId,
    binding: Arc<Binding>,
    owner: GrantId,
    session: SessionId,
    expires: Window,
    state: Revocation,
    next: Instant,
    failures: u32,
    busy: bool,
    permission: Window,
    login_expiry: Expiry,
}
struct ContainmentEvent {
    lease_id: Option<LeaseId>,
    binding: Arc<Binding>,
    action: &'static str,
    grant: GrantId,
    session: SessionId,
    clocks: FiveClocks,
}
struct State {
    binding: Option<Arc<Binding>>,
    generation: u64,
    login_generation: u64,
    login_deadline: Option<Window>,
    login_expiry: Expiry,
    grants: BTreeMap<GrantId, Grant>,
    entries: BTreeMap<Key, Entry>,
    flights: BTreeMap<Key, Flight>,
    completed: BTreeMap<Key, Completed>,
    failures: BTreeMap<Key, (u64, BackendError)>,
    leases: BTreeMap<u64, Lease>,
    next_id: u64,
    last_time: Time,
    audit_failures: u64,
    containment_events: Vec<ContainmentEvent>,
}
pub struct BackendService {
    state: Mutex<State>,
    wake: Condvar,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditSink>,
    authorize: Arc<dyn Authorize>,
}
pub struct ResolveRequest<'a> {
    pub grant: GrantId,
    pub session: SessionId,
    pub native: &'a str,
    /// A batch of local field projections; all are checked before any effect.
    pub selectors: &'a [&'a str],
    /// Owned for flight participation; must not capture secret values.
    pub cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}
/// No Debug implementation: projections and whole-bundle redaction material are secret.
pub struct Delivery {
    pub fields: BTreeMap<String, SecretField>,
    /// Every bundle field, including unselected fields; for bound-run redaction only.
    pub redact: Vec<Zeroizing<Vec<u8>>>,
}
#[derive(Clone, Debug)]
pub struct PendingRevoke {
    pub lease_id: LeaseId,
    pub next_retry: Instant,
    pub expires_at: u64,
    pub owner: GrantId,
    pub session: SessionId,
}
#[derive(Clone, Debug)]
pub struct EntryStatus {
    pub grant: GrantId,
    pub session: SessionId,
    pub issuance: String,
    pub clocks: FiveClocks,
}
#[derive(Clone, Debug)]
pub struct ServiceStatus {
    pub entries: Vec<EntryStatus>,
    pub pending_revoke: Vec<PendingRevoke>,
    pub owners: usize,
    /// Callers registered behind a running leader (value-free synchronization observation).
    pub registered_waiters: usize,
    pub binding_generation: u64,
    pub remaining_uses: Vec<(GrantId, Option<u32>)>,
    pub audit_failures: u64,
    pub startup_note: &'static str,
}
// Removes participation on every return, including per-caller refusal.
struct Participation<'a> {
    service: &'a BackendService,
    key: Key,
    caller: u64,
}
impl Drop for Participation<'_> {
    fn drop(&mut self) {
        let now = self.service.clock.now();
        let mut s = self.service.lock();
        if let Some(f) = s.flights.get_mut(&self.key)
            && f.participants.remove(&self.caller).is_some()
        {
            f.membership_revision += 1;
        }
        let done = if let Some(c) = s.completed.get_mut(&self.key) {
            c.cohort.remove(&self.caller);
            c.cohort.is_empty()
        } else {
            false
        };
        if done {
            let c = s.completed.remove(&self.key).unwrap();
            if !s.entries.contains_key(&self.key)
                && let Some(id) = c.entry.lease
            {
                BackendService::pending(&mut s, id, now);
            }
        }
        drop(s);
        self.service.wake.notify_all();
    }
}
impl BackendService {
    pub fn new(
        binding: Binding,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
        authorize: Arc<dyn Authorize>,
    ) -> Self {
        let now = clock.now();
        Self {
            state: Mutex::new(State {
                login_deadline: match binding.login_expires_at {
                    Expiry::At(t) => Some(Window::new(now, t.saturating_sub(now.wall))),
                    _ => None,
                },
                login_expiry: binding.login_expires_at,
                binding: Some(Arc::new(binding)),
                generation: 0,
                login_generation: 0,
                grants: BTreeMap::new(),
                entries: BTreeMap::new(),
                flights: BTreeMap::new(),
                completed: BTreeMap::new(),
                failures: BTreeMap::new(),
                leases: BTreeMap::new(),
                next_id: 0,
                last_time: now,
                audit_failures: 0,
                containment_events: Vec::new(),
            }),
            wake: Condvar::new(),
            clock,
            audit,
            authorize,
        }
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn id(s: &mut State) -> u64 {
        s.next_id = s
            .next_id
            .checked_add(1)
            .expect("service identifier exhausted");
        s.next_id
    }
    pub fn grant(&self, session: SessionId, lifetime: Duration) -> BResult<GrantId> {
        self.create_grant(session, lifetime, None)
    }
    pub fn grant_with_uses(
        &self,
        session: SessionId,
        lifetime: Duration,
        uses: std::num::NonZeroU32,
    ) -> BResult<GrantId> {
        self.create_grant(session, lifetime, Some(uses.get()))
    }
    fn create_grant(
        &self,
        session: SessionId,
        lifetime: Duration,
        remaining_uses: Option<u32>,
    ) -> BResult<GrantId> {
        let now = self.clock.now();
        let mut s = self.lock();
        if s.binding.is_none() || lifetime.as_secs() == 0 {
            return Err(BackendError::Denied);
        }
        let id = GrantId(
            NEXT_GRANT
                .try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |n| n.checked_add(1),
                )
                .map_err(|_| BackendError::Denied)?,
        );
        s.grants.insert(
            id,
            Grant {
                session,
                revision: 0,
                permission: Window::new(now, lifetime.as_secs()),
                consumers: BTreeSet::new(),
                remaining_uses,
            },
        );
        Ok(id)
    }
    pub fn subscribe(&self, grant: GrantId, session: SessionId, consumer: u64) -> BResult<()> {
        let now = self.clock.now();
        let mut s = self.lock();
        let g = s.grants.get_mut(&grant).ok_or(BackendError::Denied)?;
        if g.session != session || !g.permission.live(now) {
            return Err(BackendError::Denied);
        }
        g.consumers.insert(consumer);
        Ok(())
    }
    pub fn consumer_exit(&self, grant: GrantId, session: SessionId, consumer: u64) {
        if let Some(g) = self
            .lock()
            .grants
            .get_mut(&grant)
            .filter(|g| g.session == session)
        {
            g.consumers.remove(&consumer);
        }
    }
    fn pending(s: &mut State, id: u64, now: Time) {
        if let Some(l) = s
            .leases
            .get_mut(&id)
            .filter(|l| l.state == Revocation::None)
        {
            l.state = Revocation::Pending;
            l.next = now.monotonic;
            s.containment_events.push(ContainmentEvent {
                lease_id: Some(l.id.clone()),
                binding: l.binding.clone(),
                action: "lease-pending",
                grant: l.owner,
                session: l.session,
                clocks: Self::lease_clocks(l),
            });
        }
        s.entries.retain(|_, e| e.lease != Some(id));
    }
    fn lease_clocks(l: &Lease) -> FiveClocks {
        FiveClocks {
            permission_expires_at: Expiry::At(l.permission.wall),
            login_expires_at: l.login_expiry,
            credential_expires_at: Expiry::At(l.expires.wall),
            cache_fresh_until: Expiry::Unknown,
            revocation: l.state,
        }
    }
    fn queue_owner_event(s: &mut State, grant: GrantId, action: &'static str) {
        if let (Some(g), Some(binding)) = (s.grants.get(&grant), s.binding.clone()) {
            let clocks = s
                .leases
                .values()
                .find(|l| l.owner == grant)
                .map(Self::lease_clocks)
                .or_else(|| {
                    s.entries
                        .iter()
                        .find(|(k, _)| k.grant == grant)
                        .map(|(_, e)| Self::clocks(s.login_expiry, g.permission, e))
                })
                .unwrap_or(FiveClocks {
                    permission_expires_at: Expiry::At(g.permission.wall),
                    login_expires_at: s.login_expiry,
                    credential_expires_at: Expiry::Unknown,
                    cache_fresh_until: Expiry::Unknown,
                    revocation: Revocation::Pending,
                });
            s.containment_events.push(ContainmentEvent {
                lease_id: None,
                binding,
                action,
                grant,
                session: g.session,
                clocks,
            });
        }
    }
    fn flush_containment(&self) {
        let events = std::mem::take(&mut self.lock().containment_events);
        for event in events {
            let id = Self::id(&mut self.lock());
            let mut record =
                Self::record(&event.binding, id, AuditPhase::Containment, event.action);
            record.grant = Some(event.grant);
            record.session = Some(event.session);
            record.clocks = Some(event.clocks);
            record.lease_id = event.lease_id;
            let _ = self.append(&record);
        }
    }
    fn end(s: &mut State, grant: GrantId, now: Time, action: &'static str) {
        let ids: Vec<_> = s
            .leases
            .iter()
            .filter(|(_, l)| l.owner == grant)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            Self::pending(s, id, now);
        }
        Self::queue_owner_event(s, grant, action);
        s.grants.remove(&grant);
        s.entries.retain(|k, _| k.grant != grant);
    }
    pub fn end_owner(&self, grant: GrantId, session: SessionId) {
        let now = self.clock.now();
        {
            let mut s = self.lock();
            if !s.grants.get(&grant).is_some_and(|g| g.session == session) {
                return;
            }
            Self::end(&mut s, grant, now, "owner-ended");
        }
        self.flush_containment();
        self.wake.notify_all();
    }
    /// Atomically disables all old grants before exposing the replacement. Cleanup retains old Arc.
    pub fn retarget(&self, replacement: Option<Binding>) {
        let now = self.clock.now();
        {
            let mut s = self.lock();
            s.generation += 1;
            let grants: Vec<_> = s.grants.keys().copied().collect();
            for g in grants {
                Self::end(&mut s, g, now, "binding-invalidated");
            }
            s.failures.clear();
            s.login_expiry = replacement
                .as_ref()
                .map_or(Expiry::Unknown, |b| b.login_expires_at);
            s.login_deadline = replacement.as_ref().and_then(|b| match b.login_expires_at {
                Expiry::At(t) => Some(Window::new(now, t.saturating_sub(now.wall))),
                _ => None,
            });
            s.binding = replacement.map(Arc::new);
        }
        self.flush_containment();
        self.wake.notify_all();
    }
    pub fn invalidate_login(&self) {
        self.invalidate_login_if(None);
    }
    fn invalidate_login_if(&self, expected: Option<(u64, u64)>) {
        let now = self.clock.now();
        let mut s = self.lock();
        if expected.is_some_and(|pair| pair != (s.generation, s.login_generation)) {
            return;
        }
        s.login_generation += 1;
        // An observed auth failure must not allow reads with the same login snapshot.
        let grants: Vec<_> = s.grants.keys().copied().collect();
        for g in grants {
            Self::end(&mut s, g, now, "login-invalidated");
        }
        let ids: Vec<_> = s.leases.keys().copied().collect();
        for id in ids {
            Self::pending(&mut s, id, now);
        }
        s.entries.clear();
        drop(s);
        self.flush_containment();
        self.wake.notify_all();
    }
    fn observe(s: &mut State, now: Time) {
        let wall = now.wall.saturating_sub(s.last_time.wall);
        let mono = now
            .monotonic
            .saturating_duration_since(s.last_time.monotonic)
            .as_secs();
        if now.wall < s.last_time.wall || wall.abs_diff(mono) > 5 {
            let owners: Vec<_> = s.grants.keys().copied().collect();

            s.login_generation += 1;
            let ids: Vec<_> = s.leases.keys().copied().collect();
            for id in ids {
                Self::pending(s, id, now);
            }
            for owner in owners {
                Self::queue_owner_event(s, owner, "clock-invalidated");
            }
            s.entries.clear();
        }
        s.last_time = now;
        let ended: Vec<_> = s
            .grants
            .iter()
            .filter(|(_, g)| !g.permission.live(now))
            .map(|(id, _)| *id)
            .collect();
        for id in ended {
            Self::end(s, id, now, "permission-expired");
        }
    }
    fn record(
        binding: &Binding,
        operation: u64,
        phase: AuditPhase,
        action: &'static str,
    ) -> AuditRecord {
        AuditRecord {
            operation,
            phase,
            action,
            mode: "mode_a",
            source: binding.source.clone(),
            kind: binding.backend.id().into(),
            binding: binding.hash.clone(),
            grant: None,
            session: None,
            issuance: None,
            selectors: Vec::new(),
            cache_hit: false,
            clocks: None,
            version: None,
            etag: None,
            lease_id: None,
            error: None,
        }
    }
    fn append(&self, record: &AuditRecord) -> BResult<()> {
        self.audit.append(record).inspect_err(|_| {
            self.lock().audit_failures += 1;
        })
    }
    fn containment(&self, binding: &Binding, action: &'static str, lease: Option<LeaseId>) {
        self.containment_error(binding, action, lease, None);
    }
    fn containment_error(
        &self,
        binding: &Binding,
        action: &'static str,
        lease: Option<LeaseId>,
        error: Option<BackendError>,
    ) {
        let id = Self::id(&mut self.lock());
        let mut r = Self::record(binding, id, AuditPhase::Containment, action);
        r.lease_id = lease;
        r.error = error;
        {
            let s = self.lock();
            if let Some(l) = s
                .leases
                .values()
                .find(|l| Some(&l.id) == r.lease_id.as_ref() && l.binding.hash == binding.hash)
            {
                r.grant = Some(l.owner);
                r.session = Some(l.session);
                r.clocks = Some(FiveClocks {
                    permission_expires_at: Expiry::At(l.permission.wall),
                    login_expires_at: l.login_expiry,
                    credential_expires_at: Expiry::At(l.expires.wall),
                    cache_fresh_until: Expiry::Unknown,
                    revocation: l.state,
                });
            }
        }
        let _ = self.append(&r);
    }
    fn authorized(&self, r: &ResolveRequest<'_>, issuance: &str, selectors: &[String]) -> bool {
        selectors
            .iter()
            .all(|f| self.authorize.allow(r.grant, r.session, issuance, f))
    }
    fn valid(
        s: &State,
        r: &ResolveRequest<'_>,
        generation: u64,
        login: u64,
        revision: u64,
        now: Time,
    ) -> bool {
        s.generation == generation
            && s.login_deadline.is_none_or(|w| w.live(now))
            && s.login_generation == login
            && s.grants.get(&r.grant).is_some_and(|g| {
                g.session == r.session && g.revision == revision && g.permission.live(now)
            })
    }
    fn clocks(login_expiry: Expiry, permission: Window, e: &Entry) -> FiveClocks {
        FiveClocks {
            permission_expires_at: Expiry::At(permission.wall),
            login_expires_at: login_expiry,
            credential_expires_at: e
                .bundle
                .lease
                .as_ref()
                .map_or(Expiry::NotApplicable, |l| Expiry::At(l.expires_at)),
            cache_fresh_until: Expiry::At(e.fresh.wall),
            revocation: if e.lease.is_some() {
                Revocation::None
            } else {
                Revocation::Unsupported
            },
        }
    }
    fn usable(binding: &Binding, e: &Entry, now: Time) -> bool {
        e.fresh.live(now)
            && e.credential.is_none_or(|w| w.live(now))
            && match binding.login_expires_at {
                Expiry::At(t) => t > now.wall,
                _ => true,
            }
    }
    pub fn resolve(&self, r: ResolveRequest<'_>) -> BResult<Delivery> {
        let result = self.resolve_impl(r);
        self.flush_containment();
        result
    }
    fn resolve_impl(&self, r: ResolveRequest<'_>) -> BResult<Delivery> {
        let start = self.clock.now();
        let (binding, generation, login, revision, permission, login_expiry, operation) = {
            let mut s = self.lock();
            Self::observe(&mut s, start);
            let b = s.binding.clone().ok_or(BackendError::NotFound)?;
            let g = s.grants.get(&r.grant).ok_or(BackendError::Denied)?;
            if g.session != r.session {
                return Err(BackendError::Denied);
            }
            let snapshot = (
                b,
                s.generation,
                s.login_generation,
                g.revision,
                g.permission,
            );
            (
                snapshot.0,
                snapshot.1,
                snapshot.2,
                snapshot.3,
                snapshot.4,
                s.login_expiry,
                Self::id(&mut s),
            )
        };
        let native = binding.backend.parse_ref(r.native)?;
        let kind = binding.backend.resolve_kind(&native)?;
        let selectors: Vec<String> = if r.selectors.is_empty() {
            vec![native.field.clone().unwrap_or_else(|| "value".into())]
        } else {
            r.selectors.iter().map(|s| (*s).into()).collect()
        };
        if !self.authorized(&r, &native.issuance, &selectors) {
            return Err(BackendError::Denied);
        }
        if (r.cancelled)() {
            return Err(BackendError::Cancelled);
        }
        let key = Key {
            binding: binding.hash.clone(),
            issuance: native.issuance.clone(),
            grant: r.grant,
        };
        let mut record = Self::record(&binding, operation, AuditPhase::Intent, "resolve");
        record.grant = Some(r.grant);
        record.session = Some(r.session);
        record.issuance = Some(native.issuance.clone());
        record.selectors = selectors.clone();
        record.clocks = Some(FiveClocks {
            permission_expires_at: Expiry::At(permission.wall),
            login_expires_at: login_expiry,
            credential_expires_at: if kind == ResolveKind::StaticRead {
                Expiry::NotApplicable
            } else {
                Expiry::Unknown
            },
            cache_fresh_until: Expiry::Unknown,
            revocation: if kind == ResolveKind::StaticRead {
                Revocation::Unsupported
            } else {
                Revocation::None
            },
        });
        self.append(&record)
            .map_err(|_| BackendError::AuditUnavailable)?;
        let result = self.resolve_inner(
            &r,
            &binding,
            &native,
            &selectors,
            kind,
            &key,
            generation,
            login,
            revision,
            permission,
            start,
            &mut record,
        );
        // Delivery/participation teardown may have contained an owned effect.
        if let Some(id) = &record.lease_id {
            let s = self.lock();
            if let Some(l) = s
                .leases
                .values()
                .find(|l| &l.id == id && l.binding.hash == binding.hash)
                && l.state != Revocation::None
            {
                record.clocks = Some(Self::lease_clocks(l));
            }
        }
        self.flush_containment();
        record.phase = AuditPhase::Outcome;
        record.error = result.as_ref().err().copied();
        let _ = self.append(&record);
        result
    }
    #[allow(clippy::too_many_arguments)]
    fn resolve_inner(
        &self,
        r: &ResolveRequest<'_>,
        binding: &Arc<Binding>,
        native: &NativeRef,
        selectors: &[String],
        kind: ResolveKind,
        key: &Key,
        generation: u64,
        login: u64,
        revision: u64,
        permission: Window,
        start: Time,
        record: &mut AuditRecord,
    ) -> BResult<Delivery> {
        let caller = record.operation;
        let _participation = Participation {
            service: self,
            key: key.clone(),
            caller,
        };
        let mut waited = None;
        let flight_id;
        let mut revalidate = None;
        let metadata_supported = binding.backend.capabilities().metadata;
        loop {
            let now = self.clock.now();
            if (r.cancelled)() {
                return Err(BackendError::Cancelled);
            }
            if !self.authorized(r, &native.issuance, selectors) {
                return Err(BackendError::Denied);
            }
            let mut s = self.lock();
            Self::observe(&mut s, now);
            if !Self::valid(&s, r, generation, login, revision, now) {
                return Err(BackendError::BindingChanged);
            }
            if let Some(c) = s.completed.get(key).filter(|c| c.cohort.contains(&caller)) {
                let e = c.entry.clone();
                record.clocks = Some(Self::clocks(s.login_expiry, permission, &e));
                drop(s);
                return self.deliver(
                    r,
                    binding,
                    native,
                    selectors,
                    key,
                    generation,
                    login,
                    revision,
                    e.bundle,
                    e.lease,
                    e.fresh,
                    e.credential,
                    record,
                );
            }
            if let Some(e) = s
                .entries
                .get(key)
                .filter(|e| e.session == r.session && Self::usable(binding, e, now))
            {
                let bundle = e.bundle.clone();
                let lease = e.lease;
                let fresh = e.fresh;
                let credential = e.credential;
                record.cache_hit = true;
                record.clocks = Some(Self::clocks(s.login_expiry, permission, e));
                drop(s);
                return self.deliver(
                    r, binding, native, selectors, key, generation, login, revision, bundle, lease,
                    fresh, credential, record,
                );
            }
            if let Some((id, err)) = s.failures.get(key)
                && (waited == Some(*id) || *err == BackendError::Indeterminate)
            {
                return Err(*err);
            }
            if let Some(f) = s.flights.get_mut(key) {
                if f.session != r.session {
                    return Err(BackendError::Denied);
                }
                if let std::collections::btree_map::Entry::Vacant(e) = f.participants.entry(caller)
                {
                    e.insert(Participant {
                        cancelled: r.cancelled.clone(),
                        selectors: selectors.to_vec(),
                    });
                    f.membership_revision += 1;
                }
                waited = Some(f.id);
                drop(self.wake.wait(s).unwrap_or_else(|e| e.into_inner()));
                continue;
            }
            if s.completed.contains_key(key) {
                drop(self.wake.wait(s).unwrap_or_else(|e| e.into_inner()));
                continue;
            }
            if let Some(e) = s.entries.remove(key) {
                if metadata_supported
                    && e.session == r.session
                    && e.credential.is_none_or(|w| w.live(now))
                    && !binding.freshness.is_zero()
                    && !e.bundle.fresh_for.is_zero()
                {
                    revalidate = Some(e);
                } else if let Some(id) = e.lease {
                    Self::pending(&mut s, id, now);
                }
            }
            flight_id = Self::id(&mut s);
            s.flights.insert(
                key.clone(),
                Flight {
                    id: flight_id,
                    membership_revision: 0,
                    session: r.session,
                    participants: BTreeMap::from([(
                        caller,
                        Participant {
                            cancelled: r.cancelled.clone(),
                            selectors: selectors.to_vec(),
                        },
                    )]),
                },
            );
            break;
        }
        // All adapter calls and audit callbacks execute with State unlocked.
        let flight_cancelled = || loop {
            let now = self.clock.now();
            let (membership_revision, participants) = {
                let s = self.lock();
                if !Self::valid(&s, r, generation, login, revision, now) {
                    return true;
                }
                let Some(f) = s.flights.get(key).filter(|f| f.id == flight_id) else {
                    return true;
                };
                (
                    f.membership_revision,
                    f.participants.values().cloned().collect::<Vec<_>>(),
                )
            };
            let cancelled = participants.iter().all(|p| {
                (p.cancelled)()
                    || !p.selectors.iter().all(|selector| {
                        self.authorize
                            .allow(r.grant, r.session, &native.issuance, selector)
                    })
            });
            let now = self.clock.now();
            let s = self.lock();
            if !Self::valid(&s, r, generation, login, revision, now) {
                return true;
            }
            let Some(f) = s.flights.get(key).filter(|f| f.id == flight_id) else {
                return true;
            };
            if cancelled && f.membership_revision != membership_revision {
                continue;
            }
            return cancelled;
        };
        if let Some(mut entry) = revalidate {
            let ctx = CallContext {
                credential: &binding.credential,
                deadline: start.monotonic + Duration::from_secs(30),
                cancelled: &flight_cancelled,
            };
            let meta = binding.backend.metadata(&ctx, native);
            let cancelled = flight_cancelled();
            let now = self.clock.now();
            let mut s = self.lock();
            Self::observe(&mut s, now);
            let valid = Self::valid(&s, r, generation, login, revision, now)
                && now.monotonic < ctx.deadline
                && entry.credential.is_none_or(|w| w.live(now))
                && entry.lease.is_none_or(|id| {
                    s.leases
                        .get(&id)
                        .is_some_and(|l| l.state == Revocation::None)
                });
            let unchanged = meta.as_ref().is_ok_and(|m| {
                (m.change.version.is_some() || m.change.etag.is_some())
                    && m.change.version == entry.bundle.change.version
                    && m.change.etag == entry.bundle.change.etag
                    && m.credential_expires_at == entry.bundle.lease.as_ref().map(|l| l.expires_at)
            });
            if valid && !cancelled && unchanged {
                entry.fresh = Window::new(
                    now,
                    entry
                        .bundle
                        .fresh_for
                        .min(binding.freshness)
                        .min(Duration::from_secs(60))
                        .as_secs(),
                );
                record.clocks = Some(Self::clocks(s.login_expiry, permission, &entry));
                let flight = s.flights.remove(key).unwrap();
                s.completed.insert(
                    key.clone(),
                    Completed {
                        entry: entry.clone(),
                        cohort: flight.participants.keys().copied().collect(),
                    },
                );
                s.failures.remove(key);
                drop(s);
                self.wake.notify_all();
                return self.deliver(
                    r,
                    binding,
                    native,
                    selectors,
                    key,
                    generation,
                    login,
                    revision,
                    entry.bundle,
                    entry.lease,
                    entry.fresh,
                    entry.credential,
                    record,
                );
            }
            if let Some(id) = entry.lease {
                Self::pending(&mut s, id, now);
                record.clocks = s.leases.get(&id).map(Self::lease_clocks);
                record.lease_id = s.leases.get(&id).map(|l| l.id.clone());
            }
            if !valid || cancelled {
                let error = if !valid {
                    BackendError::BindingChanged
                } else {
                    BackendError::Cancelled
                };
                s.flights.remove(key);
                s.failures.insert(key.clone(), (flight_id, error));
                drop(s);
                self.wake.notify_all();
                return Err(error);
            }
            // No stale-while-error: changed, unknown and failed metadata all resolve afresh.
        }
        let issue = self.issue(
            &flight_cancelled,
            binding,
            native,
            kind,
            permission,
            start,
            generation,
            login,
        );
        let (resolved, ttl) = issue;
        let mut validation_error = None;
        if matches!(resolved.result, Err(BackendError::AuthExpired)) {
            self.invalidate_login_if(Some((generation, login)));
        }
        let now = self.clock.now();
        let mut orphan = false;
        let (lease_id, credential) = {
            let mut s = self.lock();
            Self::observe(&mut s, now);
            let mut credential = None;
            let login_expiry = s.login_expiry;
            if let Some(clocks) = &mut record.clocks {
                clocks.login_expires_at = login_expiry;
            }
            let lease_id = match &resolved.effect {
                IssueEffect::Known(l) => {
                    record.lease_id = Some(l.id.clone());
                    let ttl_secs = l.server_ttl.as_secs();
                    let actual = ttl_secs.min(l.expires_at.saturating_sub(start.wall));
                    let margin = (ttl_secs / 10).clamp(1, 30);
                    if ttl_secs == 0 || ttl_secs > ttl || actual <= margin {
                        validation_error = Some(BackendError::TtlExceeded);
                    }
                    let expiry = Window::new(start, actual);
                    credential = Some(Window::new(start, actual.saturating_sub(margin)));
                    let id = Self::id(&mut s);
                    s.leases.insert(
                        id,
                        Lease {
                            id: l.id.clone(),
                            binding: binding.clone(),
                            owner: r.grant,
                            session: r.session,
                            expires: expiry,
                            state: Revocation::None,
                            next: now.monotonic,
                            failures: 0,
                            busy: false,
                            permission,
                            login_expiry,
                        },
                    );
                    Some(id)
                }
                IssueEffect::KnownId { id } => {
                    record.lease_id = Some(id.clone());
                    let serial = Self::id(&mut s);
                    // C-40a: the actual TTL sent, conservatively anchored at request start.
                    s.leases.insert(
                        serial,
                        Lease {
                            id: id.clone(),
                            binding: binding.clone(),
                            owner: r.grant,
                            session: r.session,
                            expires: Window::new(start, ttl),
                            state: Revocation::None,
                            next: now.monotonic,
                            failures: 0,
                            busy: false,
                            permission,
                            login_expiry,
                        },
                    );
                    Self::pending(&mut s, serial, now);
                    validation_error = Some(BackendError::TtlExceeded);
                    Some(serial)
                }
                IssueEffect::Unknown => {
                    orphan = true;
                    validation_error = Some(BackendError::Indeterminate);
                    None
                }
                IssueEffect::None => None,
            };
            if !Self::valid(&s, r, generation, login, revision, now) {
                validation_error = Some(BackendError::BindingChanged);
            }
            (lease_id, credential)
        };
        // The effect is now owned even when validation rejects the bundle.
        let checked = resolved.validate(kind);
        let mut result = match validation_error {
            Some(error) => Err(error),
            None => checked.and(resolved.result),
        };
        if result.is_ok() && flight_cancelled() {
            result = Err(BackendError::Cancelled);
        }
        if orphan {
            let mut orphan_record = record.clone();
            orphan_record.phase = AuditPhase::Containment;
            orphan_record.action = "potential-orphan";
            orphan_record.error = Some(BackendError::Indeterminate);
            let _ = self.append(&orphan_record);
        }
        let result = result.and_then(|bundle| {
            let fresh_seconds = bundle
                .fresh_for
                .min(binding.freshness)
                .min(Duration::from_secs(60))
                .as_secs();
            let fresh = Window::new(now, fresh_seconds);
            let bundle = Arc::new(bundle);
            {
                let mut s = self.lock();
                if !Self::valid(&s, r, generation, login, revision, now) {
                    return Err(BackendError::BindingChanged);
                }
                if let Some(id) = lease_id
                    && s.leases
                        .get(&id)
                        .is_none_or(|l| l.state != Revocation::None)
                {
                    return Err(BackendError::BindingChanged);
                }
                let entry = Entry {
                    session: r.session,
                    bundle: bundle.clone(),
                    fresh,
                    credential,
                    lease: lease_id,
                };
                record.clocks = Some(Self::clocks(s.login_expiry, permission, &entry));
                // Only the already registered cohort can consume this completion; each
                // caller still audits, reauthorizes and projects independently.
                let flight = s.flights.remove(key).unwrap();
                s.completed.insert(
                    key.clone(),
                    Completed {
                        entry,
                        cohort: flight.participants.keys().copied().collect(),
                    },
                );
                s.failures.remove(key);
                // Dropping flight drops every retained cancellation closure.
                drop(flight);
                self.wake.notify_all();
            }
            self.deliver(
                r, binding, native, selectors, key, generation, login, revision, bundle, lease_id,
                fresh, credential, record,
            )
        });
        let now = self.clock.now();
        {
            let mut s = self.lock();
            if let Err(err) = result.as_ref()
                && !s.completed.contains_key(key)
            {
                if let Some(id) = lease_id {
                    Self::pending(&mut s, id, now);
                    record.clocks = s.leases.get(&id).map(Self::lease_clocks);
                }
                s.failures.insert(
                    key.clone(),
                    (
                        flight_id,
                        if orphan {
                            BackendError::Indeterminate
                        } else {
                            *err
                        },
                    ),
                );
            } else {
                s.failures.remove(key);
            }
            s.flights.remove(key);
        }
        self.wake.notify_all();
        result
    }
    #[allow(clippy::too_many_arguments)]
    fn issue(
        &self,
        cancelled: &(dyn Fn() -> bool + Send + Sync),
        binding: &Binding,
        native: &NativeRef,
        kind: ResolveKind,
        permission: Window,
        start: Time,
        generation: u64,
        login: u64,
    ) -> (Resolved, u64) {
        let auth = binding.backend.auth_status();
        if let Some(expiry) = auth.expires_at {
            let now = self.clock.now();
            let mut s = self.lock();
            // Observation may only shorten this immutable login generation.
            if s.generation == generation && s.login_generation == login {
                let window = Window::new(now, expiry.saturating_sub(now.wall));
                if s.login_deadline.is_none_or(|old| window.wall < old.wall) {
                    s.login_deadline = Some(window);
                    s.login_expiry = Expiry::At(expiry);
                }
            }
        }
        let ttl = binding
            .requested_ttl
            .as_secs()
            .min(900)
            .min(permission.remaining(self.clock.now()));
        if kind == ResolveKind::DynamicIssue
            && (ttl == 0
                || binding
                    .upstream_max_ttl
                    .is_none_or(|d| d.as_secs() == 0 || d > Duration::from_secs(900)))
        {
            return (
                Resolved {
                    result: Err(BackendError::Unsupported),
                    effect: IssueEffect::None,
                },
                ttl,
            );
        }
        if auth.needs_human
            || auth.expires_at.is_some_and(|t| t <= start.wall)
            || matches!(binding.login_expires_at, Expiry::At(t) if t <= start.wall)
        {
            return (
                Resolved {
                    result: Err(BackendError::AuthExpired),
                    effect: IssueEffect::None,
                },
                ttl,
            );
        }
        let ctx = CallContext {
            credential: &binding.credential,
            deadline: start.monotonic + Duration::from_secs(30),
            cancelled,
        };
        let resolved = binding.backend.resolve(
            &ctx,
            native,
            &ResolveOpts {
                requested_ttl: Duration::from_secs(ttl),
            },
        );
        (resolved, ttl)
    }
    #[allow(clippy::too_many_arguments)]
    fn deliver(
        &self,
        r: &ResolveRequest<'_>,
        binding: &Binding,
        native: &NativeRef,
        selectors: &[String],
        key: &Key,
        generation: u64,
        login: u64,
        revision: u64,
        bundle: Arc<Bundle>,
        lease: Option<u64>,
        fresh: Window,
        credential: Option<Window>,
        record: &mut AuditRecord,
    ) -> BResult<Delivery> {
        record.phase = AuditPhase::Result;
        record.version = bundle.change.version.clone();
        record.etag = bundle.change.etag.clone();
        record.lease_id = bundle.lease.as_ref().map(|l| l.id.clone());
        if self.append(record).is_err() {
            if let Some(id) = lease {
                let now = self.clock.now();
                Self::pending(&mut self.lock(), id, now);
                self.containment(binding, "delivery-refused", record.lease_id.clone());
            }
            return Err(BackendError::DeliveryRefused);
        }
        if (r.cancelled)() {
            return Err(BackendError::Cancelled);
        }
        if !self.authorized(r, &native.issuance, selectors) {
            return Err(BackendError::Denied);
        }
        let now = self.clock.now();
        let mut s = self.lock();
        Self::observe(&mut s, now);
        if !Self::valid(&s, r, generation, login, revision, now)
            || credential.is_some_and(|w| !w.live(now))
            || matches!(binding.login_expires_at, Expiry::At(t) if t <= now.wall)
            || ((record.cache_hit || bundle.fresh_for.min(binding.freshness).as_secs() > 0)
                && !fresh.live(now))
            || lease.is_some_and(|id| {
                s.leases
                    .get(&id)
                    .is_none_or(|l| l.state != Revocation::None)
            })
        {
            return Err(BackendError::BindingChanged);
        }
        let redact = bundle.fields().values().map(|field| match field {
            SecretField::Text(v) => Zeroizing::new(v.as_bytes().to_vec()),
            SecretField::Bytes(v) => v.clone(),
        }).collect();
        let mut fields = BTreeMap::new();
        for f in selectors {
            let value = match bundle.fields().get(f).ok_or(BackendError::InvalidRef)? {
                SecretField::Text(v) => SecretField::Text(v.clone()),
                SecretField::Bytes(v) => SecretField::Bytes(v.clone()),
            };
            fields.insert(f.clone(), value);
        }
        s.entries.insert(
            key.clone(),
            Entry {
                session: r.session,
                bundle,
                fresh,
                credential,
                lease,
            },
        );
        let grant = s.grants.get_mut(&r.grant).ok_or(BackendError::Denied)?;
        if let Some(uses) = &mut grant.remaining_uses {
            if *uses == 0 {
                return Err(BackendError::Denied);
            }
            *uses -= 1;
            if *uses == 0 {
                Self::end(&mut s, r.grant, now, "uses-exhausted");
            }
        }
        Ok(Delivery { fields, redact })
    }
    /// Explicit daemon scheduler entry. Exactly one in-flight revoke per local lease record.
    pub fn tick(&self, now: Time) {
        let work = {
            let mut s = self.lock();
            Self::observe(&mut s, now);
            let mut work = Vec::new();
            let expired: Vec<_> = s
                .leases
                .iter()
                .filter(|(_, l)| !l.expires.live(now))
                .map(|(id, _)| *id)
                .collect();
            for id in expired {
                Self::pending(&mut s, id, now);
            }
            for (serial, l) in &mut s.leases {
                if l.state == Revocation::None && !l.expires.live(now) {
                    l.state = Revocation::Pending;
                }
                if l.state == Revocation::Pending
                    && !l.busy
                    && (l.next <= now.monotonic || !l.expires.live(now))
                {
                    l.busy = true;
                    work.push((
                        *serial,
                        l.id.clone(),
                        l.binding.clone(),
                        !l.expires.live(now),
                    ));
                }
            }
            work
        };
        self.flush_containment();
        for (serial, id, binding, expired) in work {
            if expired {
                {
                    let mut s = self.lock();
                    let l = s.leases.get_mut(&serial).unwrap();
                    l.state = Revocation::ExpiredUnconfirmed;
                    l.busy = false;
                }
                self.containment(&binding, "revoke-abandoned-at-upstream-expiry", Some(id));
                self.lock().leases.remove(&serial);
                continue;
            }
            self.containment(&binding, "revoke-attempt", Some(id.clone()));
            let ctx = CallContext {
                credential: &binding.credential,
                deadline: now.monotonic + Duration::from_secs(30),
                cancelled: &|| false,
            };
            let result = binding.backend.revoke(&ctx, &id);
            if result.is_ok() {
                self.lock().leases.get_mut(&serial).unwrap().state = Revocation::Acknowledged;
            }
            self.containment_error(
                &binding,
                if result.is_ok() {
                    "revoke-acknowledged"
                } else {
                    "revoke-failed"
                },
                Some(id),
                result.err(),
            );
            let completed = self.clock.now();
            {
                let mut s = self.lock();
                let l = s.leases.get_mut(&serial).unwrap();
                l.busy = false;
                if result.is_ok() {
                    l.state = Revocation::Acknowledged;
                } else {
                    let delay = (1u64 << l.failures.min(6)).min(60);
                    let delay = if let Err(BackendError::RateLimited { retry_after }) = result {
                        delay.max(retry_after.as_secs())
                    } else {
                        delay
                    };
                    l.failures = l.failures.saturating_add(1);
                    l.next = (completed.monotonic + Duration::from_secs(delay)).min(l.expires.mono);
                }
            }
            if result.is_ok() {
                self.lock().leases.remove(&serial);
            }
        }
    }
    pub fn status(&self) -> ServiceStatus {
        let s = self.lock();
        let entries = s
            .entries
            .iter()
            .filter_map(|(key, e)| {
                let g = s.grants.get(&key.grant)?;
                Some(EntryStatus {
                    grant: key.grant,
                    session: e.session,
                    issuance: key.issuance.clone(),
                    clocks: Self::clocks(s.login_expiry, g.permission, e),
                })
            })
            .collect();
        let pending_revoke = s
            .leases
            .values()
            .filter(|l| l.state == Revocation::Pending)
            .map(|l| PendingRevoke {
                lease_id: l.id.clone(),
                next_retry: l.next,
                expires_at: l.expires.wall,
                owner: l.owner,
                session: l.session,
            })
            .collect();
        ServiceStatus {
            entries,
            pending_revoke,
            owners: s.grants.len(),
            registered_waiters: s
                .flights
                .values()
                .map(|f| f.participants.len().saturating_sub(1))
                .sum(),
            binding_generation: s.generation,
            remaining_uses: s
                .grants
                .iter()
                .map(|(id, g)| (*id, g.remaining_uses))
                .collect(),
            audit_failures: s.audit_failures,
            startup_note: "prior upstream tracking lost; prior credentials may remain valid up to configured TTL cap",
        }
    }
}
