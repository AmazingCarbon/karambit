//! Synthetic service tests only: no daemon, live credential, network or timing sleeps.
use karambit_core::backend::{
    fake::{FakeBackend, FakeClock, FakeServer, Gate},
    *,
};
use std::{
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;
const T0: u64 = 1_000_000;
const A: u64 = 11;
const B: u64 = 12;
fn session(n: u64) -> SessionId {
    SessionId::from_kernel(n)
}
struct TestClock(Arc<FakeClock>);
impl Clock for TestClock {
    fn now(&self) -> Time {
        Time {
            monotonic: self.0.now(),
            wall: self.0.wall(),
        }
    }
}
#[derive(Default)]
struct Audit {
    records: Mutex<Vec<AuditRecord>>,
    fail_result: AtomicBool,
    fail_all: AtomicBool,
    on_intent: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    on_containment: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    on_result: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
impl AuditSink for Audit {
    fn append(&self, r: &AuditRecord) -> BResult<()> {
        self.records.lock().unwrap().push(r.clone());
        let hook = match r.phase {
            AuditPhase::Intent => self.on_intent.lock().unwrap().clone(),
            AuditPhase::Containment => self.on_containment.lock().unwrap().clone(),
            _ => None,
        };
        if let Some(hook) = hook {
            hook();
        }
        if r.phase == AuditPhase::Result {
            let hook = self.on_result.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        if self.fail_all.load(Ordering::SeqCst)
            || (r.phase == AuditPhase::Result && self.fail_result.load(Ordering::SeqCst))
        {
            Err(BackendError::AuditUnavailable)
        } else {
            Ok(())
        }
    }
}
struct Auth {
    allowed: AtomicBool,
    calls: AtomicUsize,
}
impl Authorize for Auth {
    fn allow(&self, _: GrantId, _: SessionId, _: &str, _: &str) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.allowed.load(Ordering::SeqCst)
    }
}
struct Rig {
    clock: Arc<FakeClock>,
    server: Arc<FakeServer>,
    audit: Arc<Audit>,
    auth: Arc<Auth>,
    service: Arc<BackendService>,
    grant: GrantId,
}
fn binding(server: &Arc<FakeServer>, revision: &str, credential: &[u8]) -> Binding {
    let config = SourceConfig {
        name: "f".into(),
        kind: "fake".into(),
        endpoint: "https://synthetic.invalid/".into(),
        auth_method: "token".into(),
        credential_ref: "sources/f/cred".into(),
        credential_revision: revision.into(),
        generation: "0123456789abcdef0123456789abcdef".into(),
        policy: serde_json::json!({}),
    };
    Binding::new(
        &config,
        Arc::new(FakeBackend::new(server.clone())),
        Zeroizing::new(credential.to_vec()),
        Some(Duration::from_secs(900)),
    )
    .unwrap()
}
impl Rig {
    fn new() -> Self {
        let clock = FakeClock::new(T0);
        let server = FakeServer::new(clock.clone());
        let audit = Arc::new(Audit::default());
        let auth = Arc::new(Auth {
            allowed: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        let service = Arc::new(BackendService::new(
            binding(&server, "r1", b"synthetic-old"),
            Arc::new(TestClock(clock.clone())),
            audit.clone(),
            auth.clone(),
        ));
        let grant = service
            .grant(session(A), Duration::from_secs(1800))
            .unwrap();
        Self {
            clock,
            server,
            audit,
            auth,
            service,
            grant,
        }
    }
    fn resolve(&self, native: &str) -> BResult<Delivery> {
        self.as_owner(self.grant, session(A), native, Arc::new(|| false))
    }
    fn as_owner(
        &self,
        grant: GrantId,
        owner: SessionId,
        native: &str,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> BResult<Delivery> {
        self.service.resolve(ResolveRequest {
            grant,
            session: owner,
            native,
            selectors: &[],
            cancelled,
        })
    }
    fn tick(&self) {
        self.service.tick(Time {
            monotonic: self.clock.now(),
            wall: self.clock.wall(),
        });
    }
    fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }
    fn actions(&self) -> Vec<&'static str> {
        self.audit
            .records
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.action)
            .collect()
    }
}
fn error(result: BResult<Delivery>) -> BackendError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("unexpected delivery"),
    }
}
#[test]
fn session_b_cannot_hit_session_a_even_with_the_same_cache_key() {
    let r = Rig::new();
    assert!(r.resolve("ok/a#password").is_ok());
    assert_eq!(
        error(r.as_owner(r.grant, session(B), "ok/a#password", Arc::new(|| false))),
        BackendError::Denied
    );
    assert_eq!(r.server.issue_count(), 1);
    let other = r
        .service
        .grant(session(B), Duration::from_secs(500))
        .unwrap();
    assert!(
        r.as_owner(other, session(B), "ok/a#password", Arc::new(|| false))
            .is_ok()
    );
    assert_eq!(
        r.server.issue_count(),
        2,
        "new owner never inherits old issuance"
    );
}
#[test]
fn retarget_rejects_paused_issue_and_revokes_with_old_credential_snapshot() {
    for remove in [false, true] {
        let r = Rig::new();
        let replacement = FakeServer::new(r.clock.clone());
        r.server
            .set_expected_credential(Zeroizing::new(b"synthetic-old".to_vec()));
        replacement.set_expected_credential(Zeroizing::new(b"synthetic-new".to_vec()));
        let gate = Gate::new();
        r.server.gate_after_issue(gate.clone());
        let result = std::thread::scope(|s| {
            let h = s.spawn(|| r.resolve("ok/a#password"));
            gate.wait_reached();
            r.service.retarget(if remove {
                None
            } else {
                Some(binding(&replacement, "r2", b"synthetic-new"))
            });
            assert_eq!(r.service.status().owners, 0);
            gate.release();
            h.join().unwrap()
        });
        assert_eq!(error(result), BackendError::BindingChanged);
        assert_eq!(r.service.status().binding_generation, 1);
        assert!(r.service.status().entries.is_empty());
        assert_eq!(r.service.status().pending_revoke.len(), 1);
        assert_eq!(
            error(r.resolve("ok/a#password")),
            if remove {
                BackendError::NotFound
            } else {
                BackendError::Denied
            }
        );
        r.tick();
        let log = r.server.revoke_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].credential_matches, Some(true));
        assert!(replacement.revoke_log().is_empty());
        if remove {
            assert_eq!(
                r.service
                    .grant(session(A), Duration::from_secs(500))
                    .unwrap_err(),
                BackendError::Denied
            );
            assert_eq!(replacement.issue_count(), 0);
        } else {
            let new = r
                .service
                .grant(session(A), Duration::from_secs(500))
                .unwrap();
            assert!(
                r.as_owner(new, session(A), "ok/a#password", Arc::new(|| false))
                    .is_ok()
            );
            assert_eq!(replacement.resolve_credentials(), vec![Some(true)]);
        }
        assert_eq!(r.server.resolve_credentials(), vec![Some(true)]);
    }
}
#[test]
fn ok_batch_authorized_hit_and_intent_result_outcome_order() {
    let r = Rig::new();
    let first = r
        .service
        .resolve(ResolveRequest {
            grant: r.grant,
            session: session(A),
            native: "ok/a",
            selectors: &["user", "password"],
            cancelled: Arc::new(|| false),
        })
        .unwrap();
    assert_eq!(first.fields.len(), 2);
    assert_eq!(r.server.issue_count(), 1);
    assert!(
        r.service.status().pending_revoke.is_empty(),
        "successful Known remains active"
    );
    let before = r.auth.calls.load(Ordering::SeqCst);
    let second = r.resolve("ok/a#password").unwrap();
    assert_eq!(second.fields.len(), 1);
    assert!(r.auth.calls.load(Ordering::SeqCst) > before);
    assert_eq!(r.server.issue_count(), 1);
    let records = r.audit.records.lock().unwrap();
    assert_eq!(
        records.iter().map(|r| r.phase).collect::<Vec<_>>(),
        vec![
            AuditPhase::Intent,
            AuditPhase::Result,
            AuditPhase::Outcome,
            AuditPhase::Intent,
            AuditPhase::Result,
            AuditPhase::Outcome
        ]
    );
    assert!(records[4].cache_hit);
    assert!(records[1].lease_id.is_some());
    assert!(records[1].version.is_some());
    assert_eq!(
        records[1].clocks.as_ref().unwrap().credential_expires_at,
        Expiry::At(T0 + 300)
    );
}
#[test]
fn every_hit_rechecks_authorization_and_refuses_denied_delivery() {
    let r = Rig::new();
    assert!(r.resolve("ok/a#password").is_ok());
    let before = r.auth.calls.load(Ordering::SeqCst);
    r.auth.allowed.store(false, Ordering::SeqCst);
    assert_eq!(error(r.resolve("ok/a#password")), BackendError::Denied);
    assert!(r.auth.calls.load(Ordering::SeqCst) > before);
    assert_eq!(r.server.issue_count(), 1);
}
#[test]
fn freshness_expiry_revalidates_without_stale_while_error() {
    let r = Rig::new();
    assert!(r.resolve("static/a#value").is_ok());
    r.advance(29);
    assert!(r.resolve("static/a#value").is_ok());
    assert_eq!(r.server.call_count(), 1);
    r.advance(1);
    assert!(r.resolve("static/a#value").is_ok());
    assert_eq!(r.server.call_count(), 2);
    assert_eq!(
        r.service.status().entries[0].clocks.credential_expires_at,
        Expiry::NotApplicable
    );
    assert_eq!(
        r.service.status().entries[0].clocks.login_expires_at,
        Expiry::Unknown
    );
}
#[test]
fn dies_mid_issue_warns_and_does_not_reissue() {
    let r = Rig::new();
    for _ in 0..2 {
        assert_eq!(
            error(r.resolve("diesmid/a#password")),
            BackendError::Indeterminate
        );
    }
    assert_eq!(r.server.issue_count(), 1);
    assert!(r.actions().contains(&"potential-orphan"));
    assert_eq!(r.server.live_lease_count(), 1);
    r.advance(300);
    assert_eq!(r.server.live_lease_count(), 0);
}
#[test]
fn known_id_is_pending_retries_exponentially_and_abandons_at_fallback_deadline() {
    let r = Rig::new();
    assert_eq!(
        error(r.resolve("diesmid-nottl/a#password")),
        BackendError::TtlExceeded
    );
    let pending = r.service.status().pending_revoke;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].expires_at, T0 + 300);
    r.server
        .set_lease_revoke_failures(&pending[0].lease_id, 100)
        .unwrap();
    r.tick();
    assert_eq!(r.server.revoke_log().len(), 1);
    for (i, delay) in [1u64, 2, 4, 8, 16, 32, 60, 60].into_iter().enumerate() {
        let next = r.service.status().pending_revoke[0].next_retry;
        assert_eq!(
            next.duration_since(r.clock.now()),
            Duration::from_secs(delay)
        );
        r.tick();
        assert_eq!(
            r.server.revoke_log().len(),
            i + 1,
            "no spin before deadline"
        );
        r.advance(delay);
        r.tick();
        assert_eq!(r.server.revoke_log().len(), i + 2);
    }
    r.advance(900);
    r.tick();
    assert!(r.service.status().pending_revoke.is_empty());
    assert!(r.actions().contains(&"revoke-abandoned-at-upstream-expiry"));
}
#[test]
fn revoke_failure_stops_local_use_immediately_and_audit_failure_cannot_block_cleanup() {
    let r = Rig::new();
    assert!(r.resolve("revokefail/a#password").is_ok());
    r.audit.fail_all.store(true, Ordering::SeqCst);
    r.service.end_owner(r.grant, session(A));
    assert!(r.service.status().entries.is_empty());
    assert_eq!(
        error(r.resolve("revokefail/a#password")),
        BackendError::Denied
    );
    r.tick();
    r.advance(1);
    r.tick();
    r.advance(2);
    r.tick();
    assert_eq!(r.server.revoke_log().len(), 3);
    assert!(r.server.revoke_log()[2].succeeded);
    assert!(r.service.status().pending_revoke.is_empty());
    assert!(r.service.status().audit_failures > 0);
}
#[test]
fn cancel_before_and_after_issue_collects_effect_without_delivery() {
    for after in [false, true] {
        let r = Rig::new();
        let gate = Gate::new();
        if after {
            r.server.gate_after_issue(gate.clone());
        } else {
            r.server.gate_before_issue(gate.clone());
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let result = std::thread::scope(|s| {
            let flag = cancelled.clone();
            let h = s.spawn(|| {
                r.as_owner(
                    r.grant,
                    session(A),
                    "ok/a#password",
                    Arc::new(move || flag.load(Ordering::SeqCst)),
                )
            });
            gate.wait_reached();
            cancelled.store(true, Ordering::SeqCst);
            gate.release();
            h.join().unwrap()
        });
        assert_eq!(error(result), BackendError::Cancelled);
        assert!(r.service.status().entries.is_empty());
        assert_eq!(r.server.issue_count(), u64::from(after));
        assert_eq!(r.service.status().pending_revoke.len(), usize::from(after));
        r.tick();
        assert_eq!(r.server.revoke_log().len(), usize::from(after));
    }
}
#[test]
fn concurrent_requests_single_flight_and_owner_invalidation_prevents_publication() {
    for invalidate in [false, true] {
        let r = Rig::new();
        let gate = Gate::new();
        r.server.gate_after_issue(gate.clone());
        let results = std::thread::scope(|s| {
            let first = s.spawn(|| r.resolve("ok/a#password"));
            gate.wait_reached();
            let second = s.spawn(|| r.resolve("ok/a#password"));
            while r.service.status().registered_waiters < 1 {
                std::thread::yield_now();
            }
            if invalidate {
                r.service.end_owner(r.grant, session(A));
            }
            gate.release();
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_eq!(r.server.issue_count(), 1);
        if invalidate {
            assert!(results.0.is_err() && results.1.is_err());
            assert!(r.service.status().entries.is_empty());
            r.tick();
            assert_eq!(r.server.revoke_log().len(), 1);
        } else {
            assert!(results.0.is_ok() && results.1.is_ok());
        }
    }
}
#[test]
fn shared_owner_consumer_exit_does_not_revoke_but_owner_end_does() {
    let r = Rig::new();
    for c in [1, 2] {
        r.service.subscribe(r.grant, session(A), c).unwrap();
        assert!(r.resolve("ok/a#password").is_ok());
    }
    r.service.consumer_exit(r.grant, session(A), 1);
    r.tick();
    assert!(r.server.revoke_log().is_empty());
    let other = r
        .service
        .grant(session(A), Duration::from_secs(500))
        .unwrap();
    assert!(
        r.as_owner(other, session(A), "ok/a#password", Arc::new(|| false))
            .is_ok()
    );
    assert_eq!(r.server.issue_count(), 2);
    r.service.end_owner(r.grant, session(A));
    r.tick();
    r.tick();
    assert_eq!(r.server.revoke_log().len(), 1);
}
#[test]
fn crash_discards_local_state_without_inventing_revoke() {
    let r = Rig::new();
    assert!(r.resolve("ok/a#password").is_ok());
    let server = r.server.clone();
    let clock = r.clock.clone();
    drop(r);
    assert_eq!(server.live_lease_count(), 1);
    assert!(server.revoke_log().is_empty());
    let service = BackendService::new(
        binding(&server, "r1", b"synthetic-old"),
        Arc::new(TestClock(clock.clone())),
        Arc::new(Audit::default()),
        Arc::new(Auth {
            allowed: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        }),
    );
    assert!(service.status().entries.is_empty());
    assert_eq!(service.status().owners, 0);
    assert!(service.status().startup_note.contains("tracking lost"));
    clock.advance(Duration::from_secs(900));
    assert_eq!(server.live_lease_count(), 0);
}
#[test]
fn wall_jump_expiry_and_rollback_never_deliver_old_cache() {
    let r = Rig::new();
    assert!(r.resolve("ok/a#password").is_ok());
    let mono = r.clock.now();
    r.clock.set_wall(T0 + 2000);
    assert!(r.resolve("ok/a#password").is_err());
    assert_eq!(r.clock.now(), mono);
    assert!(r.service.status().entries.is_empty());
    let r = Rig::new();
    assert!(r.resolve("ok/a#password").is_ok());
    r.clock.set_wall(T0 - 20);
    assert!(
        r.resolve("ok/a#password").is_ok(),
        "fresh validation is allowed after invalidation"
    );
    assert_eq!(r.server.issue_count(), 2);
    assert_eq!(r.service.status().pending_revoke.len(), 1);
}
#[test]
fn audit_result_failure_refuses_dynamic_static_and_dynamic_hit() {
    for (native, hit, pending) in [
        ("ok/a#password", false, 1),
        ("static/a#value", false, 0),
        ("ok/a#password", true, 1),
    ] {
        let r = Rig::new();
        if hit {
            assert!(r.resolve(native).is_ok());
        }
        r.audit.fail_result.store(true, Ordering::SeqCst);
        assert_eq!(error(r.resolve(native)), BackendError::DeliveryRefused);
        assert_eq!(r.service.status().pending_revoke.len(), pending);
        assert_eq!(r.server.issue_count(), pending as u64);
        r.tick();
        assert_eq!(r.server.revoke_log().len(), pending);
    }
    let r = Rig::new();
    r.audit.fail_all.store(true, Ordering::SeqCst);
    assert_eq!(
        error(r.resolve("ok/a#password")),
        BackendError::AuditUnavailable
    );
    assert_eq!(r.server.call_count(), 0);
}
#[test]
fn last_use_is_atomic_and_exhaustion_ends_owner() {
    let r = Rig::new();
    let grant = r
        .service
        .grant_with_uses(
            session(A),
            Duration::from_secs(500),
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
    let gate = Gate::new();
    r.server.gate_after_issue(gate.clone());
    let results = std::thread::scope(|s| {
        let first = s.spawn(|| r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false)));
        gate.wait_reached();
        let second = s.spawn(|| r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false)));
        while r.service.status().registered_waiters < 1 {
            std::thread::yield_now();
        }
        gate.release();
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(
        usize::from(results.0.is_ok()) + usize::from(results.1.is_ok()),
        1
    );
    assert_eq!(r.server.issue_count(), 1);
    assert_eq!(r.service.status().pending_revoke.len(), 1);
    r.tick();
    r.tick();
    assert_eq!(r.server.revoke_log().len(), 1);
}
#[test]
fn refused_delivery_never_consumes_a_use() {
    let r = Rig::new();
    let grant = r
        .service
        .grant_with_uses(
            session(A),
            Duration::from_secs(500),
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
    r.audit.fail_result.store(true, Ordering::SeqCst);
    assert_eq!(
        error(r.as_owner(grant, session(A), "static/a#value", Arc::new(|| false))),
        BackendError::DeliveryRefused
    );
    assert!(
        r.service
            .status()
            .remaining_uses
            .contains(&(grant, Some(1)))
    );
    r.audit.fail_result.store(false, Ordering::SeqCst);
    assert!(
        r.as_owner(grant, session(A), "static/a#value", Arc::new(|| false))
            .is_ok()
    );
    assert!(
        !r.service
            .status()
            .remaining_uses
            .iter()
            .any(|(g, _)| *g == grant)
    );
}
#[test]
fn slow_throttle_and_flapping_are_effect_aware() {
    let r = Rig::new();
    assert_eq!(
        error(r.resolve("slowstatic/a#value")),
        BackendError::Timeout
    );
    assert_eq!(
        error(r.resolve("slow/a#password")),
        BackendError::Indeterminate
    );
    assert_eq!(
        error(r.resolve("throttledyn/a#password")),
        BackendError::rate_limited(Duration::from_secs(7))
    );
    assert_eq!(r.server.issue_count(), 1);
    let r = Rig::new();
    r.resolve("flap/a#user").unwrap();
    let first = r.audit.records.lock().unwrap()[1].version.clone();
    r.advance(30);
    r.resolve("flap/a#user").unwrap();
    let last = r
        .audit
        .records
        .lock()
        .unwrap()
        .iter()
        .rfind(|e| e.phase == AuditPhase::Result)
        .unwrap()
        .version
        .clone();
    assert_ne!(first, last);
    assert_eq!(r.server.issue_count(), 2);
}

#[test]
fn final_revision_and_clock_recheck_precedes_use_consumption() {
    let r = Rig::new();
    let grant = r
        .service
        .grant_with_uses(
            session(A),
            Duration::from_secs(1800),
            NonZeroU32::new(2).unwrap(),
        )
        .unwrap();
    let clock = r.clock.clone();
    *r.audit.on_result.lock().unwrap() =
        Some(Arc::new(move || clock.advance(Duration::from_secs(300))));
    assert!(
        r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false))
            .is_err()
    );
    assert!(
        r.service
            .status()
            .remaining_uses
            .contains(&(grant, Some(2)))
    );
    assert_eq!(r.service.status().pending_revoke.len(), 1);
}

#[test]
fn slow_result_audit_cannot_deliver_a_stale_static_read() {
    let r = Rig::new();
    let clock = r.clock.clone();
    *r.audit.on_result.lock().unwrap() =
        Some(Arc::new(move || clock.advance(Duration::from_secs(60))));
    assert_eq!(
        error(r.resolve("static/a#value")),
        BackendError::BindingChanged
    );
    assert!(r.service.status().entries.is_empty());
}

#[test]
fn known_id_grant_limited_deadline_uses_sent_ttl() {
    let r = Rig::new();
    let grant = r
        .service
        .grant(session(A), Duration::from_secs(20))
        .unwrap();
    assert_eq!(
        error(r.as_owner(
            grant,
            session(A),
            "diesmid-nottl/a#password",
            Arc::new(|| false)
        )),
        BackendError::TtlExceeded
    );
    assert_eq!(r.service.status().pending_revoke[0].expires_at, T0 + 20);
}

#[test]
fn blocking_intent_caps_issuance_by_current_permission() {
    let r = Rig::new();
    let grant = r
        .service
        .grant(session(A), Duration::from_secs(20))
        .unwrap();
    let clock = r.clock.clone();
    *r.audit.on_intent.lock().unwrap() =
        Some(Arc::new(move || clock.advance(Duration::from_secs(10))));
    assert_eq!(
        error(r.as_owner(
            grant,
            session(A),
            "diesmid-nottl/a#password",
            Arc::new(|| false)
        )),
        BackendError::TtlExceeded
    );
    assert_eq!(r.service.status().pending_revoke[0].expires_at, T0 + 10);
}

#[test]
fn revoke_backoff_starts_after_blocking_containment() {
    let r = Rig::new();
    assert!(r.resolve("revokefail/a#password").is_ok());
    r.service.end_owner(r.grant, session(A));
    let clock = r.clock.clone();
    *r.audit.on_containment.lock().unwrap() =
        Some(Arc::new(move || clock.advance(Duration::from_secs(10))));
    let before = r.clock.now();
    r.tick();
    // Both containment appends may block; backoff begins after the complete failed attempt.
    assert_eq!(
        r.service.status().pending_revoke[0].next_retry,
        before + Duration::from_secs(21)
    );
}

struct ObservedBackend {
    inner: FakeBackend,
    expiry: Option<u64>,
    fail_auth: bool,
    malformed: bool,
    revoke_hook: Option<Arc<dyn Fn() -> BResult<()> + Send + Sync>>,
}
impl SecretBackend for ObservedBackend {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    fn parse_ref(&self, native: &str) -> BResult<NativeRef> {
        self.inner.parse_ref(native)
    }
    fn resolve_kind(&self, r: &NativeRef) -> BResult<ResolveKind> {
        self.inner.resolve_kind(r)
    }
    fn auth_status(&self) -> AuthState {
        AuthState {
            expires_at: self.expiry,
            renewable: false,
            needs_human: false,
        }
    }
    fn resolve(&self, c: &CallContext<'_>, r: &NativeRef, o: &ResolveOpts) -> Resolved {
        let mut response = self.inner.resolve(c, r, o);
        if self.fail_auth {
            response.result = Err(BackendError::AuthExpired);
        }
        if self.malformed
            && let Ok(bundle) = &mut response.result
        {
            bundle.lease = None;
        }
        response
    }
    fn revoke(&self, c: &CallContext<'_>, id: &LeaseId) -> BResult<()> {
        if let Some(hook) = &self.revoke_hook {
            return hook();
        }
        self.inner.revoke(c, id)
    }
}
#[test]
fn stale_auth_failure_after_retarget_preserves_replacement_owner() {
    let r = Rig::new();
    let mut old = binding(&r.server, "auth-old", b"synthetic-old");
    old.backend = Arc::new(ObservedBackend {
        inner: FakeBackend::new(r.server.clone()),
        expiry: None,
        fail_auth: true,
        malformed: false,
        revoke_hook: None,
    });
    r.service.retarget(Some(old));
    let old_grant = r
        .service
        .grant(session(A), Duration::from_secs(500))
        .unwrap();
    let gate = Gate::new();
    r.server.gate_after_issue(gate.clone());
    let replacement_server = FakeServer::new(r.clock.clone());
    let (response, new_grant) = std::thread::scope(|scope| {
        let h =
            scope.spawn(|| r.as_owner(old_grant, session(A), "ok/a#password", Arc::new(|| false)));
        gate.wait_reached();
        r.service.retarget(Some(binding(
            &replacement_server,
            "auth-new",
            b"synthetic-new",
        )));
        let new_grant = r
            .service
            .grant(session(A), Duration::from_secs(500))
            .unwrap();
        let replacement = r.as_owner(new_grant, session(A), "ok/a#password", Arc::new(|| false));
        gate.release();
        let response = h.join().unwrap();
        assert!(replacement.is_ok());
        (response, new_grant)
    });
    assert_eq!(error(response), BackendError::BindingChanged);
    assert_eq!(r.service.status().owners, 1);
    assert!(
        r.as_owner(new_grant, session(A), "ok/a#password", Arc::new(|| false))
            .is_ok()
    );
    assert_eq!(replacement_server.issue_count(), 1);
    r.tick();
    assert!(replacement_server.revoke_log().is_empty());
}
#[test]
fn observed_login_expiry_is_reported_and_reset_on_retarget() {
    let r = Rig::new();
    let mut b = binding(&r.server, "observed", b"synthetic");
    b.backend = Arc::new(ObservedBackend {
        inner: FakeBackend::new(r.server.clone()),
        expiry: Some(T0 + 90),
        fail_auth: false,
        malformed: false,
        revoke_hook: None,
    });
    r.service.retarget(Some(b));
    let grant = r
        .service
        .grant(session(A), Duration::from_secs(500))
        .unwrap();
    assert!(
        r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false))
            .is_ok()
    );
    assert_eq!(
        r.service.status().entries[0].clocks.login_expires_at,
        Expiry::At(T0 + 90)
    );
    let records = r.audit.records.lock().unwrap();
    let result = records
        .iter()
        .rev()
        .find(|r| r.phase == AuditPhase::Result)
        .unwrap();
    assert_eq!(
        result.clocks.as_ref().unwrap().login_expires_at,
        Expiry::At(T0 + 90)
    );
    drop(records);
    r.service
        .retarget(Some(binding(&r.server, "reset", b"synthetic")));
    let grant = r
        .service
        .grant(session(A), Duration::from_secs(500))
        .unwrap();
    assert!(
        r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false))
            .is_ok()
    );
    assert_eq!(
        r.service.status().entries[0].clocks.login_expires_at,
        Expiry::Unknown
    );
}

#[test]
fn cancelled_leader_does_not_cancel_live_registered_waiter() {
    let r = Rig::new();
    let gate = Gate::new();
    r.server.gate_after_issue(gate.clone());
    let flag = Arc::new(AtomicBool::new(false));
    let flag_copy = flag.clone();
    let cancellation: Arc<dyn Fn() -> bool + Send + Sync> =
        Arc::new(move || flag_copy.load(Ordering::SeqCst));
    let (leader, waiter) = std::thread::scope(|scope| {
        let leader =
            scope.spawn(|| r.as_owner(r.grant, session(A), "ok/a#password", cancellation.clone()));
        gate.wait_reached();
        let waiter = scope.spawn(|| r.resolve("ok/a#user"));
        while r.service.status().registered_waiters < 1 {
            std::thread::yield_now();
        }
        flag.store(true, Ordering::SeqCst);
        gate.release();
        (leader.join().unwrap(), waiter.join().unwrap())
    });
    assert_eq!(error(leader), BackendError::Cancelled);
    assert!(waiter.is_ok());
    assert_eq!(r.server.issue_count(), 1);
    assert!(r.service.status().pending_revoke.is_empty());
    assert_eq!(Arc::strong_count(&cancellation), 1);
}
#[test]
fn zero_freshness_registered_cohort_shares_one_issue_only() {
    let r = Rig::new();
    let mut b = binding(&r.server, "zero", b"synthetic");
    b.freshness = Duration::ZERO;
    r.service.retarget(Some(b));
    let grant = r
        .service
        .grant(session(A), Duration::from_secs(500))
        .unwrap();
    let gate = Gate::new();
    r.server.gate_after_issue(gate.clone());
    let responses = std::thread::scope(|scope| {
        let leader =
            scope.spawn(|| r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false)));
        gate.wait_reached();
        let first = scope.spawn(|| r.as_owner(grant, session(A), "ok/a#user", Arc::new(|| false)));
        let second =
            scope.spawn(|| r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false)));
        while r.service.status().registered_waiters < 2 {
            std::thread::yield_now();
        }
        gate.release();
        (
            leader.join().unwrap(),
            first.join().unwrap(),
            second.join().unwrap(),
        )
    });
    assert!(responses.0.is_ok() && responses.1.is_ok() && responses.2.is_ok());
    assert_eq!(
        responses.1.unwrap().fields.keys().collect::<Vec<_>>(),
        vec!["user"]
    );
    assert_eq!(r.server.issue_count(), 1);
    assert!(
        r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false))
            .is_ok()
    );
    assert_eq!(r.server.issue_count(), 2);
}
#[test]
fn all_registered_callers_cancelled_contains_single_effect() {
    let r = Rig::new();
    let gate = Gate::new();
    r.server.gate_after_issue(gate.clone());
    let flag = Arc::new(AtomicBool::new(false));
    let copy = flag.clone();
    let cancellation: Arc<dyn Fn() -> bool + Send + Sync> =
        Arc::new(move || copy.load(Ordering::SeqCst));
    let results = std::thread::scope(|scope| {
        let first =
            scope.spawn(|| r.as_owner(r.grant, session(A), "ok/a#password", cancellation.clone()));
        gate.wait_reached();
        let second =
            scope.spawn(|| r.as_owner(r.grant, session(A), "ok/a#user", cancellation.clone()));
        while r.service.status().registered_waiters < 1 {
            std::thread::yield_now();
        }
        flag.store(true, Ordering::SeqCst);
        gate.release();
        (first.join().unwrap(), second.join().unwrap())
    });
    assert!(results.0.is_err() && results.1.is_err());
    assert_eq!(r.server.issue_count(), 1);
    assert_eq!(r.service.status().pending_revoke.len(), 1);
    assert!(r.service.status().entries.is_empty());
    assert_eq!(Arc::strong_count(&cancellation), 1);
}

#[test]
fn malformed_dynamic_bundle_still_owns_effect_and_correlates_failed_id() {
    let r = Rig::new();
    let mut b = binding(&r.server, "malformed", b"synthetic");
    b.backend = Arc::new(ObservedBackend {
        inner: FakeBackend::new(r.server.clone()),
        expiry: None,
        fail_auth: false,
        malformed: true,
        revoke_hook: None,
    });
    r.service.retarget(Some(b));
    let grant = r
        .service
        .grant(session(A), Duration::from_secs(500))
        .unwrap();
    let gate = Gate::new();
    r.server.gate_after_issue(gate.clone());
    std::thread::scope(|scope| {
        let h = scope.spawn(|| r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false)));
        gate.wait_reached();
        r.audit.fail_all.store(true, Ordering::SeqCst);
        gate.release();
        assert_eq!(error(h.join().unwrap()), BackendError::InvalidResponse);
    });
    assert!(r.service.status().audit_failures > 0);
    let pending = r.service.status().pending_revoke;
    assert_eq!(pending.len(), 1);
    let records = r.audit.records.lock().unwrap();
    assert_eq!(
        records.last().unwrap().lease_id.as_ref(),
        Some(&pending[0].lease_id)
    );
    let outcome = records
        .iter()
        .find(|v| v.phase == AuditPhase::Outcome)
        .unwrap();
    assert_eq!(
        outcome.clocks.as_ref().unwrap().credential_expires_at,
        Expiry::At(T0 + 300)
    );
    assert_eq!(
        outcome.clocks.as_ref().unwrap().revocation,
        Revocation::Pending
    );
    assert!(
        records.iter().any(|v| v.phase == AuditPhase::Containment
            && v.lease_id == Some(pending[0].lease_id.clone()))
    );
    drop(records);
    r.tick();
    assert_eq!(r.server.revoke_log().len(), 1);
}

#[test]
fn containment_audits_static_expiry_login_clock_and_revoke_error_snapshots() {
    for cause in ["expiry", "login", "clock"] {
        let r = Rig::new();
        assert!(r.resolve("static/a#value").is_ok());
        r.audit.fail_all.store(true, Ordering::SeqCst);
        match cause {
            "expiry" => {
                r.advance(1800);
                r.tick();
            }
            "login" => r.service.invalidate_login(),
            _ => {
                r.clock.advance_wall(Duration::from_secs(10));
                r.tick();
            }
        }
        assert!(r.service.status().entries.is_empty());
        let records = r.audit.records.lock().unwrap();
        let record = records
            .iter()
            .rev()
            .find(|v| v.phase == AuditPhase::Containment)
            .unwrap();
        assert_eq!(record.grant, Some(r.grant));
        assert_eq!(record.session, Some(session(A)));
        assert_eq!(
            record.clocks.as_ref().unwrap().credential_expires_at,
            Expiry::NotApplicable
        );
    }
    let r = Rig::new();
    assert!(r.resolve("revokefail/a#password").is_ok());
    r.service.end_owner(r.grant, session(A));
    r.tick();
    let records = r.audit.records.lock().unwrap();
    let failed = records
        .iter()
        .find(|v| v.action == "revoke-failed")
        .unwrap();
    assert_eq!(failed.error, Some(BackendError::Transient));
    assert_eq!(failed.grant, Some(r.grant));
    assert_eq!(failed.session, Some(session(A)));
    assert_eq!(
        failed.clocks.as_ref().unwrap().revocation,
        Revocation::Pending
    );
    assert!(failed.lease_id.is_some());
}

#[test]
fn rate_limited_revoke_waits_from_failure_completion_bounded_by_expiry() {
    for delay in [10, 299] {
        let r = Rig::new();
        let mut b = binding(&r.server, "rate-revoke", b"synthetic");
        let clock = r.clock.clone();
        b.backend = Arc::new(ObservedBackend {
            inner: FakeBackend::new(r.server.clone()),
            expiry: None,
            fail_auth: false,
            malformed: false,
            revoke_hook: Some(Arc::new(move || {
                clock.advance(Duration::from_secs(delay));
                Err(BackendError::rate_limited(Duration::from_secs(7)))
            })),
        });
        r.service.retarget(Some(b));
        let grant = r
            .service
            .grant(session(A), Duration::from_secs(500))
            .unwrap();
        assert!(
            r.as_owner(grant, session(A), "ok/a#password", Arc::new(|| false))
                .is_ok()
        );
        r.service.end_owner(grant, session(A));
        let before = r.clock.now();
        r.tick();
        assert_eq!(
            r.service.status().pending_revoke[0].next_retry,
            before + Duration::from_secs((delay + 7).min(300))
        );
    }
}

#[test]
fn waiter_registration_counter_observes_a_blocked_flight() {
    let r = Rig::new();
    let gate = Gate::new();
    r.server.gate_after_issue(gate.clone());
    let count = std::thread::scope(|scope| {
        let first = scope.spawn(|| r.resolve("ok/a#password"));
        gate.wait_reached();
        let second = scope.spawn(|| r.resolve("ok/a#user"));
        while r.service.status().registered_waiters < 1 {
            std::thread::yield_now();
        }
        let count = r.service.status().registered_waiters;
        gate.release();
        assert!(first.join().unwrap().is_ok());
        assert!(second.join().unwrap().is_ok());
        count
    });
    assert_eq!(count, 1);
    assert_eq!(r.service.status().registered_waiters, 0);
}

#[test]
fn waiter_registering_during_cancel_evaluation_keeps_flight_live() {
    let r = Rig::new();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let release_rx = Mutex::new(release_rx);
    let calls = AtomicUsize::new(0);
    let cancelled = Arc::new(move || {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        if call == 2 {
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        }
        call >= 2
    });
    let (leader, waiter) = std::thread::scope(|scope| {
        let leader = scope.spawn(|| r.as_owner(r.grant, session(A), "ok/a#password", cancelled));
        entered_rx.recv().unwrap();
        let waiter = scope.spawn(|| r.resolve("ok/a#user"));
        while r.service.status().registered_waiters != 1 {
            std::thread::yield_now();
        }
        release_tx.send(()).unwrap();
        (leader.join().unwrap(), waiter.join().unwrap())
    });
    assert_eq!(error(leader), BackendError::Cancelled);
    assert!(
        waiter.is_ok(),
        "registration during callback must invalidate cancellation snapshot"
    );
    assert_eq!(r.server.issue_count(), 1);
    assert!(r.service.status().pending_revoke.is_empty());
    assert!(r.server.revoke_log().is_empty());
}

#[test]
fn dynamic_containment_snapshots_are_pending_even_when_audit_fails() {
    for cancel in [false, true] {
        let r = Rig::new();
        if cancel {
            let gate = Gate::new();
            r.server.gate_after_issue(gate.clone());
            let flag = Arc::new(AtomicBool::new(false));
            let copy = flag.clone();
            std::thread::scope(|scope| {
                let h = scope.spawn(|| {
                    r.as_owner(
                        r.grant,
                        session(A),
                        "ok/a#password",
                        Arc::new(move || copy.load(Ordering::SeqCst)),
                    )
                });
                gate.wait_reached();
                r.audit.fail_all.store(true, Ordering::SeqCst);
                flag.store(true, Ordering::SeqCst);
                gate.release();
                assert_eq!(error(h.join().unwrap()), BackendError::Cancelled);
            });
        } else {
            assert!(r.resolve("ok/a#password").is_ok());
            r.audit.fail_all.store(true, Ordering::SeqCst);
            r.service.end_owner(r.grant, session(A));
        }
        assert_eq!(r.service.status().pending_revoke.len(), 1);
        assert!(r.service.status().audit_failures > 0);
        let records = r.audit.records.lock().unwrap();
        let event = records
            .iter()
            .rev()
            .find(|v| v.phase == AuditPhase::Containment)
            .unwrap();
        let clocks = event.clocks.as_ref().unwrap();
        assert_eq!(clocks.credential_expires_at, Expiry::At(T0 + 300));
        assert_eq!(clocks.revocation, Revocation::Pending);
    }
}

#[test]
fn metadata_revalidation_renews_only_unchanged_freshness() {
    use karambit_core::backend::fake::MetadataMode;
    for (mode, issues) in [
        (MetadataMode::Unchanged, 1),
        (MetadataMode::Changed, 2),
        (MetadataMode::Error, 2),
        (MetadataMode::Unsupported, 2),
    ] {
        let r = Rig::new();
        r.server.set_metadata(true, mode);
        assert!(r.resolve("ok/a#password").is_ok());
        r.advance(30);
        assert!(r.resolve("ok/a#password").is_ok());
        assert_eq!(r.server.metadata_call_count(), 1);
        assert_eq!(r.server.issue_count(), issues);
        assert_eq!(r.server.call_count(), issues);
        assert_eq!(
            r.service.status().pending_revoke.len(),
            (issues - 1) as usize
        );
        assert_eq!(
            r.service.status().entries[0].clocks.credential_expires_at,
            Expiry::At(T0 + 300 + if issues == 1 { 0 } else { 30 })
        );
        let records = r.audit.records.lock().unwrap();
        let result = records
            .iter()
            .rev()
            .find(|v| v.phase == AuditPhase::Result)
            .unwrap();
        assert_eq!(
            result.version,
            Some(format!("v{issues}")),
            "use value response token, not metadata token"
        );
        drop(records);
        assert_eq!(
            r.service.status().entries[0].clocks.cache_fresh_until,
            Expiry::At(T0 + 60)
        );
    }
}
#[test]
fn paused_metadata_single_flight_retarget_cannot_publish() {
    use karambit_core::backend::fake::MetadataMode;
    for retarget in [false, true] {
        let r = Rig::new();
        r.server.set_metadata(true, MetadataMode::Unchanged);
        assert!(r.resolve("ok/a#password").is_ok());
        r.advance(30);
        let gate = Gate::new();
        r.server.gate_metadata(gate.clone());
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(|| r.resolve("ok/a#password"));
            gate.wait_reached();
            let b = scope.spawn(|| r.resolve("ok/a#user"));
            while r.service.status().registered_waiters != 1 {
                std::thread::yield_now();
            }
            if retarget {
                r.service.retarget(None);
            }
            gate.release();
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_eq!(a.is_ok(), !retarget);
        assert_eq!(b.is_ok(), !retarget);
        assert_eq!(r.server.metadata_call_count(), 1);
        assert_eq!(r.server.issue_count(), 1);
        if retarget {
            assert!(r.service.status().entries.is_empty());
        }
    }
}
