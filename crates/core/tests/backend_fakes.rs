//! Adversarial synthetic backends (backend contract C-15, C-27, C-35, C-36, C-40a).
//! Through the public trait + registry only. No daemon, no network, no sleeping: time is the
//! injected `FakeClock`, pauses are `Gate`s.
use karambit_core::backend::{
    fake::{self, FakeClock, FakeServer, Gate},
    *,
};
use std::{
    fs,
    path::Path,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    time::Duration,
};

use zeroize::Zeroizing;

const T0: u64 = 1_000_000;
const DEADLINE: Duration = Duration::from_secs(30);

struct Rig {
    endpoint: String,
    clock: Arc<FakeClock>,
    server: Arc<FakeServer>,
    backend: Arc<dyn SecretBackend>,
}
impl Drop for Rig {
    fn drop(&mut self) {
        fake::detach(&self.endpoint);
    }
}
fn config(name: &str, endpoint: &str) -> SourceConfig {
    SourceConfig {
        name: name.into(),
        kind: "fake".into(),
        endpoint: endpoint.into(),
        auth_method: "token".into(),
        credential_ref: format!("sources/{name}/cred"),
        credential_revision: "r1".into(),
        generation: "0123456789abcdef0123456789abcdef".into(),
        policy: serde_json::json!({}),
    }
}
/// A fresh server behind a fresh registry; `name` must be unique per test (one endpoint each).
fn rig_for(name: &str) -> Rig {
    let clock = FakeClock::new(T0);
    let server = FakeServer::new(clock.clone());
    let endpoint = format!("https://{name}.fake.invalid/");
    fake::attach(&endpoint, &server).unwrap();
    let mut registry = Registry::default();
    fake::register(&mut registry).unwrap();
    registry.add_source(&config(name, &endpoint)).unwrap();
    let backend = registry.lookup(name).unwrap();
    Rig { endpoint, clock, server, backend }
}
fn opts(ttl: u64) -> ResolveOpts {
    ResolveOpts { requested_ttl: Duration::from_secs(ttl) }
}
impl Rig {
    fn call<T>(&self, cancelled: &(dyn Fn() -> bool + Send + Sync), f: impl FnOnce(&CallContext<'_>) -> T) -> T {
        let ctx = CallContext {
            credential: b"synthetic-credential",
            deadline: self.clock.now() + DEADLINE,
            cancelled,
        };
        f(&ctx)
    }
    fn resolve_with(&self, native: &str, ttl: u64, cancelled: &(dyn Fn() -> bool + Send + Sync)) -> Resolved {
        let r = self.backend.parse_ref(native).unwrap();
        self.call(cancelled, |c| self.backend.resolve(c, &r, &opts(ttl)))
    }
    fn resolve(&self, native: &str) -> Resolved {
        self.resolve_with(native, 300, &|| false)
    }
    fn kind(&self, native: &str) -> ResolveKind {
        self.backend.resolve_kind(&self.backend.parse_ref(native).unwrap()).unwrap()
    }
    fn revoke(&self, id: &str) -> BResult<()> {
        self.call(&|| false, |c| self.backend.revoke(c, &LeaseId::parse(id).unwrap()))
    }
}
fn effect_tag(e: &IssueEffect) -> String {
    match e {
        IssueEffect::None => "None".into(),
        IssueEffect::Known(l) => format!("Known:{}", l.id.as_str()),
        IssueEffect::KnownId { id } => format!("KnownId:{}", id.as_str()),
        IssueEffect::Unknown => "Unknown".into(),
    }
}
fn kind_of(e: &IssueEffect) -> &'static str {
    match e {
        IssueEffect::None => "None",
        IssueEffect::Known(_) => "Known",
        IssueEffect::KnownId { .. } => "KnownId",
        IssueEffect::Unknown => "Unknown",
    }
}
fn effect_id(e: &IssueEffect) -> String {
    match e {
        IssueEffect::Known(l) => l.id.as_str().into(),
        IssueEffect::KnownId { id } => id.as_str().into(),
        _ => panic!("effect carries no lease id: {}", effect_tag(e)),
    }
}
fn text<'a>(b: &'a Bundle, field: &str) -> &'a str {
    match &b.fields()[field] {
        SecretField::Text(t) => t.as_str(),
        SecretField::Bytes(_) => panic!("text field expected"),
    }
}
fn err(r: &Resolved) -> BackendError {
    *r.result.as_ref().expect_err("expected Err")
}

/// Smoke: each fake returns its typed result/error, the right IssueEffect, and `validate`
/// (run after taking the effect, C-40a) accepts exactly the valid shapes.
#[test]
fn smoke_each_fake_returns_typed_result_and_effect() {
    let rig = rig_for("smoke");
    // (native, kind, expected error or None for Ok, expected effect kind)
    let rows: &[(&str, ResolveKind, Option<BackendError>, &str)] = &[
        ("ok/a", ResolveKind::DynamicIssue, None, "Known"),
        ("flap/a", ResolveKind::DynamicIssue, None, "Known"),
        ("revokefail/a", ResolveKind::DynamicIssue, None, "Known"),
        ("static/a", ResolveKind::StaticRead, None, "None"),
        ("slow/a", ResolveKind::DynamicIssue, Some(BackendError::Indeterminate), "Unknown"),
        ("diesmid/a", ResolveKind::DynamicIssue, Some(BackendError::Indeterminate), "Unknown"),
        ("diesmid-nottl/a", ResolveKind::DynamicIssue, Some(BackendError::TtlExceeded), "KnownId"),
        ("throttle/a", ResolveKind::StaticRead, Some(BackendError::rate_limited(Duration::from_secs(7))), "None"),
        ("throttledyn/a", ResolveKind::DynamicIssue, Some(BackendError::rate_limited(Duration::from_secs(7))), "None"),
        ("slowstatic/a", ResolveKind::StaticRead, Some(BackendError::Timeout), "None"),
    ];
    for (native, kind, expected, effect) in rows {
        assert_eq!(rig.kind(native), *kind, "{native}");
        let resolved = rig.resolve(native);
        assert_eq!(kind_of(&resolved.effect), *effect, "{native}");
        match expected {
            Some(e) => assert_eq!(resolved.result.as_ref().err(), Some(e), "{native}"),
            None => {
                let bundle = resolved.result.as_ref().unwrap_or_else(|_| panic!("{native} must be Ok"));
                match kind {
                    ResolveKind::DynamicIssue => {
                        let lease = bundle.lease.as_ref().expect("dynamic bundle has a lease");
                        assert_eq!(effect_tag(&resolved.effect), format!("Known:{}", lease.id.as_str()));
                        assert_eq!(lease.server_ttl, Duration::from_secs(300));
                        assert_eq!(lease.expires_at, lease.issued_at + 300);
                        assert_eq!(text(bundle, "password").len(), 64);
                        assert!(bundle.change.version.is_some());
                    }
                    ResolveKind::StaticRead => assert!(bundle.lease.is_none(), "{native}"),
                }
                // Known pair ⇒ server really holds that lease.
                if *effect == "Known" {
                    assert!(rig.server.is_live(&effect_id(&resolved.effect)));
                }
            }
        }
        // Errors never trip validate; Ok results pass only for the right kind.
        assert!(resolved.validate(*kind).is_ok(), "{native}");
        if expected.is_none() {
            let other = match kind {
                ResolveKind::StaticRead => ResolveKind::DynamicIssue,
                ResolveKind::DynamicIssue => ResolveKind::StaticRead,
            };
            assert!(resolved.validate(other).is_err(), "{native} wrong kind must fail validate");
        }
    }
    // Server side: dynamic rows issued; throttle/static/slowstatic never did.
    // ok, flap, revokefail, slow, diesmid, diesmid-nottl = 6
    assert_eq!(rig.server.issue_count(), 6);
    assert_eq!(rig.server.call_count(), rows.len() as u64);

    // Effect/lease mismatch is rejected: Ok dynamic + None/Unknown effect must fail validate.
    let mut ok = rig.resolve("ok/b");
    assert!(ok.validate(ResolveKind::DynamicIssue).is_ok());
    for bad in [IssueEffect::None, IssueEffect::Unknown] {
        ok.effect = bad;
        assert!(ok.validate(ResolveKind::DynamicIssue).is_err());
    }
    let id = LeaseId::parse("x").unwrap();
    ok.effect = IssueEffect::KnownId { id };
    assert!(ok.validate(ResolveKind::DynamicIssue).is_err());
}

#[test]
fn throttle_clamps_retry_after_and_stops_on_demand() {
    let rig = rig_for("throttle");
    for (hint, expected) in [(0, 1), (1, 1), (42, 42), (301, 300), (100_000, 300)] {
        rig.server.set_throttle_retry_after(Duration::from_secs(hint));
        for native in ["throttle/a", "throttledyn/a"] {
            let r = rig.resolve(native);
            assert_eq!(err(&r), BackendError::RateLimited { retry_after: Duration::from_secs(expected) });
            assert!(matches!(r.effect, IssueEffect::None));
        }
    }
    assert_eq!(rig.server.issue_count(), 0, "a throttled dynamic request issues nothing");
    rig.server.set_throttles(2);
    assert!(rig.resolve("throttle/a").result.is_err());
    assert!(rig.resolve("throttle/a").result.is_err());
    let ok = rig.resolve("throttle/a");
    assert!(ok.result.is_ok() && matches!(ok.effect, IssueEffect::None));
}

/// flapping: new value AND version every call; each resolve is exactly one server issue.
#[test]
fn flapping_changes_value_and_version_each_call_with_one_issue_each() {
    let rig = rig_for("flap");
    let mut seen = Vec::new();
    for n in 1..=4u64 {
        let r = rig.resolve("flap/a");
        assert_eq!(rig.server.issue_count(), n, "exactly one issue per resolve");
        let b = r.result.as_ref().unwrap();
        seen.push((b.change.version.clone().unwrap(), Zeroizing::new(text(b, "user").to_owned()), Zeroizing::new(text(b, "password").to_owned()), effect_id(&r.effect)));
        assert!(r.validate(ResolveKind::DynamicIssue).is_ok());
    }
    for i in 0..seen.len() {
        for j in i + 1..seen.len() {
            assert_ne!(seen[i].0, seen[j].0, "version repeats");
            assert!(seen[i].1 != seen[j].1, "flap changed user");
            assert!(seen[i].2 != seen[j].2, "flap changed value");
            assert_ne!(seen[i].3, seen[j].3, "lease repeats");
        }
    }
    // A stable ref does not flap in version.
    let (a, b) = (rig.resolve("static/a"), rig.resolve("static/a"));
    let (a, b) = (a.result.unwrap(), b.result.unwrap());
    assert_eq!(a.change.version, b.change.version);
    assert!(text(&a, "value") == text(&b, "value"), "static value stable");
}

/// Negative case 1: dies-mid-issue family. The server holds a lease the client never saw, nothing
/// reissues, and the server-side TTL (<= 900s cap even if the caller asked for more) ends it.
#[test]
fn dies_mid_issue_never_reissues_and_server_ttl_ends_orphan() {
    for (native, error, effect) in [
        ("diesmid/a", BackendError::Indeterminate, "Unknown"),
        ("slow/a", BackendError::Indeterminate, "Unknown"),
        ("diesmid-nottl/a", BackendError::TtlExceeded, "KnownId"),
    ] {
        for requested in [300u64, 900, 5000] {
            let label = format!("{native}/{requested}");
            let rig = rig_for(&format!("dm-{}", requested));
            let start = rig.clock.wall();
            let r = rig.resolve_with(native, requested, &|| false);
            assert_eq!(err(&r), error, "{label}");
            assert_eq!(kind_of(&r.effect), effect, "{label}");
            assert!(r.validate(ResolveKind::DynamicIssue).is_ok(), "{label}");
            // No automatic second issue.
            assert_eq!(rig.server.issue_count(), 1, "{label}");
            assert_eq!(rig.server.call_count(), 1, "{label}");
            let ids = rig.server.lease_ids();
            assert_eq!(ids.len(), 1, "{label}");
            let id = &ids[0];
            if effect == "KnownId" {
                assert_eq!(&effect_id(&r.effect), id, "KnownId names the server lease");
            }
            let expires = rig.server.lease_expires_at(id).unwrap();
            let life = requested.min(900);
            assert_eq!(expires, start + life, "{label}: upstream maximum enforced");
            assert!(expires <= start + 900, "{label}: orphan bound C-35");
            assert_eq!(rig.server.live_lease_count(), 1, "{label}: orphan is live now");
            // `slow` already consumed its deadline on the clock; measure from the server's expiry.
            rig.clock.advance(Duration::from_secs(expires - rig.clock.wall() - 1));
            assert!(rig.server.is_live(id), "{label}: still live before expiry");
            rig.clock.advance(Duration::from_secs(1));
            assert!(!rig.server.is_live(id), "{label}: expired on the injected clock");
            assert_eq!(rig.server.live_lease_count(), 0, "{label}");
            assert_eq!(rig.server.issue_count(), 1, "{label}: still a single issue");
            assert!(rig.server.revoke_log().is_empty(), "{label}: adapter never self-revokes");
            if effect == "KnownId" {
                // pending-revoke path: ID-only revoke works without TTL/expiry fields.
                let rig2 = rig_for(&format!("dmk-{}", requested));
                let r2 = rig2.resolve_with(native, requested, &|| false);
                let id2 = effect_id(&r2.effect);
                assert!(rig2.server.is_live(&id2));
                rig2.revoke(&id2).unwrap();
                assert!(!rig2.server.is_live(&id2));
                assert_eq!(
                    rig2.server.revoke_log(),
                    vec![fake::RevokeAttempt { lease_id: id2, succeeded: true, credential_matches: None }]
                );
            }
        }
    }
    for native in ["ok/a", "diesmid/a", "slow/a", "diesmid-nottl/a"] {
        let rig = rig_for("ttl-limits");
        for max in [Duration::ZERO, Duration::from_secs(5000), Duration::from_millis(500)] {
            assert_eq!(rig.server.set_max_ttl(max), Err(BackendError::InvalidConfig));
        }
        for requested_ttl in [Duration::ZERO, Duration::from_millis(500)] {
            let r = rig.call(&|| false, |c| rig.backend.resolve(c,
                &rig.backend.parse_ref(native).unwrap(), &ResolveOpts { requested_ttl }));
            assert_eq!(err(&r), BackendError::TtlExceeded);
            assert!(matches!(r.effect, IssueEffect::None));
            assert_eq!(rig.server.issue_count(), 0);
        }
        rig.server.set_max_ttl(Duration::from_secs(900)).unwrap();
        rig.resolve_with(native, 5000, &|| false);
        let id = &rig.server.lease_ids()[0];
        assert_eq!(rig.server.lease_expires_at(id), Some(T0 + 900));
    }
    // An over-cap request is clamped by the upstream maximum, which is itself configurable.
    let rig = rig_for("dm-max");
    rig.server.set_max_ttl(Duration::from_secs(120)).unwrap();
    let r = rig.resolve_with("ok/a", 900, &|| false);
    assert_eq!(r.result.unwrap().lease.unwrap().server_ttl, Duration::from_secs(120));
}

/// Negative case 2: revoke-fails. Fails N times, then succeeds; log holds exactly the attempts made.
#[test]
fn revoke_fails_n_times_then_succeeds_and_logs_each_attempt() {
    for n in [0u32, 1, 3] {
        let rig = rig_for(&format!("rf-{n}"));
        rig.server.set_revoke_failures(n);
        let r = rig.resolve("revokefail/a");
        let id = effect_id(&r.effect);
        for attempt in 1..=n {
            assert_eq!(rig.revoke(&id), Err(BackendError::Transient), "n={n} attempt={attempt}");
            assert!(rig.server.is_live(&id), "failed revoke leaves the lease live");
            assert!(!rig.server.is_revoked(&id));
            assert_eq!(rig.server.revoke_log().len(), attempt as usize);
        }
        assert_eq!(rig.revoke(&id), Ok(()), "n={n}");
        assert!(rig.server.is_revoked(&id));
        assert!(!rig.server.is_live(&id));
        let expected: Vec<_> = (0..=n)
            .map(|i| fake::RevokeAttempt { lease_id: id.clone(), succeeded: i == n, credential_matches: None })
            .collect();
        assert_eq!(rig.server.revoke_log(), expected, "n={n}");
        // Revoke is idempotent once it has worked.
        assert_eq!(rig.revoke(&id), Ok(()));
        assert_eq!(rig.server.revoke_log().len(), n as usize + 2);
    }
    // An ordinary lease revokes first time; an unknown ID is NotFound and is still logged.
    let rig = rig_for("rf-ok");
    let id = effect_id(&rig.resolve("ok/a").effect);
    assert_eq!(rig.revoke(&id), Ok(()));
    assert_eq!(rig.revoke("no-such-lease"), Err(BackendError::NotFound));
    let log = rig.server.revoke_log();
    assert_eq!(log.len(), 2);
    assert!(log[0].succeeded && !log[1].succeeded);
    // A cancelled or expired revoke never reaches the server.
    let r = rig.call(&|| true, |c| rig.backend.revoke(c, &LeaseId::parse(&id).unwrap()));
    assert_eq!(r, Err(BackendError::Cancelled));
    assert_eq!(rig.server.revoke_log().len(), 2);
}

/// Negative case 3: deadline/cancel against barriers and the injected clock. Nothing blocks or sleeps.
#[test]
fn cancel_and_deadline_effects_match_what_the_server_recorded() {
    // Cancelled before send: nothing issued.
    let rig = rig_for("cx-pre");
    let r = rig.resolve_with("ok/a", 300, &|| true);
    assert_eq!(err(&r), BackendError::Cancelled);
    assert!(matches!(r.effect, IssueEffect::None));
    assert_eq!(rig.server.issue_count(), 0);

    // Deadline already passed before send: Timeout, nothing issued (safe to say so: never sent).
    let rig2 = rig_for("cx-dl");
    let r2 = rig2.resolve_with("ok/a", 300, &|| false);
    assert!(r2.result.is_ok());
    let past = rig2.call(&|| false, |c| c.deadline) + Duration::from_secs(1);
    rig2.clock.advance(past - rig2.clock.now() + Duration::from_secs(1));
    let ctx = CallContext { credential: b"c", deadline: past, cancelled: &|| false };
    let nref = rig2.backend.parse_ref("ok/a").unwrap();
    let r3 = rig2.backend.resolve(&ctx, &nref, &opts(300));
    assert_eq!(err(&r3), BackendError::Timeout);
    assert!(matches!(r3.effect, IssueEffect::None));
    assert_eq!(rig2.server.issue_count(), 1, "no second issue");

    // Slow dynamic: request sent, deadline consumed, no reply ⇒ Indeterminate + Unknown;
    // slow static read ⇒ Timeout + None. Both return immediately (injected clock, no sleep).
    let rig3 = rig_for("cx-slow");
    let before = rig3.clock.now();
    let s = rig3.resolve("slow/a");
    assert_eq!(err(&s), BackendError::Indeterminate);
    assert!(matches!(s.effect, IssueEffect::Unknown));
    assert_eq!(rig3.clock.now() - before, DEADLINE, "simulated wait ended exactly at the deadline");
    assert_eq!(rig3.server.issue_count(), 1);
    let ss = rig3.resolve("slowstatic/a");
    assert_eq!(err(&ss), BackendError::Timeout);
    assert!(matches!(ss.effect, IssueEffect::None));
    assert_eq!(rig3.server.issue_count(), 1);

    // Cancel while paused BEFORE the server issue: Cancelled + None, server untouched.
    let rig4 = rig_for("cx-before");
    let gate = Gate::new();
    rig4.server.gate_before_issue(gate.clone());
    let flag = AtomicBool::new(false);
    let r4 = std::thread::scope(|s| {
        let h = s.spawn(|| rig4.resolve_with("ok/a", 300, &|| flag.load(Ordering::SeqCst)));
        gate.wait_reached();
        assert_eq!(rig4.server.issue_count(), 0);
        flag.store(true, Ordering::SeqCst);
        gate.release();
        h.join().unwrap()
    });
    assert_eq!(err(&r4), BackendError::Cancelled);
    assert!(matches!(r4.effect, IssueEffect::None));
    assert_eq!(rig4.server.issue_count(), 0);

    // Cancel while paused AFTER the server issue: the lease is discovered and reported
    // (Known for a full reply, KnownId for an ID-only reply), never delivered.
    for (native, want) in [("ok/a", "Known"), ("revokefail/a", "Known"), ("diesmid-nottl/a", "KnownId")] {
        let rig5 = rig_for(&format!("cx-after-{}", native.split('/').next().unwrap()));
        let gate = Gate::new();
        rig5.server.gate_after_issue(gate.clone());
        let flag = AtomicBool::new(false);
        let r5 = std::thread::scope(|s| {
            let h = s.spawn(|| rig5.resolve_with(native, 300, &|| flag.load(Ordering::SeqCst)));
            gate.wait_reached();
            assert_eq!(rig5.server.issue_count(), 1, "server already issued");
            flag.store(true, Ordering::SeqCst);
            gate.release();
            h.join().unwrap()
        });
        assert_eq!(err(&r5), BackendError::Cancelled, "{native}");
        assert_eq!(kind_of(&r5.effect), want, "{native}");
        assert_eq!(effect_id(&r5.effect), rig5.server.lease_ids()[0]);
        assert_eq!(rig5.server.issue_count(), 1, "{native}: no replay after cancel");
    }

    // Lost reply because the deadline passed while paused after send ⇒ Indeterminate + Unknown.
    let rig6 = rig_for("cx-late");
    let gate = Gate::new();
    rig6.server.gate_after_issue(gate.clone());
    let r6 = std::thread::scope(|s| {
        let h = s.spawn(|| rig6.resolve("ok/a"));
        gate.wait_reached();
        rig6.clock.advance(DEADLINE + Duration::from_secs(1));
        gate.release();
        h.join().unwrap()
    });
    assert_eq!(err(&r6), BackendError::Indeterminate);
    assert!(matches!(r6.effect, IssueEffect::Unknown));
    assert_eq!(rig6.server.issue_count(), 1);
}

/// Values are random per call and never reach Debug of Bundle/Resolved parts/BackendError/server.
#[test]
fn values_never_appear_in_debug_output() {
    let rig = rig_for("dbg");
    let token = Zeroizing::new(rand::random::<[u8; 32]>());
    let planted = Zeroizing::new(token.iter().map(|b| format!("{b:02x}")).collect::<String>());
    rig.server.set_static_value("planted", planted.clone());
    let r = rig.resolve("static/planted");
    let b = r.result.as_ref().unwrap();
    assert!(text(b, "value") == planted.as_str(), "fake serves planted synthetic value");
    let mut dump = format!("{:?}", r.result);
    for native in ["ok/a", "flap/a", "static/other", "diesmid/a", "diesmid-nottl/a", "throttle/a", "slow/a"] {
        let r = rig.resolve(native);
        dump += &format!("{:?}", r.result);
        if let Ok(b) = &r.result {
            for name in b.fields().keys() {
                let v = text(b, name);
                assert!(!format!("{b:?}").contains(v), "bundle Debug leaks {name}");
                assert!(!format!("{:?}", b.fields()[name]).contains(v), "field Debug leaks {name}");
                assert!(!dump.contains(v), "{native}: {name} leaked");
            }
            if let Some(l) = &b.lease {
                dump += &format!("{l:?}");
            }
        }
        dump += &format!("{:?}", r.result.as_ref().err());
    }
    assert!(!dump.contains(planted.as_str()), "planted value leaked through Debug");
    assert!(!format!("{:?}", rig.server).contains(planted.as_str()));
    assert!(!format!("{:?}", rig.server.revoke_log()).contains(planted.as_str()));
    for e in [BackendError::Indeterminate, BackendError::Timeout, BackendError::TtlExceeded] {
        assert!(!format!("{e:?} {e}").contains(planted.as_str()));
    }
    // Two calls, two different random values.
    assert!(
        text(rig.resolve("ok/a").result.as_ref().unwrap(), "password") !=
        text(rig.resolve("ok/a").result.as_ref().unwrap(), "password"),
        "random values differ"
    );
}

/// The fake is reachable only through an explicit `fake::register` call.
#[test]
fn fake_kind_is_unregistered_by_default_and_refs_are_validated() {
    let registry = Registry::default();
    assert_eq!(registry.validate_kind("fake"), Err(BackendError::InvalidConfig));
    let mut registry = Registry::default();
    fake::register(&mut registry).unwrap();
    assert!(fake::register(&mut registry).is_err(), "double registration refused");
    assert!(registry.validate_kind("fake").is_ok());
    // Registered kind, but no server attached to this endpoint ⇒ InvalidConfig, no I/O attempt.
    assert!(matches!(
        registry.add_source(&config("nowhere", "https://nowhere.fake.invalid/")),
        Err(BackendError::InvalidConfig)
    ));
    let rig = rig_for("refs");
    for bad in ["nope/a", "ok", "ok/", "ok/a#value", "static/a#password", "ok/a b", "ok/../a", "ok/a/b"] {
        assert!(rig.backend.parse_ref(bad).is_err(), "{bad}");
    }
    assert_eq!(rig.backend.id(), "fake");
    assert!(rig.backend.capabilities().revoke);
    assert_eq!(rig.backend.parse_ref("ok/a#password").unwrap().field.as_deref(), Some("password"));
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            if !matches!(p.file_name().and_then(|n| n.to_str()), Some("target" | "node_modules" | ".git")) {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Production (every `src/` tree in the workspace) must never name or register the fake.
#[test]
fn production_sources_never_register_the_fake() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for top in ["crates", "app"] {
        if root.join(top).exists() {
            rust_files(&root.join(top), &mut files);
        }
    }
    let mut checked = 0;
    for f in files {
        let p = f.to_string_lossy().replace('\\', "/");
        let in_src = p.contains("/src/") && !p.contains("/tests/");
        if !in_src || p.ends_with("crates/core/src/backend/fake.rs") {
            continue;
        }
        checked += 1;
        let text = fs::read_to_string(&f).unwrap();
        let text: String = text.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        assert!(!text.contains("fake::"), "{p} references the fake module");
        assert!(!text.contains("FakeServer") && !text.contains("FakeBackend"), "{p}");
        if p.ends_with("crates/core/src/backend/mod.rs") {
            assert_eq!(text.matches("pub mod fake;").count(), 1);
        } else {
            assert!(!text.contains("mod fake"), "{p}");
        }
    }
    assert!(checked > 5, "scan found {checked} production files");
}

#[test]
fn known_id_revoke_override_retries_through_public_trait() {
    for n in [0, 1, 3] {
        let rig = rig_for("known-id-retry");
        let r = rig.resolve("diesmid-nottl/a");
        let IssueEffect::KnownId { id } = r.effect else { panic!("ID-only response required") };
        rig.server.set_lease_revoke_failures(&id, n).unwrap();
        for _ in 0..n {
            assert_eq!(rig.call(&|| false, |c| rig.backend.revoke(c, &id)), Err(BackendError::Transient));
            assert!(rig.server.is_live(id.as_str()));
        }
        assert_eq!(rig.call(&|| false, |c| rig.backend.revoke(c, &id)), Ok(()));
        assert_eq!(rig.server.revoke_log().len(), n as usize + 1);
        assert!(rig.server.is_revoked(id.as_str()));
    }
}

#[test]
fn wall_rollback_leaves_monotonic_unchanged() {
    let clock = FakeClock::new(T0);
    clock.advance(Duration::from_secs(10));
    let monotonic = clock.now();
    clock.set_wall(T0 - 20);
    assert_eq!(clock.wall(), T0 - 20);
    assert_eq!(clock.now(), monotonic);
}

#[test]
fn concurrent_advance_to_same_deadline_is_atomic() {
    for _ in 0..256 {
        let clock = FakeClock::new(T0);
        let deadline = clock.now() + DEADLINE;
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|s| {
            for _ in 0..2 {
                let clock = &clock;
                let start = &start;
                s.spawn(move || { start.wait(); clock.advance_to(deadline); });
            }
        });
        assert_eq!(clock.now(), deadline);
        assert_eq!(clock.wall(), T0 + DEADLINE.as_secs());
    }
}

#[test]
fn credential_only_retarget_observes_old_cleanup_identity() {
    let rig = rig_for("credential-retarget");
    let old = Zeroizing::new(rand::random::<[u8; 32]>().to_vec());
    let new = Zeroizing::new(rand::random::<[u8; 32]>().to_vec());
    rig.server.set_expected_credential(old.clone());
    let resolve = |credential: &[u8]| {
        let c = CallContext { credential, deadline: rig.clock.now() + DEADLINE, cancelled: &|| false };
        rig.backend.resolve(&c, &rig.backend.parse_ref("ok/a").unwrap(), &opts(300))
    };
    let issued = resolve(&old);
    // Replacement binding retains endpoint but changes credential revision/generation.
    let mut registry = Registry::default();
    fake::register(&mut registry).unwrap();
    let mut replacement = config("replacement", &rig.endpoint);
    replacement.credential_revision = "r2".into();
    replacement.generation = "1123456789abcdef0123456789abcdef".into();
    registry.add_source(&replacement).unwrap();
    let backend = registry.lookup("replacement").unwrap();
    let c = CallContext { credential: &new, deadline: rig.clock.now() + DEADLINE, cancelled: &|| false };
    backend.resolve(&c, &backend.parse_ref("ok/a").unwrap(), &opts(300));
    assert_eq!(rig.server.resolve_credentials(), vec![Some(true), Some(false)]);
    let id = LeaseId::parse(&effect_id(&issued.effect)).unwrap();
    backend.revoke(&c, &id).unwrap();
    let c = CallContext { credential: &old, ..c };
    rig.backend.revoke(&c, &id).unwrap();
    let log = rig.server.revoke_log();
    assert_eq!(log[0].credential_matches, Some(false));
    assert_eq!(log[1].credential_matches, Some(true));
}

#[test]
fn metadata_hook_modes_counter_and_gate_do_not_issue() {
    use fake::MetadataMode;
    let r = rig_for("metadata-hooks");
    let native = r.backend.parse_ref("ok/a").unwrap();
    assert!(!r.backend.capabilities().metadata);
    let bundle = r.resolve("ok/a").result.unwrap();
    r.server.set_metadata(true, MetadataMode::Unchanged);
    assert!(r.backend.capabilities().metadata);
    let gate = Gate::new();
    r.server.gate_metadata(gate.clone());
    let meta = std::thread::scope(|scope| {
        let h = scope.spawn(|| r.call(&|| false, |c| r.backend.metadata(c, &native)));
        gate.wait_reached();
        assert_eq!(r.server.metadata_call_count(), 1);
        assert_eq!(r.server.issue_count(), 1);
        gate.release();
        h.join().unwrap().unwrap()
    });
    assert_eq!(meta.change.version, bundle.change.version);
    assert_eq!(meta.credential_expires_at, bundle.lease.map(|l| l.expires_at));
    r.server.set_metadata(true, MetadataMode::Changed);
    assert_ne!(r.call(&|| false, |c| r.backend.metadata(c, &native)).unwrap().change.version, meta.change.version);
    for (mode, error) in [(MetadataMode::Error, BackendError::Transient), (MetadataMode::Unsupported, BackendError::Unsupported)] {
        r.server.set_metadata(true, mode);
        assert_eq!(r.call(&|| false, |c| r.backend.metadata(c, &native)).err(), Some(error));
    }
    assert_eq!(r.server.metadata_call_count(), 4);
    assert_eq!(r.server.issue_count(), 1);
    assert_eq!(r.server.call_count(), 1);
}
