//! In-process daemon fixtures, expanded only inside daemon's private test module.
//! Cargo also compiles this file as an integration target; no daemon is spawned.
#[allow(unused_macros)]
macro_rules! backend_daemon_tests {
    () => {
    struct TestBackendClock(Arc<crate::backend::fake::FakeClock>);
    impl crate::backend::Clock for TestBackendClock {
        fn now(&self) -> crate::backend::Time {
            crate::backend::Time { wall: self.0.wall(), monotonic: self.0.now() }
        }
    }
    fn backend_peer(id: i32) -> agent::Peer {
        agent::Peer { pid: id, anchor: Some((id, 42)), ancestors: vec![(id, 42)], ..Default::default() }
    }
    fn backend_decrypt() {
        helper::ECDH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|requests| {
            let sk = p256::SecretKey::from_slice(&[7;32]).unwrap();
            requests.iter().map(|(_,eph)| {
                let pk = p256::PublicKey::from_sec1_bytes(&B64.decode(eph)?)?;
                Ok(Zeroizing::new(p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()))
            }).collect()
        })));
    }
    fn backend_fixture(label: &str) -> (Paths, Ctx, Arc<crate::backend::fake::FakeServer>) {
        use crate::backend::{Registry, fake};
        let p = fixture(label);
        let clock = fake::FakeClock::new(now());
        let server = fake::FakeServer::new(clock.clone());
        let endpoint = format!("https://{label}.invalid/");
        fake::attach(&endpoint, &server).unwrap();
        let mut registry = Registry::default();
        fake::register(&mut registry).unwrap();
        let st = Ctx { state: Mutex::new(State::default()), backends: Backends {
            registry: Arc::new(registry), clock: Arc::new(TestBackendClock(clock)),
            upstream_max_ttl: Some(Duration::from_secs(900)), runtime: Mutex::new(BackendRuntime::default()),
        }};
        let mut req = source_add_request();
        if let Req::SourceAdd { endpoint: target, .. } = &mut req { *target = endpoint; }
        source_approve(&p);
        handle_as(&p, &st, backend_peer(10), req, 0, None, Ok).unwrap();
        server.set_expected_credential(Zeroizing::new(b"synthetic-source-input".to_vec()));
        (p, st, server)
    }
    fn backend_request() -> Req {
        Req::Resolve { reference: "f:ok/a#password".into(), grant: None, context: None }
    }

    #[test]
    fn backend_launch_projected_env_and_whole_bundle_redaction() {
        let (p, st, server) = backend_fixture("backend-launch");
        let mut cfg = store::load_config(&p).unwrap();
        cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
        cfg.removed_defaults = store::DEFAULT_AGENT_PROCESS_NAMES.iter()
            .chain(store::DEFAULT_AGENT_ENV_MARKERS).map(|s| (*s).into()).collect();
        store::save_config(&p, &cfg).unwrap();
        let pid = std::process::id() as i32;
        let mut peer = agent::detect_peer(&cfg, pid);
        assert!(!peer.caller.is_agent());
        peer.anchor = Some((pid, 42)); peer.ancestors.push((pid, 42));
        let live_peer = peer.clone();
        LAUNCH_OWNER_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |_| live_peer.clone())));
        let exe = agent::proc_exe(pid).unwrap();
        std::fs::write(p.keys().join("daemon.sha256"), crate::helper::sha256_file(Path::new(&exe)).unwrap()).unwrap();
        let reference = "f:ok/a#password".to_string();
        // Both initial issue and a cached delivery must carry the entire bundle.
        for iteration in 0..2 {
            let prepared = launch_scope(|| prepare_launch(&p, &st, &peer, vec![reference.clone()],
                [("PASSWORD".into(), reference.clone())].into(), "/usr/bin/true".into(),
                vec!["/usr/bin/true".into()], p.root.clone(), None, false, vec![], 0, false)).unwrap();
            assert_eq!(server.issue_count(), iteration.min(1), "prepare must not resolve values");
            let id = prepared["id"].as_str().unwrap().to_string();
            // In-process bound-session fixture: a live direct child supplies the
            // kernel shim identity; no installed binary or live daemon socket.
            let mut child = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let shim = agent::process_identity(child.id() as i32).unwrap();
            let owner = agent::process_identity(pid).unwrap();
            let taken = st.lock().unwrap().pending_launches.bind(&id, owner, shim, now()).unwrap();
            let token = [17u8; 32];
            let mut session = BoundSession { p: &p, st: &st, id: id.clone(), _token: Some(Zeroizing::new(token)),
                _shim: shim, taken: Some(taken), endpoint: None, http_port: 0 };
            source_approve(&p); backend_decrypt();
            let (mut writer, reader) = UnixStream::pair().unwrap();
            let frame = format!("{{\"op\":\"launch_redeem\",\"token\":\"{}\"}}", B64.encode(token));
            let result = launch_scope(|| redeem_launch(&mut session, frame.as_bytes(), Instant::now() + Duration::from_secs(10), &mut writer));
            if result.is_err() { let _ = child.kill(); let _ = child.wait(); }
            result.unwrap();
            let mut line = Zeroizing::new(String::new());
            BufReader::new(reader).read_line(&mut line).unwrap();
            let bundle: Value = serde_json::from_str(&line).unwrap();
            let delivered = launch_scope(|| resolve_values(&p, &st, &peer, &reference, None)).unwrap();
            let crate::backend::SecretField::Text(password) = &delivered.fields["password"] else { panic!("text") };
            assert_eq!(bundle["env"], json!({"PASSWORD": password.as_str()}));
            assert_eq!(delivered.redact.len(), 2);
            let redaction = st.lock().unwrap().launch_redactions[&id].frame.clone();
            let redaction: Value = serde_json::from_slice(&redaction).unwrap();
            let named: Vec<_> = redaction["values"].as_array().unwrap().iter()
                .map(|v| (v[0].as_str().unwrap().to_string(), v[1].as_str().unwrap().as_bytes())).collect();
            assert_eq!(named.len(), 2);
            let redactor = crate::redact::Redactor::new(&named);
            for bytes in &delivered.redact {
                assert!(named.iter().any(|(_, v)| *v == bytes.as_slice()));
                assert!(redactor.process(&mut bytes.to_vec(), true).starts_with(b"[REDACTED:"));
            }
            assert_eq!(server.issue_count(), 1);
            drop(session);
            child.kill().unwrap(); child.wait().unwrap();
        }
        let error = launch_legacy_files(&p, &cfg, &agent_peer(), &[reference]).unwrap_err();
        assert_eq!(error.to_string(), crate::backend::BackendError::NeedsHuman.to_string());
        LAUNCH_OWNER_HOOK.with(|h| h.borrow_mut().take());
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn backend_daemon_smoke_and_session_isolation() {
        let (p, st, server) = backend_fixture("backend-smoke");
        source_approve(&p);
        backend_decrypt();
        let wire = handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).unwrap();
        assert_eq!(wire, json!({"ok": true, "source": "f", "ref": "f:ok/a#password"}));
        assert_eq!(server.issue_count(), 1);
        let cached = handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).unwrap();
        assert_eq!(cached, wire);
        assert_eq!(server.issue_count(), 1);
        let delivery = launch_scope(|| resolve_values(&p, &st, &backend_peer(10), "f:ok/a#password", None)).unwrap();
        let crate::backend::SecretField::Text(value) = &delivery.fields["password"] else { panic!("not text") };
        assert!(!wire.to_string().contains(value.as_str()));
        let audit = std::fs::read_to_string(p.root.join("audit.jsonl")).unwrap();
        assert!(!audit.contains(value.as_str()));
        assert!(audit.contains("daemon-backend-resolve"));
        assert!(audit.contains("Intent") && audit.contains("Result"));
        let grant = {
            let g = st.backends.runtime.lock().unwrap();
            format!("{:?}", g.grants.values().next().unwrap().id)
        };
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| bail!("auth refused"))));
        let replay = Req::Resolve { reference: "f:ok/a#password".into(), grant: Some(grant), context: None };
        assert!(handle_as(&p, &st, backend_peer(20), replay, 0, None, Ok).is_err());
        assert_eq!(server.issue_count(), 1);
        source_approve(&p);
        handle_as(&p, &st, backend_peer(20), backend_request(), 0, None, Ok).unwrap();
        assert_eq!(server.issue_count(), 2);
        assert_eq!(server.resolve_credentials(), vec![Some(true), Some(true)]);
        assert!(st.backends.tick(), "live owners keep the daemon alive");
        server.clock().advance(Duration::from_secs(301));
        assert!(!st.backends.tick(), "expired owners no longer keep it alive");
        assert!(st.backends.services().iter().all(|s| s.status().owners == 0 && s.status().pending_revoke.is_empty()));
        assert!(std::fs::read_to_string(p.root.join("audit.jsonl")).unwrap().contains("revoke-abandoned-at-upstream-expiry"));
        clear_hooks();
        std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn backend_daemon_retarget_remove_and_tick() {
        let (p, st, server) = backend_fixture("backend-retarget");
        source_approve(&p); backend_decrypt();
        handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).unwrap();
        let old = st.backends.services()[0].clone();
        let old_grant = st.backends.runtime.lock().unwrap().grants.values().next().unwrap().id;
        source_approve(&p); backend_decrypt();
        handle_as(&p, &st, backend_peer(10), Req::SourceRetarget { name: "f".into(), endpoint: None,
            credential: Some(SourceCredential(Zeroizing::new("synthetic-new".into()))), policy: None }, 0, None, Ok).unwrap();
        assert_eq!(st.backends.runtime.lock().unwrap().sources.len(), 1);
        let stale = old.resolve(crate::backend::ResolveRequest { grant: old_grant,
            session: crate::backend::SessionId::from_kernel(1), native: "ok/a", selectors: &["password"], cancelled: Arc::new(|| false) });
        assert!(stale.is_err());
        st.backends.tick();
        assert_eq!(server.revoke_log().len(), 1);
        assert_eq!(server.revoke_log()[0].credential_matches, Some(true));
        server.set_expected_credential(Zeroizing::new(b"synthetic-new".to_vec()));
        source_approve(&p);
        handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).unwrap();
        assert_eq!(server.issue_count(), 2);
        assert_eq!(server.resolve_credentials(), vec![Some(true), Some(true)]);
        source_approve(&p);
        handle_as(&p, &st, backend_peer(10), Req::SourceRemove { name: "f".into() }, 0, None, Ok).unwrap();
        assert!(st.backends.runtime.lock().unwrap().sources.is_empty());
        assert!(handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).is_err());
        st.backends.tick();
        assert_eq!(server.revoke_log().len(), 2);
        assert_eq!(server.revoke_log()[1].credential_matches, Some(true));
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn backend_daemon_refusals_before_issue() {
        let (p, st, server) = backend_fixture("backend-refusals");
        helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(|| bail!("auth refused"))));
        let e = handle_as(&p, &st, agent_peer(), backend_request(), 0, None, Ok).unwrap_err();
        assert_eq!(e.to_string(), crate::backend::BackendError::NeedsHuman.to_string());
        assert!(helper::AUTH_HOOK.with(|h| h.borrow().is_some()));
        crate::audit::fail_phase(Some("intent"));
        assert!(handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).is_err());
        crate::audit::fail_phase(None);
        assert!(helper::AUTH_HOOK.with(|h| h.borrow().is_some()), "intent failure must precede auth");
        assert!(handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).unwrap_err().to_string().contains("auth refused"));
        let empty = Ctx::new(State::default());
        let e = handle_as(&p, &empty, backend_peer(10), backend_request(), 0, None, Ok).unwrap_err();
        assert_eq!(e.to_string(), crate::backend::BackendError::Unsupported.to_string());
        store::remove_secret(&p, "sources/f/cred").unwrap();
        source_approve(&p);
        let e = handle_as(&p, &st, backend_peer(10), backend_request(), 0, None, Ok).unwrap_err();
        assert_eq!(e.to_string(), crate::backend::BackendError::NeedsHuman.to_string());
        assert_eq!(server.issue_count(), 0);
        clear_hooks(); std::fs::remove_dir_all(p.root).unwrap();
    }

    };
}
