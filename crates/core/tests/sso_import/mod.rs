//! Loopback-only discovery/import smoke and bounded-discovery negative.
use super::*;
use crate::{helper, sso, Tier};
use std::{cell::Cell, rc::Rc};

struct PortalFake {
    base: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl PortalFake {
    fn start(cap: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = stop.clone();
        let thread = std::thread::spawn(move || {
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else { std::thread::sleep(Duration::from_millis(2)); continue; };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new(); reader.read_line(&mut request).unwrap();
                let path = request.split_whitespace().nth(1).unwrap();
                let mut bearer = false;
                loop {
                    let mut line = String::new(); reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() { break; }
                    if line.to_ascii_lowercase().starts_with("x-amz-sso_bearer_token: ") { bearer = true; }
                }
                assert!(bearer);
                let page2 = path.contains("next_token=page%2B2");
                let body = if cap {
                    json!({"accountList":[], "nextToken":"again"})
                } else if path.starts_with("/assignment/accounts?max_result=100") {
                    if page2 { json!({"accountList":[{"accountId":"222222222222","accountName":"Team"}]}) }
                    else { json!({"accountList":[{"accountId":"111111111111","accountName":"Team"}, {"accountId":"invalid","accountName":"bad"}], "nextToken":"page+2"}) }
                } else {
                    assert!(path.starts_with("/assignment/roles?account_id="));
                    let account = if path.contains("111111111111") { "111111111111" } else { "222222222222" };
                    if page2 { json!({"roleList":[{"accountId":account,"roleName":"ReadOnly"}]}) }
                    else { json!({"roleList":[{"accountId":account,"roleName":"Admin"}, {"accountId":account,"roleName":"bad/role"}], "nextToken":"page+2"}) }
                }.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        sso::TEST_BASE.with(|b| *b.borrow_mut() = Some(base.clone()));
        Self { base, stop, thread: Some(thread) }
    }
}
impl Drop for PortalFake {
    fn drop(&mut self) {
        sso::TEST_BASE.with(|b| b.borrow_mut().take());
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() { result.unwrap(); }
    }
}
fn setup(label: &str) -> (Paths, Ctx, agent::Peer) {
    let p = super::unlock_routing_tests::fixture(label);
    let session = super::tests::session("import-synthetic", 3600, None);
    let mut cfg = store::load_config(&p).unwrap();
    cfg.sso_portals.insert("main".into(), store::SsoPortal { start_url: session.start_url.clone(), region: session.region.clone(), limit_minutes: None, accounts: Default::default() });
    store::save_config(&p, &cfg).unwrap();
    let mut state = State::default(); state.sso.insert("main".into(), session);
    (p, Ctx::new(state), agent::Peer { pid: std::process::id() as i32, ..Default::default() })
}
fn import(items: Vec<sso::ImportItem>) -> Req {
    Req::SsoImport { portal: "main".into(), items, tier: Tier::Bio, agent_allowed: false, region: None }
}

#[test]
fn sso_import_loopback_smoke_and_existing_skip() {
    let fake = PortalFake::start(false);
    assert!(fake.base.starts_with("http://127.0.0.1:"));
    let (p, st, peer) = setup("sso-import-smoke");
    let auth = Rc::new(Cell::new(0)); let count = auth.clone();
    helper::AUTH_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move || { count.set(count.get()+1); Ok(()) })));
    let found = handle_as(&p, &st, peer.clone(), Req::SsoDiscover { portal: "main".into() }, 0, None, Ok).unwrap();
    let roles = serde_json::from_value(found).unwrap();
    let preview = handle_as(&p, &st, peer.clone(), Req::SsoImportPreview { portal: "main".into(), roles }, 0, None, Ok).unwrap();
    let rows: Vec<sso::ImportPreview> = serde_json::from_value(preview).unwrap();
    assert_eq!(rows.iter().map(|r| (r.item.name.as_str(), r.action.as_str())).collect::<Vec<_>>(), vec![("111111111111-admin", "new"), ("111111111111-readonly", "new"), ("222222222222-admin", "new"), ("222222222222-readonly", "new")]);
    assert_eq!(auth.get(), 0, "dry-run preview never authenticates");
    assert!(!sso::glob_matches("*Admin*", "Team/ReadOnly"));
    assert!(sso::glob_matches("*/Read?nly", "Team/ReadOnly"));
    let items: Vec<_> = rows.into_iter().map(|r| r.item).collect();
    let result = handle_as(&p, &st, peer.clone(), import(items.clone()), 0, None, Ok).unwrap();
    assert_eq!(result, json!({"added":4,"skipped":0})); assert_eq!(auth.get(), 1);
    // Account names are kept per portal for display (AWS page folders).
    let accounts = store::load_config(&p).unwrap().sso_portals["main"].accounts.clone();
    assert_eq!(accounts.get("111111111111").map(String::as_str), Some("Team"));
    assert_eq!(accounts.get("222222222222").map(String::as_str), Some("Team"));
    let before: Vec<_> = items.iter().map(|i| std::fs::read(p.secret(&format!("aws/{}", i.name)).unwrap()).unwrap()).collect();
    for i in &items {
        let f = store::load_secret(&p, &format!("aws/{}", i.name)).unwrap();
        assert_eq!(f.tier, Tier::Bio); assert!(!f.agent_allowed);
        assert_eq!(st.lock().unwrap().sso_profiles[&f.name].profile.child_region(), "us-west-2");
    }
    // Same tuple under a different proposed name is still skipped.
    let mut again = items.clone(); again[0].name = "different-name".into();
    assert_eq!(handle_as(&p, &st, peer, import(again), 0, None, Ok).unwrap(), json!({"added":0,"skipped":4}));
    assert_eq!(auth.get(), 1);
    for (i, b) in items.iter().zip(before) { assert_eq!(std::fs::read(p.secret(&format!("aws/{}", i.name)).unwrap()).unwrap(), b); }
    helper::AUTH_HOOK.with(|h| h.borrow_mut().take());
    std::fs::remove_dir_all(p.root).unwrap();
}

#[test]
fn sso_import_pagination_cap_saves_nothing() {
    let _fake = PortalFake::start(true);
    let (p, st, peer) = setup("sso-import-cap");
    let before = serde_json::to_value(store::list_secrets(&p).unwrap()).unwrap();
    let error = handle_as(&p, &st, peer, Req::SsoDiscover { portal: "main".into() }, 0, None, Ok).unwrap_err();
    assert!(error.to_string().contains("pagination cap exceeded"));
    assert_eq!(serde_json::to_value(store::list_secrets(&p).unwrap()).unwrap(), before);
    std::fs::remove_dir_all(p.root).unwrap();
}
