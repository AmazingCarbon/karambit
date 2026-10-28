//! Tests that need no Secure Enclave: a software P-256 key stands in for the SE key.

use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint};
use rand::rngs::OsRng;
use karambit_core::{
    SecretFile, Tier, crypto, default_var, parse_env_file, redact::Redactor, store::glob_match,
    store::validate_name,
};

fn soft_key() -> (SecretKey, Vec<u8>) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (sk, pk)
}

fn shared_for(sk: &SecretKey, f: &SecretFile) -> Vec<u8> {
    use base64::Engine;
    let eph = base64::engine::general_purpose::STANDARD.decode(&f.eph).unwrap();
    let eph = PublicKey::from_sec1_bytes(&eph).unwrap();
    diffie_hellman(sk.to_nonzero_scalar(), eph.as_affine()).raw_secret_bytes().to_vec()
}

fn make(name: &str, tier: Tier, agent: bool, pk: &[u8], value: &[u8], backup: Option<&str>) -> (SecretFile, crypto::Dek) {
    make_p(name, tier, agent, false, pk, value, backup)
}

#[allow(clippy::too_many_arguments)]
fn make_p(name: &str, tier: Tier, agent: bool, public: bool, pk: &[u8], value: &[u8], backup: Option<&str>) -> (SecretFile, crypto::Dek) {
    let dek = crypto::new_dek();
    let w = crypto::wrap_dek(&dek, pk, name, tier, agent, public).unwrap();
    let (nonce, ct) = crypto::seal(&dek, name, value).unwrap();
    let f = SecretFile {
        v: crypto::CURRENT_V,
        name: name.into(),
        tier,
        agent_allowed: agent,
        public,
        eph: w.eph,
        wrap_nonce: w.wrap_nonce,
        wrapped_dek: w.wrapped_dek,
        nonce,
        ct,
        backup: backup.map(|r| crypto::backup_wrap(&dek, r).unwrap()),
        created: 0,
        updated: 0,
        key: None,
    };
    (f, dek)
}

#[test]
fn envelope_roundtrip() {
    let (sk, pk) = soft_key();
    let (f, _) = make("stripe/prod", Tier::Bio, true, &pk, b"sk_live_123", None);
    let dek = crypto::unwrap_dek(&f, &shared_for(&sk, &f), &pk).unwrap();
    assert_eq!(&**crypto::open(&dek, &f).unwrap(), b"sk_live_123");
}

#[test]
fn tampering_policy_fields_breaks_unwrap() {
    let (sk, pk) = soft_key();
    let (f, _) = make("a/b", Tier::Bio, false, &pk, b"v", None);
    let s = shared_for(&sk, &f);
    let mut t = f.clone();
    t.tier = Tier::Open;
    assert!(crypto::unwrap_dek(&t, &s, &pk).is_err(), "tier flip must fail");
    let mut t = f.clone();
    t.agent_allowed = true;
    assert!(crypto::unwrap_dek(&t, &s, &pk).is_err(), "agent flip must fail");
    let mut t = f.clone();
    t.name = "a/c".into();
    assert!(crypto::unwrap_dek(&t, &s, &pk).is_err(), "rename must fail");
    let mut t = f.clone();
    t.public = true;
    assert!(crypto::unwrap_dek(&t, &s, &pk).is_err(), "public flip must fail");
}

#[test]
fn v1_file_ignores_public_flag() {
    // A pre-public (v1) file with public=true tampered in must NOT be honored.
    let (sk, pk) = soft_key();
    let (mut f, _) = make("a/b", Tier::Open, true, &pk, b"v", None);
    // Simulate a v1 file: rewrap with v1 AAD is not exposed, so just force fields.
    f.v = 1;
    f.public = true;
    assert!(!f.is_public(), "v1 public flag must be ignored");
    // And it still won't decrypt under v1 AAD because it was wrapped as v2.
    assert!(crypto::unwrap_dek(&f, &shared_for(&sk, &f), &pk).is_err());
}

#[test]
fn wrong_key_fails() {
    let (_, pk) = soft_key();
    let (other, _) = soft_key();
    let (f, _) = make("x/y", Tier::Open, true, &pk, b"v", None);
    assert!(crypto::unwrap_dek(&f, &shared_for(&other, &f), &pk).is_err());
}

#[test]
fn backup_recovers_dek() {
    let (text, recip) = crypto::generate_backup_identity();
    let (_, pk) = soft_key();
    let (f, _) = make("x/y", Tier::Bio, true, &pk, b"recover-me", Some(&recip));
    let id = crypto::parse_identity(&text).unwrap();
    let dek = crypto::backup_unwrap(f.backup.as_ref().unwrap(), &id).unwrap();
    assert_eq!(&**crypto::open(&dek, &f).unwrap(), b"recover-me");
}

#[test]
fn redacts_across_chunk_boundaries() {
    let secrets = vec![("k/a".to_string(), &b"SECRETVALUE"[..]), ("k/b".to_string(), &b"hunter22"[..])];
    let r = Redactor::new(&secrets);
    let input = b"x=SECRETVALUE y=hunter22 zSECRETVALUEz";
    for split in 0..input.len() {
        let mut buf = Vec::new();
        let mut out = Vec::new();
        buf.extend_from_slice(&input[..split]);
        out.extend(r.process(&mut buf, false));
        buf.extend_from_slice(&input[split..]);
        out.extend(r.process(&mut buf, true));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "x=[REDACTED:k/a] y=[REDACTED:k/b] z[REDACTED:k/a]z",
            "split at {split}"
        );
    }
}

#[test]
fn redact_pump_and_short_values() {
    let secrets = vec![("s".to_string(), &b"abc"[..]), ("l".to_string(), &b"longsecret"[..])];
    let r = Redactor::new(&secrets);
    let mut out = Vec::new();
    r.pump(&b"abc longsecret"[..], &mut out).unwrap();
    assert_eq!(out, b"abc [REDACTED:l]");
}

#[test]
fn names_and_globs() {
    assert!(validate_name("work/aws-staging.key_1").is_ok());
    for bad in ["", "../x", "a//b", ".hidden/x", "a/b c", "a/.."] {
        assert!(validate_name(bad).is_err(), "{bad}");
    }
    assert!(glob_match("dev/*", "dev/db"));
    assert!(glob_match("dev/*", "dev/sub/db"));
    assert!(!glob_match("dev/*", "prod/db"));
    assert!(glob_match("*", "a/b"));
}

#[test]
fn env_file_parsing() {
    let t = "# comment\nSTRIPE=stripe/prod\nexport DB=\"karambit:db/pw\"\n\n";
    let v = parse_env_file(t).unwrap();
    assert_eq!(v, vec![("STRIPE".into(), "stripe/prod".into()), ("DB".into(), "db/pw".into())]);
    assert!(parse_env_file("1BAD=x").is_err());
    assert_eq!(default_var("stripe/prod-key"), "STRIPE_PROD_KEY");
}

#[test]
fn paper_roundtrip_and_typo_detection() {
    let (id, recip) = crypto::generate_paper_identity();
    let sheet = crypto::paper_format(&id);
    let body = id.strip_prefix(crypto::PAPER_PREFIX).unwrap();
    assert_eq!(body.len(), crypto::PAPER_BODY);
    assert_eq!(sheet.lines().count(), crypto::paper_row_count());
    assert!(!body.contains(['1', 'B', 'I', 'O']));

    // Retype each sheet line exactly as displayed ("row 1   F2TK ...  check 7Q"),
    // in lowercase: labels and check code are accepted and verified.
    let rows: Vec<String> = sheet
        .lines()
        .enumerate()
        .map(|(i, l)| crypto::check_paper_row(i, &l.to_lowercase()).unwrap())
        .collect();
    assert_eq!(crypto::identity_from_rows(&rows).unwrap().to_public().to_string(), recip);

    // Bare groups, no label, no check code: also fine.
    for (i, r) in rows.iter().enumerate() {
        let spaced: Vec<&str> = r.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect();
        assert_eq!(&crypto::check_paper_row(i, &spaced.join(" ")).unwrap(), r);
    }

    // A typo in a row that has its check code is caught ON THAT ROW.
    let r0 = &rows[0];
    let code = crypto::row_check(0, r0);
    let mut bad: Vec<char> = r0.chars().collect();
    bad[5] = if bad[5] == 'Q' { 'P' } else { 'Q' };
    let bad: String = bad.into_iter().collect();
    let e = crypto::check_paper_row(0, &format!("{bad} check {code}")).unwrap_err();
    assert!(e.contains("check code"), "{e}");

    // Characters that never appear get a pointed message.
    let e = crypto::check_paper_row(0, &r0.replacen(&r0[..1], "O", 1)).unwrap_err();
    assert!(e.contains("zero"), "{e}");
    // Wrong length is reported with counts.
    assert!(crypto::check_paper_row(0, &r0[..19]).unwrap_err().contains("expected 20"));

    // Every single-character substitution is still caught by the key checksum.
    let chars: Vec<char> = body.chars().collect();
    for i in 0..chars.len() {
        let mut t = chars.clone();
        t[i] = if t[i] == 'Q' { 'P' } else { 'Q' };
        let s: String = t.into_iter().collect();
        assert!(crypto::parse_identity_loose(&s).is_err(), "typo at {i} not caught");
    }
}

#[test]
fn aws_paste_formats() {
    use karambit_core::aws;
    // Fake values in the documented shapes (AWS docs example key).
    let id = "ASIAIOSFODNN7EXAMPLE";
    let sk = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let tok = "IQoJb3JpZ2luX2VjEXAMPLE/abc+def==";
    let mac = format!("export AWS_ACCESS_KEY_ID=\"{id}\"\nexport AWS_SECRET_ACCESS_KEY=\"{sk}\"\nexport AWS_SESSION_TOKEN=\"{tok}\"\n");
    let ps = format!("$Env:AWS_ACCESS_KEY_ID=\"{id}\"\n$Env:AWS_SECRET_ACCESS_KEY=\"{sk}\"\n$Env:AWS_SESSION_TOKEN=\"{tok}\"");
    let cmd = format!("set AWS_ACCESS_KEY_ID={id}\r\nset AWS_SECRET_ACCESS_KEY={sk}\r\nset AWS_SESSION_TOKEN={tok}\r\n");
    let ini = format!("[123456789012_AdminAccess]\naws_access_key_id={id}\naws_secret_access_key={sk}\naws_session_token={tok}\nregion=us-east-2\n");
    for (label, t) in [("mac", &mac), ("powershell", &ps), ("cmd", &cmd), ("ini", &ini)] {
        let c = aws::parse(t).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(c.access_key_id, id, "{label}");
        assert_eq!(c.secret_access_key, sk, "{label}");
        assert_eq!(c.session_token.as_deref(), Some(tok), "{label}: '=' inside token must survive");
        assert!(c.temporary());
    }
    assert_eq!(aws::parse(&ini).unwrap().region.as_deref(), Some("us-east-2"));
    // JSON round trip keeps everything.
    let c = aws::parse(&mac).unwrap();
    let back = aws::AwsCreds::from_json(&c.to_json().unwrap()).unwrap();
    assert_eq!(back.session_token, c.session_token);
    // Errors that point at the problem.
    let e = aws::parse(&format!("export AWS_ACCESS_KEY_ID={id}\nexport AWS_SECRET_ACCESS_KEY={sk}")).unwrap_err().to_string();
    assert!(e.contains("SESSION_TOKEN"), "{e}");
    assert!(aws::parse("export FOO=bar").unwrap_err().to_string().contains("ACCESS_KEY_ID"));
    // Long-term AKIA key needs no token.
    assert!(aws::parse(&format!("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY={sk}")).is_ok());
    // Profile names become aws/<profile>; nested paths are not AWS entries.
    assert_eq!(aws::entry_name("prod-admin").unwrap(), "aws/prod-admin");
    assert!(aws::entry_name("a/b").is_err());
    assert!(aws::is_aws_entry("aws/prod") && !aws::is_aws_entry("aws/x/y") && !aws::is_aws_entry("ci/x"));
}

#[test]
fn redacts_truncated_and_partial_copies() {
    // Fake 1000-char token-like value (not a real credential).
    let tok: String = (0..1000).map(|i| (b'A' + (i * 7 % 26) as u8) as char).collect();
    let secrets = vec![("aws/p:session-token".to_string(), tok.as_bytes())];
    let r = Redactor::new(&secrets);
    let run = |s: &str| {
        let mut out = Vec::new();
        r.pump(s.as_bytes(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    };
    // Whole value -> single marker.
    assert_eq!(run(&format!("tok={tok}")), "tok=[REDACTED:aws/p:session-token]");
    // Truncated like `cut -c1-70`: prefix only. At most STRIDE-1 raw chars may survive.
    let cut = run(&format!("tok={}", &tok[..66]));
    assert!(cut.contains("[REDACTED:aws/p:session-token]"), "{cut}");
    let raw_left = cut.replace("tok=", "").replace("[REDACTED:aws/p:session-token]", "");
    assert!(raw_left.len() < 8, "too much survived: {raw_left:?}");
    // A slice from the middle (e.g. a wrapped log line).
    let mid = run(&tok[333..400]);
    assert!(mid.contains("[REDACTED"), "{mid}");
    assert!(mid.replace("[REDACTED:aws/p:session-token]", "").len() < 16, "{mid}");
    // Unrelated text untouched.
    assert_eq!(run("hello world 1234567890"), "hello world 1234567890");
}

#[test]
fn lease_grantee_and_scope() {
    use karambit_core::agent::Caller;
    use karambit_core::daemon::{Scope, canon_dir};
    use karambit_core::lease::Grantee;
    assert_eq!(Grantee::parse("any").unwrap(), Grantee::Any);
    assert_eq!(Grantee::parse("Claude").unwrap(), Grantee::Kind("claude".into()));
    assert_eq!(Grantee::parse("session:pid:12@34").unwrap(), Grantee::Session("pid:12@34".into()));
    assert!(Grantee::parse("rm -rf").is_err());
    let pi = Caller { agent: Some("pi".into()), kind: Some("pi".into()), ..Default::default() };
    let claude = Caller { agent: Some("claude".into()), kind: Some("claude".into()), ..Default::default() };
    assert!(Grantee::Any.covers(&pi) && Grantee::Kind("pi".into()).covers(&pi) && !Grantee::Kind("pi".into()).covers(&claude));
    assert!(!Grantee::Any.covers(&Caller::default()), "leases never apply to humans");
    // Human self-lease: covers a non-agent caller, never an agent.
    assert!(Grantee::Human.covers(&Caller::default()), "human lease covers a human");
    assert!(!Grantee::Human.covers(&pi), "human lease never covers an agent");
    assert_eq!(serde_json::from_str::<Grantee>(&serde_json::to_string(&Grantee::Human).unwrap()).unwrap(), Grantee::Human);
    // Scope labels + canonical dirs.
    let s = Scope { cwd: Some("/tmp".into()), cmds: vec!["aws".into()], max_uses: Some(3) };
    assert_eq!(s.label(), "in /tmp, only aws, 3 uses");
    assert!(Scope::default().is_empty());
    assert_eq!(canon_dir("/tmp/"), std::fs::canonicalize("/tmp").unwrap().to_string_lossy());
}

#[test]
fn key_choice_follows_policy() {
    use karambit_core::KeyId;
    // Agent key only for no-prompt secrets agents may use, and only once the vault has it.
    assert_eq!(KeyId::for_policy(Tier::Open, true, false, true), KeyId::Agent);
    assert_eq!(KeyId::for_policy(Tier::Open, false, true, true), KeyId::Agent, "public is agent-readable");
    assert_eq!(KeyId::for_policy(Tier::Open, false, false, true), KeyId::Open, "Only me stays unlock-only");
    assert_eq!(KeyId::for_policy(Tier::Bio, true, false, true), KeyId::Bio, "Touch ID never moves");
    assert_eq!(KeyId::for_policy(Tier::Open, true, false, false), KeyId::Open, "no agent key yet");
}

#[test]
fn recorded_key_must_match_tier() {
    use karambit_core::KeyId;
    let (_, pk) = soft_key();
    let (mut f, _) = make("a/b", Tier::Bio, true, &pk, b"v", None);
    assert_eq!(f.key_id().unwrap(), KeyId::Bio, "legacy file: key implied by tier");
    f.key = Some(KeyId::Agent);
    assert!(f.key_id().is_err(), "agent key on a Touch ID secret must be refused");
    let (mut g, _) = make("a/c", Tier::Open, true, &pk, b"v", None);
    g.key = Some(KeyId::Agent);
    assert_eq!(g.key_id().unwrap(), KeyId::Agent);
    // Old files without `key` parse, and None isn't written back out.
    let json = serde_json::to_string(&f).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v.as_object_mut().unwrap().remove("key");
    let back: SecretFile = serde_json::from_value(v).unwrap();
    assert_eq!(back.key, None);
}

#[test]
fn rewrap_to_another_key_keeps_value_and_policy_binding() {
    // Simulates `keys upgrade`: same DEK + AAD, new SE key. Old key must stop working.
    let (open_sk, open_pk) = soft_key();
    let (agent_sk, agent_pk) = soft_key();
    let (f, _) = make("aws/x", Tier::Open, true, &open_pk, b"creds", None);
    let dek = crypto::unwrap_dek(&f, &shared_for(&open_sk, &f), &open_pk).unwrap();
    let w = crypto::wrap_dek(&dek, &agent_pk, &f.name, f.tier, f.agent_allowed, f.public).unwrap();
    let mut nf = f.clone();
    nf.eph = w.eph;
    nf.wrap_nonce = w.wrap_nonce;
    nf.wrapped_dek = w.wrapped_dek;
    nf.key = Some(karambit_core::KeyId::Agent);
    let d2 = crypto::unwrap_dek(&nf, &shared_for(&agent_sk, &nf), &agent_pk).unwrap();
    assert_eq!(&**crypto::open(&d2, &nf).unwrap(), b"creds");
    assert!(crypto::unwrap_dek(&nf, &shared_for(&open_sk, &nf), &open_pk).is_err(), "old key must not open the new wrap");
    let mut t = nf.clone();
    t.agent_allowed = false;
    assert!(crypto::unwrap_dek(&t, &shared_for(&agent_sk, &t), &agent_pk).is_err(), "policy still bound");
}

#[test]
fn sso_profile_parsing_and_validation() {
    use karambit_core::sso::{self, AwsEntry, SsoProfile};
    let p = SsoProfile {
        portal: "main".into(),
        start_url: "https://acme.awsapps.com/start".into(),
        sso_region: "us-west-2".into(),
        account_id: "123456789012".into(),
        role_name: "ReadOnly".into(),
        region: None,
    };
    p.validate().unwrap();
    assert_eq!(p.child_region(), "us-west-2", "child region defaults to the SSO region");
    // Round trip through the vault entry format, and static entries still parse.
    assert!(matches!(sso::parse_entry(&sso::entry_json(&p).unwrap()).unwrap(), AwsEntry::Sso(q) if q == p));
    let stat = br#"{"access_key_id":"AKIAABCDEFGHIJKLMNOP","secret_access_key":"x"}"#;
    assert!(matches!(sso::parse_entry(stat).unwrap(), AwsEntry::Static(_)));
    // Bad inputs refused before anything is stored.
    for (field, bad) in [("account", "12345"), ("account", "12345678901a"), ("role", "Read Only"), ("role", "")] {
        let mut q = p.clone();
        if field == "account" { q.account_id = bad.into() } else { q.role_name = bad.into() }
        assert!(q.validate().is_err(), "{field}={bad:?} must be refused");
    }
    assert!(sso::validate_start_url("http://acme.awsapps.com/start").is_err(), "https only");
    assert!(sso::validate_start_url("https://a b").is_err());
    assert!(sso::validate_region("US-WEST-2").is_err());
    for bad in ["", "-x", "a b", "a/b", "x".repeat(33).as_str()] {
        assert!(sso::validate_portal_name(bad).is_err(), "portal name {bad:?} must be refused");
    }
    sso::validate_portal_name("client-a_2").unwrap();
}

#[test]
fn sso_session_serves_only_its_own_portal() {
    use karambit_core::sso::{Session, SsoProfile};
    let sess = |portal: &str, url: &str, region: &str| Session {
        portal: portal.into(), start_url: url.into(), region: region.into(),
        client_id: "c".into(), client_secret: "s".into(), client_expires_at: 0,
        access_token: "t".into(), access_issued_at: 0, access_expires_at: 0, refresh_token: None,
        signed_in_at: 0, renew_until: None,
    };
    let prof = |portal: &str, url: &str, region: &str| SsoProfile {
        portal: portal.into(), start_url: url.into(), sso_region: region.into(),
        account_id: "123456789012".into(), role_name: "ReadOnly".into(), region: None,
    };
    let work = sess("main", "https://acme.awsapps.com/start", "us-west-2");
    assert!(work.serves(&prof("main", "https://acme.awsapps.com/start", "us-west-2")));
    // A second org's profile is never served by the first org's session...
    assert!(!work.serves(&prof("other", "https://other.awsapps.com/start", "us-east-1")));
    // ...nor a profile that reuses the name but points elsewhere (renamed/edited config).
    assert!(!work.serves(&prof("main", "https://other.awsapps.com/start", "us-west-2")), "same name, other URL");
    assert!(!work.serves(&prof("main", "https://acme.awsapps.com/start", "us-east-1")), "same name, other region");
}

#[test]
fn sso_curl_config_quoting_cant_inject_options() {
    use karambit_core::sso::{curl_quote, pct};
    // A value with a quote + newline must stay one quoted token (no extra curl option).
    let q = curl_quote("x\"\nurl = \"https://evil");
    assert!(!q.contains('\n'), "newline escaped");
    assert_eq!(q.matches('"').count() - q.matches("\\\"").count(), 2, "only the outer quotes are bare");
    assert_eq!(pct("Read Only&x=1"), "Read%20Only%26x%3D1");
    assert_eq!(pct("123456789012"), "123456789012");
}

#[test]
fn sso_session_debug_never_prints_tokens() {
    let s = karambit_core::sso::Session {
        portal: "main".into(),
        start_url: "https://acme.awsapps.com/start".into(),
        region: "us-west-2".into(),
        client_id: "cid".into(),
        client_secret: "CLIENTSECRET".into(),
        client_expires_at: 0,
        access_token: "ACCESSTOKEN".into(),
        access_issued_at: 0,
        access_expires_at: 0,
        refresh_token: Some("REFRESHTOKEN".into()),
        signed_in_at: 0,
        renew_until: Some(0),
    };
    let d = format!("{s:?}");
    for t in ["CLIENTSECRET", "ACCESSTOKEN", "REFRESHTOKEN"] {
        assert!(!d.contains(t), "{t} leaked into Debug output");
    }
}

#[test]
fn sso_sign_in_limit_parsing_and_labels() {
    use karambit_core::sso::{limit_label, limit_secs, limit_words, parse_limit};
    for (s, want) in [("90m", 90), ("90min", 90), ("8h", 480), ("1.5h", 90), ("2d", 2880), ("8", 480), (" 12H ", 720), ("90d", 129_600), ("15m", 15)] {
        assert_eq!(parse_limit(s).unwrap(), Some(want), "{s}");
    }
    for s in ["none", "off", "NONE"] {
        assert_eq!(parse_limit(s).unwrap(), None, "{s}");
    }
    // Outside IAM Identity Center's own 15 min..90 days, or not a duration.
    for s in ["10m", "0", "0.2h", "91d", "-1h", "abc", "", "1e30h", "NaNh", "inf"] {
        assert!(parse_limit(s).is_err(), "{s:?} must be refused");
    }
    assert_eq!(limit_label(1), "1 minute");
    assert_eq!(limit_label(30), "30 minutes");
    assert_eq!(limit_label(60), "1 hour");
    assert_eq!(limit_label(90), "1 h 30 min");
    assert_eq!(limit_label(480), "8 hours");
    assert_eq!(limit_label(1440), "1 day");
    assert_eq!(limit_label(4320), "3 days");
    assert_eq!(limit_label(1500), "25 hours");
    assert_eq!(limit_words(None), "as long as AWS allows");
    assert_eq!(limit_words(Some(480)), "for up to 8 hours");
    // A hand-edited config can't turn a limit into "none" or something tiny.
    assert_eq!(limit_secs(0), 15 * 60);
    assert_eq!(limit_secs(u32::MAX), 129_600 * 60);
    assert_eq!(limit_secs(480), 8 * 3600);
}

#[test]
fn sso_renewed_tokens_dont_undo_a_tightened_limit() {
    use karambit_core::sso::Session;
    let s = |at: &str, rt: &str, until: Option<u64>| Session {
        portal: "main".into(), start_url: "https://acme.awsapps.com/start".into(), region: "us-west-2".into(),
        client_id: "c".into(), client_secret: "s".into(), client_expires_at: 0,
        access_token: at.into(), access_issued_at: 1, access_expires_at: 2, refresh_token: Some(rt.into()),
        signed_in_at: 100, renew_until: until,
    };
    // The live sign-in got a limit while a copy of it was out renewing its token.
    let mut live = s("OLD", "RT-OLD", Some(200));
    let mut renewed = s("NEW", "RT-NEW", None);
    (renewed.access_issued_at, renewed.access_expires_at) = (50, 3650);
    live.update_tokens(&renewed);
    assert_eq!((live.access_token.as_str(), live.refresh_token.as_deref()), ("NEW", Some("RT-NEW")));
    assert_eq!((live.access_issued_at, live.access_expires_at), (50, 3650));
    assert_eq!((live.signed_in_at, live.renew_until), (100, Some(200)), "limit and sign-in time stay");
}

/// Fake IAM Identity Center OIDC endpoints on loopback: register, device_authorization,
/// then `pending` "authorization_pending" polls before the token. Debug builds only.
#[cfg(debug_assertions)]
fn fake_oidc(pending: usize) -> String {
    use std::io::{BufRead, BufReader, Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut polls = 0;
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let (code, out) = match path.as_str() {
                "/client/register" => (200, r#"{"clientId":"cid","clientSecret":"csec","clientSecretExpiresAt":4102444800}"#.to_string()),
                "/device_authorization" => (200, format!(r#"{{"deviceCode":"dc","userCode":"ABCD-EFGH","verificationUriComplete":"{base_}/verify","interval":1,"expiresIn":60}}"#, base_ = "https://example.invalid")),
                "/token" if polls < pending => {
                    polls += 1;
                    (400, r#"{"error":"authorization_pending"}"#.to_string())
                }
                "/token" => (200, r#"{"accessToken":"AT","expiresIn":3600,"refreshToken":"RT"}"#.to_string()),
                _ => (404, "{}".to_string()),
            };
            let _ = write!(c, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
        }
    });
    base
}

// One test so the process-wide KARAMBIT_SSO_TEST_BASE isn't raced by parallel tests.
#[cfg(debug_assertions)]
#[test]
fn sso_login_cancel_and_commit_boundary() {
    use karambit_core::sso::{Cancelled, SignInUi, login};
    use std::cell::{Cell, RefCell};
    use std::time::Instant;
    let start = "https://acme.awsapps.com/start";

    // 1. Cancel while waiting for browser approval: stops within ~250 ms, never commits.
    // SAFETY: tests in this binary that touch this variable all run in this one test.
    unsafe { std::env::set_var("KARAMBIT_SSO_TEST_BASE", fake_oidc(1000)) };
    let shown = RefCell::new(None::<(String, String, u64)>);
    let t0 = Instant::now();
    let committed = Cell::new(false);
    let show = |c: &str, u: &str, e: u64| *shown.borrow_mut() = Some((c.into(), u.into(), e));
    let cancelled = || t0.elapsed().as_millis() > 1500;
    let commit = || {
        committed.set(true);
        true
    };
    let err = login("main", start, "us-west-2", &SignInUi { show: &show, cancelled: &cancelled, commit: &commit }).unwrap_err();
    assert!(err.is::<Cancelled>(), "want Cancelled, got {err:#}");
    assert!(!committed.get(), "a cancelled sign-in must never reach commit");
    assert!(t0.elapsed().as_millis() < 3000, "cancel should land within one poll step");
    let (code, url, exp) = shown.borrow().clone().expect("code shown before polling");
    assert_eq!((code.as_str(), exp), ("ABCD-EFGH", 60));
    assert!(url.starts_with("https://"));

    // 2. Approval arrives but the UI cancelled first: commit vetoes it, no session.
    unsafe { std::env::set_var("KARAMBIT_SSO_TEST_BASE", fake_oidc(0)) };
    let err = login("main", start, "us-west-2", &SignInUi { show: &|_, _, _| {}, cancelled: &|| false, commit: &|| false }).unwrap_err();
    assert!(err.is::<Cancelled>(), "commit=false must abort as Cancelled, got {err:#}");

    // 3. Approval after two pending polls, commit accepted: a session for this portal.
    unsafe { std::env::set_var("KARAMBIT_SSO_TEST_BASE", fake_oidc(2)) };
    let commits = Cell::new(0);
    let commit = || {
        commits.set(commits.get() + 1);
        true
    };
    let s = login("main", start, "us-west-2", &SignInUi { show: &|_, _, _| {}, cancelled: &|| false, commit: &commit }).unwrap();
    assert_eq!(commits.get(), 1, "commit is called exactly once, after approval");
    assert_eq!((s.portal.as_str(), s.start_url.as_str(), s.region.as_str()), ("main", start, "us-west-2"));
    assert!(s.refresh_token.is_some());
    unsafe { std::env::remove_var("KARAMBIT_SSO_TEST_BASE") };
}

// Frozen legacy (v1-format) fixtures: never regenerate these with later crypto/store code.
mod legacy_fixtures {
    use super::*;
    use karambit_core::store::{self, Config, KeyId, Paths, SsoPortal};
    use std::fs;

    fn paths() -> Paths {
        Paths { root: std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures") }
    }

    fn synthetic_key(key: KeyId) -> (SecretKey, Vec<u8>) {
        let keys: serde_json::Value = serde_json::from_slice(
            &fs::read(paths().root.join("SYNTHETIC-p256-keys.json")).unwrap(),
        ).unwrap();
        let bytes: Vec<u8> = serde_json::from_value(keys[key.as_str()].clone()).unwrap();
        let sk = SecretKey::from_slice(&bytes).unwrap();
        let pk = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
        (sk, pk)
    }

    fn identity() -> age::x25519::Identity {
        crypto::parse_identity(
            &fs::read_to_string(paths().root.join("SYNTHETIC-age-identity.txt")).unwrap(),
        ).unwrap()
    }

    // Each version covers both tiers and all three effective key IDs. Legacy
    // open/bio files omit key/public/backup; agent is a key ID, not a third tier.
    const CASES: [(&str, u32, Tier, KeyId, bool, bool); 6] = [
        ("v1/open", 1, Tier::Open, KeyId::Open, false, false),
        ("v1/bio", 1, Tier::Bio, KeyId::Bio, false, false),
        ("v1/agent", 1, Tier::Open, KeyId::Agent, true, false),
        ("v2/open", 2, Tier::Open, KeyId::Open, false, false),
        ("v2/bio", 2, Tier::Bio, KeyId::Bio, false, false),
        ("v2/agent", 2, Tier::Open, KeyId::Agent, true, true),
    ];

    #[test]
    #[ignore = "writes frozen synthetic fixtures; run explicitly only on the release 0.1.0 crypto/store"]
    fn generate_legacy_fixtures() {
        assert_eq!(crypto::CURRENT_V, 2);
        let p = paths();
        let age_path = p.root.join("SYNTHETIC-age-identity.txt");
        if !age_path.exists() {
            use age::secrecy::ExposeSecret;
            let id = age::x25519::Identity::generate();
            fs::write(&age_path, format!(
                "# SYNTHETIC ONLY: public test material, never use for real secrets.\n{}\n",
                id.to_string().expose_secret(),
            )).unwrap();
        }
        let recipient = identity().to_public().to_string();
        for (name, version, tier, key, agent, public) in CASES {
            let (_, pk) = synthetic_key(key);
            let backup = name == "v2/bio";
            let value = format!("SYNTHETIC pre-M1 {name} plaintext");
            let (mut f, dek) = make_p(
                name, tier, agent, public, &pk, value.as_bytes(),
                backup.then_some(recipient.as_str()),
            );
            if version == 1 {
                // crypto::aad is private. The baseline's public wrap_with_aad
                // performs all crypto with the exact historical v1 AAD spelling.
                let aad = format!("karambit/v1/dek/{}/{}/{name}", tier.as_str(), agent as u8);
                let w = crypto::wrap_with_aad(&dek, &pk, aad.as_bytes()).unwrap();
                f.v = 1;
                f.eph = w.eph;
                f.wrap_nonce = w.wrap_nonce;
                f.wrapped_dek = w.wrapped_dek;
            }
            if key == KeyId::Agent || backup {
                f.key = Some(key);
            }
            store::save_secret(&p, &f).unwrap();
            // Serialization writes defaults; remove fields genuinely absent in
            // older JSON, without changing any encrypted envelope bytes.
            let path = p.secret(name).unwrap();
            let mut json = serde_json::to_value(&f).unwrap();
            if !public { json.as_object_mut().unwrap().remove("public"); }
            if !backup { json.as_object_mut().unwrap().remove("backup"); }
            store::write_atomic(&path, &serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        }
        let mut config = Config { backup_recipient: Some(recipient), ..Config::default() };
        for (name, limit_minutes) in [("synthetic-limited", Some(45)), ("synthetic-unlimited", None)] {
            config.sso_portals.insert(name.into(), SsoPortal {
                start_url: format!("https://{name}.invalid/start"),
                region: "us-east-1".into(),
                limit_minutes,
                accounts: Default::default(),
            });
        }
        store::save_config(&p, &config).unwrap();
        let minimal = Paths { root: p.root.join("minimal") };
        store::save_config(&minimal, &Config::default()).unwrap();
        let mut json = serde_json::to_value(Config::default()).unwrap();
        for field in ["backup_recipient", "human_lease_hours", "sso_portals", "sources"] {
            json.as_object_mut().unwrap().remove(field);
        }
        store::write_atomic(&minimal.config(), &serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    }

    fn check_fixture(index: usize) {
        let (name, version, tier, key, agent, public) = CASES[index];
        let p = paths(); // Explicit root: no HOME/KARAMBIT_DIR or helper access.
        let config = store::load_config(&p).unwrap();
        assert_eq!(config.backup_recipient.as_deref(), Some(identity().to_public().to_string().as_str()));
        let f = store::load_secret(&p, name).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(p.secret(name).unwrap()).unwrap()).unwrap();
        if !public { assert!(raw.get("public").is_none()); }
        if name != "v2/bio" { assert!(raw.get("backup").is_none()); }
        if key != KeyId::Agent && name != "v2/bio" {
            assert!(raw.get("key").is_none());
            assert!(f.key.is_none());
        } else {
            assert_eq!(f.key, Some(key));
        }
        assert_eq!(f.v, version);
        assert_eq!(f.tier, tier);
        assert_eq!(f.key_id().unwrap(), key);
        assert_eq!(f.agent_allowed, agent);
        assert_eq!(f.is_public(), public);
        let (sk, pk) = synthetic_key(key);
        let dek = crypto::unwrap_dek(&f, &shared_for(&sk, &f), &pk).unwrap();
        let expected = format!("SYNTHETIC pre-M1 {name} plaintext");
        assert_eq!(&**crypto::open(&dek, &f).unwrap(), expected.as_bytes());
        if name == "v2/bio" {
            let recovered = crypto::backup_unwrap(f.backup.as_ref().unwrap(), &identity()).unwrap();
            assert_eq!(&**crypto::open(&recovered, &f).unwrap(), expected.as_bytes());
        } else {
            assert!(f.backup.is_none());
        }
    }

    #[test] fn v1_open() { check_fixture(0); }
    #[test] fn v1_bio() { check_fixture(1); }
    #[test] fn v1_agent() { check_fixture(2); }
    #[test] fn v2_open() { check_fixture(3); }
    #[test] fn v2_bio_with_age_backup() { check_fixture(4); }
    #[test] fn v2_agent_public() { check_fixture(5); }

    #[test]
    fn config_with_optional_fields() {
        assert!(paths().config().is_file(), "missing frozen config fixture");
        let c = store::load_config(&paths()).unwrap();
        assert_eq!(c.default_tier, Tier::Bio);
        assert_eq!(c.clip_seconds, 30);
        assert_eq!(c.human_lease_hours, 3.0);
        assert_eq!(c.backup_recipient, Some(identity().to_public().to_string()));
        assert_eq!(c.sso_portals.len(), 2);
        for (name, limit) in [("synthetic-limited", Some(45)), ("synthetic-unlimited", None)] {
            let portal = &c.sso_portals[name];
            assert_eq!(portal.start_url, format!("https://{name}.invalid/start"));
            assert_eq!(portal.region, "us-east-1");
            assert_eq!(portal.limit_minutes, limit);
        }
        assert!(c.agent_process_names.contains(&"pi".into()));
        assert!(c.agent_env_markers.contains(&"PI_CODING_AGENT".into()));
    }

    #[test]
    fn config_without_optional_fields() {
        let p = Paths { root: paths().root.join("minimal") };
        // load_config silently defaults on ENOENT; a missing fixture must fail.
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(p.config()).unwrap()).unwrap();
        for field in ["backup_recipient", "human_lease_hours", "sso_portals", "sources"] {
            assert!(raw.get(field).is_none());
        }
        let c = store::load_config(&p).unwrap();
        assert_eq!(c.default_tier, Tier::Bio);
        assert_eq!(c.clip_seconds, 30);
        assert_eq!(c.human_lease_hours, 3.0);
        assert!(c.backup_recipient.is_none());
        assert!(c.sso_portals.is_empty());
        assert!(c.sources.is_empty());
        assert!(c.agent_process_names.contains(&"pi".into()));
        assert!(c.agent_env_markers.contains(&"PI_CODING_AGENT".into()));
    }

    #[test]
    fn flipped_fixture_ct_byte_fails_decryption() {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        let mut f = store::load_secret(&paths(), "v2/bio").unwrap();
        let (sk, pk) = synthetic_key(KeyId::Bio);
        let dek = crypto::unwrap_dek(&f, &shared_for(&sk, &f), &pk).unwrap();
        let mut ct = B64.decode(&f.ct).unwrap();
        ct[0] ^= 1;
        f.ct = B64.encode(ct);
        assert!(crypto::open(&dek, &f).is_err());
    }
}

/// One isolated smoke. The child mode is a software-P256 helper, never the installed helper.
#[cfg(debug_assertions)]
#[test]
fn audit_ordering_smoke() {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    use karambit_core::{Karambit, agent::Caller, audit, store};
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    if let Ok(args) = std::env::var("AUDIT_SOFTWARE_HELPER_ARGS") {
        let args: Vec<&str> = args.split_whitespace().collect();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = sk.public_key().to_encoded_point(false);
        let result = match args[0] {
            "keygen" => {
                let dir = std::path::Path::new(args[2]);
                std::fs::create_dir_all(dir).unwrap();
                for k in ["bio.key", "open.key", "agent.key"] {
                    std::fs::write(dir.join(k), b"synthetic marker, not an SE key").unwrap();
                }
                json!({"bio": B64.encode(pk.as_bytes()), "open": B64.encode(pk.as_bytes()), "agent": B64.encode(pk.as_bytes())})
            }
            "ecdh" => {
                let v: Value = serde_json::from_reader(std::io::stdin()).unwrap();
                let shared: Vec<String> = v["requests"].as_array().unwrap().iter().map(|r| {
                    let eph = PublicKey::from_sec1_bytes(&B64.decode(r["eph"].as_str().unwrap()).unwrap()).unwrap();
                    B64.encode(diffie_hellman(sk.to_nonzero_scalar(), eph.as_affine()).raw_secret_bytes())
                }).collect();
                json!({"shared": shared})
            }
            "addkey" => {
                std::fs::write(std::path::Path::new(args[2]).join("agent.key"), b"synthetic marker, not an SE key").unwrap();
                json!({"agent": B64.encode(pk.as_bytes())})
            }
            "clip" => {
                use std::io::Read;
                let mut value = zeroize::Zeroizing::new(Vec::new());
                std::io::stdin().read_to_end(&mut value).unwrap();
                // No pasteboard access: record only byte count and requested duration.
                let secs = args[2].parse::<u32>().unwrap();
                let paths = store::Paths::resolve().unwrap();
                std::fs::write(paths.root.join("clip-record"), format!("bytes={} seconds={secs}", value.len())).unwrap();
                json!({"ok": true, "clear_after": secs})
            }
            "auth" => json!({"ok": true}),
            "selftest" => json!({"synthetic": true}),
            "pubkeys" => json!({"bio": B64.encode(pk.as_bytes()), "open": B64.encode(pk.as_bytes()), "agent": B64.encode(pk.as_bytes())}),
            verb => panic!("unexpected software helper verb: {verb}"),
        };
        println!("AUDIT_HELPER_JSON={result}");
        return;
    }
    if std::env::var_os("AUDIT_SMOKE_CHILD").is_none() {
        // init is human-only; run the body with agent-free kernel ancestry.
        let (ok, out) = run_detached_test("audit_ordering_smoke", "AUDIT_SMOKE_CHILD", &[]);
        assert!(ok, "detached audit smoke failed:\n{out}");
        return;
    }
    let root = std::env::temp_dir().join(format!("karambit-audit-smoke-{}-{}", std::process::id(), store::now()));
    let home = root.join("home");
    let bin = root.join("bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    // Copy only the test binary to an empty directory. No installed binaries or keys.
    let exe = bin.join("software-test");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let helper = bin.join("helper");
    std::fs::write(&helper, format!("#!/bin/sh\nAUDIT_SOFTWARE_HELPER_ARGS=\"$*\" '{}' --exact audit_ordering_smoke --nocapture | /usr/bin/sed -n 's/^AUDIT_HELPER_JSON=//p'\n", exe.display())).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Only this test uses these variables; other tests use explicit fixture paths.
    let vault = root.join("vault");
    let vars = [("HOME", home.as_os_str()), ("KARAMBIT_DIR", vault.as_os_str())];
    let saved: Vec<_> = vars.iter().map(|(k, _)| (*k, std::env::var_os(k))).collect();
    for (k, value) in vars { unsafe { std::env::set_var(k, value) }; }
    unsafe {
        std::env::set_var("KARAMBIT_DEV", "1");
        std::env::set_var("KARAMBIT_SE_HELPER", &helper);
    }
    let mut v = Karambit::open_with(Caller::default()).unwrap();
    v.cfg.human_lease_hours = 0.0;
    let (_, recipient) = crypto::generate_backup_identity();
    start_synthetic_daemon(&v.paths);
    v.init(Some(recipient)).unwrap();
    assert_eq!(std::fs::read_to_string(v.paths.keys().join("helper.sha256")).unwrap(),
        format!("{}\n", karambit_core::helper::sha256_file(&helper).unwrap()));
    let serving_exe = std::fs::canonicalize(karambit_core::agent::proc_exe(std::process::id() as i32).unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(v.paths.keys().join("daemon.sha256")).unwrap(),
        format!("{}\n", karambit_core::helper::sha256_file(&serving_exe).unwrap()));
    // Semantic mutations use the real peer, not open_with's fixture Caller.
    v.cfg.removed_defaults = v.cfg.agent_process_names.iter().chain(&v.cfg.agent_env_markers).cloned().collect();
    v.cfg.agent_process_names.clear();
    v.cfg.agent_env_markers.clear();
    store::save_config(&v.paths, &v.cfg).unwrap();
    assert_eq!(v.status().unwrap()["helper"]["synthetic"], true);
    // Force the semantic bootstrap-capable public-key fallback.
    std::fs::remove_file(v.paths.pubkeys()).unwrap();
    // A legacy event mixed with new phases must still verify.
    audit::log(&v.paths, audit::Event { action: "legacy", secrets: &[], caller: &v.caller, detail: json!({}), result: &Ok(()) }).unwrap();
    v.add("synthetic/value", b"audit synthetic canary", Some(Tier::Open), true, false, false).unwrap();
    let values = v.unlock("run", &["synthetic/value".into()], None, false).unwrap();
    assert_eq!(values[0].value.as_slice(), b"audit synthetic canary");
    let copied = v.copy("synthetic/value").unwrap();
    assert_eq!(copied.copied, ["synthetic/value"]);
    assert_eq!(copied.clears_in, v.cfg.clip_seconds);
    assert_eq!(std::fs::read_to_string(v.paths.root.join("clip-record")).unwrap(), format!("bytes=22 seconds={}", v.cfg.clip_seconds));
    let (_, recipient) = crypto::generate_backup_identity();
    assert_eq!(v.rotate_backup(&recipient).unwrap(), 1);
    assert_eq!(store::load_config(&v.paths).unwrap().backup_recipient.as_deref(), Some(recipient.as_str()));
    let activity = v.secret_activity("synthetic/value", usize::MAX).unwrap();
    let rotation: Vec<_> = activity.iter().filter(|e| e["action"] == "backup-rotate-operation").collect();
    assert_eq!(rotation.len(), 2);
    assert_eq!(rotation[0]["phase"], "intent");
    assert_eq!(rotation[1]["phase"], "outcome");
    let events = v.audit_log(usize::MAX).unwrap();
    for (i, ev) in events.iter().enumerate().filter(|(_, e)| e["phase"] == "intent") {
        assert!(events[i + 1..].iter().any(|e| e["phase"] == "outcome" && e["intent"] == ev["id"]));
    }
    for action in ["init-operation", "add", "run", "backup-rotate-operation"] {
        assert!(events.iter().any(|e| e["action"] == action && e["phase"] == "intent"));
    }
    assert_eq!(events.last().unwrap()["action"], "daemon-backup-rotate");
    assert_eq!(v.audit_verify().unwrap(), (events.len(), None));
    for (key, old) in saved {
        unsafe { match old { Some(value) => std::env::set_var(key, value), None => std::env::remove_var(key) } }
    }
    unsafe { std::env::remove_var("KARAMBIT_DEV"); std::env::remove_var("KARAMBIT_SE_HELPER"); }
    std::fs::remove_dir_all(root).unwrap();
}

/// Default merge, Hermes defaults, opt-out, and the "unknown agent" audit label.
mod agent_defaults {
    use karambit_core::agent::Caller;
    use karambit_core::audit::{self, Event};
    use karambit_core::store::{self, Config, Paths};
    use serde_json::json;
    use std::fs;

    fn temp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("karambit-agentcfg-{tag}-{}-{}", std::process::id(), store::now()));
        fs::create_dir_all(&root).unwrap();
        Paths { root }
    }

    fn load_json(tag: &str, text: &str) -> (Paths, Config) {
        let p = temp_paths(tag);
        fs::write(p.config(), text).unwrap();
        let c = store::load_config(&p).unwrap();
        (p, c)
    }

    /// Older config: pinned lists from before Hermes was a default.
    const STALE: &str = r#"{"default_tier":"bio","backup_recipient":null,"clip_seconds":30,
      "agent_process_names":["pi","claude","my-custom-agent"],
      "agent_env_markers":["PI_CODING_AGENT"],"human_lease_hours":3.0}"#;

    #[test]
    fn default_config_includes_hermes() {
        let c = Config::default();
        for n in ["hermes", "hermes-agent", "hermes-acp"] {
            assert!(c.agent_process_names.contains(&n.to_string()), "{n}");
        }
        assert!(c.removed_defaults.is_empty());
    }

    #[test]
    fn stale_pinned_config_gains_hermes_and_keeps_custom_entries() {
        let (p, c) = load_json("stale", STALE);
        for n in ["hermes", "hermes-agent", "hermes-acp", "codex"] {
            assert!(c.agent_process_names.contains(&n.to_string()), "{n}");
        }
        assert_eq!(&c.agent_process_names[..3], ["pi", "claude", "my-custom-agent"], "order and custom entries kept");
        assert!(c.agent_env_markers.contains(&"CLAUDECODE".to_string()));
        // No duplicates on repeated merge, and the merged list persists on the next save.
        let mut again = c.clone();
        again.merge_defaults();
        assert_eq!(again.agent_process_names, c.agent_process_names);
        store::save_config(&p, &c).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(p.config()).unwrap()).unwrap();
        assert!(raw["agent_process_names"].as_array().unwrap().contains(&json!("hermes")));
        assert!(raw.get("removed_defaults").is_none(), "empty opt-out list is not serialized");
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn removed_defaults_opts_out_and_survives_roundtrip() {
        let text = STALE.replace("\"clip_seconds\":30,", "\"clip_seconds\":30,\"removed_defaults\":[\"Hermes\",\"hermes-acp\",\"CLAUDECODE\"],");
        let (p, c) = load_json("optout", &text);
        assert!(!c.agent_process_names.iter().any(|n| n.eq_ignore_ascii_case("hermes") || n == "hermes-acp"));
        assert!(c.agent_process_names.contains(&"hermes-agent".to_string()), "only the listed defaults are opted out");
        assert!(!c.agent_env_markers.contains(&"CLAUDECODE".to_string()));
        assert!(c.agent_env_markers.contains(&"CODEX_SANDBOX".to_string()));
        store::save_config(&p, &c).unwrap();
        let c2 = store::load_config(&p).unwrap();
        assert_eq!(c2.removed_defaults, c.removed_defaults);
        assert_eq!(c2.agent_process_names, c.agent_process_names);
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn removed_default_wins_over_pinned_entry_and_markers_merge_exact_case() {
        // Opt-out filters an already-pinned built-in (any case), keeps custom entries.
        let (p, c) = load_json("optout-pinned", r#"{"default_tier":"bio","clip_seconds":30,"agent_process_names":["Claude","my-bot","pi"],"agent_env_markers":["CLAUDECODE","claudecode","MY_MARK"],"removed_defaults":["claude","CLAUDECODE"]}"#);
        assert!(!c.agent_process_names.iter().any(|n| n.eq_ignore_ascii_case("claude")));
        assert!(c.agent_process_names.contains(&"my-bot".to_string()) && c.agent_process_names.contains(&"pi".to_string()));
        assert!(!c.agent_env_markers.contains(&"CLAUDECODE".to_string()));
        assert!(c.agent_env_markers.contains(&"claudecode".to_string()) && c.agent_env_markers.contains(&"MY_MARK".to_string()), "non-default (custom-case) markers stay");
        fs::remove_dir_all(p.root).unwrap();
        // A lowercase custom marker must not suppress the canonical built-in.
        let (p, c) = load_json("marker-case", r#"{"default_tier":"bio","clip_seconds":30,"agent_process_names":[],"agent_env_markers":["claudecode"]}"#);
        assert!(c.agent_env_markers.contains(&"CLAUDECODE".to_string()));
        assert!(c.agent_env_markers.contains(&"claudecode".to_string()));
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn blank_lists_do_not_disable_detection() {
        let (p, c) = load_json("blank", r#"{"default_tier":"bio","clip_seconds":30,"agent_process_names":[],"agent_env_markers":[]}"#);
        assert!(c.agent_process_names.contains(&"hermes".to_string()));
        assert!(c.agent_process_names.contains(&"pi".to_string()));
        assert!(c.agent_env_markers.contains(&"PI_CODING_AGENT".to_string()));
        fs::remove_dir_all(p.root).unwrap();
    }

    #[test]
    fn old_fixtures_still_load_and_gain_hermes() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for root in [dir.clone(), dir.join("minimal")] {
            let c = store::load_config(&Paths { root: root.clone() }).unwrap();
            assert!(c.agent_process_names.contains(&"hermes".to_string()), "{root:?}");
            assert!(c.removed_defaults.is_empty());
            let raw = fs::read_to_string(root.join("config.json")).unwrap();
            assert!(!raw.contains("removed_defaults") && !raw.contains("hermes"), "fixture must stay frozen");
        }
    }

    #[test]
    fn audit_labels_suspect_callers_only() {
        let p = temp_paths("audit");
        let suspect = Caller { chain: vec!["bash".into(), "python3".into()], suspect: true, ..Default::default() };
        let plain = Caller { chain: vec!["zsh".into(), "ghostty".into()], ..Default::default() };
        for c in [&suspect, &plain] {
            audit::log(&p, Event { action: "probe", secrets: &[], caller: c, detail: json!({}), result: &Ok(()) }).unwrap();
        }
        let events = audit::read(&p, 10).unwrap();
        assert_eq!(events[0]["suspect"], true);
        assert_eq!(events[0]["label"], "unknown agent");
        assert!(events[0]["agent"].is_null(), "suspect does not make an agent");
        assert!(events[1].get("suspect").is_none() && events[1].get("label").is_none());
        assert_eq!(audit::verify(&p).unwrap(), (2, None));
        let unknown = Caller { env_unknown: true, ..Default::default() };
        audit::log(&p, Event { action: "probe", secrets: &[], caller: &unknown, detail: json!({}), result: &Ok(()) }).unwrap();
        let events = audit::read(&p, 10).unwrap();
        assert_eq!(events[2]["env_unknown"], true);
        assert_eq!(events[2]["label"], "env unavailable");
        assert!(events[1].get("env_unknown").is_none());
        assert_eq!(audit::verify(&p).unwrap(), (3, None), "old entries without env_unknown still verify");
        fs::remove_dir_all(p.root).unwrap();
    }
}

/// Approved Open operations with actual software ECDH, in a scrubbed child.
#[cfg(debug_assertions)]
#[test]
fn human_proof_open_operations_smoke() {
    use karambit_core::{Karambit, agent::Caller, store};
    use std::{fs, os::unix::fs::PermissionsExt};
    if std::env::var_os("KARAMBIT_TEST_PROOF_CHILD").is_some() {
        let mut v = Karambit::open_with(Caller::default()).unwrap();
        start_synthetic_daemon(&v.paths);
        v.init(None).unwrap();
        // Explicit synthetic human fixture: the real parent may be an agent.
        v.cfg.removed_defaults = v.cfg.agent_process_names.iter().chain(&v.cfg.agent_env_markers).cloned().collect();
        v.cfg.agent_process_names.clear();
        v.cfg.agent_env_markers.clear();
        store::save_config(&v.paths, &v.cfg).unwrap();
        v.add("test/open", b"synthetic proof smoke", Some(Tier::Open), true, false, false).unwrap();
        let sk = SecretKey::from_slice(&[7; 32]).unwrap();
        let pk = sk.public_key().to_encoded_point(false);
        let (legacy, _) = make("test/legacy", Tier::Open, false, pk.as_bytes(), b"synthetic legacy smoke", None);
        store::save_secret(&v.paths, &legacy).unwrap();
        let values = v.unlock("run", &["test/legacy".into()], None, false).unwrap();
        assert_eq!(values[0].value.as_slice(), b"synthetic legacy smoke");
        let (_, recipient) = crypto::generate_backup_identity();
        assert_eq!(v.rotate_backup(&recipient).unwrap(), 2);
        v.sso_portal_add("main", "https://example.awsapps.com/start", "us-east-1").unwrap();
        v.sso_portal_add("main", "https://example.awsapps.com/start", "us-west-2").unwrap();
        v.sso_portal_add("main", "https://example.awsapps.com/start", "us-west-2").unwrap();
        let log = fs::read_to_string(v.paths.root.join("helper-calls")).unwrap();
        assert_eq!(log.lines().filter(|l| l.starts_with("auth ")).count(), 5, "add, legacy access, rotation, first portal, repoint; no-op adds none");
        assert!(v.audit_verify().unwrap().1.is_none());
        return;
    }
    let root = std::env::temp_dir().join(format!("karambit-proof-smoke-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for d in ["bin", "home", "vault", "stub"] { fs::create_dir_all(root.join(d)).unwrap(); }
    let exe = root.join("bin/test");
    fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let helper = root.join("stub/helper");
    fs::write(&helper, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$KARAMBIT_DIR/helper-calls\"\nAUDIT_SOFTWARE_HELPER_ARGS=\"$*\" '{}' --exact audit_ordering_smoke --nocapture | /usr/bin/sed -n 's/^AUDIT_HELPER_JSON=//p'\n", exe.display())).unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    // init is human-only; the scrubbed child is also detached from agent ancestry.
    let (home, vault) = (root.join("home"), root.join("vault"));
    let (ok, out) = run_detached_test("human_proof_open_operations_smoke", "KARAMBIT_TEST_PROOF_CHILD", &[
        ("HOME", home.as_os_str()), ("KARAMBIT_DIR", vault.as_os_str()),
        ("KARAMBIT_DEV", std::ffi::OsStr::new("1")), ("KARAMBIT_SE_HELPER", helper.as_os_str()),
    ]);
    assert!(ok, "isolated proof smoke failed: {out}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn semantic_lease_requests_carry_no_client_proof_or_attribution() {
    use karambit_core::{daemon::{Req, Scope}, lease::Grantee};
    let grant = serde_json::to_value(Req::GrantLease {
        names: vec!["test/secret".into()], grantee: Grantee::Any, hours: 1.0, scope: Scope::default(),
    }).unwrap();
    for forbidden in ["dek", "by", "root", "expires", "authenticated"] {
        assert!(grant.get(forbidden).is_none());
    }
    let unlock = serde_json::to_value(Req::HumanUnlock { names: vec!["test/secret".into()] }).unwrap();
    assert!(unlock.get("anchor").is_none(), "anchor must come from the kernel, not the wire");
    assert!(unlock.get("dek").is_none());
}

#[test]
fn recovery_retirement_preserves_helper_pin() {
    use std::fs;
    use karambit_core::{Karambit, agent::Caller, helper, store::{self, Paths}};
    use std::os::unix::fs::PermissionsExt;
    if std::env::var_os("KARAMBIT_SYNTHETIC_RETIRE_CHILD").is_some() {
        let paths = Paths::resolve().unwrap();
        store::ensure_dir(&paths.keys()).unwrap();
        for key in ["bio.key", "open.key"] { fs::write(paths.keys().join(key), b"synthetic marker").unwrap(); }
        let mut cfg = karambit_core::Config::default();
            cfg.removed_defaults = cfg.agent_process_names.iter().chain(&cfg.agent_env_markers).cloned().collect();
            cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
            store::save_config(&paths, &cfg).unwrap();
        let helper_path = std::env::current_exe().unwrap().parent().unwrap().join(helper::HELPER_NAME);
        fs::write(&helper_path, b"#!/bin/sh\n[ \"$1\" = auth ] || exit 1\nprintf '{\"ok\":true}\\n'\n").unwrap();
        fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = format!("{}\n", helper::sha256_file(&helper_path).unwrap());
        fs::write(paths.keys().join("helper.sha256"), &pin).unwrap();
        let v = Karambit::open_with(Caller::default()).unwrap();
        if !karambit_core::daemon::sock_path(&paths).exists() { start_synthetic_daemon(&paths); }
        let retired = v.retire_keys().unwrap();
        assert_eq!(fs::read_to_string(retired.join("helper.sha256")).unwrap(), pin);
        assert_eq!(fs::read_to_string(paths.keys().join("helper.sha256")).unwrap(), pin);
        fs::write(&helper_path, b"#!/bin/sh\nprintf '{\"error\":\"replacement must never execute\"}\\n'\n").unwrap();
        let error = karambit_core::daemon::request(&paths, &karambit_core::daemon::Req::Init { backup_recipient: None })
            .expect_err("replacement must be refused");
        assert!(error.to_string().contains("doesn't match the pinned helper"));
        return;
    }
    let root = std::env::temp_dir().join(format!("karambit-retire-smoke-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for dir in ["bin", "home", "vault"] { fs::create_dir_all(root.join(dir)).unwrap(); }
    let binary = root.join("bin/software-test");
    fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let result = std::process::Command::new(binary)
        .args(["--exact", "recovery_retirement_preserves_helper_pin", "--nocapture"])
        .env_clear().env("PATH", "/usr/bin:/bin").env("HOME", root.join("home"))
        .env("KARAMBIT_DIR", root.join("vault")).env("KARAMBIT_SYNTHETIC_RETIRE_CHILD", "1")
        .output().unwrap();
    assert!(result.status.success(), "synthetic child failed: {}", String::from_utf8_lossy(&result.stderr));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn relative_home_cannot_forge_biometrics_unavailable() {
    use karambit_core::{Karambit, agent::Caller, helper, store::{self, Paths}};
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    if std::env::var_os("KARAMBIT_TEST_FORGED_CHILD").is_some() {
        let paths = Paths::resolve().unwrap();
        let candidate = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(".local/bin").join(helper::HELPER_NAME);
        fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        fs::write(&candidate, b"#!/bin/sh\ntouch executed\nprintf '{\"error\":\"biometrics unavailable: forged\"}\\n'\n").unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        let (identity, recipient) = crypto::generate_backup_identity();
        let (_, pk) = soft_key();
        let (secret, _) = make("test/paper", Tier::Bio, false, &pk, b"synthetic fixture", Some(&recipient));
        let mut failures = Vec::new();
        for recover in [false, true] {
            if paths.root.exists() { fs::remove_dir_all(&paths.root).unwrap(); }
            store::ensure_dir(&paths.keys()).unwrap();
            for key in ["bio.key", "open.key"] { fs::write(paths.keys().join(key), b"synthetic key marker").unwrap(); }
            fs::write(paths.keys().join("helper.sha256"), b"original trusted pin\n").unwrap();
            let mut cfg = karambit_core::Config::default();
            cfg.removed_defaults = cfg.agent_process_names.iter().chain(&cfg.agent_env_markers).cloned().collect();
            cfg.agent_process_names.clear(); cfg.agent_env_markers.clear();
            store::save_config(&paths, &cfg).unwrap();
            store::save_secret(&paths, &secret).unwrap();
            let v = Karambit::open_with(Caller::default()).unwrap();
            if !karambit_core::daemon::sock_path(&paths).exists() { start_synthetic_daemon(&paths); }
            let refused = if recover { v.recover_from_paper(&identity, &[]).is_err() }
                else { v.retire_keys_with_paper(&identity).is_err() };
            let unchanged = ["bio.key", "open.key"].iter().all(|k| fs::read(paths.keys().join(k)).ok().as_deref() == Some(b"synthetic key marker"))
                && fs::read(paths.keys().join("helper.sha256")).unwrap() == b"original trusted pin\n"
                && !fs::read_dir(&paths.root).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("keys.retired-"));
            if !refused || !unchanged { failures.push(format!("recover={recover}: refused={refused}, keys unchanged={unchanged}")); }
            assert!(!std::path::Path::new("executed").exists());
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
        // The identical message from an actually pinned auth responder does
        // qualify: exercise JSON classification, not a Rust-side test error.
        fs::write(paths.keys().join("helper.sha256"), format!("{}\n", helper::sha256_file(&candidate).unwrap())).unwrap();
        let v = Karambit::open_with(Caller::default()).unwrap();
        if !karambit_core::daemon::sock_path(&paths).exists() { start_synthetic_daemon(&paths); }
        v.retire_keys_with_paper(&identity).unwrap();
        assert!(std::path::Path::new("executed").exists());
        assert!(!paths.initialized());
        return;
    }
    let root = std::env::temp_dir().join(format!("karambit-forged-home-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("bin")).unwrap();
    let binary = root.join("bin/test");
    fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let out = Command::new(binary).args(["--exact", "relative_home_cannot_forge_biometrics_unavailable", "--nocapture"])
        .env_clear().env("PATH", "/usr/bin:/bin").env("HOME", "biometrics unavailable:synthetic")
        .env("KARAMBIT_DIR", root.join("vault")).env("KARAMBIT_TEST_FORGED_CHILD", "1")
        .current_dir(&root).output().unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(out.status.success(), "{} {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// Integration crates are not cfg(test) in the core dependency. Start the server
/// explicitly on the synthetic socket, never via current_exe/installed fallback.
/// Run one test of this binary as an orphan reparented to launchd, with a scrubbed
/// environment, so the kernel-observed caller ancestry contains no agent (the parent
/// test may itself run under one). The capability fence blocks init and other human-only verbs on that
/// ancestry; this keeps synthetic human fixtures genuine instead of weakening the fence.
#[cfg(debug_assertions)]
fn run_detached_test(name: &str, marker: &str, envs: &[(&str, &std::ffi::OsStr)]) -> (bool, String) {
    use std::{fs, process::Command, time::{Duration, Instant}};
    let dir = std::env::temp_dir().join(format!("karambit-detached-{name}-{}-{}", std::process::id(), karambit_core::store::now()));
    fs::create_dir_all(&dir).unwrap();
    let exe = std::env::current_exe().unwrap();
    let (out, rc, go) = (dir.join("out"), dir.join("rc"), dir.join("go"));
    // The shell backgrounds the test and exits at once. The background subshell waits
    // (bounded) for `go`, written only after the launching shell has been reaped, so
    // the test starts already reparented to pid 1 with no agent in its ancestry.
    let script = r#"( i=0; while [ ! -e "$4" ]; do i=$((i+1)); [ $i -gt 1000 ] && { echo 125 > "$3"; exit; }; sleep 0.01; done
        "$0" --exact "$1" --nocapture > "$2" 2>&1; echo $? > "$3.tmp"; mv "$3.tmp" "$3" ) </dev/null >/dev/null 2>&1 &"#;
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script).arg(&exe).arg(name).arg(&out).arg(&rc).arg(&go)
        .env_clear().env("PATH", "/usr/bin:/bin").env(marker, "1");
    for (k, v) in envs { cmd.env(k, v); }
    assert!(cmd.status().unwrap().success());
    fs::write(&go, b"").unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while !rc.exists() { assert!(Instant::now() < deadline, "detached {name} timed out"); std::thread::sleep(Duration::from_millis(20)); }
    let ok = fs::read_to_string(&rc).unwrap().trim() == "0";
    let text = fs::read_to_string(&out).unwrap_or_default();
    fs::remove_dir_all(&dir).unwrap();
    (ok, text)
}

fn start_synthetic_daemon(p: &karambit_core::Paths) {
    // The "daemon" is this test binary; an initialized vault refuses a daemon without a pin.
    if !p.keys().join("daemon.sha256").exists() {
        std::fs::create_dir_all(p.keys()).unwrap();
        let hash = karambit_core::helper::sha256_file(&std::env::current_exe().unwrap()).unwrap();
        std::fs::write(p.keys().join("daemon.sha256"), format!("{hash}\n")).unwrap();
    }
    let paths = p.clone();
    std::thread::spawn(move || karambit_core::daemon::serve(paths).unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::os::unix::net::UnixStream::connect(karambit_core::daemon::sock_path(p)).is_err() {
        assert!(std::time::Instant::now() < deadline, "synthetic daemon did not start");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn paired_pin_bootstrap_refuses_outside_daemon_dispatch() {
    // Integration tests link the library without cfg(test), so the real
    // capability check applies: a library caller must create neither pin.
    let root = std::env::temp_dir().join(format!("karambit-pin-outside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let pf = keys.join("helper.sha256");
    let err = karambit_core::helper::bootstrap_outside_dispatch_for_tests(&pf).unwrap_err();
    assert!(err.to_string().contains("daemon dispatch"), "{err:#}");
    assert!(!pf.exists(), "helper pin must not be created");
    assert!(!keys.join("daemon.sha256").exists(), "daemon pin must not be created");
    std::fs::remove_dir_all(&root).unwrap();
}
