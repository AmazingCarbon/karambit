//! Value-free, offline policy diagnostics. Results never confer authorization.
use super::{Action, Effect, Policy, Subject};
use crate::agent::Caller;
use anyhow::{Result, bail};
use serde::Deserialize;

/// Policy from a JSON file instead of the vault: a full config.json (its `policy`
/// section) or a bare `{rules,tags}` object. Never reads the vault, daemon or keys,
/// so it works in CI. A file with neither shape is an error, not an empty policy:
/// a wrong file must not look like a green check.
pub fn policy_from_file(text: &str) -> Result<Policy> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| anyhow::anyhow!("policy file is not valid JSON"))?;
    let Some(object) = value.as_object() else { bail!("policy file must be a JSON object"); };
    let section = if let Some(section) = object.get("policy") {
        section.clone()
    } else if object.contains_key("rules") || object.contains_key("tags") {
        value.clone()
    } else if ["default_tier", "clip_seconds", "agent_process_names"].iter().any(|k| object.contains_key(*k)) {
        // A real config.json that simply has no policy section.
        return Ok(Policy::default());
    } else {
        bail!("no policy found: expected a config.json with a \"policy\" section or an object with \"rules\"/\"tags\"");
    };
    if section.is_null() { return Ok(Policy::default()); }
    serde_json::from_value(section).map_err(|e| anyhow::anyhow!("invalid policy: {e}"))
}

/// SHA-256 of the policy's canonical JSON. An absent policy hashes like an empty one,
/// since both mean "no rules".
pub fn policy_sha256(policy: &Policy) -> String {
    crate::sso::sha256_hex(&serde_json::to_vec(policy).expect("policy serializes"))
}

/// Compare the on-disk policy with the hash a running daemon reported (`Ping`/`status`).
/// Fails when the daemon is an older build that reports none: ui-v1 does not enforce
/// the policy section, so a green `policy test` would say nothing about it.
pub fn check_live(disk: &Policy, daemon_reply: &serde_json::Value) -> Result<serde_json::Value> {
    let Some(reported) = daemon_reply.get("policy_sha256").and_then(|h| h.as_str()) else {
        bail!("the running daemon is an older build that does not report its policy hash (ui-v1 does not enforce the policy section); restart the daemon from a current build");
    };
    let on_disk = policy_sha256(disk);
    if reported != on_disk {
        bail!("policy on disk ({on_disk}) differs from the running daemon's ({reported}); the daemon is not enforcing this policy");
    }
    Ok(serde_json::json!({"policy_sha256": on_disk, "daemon_build_id": daemon_reply.get("build_id")}))
}

pub fn caller(as_who: Option<&str>) -> Result<Caller> {
    match as_who {
        None => Ok(Caller::default()),
        Some(s) => {
            let kind = s.strip_prefix("agent:").filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            let Some(kind) = kind else { bail!("expected --as agent:KIND"); };
            Ok(Caller { agent: Some("simulation".into()), kind: Some(kind.into()), ..Default::default() })
        }
    }
}

pub fn action(text: &str) -> Result<Action> {
    serde_json::from_value(serde_json::Value::String(text.into())).map_err(|_| anyhow::anyhow!("invalid policy action"))
}

pub fn subject(action: Action, name: &str) -> Subject {
    match action {
        Action::Call => Subject::Tool(name.into()),
        Action::Egress => Subject::Egress(name.into()),
        _ => Subject::Secret(name.into()),
    }
}

pub fn explain(policy: &Policy, action: Action, subject: &Subject, caller: &Caller) -> serde_json::Value {
    let d = super::evaluate(policy, caller, action, subject);
    serde_json::json!({"effect": d.effect, "reason_code": d.reason, "rule_index": d.rule_index,
        "simulation_only": true, "base_authorization_required": true})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    action: Action,
    subject: String,
    #[serde(default, rename = "as")]
    as_who: Option<String>,
    expected: Effect,
}

/// JSON array of cases; errors deliberately exclude input strings/values.
pub fn test_cases(policy: &Policy, text: &str) -> Result<usize> {
    let cases: Vec<Case> = serde_json::from_str(text).map_err(|_| anyhow::anyhow!("invalid policy cases (expected JSON array)"))?;
    for (i, case) in cases.iter().enumerate() {
        let who = caller(case.as_who.as_deref())?;
        let d = super::evaluate(policy, &who, case.action, &subject(case.action, &case.subject));
        if d.effect != case.expected { bail!("case {}: effect mismatch ({})", i + 1, d.reason); }
    }
    Ok(cases.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RULES: &str = r#"{"rules":[{"subject":{"secret":"dev/*"},"action":"get","who":"agent","effect":"deny"}]}"#;

    #[test]
    fn policy_file_accepts_full_config_or_bare_policy() {
        let bare = policy_from_file(RULES).unwrap();
        let full = policy_from_file(&format!(r#"{{"default_tier":"bio","policy":{RULES}}}"#)).unwrap();
        assert_eq!(bare.rules.len(), 1);
        assert_eq!(policy_sha256(&bare), policy_sha256(&full));
        assert!(policy_from_file(r#"{"policy":null}"#).unwrap().rules.is_empty());
        assert!(policy_from_file(r#"{"default_tier":"bio"}"#).unwrap().rules.is_empty());
    }

    #[test]
    fn policy_file_rejects_wrong_shapes_instead_of_passing_empty() {
        for text in ["not json", "[]", "{}", r#"{"colour":"bio"}"#, r#"{"rules":[],"typo":1}"#,
            r#"{"policy":{"rules":[{"subject":{"tool":"x"},"action":"get","who":"agent","effect":"allow"}]}}"#] {
            assert!(policy_from_file(text).is_err(), "{text}");
        }
    }

    #[test]
    fn live_check_fails_for_older_daemon_and_for_hash_mismatch() {
        let policy = policy_from_file(RULES).unwrap();
        let err = check_live(&policy, &json!({"ok": true, "pid": 1})).unwrap_err().to_string();
        assert!(err.contains("older build") && err.contains("ui-v1 does not enforce"), "{err}");
        let err = check_live(&policy, &json!({"policy_sha256": policy_sha256(&Policy::default())})).unwrap_err().to_string();
        assert!(err.contains("differs"), "{err}");
        let ok = check_live(&policy, &json!({"policy_sha256": policy_sha256(&policy), "build_id": "abc"})).unwrap();
        assert_eq!(ok["daemon_build_id"], "abc");
    }

    #[test]
    fn absent_and_empty_policy_hash_alike_and_rules_change_hash() {
        assert_eq!(policy_sha256(&Policy::default()), policy_sha256(&policy_from_file(r#"{"rules":[]}"#).unwrap()));
        assert_ne!(policy_sha256(&Policy::default()), policy_sha256(&policy_from_file(RULES).unwrap()));
    }
}
