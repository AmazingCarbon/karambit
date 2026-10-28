//! Portable, subtractive policy. An allow never replaces existing authorization.
mod eval;
pub(crate) mod profile;
pub mod diagnostics;
pub(crate) mod approval;
pub use eval::{Decision, evaluate};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(try_from = "PolicyInput")]
pub struct Policy {
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub tags: BTreeMap<String, Tier>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyInput {
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    tags: BTreeMap<String, Tier>,
}
impl TryFrom<PolicyInput> for Policy {
    type Error = &'static str;
    fn try_from(input: PolicyInput) -> Result<Self, Self::Error> {
        let policy = Self { rules: input.rules, tags: input.tags };
        policy.validate()?;
        Ok(policy)
    }
}
impl Policy {
    pub fn validate(&self) -> Result<(), &'static str> {
        let text = |s: &str| !s.is_empty() && s.len() <= 1024 && s.bytes().all(|b| (0x21..=0x7e).contains(&b));
        for rule in &self.rules {
            let name = match &rule.subject { Subject::Secret(n) | Subject::Tool(n) | Subject::Egress(n) => n };
            if !text(name) { return Err("policy.invalid_subject"); }
            match (&rule.subject, rule.action) {
                (Subject::Tool(_), Action::Call) | (Subject::Egress(_), Action::Egress) => (),
                (Subject::Secret(_), Action::Get | Action::Copy | Action::View | Action::Run | Action::Export) => (),
                _ => return Err("policy.invalid_action_subject"),
            }
            if matches!(&rule.who, Who::Kind(n) | Who::Session(n) if !text(n)) { return Err("policy.invalid_who"); }
            if matches!(rule.who, Who::Session(_)) && rule.effect == Effect::Allow { return Err("policy.session_cannot_allow"); }
        }
        if self.tags.keys().any(|p| !text(p)) { return Err("policy.invalid_tag_pattern"); }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub subject: Subject,
    pub action: Action,
    pub who: Who,
    pub effect: Effect,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subject { Secret(String), Tool(String), Egress(String) }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Who { Any, Agent, Kind(String), Session(String) }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action { Get, Copy, View, Run, Call, Export, Egress }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect { Deny, Approve, Allow }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier { Prod, Preprod, Dev }

/// Optional persisted containment; labels can only deny, never grant.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Killed {
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub agents: std::collections::BTreeSet<String>,
    #[serde(default)]
    pub sessions: std::collections::BTreeSet<String>,
}
impl Killed {
    pub fn matches(&self, caller: &crate::agent::Caller) -> bool {
        caller.is_agent() && (self.all
            || caller.kind.as_ref().is_some_and(|k| self.agents.contains(k))
            || caller.session.as_ref().is_some_and(|s| self.sessions.contains(s)))
    }
}

pub(crate) fn check_killed(p: &crate::store::Paths, caller: &crate::agent::Caller) -> anyhow::Result<()> {
    if crate::store::load_config(p)?.killed.as_ref().is_some_and(|k| k.matches(caller)) {
        let result = Err(anyhow::anyhow!("policy.killed"));
        crate::audit::log(p, crate::audit::Event { action: "policy-decision", secrets: &[], caller,
            detail: serde_json::json!({"reason_code":"policy.killed"}), result: &result })?;
        return result;
    }
    Ok(())
}

/// Audit and deny now; callers deferring approval must obtain proof before use.
pub(crate) fn check(p: &crate::store::Paths, caller: &crate::agent::Caller, action: Action, subject: &Subject) -> anyhow::Result<bool> {
    check_killed(p, caller)?;
    let config = crate::store::load_config(p)?;
    let Some(policy) = config.policy else { return Ok(false); };
    let decision = evaluate(&policy, caller, action, subject);
    let result = if decision.effect == Effect::Deny { Err(anyhow::anyhow!(decision.reason)) } else { Ok(()) };
    crate::audit::log(p, crate::audit::Event {
        action: "policy-decision", secrets: &[], caller,
        detail: serde_json::json!({"action": action, "subject": subject, "effect": decision.effect, "reason_code": decision.reason}),
        result: &result,
    })?;
    result?;
    Ok(decision.effect == Effect::Approve)
}

pub(crate) fn enforce_args(p: &crate::store::Paths, caller: &crate::agent::Caller, action: Action, subject: Subject, args: &serde_json::Value) -> anyhow::Result<()> {
    if !check(p, caller, action, &subject)? { return Ok(()); }
    let action_bytes = serde_json::to_vec(&action)?;
    let subjects = serde_json::to_vec(&subject)?;
    let caller_bytes = serde_json::to_vec(caller)?;
    let args = serde_json::to_vec(args)?;
    let hash = approval::binding(&[&action_bytes, &subjects, &caller_bytes, &args]);
    let name = match &subject { Subject::Secret(n) | Subject::Tool(n) | Subject::Egress(n) => n.clone() };
    // Refuse rather than silently truncate an approval's subject list.
    if crate::helper::prompt_param(&name) != name { anyhow::bail!("policy.approval_prompt_too_long"); }
    let context = format!("policy {} {}", String::from_utf8_lossy(&action_bytes), hex(&hash));
    let mut proof = crate::audit::run(p, "policy-approval", &[], caller,
        serde_json::json!({"binding_hash":hex(&hash),"reason_code":"policy.approval_required"}), || {
        approval::Approval::request(hash, || crate::helper::auth(&crate::helper::Prompt::Use {
            names: name, caller: caller.label(), context,
        }))
    })?;
    check(p, caller, action, &subject)?;
    proof.consume(hash)
}
pub(crate) fn hex(hash: &[u8; 32]) -> String { hash.iter().map(|b| format!("{b:02x}")).collect() }
