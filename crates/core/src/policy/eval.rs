use super::{Action, Effect, Policy, Subject, Tier, Who};
use crate::{agent::Caller, store::glob_match};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    pub reason: &'static str,
    /// Zero-based index of the decisive rule, absent for defaults.
    pub rule_index: Option<usize>,
}

pub fn evaluate(policy: &Policy, caller: &Caller, action: Action, subject: &Subject) -> Decision {
    let matching = |rule: &&super::Rule| {
        rule.action == action && match (&rule.subject, subject) {
            (Subject::Secret(pattern), Subject::Secret(name)) => glob_match(pattern, name),
            (Subject::Tool(a), Subject::Tool(b)) | (Subject::Egress(a), Subject::Egress(b)) => a == b,
            _ => false,
        } && match &rule.who {
            Who::Any => true,
            Who::Agent => caller.is_agent(),
            Who::Kind(kind) => caller.is_agent() && caller.kind.as_ref() == Some(kind),
            // Session labels are attribution, never authority: they may only tighten.
            Who::Session(label) => rule.effect != Effect::Allow && caller.session.as_ref() == Some(label),
        }
    };
    let rules: Vec<_> = policy.rules.iter().enumerate().filter(|(_, r)| matching(r)).collect();
    let index = |effect| rules.iter().find(|(_, r)| r.effect == effect).map(|(i, _)| *i);
    if index(Effect::Deny).is_some() {
        return Decision { effect: Effect::Deny, reason: "policy.rule_deny", rule_index: index(Effect::Deny) };
    }
    let name = match subject { Subject::Secret(n) | Subject::Tool(n) | Subject::Egress(n) => n };
    let prod = !matches!(subject, Subject::Egress(_)) && policy.tags.iter().any(|(p, t)| *t == Tier::Prod && glob_match(p, name));
    let allow = index(Effect::Allow).is_some();
    if caller.is_agent() && prod && !allow {
        return Decision { effect: Effect::Deny, reason: "policy.prod_agent", rule_index: None };
    }
    if index(Effect::Approve).is_some() {
        return Decision { effect: Effect::Approve, reason: "policy.approval_required", rule_index: index(Effect::Approve) };
    }
    Decision { effect: Effect::Allow, rule_index: index(Effect::Allow), reason: if allow { "policy.rule_allow" } else { "policy.base" } }
}
