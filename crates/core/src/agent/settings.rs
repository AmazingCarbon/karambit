//! Atomic detection-list update through the existing config approval path.
use crate::store::{Config, DEFAULT_AGENT_ENV_MARKERS, DEFAULT_AGENT_PROCESS_NAMES};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionSettings {
    pub agent_process_names: Vec<String>,
    pub agent_env_markers: Vec<String>,
    pub removed_defaults: Vec<String>,
}

impl DetectionSettings {
    pub fn parse(value: &str) -> Result<Self> {
        let settings: Self = serde_json::from_str(value)?;
        for (names, env) in [(&settings.agent_process_names, false), (&settings.agent_env_markers, true), (&settings.removed_defaults, false)] {
            ensure!(names.len() <= 256, "at most 256 detection tokens per field");
            for name in names {
                ensure!(!name.is_empty() && name.len() <= 128 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)), "invalid detection token");
                if env { crate::valid_var(name)?; }
            }
        }
        ensure!(settings.removed_defaults.iter().all(|n| DEFAULT_AGENT_PROCESS_NAMES.iter().any(|d| d.eq_ignore_ascii_case(n)) || DEFAULT_AGENT_ENV_MARKERS.contains(&n.as_str())), "only built-in defaults can be removed");
        Ok(settings)
    }
    pub fn apply(&self, cfg: &mut Config) {
        cfg.agent_process_names = self.agent_process_names.clone();
        cfg.agent_env_markers = self.agent_env_markers.clone();
        cfg.removed_defaults = self.removed_defaults.clone();
        cfg.merge_defaults();
    }
    pub fn relaxes(&self, old: &Config) -> bool {
        let mut next = old.clone();
        self.apply(&mut next);
        removes(&old.agent_process_names, &next.agent_process_names, true)
            || removes(&old.agent_env_markers, &next.agent_env_markers, false)
    }
}

pub(crate) fn removes(old: &[String], next: &[String], ci: bool) -> bool {
    old.iter().any(|o| !next.iter().any(|n| if ci { o.eq_ignore_ascii_case(n) } else { o == n }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn additions_tighten_and_default_removal_relaxes() {
        let old = Config::default();
        let mut settings: DetectionSettings = serde_json::from_value(serde_json::json!({
            "agent_process_names": old.agent_process_names, "agent_env_markers": old.agent_env_markers, "removed_defaults": []
        })).unwrap();
        settings.agent_process_names.push("grok".into());
        assert!(!settings.relaxes(&old));
        settings.removed_defaults.push("claude".into());
        assert!(settings.relaxes(&old));
        let mut next = old.clone(); settings.apply(&mut next);
        assert!(!next.agent_process_names.contains(&"claude".into()));
        assert!(DetectionSettings::parse(r#"{"agent_process_names":["bad name"],"agent_env_markers":[],"removed_defaults":[]}"#).is_err());
    }
}
