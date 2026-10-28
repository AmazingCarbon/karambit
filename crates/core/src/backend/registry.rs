use super::*;
use std::{collections::BTreeMap, sync::Arc};
pub type Factory = fn(&SourceConfig) -> BResult<Arc<dyn SecretBackend>>;
/// The open core ships no built-in backend kinds; kinds come from explicit registration.
pub fn production_registry() -> Registry {
    Registry::default()
}
#[derive(Default)]
pub struct Registry {
    factories: BTreeMap<String, Factory>,
    sources: BTreeMap<String, Arc<dyn SecretBackend>>,
}
impl Registry {
    pub fn register(&mut self, kind: &str, factory: Factory) -> BResult<()> {
        if kind.is_empty() || self.factories.contains_key(kind) {
            return Err(BackendError::InvalidConfig);
        }
        self.factories.insert(kind.into(), factory);
        Ok(())
    }
    /// Registered backend kinds, sorted.
    pub fn kinds(&self) -> Vec<String> {
        self.factories.keys().cloned().collect()
    }
    pub fn validate_kind(&self, kind: &str) -> BResult<()> {
        if self.factories.contains_key(kind) {
            Ok(())
        } else {
            Err(BackendError::InvalidConfig)
        }
    }
    /// Construct an immutable binding without registering it. Call outside daemon State.
    pub fn construct(&self, config: &SourceConfig) -> BResult<Arc<dyn SecretBackend>> {
        config.validate()?;
        self.validate_kind(&config.kind)?;
        self.factories[&config.kind](config)
    }
    pub fn add_source(&mut self, config: &SourceConfig) -> BResult<()> {
        config.validate()?;
        self.validate_kind(&config.kind)?;
        if self.sources.contains_key(&config.name) {
            return Err(BackendError::InvalidConfig);
        }
        let backend = self.construct(config)?;
        self.sources.insert(config.name.clone(), backend);
        Ok(())
    }
    pub fn lookup(&self, name: &str) -> BResult<Arc<dyn SecretBackend>> {
        self.sources
            .get(name)
            .cloned()
            .ok_or(BackendError::NotFound)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Stub;
    impl SecretBackend for Stub {
        fn id(&self) -> &str {
            "stub"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                metadata: false,
                list: false,
                renew: false,
                revoke: false,
                interactive_auth: false,
                refresh_auth: false,
            }
        }
        fn parse_ref(&self, _: &str) -> BResult<NativeRef> {
            Err(BackendError::InvalidRef)
        }
        fn resolve_kind(&self, _: &NativeRef) -> BResult<ResolveKind> {
            Ok(ResolveKind::StaticRead)
        }
        fn auth_status(&self) -> AuthState {
            AuthState {
                expires_at: None,
                renewable: false,
                needs_human: true,
            }
        }
        fn resolve(&self, _: &CallContext<'_>, _: &NativeRef, _: &ResolveOpts) -> Resolved {
            Resolved {
                result: Err(BackendError::NeedsHuman),
                effect: IssueEffect::None,
            }
        }
    }
    #[test]
    fn registry_and_object_safety() {
        let factory: Factory = |_| Ok(Arc::new(Stub));
        let mut r = Registry::default();
        assert_eq!(r.validate_kind("mystery"), Err(BackendError::InvalidConfig));
        assert!(r.kinds().is_empty());
        assert!(production_registry().kinds().is_empty(), "the open core registers no built-in kinds");
        assert!(matches!(r.lookup("missing"), Err(BackendError::NotFound)));
        r.register("fake", factory).unwrap();
        assert!(r.register("fake", factory).is_err());
        assert!(r.register("", factory).is_err());
        assert_eq!(r.kinds(), vec!["fake".to_string()]);
        let c = SourceConfig {
            name: "f".into(),
            kind: "fake".into(),
            endpoint: "https://fake.invalid/".into(),
            auth_method: "token".into(),
            credential_ref: "sources/f/cred".into(),
            credential_revision: "r".into(),
            generation: "0".repeat(32),
            policy: serde_json::json!({}),
        };
        assert_eq!(r.construct(&c).unwrap().id(), "stub");
        assert!(matches!(r.lookup("f"), Err(BackendError::NotFound)));
        let mut invalid = c.clone();
        invalid.kind = "missing".into();
        assert!(matches!(r.construct(&invalid), Err(BackendError::InvalidConfig)));
        invalid = c.clone();
        invalid.name = "aws".into();
        assert!(matches!(r.construct(&invalid), Err(BackendError::InvalidConfig)));
        r.add_source(&c).unwrap();
        // Construction is also available for replacement of an existing registration.
        assert_eq!(r.construct(&c).unwrap().id(), "stub");
        assert!(r.add_source(&c).is_err());
        let backend: Arc<dyn SecretBackend> = r.lookup("f").unwrap();
        std::thread::spawn(move || assert_eq!(backend.id(), "stub"))
            .join()
            .unwrap();
    }
}
