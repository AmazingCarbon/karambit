//! Portable, stack-owned proof: no wire token, cache, persistence or transferable authority.
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub(crate) fn binding(fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for field in std::iter::once(b"karambit-approval-v1".as_slice()).chain(fields.iter().copied()) {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

pub(crate) struct Approval {
    binding: Option<[u8; 32]>,
    deadline: Instant,
}
impl Approval {
    /// Start the deadline BEFORE the user-presence operation, not after it.
    pub(crate) fn request(binding: [u8; 32], confirm: impl FnOnce() -> Result<()>) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(120);
        confirm()?;
        Ok(Self { binding: Some(binding), deadline })
    }
    pub(crate) fn consume(&mut self, expected: [u8; 32]) -> Result<()> {
        let supplied = self.binding.take();
        if supplied != Some(expected) || Instant::now() >= self.deadline {
            bail!("policy.approval_invalid");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replayed_approval_refused() {
        let hash = binding(&[b"run", b"A", b"caller", b"args"]);
        let mut proof = Approval::request(hash, || Ok(())).unwrap();
        proof.consume(hash).unwrap();
        assert!(proof.consume(hash).is_err());
        let mut expired = Approval::request(hash, || Ok(())).unwrap();
        expired.deadline = Instant::now();
        assert!(expired.consume(hash).is_err());
    }
    #[test]
    fn approval_for_a_not_usable_for_b() {
        let a = binding(&[b"run", b"A", b"caller", b"args"]);
        for b in [binding(&[b"run", b"B", b"caller", b"args"]), binding(&[b"run", b"A", b"other", b"args"]), binding(&[b"run", b"A", b"caller", b"changed"])] {
            let mut proof = Approval::request(a, || Ok(())).unwrap();
            assert!(proof.consume(b).is_err());
            assert!(proof.consume(a).is_err());
        }
    }
}
