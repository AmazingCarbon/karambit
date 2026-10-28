use super::{Jail, Sandbox};
pub struct Unsupported;
impl Sandbox for Unsupported {
    fn available(&self) -> bool { false }
    fn apply(&self, _: &Jail) -> anyhow::Result<()> {
        anyhow::bail!("child sandbox unavailable on this platform")
    }
}
