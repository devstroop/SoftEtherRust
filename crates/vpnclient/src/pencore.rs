use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Pencore;

impl Pencore {
    pub fn parse(_data: &[u8]) -> Result<Self> { Ok(Pencore) }
    pub fn validate(&self) -> Result<()> { Ok(()) }
}
