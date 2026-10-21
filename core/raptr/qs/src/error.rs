use thiserror::Error;
#[derive(Debug,Error)]
#[error(transparent)]
pub struct DbError { #[from] inner:anyhow::Error }
#[derive(Debug,Error)]
#[error(transparent)]
pub struct QuorumStoreError { #[from] inner:anyhow::Error }
