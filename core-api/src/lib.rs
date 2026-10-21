//! Service contracts, independent of consensus types and certificate policies.

/// A store completion never implicitly grants permission to vote or release data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Persistence {
    Accepted,
    Visible,
    Written,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCapabilities {
    pub maximum_completion: Persistence,
    pub crash_recovery: bool,
    pub fault_model: &'static str,
}

impl StorageCapabilities {
    pub fn require(self, requested: Persistence) -> Result<(), UnsupportedPersistence> {
        if requested <= self.maximum_completion {
            Ok(())
        } else {
            Err(UnsupportedPersistence { requested, supported: self.maximum_completion })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedPersistence {
    pub requested: Persistence,
    pub supported: Persistence,
}

/// Async completion identity. A stale generation cannot complete a newer request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OperationId {
    pub sequence: u64,
    pub generation: u64,
}

/// Node lifecycle facade. Configuration bytes and verification formats remain
/// owned by each core; the common CLI does not interpret consensus settings.
pub trait ProtocolFactory {
    fn name(&self) -> &'static str;
    fn run(&self, configuration: &[u8], id: u32) -> Result<(), String>;
    fn generate_keys(&self, directory: &std::path::Path, nodes: usize) -> Result<String, String>;
    fn verify_archive(&self, configuration: &[u8], path: &std::path::Path) -> Result<String, String>;
    fn verify_ledger(&self, configuration: &[u8], path: &std::path::Path) -> Result<String, String>;
}
