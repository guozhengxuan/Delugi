//! Delugi-specific configuration and observer formats behind the common CLI.
use crate::{ledger, process::{self, Config}};
use core_api::ProtocolFactory;
use std::path::Path;

pub struct DelugiFactory;

fn configuration(bytes: &[u8]) -> Result<Config, String> {
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}

impl ProtocolFactory for DelugiFactory {
    fn name(&self) -> &'static str { "delugi" }
    fn run(&self, bytes: &[u8], id: u32) -> Result<(), String> {
        process::run(configuration(bytes)?, id)
    }
    fn generate_keys(&self, directory: &Path, nodes: usize) -> Result<String, String> {
        Ok(process::keygen(directory, nodes)?.to_string())
    }
    fn verify_archive(&self, bytes: &[u8], path: &Path) -> Result<String, String> {
        Ok(ledger::verify_workload_archive(&configuration(bytes)?, path)?.to_string())
    }
    fn verify_ledger(&self, bytes: &[u8], path: &Path) -> Result<String, String> {
        let config = configuration(bytes)?;
        if std::fs::metadata(path).map_err(|e| e.to_string())?.len() > 1024 * 1024 * 1024 {
            return Err("offline ledger exceeds the 1 GiB verifier resource envelope".into());
        }
        let ledger = serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(process::verify_workload_ledger(&config, &ledger)?.to_string())
    }
}
