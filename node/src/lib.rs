//! Common command-line lifecycle. Protocol factories are registered by the
//! executable; parsing, file loading and dispatch are shared across cores.
use core_api::ProtocolFactory;
use std::path::PathBuf;

pub fn execute(
    mut args: impl Iterator<Item = String>,
    default_protocol: &str,
    factories: &[&dyn ProtocolFactory],
) -> Result<(), String> {
    let mut protocol = default_protocol.to_owned();
    let mut config = None;
    let mut id = None;
    let mut keygen = None;
    let mut nodes = 4;
    let mut verify_ledger = None;
    let mut verify_archive = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--protocol" => protocol = args.next().ok_or("missing protocol name")?,
            "--config" => config = Some(PathBuf::from(args.next().ok_or("missing configuration path")?)),
            "--id" => id = Some(args.next().ok_or("missing id")?.parse::<u32>().map_err(|e| e.to_string())?),
            "--keygen" => keygen = Some(PathBuf::from(args.next().ok_or("missing key directory")?)),
            "--verify-workload-archive" => verify_archive = Some(PathBuf::from(args.next().ok_or("missing archive index")?)),
            "--verify-workload-ledger" => verify_ledger = Some(PathBuf::from(args.next().ok_or("missing ledger path")?)),
            "--nodes" => nodes = args.next().ok_or("missing nodes")?.parse::<usize>().map_err(|e| e.to_string())?,
            "--help" => {
                let names: Vec<_> = factories.iter().map(|factory| factory.name()).collect();
                println!("delugi-node --protocol {} --config FILE --id ID\ndelugi-node --protocol NAME --keygen DIRECTORY --nodes N\ndelugi-node --protocol NAME --config FILE --verify-workload-ledger FILE\ndelugi-node --protocol NAME --config FILE --verify-workload-archive INDEX", names.join("|"));
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    let factory = factories.iter().find(|factory| factory.name() == protocol)
        .ok_or_else(|| format!("protocol {protocol} has no installed runtime factory"))?;
    if let Some(directory) = keygen {
        println!("{}", factory.generate_keys(&directory, nodes)?);
        return Ok(());
    }
    let configuration = std::fs::read(config.ok_or("--config is required")?).map_err(|e| e.to_string())?;
    if let Some(path) = verify_archive {
        if verify_ledger.is_some() { return Err("choose one ledger verification format".into()); }
        println!("{}", factory.verify_archive(&configuration, &path)?);
        return Ok(());
    }
    if let Some(path) = verify_ledger {
        println!("{}", factory.verify_ledger(&configuration, &path)?);
        return Ok(());
    }
    factory.run(&configuration, id.ok_or("--id is required")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Factory { name: &'static str, calls: AtomicUsize }
    impl ProtocolFactory for Factory {
        fn name(&self) -> &'static str { self.name }
        fn run(&self, _: &[u8], _: u32) -> Result<(), String> { unreachable!() }
        fn generate_keys(&self, _: &std::path::Path, nodes: usize) -> Result<String, String> {
            self.calls.store(nodes, Ordering::SeqCst); Ok("{}".into())
        }
        fn verify_archive(&self, _: &[u8], _: &std::path::Path) -> Result<String, String> { unreachable!() }
        fn verify_ledger(&self, _: &[u8], _: &std::path::Path) -> Result<String, String> { unreachable!() }
    }
    #[test]
    fn factory_registration_controls_dispatch_before_any_core_work() {
        let first = Factory { name: "first", calls: AtomicUsize::new(0) };
        let second = Factory { name: "second", calls: AtomicUsize::new(0) };
        let args = ["--protocol", "second", "--keygen", "unused", "--nodes", "7"];
        execute(args.into_iter().map(str::to_owned), "first", &[&first, &second]).unwrap();
        assert_eq!(first.calls.load(Ordering::SeqCst), 0);
        assert_eq!(second.calls.load(Ordering::SeqCst), 7);
        let args = ["--protocol", "missing", "--keygen", "unused"];
        assert!(execute(args.into_iter().map(str::to_owned), "first", &[&first, &second]).is_err());
        assert_eq!(first.calls.load(Ordering::SeqCst), 0);
        assert_eq!(second.calls.load(Ordering::SeqCst), 7);
    }
}
