use delugi::process::{self, Config};
use std::path::PathBuf;
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn execute() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut config = None;
    let mut id = None;
    let mut keygen = None;
    let mut nodes = 4;
    let mut verify_ledger = None;
    let mut verify_archive = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config = Some(PathBuf::from(
                    args.next().ok_or("missing configuration path")?,
                ))
            }
            "--id" => {
                id = Some(
                    args.next()
                        .ok_or("missing id")?
                        .parse::<u32>()
                        .map_err(|e| e.to_string())?,
                )
            }
            "--keygen" => keygen = Some(PathBuf::from(args.next().ok_or("missing key directory")?)),
            "--verify-workload-archive" => {
                verify_archive = Some(PathBuf::from(args.next().ok_or("missing archive index")?))
            }
            "--verify-workload-ledger" => {
                verify_ledger = Some(PathBuf::from(args.next().ok_or("missing ledger path")?))
            }
            "--nodes" => {
                nodes = args
                    .next()
                    .ok_or("missing nodes")?
                    .parse::<usize>()
                    .map_err(|e| e.to_string())?
            }
            "--help" => {
                println!("delugi-replica --config FILE --id ID\ndelugi-replica --keygen DIRECTORY --nodes N\ndelugi-replica --config FILE --verify-workload-ledger FILE\ndelugi-replica --config FILE --verify-workload-archive INDEX");
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    if let Some(directory) = keygen {
        println!("{}", process::keygen(&directory, nodes)?);
        return Ok(());
    }
    let c: Config = serde_json::from_slice(
        &std::fs::read(config.ok_or("--config is required")?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if let Some(path) = verify_archive {
        if verify_ledger.is_some() {
            return Err("choose one ledger verification format".into());
        }
        println!("{}", delugi::ledger::verify_workload_archive(&c, &path)?);
        return Ok(());
    }
    if let Some(path) = verify_ledger {
        if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 * 1024 {
            return Err("offline ledger exceeds the 1 GiB verifier resource envelope".into());
        }
        let ledger = serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        println!("{}", process::verify_workload_ledger(&c, &ledger)?);
        return Ok(());
    }
    process::run(c, id.ok_or("--id is required")?)
}
