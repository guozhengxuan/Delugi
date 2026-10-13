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
            "--nodes" => {
                nodes = args
                    .next()
                    .ok_or("missing nodes")?
                    .parse::<usize>()
                    .map_err(|e| e.to_string())?
            }
            "--help" => {
                println!("delugi-replica --config FILE --id ID\ndelugi-replica --keygen DIRECTORY --nodes 4|7");
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
    process::run(c, id.ok_or("--id is required")?)
}
