//! Deterministic virtual-time ordering traces, never network performance samples.
use delugi::simulation::{self, Config};

fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn execute() -> Result<(), String> {
    let mut config = Config::default();
    let mut explicit_until = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--delta" => config.delta = number(&mut args, "--delta")?,
            "--bound" => config.bound = number(&mut args, "--bound")?,
            "--nodes" => config.nodes = number(&mut args, "--nodes")?,
            "--rounds" => config.rounds = number(&mut args, "--rounds")?,
            "--until" => {
                config.until = number(&mut args, "--until")?;
                explicit_until = true;
            }
            "--silent" => config.silent = Some(number(&mut args, "--silent")?),
            "--duplicates" => config.duplicate_packets = true,
            "--help" | "-h" => {
                println!("ordering-trace [--nodes 4|7] [--delta 10] [--bound 100] [--rounds 4] [--until TICKS] [--silent ID] [--duplicates]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg}; use --help")),
        }
    }
    if !explicit_until {
        config.until = config
            .bound
            .checked_mul(config.rounds.div_ceil(3).saturating_add(1))
            .and_then(|v| v.checked_mul(8))
            .ok_or("default observation horizon overflow")?;
    }
    let run = simulation::run(config)?;
    let summary = run.summary();
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
    );
    if summary["pass"] != true {
        std::process::exit(1);
    }
    Ok(())
}

fn number<T: std::str::FromStr>(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))?
        .parse()
        .map_err(|_| format!("invalid integer for {flag}"))
}
