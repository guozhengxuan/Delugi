use delugi::end_to_end::{self, Config, PayloadDelay};
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
fn execute() -> Result<(), String> {
    let mut c = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--silent" => c.silent = Some(number(&mut args, &arg)?),
            "--nodes" => c.nodes = number(&mut args, &arg)?,
            "--rounds" => c.rounds = number(&mut args, &arg)?,
            "--until" => c.until = number(&mut args, &arg)?,
            "--delta" => c.delta = number(&mut args, &arg)?,
            "--bound" => c.bound = number(&mut args, &arg)?,
            "--duplicates" => c.duplicates = true,
            "--delay-payload" => {
                c.delayed_payload = Some(PayloadDelay {
                    producer: 2,
                    receiver: 0,
                    extra: 2000,
                })
            }
            "--data-delay" => c.data_delay = number(&mut args, &arg)?,
            "--descriptor-only" => c.proposal_delay_to = Some(0),
            "--help" => {
                println!("end-to-end-trace [--nodes 4|7] [--rounds 4] [--delta 10] [--bound 100] [--until 900] [--silent ID] [--duplicates] [--delay-payload] [--data-delay TICKS] [--descriptor-only]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    let run = end_to_end::run(c)?;
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
        .ok_or_else(|| format!("{flag} requires an integer"))?
        .parse()
        .map_err(|_| format!("invalid {flag}"))
}
