//! Unmodified source is compiled against each side of a mechanical extraction.
//! Emits exact ordering message bytes, not hashes of debug/display formatting.
use delugi::{simulation, wire};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn file_record(root: &Path, name: &str, file: &str, data: &[u8]) -> Result<Value, String> {
    let mut out = fs::OpenOptions::new().write(true).create_new(true).open(root.join(file)).map_err(|e| e.to_string())?;
    out.write_all(data).map_err(|e| e.to_string())?;
    Ok(json!({"name":name,"path":file,"bytes":data.len(),"sha256":format!("{:x}",Sha256::digest(data))}))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: shared-core-wire NEW_OUTPUT_DIRECTORY".into());
    }
    let root = Path::new(&args[1]);
    fs::create_dir(root).map_err(|e| e.to_string())?;
    let cases = [
        ("honest-round-four", 4, 10, 4, 70, None, false),
        ("honest-delta-twenty", 4, 20, 4, 140, None, false),
        ("silent-first-three-anchors", 4, 10, 4, 800, Some(0), false),
        ("silent-first-delta-twenty", 4, 20, 4, 900, Some(0), false),
        ("recurring-silent", 4, 10, 8, 1500, Some(0), false),
        ("duplicate-packets", 4, 10, 4, 70, None, true),
        ("seven-replicas", 7, 10, 4, 70, None, false),
        ("seven-silent-first", 7, 10, 4, 800, Some(0), false),
    ];
    let mut fixtures = Vec::new();
    let mut kinds = BTreeSet::new();
    for (name, nodes, delta, rounds, until, silent, duplicate_packets) in cases {
        let config = simulation::Config { nodes, delta, bound:100, rounds, until, silent, duplicate_packets, delays:vec![] };
        let result = simulation::run(config)?;
        if result.summary()["pass"] != true { return Err(format!("scenario failed: {name}")); }
        let mut stream = b"SCWIRE01".to_vec();
        let mut rows = Vec::new();
        let mut counts = BTreeMap::<String, usize>::new();
        for (index, emitted) in result.messages.iter().enumerate() {
            let encoded = wire::encode(&emitted.message)?;
            let (kind, round) = simulation::message_kind(&emitted.message);
            kinds.insert(kind);
            *counts.entry(kind.into()).or_default() += 1;
            stream.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
            stream.extend_from_slice(&encoded);
            rows.push(json!({"index":index,"from":emitted.from,"to":emitted.to,"at":emitted.at,
                             "kind":kind,"round":round,"encoded_bytes":encoded.len()}));
        }
        let keys: Vec<Vec<u8>> = (0..nodes).map(|id| wire::fixture_key(id).public.to_bytes().to_vec()).collect();
        let context = serde_json::to_vec_pretty(&json!({"config":result.config,"fixture_public_keys":keys,
            "messages":rows,"counts":counts,"packet_sends":result.sends,
            "encoding":"SCWIRE01 then repeated u64le byte length and exact wire::encode(Message); contexts preserve broadcast/unicast and ordering"})).map_err(|e| e.to_string())?;
        fixtures.push(file_record(root, &format!("ordering/{name}/raw"), &format!("{name}.bin"), &stream)?);
        fixtures.push(file_record(root, &format!("ordering/{name}/context"), &format!("{name}.json"), &context)?);
    }
    let required = BTreeSet::from(["PROPOSE","VOTE","CER","PROG","CLOSED","HISTORY3"]);
    if kinds != required { return Err(format!("ordering message coverage incomplete: {kinds:?}")); }
    let index = json!({"schema":1,"fixtures":fixtures,"message_kinds":kinds,
        "scope":"exact ordering encoded bytes and signed evidence; transport envelopes require their own golden gate; finite simulations are not performance samples"});
    fs::write(root.join("index.json"), serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(())
}
