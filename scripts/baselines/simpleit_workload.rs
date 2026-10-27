//! Independent finite evaluation ingress and application observer.
//! Protocol voting, timers and certificate rules are outside this module.
use config::{Import, KeyPair};
use crypto::{Digest as NativeDigest, PublicKey, Signature};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    convert::TryInto,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: u32,
    run_id: String,
    id: usize,
    members: Vec<String>,
    honest_origins: Vec<usize>,
    total_rate: u64,
    duration_ms: u64,
    drain_ms: u64,
    useful_bytes: usize,
    queue_capacity: usize,
    journal_limit_bytes: u64,
    directory: PathBuf,
    arm_path: PathBuf,
    native_key: PathBuf,
    #[serde(default)]
    payload_fault: Option<PayloadFault>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PayloadFault {
    source: usize,
    recipient: usize,
    initial_headers: usize,
}
#[derive(Clone, Default)]
struct Row {
    offered: u64,
    admitted: u64,
    rejected: u64,
    cancelled: u64,
    batch: u64,
    done: u64,
}
struct State {
    cfg: Configuration,
    epoch: u64,
    end: u64,
    deadline: u64,
    rows: Vec<Row>,
    counts: Vec<u64>,
    queue: VecDeque<Vec<u8>>,
    seen: Vec<bool>,
    output: BufWriter<File>,
    output_bytes: u64,
    output_rows: u64,
    frozen: bool,
    pending: VecDeque<(u64, NativeDigest)>,
    retained_bytes: u64,
    withheld: Vec<NativeDigest>,
    fault_events: Vec<Value>,
    attacker_headers: usize,
}
static STATE: OnceCell<Arc<Mutex<State>>> = OnceCell::new();
pub fn enabled() -> bool {
    std::env::var_os("DELUGI_SIMPLEIT_WORKLOAD").is_some()
}
pub fn now() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) },
        0
    );
    t.tv_sec as u64 * 1_000_000 + t.tv_nsec as u64 / 1000
}
fn wait(at: u64) {
    while now() < at {
        thread::sleep(Duration::from_micros((at - now().min(at)).min(1000)));
    }
}
fn count(cfg: &Configuration, id: usize) -> u64 {
    let total = cfg.total_rate * cfg.duration_ms / 1000;
    cfg.honest_origins
        .iter()
        .position(|&v| v == id)
        .map(|rank| {
            (total + cfg.honest_origins.len() as u64 - 1 - rank as u64)
                / cfg.honest_origins.len() as u64
        })
        .unwrap_or(0)
}
fn scheduled(cfg: &Configuration, id: usize, seq: u64, epoch: u64) -> u64 {
    let rank = cfg
        .honest_origins
        .iter()
        .position(|&v| v == id)
        .expect("honest origin");
    epoch + (seq * cfg.honest_origins.len() as u64 + rank as u64) * 1_000_000 / cfg.total_rate
}
fn transaction(cfg: &Configuration, origin: usize, seq: u64) -> Vec<u8> {
    let mut tx = b"DLG-SIT1".to_vec();
    tx.extend_from_slice(&hex::decode(&cfg.run_id).unwrap());
    tx.extend_from_slice(&(origin as u32).to_le_bytes());
    tx.extend_from_slice(&seq.to_le_bytes());
    let digest = Sha256::digest(&tx);
    tx.extend((0..cfg.useful_bytes).map(|i| digest[i % 32]));
    tx
}
fn identify(cfg: &Configuration, tx: &[u8]) -> Option<(usize, u64)> {
    if tx.len() != 52 + cfg.useful_bytes || &tx[..8] != b"DLG-SIT1" {
        return None;
    }
    let origin = u32::from_le_bytes(tx[40..44].try_into().ok()?) as usize;
    let seq = u64::from_le_bytes(tx[44..52].try_into().ok()?);
    if origin >= cfg.members.len()
        || seq >= count(cfg, origin)
        || tx != transaction(cfg, origin, seq)
    {
        return None;
    }
    Some((origin, seq))
}
fn new_file(path: &PathBuf) -> File {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .expect("new private observer file")
}
fn write_json(path: PathBuf, value: &impl Serialize) {
    let temporary = path.with_extension("pending");
    let mut f = new_file(&temporary);
    serde_json::to_writer(&mut f, value).unwrap();
    f.write_all(b"\n").unwrap();
    f.sync_all().unwrap();
    fs::hard_link(&temporary, &path).expect("publish complete one-shot receipt");
    fs::remove_file(&temporary).unwrap();
}
fn file_record(path: PathBuf) -> Value {
    let mut f = File::open(&path).unwrap();
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    let mut bytes = 0;
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        bytes += n;
    }
    json!({"name":path.file_name().unwrap().to_str().unwrap(),"bytes":bytes,"sha256":hex::encode(hash.finalize())})
}

pub fn start(name: PublicKey) {
    if !enabled() {
        return;
    }
    assert!(
        network::eval_tls::enabled(),
        "identifiable evaluation requires authenticated channels"
    );
    let path = PathBuf::from(std::env::var_os("DELUGI_SIMPLEIT_WORKLOAD").unwrap());
    let raw = fs::read(&path).unwrap();
    assert!(raw.len() <= 1024 * 1024);
    let cfg: Configuration = serde_json::from_slice(&raw).unwrap();
    assert!(
        cfg.schema == 1 && [4, 10, 50].contains(&cfg.members.len()) && cfg.id < cfg.members.len()
    );
    assert!(cfg
        .members
        .iter()
        .all(|key| hex::decode(key).map(|b| b.len() == 32).unwrap_or(false)));
    assert_eq!(
        cfg.members
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        cfg.members.len()
    );
    assert!(
        cfg.members[cfg.id] == hex::encode(name.as_ref())
            && hex::decode(&cfg.run_id).unwrap().len() == 32
    );
    assert!(
        !cfg.honest_origins.is_empty()
            && cfg.honest_origins.windows(2).all(|w| w[0] < w[1])
            && *cfg.honest_origins.last().unwrap() < cfg.members.len()
    );
    assert!(
        cfg.total_rate <= 80_000
            && cfg.duration_ms > 0
            && cfg.duration_ms <= 60_000
            && cfg.drain_ms <= 15_000
    );
    assert!((1..=4096).contains(&cfg.useful_bytes) && (1..=65536).contains(&cfg.queue_capacity));
    assert!(cfg.journal_limit_bytes > 0 && cfg.journal_limit_bytes <= 4 * 1024 * 1024 * 1024);
    if let Some(f) = &cfg.payload_fault {
        assert!(
            f.source < cfg.members.len()
                && f.recipient < cfg.members.len()
                && f.source != f.recipient
        );
        assert!((1..=3).contains(&f.initial_headers) && !cfg.honest_origins.contains(&f.source));
    }
    fs::create_dir(&cfg.directory).expect("fresh observer directory required");
    write_json(
        cfg.directory.join("ready.json"),
        &json!({"schema":1,"id":cfg.id,"pid":std::process::id(),
        "configuration_sha256":hex::encode(Sha256::digest(&raw)),"run_id":cfg.run_id,"ready_us":now()}),
    );
    let guard = now() + 240_000_000;
    while !cfg.arm_path.is_file() {
        assert!(now() < guard, "arm timeout");
        thread::sleep(Duration::from_millis(2));
    }
    let arm: Value = serde_json::from_slice(&fs::read(&cfg.arm_path).unwrap()).unwrap();
    assert_eq!(arm["run_id"], cfg.run_id);
    let epoch = arm["epoch_us"].as_u64().unwrap();
    assert!(epoch > now(), "arm epoch must be in the future");
    network::eval_tls::arm_traffic(epoch, epoch + cfg.duration_ms * 1000);
    wait(epoch);
    let counts: Vec<_> = (0..cfg.members.len()).map(|i| count(&cfg, i)).collect();
    let output = BufWriter::new(new_file(&cfg.directory.join("output.jsonl")));
    let state = Arc::new(Mutex::new(State {
        cfg: cfg.clone(),
        epoch,
        end: epoch + cfg.duration_ms * 1000,
        deadline: epoch + (cfg.duration_ms + cfg.drain_ms) * 1000,
        rows: vec![Row::default(); counts[cfg.id] as usize],
        queue: VecDeque::new(),
        seen: vec![false; counts.iter().sum::<u64>() as usize],
        counts,
        output,
        output_bytes: 0,
        output_rows: 0,
        frozen: false,
        pending: VecDeque::new(),
        retained_bytes: 0,
        withheld: Vec::new(),
        fault_events: Vec::new(),
        attacker_headers: 0,
    }));
    assert!(STATE.set(state.clone()).is_ok());
    let arrivals = state.clone();
    let plan = cfg.clone();
    thread::spawn(move || {
        for seq in 0..count(&plan, plan.id) {
            let at = scheduled(&plan, plan.id, seq, epoch);
            wait(at);
            let offered = now();
            if offered >= epoch + plan.duration_ms * 1000 {
                break;
            }
            let tx = transaction(&plan, plan.id, seq);
            let mut s = arrivals.lock().unwrap();
            if s.frozen {
                break;
            }
            let time = now();
            let full = s.queue.len() >= plan.queue_capacity;
            if time < s.end && !full {
                s.queue.push_back(tx);
            }
            let end = s.end;
            let row = &mut s.rows[seq as usize];
            row.offered = offered;
            if time >= end {
                row.cancelled = time;
            } else if full {
                row.rejected = time;
            } else {
                row.admitted = time;
            }
        }
    });
    thread::spawn(move || {
        while now() < epoch + (cfg.duration_ms + cfg.drain_ms) * 1000 {
            while flush_one() {}
            thread::sleep(Duration::from_millis(1));
        }
        let mut s = state.lock().unwrap();
        s.frozen = true;
        let freeze = now();
        s.output.flush().unwrap();
        s.output.get_ref().sync_all().unwrap();
        let mut requests = BufWriter::new(new_file(&cfg.directory.join("requests.jsonl")));
        let mut populations = [0u64; 6];
        for (seq, row) in s.rows.iter().enumerate() {
            let opt = |time| if time == 0 { None } else { Some(time) };
            for (i, time) in [
                row.offered,
                row.admitted,
                row.rejected,
                row.cancelled,
                row.done,
            ]
            .iter()
            .enumerate()
            {
                populations[i] += u64::from(*time != 0);
            }
            let tx = transaction(&cfg, cfg.id, seq as u64);
            let value = json!({"origin":cfg.id,"sequence":seq,"request_id":hex::encode(Sha256::digest(&tx)),
                "useful_bytes":cfg.useful_bytes,"scheduled_us":scheduled(&cfg,cfg.id,seq as u64,epoch),
                "offered_us":opt(row.offered),"admitted_us":opt(row.admitted),"rejected_us":opt(row.rejected),
                "cancelled_us":opt(row.cancelled),"batch_ready_us":opt(row.batch),"materialized_us":opt(row.done)});
            serde_json::to_writer(&mut requests, &value).unwrap();
            requests.write_all(b"\n").unwrap();
        }
        requests.flush().unwrap();
        requests.get_ref().sync_all().unwrap();
        let [offered, admitted, rejected, cancelled, completed, _] = populations;
        let body = json!({"schema":1,"run_id":cfg.run_id,"id":cfg.id,"epoch_us":epoch,"deadline_us":s.deadline,
            "freeze_us":freeze,"configuration_sha256":hex::encode(Sha256::digest(&raw)),
            "populations":{"planned":s.rows.len(),"offered":offered,"admitted":admitted,"rejected":rejected,
                "cancelled":cancelled,"completed":completed,"unfinished":admitted-completed,"unoffered":s.rows.len() as u64-offered},
            "output_rows":s.output_rows,"traffic":network::eval_tls::traffic(),
            "payload_fault":{"configuration":cfg.payload_fault,"events":s.fault_events},
            "files":[file_record(cfg.directory.join("requests.jsonl")),file_record(cfg.directory.join("output.jsonl"))]});
        let bytes = serde_json::to_vec(&body).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let keys = KeyPair::import(cfg.native_key.to_str().unwrap()).unwrap();
        assert_eq!(keys.name, name);
        let signature = Signature::new(&NativeDigest(digest), &keys.secret);
        write_json(
            cfg.directory.join("final.json"),
            &json!({"body":body,"body_hex":hex::encode(bytes),"signature":signature}),
        );
    });
}

fn retain(id: &NativeDigest, kind: &str, bytes: &[u8]) {
    if !enabled() {
        return;
    }
    let mut s = STATE.get().unwrap().lock().unwrap();
    if s.frozen {
        return;
    }
    assert!(bytes.len() <= 64 * 1024 * 1024);
    let path = s
        .cfg
        .directory
        .join(format!("{}-{}.bin", kind, hex::encode(id.as_ref())));
    if path.exists() {
        assert_eq!(fs::read(path).unwrap(), bytes);
        return;
    }
    s.retained_bytes += bytes.len() as u64;
    assert!(s.retained_bytes <= s.cfg.journal_limit_bytes);
    let mut file = new_file(&path);
    file.write_all(bytes).unwrap();
}
pub fn retain_header(header: &crate::Header) {
    use crypto::Hash;
    if !enabled() {
        return;
    }
    assert_eq!(
        header.digest(),
        header.id,
        "reconstructed native header hash mismatch"
    );
    retain(&header.id, "header", &bincode::serialize(header).unwrap());
}
pub fn retain_reconstruction(id: &NativeDigest, bytes: &[u8]) {
    fault_event("reconstructed", id);
    retain(id, "payload", bytes);
}

pub fn fault_event(kind: &str, id: &NativeDigest) {
    if !enabled() {
        return;
    }
    let mut s = STATE.get().unwrap().lock().unwrap();
    if s.frozen || s.cfg.payload_fault.is_none() {
        return;
    }
    // Keep a bounded witness set; normal native processing is unaffected when
    // later diagnostic events exceed the witness envelope.
    let identity = hex::encode(id.as_ref());
    if s.fault_events.len() < 1024
        && !s
            .fault_events
            .iter()
            .any(|e| e["kind"] == kind && e["header"] == identity)
    {
        let replica = s.cfg.id;
        s.fault_events
            .push(json!({"kind":kind,"header":identity,"replica":replica,"at_us":now()}));
    }
}
pub fn withhold(header: &crate::Header) {
    if !enabled() || header.payload.is_empty() {
        return;
    }
    let mut s = STATE.get().unwrap().lock().unwrap();
    let Some(f) = s.cfg.payload_fault.clone() else {
        return;
    };
    if s.frozen
        || f.source != s.cfg.id
        || s.withheld.len() >= f.initial_headers
        || s.withheld.contains(&header.id)
    {
        return;
    }
    s.withheld.push(header.id.clone());
    s.fault_events.push(json!({"kind":"initial_header_withheld","header":hex::encode(header.id.as_ref()),
        "source":f.source,"recipient":f.recipient,"payload_bytes":header.payload.iter().map(|p|p.len()).sum::<usize>(),"at_us":now()}));
}
pub fn publish_to(header: &NativeDigest, peer: &PublicKey) -> bool {
    if !enabled() {
        return true;
    }
    let s = STATE.get().unwrap().lock().unwrap();
    match &s.cfg.payload_fault {
        Some(f) => {
            !(s.withheld.contains(header)
                && s.cfg.members[f.recipient] == hex::encode(peer.as_ref()))
        }
        None => true,
    }
}
pub fn reconstructed(id: &NativeDigest, length: usize) -> Option<Vec<Vec<u8>>> {
    if !enabled() {
        return None;
    }
    let s = STATE.get().unwrap().lock().unwrap();
    let path = s
        .cfg
        .directory
        .join(format!("payload-{}.bin", hex::encode(id.as_ref())));
    if !path.exists() {
        return None;
    }
    let bytes = fs::read(path).unwrap();
    assert!(length <= bytes.len() && bytes.len() <= 64 * 1024 * 1024);
    use bincode::Options;
    Some(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(length as u64)
            .reject_trailing_bytes()
            .deserialize(&bytes[..length])
            .expect("canonical reconstructed payload"),
    )
}
pub fn decide(round: u64, id: NativeDigest) {
    if !enabled() {
        return;
    }
    let mut s = STATE.get().unwrap().lock().unwrap();
    if s.frozen {
        return;
    }
    assert!(
        s.pending.len() < 65536,
        "application backlog envelope exhausted"
    );
    s.pending.push_back((round, id));
}
fn flush_one() -> bool {
    let (round, id, path) = {
        let s = STATE.get().unwrap().lock().unwrap();
        if s.frozen || now() >= s.deadline {
            return false;
        }
        match s.pending.front() {
            None => return false,
            Some((round, id)) => (
                *round,
                id.clone(),
                s.cfg
                    .directory
                    .join(format!("header-{}.bin", hex::encode(id.as_ref()))),
            ),
        }
    };
    if !path.exists() {
        return false;
    }
    let bytes = fs::read(path).unwrap();
    let header: crate::Header = bincode::deserialize(&bytes).unwrap();
    use crypto::Hash;
    assert_eq!(header.id, id);
    assert_eq!(header.digest(), id);
    materialize(round, id.clone(), bytes, &header.payload);
    let mut s = STATE.get().unwrap().lock().unwrap();
    assert_eq!(s.pending.pop_front(), Some((round, id)));
    true
}

pub fn payload(maximum_bytes: usize) -> Vec<Vec<u8>> {
    let owner = STATE.get().expect("workload started");
    let mut s = owner.lock().unwrap();
    if let Some(f) = s.cfg.payload_fault.clone() {
        if !s.frozen && s.cfg.id == f.source && s.attacker_headers < f.initial_headers {
            let mut payload = b"DLG-FAULT".to_vec();
            payload.resize(s.cfg.useful_bytes.max(9), 0xA5);
            assert!(payload.len() <= maximum_bytes);
            s.attacker_headers += 1;
            return vec![payload];
        }
    }
    let mut out = vec![];
    let mut bytes = 0;
    while !s.frozen
        && s.queue
            .front()
            .map(|t| bytes + t.len() <= maximum_bytes)
            .unwrap_or(false)
    {
        let tx = s.queue.pop_front().unwrap();
        bytes += tx.len();
        if let Some((_, seq)) = identify(&s.cfg, &tx) {
            s.rows[seq as usize].batch = now();
        }
        out.push(tx);
    }
    out
}

pub fn materialize(round: u64, header: NativeDigest, native_header: Vec<u8>, payload: &[Vec<u8>]) {
    if !enabled() {
        return;
    }
    let mut s = STATE.get().unwrap().lock().unwrap();
    if s.frozen || now() >= s.deadline {
        return;
    }
    let mut rows = vec![];
    let mut staged = std::collections::HashSet::new();
    let mut credits = vec![];
    for tx in payload {
        if let Some((origin, seq)) = identify(&s.cfg, tx) {
            let index = (s.counts[..origin].iter().sum::<u64>() + seq) as usize;
            let first = !s.seen[index] && staged.insert(index);
            let own = origin == s.cfg.id && first && s.rows[seq as usize].admitted != 0;
            if own {
                credits.push(seq as usize);
            }
            rows.push(json!({"origin":origin,"sequence":seq,"request_id":hex::encode(Sha256::digest(tx)),"first_seen":first,"own_credit":own}));
        }
    }
    // The endpoint follows complete native-body and request validation. Prepare
    // the record before publishing any credit; deadline crossing stays censored.
    let at = now();
    if at >= s.deadline {
        return;
    }
    let value = json!({"ordinal":s.output_rows,"round":round,"header":hex::encode(header.as_ref()),
        "native_header_bincode_hex":hex::encode(native_header),"materialized_us":at,"transactions":rows});
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(bytes.len() <= 64 * 1024 * 1024);
    assert!(s.output_bytes + bytes.len() as u64 + 1 <= s.cfg.journal_limit_bytes);
    s.output.write_all(&bytes).unwrap();
    s.output.write_all(b"\n").unwrap();
    s.output_rows += 1;
    s.output_bytes += bytes.len() as u64 + 1;
    for index in staged {
        s.seen[index] = true;
    }
    for seq in credits {
        s.rows[seq].done = at;
    }
}

fn journal(path: PathBuf, limit: u64, mut f: impl FnMut(Value)) -> u64 {
    assert!(!path.is_symlink() && fs::metadata(&path).unwrap().len() <= limit);
    let mut reader = BufReader::new(File::open(path).unwrap());
    let mut ordinal = 0;
    loop {
        let mut bytes = Vec::new();
        let n = reader
            .by_ref()
            .take(64 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut bytes)
            .unwrap();
        if n == 0 {
            break;
        }
        assert!(n <= 64 * 1024 * 1024 && bytes.last() == Some(&b'\n'));
        f(serde_json::from_slice(&bytes).unwrap());
        ordinal += 1;
        assert!(ordinal <= 4_800_000);
    }
    ordinal
}

/// Authenticate a frozen archive and re-decode every complete native header.
/// This checks materialization evidence, not a new consensus/certificate rule.
pub fn verify(config_path: &str, directory: &str) {
    use bincode::Options;
    use crypto::Hash;
    let raw = fs::read(config_path).unwrap();
    assert!(raw.len() <= 1024 * 1024);
    let cfg: Configuration = serde_json::from_slice(&raw).unwrap();
    assert!(
        cfg.schema == 1 && [4, 10, 50].contains(&cfg.members.len()) && cfg.id < cfg.members.len()
    );
    assert!(
        cfg.total_rate <= 80_000
            && cfg.duration_ms > 0
            && cfg.duration_ms <= 60_000
            && cfg.drain_ms <= 15_000
    );
    assert!(
        !cfg.honest_origins.is_empty()
            && cfg.honest_origins.windows(2).all(|w| w[0] < w[1])
            && *cfg.honest_origins.last().unwrap() < cfg.members.len()
    );
    assert!((1..=4096).contains(&cfg.useful_bytes));
    assert!(cfg.journal_limit_bytes > 0 && cfg.journal_limit_bytes <= 4 * 1024 * 1024 * 1024);
    let directory = PathBuf::from(directory);
    let final_path = directory.join("final.json");
    assert!(!final_path.is_symlink() && fs::metadata(&final_path).unwrap().len() < 1024 * 1024);
    let receipt: Value = serde_json::from_slice(&fs::read(final_path).unwrap()).unwrap();
    let bytes = hex::decode(receipt["body_hex"].as_str().unwrap()).unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(receipt["body"], body);
    let signature: Signature = serde_json::from_value(receipt["signature"].clone()).unwrap();
    let key: [u8; 32] = hex::decode(&cfg.members[cfg.id])
        .unwrap()
        .try_into()
        .unwrap();
    signature
        .verify(
            &NativeDigest(Sha256::digest(&bytes).into()),
            &PublicKey(key),
        )
        .unwrap();
    assert_eq!(
        body["configuration_sha256"],
        hex::encode(Sha256::digest(&raw))
    );
    assert_eq!(body["schema"], 1);
    assert_eq!(body["run_id"], cfg.run_id);
    assert_eq!(body["id"], cfg.id);
    let epoch = body["epoch_us"].as_u64().unwrap();
    let end = epoch + cfg.duration_ms * 1000;
    let deadline = end + cfg.drain_ms * 1000;
    assert_eq!(body["deadline_us"], deadline);
    assert!(body["freeze_us"].as_u64().unwrap() >= deadline);
    if let Some(traffic) = body.get("traffic") {
        assert_eq!(traffic["window_start_us"], epoch);
        assert_eq!(traffic["window_end_us"], end);
        let begin = traffic["sample_start_us"].as_u64().unwrap();
        let finish = traffic["sample_end_us"].as_u64().unwrap();
        assert!(begin >= deadline && finish >= begin);
        for (window, total) in [
            ("window_written_bytes", "written_bytes"),
            ("window_read_bytes", "read_bytes"),
        ] {
            assert!(
                traffic["counters"][window].as_u64().unwrap()
                    <= traffic["counters"][total].as_u64().unwrap()
            );
        }
    }
    let files = body["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    for (descriptor, name) in files.iter().zip(["requests.jsonl", "output.jsonl"]) {
        assert_eq!(descriptor["name"], name);
        let path = directory.join(name);
        assert!(
            !path.is_symlink() && fs::metadata(&path).unwrap().len() <= cfg.journal_limit_bytes
        );
        assert_eq!(*descriptor, file_record(path));
    }
    let counts: Vec<u64> = (0..cfg.members.len()).map(|i| count(&cfg, i)).collect();
    let mut rows = Vec::new();
    let mut populations = [0u64; 5];
    journal(
        directory.join("requests.jsonl"),
        cfg.journal_limit_bytes,
        |value| {
            let seq = rows.len() as u64;
            assert!(seq < counts[cfg.id]);
            assert_eq!(value["origin"], cfg.id);
            assert_eq!(value["sequence"], seq);
            assert_eq!(value["useful_bytes"], cfg.useful_bytes);
            assert_eq!(
                value["request_id"],
                hex::encode(Sha256::digest(transaction(&cfg, cfg.id, seq)))
            );
            let scheduled = scheduled(&cfg, cfg.id, seq, epoch);
            assert_eq!(value["scheduled_us"], scheduled);
            let time = |field: &str| {
                if value[field].is_null() {
                    0
                } else {
                    value[field].as_u64().unwrap()
                }
            };
            let row = Row {
                offered: time("offered_us"),
                admitted: time("admitted_us"),
                rejected: time("rejected_us"),
                cancelled: time("cancelled_us"),
                batch: time("batch_ready_us"),
                done: time("materialized_us"),
            };
            if row.offered == 0 {
                assert_eq!(
                    row.admitted + row.rejected + row.cancelled + row.batch + row.done,
                    0
                );
            } else {
                assert!(scheduled <= row.offered && row.offered < end);
                assert_eq!(
                    [row.admitted, row.rejected, row.cancelled]
                        .iter()
                        .filter(|t| **t != 0)
                        .count(),
                    1
                );
                for t in [row.admitted, row.rejected].iter().filter(|t| **t != 0) {
                    assert!(row.offered <= *t && *t < end);
                }
                if row.cancelled != 0 {
                    assert!(row.cancelled >= end && row.cancelled >= row.offered);
                }
                if row.admitted == 0 {
                    assert_eq!(row.batch + row.done, 0);
                }
                if row.batch != 0 {
                    assert!(row.admitted > 0 && row.batch >= row.admitted);
                }
                if row.done != 0 {
                    assert!(row.batch > 0 && row.done >= row.batch && row.done < deadline);
                }
            }
            for (i, t) in [
                row.offered,
                row.admitted,
                row.rejected,
                row.cancelled,
                row.done,
            ]
            .iter()
            .enumerate()
            {
                populations[i] += u64::from(*t != 0);
            }
            rows.push(row);
        },
    );
    assert_eq!(rows.len() as u64, counts[cfg.id]);
    let [offered, admitted, rejected, cancelled, completed] = populations;
    assert_eq!(
        body["populations"],
        json!({"planned":rows.len(),"offered":offered,"admitted":admitted,"rejected":rejected,"cancelled":cancelled,"completed":completed,"unfinished":admitted-completed,"unoffered":rows.len() as u64-offered})
    );
    let mut seen = vec![false; counts.iter().sum::<u64>() as usize];
    let mut credits = vec![false; rows.len()];
    let mut ordinal = 0;
    let mut last_round = 0;
    let mut last_time = epoch;
    journal(
        directory.join("output.jsonl"),
        cfg.journal_limit_bytes,
        |value| {
            assert_eq!(value["ordinal"], ordinal);
            let round = value["round"].as_u64().unwrap();
            assert!(round >= last_round);
            last_round = round;
            let at = value["materialized_us"].as_u64().unwrap();
            assert!(at >= last_time && at < deadline);
            last_time = at;
            let raw = hex::decode(value["native_header_bincode_hex"].as_str().unwrap()).unwrap();
            assert!(raw.len() <= 32 * 1024 * 1024);
            let header: crate::Header = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(raw.len() as u64)
                .reject_trailing_bytes()
                .deserialize(&raw)
                .unwrap();
            assert_eq!(bincode::serialize(&header).unwrap(), raw);
            assert_eq!(header.digest(), header.id);
            assert_eq!(value["header"], hex::encode(header.id.as_ref()));
            assert!(cfg.members.contains(&hex::encode(header.author.as_ref())));
            let mut expected = vec![];
            for tx in &header.payload {
                if let Some((origin, seq)) = identify(&cfg, tx) {
                    let index = (counts[..origin].iter().sum::<u64>() + seq) as usize;
                    let first = !seen[index];
                    seen[index] = true;
                    let own = origin == cfg.id && first && rows[seq as usize].admitted != 0;
                    if own {
                        assert_eq!(rows[seq as usize].done, at);
                        credits[seq as usize] = true;
                    }
                    expected.push(json!({"origin":origin,"sequence":seq,"request_id":hex::encode(Sha256::digest(tx)),"first_seen":first,"own_credit":own}));
                }
            }
            assert_eq!(value["transactions"], json!(expected));
            ordinal += 1;
        },
    );
    assert_eq!(body["output_rows"], ordinal);
    assert!(rows
        .iter()
        .enumerate()
        .all(|(i, r)| (r.done != 0) == credits[i]));
    println!(
        "{}",
        json!({"verified":true,"id":cfg.id,"output_rows":ordinal,"last_round":last_round,"populations":body["populations"]})
    );
}
