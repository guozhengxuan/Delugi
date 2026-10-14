//! Independent-process regression; opt in where loopback sockets are permitted.
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn request(address: &str, token: &str, kind: &str, round: Option<u64>) -> Result<Value, String> {
    let mut socket = TcpStream::connect(address).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut command = json!({"token":token,"type":kind,"request_id":"smoke"});
    if let Some(round) = round {
        command["round"] = json!(round);
    }
    let mut bytes = serde_json::to_vec(&command).unwrap();
    bytes.push(b'\n');
    socket.write_all(&bytes).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(socket)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| e.to_string())
}

fn success(address: &str, token: &str, kind: &str, round: Option<u64>) -> Value {
    let reply = request(address, token, kind, round).unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    reply["data"].clone()
}

#[test]
#[ignore = "requires loopback socket permission; launches four real replica processes"]
fn prestart_frames_survive_and_prepared_producers_accept_consecutive_batches_before_auto_reports() {
    let binary = env!("CARGO_BIN_EXE_delugi-replica");
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "delugi-process-smoke-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let keygen = Command::new(binary)
        .args([
            "--keygen",
            directory.join("keys").to_str().unwrap(),
            "--nodes",
            "4",
        ])
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let keys: Value = serde_json::from_slice(&keygen.stdout).unwrap();
    let listeners: Vec<_> = (0..8)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect();
    drop(listeners);
    let token = "local-process-regression-capability";
    let configuration = json!({"instance":vec![94;32],"addresses":addresses[..4],"control_addresses":addresses[4..],
        "control_token":token,"public_keys":keys["public_keys"],"key_files":keys["key_files"],
        "bound_ms":250,"chunk_capacity":4,"workload_rounds":4,"silent":null,"max_runtime_ms":15_000});
    let path = directory.join("config.json");
    fs::write(&path, serde_json::to_vec(&configuration).unwrap()).unwrap();
    let mut children = Children(Vec::new());
    for id in 0..4 {
        children.0.push(
            Command::new(binary)
                .arg("--config")
                .arg(&path)
                .arg("--id")
                .arg(id.to_string())
                .stdout(Stdio::from(
                    File::create(directory.join(format!("replica-{id}.stdout"))).unwrap(),
                ))
                .stderr(Stdio::from(
                    File::create(directory.join(format!("replica-{id}.stderr"))).unwrap(),
                ))
                .spawn()
                .unwrap(),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    for address in &addresses[4..] {
        while request(address, token, "snapshot", None).is_err() {
            assert!(
                Instant::now() < deadline,
                "process startup timed out; logs: {}",
                directory.display()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
    assert_eq!(
        request(&addresses[7], "wrong-capability", "start", None).unwrap()["ok"],
        false
    );
    assert_eq!(
        success(&addresses[7], token, "snapshot", None)["started"],
        false
    );
    for address in &addresses[4..7] {
        success(address, token, "prepare", None);
    }
    // Prepared producers accept consecutive batches before ordering admission,
    // with no holding gate and no controller observation/report command.
    success(&addresses[4], token, "submit", Some(1));
    success(&addresses[4], token, "submit", Some(2));
    let producer = success(&addresses[4], token, "snapshot", None);
    assert_eq!(producer["holding_heights"][0], 2);
    assert_eq!(producer["started"], false);
    assert_eq!(producer["observations"], 0);
    for address in &addresses[4..7] {
        success(address, token, "start", None);
    }
    // This member is listening and ACKs packets, but its protocol has not started.
    loop {
        let snapshot = success(&addresses[7], token, "snapshot", None);
        let accepted: u64 = snapshot["transport"]["peers"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|peer| peer["layers"].as_object().unwrap().values())
            .map(|layer| layer["accepted_frames"].as_u64().unwrap())
            .sum();
        assert_eq!(snapshot["processed_messages"], 0);
        assert_eq!(snapshot["post_cutoff_frames"], 0);
        if accepted > 0 {
            break;
        }
        assert!(Instant::now() < deadline, "no prestart messages arrived");
        thread::sleep(Duration::from_millis(5));
    }
    success(&addresses[7], token, "start", None);
    loop {
        let snapshot = success(&addresses[7], token, "snapshot", None);
        if snapshot["processed_messages"].as_u64().unwrap() > 0
            && snapshot["observations"].as_u64().unwrap() > 0
            && snapshot["holding_heights"][0] == 2
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "prestart mailbox did not restore batches and answer automatic REPORT"
        );
        thread::sleep(Duration::from_millis(5));
    }
    for address in &addresses[4..] {
        success(address, token, "quiesce", None);
    }
    loop {
        let pending: u64 = addresses[4..]
            .iter()
            .map(|address| success(address, token, "snapshot", None))
            .map(|s| {
                s["transport"]["peers"]
                    .as_object()
                    .unwrap()
                    .values()
                    .map(|peer| peer["outstanding_frames"].as_u64().unwrap())
                    .sum::<u64>()
            })
            .sum();
        if pending == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "transport did not drain");
        thread::sleep(Duration::from_millis(5));
    }
    for address in &addresses[4..] {
        success(address, token, "stop", None);
    }
    for child in &mut children.0 {
        assert!(child.wait().unwrap().success());
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires loopback socket permission; launches a real replica and authenticated Byzantine peer"]
fn invalid_signed_report_is_rejected_without_stopping_subsequent_batch_progress() {
    use delugi::availability::{genesis_binding, AvailabilityConfig};
    use delugi::batch::BatchStore;
    use delugi::composed::Message;
    use delugi::transport::{Layer, Transport, TransportSettings};
    use delugi::wire::{self, Committee};

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "delugi-process-reject-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let committee = Committee::new(
        [96; 32],
        (0..4).map(|i| wire::fixture_key(i).public).collect(),
    )
    .unwrap();
    let key_path = directory.join("public-test-fixture.key");
    fs::write(&key_path, wire::fixture_key(0).secret.to_bytes()).unwrap();
    let listeners: Vec<_> = (0..8)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
    drop(listeners);
    let token = "local-byzantine-input-regression-capability";
    let configuration = json!({"instance":vec![96;32],"addresses":addresses[..4],"control_addresses":addresses[4..],
        "control_token":token,"public_keys":committee.keys.iter().map(|key|key.to_bytes().to_vec()).collect::<Vec<_>>(),
        "key_files":vec![key_path;4],"bound_ms":250,"chunk_capacity":4,
        "workload_rounds":4,"silent":null,"max_runtime_ms":15_000});
    let path = directory.join("config.json");
    fs::write(&path, serde_json::to_vec(&configuration).unwrap()).unwrap();
    let mut children = Children(vec![Command::new(env!("CARGO_BIN_EXE_delugi-replica"))
        .arg("--config")
        .arg(&path)
        .arg("--id")
        .arg("0")
        .stdout(Stdio::from(
            File::create(directory.join("replica.stdout")).unwrap(),
        ))
        .stderr(Stdio::from(
            File::create(directory.join("replica.stderr")).unwrap(),
        ))
        .spawn()
        .unwrap()]);
    let mut peer = Transport::bind(
        1,
        committee.clone(),
        wire::fixture_key(1),
        addresses[..4].to_vec(),
        TransportSettings::default(),
    )
    .unwrap();
    let address = addresses[4].to_string();
    let deadline = Instant::now() + Duration::from_secs(8);
    while request(&address, token, "snapshot", None).is_err() {
        assert!(Instant::now() < deadline, "replica startup timed out");
        thread::sleep(Duration::from_millis(5));
    }
    success(&address, token, "prepare", None);

    // Transport authentication succeeds, but the scheduled leader's REPORT
    // signature is corrupted. This bounded invalid protocol input must not
    // kill the receiver or consume its one observation for the opportunity.
    let availability = AvailabilityConfig::new(committee.clone(), 4).unwrap();
    let base = genesis_binding(&availability.mmr, 2, 4);
    let mut report = availability
        .report(&base, &wire::fixture_key(1), 1)
        .unwrap();
    report.signature[0] ^= 1;
    peer.send(
        0,
        Layer::Dissemination,
        wire::encode(&Message::Report {
            request: report,
            base,
        })
        .unwrap(),
    )
    .unwrap();
    let mut producer = BatchStore::new(committee, 4).unwrap();
    let record = producer
        .produce(&wire::fixture_key(1), 1, vec![17; 32])
        .unwrap();
    peer.send(
        0,
        Layer::Dissemination,
        wire::encode(&Message::Batch(record)).unwrap(),
    )
    .unwrap();
    loop {
        assert!(
            children.0[0].try_wait().unwrap().is_none(),
            "replica exited after bounded invalid peer input"
        );
        let snapshot = success(&address, token, "snapshot", None);
        if snapshot["holding_heights"][1] == 1 {
            assert_eq!(snapshot["rejected_protocol_messages"], 1);
            assert_eq!(snapshot["processed_messages"], 1);
            assert_eq!(snapshot["observations"], 0);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "valid batch after invalid REPORT was not processed"
        );
        thread::sleep(Duration::from_millis(5));
    }
    success(&address, token, "quiesce", None);
    while peer
        .snapshot()
        .peers
        .values()
        .any(|p| p.outstanding_frames != 0)
    {
        assert!(
            Instant::now() < deadline,
            "Byzantine peer transport did not drain"
        );
        thread::sleep(Duration::from_millis(5));
    }
    success(&address, token, "stop", None);
    assert!(children.0[0].wait().unwrap().success());
    peer.shutdown();
    let events: Vec<Value> = fs::read_to_string(directory.join("replica.stdout"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "protocol_rejected")
            .count(),
        1
    );
    assert!(!events.iter().any(|event| event["event"] == "fatal"));
    fs::remove_dir_all(directory).unwrap();
}
