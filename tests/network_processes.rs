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
fn prestart_frames_survive_and_producers_accept_consecutive_batches_without_reports() {
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
    // The producer accepts another batch without any reporting/receipt command.
    success(&addresses[4], token, "submit", Some(1));
    success(&addresses[4], token, "submit", Some(2));
    let producer = success(&addresses[4], token, "snapshot", None);
    assert_eq!(producer["holding_heights"][0], 2);
    assert_eq!(producer["observations"], 0);
    success(&addresses[7], token, "start", None);
    loop {
        let snapshot = success(&addresses[7], token, "snapshot", None);
        if snapshot["processed_messages"].as_u64().unwrap() > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "prestart mailbox was not processed"
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
