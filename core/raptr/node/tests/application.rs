//! Signed archive fixtures use actual native transactions and batch payloads.
use anyhow::Result;
use aptos_consensus_types::proof_of_store::BatchId;
use aptos_types::transaction::SignedTransaction;
use raptr_qs::quorum_store::types::Batch;
use raptr_shared_node::{
    config::{self, Config, Keys},
    verify::{verify_archive, verify_receipt},
    workload::Workload,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    config: Vec<u8>,
    keys: Keys,
    body: Value,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
impl Fixture {
    fn new(planned: u64, output: bool, preplay: bool) -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "raptr-app-verify-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
            FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let key_dir = root.join("keys");
        config::generate_keys(&key_dir, 4)?;
        let keys = Keys::load(&key_dir, 0)?;
        let value = json!({"schema":1,"epoch":1,"run_id":"11".repeat(32),"key_directory":key_dir,"addresses":["127.0.0.1:29001","127.0.0.1:29002","127.0.0.1:29003","127.0.0.1:29004"],"output_directory":root,"arm_path":root.join("arm.json"),"delta_ms":100,"measurement_duration_ms":1000,"drain_ms":0,"finite_workload":{"counts":[planned,0,0,0],"useful_bytes":32,"interval_us":1,"start_delay_ms":0}});
        let config = serde_json::to_vec(&value)?;
        let parsed = Arc::new(Config::parse(&config, 0)?);
        let workload = Workload::prepare(
            parsed.clone(),
            Arc::new(keys.committee.clone()),
            0,
            &keys.transport,
        )?;
        let manifest = workload.manifest(&config::digest(&config))?;
        fs::write(
            root.join("workload-manifest.json"),
            serde_json::to_vec(&manifest)?,
        )?;
        let epoch = 10000_u64;
        let time = 10010_u64;
        let mut requests = vec![];
        let mut outputs = vec![];
        for (sequence, request) in manifest["requests"].as_array().unwrap().iter().enumerate() {
            let tx: SignedTransaction = bcs::from_bytes(&config::unhex(
                request["native_transaction_bcs_hex"].as_str().unwrap(),
            )?)?;
            requests.push(json!({"sequence":sequence,"request_id":request["request_id"],"native_transaction_hash":config::hex(tx.committed_hash().as_ref()),"useful_bytes":32,"planned_us":epoch+sequence as u64,"admitted_us":time,"rejected_us":null,"rejection":null,"own_batch_ready_us":null,"first_materialized_us":if output&&!preplay{Some(time)}else{None},"admission_event":if preplay{2}else{sequence as u64+1},"rejection_event":null,"first_materialized_event":if output&&!preplay{Some(planned+1)}else{None}}));
            if output {
                let batch = Batch::new(
                    BatchId::new_for_test(5),
                    vec![tx],
                    1,
                    2000000,
                    keys.authors[0],
                    0,
                );
                let info = delugi_raptr_core::BatchInfo::from_native_bcs(&bcs::to_bytes(
                    batch.batch_info(),
                )?)
                .unwrap();
                let key = &info.key;
                outputs.push(json!({"schema":1,"ordinal":0,"event":if preplay{1}else{planned+1},"append_us":time,"block":{"epoch":1,"round":1,"author":config::hex(&keys.authors[0].into_bytes()),"digest":"33".repeat(32)},"section":{"kind":"proofs"},"batches":[{"key":{"epoch":key.epoch,"author":config::hex(&key.author),"nonce":key.nonce,"id":key.id,"digest":config::hex(&key.digest)},"native_info_bcs_hex":config::hex(&info.to_native_bcs()),"first_occurrence":true,"transactions":[{"native_transaction_bcs_hex":request["native_transaction_bcs_hex"],"request_id":request["request_id"],"origin":0,"sequence":sequence,"eligible":true,"first_seen":true,"own_credit":!preplay}]}]}));
            }
        }
        assert!(planned <= 1, "small fixtures keep one batch");
        fn journal(path: PathBuf, rows: &[Value]) -> Result<()> {
            let mut bytes = vec![];
            for row in rows {
                bytes.extend(serde_json::to_vec(row)?);
                bytes.push(b'\n');
            }
            fs::write(path, bytes)?;
            Ok(())
        }
        journal(root.join("requests.jsonl"), &requests)?;
        journal(root.join("output.jsonl"), &outputs)?;
        fs::write(
            root.join("effective-profile.json"),
            serde_json::to_vec(
                &json!({"schema":1,"profile":config::PROFILE,"committee_sha256":config::digest(&fs::read(key_dir.join("committee.json"))?),"configured_delta_ms":100,"injected_delay_ms":0,"consensus":parsed.consensus.clone().unwrap_or_default(),"quorum_store":parsed.quorum_store.clone().unwrap_or_default(),"limits":parsed.limits}),
            )?,
        )?;
        let completed = if output && !preplay { planned } else { 0 };
        let counts = json!({"planned":planned,"scheduled":planned,"offered":planned,"admitted":planned,"rejected":0,"unoffered":0,"scheduled_not_offered":0,"completed":completed,"origin_completed":completed,"unfinished":planned-completed,"output_sections":outputs.len(),"unique_eligible_output":if output{planned}else{0},"unique_recognized_output":if output{planned}else{0},"unadmitted_first_outputs":if preplay{planned}else{0}});
        let body = json!({"schema":1,"profile":config::PROFILE,"id":0,"run_id":parsed.run_id,"configuration_sha256":config::digest(&config),"committee_sha256":config::digest(&fs::read(key_dir.join("committee.json"))?),"status":"completed","epoch_us":epoch,"deadline_us":epoch+1000000,"freeze_us":epoch+1000000,"files":[],"counts":counts,"async_transport":{"terminal_error":null},"output_snapshot":{"frozen":true,"published_sections":outputs.len(),"published_transactions":if output{planned}else{0}}});
        let mut fixture = Self {
            root,
            config,
            keys,
            body,
        };
        fixture.seal()?;
        Ok(fixture)
    }
    fn seal(&mut self) -> Result<()> {
        self.body["files"] = Value::Array(
            [
                "workload-manifest.json",
                "requests.jsonl",
                "output.jsonl",
                "effective-profile.json",
            ]
            .into_iter()
            .map(|name| {
                let bytes = fs::read(self.root.join(name)).unwrap();
                let rows = if name.ends_with("jsonl") {
                    bytes.iter().filter(|&&b| b == b'\n').count()
                } else {
                    1
                };
                json!({"name":name,"sha256":config::digest(&bytes),"bytes":bytes.len(),"rows":rows})
            })
            .collect(),
        );
        let body_bcs = bcs::to_bytes(&serde_json::to_vec(&self.body)?)?;
        let mut signed = b"delugi-shared-observer-receipt-v1\0".to_vec();
        signed.extend(&body_bcs);
        let signature = shared_crypto::sign_ed25519(
            &self.keys.transport,
            &signed,
            shared_metrics::Operation::ObserverReceiptSign,
        );
        fs::write(
            self.root.join("final.json"),
            serde_json::to_vec(
                &json!({"schema":1,"signer":0,"body":self.body,"body_bcs_hex":config::hex(&body_bcs),"signature_hex":config::hex(&signature)}),
            )?,
        )?;
        Ok(())
    }
    fn mutate_output(&self, change: impl FnOnce(&mut Value)) -> Result<()> {
        let mut value: Value = serde_json::from_slice(&fs::read(self.root.join("output.jsonl"))?)?;
        change(&mut value);
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        fs::write(self.root.join("output.jsonl"), bytes)?;
        Ok(())
    }
    fn verify(&self) -> Result<String> {
        verify_receipt(&self.config, &self.root.join("final.json"))
    }
}
#[test]
fn finite_healthy_empty_and_unfinished_signed_archives() -> Result<()> {
    for (planned, output, completed) in [(1, true, 1), (0, false, 0), (1, false, 0)] {
        let fixture = Fixture::new(planned, output, false)?;
        let result: Value = serde_json::from_str(&fixture.verify()?)?;
        assert_eq!(result["origin_completed"], completed);
        assert_eq!(result["planned"], planned);
    }
    Ok(())
}
#[test]
fn same_microsecond_preplay_is_retained_without_retroactive_credit() -> Result<()> {
    let mut fixture = Fixture::new(1, true, true)?;
    let result: Value = serde_json::from_str(&fixture.verify()?)?;
    assert_eq!(result["origin_completed"], 0);
    fixture
        .mutate_output(|row| row["batches"][0]["transactions"][0]["own_credit"] = json!(true))?;
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    Ok(())
}
#[test]
fn signed_file_hash_and_native_payload_mutation_are_rejected() -> Result<()> {
    let mut fixture = Fixture::new(1, true, false)?;
    fixture.mutate_output(|row| row["batches"][0]["first_occurrence"] = json!(false))?;
    assert!(fixture.verify().is_err());
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    fixture.mutate_output(|row| {
        row["batches"][0]["first_occurrence"] = json!(true);
        row["batches"][0]["transactions"] = json!([]);
    })?;
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    Ok(())
}
#[test]
fn event_order_and_section_gaps_are_rejected() -> Result<()> {
    let mut fixture = Fixture::new(1, true, false)?;
    fixture.mutate_output(|row| row["event"] = json!(1))?;
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    fixture.mutate_output(|row| {
        row["event"] = json!(2);
        row["ordinal"] = json!(1);
    })?;
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    Ok(())
}
#[test]
fn archive_rejects_duplicate_signers_and_path_escape() -> Result<()> {
    let fixture = Fixture::new(1, true, false)?;
    let mut index = json!({"schema":1,"run_id":"11".repeat(32),"configuration_sha256":config::digest(&fixture.config),"receipts":["final.json"]});
    let path = fixture.root.join("index.json");
    fs::write(&path, serde_json::to_vec(&index)?)?;
    assert!(verify_archive(&fixture.config, &path).is_ok());
    index["receipts"] = json!(["final.json", "final.json"]);
    fs::write(&path, serde_json::to_vec(&index)?)?;
    assert!(verify_archive(&fixture.config, &path).is_err());
    index["receipts"] = json!(["../final.json"]);
    fs::write(&path, serde_json::to_vec(&index)?)?;
    assert!(verify_archive(&fixture.config, &path).is_err());
    Ok(())
}
#[test]
fn displayed_receipt_cannot_override_signed_body() -> Result<()> {
    let fixture = Fixture::new(1, true, false)?;
    let path = fixture.root.join("final.json");
    let mut envelope: Value = serde_json::from_slice(&fs::read(&path)?)?;
    envelope["body"]["counts"]["origin_completed"] = json!(0);
    fs::write(&path, serde_json::to_vec(&envelope)?)?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[test]
fn frozen_transport_failure_cannot_claim_completed_status() -> Result<()> {
    let mut fixture = Fixture::new(0, false, false)?;
    fixture.body["async_transport"]["terminal_error"] = json!("injected frozen failure");
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[test]
fn signed_executor_evidence_requires_joined_owned_work_and_monotonic_counters() -> Result<()> {
    let mut fixture = Fixture::new(0, false, false)?;
    // Historical receipts without these fields stay readable.
    fixture.verify()?;
    let frozen = json!({
        "limits":{"max_async_tasks":8,"max_blocking_tasks":4},
        "admitted_async":3,"admitted_blocking":2,
        "started_async":2,"started_blocking":1,
        "body_finished_async":1,"body_finished_blocking":0,
        "joined_async":1,"joined_blocking":0,
        "cancelled_async":0,"cancelled_blocking":0,
        "panicked":0,"rejected_capacity":0,"rejected_closed":0,
        "retained_async":2,"retained_blocking":2,
        "queued_async":1,"queued_blocking":1,
        "active_async":1,"active_blocking":1,
        "maximum_retained_async":2,"maximum_retained_blocking":2,
        "groups":[{"id":0,"label":"native","closed":false,"retained":4}],
        "failure":null
    });
    let mut cleanup = frozen.clone();
    for (field, value) in [
        ("joined_async", 3),
        ("joined_blocking", 2),
        ("cancelled_async", 2),
        ("cancelled_blocking", 2),
        ("retained_async", 0),
        ("retained_blocking", 0),
        ("queued_async", 0),
        ("queued_blocking", 0),
        ("active_async", 0),
        ("active_blocking", 0),
    ] {
        cleanup[field] = json!(value);
    }
    cleanup["groups"][0]["closed"] = json!(true);
    cleanup["groups"][0]["retained"] = json!(0);
    fixture.body["executor_at_freeze"] = frozen;
    fixture.body["executor_at_cleanup"] = cleanup;
    fixture.seal()?;
    fixture.verify()?;
    let valid = fixture.body.clone();
    let changes = [
        ("/executor_at_cleanup/joined_async", json!(2)),
        ("/executor_at_cleanup/retained_blocking", json!(1)),
        ("/executor_at_cleanup/queued_async", json!(1)),
        ("/executor_at_cleanup/active_blocking", json!(1)),
        ("/executor_at_cleanup/failure", json!("owned failure")),
        ("/executor_at_cleanup/rejected_capacity", json!(1)),
        ("/executor_at_cleanup/groups/0/closed", json!(false)),
        ("/executor_at_cleanup/groups/0/retained", json!(1)),
        ("/executor_at_cleanup/groups/0/label", json!("replacement")),
        ("/executor_at_cleanup/groups/0/id", json!(1)),
        ("/executor_at_cleanup/body_finished_async", json!(0)),
        ("/executor_at_cleanup/maximum_retained_async", json!(1)),
        ("/executor_at_freeze/retained_async", json!(1)),
    ];
    for (path, value) in changes {
        fixture.body = valid.clone();
        *fixture.body.pointer_mut(path).unwrap() = value;
        fixture.seal()?;
        assert!(
            fixture.verify().is_err(),
            "accepted signed malformed evidence at {path}"
        );
    }
    for field in ["executor_at_freeze", "executor_at_cleanup"] {
        fixture.body = valid.clone();
        fixture.body.as_object_mut().unwrap().remove(field);
        fixture.seal()?;
        assert!(fixture.verify().is_err(), "accepted missing {field}");
    }
    Ok(())
}

#[test]
fn signed_snapshot_copy_timing_is_separate_from_freeze_and_checked() -> Result<()> {
    let mut fixture = Fixture::new(0, false, false)?;
    let freeze = fixture.body["freeze_us"].as_u64().unwrap();
    fixture.body["snapshot_completed_us"] = json!(freeze + 37);
    fixture.body["snapshot_copy_us"] = json!(37);
    fixture.seal()?;
    fixture.verify()?;
    for (completed, copy) in [(freeze - 1, 0), (freeze + 37, 36)] {
        fixture.body["snapshot_completed_us"] = json!(completed);
        fixture.body["snapshot_copy_us"] = json!(copy);
        fixture.seal()?;
        assert!(fixture.verify().is_err());
    }
    fixture
        .body
        .as_object_mut()
        .unwrap()
        .remove("snapshot_completed_us");
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[tokio::test]
async fn actual_publication_journal_overflow_is_atomic() -> Result<()> {
    use delugi_raptr_core::{BlockId, PublishedBatch, PublishedSection, SectionKind};
    use futures::SinkExt;
    use raptr_qs::mempool::{QuorumStoreRequest, QuorumStoreResponse};
    let fixture = Fixture::new(1, false, false)?;
    let mut config = Config::parse(&fixture.config, 0)?;
    config.measurement_duration_ms = 5000;
    config.limits.max_journal_bytes = 1;
    let workload = Workload::prepare(
        Arc::new(config),
        Arc::new(fixture.keys.committee.clone()),
        0,
        &fixture.keys.transport,
    )?;
    let (mut requests, receiver) = futures_channel::mpsc::channel(4);
    let epoch = shared_runtime::monotonic_us().map_err(anyhow::Error::msg)?;
    let executor = shared_runtime_async::Executor::new(
        tokio::runtime::Handle::current(),
        shared_runtime_async::Limits::default(),
        |_| {},
    )?;
    let (mut worker, task) =
        workload.start(epoch, receiver, executor.group("application-test")?)?;
    let transaction = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (reply, rx) = futures_channel::oneshot::channel();
            requests
                .send(QuorumStoreRequest::GetBatchRequest(
                    1,
                    1_000_000,
                    true,
                    Default::default(),
                    reply,
                ))
                .await?;
            let QuorumStoreResponse::GetBatchResponse(mut batch) = rx.await?? else {
                anyhow::bail!("unexpected native pool reply")
            };
            if let Some(tx) = batch.pop() {
                return Ok::<_, anyhow::Error>(tx);
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await??;
    worker.stop();
    let batch = Batch::new(
        BatchId::new_for_test(1),
        vec![transaction.clone()],
        1,
        u64::MAX,
        fixture.keys.authors[0],
        0,
    );
    let info =
        delugi_raptr_core::BatchInfo::from_native_bcs(&bcs::to_bytes(batch.batch_info())?).unwrap();
    let publication = workload.publish(PublishedSection {
        ordinal: 0,
        block: BlockId {
            epoch: 1,
            round: 1,
            author: fixture.keys.authors[0].into_bytes(),
            digest: [9; 32],
        },
        kind: SectionKind::Proofs,
        batches: vec![PublishedBatch {
            info,
            first_occurrence: true,
            transactions: vec![transaction],
        }],
    });
    assert!(publication.is_err());
    let (_freeze_us, rows, outputs, counts) = workload.freeze();
    assert!(outputs.is_empty());
    assert!(rows[0].admitted_us.is_some());
    assert!(rows[0].first_materialized_us.is_none());
    assert_eq!(counts["origin_completed"], 0);
    assert_eq!(counts["unique_recognized_output"], 0);
    assert_eq!(counts["unadmitted_first_outputs"], 0);
    task.abort();
    let _ = task.await;
    assert_eq!(executor.shutdown().await?.retained_async, 0);
    Ok(())
}
