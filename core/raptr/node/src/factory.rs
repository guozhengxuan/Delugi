use crate::{
    config::{self, Arm, Config, Keys, PROFILE},
    dissemination::NativeDissemination,
    network::{self, NativeSender},
    output::Materializer,
    timer::NativeTimer,
    workload::Workload,
};
use anyhow::{anyhow, ensure, Result};
use aptos_consensus_types::proof_of_store::ProofCache;
use aptos_types::ledger_info::LedgerInfoWithSignatures;
use core_api::ProtocolFactory;
use delugi_raptr_core::Limits as OutputLimits;
use raptr::{
    framework::{module_network::ModuleNetwork, Protocol},
    raptr::Metrics,
};
use raptr_qs::{
    assembly::{Assembly, AssemblyConfig, LatestLedger},
    liveness::proposal_status_tracker::{
        ExponentialWindowFailureTracker, LockedExponentialWindowFailureTracker,
        OptQSPullParamsProvider,
    },
    payload_client::user::quorum_store_client::QuorumStoreClient,
    payload_manager::{QuorumStoreCommitNotifier, QuorumStorePayloadManager},
    quorum_store::quorum_store_db::QuorumStoreDB,
};
use raptr_shared_transport::{AsyncLimits, Auth, Context, Service};
use serde::Serialize;
use serde_json::{json, Value};
use std::{fs, path::Path, sync::Arc, time::Duration};

pub struct RaptrFactory;
impl ProtocolFactory for RaptrFactory {
    fn name(&self) -> &'static str {
        "raptr"
    }
    fn generate_keys(&self, path: &Path, n: usize) -> Result<String, String> {
        config::generate_keys(path, n).map_err(|e| e.to_string())
    }
    fn run(&self, bytes: &[u8], id: u32) -> Result<(), String> {
        let config = Config::parse(bytes, id).map_err(|e| e.to_string())?;
        shared_runtime_async::initialize_global_rayon(2)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(32)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        runtime
            .block_on(run(Arc::new(config), bytes, id))
            .map_err(|e| format!("{e:#}"))
    }
    fn verify_archive(&self, bytes: &[u8], path: &Path) -> Result<String, String> {
        crate::verify::verify_archive(bytes, path).map_err(|e| format!("{e:#}"))
    }
    fn verify_ledger(&self, bytes: &[u8], path: &Path) -> Result<String, String> {
        crate::verify::verify_receipt(bytes, path).map_err(|e| format!("{e:#}"))
    }
}
struct FixedGenesis(LedgerInfoWithSignatures);
impl LatestLedger for FixedGenesis {
    fn latest(&self) -> Result<LedgerInfoWithSignatures> {
        Ok(self.0.clone())
    }
}
fn clock() -> Result<u64> {
    shared_runtime::monotonic_us().map_err(anyhow::Error::msg)
}

async fn wait_arm(config: &Config, configuration_sha256: &str) -> Result<Arm> {
    let timeout = shared_runtime_async::time::Instant::now() + Duration::from_secs(45);
    loop {
        match fs::read(&config.arm_path) {
            Ok(bytes) => {
                let arm: Arm = serde_json::from_slice(&bytes)?;
                ensure!(
                    arm.schema == 1
                        && arm.run_id == config.run_id
                        && arm.configuration_sha256 == configuration_sha256,
                    "arm identity mismatch"
                );
                let now = clock()?;
                ensure!(
                    arm.epoch_us > now && arm.epoch_us - now <= 10_000_000,
                    "arm epoch must be within next10seconds"
                );
                return Ok(arm);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(
            shared_runtime_async::time::Instant::now() < timeout,
            "all-ready arm timeout"
        );
        shared_runtime_async::time::sleep(Duration::from_millis(1)).await;
    }
}
async fn until(deadline_us: u64) -> Result<()> {
    loop {
        let now = clock()?;
        if now >= deadline_us {
            return Ok(());
        }
        shared_runtime_async::time::sleep(Duration::from_micros(
            (deadline_us - now).min(1_000_000),
        ))
        .await;
    }
}
fn output_snapshot(s: delugi_raptr_core::Snapshot) -> Value {
    json!({"frozen":s.frozen,"published_sections":s.published_sections,"published_transactions":s.published_transactions,"pending_slices":s.pending_slices,"resolved_pending_slices":s.resolved_pending_slices,"pending_transactions":s.pending_transactions,"pending_payload_bytes":s.pending_payload_bytes})
}
fn journal(path: &Path, name: &str, rows: &[impl Serialize]) -> Result<Value> {
    let mut bytes = vec![];
    for row in rows {
        serde_json::to_writer(&mut bytes, row)?;
        bytes.push(b'\n');
    }
    config::write_new(&path.join(name), &bytes, false)?;
    Ok(json!({"name":name,"sha256":config::digest(&bytes),"bytes":bytes.len(),"rows":rows.len()}))
}
fn file_record(path: &Path, name: &str) -> Result<Value> {
    let bytes = fs::read(path.join(name))?;
    Ok(json!({"name":name,"sha256":config::digest(&bytes),"bytes":bytes.len(),"rows":1}))
}
async fn run(config: Arc<Config>, raw: &[u8], id: u32) -> Result<()> {
    let configuration_sha256 = config::digest(raw);
    let keys = Keys::load(&config.key_directory, id)?;
    ensure!(
        keys.authors.len() == config.addresses.len(),
        "config/key membership differs"
    );
    let directory = config.output_directory.join(format!("node-{id}"));
    fs::create_dir(&directory)?; // A result directory is never reused or overwritten.
    let committee = Arc::new(keys.committee.clone());
    let workload = Workload::prepare(config.clone(), committee, id, &keys.transport)?;
    config::write_json_new(
        &directory.join("workload-manifest.json"),
        &workload.manifest(&configuration_sha256)?,
        false,
    )?;
    let consensus = config.consensus.clone().unwrap_or_default();
    let qs_config = config.quorum_store.clone().unwrap_or_default();
    let limits = &config.limits;
    let context = Context {
        instance: config::unhex(&config.run_id)?
            .try_into()
            .map_err(|_| anyhow!("invalidrunID"))?,
        configuration: shared_crypto::sha256(&[raw, &keys.public_hash], None),
    };
    let auth = Auth::new(
        id,
        context,
        keys.transport_keys.clone(),
        keys.transport.clone(),
        limits.max_wire_bytes,
    )
    .map_err(anyhow::Error::msg)?;
    let mut settings = shared_network::TransportSettings::default();
    settings.inbox_capacity = limits.inbox_frames;
    settings.max_inbox_bytes = limits.inbox_bytes;
    let transport = shared_network::Transport::bind(id, auth, config.addresses.clone(), settings)
        .map_err(anyhow::Error::msg)?;
    let (mut service, shared_tx, shared_rx) = Service::start(
        transport,
        id,
        limits.max_wire_bytes,
        AsyncLimits {
            inbox_frames: limits.inbox_frames,
            inbox_bytes: limits.inbox_bytes,
            ..AsyncLimits::default()
        },
    )
    .map_err(anyhow::Error::msg)?;
    let sender = NativeSender::new(
        shared_tx,
        keys.authors.clone(),
        id as usize,
        limits.max_wire_bytes,
        limits.maximum_rpcs,
    )?;
    if let Some(fault) = &config.payload_fault {
        if fault.node == id {
            sender.configure_payload_fault(fault.drop_initial_batch_messages)?;
        }
    }
    let failure_sender = sender.clone();
    let executor = shared_runtime_async::Executor::new(
        tokio::runtime::Handle::current(),
        shared_runtime_async::Limits {
            max_async_tasks: limits.max_async_tasks,
            max_blocking_tasks: limits.max_blocking_tasks,
        },
        move |error| failure_sender.fail(error),
    )?;
    let node_tasks = executor.group("node")?;
    let network_tasks = executor.group("network")?;
    let dl_group = executor.group("dissemination")?;
    let qs_group = executor.group("quorum-store")?;
    let (pool_tx, pool_rx) = futures_channel::mpsc::channel(limits.ingress_capacity);
    let cache = ProofCache::new(10_000);
    fs::create_dir(directory.join("db"))?;
    let storage = Arc::new(QuorumStoreDB::open(directory.join("db"))?);
    let qs = Assembly::start(
        AssemblyConfig {
            epoch: config.epoch,
            author: keys.authors[id as usize],
            config: qs_config.clone(),
            num_validators: keys.authors.len() as u64,
            last_committed_timestamp: 0,
            is_new_epoch: true,
            broadcast_proofs: true,
        },
        raptr_qs::network::NetworkSender::new(Arc::new(sender.clone())),
        storage,
        keys.verifier.clone(),
        keys.consensus.clone(),
        pool_tx,
        consensus.mempool_txn_pull_timeout_ms,
        cache.clone(),
        Arc::new(FixedGenesis(keys.genesis.clone())),
        qs_group,
    )?;
    let payload_client = Arc::new(QuorumStoreClient::new(
        qs.payload_requests.clone(),
        consensus.quorum_store_pull_timeout_ms,
        consensus.wait_for_full_blocks_above_recent_fill_threshold,
        consensus.wait_for_full_blocks_above_pending_blocks,
    ));
    let manager = Arc::new(QuorumStorePayloadManager::new(
        qs.batch_reader.clone(),
        Box::new(QuorumStoreCommitNotifier::new(qs.coordinator.clone())),
        keys.authors.clone(),
        keys.verifier.address_to_validator_index().clone(),
    ));
    let tracker = Arc::new(LockedExponentialWindowFailureTracker::from(
        aptos_infallible::Mutex::new(ExponentialWindowFailureTracker::new(
            100,
            keys.authors.clone(),
        )),
    ));
    let provider = Arc::new(OptQSPullParamsProvider::new(
        qs_config.enable_opt_quorum_store,
        qs_config.opt_qs_minimum_batch_age_usecs,
        tracker.clone(),
    ));
    let (materializer, mut output) = Materializer::new(
        OutputLimits {
            max_slices: 100_000,
            max_sections: 900_000,
            max_batch_occurrences: 1_000_000,
            max_pending_transactions: limits.max_pending_transactions,
            max_pending_payload_bytes: limits.max_pending_payload_bytes,
        },
        limits.output_capacity,
    );
    let mut modules = ModuleNetwork::new();
    let core_module = modules.register().await;
    let dl_module = modules.register().await;
    let (dl, dl_tasks) = NativeDissemination::new(
        config.epoch,
        id as usize,
        keys.authors.clone(),
        consensus.clone(),
        payload_client,
        manager,
        provider,
        dl_module,
        sender.clone(),
        materializer.clone(),
        Arc::new(workload.clone()),
        dl_group,
        Duration::from_millis(config.materialization_delay_ms),
    )?;
    let native_config = raptr::rehost::native_config(
        keys.authors.len(),
        Duration::from_millis(config.delta_ms),
        shared_runtime_async::time::Instant::now() + Duration::from_secs(180),
    )?;
    let core = raptr::rehost::build_core(
        native_config,
        raptr::rehost::CommitteeKeys::new(keys.signer.clone(), keys.verifier.clone())?,
        dl,
        cache,
        Metrics {
            block_consensus_latency: None,
            batch_consensus_latency: None,
        },
        false,
        Some(tracker),
    )?;
    let (inbox, dispatcher) = network::dispatch(
        shared_rx,
        sender.clone(),
        core.verifier.clone(),
        qs.inbound.clone(),
        limits.inbox_frames,
        network_tasks,
    )?;
    let snapshot = sender.shared().snapshot();
    config::write_json_new(
        &directory.join("effective-profile.json"),
        &json!({"schema":1,"profile":PROFILE,"native_policy_commit":"a4c98047cf8aeae3571168d02fb7e343140d2948","transport":snapshot.transport,"consensus":consensus,"quorum_store":qs_config,"crypto":"nativeBCS/BLS/SHA3; ordinaryEd25519outertransport","storage":"blob-lz4-pipelined-v1 Written WAL enabled syncfalse","tokio_workers":2,"maximum_blocking_threads":32,"rayon_workers":2,"task_executor":"shared global queued-plus-running budgets; group-owned shutdown","endpoint_clock":"CLOCK_MONOTONIC; admission after successful enqueue/publication; output after verification and journal construction","proof_cache_entries":10000,"native_end_guard_seconds":180,"configured_delta_ms":config.delta_ms,"injected_delay_ms":0,"native_timer_multipliers":{"leader":4.0,"partial_qc":0.1,"fetch":2.0,"round_sync":15.0},"execution":"consensus-only, signed synthetic Script payload; no Aptos VM/state-sync; fixed quorum-signed genesis ledger","genesis_ledger_sha256":keys.committee.genesis_ledger_sha256,"committee_sha256":config::hex(&keys.public_hash),"materialization_delay_ms":config.materialization_delay_ms,"payload_fault":config.payload_fault,"limits":limits}),
        false,
    )?;
    config::write_json_new(
        &directory.join("ready.json"),
        &json!({"schema":1,"profile":PROFILE,"run_id":config.run_id,"configuration_sha256":configuration_sha256,"id":id,"pid":std::process::id(),"ready_us":clock()?}),
        false,
    )?;
    let arm = wait_arm(&config, &configuration_sha256).await?;
    until(arm.epoch_us).await?;
    shared_metrics::configure(true);
    let (mut ingress, pool_task) = workload.start(arm.epoch_us, pool_rx, node_tasks.clone())?;
    let (finish_tx, mut finish_rx) = tokio::sync::oneshot::channel::<()>();
    let consumer = workload.clone();
    let consumer_status = sender.clone();
    let output_task = node_tasks.spawn(async move {
        loop {
            tokio::select! {
                _=&mut finish_rx=>{while let Ok(section)=output.try_recv(){consumer.publish(section)?;}return Ok::<(),anyhow::Error>(());},
                section=output.recv()=>match section {
                    Some(section)=>if let Err(error)=consumer.publish(section){consumer_status.fail(&error);return Err(error);},
                    None=>return Ok(()),
                }
            }
        }
    });
    let mut protocol = node_tasks.spawn(Protocol::run(
        core.node,
        id as usize,
        inbox,
        core_module,
        NativeTimer::new(),
    ));
    let deadline_us = arm.epoch_us + (config.measurement_duration_ms + config.drain_ms) * 1000;
    let (mut result, protocol_finished) = tokio::select! {
        end=until(deadline_us)=>(end,false),
        error=sender.failed()=>(Err(anyhow!(error)),false),
        ended=&mut protocol=>(Err(anyhow!("native protocol ended before observer deadline: {ended:?}")),true),
    };
    ingress.stop();
    let (freeze_us, rows, outputs, counts) = workload.freeze();
    let snapshot_completed_us = clock()?;
    let materialized = materializer.freeze();
    let transport = sender.shared().snapshot();
    if let Some(error) = &transport.terminal_error {
        result = Err(anyhow!("transport failed at observer freeze: {error}"));
    }
    let costs = shared_metrics::snapshot();
    let payload_fault = sender.payload_fault_snapshot();
    let executor_at_freeze = executor.snapshot();
    if let Err(error) = executor.check() {
        result = Err(error.into());
    }
    if !protocol_finished {
        protocol.abort();
        let _ = protocol.await;
    }
    if let Err(error) = dl_tasks.shutdown().await {
        result = Err(error);
    }
    // The native QS shutdown coordinator preserves save/ack worker ordering.
    match shared_runtime_async::time::timeout(Duration::from_secs(10), qs.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => result = Err(error),
        Err(_) => result = Err(anyhow!("native QS shutdown timeout")),
    }
    dispatcher.abort();
    let _ = dispatcher.await;
    pool_task.abort();
    let _ = pool_task.await;
    let _ = finish_tx.send(());
    match output_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => result = Err(e),
        Err(e) => result = Err(e.into()),
    }
    match shared_runtime_async::time::timeout(Duration::from_secs(10), executor.shutdown()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => result = Err(error.into()),
        Err(_) => result = Err(anyhow!("shared task shutdown timeout; owned work remains")),
    }
    let executor_at_cleanup = executor.snapshot();
    service.shutdown();
    let mut files = vec![
        journal(&directory, "requests.jsonl", &rows)?,
        journal(&directory, "output.jsonl", &outputs)?,
    ];
    files.push(file_record(&directory, "workload-manifest.json")?);
    files.push(file_record(&directory, "effective-profile.json")?);
    let body = json!({"schema":1,"profile":PROFILE,"run_id":config.run_id,"configuration_sha256":configuration_sha256,"committee_sha256":config::hex(&keys.public_hash),"id":id,"epoch_us":arm.epoch_us,"deadline_us":deadline_us,"freeze_us":freeze_us,"snapshot_completed_us":snapshot_completed_us,"snapshot_copy_us":snapshot_completed_us.saturating_sub(freeze_us),"executor_at_freeze":executor_at_freeze,"executor_at_cleanup":executor_at_cleanup,"deadline_lateness_us":freeze_us.saturating_sub(deadline_us),"status":if result.is_ok(){"completed"}else{"failed"},"error":result.as_ref().err().map(|e|format!("{e:#}")),"files":files,"counts":counts,"transport":transport.transport,"async_transport":{"leased_bytes":transport.leased_bytes,"maximum_leased_bytes":transport.maximum_leased_bytes,"pending_bytes":transport.pending_bytes,"maximum_pending_bytes":transport.maximum_pending_bytes,"maximum_extra_pending_bytes":transport.maximum_extra_pending_bytes,"self_frames":transport.self_frames,"inbound_frames":transport.inbound_frames,"terminal_error":transport.terminal_error},"output_snapshot":output_snapshot(materialized),"materializer":materializer.delay_telemetry(),"payload_fault":payload_fault,"metrics":costs});
    let body_bcs = shared_crypto_aptos::encode(&serde_json::to_vec(&body)?)?;
    let mut signed = b"delugi-shared-observer-receipt-v1\0".to_vec();
    signed.extend_from_slice(&body_bcs);
    let signature = shared_crypto::sign_ed25519(
        &keys.transport,
        &signed,
        shared_metrics::Operation::ObserverReceiptSign,
    );
    config::write_json_new(
        &directory.join("final.json"),
        &json!({"schema":1,"signer":id,"body":body,"body_bcs_hex":config::hex(&body_bcs),"signature_hex":config::hex(&signature)}),
        false,
    )?;
    result
}
