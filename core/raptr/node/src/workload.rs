//! Finite consensus-only application endpoint. Native signed transactions carry
//! an authenticated experiment identity; no Aptos VM execution is claimed.
use crate::{
    config::{self, Committee, Config},
    dissemination::NativeCommitSink,
};
use anyhow::{anyhow, ensure, Result};
use aptos_consensus_types::common::TransactionSummary;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_types::{
    chain_id::ChainId,
    transaction::{
        authenticator::{AuthenticationKey, TransactionAuthenticator},
        RawTransaction, Script, SignedTransaction, TransactionPayload,
    },
};
use delugi_raptr_core::{PublishedSection, SectionKind};
use futures::StreamExt;
use raptr_qs::mempool::{QuorumStoreRequest, QuorumStoreResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared_metrics::Operation;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Request {
    domain: String,
    run_id: String,
    origin: u32,
    sequence: u64,
    useful: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub sequence: u64,
    pub request_id: String,
    pub native_transaction_hash: String,
    pub useful_bytes: usize,
    pub planned_us: u64,
    pub admitted_us: Option<u64>,
    pub rejected_us: Option<u64>,
    pub rejection: Option<String>,
    pub own_batch_ready_us: Option<u64>,
    pub first_materialized_us: Option<u64>,
    pub admission_event: Option<u64>,
    pub rejection_event: Option<u64>,
    pub first_materialized_event: Option<u64>,
}
struct State {
    rows: Vec<Row>,
    pool: BTreeMap<TransactionSummary, SignedTransaction>,
    retained: usize,
    frozen: bool,
    output: Vec<Value>,
    journal_bytes: u64,
    seen: BTreeSet<String>,
    native_commits: u64,
    native_commit_transactions: u64,
    deadline_us: u64,
    next_event: u64,
    unadmitted_first_outputs: u64,
}
#[derive(Clone)]
pub struct Workload {
    config: Arc<Config>,
    committee: Arc<Committee>,
    id: u32,
    transactions: Arc<Vec<SignedTransaction>>,
    state: Arc<Mutex<State>>,
}
fn clock() -> u64 {
    shared_runtime::monotonic_us().expect("host monotonic clock")
}
fn summary(tx: &SignedTransaction) -> TransactionSummary {
    TransactionSummary::new(tx.sender(), tx.sequence_number(), tx.committed_hash())
}
fn useful(run: &str, origin: u32, seq: u64, len: usize) -> Vec<u8> {
    let seed = shared_crypto::sha256(
        &[
            b"finite-native-raptr-useful-v1",
            run.as_bytes(),
            &origin.to_le_bytes(),
            &seq.to_le_bytes(),
        ],
        None,
    );
    (0..len).map(|i| seed[i % 32]).collect()
}
fn request(config: &Config, origin: u32, sequence: u64) -> Request {
    Request {
        domain: "delugi-shared-finite-workload-v1".into(),
        run_id: config.run_id.clone(),
        origin,
        sequence,
        useful: useful(
            &config.run_id,
            origin,
            sequence,
            config.finite_workload.useful_bytes,
        ),
    }
}
pub fn identify(
    config: &Config,
    committee: &Committee,
    tx: &SignedTransaction,
) -> Result<(u32, u64, String)> {
    let script = match tx.payload() {
        TransactionPayload::Script(script) => script,
        _ => return Err(anyhow!("foreign transaction payload")),
    };
    let body: Request = shared_crypto_aptos::decode(script.code())?;
    ensure!(
        (body.origin as usize) < committee.members.len()
            && body.sequence < config.finite_workload.counts[body.origin as usize],
        "request outside finite manifest"
    );
    ensure!(
        body == request(config, body.origin, body.sequence)
            && script.ty_args().is_empty()
            && script.args().is_empty(),
        "foreign/noncanonical request"
    );
    let public = Ed25519PublicKey::try_from(
        config::unhex(&committee.members[body.origin as usize].transport_public)?.as_slice(),
    )?;
    ensure!(
        matches!(tx.authenticator_ref(),TransactionAuthenticator::Ed25519{public_key,..} if public_key==&public),
        "request signer differs from assigned origin"
    );
    ensure!(
        tx.sender() == AuthenticationKey::ed25519(&public).account_address()
            && tx.sequence_number() == body.sequence
            && tx.chain_id() == ChainId::test()
            && tx.max_gas_amount() == 1_000_000
            && tx.gas_unit_price() == 1
            && tx.expiration_timestamp_secs() == u64::MAX,
        "noncanonical native transaction envelope"
    );
    let _cost = shared_metrics::measure(Operation::WorkloadManifestVerify);
    tx.verify_signature()?;
    Ok((
        body.origin,
        body.sequence,
        config::digest(&shared_crypto_aptos::encode(tx)?),
    ))
}

impl Workload {
    pub fn prepare(
        config: Arc<Config>,
        committee: Arc<Committee>,
        id: u32,
        key: &shared_crypto::Keypair,
    ) -> Result<Self> {
        let private = Ed25519PrivateKey::try_from(key.secret.to_bytes().as_slice())?;
        let public = Ed25519PublicKey::from(&private);
        let sender = AuthenticationKey::ed25519(&public).account_address();
        let mut transactions = vec![];
        let mut rows = vec![];
        for sequence in 0..config.finite_workload.counts[id as usize] {
            let payload = shared_crypto_aptos::encode(&request(&config, id, sequence))?;
            let raw = RawTransaction::new_script(
                sender,
                sequence,
                Script::new(payload, vec![], vec![]),
                1_000_000,
                1,
                u64::MAX,
                ChainId::test(),
            );
            let tx = {
                let _cost = shared_metrics::measure(Operation::WorkloadManifestSign);
                raw.sign(&private, public.clone())?.into_inner()
            };
            let (_, _, request_id) = identify(&config, &committee, &tx)?;
            rows.push(Row {
                sequence,
                request_id,
                native_transaction_hash: config::hex(tx.committed_hash().as_ref()),
                useful_bytes: config.finite_workload.useful_bytes,
                planned_us: 0,
                admitted_us: None,
                rejected_us: None,
                rejection: None,
                own_batch_ready_us: None,
                first_materialized_us: None,
                admission_event: None,
                rejection_event: None,
                first_materialized_event: None,
            });
            transactions.push(tx);
        }
        Ok(Self {
            config,
            committee,
            id,
            transactions: Arc::new(transactions),
            state: Arc::new(Mutex::new(State {
                rows,
                pool: BTreeMap::new(),
                retained: 0,
                frozen: false,
                output: vec![],
                journal_bytes: 0,
                seen: BTreeSet::new(),
                native_commits: 0,
                native_commit_transactions: 0,
                deadline_us: 0,
                next_event: 1,
                unadmitted_first_outputs: 0,
            })),
        })
    }
    pub fn manifest(&self, configuration_sha256: &str) -> Result<Value> {
        Ok(
            json!({"schema":1,"profile":config::PROFILE,"run_id":self.config.run_id,"configuration_sha256":configuration_sha256,"origin":self.id,"requests":self.transactions.iter().enumerate().map(|(sequence,tx)| Ok(json!({"sequence":sequence,"request_id":config::digest(&shared_crypto_aptos::encode(tx)?),"native_transaction_bcs_hex":config::hex(&shared_crypto_aptos::encode(tx)?),"useful_bytes":self.config.finite_workload.useful_bytes}))).collect::<Result<Vec<_>>>()?}),
        )
    }
    /// Arm the independent shared ingress worker only after every process is ready.
    pub fn start(
        &self,
        epoch_us: u64,
        mut requests: futures_channel::mpsc::Receiver<QuorumStoreRequest>,
    ) -> Result<(shared_mempool::Worker, tokio::task::JoinHandle<Result<()>>)> {
        let now = clock();
        ensure!(now >= epoch_us, "ingress armed before epoch");
        let local_epoch = Instant::now()
            .checked_sub(Duration::from_micros(now - epoch_us))
            .context("local monotonic epoch mapping failed")?;
        let count = self.transactions.len() as u64;
        let start = self.config.finite_workload.start_delay_ms * 1000;
        let interval = self.config.finite_workload.interval_us;
        {
            let mut state = self.state.lock().unwrap();
            state.deadline_us =
                epoch_us + (self.config.measurement_duration_ms + self.config.drain_ms) * 1000;
            for row in &mut state.rows {
                row.planned_us = epoch_us + start + row.sequence * interval;
            }
        }
        let owner = self.clone();
        let capacity = self.config.limits.ingress_capacity;
        let (worker, rx, _finished) = shared_mempool::Worker::start(
            capacity,
            count,
            local_epoch,
            move |seq| start + seq * interval,
            move |seq, tx| {
                let mut state = owner.state.lock().unwrap();
                if state.frozen {
                    return;
                }
                let now = clock();
                if now >= state.deadline_us {
                    return;
                }
                let event = state.next_event;
                state.next_event += 1;
                if state.retained >= capacity {
                    let row = &mut state.rows[seq as usize];
                    row.rejected_us = Some(now);
                    row.rejection_event = Some(event);
                    row.rejection = Some("aggregate ingress/pool envelope exhausted".into());
                    return;
                }
                match tx.try_send((seq, owner.transactions[seq as usize].clone())) {
                    Ok(()) => {
                        state.rows[seq as usize].admitted_us = Some(now);
                        state.rows[seq as usize].admission_event = Some(event);
                        state.retained += 1;
                    }
                    Err(_) => {
                        let row = &mut state.rows[seq as usize];
                        row.rejected_us = Some(now);
                        row.rejection_event = Some(event);
                        row.rejection = Some("ingress mailbox full or closed".into());
                    }
                }
            },
        );
        let owner = self.clone();
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(1));
            loop {
                // Admission receipts are published under this same lock before
                // the native pool can see the corresponding transaction.
                {
                    let mut state = owner.state.lock().unwrap();
                    while let Ok((_seq, tx)) = rx.try_recv() {
                        state.pool.insert(summary(&tx), tx);
                    }
                }
                tokio::select! {
                    _=tick.tick()=>{},
                    req=requests.next()=>match req {
                        None=>break,
                        Some(QuorumStoreRequest::GetBatchRequest(max_txns,max_bytes,return_non_full,exclude,reply))=>{
                            let state=owner.state.lock().unwrap(); let mut batch=vec![];let mut bytes=0_u64;let mut full=false;
                            for (key,tx) in &state.pool {
                                if exclude.contains_key(key){continue;}
                                let size=shared_crypto_aptos::encode(tx)?.len() as u64;
                                if batch.len() as u64>=max_txns || bytes.checked_add(size).map_or(true,|v|v>max_bytes){full=true;break;}
                                bytes+=size;batch.push(tx.clone());
                            }
                            if !return_non_full && !full && (batch.len() as u64)<max_txns && bytes<max_bytes {batch.clear();}
                            let _=reply.send(Ok(QuorumStoreResponse::GetBatchResponse(batch)));
                        }
                        Some(QuorumStoreRequest::RejectNotification(rejected,reply))=>{
                            let mut state=owner.state.lock().unwrap();
                            for rejected in rejected {
                                let key=TransactionSummary::new(rejected.sender,rejected.sequence_number,rejected.hash);
                                if state.pool.remove(&key).is_some(){state.retained-=1;}
                            }
                            let _=reply.send(Ok(QuorumStoreResponse::CommitResponse()));
                        }
                    }
                }
            }
            Ok(())
        });
        Ok((worker, task))
    }
    pub fn publish(&self, section: PublishedSection<SignedTransaction>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.frozen || clock() >= state.deadline_us {
            return Ok(());
        }
        let mut batches = vec![];
        let mut completed = vec![];
        let mut new_ids = BTreeSet::new();
        let mut unadmitted = 0_u64;
        for batch in section.batches {
            let mut transactions = vec![];
            for tx in batch.transactions {
                let native_bcs = shared_crypto_aptos::encode(&tx)?;
                let identity = identify(&self.config, &self.committee, &tx);
                let (origin, sequence, request_id, eligible, first_seen, own_credit) =
                    match identity {
                        Ok((origin, seq, key)) => {
                            let first = !state.seen.contains(&key) && new_ids.insert(key.clone());
                            let credit = origin == self.id
                                && first
                                && state.rows[seq as usize].admission_event.is_some();
                            if credit {
                                completed.push(seq as usize);
                            } else if origin == self.id && first {
                                unadmitted += 1;
                            }
                            (Some(origin), Some(seq), key, true, first, credit)
                        }
                        Err(_) => (None, None, config::digest(&native_bcs), false, false, false),
                    };
                transactions.push(json!({"native_transaction_bcs_hex":config::hex(&native_bcs),"request_id":request_id,"origin":origin,"sequence":sequence,"eligible":eligible,"first_seen":first_seen,"own_credit":own_credit}));
            }
            let info = &batch.info;
            let key = &info.key;
            batches.push(json!({"key":{"epoch":key.epoch,"author":config::hex(&key.author),"nonce":key.nonce,"id":key.id,"digest":config::hex(&key.digest)},"native_info_bcs_hex":config::hex(&info.to_native_bcs()),"first_occurrence":batch.first_occurrence,"transactions":transactions}));
        }
        let kind = match section.kind {
            SectionKind::Proofs => json!({"kind":"proofs"}),
            SectionKind::SubBlock(index) => json!({"kind":"sub_block","index":index}),
        };
        let append_us = clock();
        // Verification may cross the declared endpoint. Do not extend the
        // observed cohort merely because the timer task was scheduled late.
        if append_us >= state.deadline_us {
            return Ok(());
        }
        let event = state.next_event;
        let output = json!({"schema":1,"ordinal":section.ordinal,"event":event,"append_us":append_us,"block":{"epoch":section.block.epoch,"round":section.block.round,"author":config::hex(&section.block.author),"digest":config::hex(&section.block.digest)},"section":kind,"batches":batches});
        // Bound the cumulative serialized journal separately from unresolved
        // materializer payloads. Failure cannot partially credit this section.
        let journal_bytes = state.journal_bytes
            .checked_add(serde_json::to_vec(&output)?.len() as u64 + 1)
            .context("journal byte overflow")?;
        ensure!(journal_bytes <= self.config.limits.max_journal_bytes,
            "cumulative application journal byte envelope exhausted");
        if clock() >= state.deadline_us {
            return Ok(());
        }
        state.journal_bytes = journal_bytes;
        state.seen.extend(new_ids);
        state.next_event += 1;
        state.unadmitted_first_outputs += unadmitted;
        for sequence in completed {
            state.rows[sequence].first_materialized_us = Some(append_us);
            state.rows[sequence].first_materialized_event = Some(event);
        }
        state.output.push(output);
        Ok(())
    }
    pub fn freeze(&self) -> (Vec<Row>, Vec<Value>, Value) {
        let mut state = self.state.lock().unwrap();
        state.frozen = true;
        let admitted = state
            .rows
            .iter()
            .filter(|r| r.admitted_us.is_some())
            .count();
        let rejected = state
            .rows
            .iter()
            .filter(|r| r.rejected_us.is_some())
            .count();
        let completed = state
            .rows
            .iter()
            .filter(|r| r.first_materialized_us.is_some())
            .count();
        let counts = json!({"planned":state.rows.len(),"offered":admitted+rejected,"completed":completed,"unoffered":state.rows.len()-admitted-rejected,"scheduled":state.rows.len(),"admitted":admitted,"rejected":rejected,"scheduled_not_offered":state.rows.len()-admitted-rejected,"origin_completed":completed,"unfinished":admitted-completed,"output_sections":state.output.len(),"unique_eligible_output":state.seen.len(),"unique_recognized_output":state.seen.len(),"unadmitted_first_outputs":state.unadmitted_first_outputs,"native_commit_callbacks":state.native_commits,"native_commit_transactions":state.native_commit_transactions,"retained_admitted_transactions":state.retained});
        (state.rows.clone(), state.output.clone(), counts)
    }
}
use anyhow::Context as _;
#[async_trait::async_trait]
impl NativeCommitSink for Workload {
    async fn native_commit(&self, transactions: &[SignedTransaction]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.native_commits += 1;
        state.native_commit_transactions += transactions.len() as u64;
        for tx in transactions {
            if state.pool.remove(&summary(tx)).is_some() {
                state.retained -= 1;
            }
        }
        Ok(())
    }
}
