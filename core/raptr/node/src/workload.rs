//! Finite consensus-only application endpoint. Native signed transactions carry
//! an authenticated experiment identity; no Aptos VM execution is claimed.
use crate::{
    archive::{Journal, Outputs, Rows, Slots},
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_event: Option<u64>,
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
    rows: Rows<Row>,
    pool: BTreeMap<TransactionSummary, SignedTransaction>,
    retained: usize,
    frozen: bool,
    output: Outputs,
    journal_bytes: u64,
    seen: Seen,
    native_commits: u64,
    native_commit_transactions: u64,
    deadline_us: u64,
    offer_deadline_us: u64,
    epoch_us: u64,
    sustained: bool,
    error: Option<String>,
    next_event: u64,
    unadmitted_first_outputs: u64,
}
struct Seen {
    bits: Vec<u64>,
    count: usize,
}
impl Seen {
    fn new(count: usize) -> Self {
        Self {
            bits: vec![0; (count + 63) / 64],
            count: 0,
        }
    }
    fn contains(&self, index: usize) -> bool {
        self.bits[index / 64] & (1u64 << (index % 64)) != 0
    }
    fn insert(&mut self, index: usize) {
        if !self.contains(index) {
            self.bits[index / 64] |= 1u64 << (index % 64);
            self.count += 1;
        }
    }
    fn len(&self) -> usize {
        self.count
    }
}

/// Admission linearizes only after the nonblocking offer succeeds and before
/// the deadline. The caller holds the same lock as the native pool consumer.
fn admit(
    state: &mut State,
    capacity: usize,
    sequence: u64,
    enqueue: impl FnOnce() -> Result<(), ()>,
    mut now: impl FnMut() -> u64,
) -> Result<()> {
    if state.frozen || state.error.is_some() {
        return Ok(());
    }
    let begun = now();
    let cutoff = if state.sustained {
        state.offer_deadline_us
    } else {
        state.deadline_us
    };
    if begun >= cutoff && !state.sustained {
        return Ok(());
    }
    let offered = if begun >= cutoff {
        Err("arrival window closed")
    } else if state.retained >= capacity {
        Err("aggregate ingress/pool envelope exhausted")
    } else {
        enqueue().map_err(|_| "ingress mailbox full or closed")
    };
    let finished_us = now();
    if finished_us >= cutoff && !state.sustained {
        return Ok(());
    }
    let event = state.next_event;
    let mut row = state.rows.read(sequence as usize)?;
    if state.sustained && row.offered_us.is_none() {
        row.offered_us = Some(begun);
    }
    if finished_us >= cutoff {
        row.cancelled_us = Some(finished_us);
        row.cancellation_event = Some(event);
        row.rejection =
            Some("offer crossed the measurement cutoff; tentative enqueue discarded".into());
    } else {
        match offered {
            Ok(()) => {
                row.admitted_us = Some(finished_us);
                row.admission_event = Some(event);
                state.retained += 1;
            }
            Err(error) => {
                row.rejected_us = Some(finished_us);
                row.rejection_event = Some(event);
                row.rejection = Some(error.into());
            }
        }
    }
    state.rows.write(sequence as usize, row)?;
    state.next_event += 1;
    Ok(())
}

fn timestamped_row_bytes(placeholder_bytes: u64, timestamp: u64) -> Option<u64> {
    // Replace the single-digit zero with the timestamp, then append a newline.
    placeholder_bytes.checked_add(timestamp.to_string().len() as u64)
}
#[derive(Clone)]
pub struct Workload {
    config: Arc<Config>,
    committee: Arc<Committee>,
    id: u32,
    transactions: Arc<Prepared>,
    planned_file: Option<Value>,
    state: Arc<Mutex<State>>,
}
enum Prepared {
    Memory(Vec<SignedTransaction>),
    Disk(Mutex<Slots>),
}
impl Prepared {
    fn len(&self) -> usize {
        match self {
            Self::Memory(v) => v.len(),
            Self::Disk(s) => s.lock().unwrap().len() as usize,
        }
    }
    fn get(&self, index: usize) -> Result<SignedTransaction> {
        match self {
            Self::Memory(v) => v.get(index).cloned().context("prepared request absent"),
            Self::Disk(s) => Ok(shared_crypto_aptos::decode(
                &s.lock().unwrap().read(index as u64)?,
            )?),
        }
    }
}

fn clock() -> u64 {
    shared_runtime::monotonic_us().expect("host monotonic clock")
}
fn summary(tx: &SignedTransaction) -> TransactionSummary {
    TransactionSummary::new(
        tx.sender(),
        tx.sequence_number(),
        shared_crypto_aptos::native_hashing(|| tx.committed_hash()),
    )
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
        tx.sender()
            == shared_crypto_aptos::native_hashing(
                || AuthenticationKey::ed25519(&public).account_address()
            )
            && tx.sequence_number() == body.sequence
            && tx.chain_id() == ChainId::test()
            && tx.max_gas_amount() == 1_000_000
            && tx.gas_unit_price() == 1
            && tx.expiration_timestamp_secs() == u64::MAX,
        "noncanonical native transaction envelope"
    );
    shared_crypto_aptos::workload_validation(|| tx.verify_signature())?;
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
        let sender = shared_crypto_aptos::native_hashing(|| {
            AuthenticationKey::ed25519(&public).account_address()
        });
        let count = config.finite_workload.counts[id as usize];
        let directory = config.output_directory.join(format!("node-{id}"));
        let mut transactions = if let Some(s) = &config.sustained_workload {
            Prepared::Disk(Mutex::new(Slots::create(
                &directory.join("prepared.spool"),
                count,
                config.finite_workload.useful_bytes + 1024,
                s.spool_limit_bytes,
            )?))
        } else {
            Prepared::Memory(vec![])
        };
        let mut rows = if let Some(s) = &config.sustained_workload {
            Rows::disk(
                &directory.join("requests.spool"),
                count,
                s.spool_limit_bytes,
            )?
        } else {
            Rows::Memory(vec![])
        };
        let mut planned = if config.schema == 2 {
            Some(Journal::create(
                &directory.join("planned.jsonl"),
                config
                    .sustained_workload
                    .as_ref()
                    .unwrap()
                    .spool_limit_bytes,
            )?)
        } else {
            None
        };
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
            let tx = shared_crypto_aptos::workload_signing(|| raw.sign(&private, public.clone()))?
                .into_inner();
            let (_, _, request_id) = identify(&config, &committee, &tx)?;
            let row = Row {
                sequence,
                request_id,
                native_transaction_hash: config::hex(
                    shared_crypto_aptos::native_hashing(|| tx.committed_hash()).as_ref(),
                ),
                useful_bytes: config.finite_workload.useful_bytes,
                planned_us: config.planned_offset_us(id, sequence)?,
                offered_us: None,
                prepared_us: None,
                cancelled_us: None,
                cancellation_event: None,
                admitted_us: None,
                rejected_us: None,
                rejection: None,
                own_batch_ready_us: None,
                first_materialized_us: None,
                admission_event: None,
                rejection_event: None,
                first_materialized_event: None,
            };
            if let Some(j) = &mut planned {
                j.append(&json!({"sequence":sequence,"request_id":row.request_id,
                "native_transaction_bcs_hex":config::hex(&shared_crypto_aptos::encode(&tx)?),"useful_bytes":config.finite_workload.useful_bytes}))?;
            }
            match &mut rows {
                Rows::Memory(v) => v.push(row),
                Rows::Disk(..) => rows.write(sequence as usize, row)?,
            };
            match &mut transactions {
                Prepared::Memory(v) => v.push(tx),
                Prepared::Disk(s) => s
                    .lock()
                    .unwrap()
                    .write(sequence, &shared_crypto_aptos::encode(&tx)?)?,
            };
        }
        let planned_file = planned.map(Journal::finish).transpose()?;
        let output = if config.schema == 2 {
            Outputs::Disk(Journal::create(
                &directory.join("output.jsonl"),
                config.limits.max_journal_bytes,
            )?)
        } else {
            Outputs::Memory(vec![])
        };
        let sustained = config.schema == 2;
        let population = config.finite_workload.counts.iter().sum::<u64>() as usize;
        Ok(Self {
            config,
            committee,
            id,
            transactions: Arc::new(transactions),
            planned_file,
            state: Arc::new(Mutex::new(State {
                rows,
                pool: BTreeMap::new(),
                retained: 0,
                frozen: false,
                output,
                journal_bytes: 0,
                seen: Seen::new(population),
                native_commits: 0,
                native_commit_transactions: 0,
                deadline_us: 0,
                offer_deadline_us: 0,
                epoch_us: 0,
                sustained,
                error: None,
                next_event: 1,
                unadmitted_first_outputs: 0,
            })),
        })
    }
    pub fn manifest(&self, configuration_sha256: &str) -> Result<Value> {
        let mut m = json!({"schema":self.config.schema,"profile":config::PROFILE,"run_id":self.config.run_id,
            "configuration_sha256":configuration_sha256,"origin":self.id});
        if let Some(file) = &self.planned_file {
            m["planned_file"] = file.clone();
        } else {
            m["requests"]=Value::Array((0..self.transactions.len()).map(|sequence| {
                let tx=self.transactions.get(sequence)?;let bytes=shared_crypto_aptos::encode(&tx)?;
                Ok(json!({"sequence":sequence,"request_id":config::digest(&bytes),"native_transaction_bcs_hex":config::hex(&bytes),"useful_bytes":self.config.finite_workload.useful_bytes}))
            }).collect::<Result<Vec<_>>>()?);
        }
        Ok(m)
    }
    pub fn planned_file(&self) -> Option<Value> {
        self.planned_file.clone()
    }
    /// Arm the independent shared ingress worker only after every process is ready.
    pub fn start(
        &self,
        epoch_us: u64,
        mut requests: futures_channel::mpsc::Receiver<QuorumStoreRequest>,
        task_group: shared_runtime_async::TaskGroup,
    ) -> Result<(
        shared_mempool::Worker,
        shared_runtime_async::Task<Result<()>>,
    )> {
        let now = clock();
        ensure!(now >= epoch_us, "ingress armed before epoch");
        let local_epoch = Instant::now()
            .checked_sub(Duration::from_micros(now - epoch_us))
            .context("local monotonic epoch mapping failed")?;
        let count = self.transactions.len() as u64;
        let schedule_config = self.config.clone();
        let origin = self.id;
        {
            let mut state = self.state.lock().unwrap();
            state.deadline_us =
                epoch_us + (self.config.measurement_duration_ms + self.config.drain_ms) * 1000;
            state.epoch_us = epoch_us;
            state.offer_deadline_us = epoch_us + self.config.measurement_duration_ms * 1000;
            if !state.sustained {
                for index in 0..state.rows.len() {
                    let mut row = state.rows.read(index)?;
                    row.planned_us =
                        epoch_us + self.config.planned_offset_us(self.id, row.sequence)?;
                    state.rows.write(index, row)?;
                }
            }
        }
        let owner = self.clone();
        let capacity = self.config.limits.ingress_capacity;
        let (worker, rx, _finished) = shared_mempool::Worker::start(
            capacity,
            count,
            local_epoch,
            move |seq| {
                schedule_config
                    .planned_offset_us(origin, seq)
                    .expect("validated arrival plan")
            },
            move |seq, tx| {
                // Preparing the independent arrival is outside the admission
                // endpoint. The pool cannot inspect a tentative enqueue until
                // this same lock publishes its successful admission.
                let offered = clock();
                let prepared = owner.transactions.get(seq as usize);
                let mut state = owner.state.lock().unwrap();
                let outcome = (|| -> Result<()> {
                    let prepared = prepared?;
                    if state.sustained {
                        let mut row = state.rows.read(seq as usize)?;
                        row.offered_us = Some(offered);
                        row.prepared_us = Some(clock());
                        state.rows.write(seq as usize, row)?;
                    }
                    admit(
                        &mut state,
                        capacity,
                        seq,
                        || tx.try_send((seq, prepared)).map_err(|_| ()),
                        clock,
                    )?;
                    Ok(())
                })();
                if let Err(e) = outcome {
                    state.error = Some(format!("{e:#}"));
                }
            },
        );
        let owner = self.clone();
        let task = task_group.spawn(async move {
            let mut tick = shared_runtime_async::time::interval(Duration::from_millis(1));
            loop {
                // Admission receipts are published under this same lock before
                // the native pool can see the corresponding transaction.
                {
                    let mut state = owner.state.lock().unwrap();
                    while let Ok((seq, tx)) = rx.try_recv() {
                        // An enqueue that crossed the observation deadline was
                        // tentative only; it must never enter the native pool.
                        if state.rows.read(seq as usize)?.admitted_us.is_some() {
                            state.pool.insert(summary(&tx), tx);
                        }
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
                            let index = self.config.finite_workload.counts[..origin as usize]
                                .iter()
                                .sum::<u64>() as usize
                                + seq as usize;
                            let first = !state.seen.contains(index) && new_ids.insert(index);
                            let credit = origin == self.id
                                && first
                                && state.rows.read(seq as usize)?.admission_event.is_some();
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
        let event = state.next_event;
        let mut output = json!({"schema":1,"ordinal":section.ordinal,"event":event,"append_us":0,"block":{"epoch":section.block.epoch,"round":section.block.round,"author":config::hex(&section.block.author),"digest":config::hex(&section.block.digest)},"section":kind,"batches":batches});
        // Bound the cumulative serialized journal separately from unresolved
        // materializer payloads. Failure cannot partially credit this section.
        // Complete expensive row construction and serialization before sampling
        // publication. Replacing the integer placeholder only changes its digits.
        let encoded_bytes = serde_json::to_vec(&output)?.len() as u64;
        let append_us = clock();
        if append_us >= state.deadline_us {
            return Ok(());
        }
        let journal_bytes = state
            .journal_bytes
            .checked_add(
                timestamped_row_bytes(encoded_bytes, append_us).context("journal row overflow")?,
            )
            .context("journal byte overflow")?;
        ensure!(
            journal_bytes <= self.config.limits.max_journal_bytes,
            "cumulative application journal byte envelope exhausted"
        );
        // The newline adds one byte and the placeholder removed one byte.
        output["append_us"] = append_us.into();
        state.journal_bytes = journal_bytes;
        state.output.push(output)?;
        for index in new_ids {
            state.seen.insert(index);
        }
        state.next_event += 1;
        state.unadmitted_first_outputs += unadmitted;
        for sequence in completed {
            let mut row = state.rows.read(sequence)?;
            row.first_materialized_us = Some(append_us);
            row.first_materialized_event = Some(event);
            state.rows.write(sequence, row)?;
        }
        Ok(())
    }
    pub fn freeze_archive(&self) -> Result<(u64, Frozen, Value)> {
        let mut state = self.state.lock().unwrap();
        state.frozen = true;
        let freeze_us = clock();
        let rows = std::mem::replace(&mut state.rows, Rows::Memory(vec![]));
        let output = std::mem::replace(&mut state.output, Outputs::Memory(vec![]));
        let counts = json!({"planned":rows.len(),"scheduled":rows.len(),"output_sections":output.len(),
            "unique_eligible_output":state.seen.len(),"unique_recognized_output":state.seen.len(),
            "unadmitted_first_outputs":state.unadmitted_first_outputs,"native_commit_callbacks":state.native_commits,
            "native_commit_transactions":state.native_commit_transactions,"retained_admitted_transactions":state.retained,
            "ingress_error":state.error});
        Ok((
            freeze_us,
            Frozen {
                rows,
                output,
                epoch_us: state.epoch_us,
                sustained: state.sustained,
            },
            counts,
        ))
    }
    // Compatibility helper for the accepted finite in-memory fixtures.
    pub fn freeze(&self) -> (u64, Vec<Row>, Vec<Value>, Value) {
        let (time, mut frozen, mut counts) = self.freeze_archive().expect("finite freeze");
        frozen.account(&mut counts).expect("finite accounting");
        match (frozen.rows, frozen.output) {
            (Rows::Memory(r), Outputs::Memory(o)) => (time, r, o, counts),
            _ => panic!("sustained archives must stream to disk"),
        }
    }
}

pub struct Frozen {
    rows: Rows<Row>,
    output: Outputs,
    epoch_us: u64,
    sustained: bool,
}
impl Frozen {
    fn account(&mut self, counts: &mut Value) -> Result<()> {
        let (mut admitted, mut rejected, mut cancelled, mut completed) = (0u64, 0u64, 0u64, 0u64);
        for index in 0..self.rows.len() {
            let row = self.rows.read(index)?;
            admitted += u64::from(row.admitted_us.is_some());
            rejected += u64::from(row.rejected_us.is_some());
            cancelled += u64::from(row.cancelled_us.is_some());
            completed += u64::from(row.first_materialized_us.is_some());
        }
        let offered = admitted + rejected + cancelled;
        for (key, value) in [
            ("admitted", admitted),
            ("rejected", rejected),
            ("cancelled", cancelled),
            ("completed", completed),
            ("origin_completed", completed),
            ("unfinished", admitted - completed),
            ("offered", offered),
            ("unoffered", self.rows.len() as u64 - offered),
            ("scheduled_not_offered", self.rows.len() as u64 - offered),
        ] {
            counts[key] = value.into();
        }
        Ok(())
    }
    pub fn write(
        mut self,
        directory: &std::path::Path,
        limit: u64,
        counts: &mut Value,
    ) -> Result<Vec<Value>> {
        self.account(counts)?;
        let mut journal = Journal::create(&directory.join("requests.jsonl"), limit)?;
        for index in 0..self.rows.len() {
            let mut row = self.rows.read(index)?;
            if self.sustained {
                row.planned_us = row
                    .planned_us
                    .checked_add(self.epoch_us)
                    .context("row clock overflow")?;
            }
            journal.append(&row)?;
        }
        let requests = journal.finish()?;
        self.rows.remove()?;
        Ok(vec![
            requests,
            self.output.finish(&directory.join("output.jsonl"), limit)?,
        ])
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

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    fn fixture_state() -> State {
        State {
            rows: Rows::Memory(vec![Row {
                sequence: 0,
                request_id: String::new(),
                native_transaction_hash: String::new(),
                useful_bytes: 0,
                planned_us: 10,
                offered_us: None,
                prepared_us: None,
                cancelled_us: None,
                cancellation_event: None,
                admitted_us: None,
                rejected_us: None,
                rejection: None,
                own_batch_ready_us: None,
                first_materialized_us: None,
                admission_event: None,
                rejection_event: None,
                first_materialized_event: None,
            }]),
            pool: BTreeMap::new(),
            retained: 0,
            frozen: false,
            output: Outputs::Memory(vec![]),
            journal_bytes: 0,
            seen: Seen::new(1),
            native_commits: 0,
            native_commit_transactions: 0,
            deadline_us: 100,
            offer_deadline_us: 100,
            epoch_us: 0,
            sustained: false,
            error: None,
            next_event: 1,
            unadmitted_first_outputs: 0,
        }
    }
    #[test]
    fn admission_records_success_endpoint_and_rejection_without_retroactive_credit() {
        let mut state = fixture_state();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let mut times = [10, 11].into_iter();
        admit(
            &mut state,
            1,
            0,
            || tx.try_send(7).map_err(|_| ()),
            || times.next().unwrap(),
        )
        .unwrap();
        assert_eq!(rx.try_recv().unwrap(), 7);
        assert_eq!(state.rows.read(0).unwrap().admitted_us, Some(11));
        assert_eq!(state.rows.read(0).unwrap().admission_event, Some(1));
        assert_eq!(state.retained, 1);
        let mut rejected = fixture_state();
        let mut times = [10, 13].into_iter();
        admit(&mut rejected, 1, 0, || Err(()), || times.next().unwrap()).unwrap();
        assert_eq!(rejected.rows.read(0).unwrap().rejected_us, Some(13));
        assert!(rejected.rows.read(0).unwrap().admission_event.is_none());
        assert_eq!(rejected.retained, 0);
    }
    #[test]
    fn deadline_crossing_enqueue_has_no_admission_or_event_and_frozen_never_offers() {
        let mut state = fixture_state();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let mut times = [99, 100].into_iter();
        admit(
            &mut state,
            1,
            0,
            || tx.try_send(7).map_err(|_| ()),
            || times.next().unwrap(),
        )
        .unwrap();
        assert_eq!(rx.try_recv().unwrap(), 7); // tentative bytes exist, membership does not
        assert!(state.rows.read(0).unwrap().admitted_us.is_none());
        assert!(state.rows.read(0).unwrap().rejection_event.is_none());
        assert_eq!((state.retained, state.next_event), (0, 1));
        state.frozen = true;
        admit(
            &mut state,
            1,
            0,
            || panic!("frozen workload offered"),
            || 99,
        )
        .unwrap();
        assert_eq!(state.next_event, 1);
    }
    #[test]
    fn sustained_cutoff_crossing_is_cancelled_and_cannot_enter_pool() {
        let mut state = fixture_state();
        state.sustained = true;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let mut times = [99, 100].into_iter();
        admit(
            &mut state,
            1,
            0,
            || tx.try_send(7).map_err(|_| ()),
            || times.next().unwrap(),
        )
        .unwrap();
        assert_eq!(rx.try_recv().unwrap(), 7);
        let row = state.rows.read(0).unwrap();
        assert_eq!(row.offered_us, Some(99));
        assert_eq!(row.cancelled_us, Some(100));
        assert!(row.admitted_us.is_none());
        assert!(row.rejected_us.is_none());
        assert_eq!(row.cancellation_event, Some(1));
        assert_eq!(state.retained, 0);
    }

    #[test]
    fn sustained_spools_stream_every_planned_identity_including_unoffered_tail() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "raptr-stream-fixture-{}-{}",
            std::process::id(),
            clock()
        ));
        std::fs::create_dir(&root)?;
        config::generate_keys(&root.join("keys"), 4)?;
        std::fs::create_dir(root.join("node-0"))?;
        let keys = config::Keys::load(&root.join("keys"), 0)?;
        let raw = serde_json::to_vec(&json!({"schema":2,"epoch":1,"run_id":"01".repeat(32),
            "key_directory":root.join("keys"),"addresses":["127.0.0.1:21001","127.0.0.1:21002","127.0.0.1:21003","127.0.0.1:21004"],
            "output_directory":root,"arm_path":root.join("arm.json"),"delta_ms":100,"measurement_duration_ms":1000,"drain_ms":0,
            "finite_workload":{"counts":[4,0,0,3],"useful_bytes":32,"interval_us":0,"start_delay_ms":0},
            "sustained_workload":{"total_honest_input_tps":7,"honest_origins":[0,3],"spool_limit_bytes":1048576}}))?;
        let c = Arc::new(Config::parse(&raw, 0)?);
        let w = Workload::prepare(c, Arc::new(keys.committee.clone()), 0, &keys.transport)?;
        assert!(matches!(&*w.transactions, Prepared::Disk(..)));
        assert!(matches!(&w.state.lock().unwrap().rows, Rows::Disk(..)));
        let manifest = w.manifest(&config::digest(&raw))?;
        assert!(manifest.get("requests").is_none());
        assert_eq!(manifest["planned_file"]["rows"], 4);
        let (_, archive, mut counts) = w.freeze_archive()?;
        archive.write(&root.join("node-0"), 1048576, &mut counts)?;
        assert_eq!(counts["unoffered"], 4);
        assert_eq!(counts["offered"], 0);
        let rows = std::fs::read_to_string(root.join("node-0/requests.jsonl"))?;
        let planned = rows
            .lines()
            .map(|l| serde_json::from_str::<Row>(l).unwrap().planned_us)
            .collect::<Vec<_>>();
        assert_eq!(planned, vec![0, 285714, 571428, 857142]);
        drop(w);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn publication_journal_bound_matches_actual_serialized_row_at_digit_boundaries() {
        let mut row = json!({"append_us":0,"transactions":["payload",7],"ordinal":2});
        let placeholder = serde_json::to_vec(&row).unwrap().len() as u64;
        for timestamp in [0, 9, 10, 99, 100, u64::MAX] {
            row["append_us"] = timestamp.into();
            assert_eq!(
                timestamped_row_bytes(placeholder, timestamp),
                Some(serde_json::to_vec(&row).unwrap().len() as u64 + 1)
            );
        }
        assert_eq!(timestamped_row_bytes(u64::MAX, 1), None);
    }
}
