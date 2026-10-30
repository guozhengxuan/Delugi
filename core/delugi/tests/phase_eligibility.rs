//! Offline diagnostic of the real signed core. Virtual message times exclude
//! CPU, queues, disk, TCP and serialization delay; serialization/checks still run.
//! No production guards, quorums, or constructor behavior are changed.
use delugi_core::availability::{
    AvailabilityConfig, AvailabilityProof, Descriptor, NamedBase, Observation,
};
use delugi_core::composed::{self, Effect, Node, ReportSchedule};
use delugi_core::end_to_end::transactions;
use delugi_core::mmr::Checkpoint;
use delugi_core::replica::{Effect as OrderingEffect, OrderingSchedule};
use delugi_core::wire::{self, Committee, Id, Message, Signed};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const N: Id = 4;
const D: u64 = 10_000;
type Links = [[u64; 4]; 4];

#[derive(Clone)]
enum Packet {
    Ordering(Message),
    Availability(composed::Message),
}
enum Event {
    Start(Id),
    Produce(Id, u64, String),
    Timer(Id),
    Deliver(Id, Id, Packet),
}
#[derive(Clone)]
struct Batch {
    origin: Id,
    height: u64,
    at: u64,
    checkpoint: Checkpoint,
    label: String,
}
struct Input {
    round: u64,
    leader: Id,
    report_at: u64,
    fixed_at: u64,
    value: Vec<u8>,
    proof: Vec<u8>,
    descriptor: Descriptor,
    pool: Vec<Signed<Observation>>,
    // Covering OBS count, usable OBS count, included, local target suffix/proof ready.
    eligibility: BTreeMap<(Id, u64), (usize, usize, bool, bool)>,
}
struct Proposal {
    round: u64,
    leader: Id,
    at: u64,
    descriptor: Descriptor,
}
struct Harness {
    committee: Committee,
    availability: AvailabilityConfig,
    nodes: Vec<Node>,
    links: Links,
    now: u64,
    serial: u64,
    queue: BTreeMap<(u64, u64), Event>,
    batches: Vec<Batch>,
    reports: BTreeMap<u64, (u64, NamedBase)>,
    delivered_obs: BTreeMap<u64, BTreeMap<Id, Signed<Observation>>>,
    inputs: BTreeMap<u64, Input>,
    proposals: Vec<Proposal>,
    received_proposal: BTreeMap<(Id, u64), u64>,
    snapshot_at: BTreeMap<(Id, u64), u64>,
    execution: BTreeMap<(Id, Id, u64), (u64, u64)>,
}
fn leader(round: u64) -> Id {
    ((round - 1) % u64::from(N)) as Id
}
impl Harness {
    fn new(links: Links, rounds: u64, chunk_capacity: u64) -> Self {
        let committee = Committee::new(
            [123; 32],
            (0..N).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap();
        let availability = AvailabilityConfig::new(committee.clone(), chunk_capacity).unwrap();
        let nodes = (0..N)
            .map(|i| {
                let mut n = Node::new(
                    committee.clone(),
                    i,
                    wire::fixture_key(i),
                    1_000_000,
                    availability.clone(),
                    chunk_capacity,
                )
                .unwrap();
                n.ordering
                    .configure_ordering(OrderingSchedule::Canonical)
                    .unwrap();
                n.configure_report_schedule(ReportSchedule::Pipeline)
                    .unwrap();
                n.set_opportunity_limit(rounds).unwrap();
                n
            })
            .collect();
        Self {
            committee,
            availability,
            nodes,
            links,
            now: 0,
            serial: 0,
            queue: BTreeMap::new(),
            batches: vec![],
            reports: BTreeMap::new(),
            delivered_obs: BTreeMap::new(),
            inputs: BTreeMap::new(),
            proposals: vec![],
            received_proposal: BTreeMap::new(),
            snapshot_at: BTreeMap::new(),
            execution: BTreeMap::new(),
        }
    }
    fn schedule(&mut self, at: u64, e: Event) {
        self.queue.insert((at, self.serial), e);
        self.serial += 1;
    }
    fn send(&mut self, from: Id, to: Option<Id>, packet: Packet) {
        match &packet {
            Packet::Availability(composed::Message::Report { base, .. }) => {
                assert!(self
                    .reports
                    .insert(base.opportunity, (self.now, base.clone()))
                    .is_none());
            }
            Packet::Ordering(Message::Propose(p)) => {
                let r = p.header.body.round;
                self.committee
                    .verify_proposal(p, |r, x, pi| self.availability.q(r, x, pi))
                    .unwrap();
                let input = &self.inputs[&r];
                assert_eq!(
                    p.value, input.value,
                    "observer reconstructed a different construction snapshot"
                );
                assert_eq!(
                    p.witness, input.proof,
                    "observer reconstructed a different frozen pool"
                );
                let proof: AvailabilityProof = self.committee.decode(&p.witness).unwrap();
                assert_eq!(proof.pool.len(), 3);
                assert!(self.proposals.iter().all(|prior| prior.round != r));
                self.proposals.push(Proposal {
                    round: r,
                    leader: from,
                    at: self.now,
                    descriptor: input.descriptor.clone(),
                });
                self.received_proposal.insert((from, r), self.now);
            }
            _ => {}
        }
        for recipient in to.map_or_else(|| (0..N).collect::<Vec<_>>(), |i| vec![i]) {
            if recipient != from {
                self.schedule(
                    self.now + self.links[from as usize][recipient as usize],
                    Event::Deliver(from, recipient, packet.clone()),
                );
            }
        }
    }
    fn observe_state(&mut self, id: Id) {
        // This is invoked immediately after the real handler, before another
        // network/workload event. Reconstruct the exact immutable first pool
        // and run the public pure constructor against that handler's store.
        for (&r, obs) in &self.nodes[id as usize].observations {
            self.snapshot_at.entry((id, r)).or_insert(self.now);
            if leader(r) == id {
                self.delivered_obs
                    .entry(r)
                    .or_default()
                    .entry(id)
                    .or_insert_with(|| obs.clone());
            }
        }
        let ready = self.nodes[id as usize]
            .input_ready
            .iter()
            .filter(|(r, _)| !self.inputs.contains_key(r))
            .map(|(&r, &at)| (r, at))
            .collect::<Vec<_>>();
        for (r, at) in ready {
            assert_eq!(leader(r), id);
            let (report_at, base) = &self.reports[&r];
            let pool = self.delivered_obs[&r].values().cloned().collect::<Vec<_>>();
            assert_eq!(pool.len(), 3, "must capture input before a fourth OBS");
            let store = &self.nodes[id as usize].store;
            let (value, proof) = self.availability.construct(base, store, &pool).unwrap();
            let descriptor: Descriptor = self.committee.decode(&value).unwrap();
            let mut eligibility = BTreeMap::new();
            for batch in &self.batches {
                let k = batch.origin as usize;
                let support = pool
                    .iter()
                    .filter(|o| o.body.coordinates[k].checkpoint.height >= batch.height)
                    .count();
                let covered_base = base.frontier[k].height >= batch.height;
                let usable = pool
                    .iter()
                    .filter(|o| {
                        let cp = &o.body.coordinates[k].checkpoint;
                        cp.height >= batch.height
                            && store.holds(&base.frontier[k], cp)
                            && (covered_base
                                || (store.proof(&base.frontier[k], &batch.checkpoint).is_ok()
                                    && store.proof(&batch.checkpoint, cp).is_ok()))
                    })
                    .count();
                let included = descriptor.targets[k].height >= batch.height;
                assert!(
                    !(usable >= 2 && !included),
                    "eligible exact honest prefix omitted"
                );
                let local_ready = covered_base
                    || (store.holds(&base.frontier[k], &batch.checkpoint)
                        && store.proof(&base.frontier[k], &batch.checkpoint).is_ok());
                eligibility.insert(
                    (batch.origin, batch.height),
                    (support, usable, included, local_ready),
                );
            }
            self.inputs.insert(
                r,
                Input {
                    round: r,
                    leader: id,
                    report_at: *report_at,
                    fixed_at: at,
                    value,
                    proof,
                    descriptor,
                    pool,
                    eligibility,
                },
            );
        }
        for b in &self.nodes[id as usize].materialized_batches {
            self.execution
                .entry((id, b.header.producer, b.header.height))
                .or_insert((self.now, b.round));
        }
    }
    fn emit(&mut self, id: Id, effects: Vec<Effect>) {
        // REPORT can be opened inside this handler; retain binding before
        // reconstructing any inputs generated in the same handler.
        for effect in &effects {
            if let Effect::Send {
                message: composed::Message::Report { base, .. },
                ..
            } = effect
            {
                self.reports
                    .entry(base.opportunity)
                    .or_insert((self.now, base.clone()));
            }
        }
        self.observe_state(id);
        for e in effects {
            match e {
                Effect::Send { to, message } => {
                    if matches!(&message, composed::Message::Report { .. }) {
                        // Binding was captured above; send() performs once-only assertion.
                        if let composed::Message::Report { base, .. } = &message {
                            self.reports.remove(&base.opportunity);
                        }
                    }
                    self.send(id, to, Packet::Availability(message));
                }
                Effect::Ordering(OrderingEffect::Send { to, message }) => {
                    self.send(id, to, Packet::Ordering(message))
                }
                Effect::Ordering(OrderingEffect::Wake { at }) => {
                    self.schedule(at, Event::Timer(id))
                }
                _ => {}
            }
        }
    }
    fn run(&mut self, until: u64) {
        let mut steps = 0;
        while self
            .queue
            .first_key_value()
            .is_some_and(|(&(at, _), _)| at <= until)
        {
            let ((at, _), event) = self.queue.pop_first().unwrap();
            self.now = at;
            let id = match &event {
                Event::Start(i) | Event::Produce(i, ..) | Event::Timer(i) => *i,
                Event::Deliver(_, to, _) => *to,
            };
            let effects = match event {
                Event::Start(_) => self.nodes[id as usize].start(at),
                Event::Timer(_) => self.nodes[id as usize].tick(at),
                Event::Produce(_, h, label) => {
                    let effects = self.nodes[id as usize]
                        .produce(at, wire::encode(&transactions(id, h, 1, 1)).unwrap())
                        .unwrap();
                    let checkpoint = self.nodes[id as usize]
                        .store
                        .checkpoints(id)
                        .into_iter()
                        .find(|p| p.height == h)
                        .unwrap();
                    self.batches.push(Batch {
                        origin: id,
                        height: h,
                        at,
                        checkpoint,
                        label,
                    });
                    Ok(effects)
                }
                Event::Deliver(from, _, packet) => match packet {
                    Packet::Ordering(message) => {
                        let encoded = self.committee.encode(&message).unwrap();
                        let round = if let Message::Propose(p) = &message {
                            Some(p.header.body.round)
                        } else {
                            None
                        };
                        let result = self.nodes[id as usize]
                            .receive_ordering(at, self.committee.decode(&encoded).unwrap());
                        if result.is_ok() {
                            if let Some(r) = round {
                                self.received_proposal.entry((id, r)).or_insert(at);
                            }
                        }
                        result
                    }
                    Packet::Availability(message) => {
                        let encoded = self.committee.encode(&message).unwrap();
                        let obs = if let composed::Message::Observation(o) = &message {
                            Some(o.clone())
                        } else {
                            None
                        };
                        let result = self.nodes[id as usize].receive(
                            at,
                            from,
                            self.committee.decode(&encoded).unwrap(),
                        );
                        if result.is_ok() {
                            if let Some(o) = obs {
                                let r = o.body.opportunity;
                                if !self.inputs.contains_key(&r) {
                                    self.delivered_obs
                                        .entry(r)
                                        .or_default()
                                        .entry(o.signer)
                                        .or_insert(o);
                                }
                            }
                        }
                        result
                    }
                },
            }
            .unwrap_or_else(|e| panic!("node{id} time{at}: {e}"));
            self.emit(id, effects);
            steps += 1;
            assert!(steps < 2_000_000);
        }
    }
    fn result(&self, label: &str, window: Option<(u64, u64)>) -> Value {
        let mut rows = vec![];
        for b in &self.batches {
            if window.is_some_and(|(lo, hi)| b.at < lo || b.at >= hi) {
                continue;
            }
            let p = self
                .proposals
                .iter()
                .filter(|p| p.descriptor.targets[b.origin as usize].height >= b.height)
                .min_by_key(|p| (p.at, p.round))
                .unwrap();
            let first = self
                .inputs
                .values()
                .filter(|i| i.descriptor.targets[b.origin as usize].height >= b.height)
                .min_by_key(|i| (i.fixed_at, i.round))
                .unwrap();
            let mut missed = BTreeMap::<String, usize>::new();
            for earlier in self
                .inputs
                .values()
                .filter(|i| i.fixed_at >= b.at && i.fixed_at <= p.at && i.round != p.round)
            {
                let reason = match earlier.eligibility.get(&(b.origin, b.height)) {
                    None => "not_broadcast_at_construction",
                    Some((_, _, true, _)) => "already_included_in_overlapping_input",
                    Some((support, _, false, _)) if *support < 2 => "insufficient_snapshot_support",
                    Some((_, usable, false, _)) if *usable < 2 => "source_or_proof_unready",
                    _ => "eligible_but_omitted",
                };
                *missed.entry(reason.into()).or_default() += 1;
            }
            let (output_at, execution_round) = self.execution[&(b.origin, b.origin, b.height)];
            // Read-only selection counterfactual: keep every ACTUAL proposal
            // time and input-construction snapshot, but ask whether the exact
            // local target suffix/proof existed without the OBS support rule.
            // This is not a valid modified Delugi execution or a Raptr estimate.
            let optimistic_candidates = self.proposals.iter().filter(|p| {
                self.inputs[&p.round]
                    .eligibility
                    .get(&(b.origin, b.height))
                    .is_some_and(|(_, _, included, local_ready)| *included || *local_ready)
            });
            let optimistic = optimistic_candidates
                .clone()
                .min_by_key(|p| (p.at, p.round))
                .unwrap();
            let optimistic_accept = optimistic_candidates
                .filter_map(|p| self.received_proposal.get(&(b.origin, p.round)).copied())
                .min()
                .unwrap();
            assert!(optimistic.at <= p.at);
            let execution_accept = self.received_proposal[&(b.origin, execution_round)];
            let first_accept = self
                .received_proposal
                .iter()
                .filter(|((id, r), _)| {
                    *id == b.origin
                        && self.inputs.get(r).is_some_and(|i| {
                            i.descriptor.targets[b.origin as usize].height >= b.height
                        })
                })
                .map(|(_, at)| *at)
                .min()
                .unwrap();
            rows.push(json!({"origin":b.origin,"height":b.height,"label":b.label,"batch_at_us":b.at,
                "first_proposal_round":p.round,"first_proposal_leader":p.leader,"first_proposal_us":p.at,
                "first_input_round":first.round,"first_input_us":first.fixed_at,
                "broadcast_to_first_proposal_ms":(p.at-b.at) as f64/1000.,
                "selection_counterfactual_proposal_round":optimistic.round,
                "selection_counterfactual_input_us":self.inputs[&optimistic.round].fixed_at,
                "selection_counterfactual_eligibility":self.inputs[&optimistic.round].eligibility[&(b.origin,b.height)],
                "selection_counterfactual_broadcast_to_proposal_ms":(optimistic.at-b.at) as f64/1000.,
                "selection_counterfactual_broadcast_to_acceptance_ms":(optimistic_accept-b.at) as f64/1000.,
                "selection_counterfactual_proposal_gain_ms":(p.at-optimistic.at) as f64/1000.,
                "broadcast_to_first_acceptance_ms":(first_accept-b.at) as f64/1000.,
                "broadcast_to_execution_acceptance_ms":(execution_accept-b.at) as f64/1000.,
                "broadcast_to_output_ms":(output_at-b.at) as f64/1000.,
                "execution_round":execution_round,"execution_leader":leader(execution_round),
                "missed_inputs":missed}));
        }
        let avg = |key: &str| {
            rows.iter().map(|r| r[key].as_f64().unwrap()).sum::<f64>() / rows.len() as f64
        };
        let per_origin=(0..N).map(|id|{let rs=rows.iter().filter(|r|r["origin"]==id).collect::<Vec<_>>();json!({"origin":id,"n":rs.len(),"broadcast_to_first_proposal_ms":rs.iter().map(|r|r["broadcast_to_first_proposal_ms"].as_f64().unwrap()).sum::<f64>()/rs.len() as f64,"broadcast_to_execution_acceptance_ms":rs.iter().map(|r|r["broadcast_to_execution_acceptance_ms"].as_f64().unwrap()).sum::<f64>()/rs.len() as f64})}).collect::<Vec<_>>();
        let opportunities=self.inputs.values().map(|i|json!({"round":i.round,"leader":i.leader,"report_us":i.report_at,"fixed_us":i.fixed_at,"base":i.descriptor.base,"frontier":i.descriptor.frontier.iter().map(|p|p.height).collect::<Vec<_>>(),"targets":i.descriptor.targets.iter().map(|p|p.height).collect::<Vec<_>>(),"pool":i.pool.iter().map(|o|json!({"signer":o.signer,"snapshot_us":self.snapshot_at[&(o.signer,i.round)],"heights":o.body.coordinates.iter().map(|c|c.checkpoint.height).collect::<Vec<_>>()})).collect::<Vec<_>>() })).collect::<Vec<_>>();
        json!({"label":label,"n":rows.len(),"links_us":self.links,"means_ms":{
            "broadcast_to_first_proposal":avg("broadcast_to_first_proposal_ms"),
            "selection_counterfactual_broadcast_to_proposal":avg("selection_counterfactual_broadcast_to_proposal_ms"),
            "selection_counterfactual_broadcast_to_acceptance":avg("selection_counterfactual_broadcast_to_acceptance_ms"),
            "selection_counterfactual_proposal_gain":avg("selection_counterfactual_proposal_gain_ms"),
            "broadcast_to_first_acceptance":avg("broadcast_to_first_acceptance_ms"),
            "broadcast_to_execution_acceptance":avg("broadcast_to_execution_acceptance_ms"),
            "broadcast_to_output":avg("broadcast_to_output_ms")},"by_origin":per_origin,"batches":rows,"opportunities":opportunities})
    }
}

#[test]
#[ignore = "offline real-core diagnostic; writes an explicitly selected local report"]
fn phase_and_wan_eligibility_diagnostic() {
    let mut uniform = [[D; 4]; 4];
    for i in 0..4 {
        uniform[i][i] = 0;
    }
    let mut run = Harness::new(uniform, 900, 4);
    for id in 0..N {
        run.schedule(2 * D, Event::Start(id));
    }
    for case in 0..40u64 {
        let phase = (case % 10) * 1000 + 500;
        let at = (40 + case * 20 + case / 10) * D + phase;
        for id in 0..N {
            run.schedule(
                at,
                Event::Produce(
                    id,
                    case + 1,
                    format!("phase_{phase}_rotation_{}", case / 10),
                ),
            );
        }
    }
    run.run(920 * D);
    let uniform_result = run.result("uniform_tagged_phase_sweep", None);
    assert_eq!(uniform_result["n"], 160);
    let uniform_mean = uniform_result["means_ms"]["broadcast_to_first_proposal"]
        .as_f64()
        .unwrap();
    assert!(
        (uniform_mean - 25.).abs() < 1e-8,
        "actual signed core differs from conditional phase prediction: {uniform_mean}"
    );
    let wan: Links = [
        [0, 80_000, 87_500, 32_200],
        [80_000, 0, 6_750, 97_000],
        [87_500, 6_750, 0, 120_000],
        [32_200, 97_000, 120_000, 0],
    ];
    let mut outputs = vec![uniform_result];
    for (label, offset_us, link_numerator, link_denominator, permutation) in [
        ("wan_symmetric_rtt_proxy", 0, 1, 1, [0, 1, 2, 3]),
        ("wan_arrival_phase_plus_5ms", 5_000, 1, 1, [0, 1, 2, 3]),
        ("wan_half_link_delays", 0, 1, 2, [0, 1, 2, 3]),
        ("wan_reversed_region_cycle", 0, 1, 1, [0, 3, 2, 1]),
    ] {
        // Profiles preserve or reverse physical-region assignment along leader
        // order, and apply the declared link scale without fitting latency.
        let links = std::array::from_fn(|i| {
            std::array::from_fn(|j| {
                wan[permutation[i]][permutation[j]] * link_numerator / link_denominator
            })
        });
        let mut run = Harness::new(links, 450, 64);
        for id in 0..N {
            run.schedule(0, Event::Start(id));
            for h in 1..=250u64 {
                run.schedule(
                    2_000_000 + offset_us + u64::from(id) * 10_000 + (h - 1) * 40_000,
                    Event::Produce(id, h, "sustained_100txps".into()),
                );
            }
        }
        run.run(16_000_000);
        let mut result = run.result(label, Some((2_000_000 + offset_us, 12_000_000 + offset_us)));
        result["configuration"] = json!({"empty_startup_us":2_000_000,"load_duration_us":10_000_000,"load_offset_us":offset_us,"aggregate_tx_per_second":100,"per_origin_interval_us":40_000,"origin_stagger_us":[0,10_000,20_000,30_000],"chunk_capacity":64,"transactions_per_batch":1,"useful_bytes_per_transaction":1,"link_scale":[link_numerator,link_denominator],"physical_region_per_replica":permutation});
        outputs.push(result);
    }
    let report = json!({"schema":1,"kind":"signed-core-phase-eligibility-v1","scope":"Real unchanged Delugi Node; deterministic virtual time, signed serialized messages, all proposal Q checks; excludes CPU/disk/network transport queueing. WAN links use half mean directional median RTT, assuming symmetry, not measured protocol one-way delay. A region-cycle permutation, arrival phase and link scaling probe sensitivity. Selection counterfactual removes OBS requirement ONLY in read-only analysis at fixed actual proposal times and input construction snapshots; it is neither a valid altered Delugi execution nor Raptr performance.","checks":{"eligible_but_omitted":0,"reconstructed_inputs_match_actual_proposals":true,"pool_size":3,"wa_support":2},"runs":outputs});
    let path =
        std::env::var("DELUGI_PHASE_REPORT").expect("set DELUGI_PHASE_REPORT to output JSON path");
    std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}",serde_json::to_string(&report["runs"].as_array().unwrap().iter().map(|r|json!({"label":r["label"],"n":r["n"],"means_ms":r["means_ms"],"by_origin":r["by_origin"]})).collect::<Vec<_>>()).unwrap());
}
