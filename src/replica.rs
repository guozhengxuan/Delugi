//! Complete deterministic ordering transitions, with an atomic in-memory outbox.
//!
//! The caller supplies monotonic local time and authenticated wire messages, then
//! drains the returned effects before scheduling further external events. Every
//! signature is still checked here. Self-delivery is drained in the same call.
//! State/evidence/outbox are retained for the process lifetime; crash recovery,
//! disk durability, dissemination and application execution are separate layers.
use crate::history::{self, CerProof, History, Report, ReportHeader};
use crate::scanner::{self, Delivery, Status};
use crate::slot::{Action, Slot, Terminal, Trigger};
use crate::wire::{
    self, Committee, Digest, Header, Id, Kind, Message, Proposal, Signed, Statement,
};
use ed25519_dalek::Keypair;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Immutable adapter configuration may be captured; mutable replica state must not be.
pub type Predicate = Box<dyn Fn(u64, &[u8], &[u8]) -> bool + Send + Sync>;
pub type Inputs = BTreeMap<u64, (Vec<u8>, Vec<u8>)>;
type Signatures = BTreeMap<(u64, Digest), BTreeMap<Id, Signed<Statement>>>;

#[derive(Clone, Debug)]
pub enum Effect {
    /// None means multicast. The caller sends to other members only; self has
    /// already been enqueued in this transition's local mailbox.
    Send {
        to: Option<Id>,
        message: Message,
    },
    Wake {
        at: u64,
    },
    DirectCommit {
        round: u64,
        digest: Digest,
    },
    Deliver(Delivery),
    Notice {
        kind: String,
        round: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    fn accepts(_: u64, _: &[u8], _: &[u8]) -> bool {
        true
    }
    fn node() -> Replica {
        let c = Committee::new(
            [42; 32],
            (0..4).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap();
        let mut n = Replica::new(c, 0, wire::fixture_key(0), 100, BTreeMap::new(), accepts);
        n.start(0).unwrap();
        n
    }
    fn short(n: &Replica, signer: Id, kind: Kind, r: u64, d: Option<Digest>) -> Signed<Statement> {
        wire::sign(
            &wire::fixture_key(signer),
            signer,
            Statement {
                context: n.committee.context.clone(),
                kind,
                round: r,
                digest: d,
            },
        )
    }
    fn closed(n: &mut Replica, at: u64, h: u64) {
        for i in [1, 2] {
            let s = short(n, i, Kind::Closed, h, None);
            n.receive(at, Message::Closed(s)).unwrap();
        }
    }
    fn enter(n: &mut Replica, at: u64, k: u64) -> Vec<Effect> {
        let mut effects = Vec::new();
        for i in [1, 2] {
            let s = short(n, i, Kind::Prog, k - 1, None);
            effects.extend(n.receive(at, Message::Prog(s)).unwrap());
        }
        effects
    }
    #[test]
    fn expired_catchup_waits_for_admission_and_never_restarts() {
        let mut n = node();
        closed(&mut n, 0, 1);
        assert_eq!(n.catchup_deadline(1), Some(300));
        n.tick(300).unwrap();
        assert_eq!(n.terminal(1), Terminal::Open);
        enter(&mut n, 350, 3);
        assert_eq!(n.terminal(1), Terminal::NoCer);
        closed(&mut n, 400, 1);
        assert_eq!(n.catchup_deadline(1), Some(300));
        assert!(n.own_reports.contains_key(&1));
    }
    #[test]
    fn exact_deadlines_and_every_exact_report_survive_prefix_catchup() {
        let mut n = node();
        closed(&mut n, 0, 1);
        closed(&mut n, 100, 5);
        assert_eq!(n.catchup_deadline(1), Some(300));
        assert_eq!(n.catchup_deadline(5), Some(400));
        enter(&mut n, 300, 3);
        assert_eq!(n.terminal(1), Terminal::NoCer);
        enter(&mut n, 350, 7);
        for r in 2..=5 {
            assert_eq!(
                n.terminal(r),
                Terminal::Open,
                "larger horizon inherited earlier expiry"
            );
        }
        let effects = n.tick(400).unwrap();
        for h in 2..=5 {
            assert_eq!(n.terminal(h), Terminal::NoCer);
            let report = n.own_reports.get(&h).unwrap();
            assert_eq!(report.header.body.horizon, h);
            history::verify_report(&n.committee, report).unwrap();
            let report_pos=effects.iter().position(|e|matches!(e,Effect::Send{message:Message::History3(r),..} if r.header.body.horizon==h)).unwrap();
            let closed_pos = effects
                .iter()
                .position(
                    |e| matches!(e,Effect::Send{message:Message::Closed(s),..} if s.body.round==h),
                )
                .unwrap();
            assert!(report_pos < closed_pos);
        }
        assert_eq!(n.own_reports.len(), 5);
        assert_eq!(n.closed_sent.len(), 5);
        assert!(!n.tick(401).unwrap().iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::History3(_) | Message::Closed(_),
                ..
            }
        )));
    }
    #[test]
    fn received_real_evidence_beats_expired_negative_timer_at_admission() {
        let mut n = node();
        let d = [7; 32];
        closed(&mut n, 0, 1);
        for i in [1, 2, 3] {
            let vote = short(&n, i, Kind::Vote, 1, Some(d));
            n.receive(
                299,
                Message::Vote {
                    vote,
                    header: None,
                    value: None,
                },
            )
            .unwrap();
        }
        assert_eq!(n.terminal(1), Terminal::Open);
        enter(&mut n, 300, 3);
        assert_eq!(n.terminal(1), Terminal::Cer(d));
        assert_eq!(n.main_deadline(1), Some(1000)); // arms even after own CER
        history::verify_proof(&n.committee, &n.own_proofs[&1]).unwrap();
        assert!(!n.proposals.keys().any(|(r, _)| *r == 1));
        assert!(n.deliveries.is_empty());
    }
    fn initial_proposal(n: &Replica, r: u64, value: Vec<u8>) -> Proposal {
        let history = History::Empty;
        let witness = Vec::new();
        let header = Header {
            context: n.committee.context.clone(),
            round: r,
            value_hash: wire::hash(&value),
            witness_hash: wire::hash(&witness),
            history_hash: wire::hash(&history),
            entries: history::project(r, &history),
        };
        Proposal {
            header: wire::sign(&wire::fixture_key(n.leader(r)), n.leader(r), header),
            value,
            witness,
            history,
        }
    }
    #[test]
    fn cer_before_proposal_then_one_matching_validated_vote() {
        let mut n = node();
        enter(&mut n, 0, 3);
        let p = initial_proposal(&n, 1, b"matching".to_vec());
        let d = wire::proposal_digest(&p.header.body);
        for i in [1, 2] {
            let s = short(&n, i, Kind::Cer, 1, Some(d));
            n.receive(10, Message::Cer(s)).unwrap();
        }
        assert_eq!(n.terminal(1), Terminal::Cer(d));
        assert_eq!(n.committed(1), Some(d));
        assert!(n.deliveries.is_empty());
        assert!(n.votes.get(&(1, d)).is_none());
        let effects = n.receive(20, Message::Propose(p.clone())).unwrap();
        assert_eq!(
            effects
                .iter()
                .filter(|e| matches!(
                    e,
                    Effect::Send {
                        message: Message::Vote { .. },
                        ..
                    }
                ))
                .count(),
            1
        );
        assert_eq!(n.deliveries.len(), 1);
        let again = n.receive(21, Message::Propose(p)).unwrap();
        assert!(!again.iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::Vote { .. },
                ..
            } | Effect::Deliver(_)
        )));
    }
    #[test]
    fn independent_vote_signature_and_later_matching_attachment() {
        let mut n = node();
        enter(&mut n, 0, 3);
        let p = initial_proposal(&n, 1, b"payload".to_vec());
        let d = wire::proposal_digest(&p.header.body);
        for i in [1, 2, 3] {
            let vote = short(&n, i, Kind::Vote, 1, Some(d));
            n.receive(
                10,
                Message::Vote {
                    vote,
                    header: None,
                    value: None,
                },
            )
            .unwrap();
        }
        assert_eq!(n.terminal(1), Terminal::Cer(d));
        let mut bad = p.header.clone();
        bad.signature[0] ^= 1;
        let vote = short(&n, 1, Kind::Vote, 1, Some(d));
        n.receive(
            11,
            Message::Vote {
                vote: vote.clone(),
                header: Some(bad),
                value: Some(p.value.clone()),
            },
        )
        .unwrap();
        assert!(!n.headers.contains_key(&(1, d)));
        n.receive(
            12,
            Message::Vote {
                vote,
                header: Some(p.header),
                value: Some(p.value.clone()),
            },
        )
        .unwrap();
        assert_eq!(n.values[&(1, d)], p.value);
        assert!(n.slots[&1].voted().is_none()); // attachment is not full validation
    }
    #[test]
    fn projected_positive_never_enters_actual_signature_store() {
        let mut n = node();
        enter(&mut n, 0, 6);
        let entries = history::Entries {
            horizon: 1,
            pivot: 1,
            digest: Some([9; 32]),
            previous: vec![],
        };
        let value = vec![1];
        let header = Header {
            context: n.committee.context.clone(),
            round: 4,
            value_hash: wire::hash(&value),
            witness_hash: [0; 32],
            history_hash: [0; 32],
            entries,
        };
        let d = wire::proposal_digest(&header);
        let header = wire::sign(&wire::fixture_key(3), 3, header);
        let vote = short(&n, 1, Kind::Vote, 4, Some(d));
        n.receive(
            10,
            Message::Vote {
                vote,
                header: Some(header),
                value: Some(value),
            },
        )
        .unwrap();
        assert!(n.cers.get(&(1, [9; 32])).is_none());
        assert!(n.proofs.get(&(1, [9; 32])).is_none());
        assert_eq!(n.terminal(1), Terminal::Open);
        assert_eq!(n.statuses[&1], Status::Undecided);
    }
    #[test]
    fn closed_is_not_echoed_and_does_not_assert_all_negative() {
        let mut n = node();
        let s = short(&n, 1, Kind::Closed, 1, None);
        let effects = n.receive(0, Message::Closed(s)).unwrap();
        assert!(!effects.iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::Closed(_),
                ..
            }
        )));
        assert_eq!(n.terminal(1), Terminal::Open);
    }
    #[test]
    fn invalid_external_input_is_rejected_before_fixing_or_hashing_it() {
        let mut n = node();
        let too_large = vec![0; wire::MAX_WIRE_BYTES];
        assert!(n.supply_input(0, 1, too_large, vec![]).is_err());
        assert!(!n.inputs.contains_key(&1));
        let effects = n.supply_input(0, 1, b"valid".to_vec(), vec![]).unwrap();
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::Propose(_),
                ..
            }
        )));
        let c = n.committee.clone();
        let bad = BTreeMap::from([(0, (vec![], vec![]))]);
        assert!(Replica::try_new(c, 0, wire::fixture_key(0), 100, bad, accepts).is_err());
    }
}

#[derive(Clone, Copy, Debug)]
struct Timer {
    deadline: u64,
    acted: bool,
}

pub struct Replica {
    committee: Committee,
    id: Id,
    key: Keypair,
    bound: u64,
    q: Predicate,
    inputs: Inputs,
    now: u64,
    started: bool,
    current: u64,
    cursor: u64,
    version: u64,
    slots: BTreeMap<u64, Slot>,
    votes: Signatures,
    cers: Signatures,
    progress: BTreeMap<u64, BTreeMap<Id, Signed<Statement>>>,
    closed: BTreeMap<u64, BTreeMap<Id, Signed<Statement>>>,
    progress_sent: BTreeSet<u64>,
    closed_sent: BTreeMap<u64, Signed<Statement>>,
    proposal_sent: BTreeSet<u64>,
    proposals: BTreeMap<(u64, Digest), Proposal>,
    headers: BTreeMap<(u64, Digest), Signed<Header>>,
    values: BTreeMap<(u64, Digest), Vec<u8>>,
    reports: BTreeMap<u64, BTreeMap<Id, Report>>,
    own_reports: BTreeMap<u64, Report>,
    own_proofs: BTreeMap<u64, CerProof>,
    proofs: BTreeMap<(u64, Digest), CerProof>,
    main_timers: BTreeMap<u64, Timer>,
    catchup_timers: BTreeMap<u64, Timer>,
    statuses: BTreeMap<u64, Status>,
    deliveries: Vec<Delivery>,
    inbox: VecDeque<Message>,
    outbox: Vec<Effect>,
}

impl Replica {
    pub fn new(
        committee: Committee,
        id: Id,
        key: Keypair,
        bound: u64,
        inputs: Inputs,
        q: impl Fn(u64, &[u8], &[u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self::try_new(committee, id, key, bound, inputs, q).expect("invalid replica configuration")
    }
    pub fn try_new(
        committee: Committee,
        id: Id,
        key: Keypair,
        bound: u64,
        inputs: Inputs,
        q: impl Fn(u64, &[u8], &[u8]) -> bool + Send + Sync + 'static,
    ) -> Result<Self, String> {
        if bound == 0
            || bound > u64::MAX / 7
            || committee.keys.get(id as usize) != Some(&key.public)
        {
            return Err("invalid timer bound or own identity/key".into());
        }
        for (round, (value, witness)) in &inputs {
            if *round == 0 || *round > wire::MAX_ROUND {
                return Err("invalid input round".into());
            }
            committee.validate_input_size(value, witness)?;
            if !q(*round, value, witness) {
                return Err("configured input fails Q".into());
            }
        }
        Ok(Self {
            committee,
            id,
            key,
            bound,
            q: Box::new(q),
            inputs,
            now: 0,
            started: false,
            current: 0,
            cursor: 0,
            version: 0,
            slots: BTreeMap::new(),
            votes: BTreeMap::new(),
            cers: BTreeMap::new(),
            progress: BTreeMap::new(),
            closed: BTreeMap::new(),
            progress_sent: BTreeSet::new(),
            closed_sent: BTreeMap::new(),
            proposal_sent: BTreeSet::new(),
            proposals: BTreeMap::new(),
            headers: BTreeMap::new(),
            values: BTreeMap::new(),
            reports: BTreeMap::new(),
            own_reports: BTreeMap::new(),
            own_proofs: BTreeMap::new(),
            proofs: BTreeMap::new(),
            main_timers: BTreeMap::new(),
            catchup_timers: BTreeMap::new(),
            statuses: BTreeMap::new(),
            deliveries: Vec::new(),
            inbox: VecDeque::new(),
            outbox: Vec::new(),
        })
    }
    fn quorum(&self) -> usize {
        self.committee.keys.len() - (self.committee.keys.len() - 1) / 3
    }
    fn amplification(&self) -> usize {
        (self.committee.keys.len() - 1) / 3 + 1
    }
    fn leader(&self, r: u64) -> Id {
        ((r - 1) % self.committee.keys.len() as u64) as Id
    }
    pub fn current_round(&self) -> u64 {
        self.current
    }
    pub fn last_delivered(&self) -> u64 {
        self.cursor
    }
    pub fn terminal(&self, r: u64) -> Terminal {
        self.slots.get(&r).map_or(Terminal::Open, Slot::terminal)
    }
    pub fn committed(&self, r: u64) -> Option<Digest> {
        self.slots.get(&r).and_then(Slot::committed)
    }
    pub fn deliveries(&self) -> &[Delivery] {
        &self.deliveries
    }
    pub fn own_reports(&self) -> &BTreeMap<u64, Report> {
        &self.own_reports
    }
    pub fn statuses(&self) -> &BTreeMap<u64, Status> {
        &self.statuses
    }
    pub fn main_deadline(&self, r: u64) -> Option<u64> {
        self.main_timers.get(&r).map(|t| t.deadline)
    }
    pub fn catchup_deadline(&self, h: u64) -> Option<u64> {
        self.catchup_timers.get(&h).map(|t| t.deadline)
    }

    pub fn start(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        self.set_time(now)?;
        if !self.started {
            self.started = true;
            self.enter(1)?;
        }
        self.settle()
    }
    pub fn receive(&mut self, now: u64, message: Message) -> Result<Vec<Effect>, String> {
        self.set_time(now)?;
        // Check an entire bounded frame before any state mutation from its fields.
        wire::encode(&message)?;
        self.ingest(message)?;
        self.settle()
    }
    pub fn tick(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        self.set_time(now)?;
        self.settle()
    }
    /// Explicit asynchronous input arrival for testing the external-readiness
    /// premise. Supplying late input does not reset any ordering timer.
    pub fn supply_input(
        &mut self,
        now: u64,
        round: u64,
        value: Vec<u8>,
        witness: Vec<u8>,
    ) -> Result<Vec<Effect>, String> {
        self.set_time(now)?;
        self.committee.validate_input_size(&value, &witness)?;
        if round == 0 || round > wire::MAX_ROUND || !(self.q)(round, &value, &witness) {
            return Err("invalid immutable input".into());
        }
        if self.inputs.contains_key(&round) {
            return Err("input already fixed for round".into());
        }
        self.inputs.insert(round, (value, witness));
        self.version += 1;
        self.settle()
    }
    fn set_time(&mut self, now: u64) -> Result<(), String> {
        if now < self.now {
            return Err("local clock moved backwards".into());
        }
        self.now = now;
        Ok(())
    }
    fn slot(&mut self, r: u64) -> &mut Slot {
        let n = self.committee.keys.len();
        let own = self.id;
        self.slots.entry(r).or_insert_with(|| Slot::new(r, n, own))
    }
    fn notice(&mut self, kind: &str, round: u64) {
        self.outbox.push(Effect::Notice {
            kind: kind.into(),
            round,
        });
    }
    fn signed(&self, kind: Kind, round: u64, digest: Option<Digest>) -> Signed<Statement> {
        wire::sign(
            &self.key,
            self.id,
            Statement {
                context: self.committee.context.clone(),
                kind,
                round,
                digest,
            },
        )
    }
    fn send(&mut self, to: Option<Id>, message: Message) -> Result<(), String> {
        wire::encode(&message)?;
        self.outbox.push(Effect::Send {
            to,
            message: message.clone(),
        });
        if to.is_none() || to == Some(self.id) {
            self.inbox.push_back(message);
        }
        Ok(())
    }
    fn send_progress(&mut self, r: u64) -> Result<(), String> {
        if self.progress_sent.insert(r) {
            self.version += 1;
            self.send(None, Message::Prog(self.signed(Kind::Prog, r, None)))?;
        }
        Ok(())
    }
    fn enter(&mut self, k: u64) -> Result<(), String> {
        if k > wire::MAX_ROUND {
            return Err("round representation exhausted".into());
        }
        if k > self.current {
            let old = self.current;
            self.current = k;
            self.version += 1;
            for r in old + 1..=k {
                self.slot(r);
                self.notice("admission", r);
                self.send_progress(r)?;
            }
        }
        Ok(())
    }
    fn retain_statement(&mut self, signed: Signed<Statement>) {
        let s = &signed.body;
        let r = s.round;
        let changed = match s.kind {
            Kind::Vote => {
                let d = s.digest.unwrap();
                self.slot(r).observe_vote(signed.signer, d);
                self.votes
                    .entry((r, d))
                    .or_default()
                    .insert(signed.signer, signed)
                    .is_none()
            }
            Kind::Cer => {
                let d = s.digest.unwrap();
                self.slot(r).observe_cer(signed.signer, d);
                self.cers
                    .entry((r, d))
                    .or_default()
                    .insert(signed.signer, signed)
                    .is_none()
            }
            Kind::Prog => self
                .progress
                .entry(r)
                .or_default()
                .insert(signed.signer, signed)
                .is_none(),
            Kind::Closed => self
                .closed
                .entry(r)
                .or_default()
                .insert(signed.signer, signed)
                .is_none(),
        };
        if changed {
            self.version += 1;
        }
    }
    fn retain_proof(&mut self, proof: CerProof) {
        let r = proof.cer.body.round;
        let d = proof.cer.body.digest.unwrap();
        self.retain_statement(proof.cer.clone());
        for s in &proof.triggers {
            self.retain_statement(s.clone());
        }
        if let std::collections::btree_map::Entry::Vacant(e) = self.proofs.entry((r, d)) {
            e.insert(proof);
            self.version += 1;
        }
    }
    fn retain_history(&mut self, history: &History) {
        if let History::Evidence {
            proof, previous, ..
        } = history
        {
            if let Some(p) = proof {
                self.retain_proof(p.clone());
            }
            for (_, p) in previous {
                if let Some(p) = p {
                    self.retain_proof(p.clone());
                }
            }
        }
    }
    fn retain_header(&mut self, r: u64, d: Digest, header: Signed<Header>, value: Option<Vec<u8>>) {
        if self.committee.verify_header(&header).is_err()
            || header.body.round != r
            || wire::proposal_digest(&header.body) != d
        {
            return;
        }
        if let Some(value) = value {
            if wire::hash(&value) == header.body.value_hash && !self.values.contains_key(&(r, d)) {
                self.values.insert((r, d), value);
                self.version += 1;
            }
        }
        if let std::collections::btree_map::Entry::Vacant(e) = self.headers.entry((r, d)) {
            e.insert(header);
            self.version += 1;
        }
    }
    fn checked_statement(&self, s: &Signed<Statement>, kind: Kind) -> Result<(), String> {
        self.committee.verify_statement(s)?;
        if s.body.kind != kind {
            return Err("outer message/statement kind mismatch".into());
        }
        Ok(())
    }
    fn ingest(&mut self, message: Message) -> Result<(), String> {
        match message {
            Message::Propose(p) => {
                self.committee.verify_proposal(&p, &self.q)?;
                let r = p.header.body.round;
                let d = wire::proposal_digest(&p.header.body);
                self.retain_header(r, d, p.header.clone(), Some(p.value.clone()));
                self.retain_history(&p.history);
                if !self.proposals.contains_key(&(r, d)) {
                    self.slot(r).validate(d);
                    self.proposals.insert((r, d), p);
                    self.version += 1;
                    self.notice("full_validation", r);
                }
            }
            Message::Vote {
                vote,
                header,
                value,
            } => {
                self.checked_statement(&vote, Kind::Vote)?;
                let r = vote.body.round;
                let d = vote.body.digest.unwrap();
                self.retain_statement(vote);
                // A missing or invalid attachment never suppresses a valid vote.
                if let Some(header) = header {
                    self.retain_header(r, d, header, value);
                }
            }
            Message::Cer(s) => {
                self.checked_statement(&s, Kind::Cer)?;
                self.retain_statement(s);
            }
            Message::Prog(s) => {
                self.checked_statement(&s, Kind::Prog)?;
                self.retain_statement(s);
            }
            Message::Closed(s) => {
                self.checked_statement(&s, Kind::Closed)?;
                self.retain_statement(s);
            }
            Message::History3(report) => {
                history::verify_report(&self.committee, &report)?;
                let h = report.header.body.horizon;
                for proof in &report.proofs {
                    self.retain_proof(proof.clone());
                }
                if self.leader(h + 3) == self.id {
                    let sender = report.header.signer;
                    if let std::collections::btree_map::Entry::Vacant(e) =
                        self.reports.entry(h).or_default().entry(sender)
                    {
                        e.insert(report);
                        self.version += 1;
                    }
                }
            }
        }
        Ok(())
    }
    fn apply_actions(&mut self, r: u64, actions: Vec<Action>) -> Result<(), String> {
        for action in actions {
            self.version += 1;
            match action {
                Action::Vote(d) => {
                    let signed = self.signed(Kind::Vote, r, Some(d));
                    self.retain_statement(signed.clone());
                    let header = self.headers[&(r, d)].clone();
                    let value = self.values[&(r, d)].clone();
                    self.send(
                        None,
                        Message::Vote {
                            vote: signed,
                            header: Some(header),
                            value: Some(value),
                        },
                    )?;
                }
                Action::Cer(d) => {
                    let trigger = self.slots[&r].proof().expect("CER retains proof").clone();
                    let triggers = match trigger {
                        Trigger::Votes(ids) => ids
                            .into_iter()
                            .map(|i| self.votes[&(r, d)][&i].clone())
                            .collect(),
                        Trigger::Cers(ids) => ids
                            .into_iter()
                            .map(|i| self.cers[&(r, d)][&i].clone())
                            .collect(),
                    };
                    let cer = self.signed(Kind::Cer, r, Some(d));
                    let proof = CerProof {
                        cer: cer.clone(),
                        triggers,
                    };
                    history::verify_proof(&self.committee, &proof)?;
                    self.own_proofs.insert(r, proof.clone());
                    self.retain_proof(proof);
                    self.send(None, Message::Cer(cer))?;
                }
                Action::DirectCommit(d) => {
                    assert!(self
                        .cers
                        .get(&(r, d))
                        .is_some_and(|s| s.len() >= self.quorum()));
                    self.outbox.push(Effect::DirectCommit {
                        round: r,
                        digest: d,
                    });
                }
            }
        }
        Ok(())
    }
    fn drive_slots(&mut self) -> Result<(), String> {
        let rounds: Vec<_> = self.slots.keys().copied().collect();
        for r in rounds {
            let actions = self.slots.get_mut(&r).unwrap().drive(self.current);
            self.apply_actions(r, actions)?;
        }
        Ok(())
    }
    fn drive_progress(&mut self) -> Result<(), String> {
        let counts: Vec<_> = self.progress.iter().map(|(r, v)| (*r, v.len())).collect();
        for (r, n) in counts {
            if n >= self.amplification() {
                self.send_progress(r)?;
            }
            if n >= self.quorum() {
                self.enter(r + 1)?;
            }
        }
        Ok(())
    }
    fn make_reports(&mut self) -> Result<(), String> {
        let mut prefix = 0;
        while prefix < self.current.saturating_sub(2) && self.terminal(prefix + 1) != Terminal::Open
        {
            prefix += 1;
        }
        for h in 1..=prefix {
            if self.own_reports.contains_key(&h) {
                continue;
            }
            let proofs: Vec<_> = self
                .own_proofs
                .range(..=h)
                .rev()
                .take(3)
                .map(|(_, p)| p.clone())
                .collect();
            let positives = proofs
                .iter()
                .map(|p| (p.cer.body.round, p.cer.body.digest.unwrap()))
                .collect();
            let report = Report {
                header: wire::sign(
                    &self.key,
                    self.id,
                    ReportHeader {
                        context: self.committee.context.clone(),
                        horizon: h,
                        positives,
                    },
                ),
                proofs,
            };
            history::verify_report(&self.committee, &report)?;
            // Queue the complete exact report before signing and queuing CLOSED.
            self.send(Some(self.leader(h + 3)), Message::History3(report.clone()))?;
            self.own_reports.insert(h, report);
            self.version += 1;
            let closed = self.signed(Kind::Closed, h, None);
            self.closed_sent.insert(h, closed.clone());
            self.send(None, Message::Closed(closed))?;
        }
        Ok(())
    }
    fn propose(&mut self) -> Result<(), String> {
        let ready: Vec<_> = self
            .inputs
            .range(..=self.current)
            .filter(|(r, _)| self.leader(**r) == self.id && !self.proposal_sent.contains(r))
            .map(|(r, x)| (*r, x.clone()))
            .collect();
        for (r, (value, witness)) in ready {
            if !(self.q)(r, &value, &witness) {
                return Err("configured input fails Q".into());
            }
            let reports = self
                .reports
                .get(&r.saturating_sub(3))
                .map(|v| v.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            if r > 3 && reports.len() < self.quorum() {
                continue;
            }
            let proofs: Vec<_> = self.proofs.values().cloned().collect();
            let history = history::build_history(&self.committee, r, &reports, &proofs)?;
            let header = Header {
                context: self.committee.context.clone(),
                round: r,
                value_hash: wire::hash(&value),
                witness_hash: wire::hash(&witness),
                history_hash: wire::hash(&history),
                entries: history::project(r, &history),
            };
            let proposal = Proposal {
                header: wire::sign(&self.key, self.id, header),
                value,
                witness,
                history,
            };
            self.committee.verify_proposal(&proposal, &self.q)?;
            self.send(None, Message::Propose(proposal))?;
            self.proposal_sent.insert(r);
            self.version += 1;
        }
        Ok(())
    }
    fn arm_timers(&mut self) -> Result<(), String> {
        for r in 1..=self.current.saturating_sub(2) {
            let ready = r <= 3
                || self
                    .closed
                    .get(&(r - 3))
                    .is_some_and(|s| s.len() >= self.quorum());
            if ready && !self.main_timers.contains_key(&r) {
                let deadline = self
                    .now
                    .checked_add(7 * self.bound)
                    .ok_or("timer clock overflow")?;
                self.main_timers.insert(
                    r,
                    Timer {
                        deadline,
                        acted: false,
                    },
                );
                self.outbox.push(Effect::Wake { at: deadline });
                self.notice("main_timer_arm", r);
                self.version += 1;
            }
        }
        let horizons: Vec<_> = self
            .closed
            .iter()
            .filter(|(_, s)| s.len() >= self.amplification())
            .map(|(h, _)| *h)
            .collect();
        for h in horizons {
            if !self.catchup_timers.contains_key(&h) {
                let deadline = self
                    .now
                    .checked_add(3 * self.bound)
                    .ok_or("timer clock overflow")?;
                self.catchup_timers.insert(
                    h,
                    Timer {
                        deadline,
                        acted: false,
                    },
                );
                self.outbox.push(Effect::Wake { at: deadline });
                self.notice("catchup_timer_arm", h);
                self.version += 1;
            }
        }
        Ok(())
    }
    fn finish(&mut self, r: u64) -> Result<(), String> {
        let before = self.terminal(r);
        let admitted = self.current;
        let actions = self.slot(r).finish(admitted);
        self.apply_actions(r, actions)?;
        if before != self.terminal(r) {
            self.version += 1;
            if self.terminal(r) == Terminal::NoCer {
                self.notice("no_cer", r);
            }
        }
        Ok(())
    }
    fn expire_timers(&mut self) -> Result<(), String> {
        let rounds: Vec<_> = self
            .main_timers
            .iter()
            .filter(|(_, t)| !t.acted && t.deadline <= self.now)
            .map(|(r, _)| *r)
            .collect();
        for r in rounds {
            self.main_timers.get_mut(&r).unwrap().acted = true;
            self.version += 1;
            self.notice("main_timer_expiry", r);
            self.finish(r)?;
        }
        let horizons: Vec<_> = self
            .catchup_timers
            .iter()
            .filter(|(h, t)| !t.acted && t.deadline <= self.now && self.current >= **h + 2)
            .map(|(h, _)| *h)
            .collect();
        for h in horizons {
            self.catchup_timers.get_mut(&h).unwrap().acted = true;
            self.version += 1;
            self.notice("catchup_timer_expiry", h);
            for r in 1..=h {
                self.finish(r)?;
            }
        }
        Ok(())
    }
    fn settle(&mut self) -> Result<Vec<Effect>, String> {
        loop {
            let before = self.version;
            while let Some(message) = self.inbox.pop_front() {
                self.ingest(message)?;
            }
            self.drive_progress()?;
            self.drive_slots()?;
            self.make_reports()?;
            self.propose()?;
            self.arm_timers()?;
            if !self.inbox.is_empty() || self.version != before {
                continue;
            }
            // No enabled positive transition remains with the evidence received
            // at this local step. Each expired timer now takes CER before NO-CER.
            self.expire_timers()?;
            if !self.inbox.is_empty() || self.version != before {
                continue;
            }
            break;
        }
        let direct = self
            .slots
            .iter()
            .filter_map(|(r, s)| s.committed().map(|d| (*r, d)))
            .collect();
        let statuses = scanner::scan(self.current, &direct, &self.headers);
        for (r, old) in &self.statuses {
            if *old != Status::Undecided {
                assert_eq!(statuses.get(r), Some(old), "decided classification changed");
            }
        }
        self.statuses = statuses;
        let delivered = scanner::release(
            &self.statuses,
            &self.headers,
            &self.values,
            &mut self.cursor,
        );
        for d in delivered {
            self.deliveries.push(d.clone());
            self.outbox.push(Effect::Deliver(d));
        }
        Ok(std::mem::take(&mut self.outbox))
    }
    pub fn snapshot(&self) -> Value {
        json!({"id":self.id,"current_round":self.current,"last_delivered":self.cursor,
            "deliveries":self.deliveries,"statuses":self.statuses,
            "own_reports":self.own_reports.values().collect::<Vec<_>>(),
            "own_proofs":self.own_proofs.values().collect::<Vec<_>>(),
            "closed_sent":self.closed_sent.values().collect::<Vec<_>>(),
            "main_timers":self.main_timers.iter().map(|(r,t)|json!({"round":r,"deadline":t.deadline,"acted":t.acted})).collect::<Vec<_>>(),
            "catchup_timers":self.catchup_timers.iter().map(|(h,t)|json!({"horizon":h,"deadline":t.deadline,"acted":t.acted})).collect::<Vec<_>>(),
            "headers":self.headers.values().collect::<Vec<_>>()})
    }
}
