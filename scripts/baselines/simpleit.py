#!/usr/bin/env python3
"""Pinned Simple-IT source adapters; upstream branches remain explicit variants.

The authenticated channel adapter is a disclosed evaluation change. It is not
evidence that native certificate predicates or application output are qualified.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
NEW_FILES=('network/src/eval_tls.rs','network/examples/eval_tls_probe.rs','primary/src/evaluation.rs')
sys.path.insert(0,str(ROOT/'scripts'))
from compact_campaign import UPSTREAMS
from baselines import raptr_artifacts as guard


def replace(text,old,new,count=1):
    if text.count(old)!=count:raise ValueError('pinned source anchor changed: '+old[:100])
    return text.replace(old,new)


def sources(variant):
    if variant not in ('simpleit-mempool','simpleit-dispersed'):raise ValueError('explicit Simple-IT variant required')
    source=ROOT/'benchmarks/baselines'/variant
    pin=UPSTREAMS[variant][1]
    head=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if head!=pin:raise ValueError('Simple-IT checkout differs from selected pin')
    def original(name):return subprocess.check_output(['git','-C',str(source),'show',pin+':'+name],text=True)
    output={}
    output['network/src/eval_tls.rs']=(ROOT/'scripts/baselines/simpleit_tls.rs').read_text()
    output['network/examples/eval_tls_probe.rs']=(ROOT/'scripts/baselines/simpleit_tls_probe.rs').read_text()
    output['primary/src/evaluation.rs']=(ROOT/'scripts/baselines/simpleit_workload.rs').read_text()
    output['primary/src/lib.rs']=original('primary/src/lib.rs')+'\npub mod evaluation;\n'
    pcargo=original('primary/Cargo.toml')
    output['primary/Cargo.toml']=replace(pcargo,'[dependencies]','''[dependencies]
once_cell = "=1.21.3"
serde_json = "1.0"
sha2 = "=0.10.8"
hex = "=0.4.3"
libc = "0.2"''')
    main=original('node/src/main.rs')
    main=replace(main,'        .about("A research implementation of Narwhal and Tusk.")',
        '''        .about("A research implementation of Narwhal and Tusk.")
        .subcommand(SubCommand::with_name("verify_evaluation")
            .args_from_usage("--configuration=<FILE> 'Frozen workload configuration'")
            .args_from_usage("--directory=<PATH> 'Frozen observer directory'"))''')
    main=replace(main,'        ("run", Some(sub_matches)) => run(sub_matches).await?,',
        '''        ("verify_evaluation",Some(args)) => primary::evaluation::verify(
            args.value_of("configuration").unwrap(),args.value_of("directory").unwrap()),
        ("run", Some(sub_matches)) => run(sub_matches).await?,''')
    output['node/src/main.rs']=main
    output['network/src/lib.rs']=original('network/src/lib.rs')+'\npub mod eval_tls;\n'
    cargo=original('network/Cargo.toml')
    cargo=replace(cargo,'"rt", "net", "sync", "macros", "time"','"rt", "net", "sync", "macros", "time", "io-util"')
    cargo=replace(cargo,'[dependencies]','''[dependencies]
once_cell = "=1.21.3"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "=0.10.8"
hex = "=0.4.3"
tokio-rustls = "=0.24.1"
rustls-pemfile = "=1.0.4"''')
    cargo=replace(cargo,'rustls-pemfile = "=1.0.4"','rustls-pemfile = "=1.0.4"\nlibc = "0.2"')
    output['network/Cargo.toml']=cargo
    for name in ('simple_sender','reliable_sender'):
        path='network/src/'+name+'.rs';text=original(path)
        text=replace(text,'TcpStream::connect(self.address).await','crate::eval_tls::connect(self.address).await')
        if name=='reliable_sender':text=replace(text,'stream: TcpStream','stream: crate::eval_tls::Stream')
        output[path]=text
    text=original('network/src/receiver.rs')
    text=replace(text,'Framed<TcpStream, LengthDelimitedCodec>','Framed<crate::eval_tls::Stream, LengthDelimitedCodec>')
    text=replace(text,'            let transport = Framed::new(socket, LengthDelimitedCodec::new());','''            let (socket, authenticated) = match crate::eval_tls::accept(socket).await {
                Ok(value) => value,
                Err(error) => { warn!("Authenticated channel rejected: {}", error); return; }
            };
            crate::eval_tls::PEER.scope(authenticated, async move {
            let transport = Framed::new(socket, LengthDelimitedCodec::new());''')
    if variant=='simpleit-mempool':
        text=replace(text,'            warn!("Connection closed by peer {}", peer);','''            warn!("Connection closed by peer {}", peer);
            }).await;''')
    else:
        text=replace(text,'                start_time.elapsed()\n            );','                start_time.elapsed()\n            );\n            }).await;')
    output['network/src/receiver.rs']=text
    text=original('primary/src/primary.rs')
    checks='''            PrimaryMessage::Timeout(m) => Some(&m.author),
            PrimaryMessage::TimeoutAccept(m) => Some(&m.author),
            PrimaryMessage::Decide(m) => Some(&m.author),
            PrimaryMessage::CertificatesRequest(_, author) => Some(author),
'''
    if variant=='simpleit-mempool':checks+='''            PrimaryMessage::Vote(m) => Some(&m.author),
            PrimaryMessage::CutVote(m) => Some(&m.author),
            PrimaryMessage::CutProposal(m) => Some(&m.proposer),
            PrimaryMessage::ConsensusVote(m) => Some(&m.author),
            PrimaryMessage::HeadersRequest(_, author) => Some(author),
            PrimaryMessage::ProposalHeadersRequest(_, _, author) => Some(author),
'''
    else:checks+='''            PrimaryMessage::Echo(m) => Some(&m.author),
'''
    old='match bincode::deserialize(&serialized).map_err(DagError::SerializationError)? {'
    new='''let message: PrimaryMessage = bincode::deserialize(&serialized).map_err(DagError::SerializationError)?;
        // Bind directly authored votes/requests to the channel identity. Header
        // repair and forwarded certificate objects retain their native origin.
        let direct_author = match &message {
'''+checks+'''            _ => None,
        };
        if let Some(author) = direct_author { network::eval_tls::require_peer(author.as_ref())?; }
        match message {'''
    if variant=='simpleit-mempool':
        new=new.replace('        match message {', '''        if let PrimaryMessage::Header(header,true)=&message {
            crate::evaluation::fault_event("repair_received",&header.id);
        }
        match message {''')
    # Worker receiver uses a differently typed deserializer. Only replace the
    # first primary-handler occurrence, verified against the selected source.
    at=text.index('impl MessageHandler for PrimaryReceiverHandler')
    end=text.index('\n}\n',at)+3
    text=text[:at]+replace(text[at:end],old,new)+text[end:]
    own='name' if variant=='simpleit-mempool' else 'keypair.name'
    text=replace(text,'        parameters.log();','        crate::evaluation::start('+own+');\n        parameters.log();')
    output['primary/src/primary.rs']=text
    proposer=original('primary/src/proposer.rs')
    if variant=='simpleit-mempool':
        proposer=replace(proposer,'let payload = vec![vec![0u8; self.tx_size]; self.header_size / self.tx_size];',
            'let payload = if crate::evaluation::enabled() { crate::evaluation::payload(self.header_size) } else { vec![vec![0u8; self.tx_size]; self.header_size / self.tx_size] };')
    else:
        proposer=replace(proposer,'if self.consensus_only {\n            payload =',
            'if crate::evaluation::enabled() {\n            payload = crate::evaluation::payload(self.header_size);\n        } else if self.consensus_only {\n            payload =')
    output['primary/src/proposer.rs']=proposer
    if variant=='simpleit-mempool':
        committer=original('primary/src/committer.rs')
        begin=committer.index('        for (pk, proposal) in proposals {')
        finish=committer.index('        Ok(())',begin)
        committer=committer[:begin]+'''        // Preflight every selected lane before advancing application state.
        // This preserves the native committed cut and deterministically expands
        // its complete payload; a missing lane cannot publish a partial cut.
        let mut prepared = Vec::new();
        for (pk, proposal) in proposals {
            let matching = state.dag.get(&proposal.height).and_then(|a|a.get(pk))
                .map(|(_,c)|c.header_id==proposal.header_digest).unwrap_or(false);
            if !matching { return Err(DagError::MalformedHeader(proposal.header_digest.clone())); }
            let stop = *state.last_executed_heights.get(pk).unwrap_or(&0);
            if proposal.height>stop {
                prepared.extend(self.synchronizer.get_all_headers_for_proposal(proposal.clone(),stop).await?);
            }
        }
        prepared.sort_by_key(|header|(header.height,header.author,header.id.clone()));
        for header in &prepared {
            if header.digest()!=header.id {return Err(DagError::MalformedHeader(header.id.clone()));}
        }
        for (pk,proposal) in proposals {state.last_executed_heights.entry(*pk).and_modify(|h|*h=(*h).max(proposal.height));}
        for header in prepared {
            crate::evaluation::materialize(round,header.id.clone(),bincode::serialize(&header).unwrap(),&header.payload);
            info!("Committed {:?} ",header.id);
            let _ = self.tx_output.send(header).await;
        }
'''+committer[finish:]
        committer=replace(committer,'        let rounds: Vec<_> = state.pending_commits.keys().cloned().collect();',
            '        let mut rounds: Vec<_> = state.pending_commits.keys().cloned().collect();\n        rounds.sort();')
        committer=replace(committer,'                if state.log.contains_key(&round) {',
            '''                if state.pending_commits.keys().any(|r|*r<round) {
                    state.pending_commits.insert(round,ConsensusMessage::Commit{round,proposals});
                    return;
                }
                if state.log.contains_key(&round) {''')
        committer=replace(committer,'                    self.process_commit_message(state.borrow_mut(), commit_message).await;',
            '                    self.process_commit_message(state.borrow_mut(), commit_message).await;\n                    self.process_pending_commits(state.borrow_mut()).await;')
        output['primary/src/committer.rs']=committer
        core=original('primary/src/core.rs')
        old='''        // Broadcast the new header in a reliable manner.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)'''
        core=replace(core,old,old.replace('// Broadcast the new header in a reliable manner.','// Omit only selected initial bodies; native vote and repair paths stay active.\n        crate::evaluation::withhold(&header);').replace('.map(|(_, x)| x.primary_to_primary)',
            '.filter(|(pk,_)|crate::evaluation::publish_to(&header.id,pk))\n            .map(|(_, x)| x.primary_to_primary)'))
        begin=core.index('        if self.sent_commit_rounds.contains(&round)',core.index('async fn emit_commit_to_committer'))
        finish=core.index('\n    }',begin)
        core=core[:begin]+'''        // Expand a decided native cut in ancestor order. Do not expose a
        // descendant before an earlier cut whose individual Decide was delayed.
        // This changes application delivery only, not votes or commit predicates.
        let mut path=Vec::new();
        let mut next=cut_id.clone();
        let mut bound=round+1;
        while next!=Digest::default() {
            let Some(cut)=self.cut_proposals.get(&next) else {return;};
            if self.sent_commit_rounds.contains(&cut.round) {break;}
            if cut.round>=bound || cut.digest()!=next {return;}
            bound=cut.round;
            path.push(cut.clone());
            next=cut.parent_cut.clone();
        }
        for cut in path.into_iter().rev() {
            let proposals=cut.tips.into_iter().collect();
            if self.tx_committer.send(ConsensusMessage::Commit{round:cut.round,proposals}).await.is_err(){return;}
            self.sent_commit_rounds.insert(cut.round);
        }'''+core[finish:]
        output['primary/src/core.rs']=core
        aggregators=original('primary/src/aggregators.rs')
        aggregators=replace(aggregators,'if self.weight >= committee.optimistic_threshold() {',
            '''// The published constructor emitted at 2 votes for n=4,f=1,
        // then reset; its own verifier requires 3. With one silent member no
        // valid certificate was ever emitted. Preserve both native predicates.
        if self.weight >= committee.optimistic_threshold().max(committee.quorum_threshold()) {''')
        aggregators+='''

#[cfg(test)]
mod evaluation_threshold_tests {
    use super::*;
    use config::{Authority,ConsensusAddresses,PrimaryAddresses};
    use std::collections::{BTreeMap,HashMap};
    #[test]
    fn constructed_cut_certificate_meets_its_native_verifier() {
        for n in [4u32,10,50] {
            let mut authorities=BTreeMap::new();
            for i in 0..n {
                authorities.insert(PublicKey([(i+1) as u8;32]),Authority{
                    node_id:Some(i as usize),stake:1,
                    consensus:ConsensusAddresses{consensus_to_consensus:"127.0.0.1:19000".parse().unwrap()},
                    primary:PrimaryAddresses{primary_to_primary:"127.0.0.1:19001".parse().unwrap(),worker_to_primary:"127.0.0.1:19002".parse().unwrap()},
                    workers:HashMap::new()});
            }
            let committee=Committee::new(authorities,(n-1)/3);
            let threshold=committee.optimistic_threshold().max(committee.quorum_threshold());
            let mut aggregator=CutVoteAggregator::new();
            for i in 0..threshold {
                let vote=CutVote{round:2,cut_id:Digest([1;32]),author:PublicKey([(i+1) as u8;32])};
                let certificate=aggregator.append(&vote,&committee).unwrap();
                if i+1<threshold {assert!(certificate.is_none());}
                else {certificate.unwrap().verify(&committee).unwrap();}
            }
            assert_eq!(threshold,match n {4=>3,10=>7,50=>40,_=>unreachable!()});
        }
    }
}
'''
        output['primary/src/aggregators.rs']=aggregators
        sync=original('primary/src/synchronizer.rs')
        sync=replace(sync,'    pub async fn fetch_header(&mut self, header_digest: Digest) -> DagResult<()> {',
            '    pub async fn fetch_header(&mut self, header_digest: Digest) -> DagResult<()> {\n        crate::evaluation::fault_event("repair_requested",&header_digest);')
        output['primary/src/synchronizer.rs']=sync
    else:
        core=original('primary/src/core.rs')
        core=replace(core,'    success: bool,','    success: bool,\n    recovered_payload: Option<Vec<u8>>,')
        core=replace(core,'                                success: false,','                                success: false,\n                                recovered_payload: None,')
        core=replace(core,'                            success,','''                            success,
                            recovered_payload: if success && crate::evaluation::enabled() {
                                Some(leaf_values.iter().take(coding.data_shard_count())
                                    .flat_map(|shard|shard.as_ref().unwrap().iter().copied()).collect())
                            } else {None},''')
        core=replace(core,'        let (header_id, round, origin) = match self.processing_header_proofs.get(&result.id) {',
            '''        if let Some(payload)=&result.recovered_payload {
            crate::evaluation::retain_reconstruction(&result.id,payload);
        }
        let (header_id, round, origin) = match self.processing_header_proofs.get(&result.id) {''')
        anchor='''        let certificate = Certificate {
            header_id,
            round,
            origin: author,
        };'''
        core=replace(core,anchor,'''        if crate::evaluation::enabled() {
            if let Some(info)=self.processing_header_proofs.get(&header_id) {
                if let Some(payload)=crate::evaluation::reconstructed(&header_id,info.payload_len) {
                    let header=Header{author:info.author,round:info.round,parent:info.parent.clone(),id:info.id.clone(),payload};
                    crate::evaluation::retain_header(&header);
                }
            }
        }
'''+anchor)
        core=replace(core,'            let mut header_info = HeaderInfo::create_from_fast(&header);',
            '            crate::evaluation::retain_header(&header);\n            crate::evaluation::withhold(&header);\n            let mut header_info = HeaderInfo::create_from_fast(&header);')
        core=replace(core,'                (_, Some(bytes)) => {',
            '                (_, Some(bytes)) => {\n                    if !crate::evaluation::publish_to(&result.header_info.id,pk){continue;}')
        core=replace(core,'            info!("Committed {:?} ", header_id);',
            '            crate::evaluation::decide(self.parent_info[&header_id].0,header_id.clone());\n            info!("Committed {:?} ", header_id);')
        output['primary/src/core.rs']=core
    return source,pin,output,original


def prepare(variant):
    source,pin,output,original=sources(variant)
    patch_path=ROOT/'benchmarks/patches'/(variant+'-evaluation.patch')
    previous = patch_path.exists() and subprocess.run(
        ['git','-C',str(source),'apply','--reverse','--check',str(patch_path)],
        capture_output=True).returncode==0
    changed=[]
    for name,text in output.items():
        path=source/name
        current=path.read_text() if path.exists() else None
        if current==text:continue
        baseline=None if name in NEW_FILES else original(name)
        if current!=baseline and not previous:raise ValueError('refusing to overwrite unrecorded source changes: '+name)
        changed.append((path,text))
    for path,text in changed:
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(text)
    patch=[]
    for name,text in output.items():
        baseline='' if name in NEW_FILES else original(name)
        patch.extend(difflib.unified_diff(baseline.splitlines(True),text.splitlines(True),
            fromfile='/dev/null' if not baseline else 'a/'+name,tofile='b/'+name))
    patch_path.write_text(''.join(patch))
    return {'protocol':variant,'source_commit':pin,'source':str(source),
            'patch':str(patch_path.relative_to(ROOT)),
            'patch_sha256':hashlib.sha256(patch_path.read_bytes()).hexdigest(),
            'status':'adapted_source_prepared','comparison_eligible':False}


def source_identity(variant):
    source,pin,output,original=sources(variant)
    for name,text in output.items():
        if (source/name).read_text()!=text:raise ValueError('prepared source differs: '+name)
    changed=set(subprocess.check_output(['git','-C',str(source),'diff','--name-only','HEAD'],text=True).splitlines())
    if changed-set(output):raise ValueError('unrecorded native source changes')
    untracked=set(subprocess.check_output(['git','-C',str(source),'ls-files','--others','--exclude-standard'],text=True).splitlines())
    if untracked-set(NEW_FILES)-{'Cargo.lock'}:raise ValueError('unrecorded native source files')
    lock=ROOT/'benchmarks/locks'/(variant+'-evaluation-2026-10-27.lock')
    if (source/'Cargo.lock').read_bytes()!=lock.read_bytes():raise ValueError('native dependency lock differs')
    patch=ROOT/'benchmarks/patches'/(variant+'-evaluation.patch')
    return {'variant':variant,'source_commit':pin,'patch_sha256':guard.sha256(patch),
            'cargo_lock_sha256':guard.sha256(lock),
            'adapter_sources':{str(p.relative_to(ROOT)):guard.sha256(p) for p in
                [Path(__file__),ROOT/'scripts/baselines/simpleit_workload.rs',ROOT/'scripts/baselines/simpleit_tls.rs',ROOT/'scripts/baselines/simpleit_tls_probe.rs']}}


def build(variant,directory,release=False):
    source=ROOT/'benchmarks/baselines'/variant;identity=source_identity(variant)
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=False)
    target=ROOT/'benchmarks/.cache/simpleit-target';target.mkdir(parents=True,exist_ok=True)
    env={k:v for k,v in os.environ.items() if k in guard.ENV_KEYS}
    env.update(CARGO_HOME=str(ROOT/'benchmarks/.cache/autobahn-cargo'),CARGO_TARGET_DIR=str(target),
        CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG='0')
    if platform.system()=='Darwin' and 'LIBCLANG_PATH' not in env:
        env['LIBCLANG_PATH']='/opt/homebrew/opt/llvm@14/lib'
    record={'schema':1,'format':'simpleit-adapted-build-v1','identity':identity,
            'profile':'release' if release else 'dev','platform':platform.platform(),
            'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'status':'preparing',
            'comparison_eligible':False}
    try:
        with guard.target_lock(target):
            argv=['cargo','build','--locked','-p','node','--features','benchmark','--jobs','2']+(['--release'] if release else [])
            guard.guarded_command(argv,source,env,target,directory/'build.log',directory/'resources.jsonl',
                {'target_bytes':12*1024**3,'free_bytes':30*1024**3,'rss_bytes':8*1024**3,'seconds':1200,
                 'poll_seconds':1,'cleanup_seconds':5},record)
            if identity!=source_identity(variant):raise ValueError('source changed during build')
            binary=directory/(variant+'-node');shutil.copy2(target/('release' if release else 'debug')/'node',binary)
            record['binary']={'path':str(binary),'sha256':guard.sha256(binary),'bytes':binary.stat().st_size}
    except BaseException as error:
        record.update(status='failed',error=f'{type(error).__name__}: {error}');raise
    finally:
        (directory/'build-receipt.json').write_text(json.dumps(record,indent=2)+'\n')
    return record


def verify_build(path,variant):
    path=Path(path);record=json.loads(path.read_text())
    if (record.get('format')!='simpleit-adapted-build-v1' or record.get('status')!='completed'
            or record['identity']!=source_identity(variant)):
        raise ValueError('Simple-IT artifact is not bound to the current adapter sources')
    binary=Path(record['binary']['path']);guard.regular(binary,executable=True)
    if guard.sha256(binary)!=record['binary']['sha256']:raise ValueError('Simple-IT binary changed')
    return binary,record


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('variant',choices=('simpleit-mempool','simpleit-dispersed'))
    p.add_argument('--build',action='store_true');p.add_argument('--output',type=Path);p.add_argument('--release',action='store_true')
    a=p.parse_args()
    if a.build and a.output is None:p.error('--build requires --output')
    print(json.dumps(build(a.variant,a.output,a.release) if a.build else prepare(a.variant),indent=2))


if __name__=='__main__':main()
