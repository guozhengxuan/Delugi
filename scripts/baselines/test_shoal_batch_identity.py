#!/usr/bin/env python3
"""Compile the exact pinned HashValue formatters and native observer expression.

This small regression avoids compiling another Aptos test target. The format
implementations and selected observation expression are read from native source;
their hashes and exact generated fixture are retained with the result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def implementation(source, name):
    start=source.index('impl fmt::'+name+' for HashValue')
    brace=source.index('{',start);depth=1;end=brace+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expect-legacy-collision',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[2]/'benchmarks/baselines/shoal'
    hash_path=root/'crates/aptos-crypto/src/hash.rs'
    hook_path=root/'consensus/src/dag/shoal_plus_plus/shoalpp_order_notifier.rs'
    hash_source=hash_path.read_text();hook=hook_path.read_text()
    expression=re.search(r'format!\("[^"\n]*", dag_id, node\.digest\(\)\)',hook).group()
    expected='assert_eq!(first,second);' if args.expect_legacy_collision else 'assert_ne!(first,second);assert_eq!(first.len(),66);assert_eq!(second.len(),66);'
    source='use std::fmt;\n#[derive(Copy,Clone)] struct HashValue {hash:[u8;32]}\n'
    source+=implementation(hash_source,'Display')+'\n'+implementation(hash_source,'LowerHex')+'\n'
    source+='struct Node(HashValue);impl Node {fn digest(&self)->HashValue {self.0}}\n'
    source+='fn identity(dag_id:usize,node:&Node)->String {'+expression+'}\n'
    source+='fn main(){let a=HashValue{hash:[0x11;32]};let mut b=a;b.hash[31]=0x12;assert_eq!(format!("{}",a),format!("{}",b));let first=identity(0,&Node(a));let second=identity(0,&Node(b));'+expected+'println!("{}\\n{}",first,second);}\n'
    with tempfile.TemporaryDirectory(prefix='shoal-batch-identity-') as temporary:
        path=Path(temporary);(path/'fixture.rs').write_text(source)
        subprocess.run(['rustc','--edition=2021',str(path/'fixture.rs'),'-o',str(path/'fixture')],check=True,capture_output=True)
        identities=subprocess.check_output([str(path/'fixture')],text=True).splitlines()
    record={'status':'reproduced_legacy_collision' if args.expect_legacy_collision else 'passed',
        'scope':'exact observer formatter expression with the pinned native HashValue Display/LowerHex implementations',
        'native_sources':{str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in (hash_path,hook_path)},
        'observer_expression':expression,'identities':identities,'generated_fixture':source,
        'compiler':subprocess.check_output(['rustc','--version','--verbose'],text=True)}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
    print(args.output)


if __name__=='__main__':main()
