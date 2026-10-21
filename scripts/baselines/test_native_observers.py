#!/usr/bin/env python3
"""Compile isolated copies of the exact native observer modules and test withdrawal.

This is a small functional fixture, not a replica benchmark or throughput test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import tempfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    base=Path(__file__).resolve().parent
    source=f'''#[path={json.dumps(str(base/"native_fault.rs"))}] mod fault;
#[path={json.dumps(str(base/"native_cpu.rs"))}] mod cpu;
#[path={json.dumps(str(base/"native_io.rs"))}] mod io;
fn main() {{
    let directory=std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let control=directory.join("interval.txt");let log=directory.join("omissions.jsonl");
    std::env::set_var("BENCHMARK_FAULT_CONTROL",&control);
    std::env::set_var("BENCHMARK_FAULT_LOG",&log);
    std::env::set_var("BENCHMARK_FAULT_ALLOWED","allowed");
    std::env::set_var("BENCHMARK_FAULT_REPAIR","1");
    std::env::set_var("BENCHMARK_CPU_PATH",directory.join("cpu.json"));
    std::env::set_var("BENCHMARK_IO_PATH",directory.join("io.json"));
    assert!(fault::permit("payload_initial","blocked",100));
    let start=fault::monotonic_ns();let end=start+50_000_000;
    std::fs::write(&control,format!("{{}} {{}}\\n",start,end)).unwrap();
    assert!(fault::permit("payload_initial","allowed",100));
    assert!(!fault::permit("payload_initial","blocked",100));
    assert!(!fault::permit("payload_repair","blocked",80));
    assert!(!fault::permit("native_node_repair","blocked",90));
    io::record(123,true);io::record(45,false);io::record(7,true);
    {{let _guard=cpu::begin(0);let mut total=0u64;for i in 0..100_000u64 {{total=total.wrapping_add(std::hint::black_box(i));}}std::hint::black_box(total);}}
    std::thread::sleep(std::time::Duration::from_millis(80));
    assert!(fault::monotonic_ns()>=end);
    assert!(fault::permit("payload_initial","blocked",100));
    assert!(fault::permit("payload_repair","blocked",80));
    assert!(fault::permit("native_node_repair","blocked",90));
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(),3);
    // An unsampled last write still appears in the shared counter sidecar.
    io::record(19,true);
}}
'''
    with tempfile.TemporaryDirectory(prefix="delugi-native-observer-test-") as directory:
        root=Path(directory);(root/"fixture.rs").write_text(source)
        compile_result=subprocess.run(["rustc","--edition=2021","-O",str(root/"fixture.rs"),"-o",str(root/"fixture")],capture_output=True,text=True,check=True)
        subprocess.run([str(root/"fixture"),str(root)],check=True,capture_output=True)
        cpu=json.loads((root/"cpu.json").read_text())
        assert cpu["operations"]["ordinary_sign"]["calls"]==1
        assert cpu["operations"]["ordinary_sign"]["thread_cpu_ns"]>0
        io=json.loads((root/"io.json").read_text())
        assert io["written_bytes"] in (130,149) and io["read_bytes"]==45 and io["observed_us"]>0
        magic,written,read=struct.unpack('=QQQ',(root/'io.counters').read_bytes())
        assert magic==0x444c47494f563031 and written==149 and read==45
        rows=[json.loads(line) for line in (root/"omissions.jsonl").read_text().splitlines()]
        result={"status":"passed","tests":["inactive before interval publication","recipient whitelist","payload and native node repair omitted during interval","both publications resume after declared end","resumed messages produce no omission events","positive synchronous thread CPU count","successful TCP byte totals retain read/write separation","shared native counters retain unsampled final socket write"],"source_sha256":{name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in ["native_fault.rs","native_cpu.rs","native_io.rs"]},"compiler":subprocess.check_output(["rustc","--version","--verbose"],text=True),"omission_events":rows,"cpu":cpu,"io":io,"io_final":{"written_bytes":written,"read_bytes":read},"compiler_stderr":compile_result.stderr}
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open("x") as stream:json.dump(result,stream,indent=2);stream.write("\n")
        print(args.output)

if __name__=="__main__":main()
