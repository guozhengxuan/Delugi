// Copied verbatim into each native transport module. Only a configured faulty
// sender invokes this on native payload/publication units. It does not edit data,
// quorum predicates, honest custody, or native request/recovery algorithms.
use std::{collections::HashSet, fs, io::Write, os::raw::{c_int,c_long}, path::PathBuf,
    sync::{Mutex,OnceLock}};
#[repr(C)] struct Timespec { tv_sec:c_long, tv_nsec:c_long }
extern "C" { fn clock_gettime(id:c_int, time:*mut Timespec)->c_int; }
#[cfg(target_os="linux")] const CLOCK:c_int=1;
#[cfg(target_os="macos")] const CLOCK:c_int=6;
pub fn monotonic_ns()->u64 { let mut ts=Timespec{tv_sec:0,tv_nsec:0};assert_eq!(unsafe{clock_gettime(CLOCK,&mut ts)},0);ts.tv_sec as u64*1_000_000_000+ts.tv_nsec as u64 }
struct Config { control:PathBuf, log:PathBuf, allowed:HashSet<String>, repair:bool }
static CONFIG:OnceLock<Option<Config>>=OnceLock::new();
static INTERVAL:OnceLock<(u64,u64)>=OnceLock::new();
static LOG:Mutex<()>=Mutex::new(());
pub fn permit(kind:&str, peer:&str, bytes:usize)->bool {
    let config=CONFIG.get_or_init(|| Some(Config {
        control:PathBuf::from(std::env::var_os("BENCHMARK_FAULT_CONTROL")?),
        log:PathBuf::from(std::env::var_os("BENCHMARK_FAULT_LOG")?),
        allowed:std::env::var("BENCHMARK_FAULT_ALLOWED").unwrap_or_default().split(',').filter(|x|!x.is_empty()).map(str::to_owned).collect(),
        repair:std::env::var("BENCHMARK_FAULT_REPAIR").as_deref()==Ok("1"),
    }));
    let Some(config)=config else{return true};
    if kind=="payload_repair" && !config.repair {return true}
    if INTERVAL.get().is_none() {
        match fs::read_to_string(&config.control) {
            Ok(text)=>{let values:Vec<u64>=text.split_whitespace().map(|x|x.parse().expect("invalid benchmark fault time")).collect();assert_eq!(values.len(),2);assert!(values[0]<values[1]);let _=INTERVAL.set((values[0],values[1]));},
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>return true,
            Err(error)=>panic!("read benchmark fault interval: {}",error),
        }
    }
    let (start,end)=*INTERVAL.get().unwrap();let now=monotonic_ns();
    if now<start || now>=end || config.allowed.contains(peer) {return true}
    let _guard=LOG.lock().unwrap();let mut file=fs::OpenOptions::new().create(true).append(true).open(&config.log).expect("open omission log");
    writeln!(file,"{{\"kind\":\"{}\",\"peer\":\"{}\",\"serialized_bytes_omitted\":{},\"monotonic_ns\":{}}}",kind,peer,bytes,now).expect("write omission log");
    false
}
