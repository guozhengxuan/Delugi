// Optional native TCP byte observer. Call only after successful socket IO.
// Counts native encrypted framing/handshakes; excludes external REST ingress.
use std::{fs, os::{raw::{c_int,c_long,c_void},fd::AsRawFd}, path::PathBuf,
    sync::{OnceLock,atomic::{AtomicU64,Ordering}}, time::Duration};
#[repr(C)] struct Timespec { tv_sec:c_long, tv_nsec:c_long }
extern "C" { fn clock_gettime(id:c_int, time:*mut Timespec)->c_int; }
extern "C" { fn mmap(address:*mut c_void,length:usize,protection:c_int,flags:c_int,fd:c_int,offset:i64)->*mut c_void; }
#[cfg(target_os="linux")] const CLOCK:c_int=1;
#[cfg(target_os="macos")] const CLOCK:c_int=6;
fn monotonic_us()->u64 {let mut ts=Timespec{tv_sec:0,tv_nsec:0};assert_eq!(unsafe{clock_gettime(CLOCK,&mut ts)},0);ts.tv_sec as u64*1_000_000+ts.tv_nsec as u64/1000}
#[repr(C)] struct Counters { magic:u64,written:AtomicU64,read:AtomicU64 }
static CONFIG:OnceLock<Option<&'static Counters>>=OnceLock::new();
// Native-endian24-byte sidecar, read by the controller only after confirmed
// process suspension. MAP_SHARED preserves exact successful socket totals
// without per-frame syscalls/fsync; the periodic JSON is only a window sample.
const MAGIC:u64=0x444c47494f563031;
pub fn record(bytes:usize,write:bool) {
    let Some(counters)=CONFIG.get_or_init(|| {
        let path=std::env::var_os("BENCHMARK_IO_PATH")?;
        let path=PathBuf::from(path);
        assert_eq!(std::mem::size_of::<Counters>(),24);
        let file=fs::OpenOptions::new().create_new(true).read(true).write(true).open(path.with_extension("counters")).expect("create native shared TCP counters");
        file.set_len(24).expect("size native shared TCP counters");
        let address=unsafe{mmap(std::ptr::null_mut(),24,3,1,file.as_raw_fd(),0)};
        assert_ne!(address as isize,-1,"map native shared TCP counters");
        let counters=unsafe {
            let pointer=address.cast::<Counters>();
            pointer.write(Counters{magic:MAGIC,written:AtomicU64::new(0),read:AtomicU64::new(0)});
            &*pointer
        };
        std::thread::Builder::new().name("benchmark-io".into()).spawn(move||loop {
            let row=format!("{{\"observed_us\":{},\"written_bytes\":{},\"read_bytes\":{}}}\n",monotonic_us(),counters.written.load(Ordering::Relaxed),counters.read.load(Ordering::Relaxed));
            let temporary=path.with_extension("tmp");
            fs::write(&temporary,row).expect("write native TCP counters");
            fs::rename(&temporary,&path).expect("publish native TCP counters");
            std::thread::sleep(Duration::from_millis(10));
        }).expect("native TCP counter thread");Some(counters)
    }) else{return};
    if write {counters.written.fetch_add(bytes as u64,Ordering::Relaxed);} else {counters.read.fetch_add(bytes as u64,Ordering::Relaxed);}
}
