// Copied verbatim into each instrumented native crypto module. Disabled unless
// BENCHMARK_CPU_PATH is set. Synchronous guards never cross an await point.
use std::{fs, io::Write, os::raw::{c_int, c_long}, path::PathBuf,
    sync::{OnceLock, atomic::{AtomicU64, Ordering}}, time::Duration};

#[repr(C)] struct Timespec { tv_sec: c_long, tv_nsec: c_long }
extern "C" { fn clock_gettime(id: c_int, time: *mut Timespec) -> c_int; }
#[cfg(target_os = "linux")] const THREAD_CLOCK: c_int = 3;
#[cfg(target_os = "macos")] const THREAD_CLOCK: c_int = 16;
#[cfg(target_os = "linux")] const MONOTONIC_CLOCK: c_int = 1;
#[cfg(target_os = "macos")] const MONOTONIC_CLOCK: c_int = 6;
fn clock(id: c_int) -> u64 {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    assert_eq!(unsafe { clock_gettime(id, &mut ts) }, 0, "benchmark CPU clock unavailable");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
static COUNT: [AtomicU64; 4] = [AtomicU64::new(0),AtomicU64::new(0),AtomicU64::new(0),AtomicU64::new(0)];
static CPU: [AtomicU64; 4] = [AtomicU64::new(0),AtomicU64::new(0),AtomicU64::new(0),AtomicU64::new(0)];
static CONFIG: OnceLock<Option<PathBuf>> = OnceLock::new();

fn enabled() -> bool {
    CONFIG.get_or_init(|| {
        let path = std::env::var_os("BENCHMARK_CPU_PATH").map(PathBuf::from)?;
        let output = path.clone();
        std::thread::Builder::new().name("native-crypto-observer".into()).spawn(move || loop {
            let names = ["ordinary_sign", "ordinary_verify", "ordinary_verify_batch", "ordinary_verify_batch_multi"];
            let fields: Vec<String> = names.iter().enumerate().map(|(i,name)| format!(
                "\"{}\":{{\"calls\":{},\"thread_cpu_ns\":{}}}", name,
                COUNT[i].load(Ordering::Relaxed), CPU[i].load(Ordering::Relaxed))).collect();
            let row = format!("{{\"schema\":1,\"monotonic_ns\":{},\"scope\":\"native synchronous ordinary protocol authentication; hashing and input decoding included; elapsed thread CPU, not wall time; failed attempts charged\",\"operations\":{{{}}}}}\n", clock(MONOTONIC_CLOCK), fields.join(","));
            let temporary = output.with_extension("tmp");
            let mut file = fs::File::create(&temporary).expect("create native CPU snapshot");
            file.write_all(row.as_bytes()).expect("write native CPU snapshot");
            fs::rename(temporary, &output).expect("publish native CPU snapshot");
            std::thread::sleep(Duration::from_millis(20));
        }).expect("start native crypto observer");
        Some(path)
    }).is_some()
}

pub struct Guard { kind: usize, start_ns: u64 }
pub fn begin(kind: usize) -> Option<Guard> {
    if enabled() { Some(Guard { kind, start_ns: clock(THREAD_CLOCK) }) } else { None }
}
impl Drop for Guard {
    fn drop(&mut self) {
        CPU[self.kind].fetch_add(clock(THREAD_CLOCK).saturating_sub(self.start_ns), Ordering::Relaxed);
        COUNT[self.kind].fetch_add(1, Ordering::Relaxed);
    }
}
