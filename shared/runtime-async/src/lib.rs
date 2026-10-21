//! Shared asynchronous mechanisms. The core supplies task bodies and timer policy.
//! No protocol imports, global executor fallback, admission waits or hidden skips.
mod executor;
mod timer;
pub use executor::{Executor, ExecutorError, Limits, Snapshot, Task, TaskGroup};
pub use timer::Timer;

/// Exact pinned async clock/deadline primitives. Native policy chooses every
/// duration, interval missed-tick rule and timeout branch at its original site.
pub mod time {
    pub use tokio::time::*;
}

/// Initialize the native compatibility backend's global Rayon pool explicitly.
/// Calling this after another initializer is an error, never silently accepted.
/// Local independent processes call once before native verification starts.
pub fn initialize_global_rayon(workers: usize) -> Result<RayonProfile, String> {
    if workers == 0 || workers > 256 {
        return Err("invalid Rayon worker count".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|id| format!("shared-rayon-{id}"))
        .build_global()
        .map_err(|e| format!("explicit global Rayon initialization: {e}"))?;
    let effective = rayon::current_num_threads();
    if effective != workers {
        return Err("Rayon worker count differs from requested profile".into());
    }
    Ok(RayonProfile { workers: effective })
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RayonProfile {
    pub workers: usize,
}
