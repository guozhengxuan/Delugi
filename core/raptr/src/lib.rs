//! The application output boundary of the pinned real-QS Raptr implementation.
//!
//! This crate currently defines ordering and native descriptor contracts only. It
//! is not a consensus implementation and does not authenticate native proposals.
//! Its caller supplies **already committed** slices from the unchanged Raptr
//! core, and a native BatchPayload verifier backed by the shared crypto service.
//! See CONTRACT.txt and source-map.json for the exact upstream mapping.

mod output;
pub mod latency;

pub use output::*;
