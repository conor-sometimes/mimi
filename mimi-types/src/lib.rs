#![no_std]
//! mimi's wire schema: the one `#[repr(C)]` layout both the eBPF probe (`mimi-ebpf`, no_std) and the
//! userspace loader (`mimi`) read, so the two halves can never disagree on the bytes crossing the
//! ring buffer. The single source of truth for the sensor's on-wire shape.
//!
//! The `user` feature additionally pulls in the std-side parsing/rendering (and its unit tests),
//! kept here, in a crate with no `build.rs`, so the logic is testable on **stable** Rust without
//! triggering the probe's nightly `build-std` compile.

/// How far up the ancestry we walk before stopping (bounded for the BPF verifier and the stack).
pub const MAX_DEPTH: usize = 8;
/// Bytes of argv captured (NUL-separated, as the kernel stores it between mm->arg_start/arg_end).
pub const CMDLINE_LEN: usize = 128;
/// Length of a task's `comm` (the kernel's fixed TASK_COMM_LEN).
pub const COMM_LEN: usize = 16;
/// Bytes of the executed program's path (sched_process_exec's `filename`), NUL-terminated.
pub const FILENAME_LEN: usize = 256;

/// The wire schema version, emitted in every event. The consumer (banken) checks it and refuses or
/// downgrades on skew, so the two repos can evolve without silently misreading each other's bytes.
pub const SCHEMA: &str = "mimi/2";

/// One process in the ancestry chain.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ancestor {
    pub pid: u32,
    /// NUL-padded task name (`comm`).
    pub comm: [u8; COMM_LEN],
}

impl Ancestor {
    pub const fn zeroed() -> Self {
        Self { pid: 0, comm: [0u8; COMM_LEN] }
    }
}

/// One exec event: the process's argv plus its ancestry (child first, up toward pid 1).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Lineage {
    /// Monotonic capture time (`bpf_ktime_get_ns`), so end-to-end detection latency (event -> mimi
    /// -> banken -> alert) is measurable rather than guessed. banken consumes mimi as a continuous
    /// stream, so that latency is capture + match, not bounded by any scan interval.
    pub time_ns: u64,
    /// Number of valid entries in `chain`.
    pub count: u32,
    /// Valid bytes in `cmdline`.
    pub cmdline_len: u32,
    /// The argv's true total length; `> cmdline_len` means the capture was truncated (so banken can
    /// both match on what it has and alert that the command line was cut).
    pub argv_total_len: u32,
    /// The execed process's real uid and gid (`bpf_get_current_uid_gid`); the account the agent
    /// rules key on.
    pub uid: u32,
    pub gid: u32,
    /// The executed program's path (`sched_process_exec` `filename`), NUL-terminated. This is the
    /// Image banken matches `endswith` on; `comm` alone is a 15-byte basename that truncates.
    pub filename: [u8; FILENAME_LEN],
    /// The execed process's argv, NUL-separated.
    pub cmdline: [u8; CMDLINE_LEN],
    /// chain[0] is the execed process; chain[1] its parent; ... up to the root or MAX_DEPTH.
    pub chain: [Ancestor; MAX_DEPTH],
}

impl Lineage {
    pub const fn zeroed() -> Self {
        Self {
            time_ns: 0,
            count: 0,
            cmdline_len: 0,
            argv_total_len: 0,
            uid: 0,
            gid: 0,
            filename: [0u8; FILENAME_LEN],
            cmdline: [0u8; CMDLINE_LEN],
            chain: [Ancestor::zeroed(); MAX_DEPTH],
        }
    }
}

#[cfg(feature = "user")]
extern crate std;

#[cfg(feature = "user")]
mod user;
#[cfg(feature = "user")]
pub use user::{
    cmdline_str, comm_str, filename_str, parse, render_json, render_mimi, render_text, rfc3339_utc,
};
