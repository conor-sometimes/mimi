use aya::{maps::RingBuf, programs::TracePoint};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// mimi: load the probe, attach it to sched_process_exec, and emit each exec event. The probe and
// its BPF object are embedded in this binary by the build script. Parsing and rendering live in
// mimi-types (the `user` feature), shared with anything else that reads the wire format and
// unit-tested without the kernel.
//
// Default output is one OCSF-shaped event per line (mimi-types `render_mimi`, the schema banken
// ingests through its `mimi` parser); `--text` prints the human view instead. Streaming to banken
// as a continuous feed (so end-to-end latency is capture + match, not bounded by a scan interval)
// is the next step -- see the roadmap; for now events go to stdout, which a durable file sink or a
// pipe to banken consumes.

// Read CLOCK_MONOTONIC in nanoseconds (the clock the probe's bpf_ktime_get_ns stamps).
fn monotonic_ns() -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes a valid timespec for a valid clock id.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

fn main() -> anyhow::Result<()> {
    // Bump the memlock rlimit for older kernels' map accounting.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mimi"
    )))?;
    let program: &mut TracePoint = ebpf.program_mut("mimi").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let text = std::env::args().any(|a| a == "--text");

    // The probe stamps CLOCK_MONOTONIC (bpf_ktime_get_ns), so sample the offset to wall-clock once
    // and turn each event's monotonic time_ns into a real UTC timestamp; capture_ns keeps the raw
    // monotonic value for latency measurement on the banken side.
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    let offset_ns = wall_now - monotonic_ns();

    let mut ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    // The probe counts events it had to drop because the ring was full (per CPU); surface that so
    // loss under a burst is visible and counted, not silent (the classic EDR blinding failure).
    let drops: aya::maps::PerCpuArray<_, u64> =
        aya::maps::PerCpuArray::try_from(ebpf.take_map("DROPS").unwrap())?;
    let mut last_drops = 0u64;
    eprintln!("mimi: watching execs. Ctrl-C to stop.");

    loop {
        while let Some(item) = ring.next() {
            if let Some(lin) = mimi_types::parse(&item) {
                let out = if text {
                    mimi_types::render_text(&lin)
                } else {
                    let wall = (offset_ns + lin.time_ns as i128).max(0) as u128;
                    mimi_types::render_mimi(&lin, &mimi_types::rfc3339_utc(wall))
                };
                if !out.is_empty() {
                    println!("{out}");
                }
            }
        }
        if let Ok(per_cpu) = drops.get(&0, 0) {
            let total: u64 = per_cpu.iter().sum();
            if total > last_drops {
                eprintln!(
                    "mimi: dropped {} event(s) to a full ring buffer (raise the ring if sustained)",
                    total - last_drops
                );
                last_drops = total;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
