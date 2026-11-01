use aya::{maps::RingBuf, programs::TracePoint};
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod btf;

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
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes a valid timespec for a valid clock id.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

// Whether a stdout write/flush means the consumer is gone and the sensor should stop. BrokenPipe is
// the normal "the reader closed" signal: exit 0, no crash-loop under Restart=on-failure. Any other
// write error means the sink is unusable (a full disk, say), so log it and stop too rather than spin.
fn is_gone(r: io::Result<()>) -> bool {
    match r {
        Ok(()) => false,
        Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => true,
        Err(e) => {
            eprintln!("mimi: stdout write failed ({e}); stopping");
            true
        }
    }
}

// validate_offsets resolves the probe's task_struct/mm_struct fields in the running kernel's BTF
// (/sys/kernel/btf/vmlinux) and returns the entries whose byte offset differs from the compiled one
// (empty = every offset matches). An Err means BTF could not be read or parsed, so validation could
// not run -- distinct from a clean "no mismatches".
fn validate_offsets() -> Result<Vec<String>, String> {
    let data =
        std::fs::read("/sys/kernel/btf/vmlinux").map_err(|e| format!("read kernel BTF: {e}"))?;
    let mut structs: Vec<&str> = mimi_types::OFFSET_TABLE
        .iter()
        .map(|(s, _, _)| *s)
        .collect();
    structs.sort_unstable();
    structs.dedup();
    let resolved = btf::member_offsets(&data, &structs)?;
    let mut mismatches = Vec::new();
    for (st, field, want) in mimi_types::OFFSET_TABLE {
        match resolved.get(st).and_then(|m| m.get(field)).copied() {
            Some(got) if got == want => {}
            Some(got) => mismatches.push(format!("{st}.{field}: kernel {got} vs compiled {want}")),
            None => mismatches.push(format!("{st}.{field}: absent from kernel BTF")),
        }
    }
    Ok(mismatches)
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

    // Before attaching, check the probe's compiled task_struct/mm_struct offsets against this
    // kernel's own BTF. On a mismatch the layout differs and the probe would read the wrong fields,
    // so refuse rather than emit garbage (the hazard of any hardcoded-offset probe off its build
    // kernel; CO-RE will remove the hardcoding, this makes it safe meanwhile). No BTF = cannot check.
    match validate_offsets() {
        Ok(m) if m.is_empty() => {}
        Ok(m) => {
            anyhow::bail!(
                "kernel task_struct/mm_struct layout differs from mimi's compiled offsets; refusing \
                 to attach so it cannot read the wrong fields (this kernel needs CO-RE). {}",
                m.join("; ")
            );
        }
        Err(e) => eprintln!(
            "mimi: could not validate offsets against kernel BTF ({e}); proceeding on the compiled \
             offsets, which are correct only on a matching kernel"
        ),
    }

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

    // Hold the stdout lock for the whole run and write through it, so a consumer that goes away
    // (the sink file closed, a tail pipe whose reader exits) surfaces as a BrokenPipe we exit on
    // cleanly rather than the panic `println!` raises -- under the unit's Restart=on-failure a panic
    // would crash-loop the sensor. Flush after each drain so a file sink banken tails sees every
    // batch promptly (stdout is block-buffered to a file), not only when an 8K buffer fills.
    let mut out = io::stdout().lock();

    loop {
        while let Some(item) = ring.next() {
            if let Some(lin) = mimi_types::parse(&item) {
                let line = if text {
                    mimi_types::render_text(&lin)
                } else {
                    let wall = (offset_ns + lin.time_ns as i128).max(0) as u128;
                    mimi_types::render_mimi(&lin, &mimi_types::rfc3339_utc(wall))
                };
                if !line.is_empty() && is_gone(writeln!(out, "{line}")) {
                    return Ok(());
                }
            }
        }
        if is_gone(out.flush()) {
            return Ok(());
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
