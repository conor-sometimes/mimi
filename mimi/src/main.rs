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

// Whether an event-sink write/flush means the consumer is gone and the sensor should stop. BrokenPipe
// is the normal "the reader closed" signal for a pipe sink: exit 0, no crash-loop under
// Restart=on-failure. Any other write error means the sink is unusable (a full disk, say), so log it
// and stop too rather than spin.
fn is_gone(r: io::Result<()>) -> bool {
    match r {
        Ok(()) => false,
        Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => true,
        Err(e) => {
            eprintln!("mimi: event sink write failed ({e}); stopping");
            true
        }
    }
}

// --sink PATH, if given. Parses both `--sink PATH` and `--sink=PATH`.
fn sink_arg() -> Option<String> {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == "--sink" {
            return args.next();
        }
        if let Some(rest) = a.strip_prefix("--sink=") {
            return Some(rest.to_string());
        }
    }
    None
}

// resolve_offsets returns the task_struct/mm_struct field byte offsets for the RUNNING kernel, in
// OFFSETS-map index order, read from its own BTF (/sys/kernel/btf/vmlinux). Per field it uses the
// BTF value, falling back to the build-kernel offset in OFFSET_TABLE only when BTF is unavailable or
// lacks the field (warned, never silent). The loader writes these into the probe's OFFSETS map, so
// the one binary adapts to each kernel's layout rather than assuming one (CO-RE); the probe carries
// no offset of its own.
fn resolve_offsets() -> [u32; mimi_types::OFFSET_COUNT as usize] {
    let resolved = match std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| e.to_string())
        .and_then(|d| btf::member_offsets(&d, &["task_struct", "mm_struct"]))
    {
        Ok(m) => Some(m),
        Err(e) => {
            eprintln!(
                "mimi: no usable kernel BTF ({e}); using build-kernel offsets, correct only on a matching kernel"
            );
            None
        }
    };
    let mut out = [0u32; mimi_types::OFFSET_COUNT as usize];
    for (i, (st, field, fallback)) in mimi_types::OFFSET_TABLE.iter().enumerate() {
        out[i] = match resolved
            .as_ref()
            .and_then(|m| m.get(*st)?.get(*field))
            .copied()
        {
            Some(v) => {
                if v != *fallback {
                    eprintln!(
                        "mimi: {st}.{field} at {v} on this kernel (build kernel {fallback}); using BTF"
                    );
                }
                v
            }
            None => {
                if resolved.is_some() {
                    eprintln!(
                        "mimi: {st}.{field} absent from kernel BTF; using build-kernel offset {fallback}"
                    );
                }
                *fallback
            }
        };
    }
    out
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

    // Fill the probe's OFFSETS map from this kernel's BTF before it runs: the probe reads its
    // task_struct/mm_struct field offsets from here, so one binary adapts to each kernel's layout
    // (CO-RE) instead of assuming the build kernel's. Done before loading the program so the map is
    // populated the moment the probe can run.
    {
        let offs = resolve_offsets();
        let mut map: aya::maps::Array<_, u32> =
            aya::maps::Array::try_from(ebpf.map_mut("OFFSETS").expect("OFFSETS map in the probe"))?;
        for (i, v) in offs.iter().enumerate() {
            map.set(i as u32, *v, 0)?;
        }
    }

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

    // The event sink: a durable file when `--sink PATH` is given (what the systemd unit uses), else
    // stdout (for `mimi | banken`, a pipe, or dev use). mimi opening the file itself -- as the
    // service user, in its writable LogsDirectory -- is deliberate: systemd's StandardOutput=append:
    // to a DynamicUser LogsDirectory path fails to set up (exit 209/STDOUT, the sink dir not yet
    // present when the manager opens the fd), so the sensor owns its own file instead. We write
    // through `writeln!`/`flush` (both return a Result, so a vanished reader surfaces as the
    // BrokenPipe we exit cleanly on, never the panic `println!` raises -- a panic would crash-loop
    // under Restart=on-failure). Flush after each drain so banken tailing the file sees every batch
    // promptly, not only when an 8K buffer fills.
    let mut out: Box<dyn Write> = match sink_arg() {
        Some(path) => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| anyhow::anyhow!("mimi: cannot open --sink {path}: {e}"))?;
            Box::new(io::BufWriter::new(f))
        }
        None => Box::new(io::stdout()),
    };

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
