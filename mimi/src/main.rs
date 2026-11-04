use anyhow::Context;
use aya::{maps::RingBuf, programs::TracePoint};
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod btf;
mod preflight;

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

// What a sink write/flush result means for the loop.
enum Sink {
    Ok,                   // written; keep going
    ReaderGone,           // the consumer closed a pipe sink (BrokenPipe): a clean stop, exit 0
    Fatal(anyhow::Error), // the sink is unusable after retries: stop with a clear non-zero exit
}

// Flush the sink, retrying a transient error with bounded backoff before giving up. A momentary
// hiccup (a brief ENOSPC that log rotation clears, an EINTR) is ridden out rather than turned into a
// crash-loop; a persistent failure (a full or read-only disk) becomes ONE clear line to stderr (the
// journal) and a fatal exit, so the unit shows exactly why it stopped instead of an opaque loop.
// BrokenPipe on a pipe sink is the normal "reader closed" signal: a clean stop, never an error.
fn flush_sink(out: &mut dyn Write) -> Sink {
    const MAX_ATTEMPTS: u32 = 5;
    let mut delay = Duration::from_millis(100);
    for attempt in 1..=MAX_ATTEMPTS {
        match out.flush() {
            Ok(()) => return Sink::Ok,
            Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => return Sink::ReaderGone,
            Err(e) if attempt == MAX_ATTEMPTS => {
                return Sink::Fatal(anyhow::Error::from(e).context(
                    "event sink still unwritable after retries -- likely a full or read-only disk at the sink path; free space or fix the mount (the unit restarts on-failure, so it recovers once the sink is writable again)",
                ));
            }
            Err(e) => {
                eprintln!(
                    "mimi: event sink write failed ({e}); retry {attempt}/{MAX_ATTEMPTS} in {}ms",
                    delay.as_millis()
                );
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
    unreachable!("the loop returns on the final attempt")
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
    // The tracepoint record offset is not a BTF struct field, so it is resolved
    // from tracefs separately from the loop above.
    out[mimi_types::OFF_IDX_FILENAME_LOC as usize] = filename_loc_offset();
    out
}

/// The sched_process_exec `__data_loc filename` byte offset for the RUNNING
/// kernel, read from its own tracefs `.../format`. This is a tracepoint record
/// layout, not a struct in vmlinux BTF, so it cannot come from member_offsets:
/// the common-tracepoint header is 8 bytes on mainline 6.x but 12 on RHEL-9's
/// 5.14, so the field sits at 8 there and 12 here. Reading it per-kernel is what
/// the old hardcoded offset got wrong (empty path on 5.14). Falls back to the
/// mainline offset when tracefs is unreadable.
fn filename_loc_offset() -> u32 {
    let fallback = mimi_types::FILENAME_LOC_DEFAULT;
    for base in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let path = format!("{base}/events/sched/sched_process_exec/format");
        let Ok(fmt) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(v) = mimi_types::parse_filename_offset(&fmt) {
            if v != fallback {
                eprintln!(
                    "mimi: sched_process_exec filename at record offset {v} on this kernel (mainline 6.x is {fallback}); using tracefs"
                );
            }
            return v;
        }
    }
    eprintln!(
        "mimi: could not read the sched_process_exec format from tracefs; using the mainline filename offset {fallback} (wrong on a shifted-header kernel such as RHEL-9's 5.14)"
    );
    fallback
}

fn main() -> anyhow::Result<()> {
    // Bump the memlock rlimit for older kernels' map accounting.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let sink = sink_arg();

    // `mimi --check`: run the preflight doctor and exit (0 if every hard dependency is met, non-zero
    // otherwise). Loads nothing -- an operator can run it against a live box to see what to fix.
    if std::env::args().any(|a| a == "--check") {
        let checks = preflight::run(sink.as_deref());
        if preflight::report(&checks) {
            eprintln!("mimi check: OK -- all hard dependencies satisfied");
            std::process::exit(0);
        }
        eprintln!("mimi check: FAILED -- fix the item(s) marked FAIL above, then re-run");
        std::process::exit(1);
    }

    // Implicit preflight on every boot: a missing hard dependency (tracefs unreadable, no caps,
    // unwritable sink) is a clear fatal with the fix, printed to stderr -> journal, BEFORE the opaque
    // aya load path. This is what stops the "exit 1 with nothing useful in the journal" crash-loop.
    preflight::preflight(sink.as_deref())?;

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mimi"
    )))
    .context(
        "loading the embedded BPF object (CO-RE relocation + map creation against this kernel). An EPERM here means missing CAP_BPF/CAP_PERFMON, kernel lockdown, or too-low RLIMIT_MEMLOCK; a BTF/relocation error means the kernel lacks /sys/kernel/btf/vmlinux (run `mimi --check`)",
    )?;

    // Fill the probe's OFFSETS map from this kernel's BTF before it runs: the probe reads its
    // task_struct/mm_struct field offsets from here, so one binary adapts to each kernel's layout
    // (CO-RE) instead of assuming the build kernel's. Done before loading the program so the map is
    // populated the moment the probe can run.
    {
        let offs = resolve_offsets();
        let mut map: aya::maps::Array<_, u32> =
            aya::maps::Array::try_from(ebpf.map_mut("OFFSETS").expect("OFFSETS map in the probe"))
                .context("accessing the probe's OFFSETS map")?;
        for (i, v) in offs.iter().enumerate() {
            map.set(i as u32, *v, 0)
                .context("writing the resolved field offsets into the OFFSETS map")?;
        }
    }

    let program: &mut TracePoint = ebpf.program_mut("mimi").unwrap().try_into()?;
    program.load().context(
        "loading the tracepoint program into the kernel. An EPERM here means missing CAP_BPF/CAP_PERFMON or kernel lockdown; a verifier rejection points at a kernel/offset mismatch (run `mimi --check`)",
    )?;
    program.attach("sched", "sched_process_exec").context(
        "attaching to the sched:sched_process_exec tracepoint. This reads the tracepoint id from tracefs (/sys/kernel/tracing, root-owned 0700), which a non-root user can only read with CAP_DAC_READ_SEARCH -- the exact capability whose absence caused the original crash-loop (run `mimi --check`)",
    )?;

    let text = std::env::args().any(|a| a == "--text");

    // The probe stamps CLOCK_MONOTONIC (bpf_ktime_get_ns), so sample the offset to wall-clock once
    // and turn each event's monotonic time_ns into a real UTC timestamp; capture_ns keeps the raw
    // monotonic value for latency measurement on the banken side.
    let wall_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    let offset_ns = wall_now - monotonic_ns();

    let mut ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap()).context(
        "creating the EVENTS ring buffer reader (needs CAP_BPF and sufficient RLIMIT_MEMLOCK)",
    )?;
    // The probe counts events it had to drop because the ring was full (per CPU); surface that so
    // loss under a burst is visible and counted, not silent (the classic EDR blinding failure).
    let drops: aya::maps::PerCpuArray<_, u64> =
        aya::maps::PerCpuArray::try_from(ebpf.take_map("DROPS").unwrap())
            .context("accessing the DROPS counter map")?;
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
    let mut out: Box<dyn Write> = match &sink {
        Some(path) => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| {
                    format!(
                        "opening the --sink file {path} for append (preflight checks writability; this is the real open). Make the path writable by the service user, or keep it under /var/log/mimi (systemd LogsDirectory owns it for the DynamicUser)"
                    )
                })?;
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
                if !line.is_empty() {
                    match writeln!(out, "{line}") {
                        Ok(()) => {}
                        Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
                        Err(e) => {
                            return Err(
                                anyhow::Error::from(e).context("writing an event line to the sink")
                            );
                        }
                    }
                }
            }
        }
        match flush_sink(out.as_mut()) {
            Sink::Ok => {}
            Sink::ReaderGone => return Ok(()),
            Sink::Fatal(e) => return Err(e),
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
