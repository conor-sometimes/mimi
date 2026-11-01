use aya::{maps::RingBuf, programs::TracePoint};
use std::time::Duration;

// mimi: load the probe, attach it to sched_process_exec, and print each exec event. The probe and
// its BPF object are embedded in this binary by the build script. Parsing and rendering live in
// mimi-types (the `user` feature) so they are shared with anything else that reads the wire format
// and are unit-tested without the kernel.
//
// This is the PoC's one-binary-prints-events shape. The real sensor streams structured events to
// banken continuously (so end-to-end latency is capture + match, not bounded by a scan interval) --
// see the roadmap; for now it prints the human view to stdout.
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

    // Default output is the JSON process object (the wire shape banken ingests / maps onto OCSF);
    // `--text` prints the human view instead.
    let text = std::env::args().any(|a| a == "--text");

    let mut ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    eprintln!("mimi: watching execs. Ctrl-C to stop.");

    loop {
        while let Some(item) = ring.next() {
            if let Some(lin) = mimi_types::parse(&item) {
                let out = if text {
                    mimi_types::render_text(&lin)
                } else {
                    mimi_types::render_json(&lin)
                };
                if !out.is_empty() {
                    println!("{out}");
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
