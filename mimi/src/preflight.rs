//! Startup self-check -- `mimi --check`, and run implicitly on every boot before the probe loads.
//!
//! The motivating incident: the hardened unit shipped without CAP_DAC_READ_SEARCH, so attaching the
//! tracepoint failed when the loader could not read tracefs, and the journal showed only "exit 1"
//! (the real error was buried in the append: sink). This module turns every such precondition into a
//! named pass/fail line with the fix, like a doctor: tracefs readable, kernel BTF present, the
//! capabilities the loader needs (parsed from /proc/self/status CapEff), and the sink writable.
//!
//! A missing HARD dependency makes mimi exit non-zero with a one-line summary, so a restart under
//! Restart=on-failure surfaces exactly what to fix in `journalctl -u mimi` instead of an opaque
//! crash-loop. BTF is a SOFT dependency: absent, the loader falls back to build-kernel offsets (its
//! existing behaviour), so it warns rather than refusing to start.

use std::io;
use std::path::Path;

// Capability bit numbers (linux/capability.h). The loader needs CAP_BPF + CAP_PERFMON to load the
// tracepoint program and read the ring buffer, and CAP_DAC_READ_SEARCH to read tracefs (root-owned
// 0700) as a non-root DynamicUser -- exactly the three the unit grants.
const CAP_DAC_READ_SEARCH: u8 = 2;
const CAP_PERFMON: u8 = 38;
const CAP_BPF: u8 = 39;
const REQUIRED_CAPS: [(&str, u8); 3] = [
    ("CAP_BPF", CAP_BPF),
    ("CAP_PERFMON", CAP_PERFMON),
    ("CAP_DAC_READ_SEARCH", CAP_DAC_READ_SEARCH),
];

// Where the sched:sched_process_exec tracepoint id lives. aya reads it here to attach; a non-root
// user needs CAP_DAC_READ_SEARCH to descend the root-owned 0700 tracefs directory.
const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];
const TRACEPOINT_REL: &str = "events/sched/sched_process_exec/id";

const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// Whether a failed check stops mimi (`Hard`) or merely warns because a working fallback exists
/// (`Soft`, as for BTF).
#[derive(PartialEq, Clone, Copy)]
pub enum Severity {
    Hard,
    Soft,
}

/// One preflight result: a named check, whether it passed, what was found, and -- when it did not --
/// the single actionable fix.
pub struct Check {
    pub name: &'static str,
    pub severity: Severity,
    pub ok: bool,
    pub detail: String,
    pub fix: Option<String>,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            severity: Severity::Hard,
            ok: true,
            detail: detail.into(),
            fix: None,
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check {
            name,
            severity: Severity::Hard,
            ok: false,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check {
            name,
            severity: Severity::Soft,
            ok: false,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// Parse the `CapEff:` hex mask out of /proc/self/status contents. Split out from the file read so
/// the bit logic is unit-tested without a live /proc.
fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

fn has_cap(mask: u64, bit: u8) -> bool {
    mask & (1u64 << bit) != 0
}

fn check_tracefs() -> Check {
    let mut any_root = false;
    let mut perm_denied = false;
    for root in TRACEFS_ROOTS {
        if Path::new(root).exists() {
            any_root = true;
        }
        let idp = format!("{root}/{TRACEPOINT_REL}");
        match std::fs::read_to_string(&idp) {
            Ok(_) => return Check::pass("tracefs readable", format!("{idp} readable")),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => perm_denied = true,
            Err(_) => {}
        }
    }
    if perm_denied {
        Check::fail(
            "tracefs readable",
            "tracefs is present but the sched:sched_process_exec tracepoint id is not readable (permission denied)",
            "tracefs is root-owned 0700; grant the unit CAP_DAC_READ_SEARCH (AmbientCapabilities), or run mimi as root",
        )
    } else if any_root {
        Check::fail(
            "tracefs readable",
            "tracefs is mounted but the sched:sched_process_exec tracepoint is absent",
            "unexpected on a modern kernel; confirm CONFIG_FTRACE and the sched tracepoints are enabled",
        )
    } else {
        Check::fail(
            "tracefs readable",
            "tracefs is not mounted at /sys/kernel/tracing or /sys/kernel/debug/tracing",
            "mount it (mount -t tracefs nodev /sys/kernel/tracing); NixOS mounts it by default, so check the service sandbox is not hiding it",
        )
    }
}

fn check_btf() -> Check {
    match std::fs::File::open(BTF_PATH) {
        Ok(_) => Check::pass("kernel BTF present", format!("{BTF_PATH} readable")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Check::warn(
            "kernel BTF present",
            format!("{BTF_PATH} missing"),
            "kernel built without CONFIG_DEBUG_INFO_BTF; CO-RE needs it -- mimi falls back to build-kernel field offsets, correct only on a matching kernel",
        ),
        Err(e) => Check::warn(
            "kernel BTF present",
            format!("{BTF_PATH} present but unreadable ({e})"),
            "CO-RE field offsets fall back to build-kernel values (correct only on a matching kernel); grant read access if captured fields look wrong",
        ),
    }
}

fn check_caps() -> Check {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            return Check::fail(
                "capabilities held",
                format!("cannot read /proc/self/status ({e})"),
                "ensure /proc is mounted and readable (ProtectProc must not hide the unit's own status)",
            );
        }
    };
    let Some(mask) = parse_cap_eff(&status) else {
        return Check::fail(
            "capabilities held",
            "no CapEff line in /proc/self/status",
            "unexpected; confirm this is a Linux /proc -- the loader cannot verify its capabilities",
        );
    };
    let missing: Vec<&str> = REQUIRED_CAPS
        .iter()
        .filter(|(_, bit)| !has_cap(mask, *bit))
        .map(|(n, _)| *n)
        .collect();
    if missing.is_empty() {
        Check::pass(
            "capabilities held",
            "CAP_BPF, CAP_PERFMON, CAP_DAC_READ_SEARCH effective",
        )
    } else {
        Check::fail(
            "capabilities held",
            format!("missing {}", missing.join(", ")),
            "grant them via the unit's AmbientCapabilities (CAP_BPF + CAP_PERFMON load the probe and read the ring; CAP_DAC_READ_SEARCH reads root-owned tracefs), or run as root. A map-creation EPERM despite these caps points at kernel lockdown or too-low RLIMIT_MEMLOCK (the unit sets LimitMEMLOCK=infinity)",
        )
    }
}

fn check_sink(sink: Option<&str>) -> Check {
    let Some(path) = sink else {
        return Check::pass("sink writable", "stdout (no --sink)");
    };
    let p = Path::new(path);
    if p.exists() {
        return match std::fs::OpenOptions::new().append(true).open(p) {
            Ok(_) => Check::pass("sink writable", format!("{path} appendable")),
            Err(e) => Check::fail(
                "sink writable",
                format!("{path} exists but cannot be opened for append ({e})"),
                "fix the sink file's ownership/permissions so the service user can append (LogsDirectory owns /var/log/mimi for the DynamicUser)",
            ),
        };
    }
    // The sink does not exist yet (normal on a fresh unit): probe the parent directory's writability
    // without leaving a file behind, so `mimi --check` run by hand as root never pre-creates a
    // root-owned sink the DynamicUser then cannot append to.
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let probe = dir.join(format!(".mimi-check-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Check::pass(
                "sink writable",
                format!("{} writable (sink will be created there)", dir.display()),
            )
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Check::fail(
            "sink writable",
            format!("sink directory {} does not exist", dir.display()),
            "create it writable by the service user, or set services.mimi.sink under /var/log/mimi (systemd LogsDirectory creates and owns it)",
        ),
        Err(e) => Check::fail(
            "sink writable",
            format!("sink directory {} is not writable ({e})", dir.display()),
            "make it writable by the service user, or use a sink under /var/log/mimi (systemd LogsDirectory)",
        ),
    }
}

/// Run every check, in the order an operator reads them.
pub fn run(sink: Option<&str>) -> Vec<Check> {
    vec![check_tracefs(), check_btf(), check_caps(), check_sink(sink)]
}

/// Print each check to stderr (so it lands in the journal), one line plus a `fix:` line on anything
/// that is not a pass. Returns whether every HARD dependency is satisfied.
pub fn report(checks: &[Check]) -> bool {
    let mut hard_ok = true;
    for c in checks {
        let tag = if c.ok {
            "PASS"
        } else if c.severity == Severity::Soft {
            "WARN"
        } else {
            hard_ok = false;
            "FAIL"
        };
        eprintln!("mimi check: [{tag}] {}: {}", c.name, c.detail);
        if let Some(fix) = &c.fix {
            eprintln!("mimi check:        fix: {fix}");
        }
    }
    hard_ok
}

/// Run the preflight, print it, and return `Err` naming the missing hard dependencies if any failed
/// -- the implicit boot path, so a missing hard dep is a clear fatal, never an opaque exit-1 loop.
pub fn preflight(sink: Option<&str>) -> anyhow::Result<()> {
    let checks = run(sink);
    if report(&checks) {
        return Ok(());
    }
    let failed: Vec<&str> = checks
        .iter()
        .filter(|c| !c.ok && c.severity == Severity::Hard)
        .map(|c| c.name)
        .collect();
    anyhow::bail!(
        "preflight failed ({}) -- see the fix line(s) above; mimi will not start until the hard dependency is met",
        failed.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cap_eff_and_decodes_bits() {
        // A mask with exactly CAP_BPF (39), CAP_PERFMON (38), CAP_DAC_READ_SEARCH (2) set.
        let mask = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON) | (1u64 << CAP_DAC_READ_SEARCH);
        let status = format!("Name:\tmimi\nCapEff:\t{mask:016x}\nSeccomp:\t2\n");
        let got = parse_cap_eff(&status).expect("CapEff parsed");
        assert_eq!(got, mask);
        for (_, bit) in REQUIRED_CAPS {
            assert!(has_cap(got, bit));
        }
        // A bit we do not require is absent.
        assert!(!has_cap(got, 0)); // CAP_CHOWN
    }

    #[test]
    fn cap_eff_absent_is_none() {
        assert!(parse_cap_eff("Name:\tmimi\nSeccomp:\t2\n").is_none());
    }

    #[test]
    fn missing_caps_are_reported_with_a_fix() {
        // Reproduce the incident mask: CAP_BPF + CAP_PERFMON but NOT CAP_DAC_READ_SEARCH.
        let mask = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        let missing: Vec<&str> = REQUIRED_CAPS
            .iter()
            .filter(|(_, bit)| !has_cap(mask, *bit))
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(missing, vec!["CAP_DAC_READ_SEARCH"]);
    }

    #[test]
    fn sink_in_a_writable_dir_passes_without_leaving_a_file() {
        let dir = std::env::temp_dir().join(format!("mimi-pf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sink = dir.join("events.jsonl");
        let c = check_sink(Some(sink.to_str().unwrap()));
        assert!(c.ok, "writable dir should pass: {}", c.detail);
        // The probe left nothing behind, and the sink itself was not created.
        assert!(!sink.exists(), "check_sink must not create the sink");
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(leftovers.is_empty(), "check_sink left a probe file behind");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sink_in_a_missing_dir_fails_with_an_actionable_fix() {
        let c = check_sink(Some("/no/such/mimi/dir/events.jsonl"));
        assert!(!c.ok && c.severity == Severity::Hard);
        let fix = c.fix.unwrap();
        assert!(
            fix.contains("/var/log/mimi"),
            "fix should point at LogsDirectory: {fix}"
        );
    }

    #[test]
    fn report_returns_false_when_a_hard_check_fails_but_true_on_only_warnings() {
        let hard_fail = vec![Check::fail("x", "broke", "do y")];
        assert!(!report(&hard_fail));
        let only_warn = vec![
            Check::pass("a", "fine"),
            Check::warn("b", "soft", "optional fix"),
        ];
        assert!(report(&only_warn));
    }
}
