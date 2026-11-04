//! Std-side parsing and rendering of mimi's wire events (the `user` feature). Unit-tested on stable
//! with no kernel involved, so a schema or format regression is caught here, not in production.

use std::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::Lineage;

/// Interpret a ring-buffer record as a `Lineage`, or `None` if it is too short.
pub fn parse(bytes: &[u8]) -> Option<Lineage> {
    if bytes.len() < core::mem::size_of::<Lineage>() {
        return None;
    }
    // SAFETY: length checked above; `Lineage` is `repr(C)`, `Copy`, and every byte pattern is valid
    // (only integers and byte arrays). `read_unaligned` tolerates the ring buffer's alignment.
    Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Lineage) })
}

/// A task's `comm`, trimmed at the first NUL.
pub fn comm_str(comm: &[u8]) -> String {
    let len = comm.iter().position(|&c| c == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..len]).into_owned()
}

/// The execed process's argv, NUL-separated on the wire, rendered with spaces.
pub fn cmdline_str(lin: &Lineage) -> String {
    let m = (lin.cmdline_len as usize).min(lin.cmdline.len());
    let mut b = lin.cmdline[..m].to_vec();
    for c in b.iter_mut() {
        if *c == 0 {
            *c = b' ';
        }
    }
    String::from_utf8_lossy(&b).trim().to_string()
}

/// A human view: `process.*` and `process.parent.*` (one level, as OCSF/SentinelOne), plus a single
/// `process.ancestry` path for the full chain -- no `.parent.parent.parent` nesting.
pub fn render_text(lin: &Lineage) -> String {
    let n = (lin.count as usize).min(lin.chain.len());
    if n == 0 {
        return String::new();
    }
    let mut out = String::new();
    let p = &lin.chain[0];
    out.push_str(&format!(
        "process.name={} process.pid={}",
        comm_str(&p.comm),
        p.pid
    ));
    let cmd = cmdline_str(lin);
    if !cmd.is_empty() {
        out.push_str(&format!(" process.cmdline=\"{cmd}\""));
    }
    if n > 1 {
        let par = &lin.chain[1];
        out.push_str(&format!(
            "\nprocess.parent.name={} process.parent.pid={}",
            comm_str(&par.comm),
            par.pid
        ));
        let anc: Vec<String> = lin.chain[1..n]
            .iter()
            .map(|a| format!("{}({})", comm_str(&a.comm), a.pid))
            .collect();
        out.push_str(&format!("\nprocess.ancestry={}", anc.join(" < ")));
    }
    out
}

/// Minimal JSON string escaping (quotes, backslashes, control chars).
fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// The event as a JSON process object -- the shape banken ingests and maps onto OCSF `process` /
/// `parent_process`. A hand-rolled minimal encoder for the PoC; a serde schema (and the full OCSF
/// mapping) is the first-class follow-up.
pub fn render_json(lin: &Lineage) -> String {
    let n = (lin.count as usize).min(lin.chain.len());
    if n == 0 {
        return String::from("{}");
    }
    let p = &lin.chain[0];
    let mut s = format!(
        r#"{{"time_ns":{},"process":{{"name":"{}","pid":{},"cmd_line":"{}""#,
        lin.time_ns,
        json_escape(&comm_str(&p.comm)),
        p.pid,
        json_escape(&cmdline_str(lin)),
    );
    if n > 1 {
        let par = &lin.chain[1];
        s.push_str(&format!(
            r#","parent_process":{{"name":"{}","pid":{}}}"#,
            json_escape(&comm_str(&par.comm)),
            par.pid
        ));
    }
    s.push_str(r#"},"ancestry":["#);
    let anc: Vec<String> = lin.chain[..n]
        .iter()
        .map(|a| {
            format!(
                r#"{{"name":"{}","pid":{}}}"#,
                json_escape(&comm_str(&a.comm)),
                a.pid
            )
        })
        .collect();
    s.push_str(&anc.join(","));
    s.push_str("]}");
    s
}

/// The executed program's path, trimmed at the first NUL.
pub fn filename_str(filename: &[u8]) -> String {
    let len = filename
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(filename.len());
    String::from_utf8_lossy(&filename[..len]).into_owned()
}

/// The last path segment (OCSF file.name alongside file.path).
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Render one exec event in the OCSF-shaped schema banken ingests through its `mimi` parser (see
/// `crate::SCHEMA`). The `process` object matches banken's own OCSF process object exactly
/// (pid / name / cmd_line / file{path,name} / user{uid} / parent_process), so the two map with no
/// translation; `ancestry` is mimi's extension (the full chain, its headline). This JSON is the
/// contract; the shared fixture is a byte-for-byte copy, tested on both sides so the repos cannot
/// drift. `time` is the wall-clock RFC3339 stamp the loader derives from the monotonic `time_ns`
/// (kept as `capture_ns` for latency).
pub fn render_mimi(lin: &Lineage, time: &str) -> String {
    let n = (lin.count as usize).min(lin.chain.len());
    let image = filename_str(&lin.filename);
    let mut s = format!(
        r#"{{"schema":"{}","kind":"exec","time":"{}","capture_ns":{},"activity_id":1,"cmdline_truncated":{},"process":{{"#,
        crate::SCHEMA,
        json_escape(time),
        lin.time_ns,
        lin.argv_total_len > lin.cmdline_len,
    );
    if n > 0 {
        let p = &lin.chain[0];
        s.push_str(&format!(
            r#""pid":{},"name":"{}","cmd_line":"{}","file":{{"path":"{}","name":"{}"}},"user":{{"uid":"{}","gid":"{}"}}"#,
            p.pid,
            json_escape(&comm_str(&p.comm)),
            json_escape(&cmdline_str(lin)),
            json_escape(&image),
            json_escape(basename(&image)),
            lin.uid,
            lin.gid,
        ));
        if n > 1 {
            let par = &lin.chain[1];
            s.push_str(&format!(
                r#","parent_process":{{"pid":{},"name":"{}"}}"#,
                par.pid,
                json_escape(&comm_str(&par.comm)),
            ));
        }
    }
    s.push('}'); // close "process"
    s.push_str(r#","ancestry":["#);
    let anc: Vec<String> = lin.chain[..n]
        .iter()
        .map(|a| {
            format!(
                r#"{{"pid":{},"name":"{}"}}"#,
                a.pid,
                json_escape(&comm_str(&a.comm))
            )
        })
        .collect();
    s.push_str(&anc.join(","));
    s.push_str("]}");
    s
}

/// Format a wall-clock time (nanoseconds since the Unix epoch, UTC) as RFC3339Nano, with no
/// dependency: the y/m/d comes from the standard civil-from-days algorithm (Hinnant). The loader
/// derives this from the probe's monotonic `time_ns` plus a sampled realtime offset, and passes it
/// to `render_mimi` as the event `time`; the raw monotonic value rides along as `capture_ns` for
/// latency measurement.
pub fn rfc3339_utc(epoch_ns: u128) -> String {
    let secs = (epoch_ns / 1_000_000_000) as i64;
    let nanos = (epoch_ns % 1_000_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );
    // civil_from_days: `days` is days since 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (yoe as i64 + era * 400) + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{nanos:09}Z")
}

/// The byte offset of the `__data_loc char[] filename` field within the
/// sched_process_exec tracepoint record, parsed from that tracepoint's tracefs
/// `format` file. This is NOT a BTF struct field: it is the tracepoint record
/// layout, and the common-tracepoint header is 8 bytes on mainline 6.x but 12
/// on RHEL-9's 5.14, so the field sits at 8 there and 12 here. Reading it from
/// the running kernel (rather than hardcoding 8) is what makes the probe's path
/// capture correct on both. `None` when the field is absent.
pub fn parse_filename_offset(format: &str) -> Option<u32> {
    for line in format.lines() {
        // e.g. "\tfield:__data_loc char[] filename;\toffset:12;\tsize:4;\tsigned:1;"
        if !(line.contains("__data_loc") && line.contains("filename;")) {
            continue;
        }
        let rest = line.split("offset:").nth(1)?;
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        return rest[..end].parse::<u32>().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ancestor, COMM_LEN, Lineage};

    #[test]
    fn filename_offset_reads_the_per_kernel_record_layout() {
        // Real sched_process_exec `format` on a mainline 6.x kernel: filename @8.
        let mainline = "name: sched_process_exec\nID: 316\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:1;\n\tfield:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;\n\tfield:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;\n";
        assert_eq!(parse_filename_offset(mainline), Some(8));

        // Real format on RHEL-9's 5.14: the header is 4 bytes larger, filename @12.
        let rhel = "name: sched_process_exec\nformat:\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\tfield:__data_loc char[] filename;\toffset:12;\tsize:4;\tsigned:1;\n\tfield:pid_t pid;\toffset:16;\tsize:4;\tsigned:1;\n\tfield:pid_t old_pid;\toffset:20;\tsize:4;\tsigned:1;\n";
        assert_eq!(parse_filename_offset(rhel), Some(12));

        // No filename field -> None (the loader then uses its fallback).
        assert_eq!(
            parse_filename_offset("name: x\nformat:\n\tfield:int common_pid;\toffset:4;\n"),
            None
        );
    }

    fn comm(name: &str) -> [u8; COMM_LEN] {
        let mut c = [0u8; COMM_LEN];
        let b = name.as_bytes();
        c[..b.len()].copy_from_slice(b);
        c
    }

    fn sample() -> Lineage {
        let mut l = Lineage::zeroed();
        l.chain[0] = Ancestor {
            pid: 213541,
            comm: comm("ping"),
        };
        l.chain[1] = Ancestor {
            pid: 210139,
            comm: comm("fish"),
        };
        l.chain[2] = Ancestor {
            pid: 1,
            comm: comm("systemd"),
        };
        l.count = 3;
        let cmd = b"ping\x008.8.8.8\x00";
        l.cmdline[..cmd.len()].copy_from_slice(cmd);
        l.cmdline_len = cmd.len() as u32;
        l.argv_total_len = l.cmdline_len; // not truncated
        l.uid = 1000;
        l.gid = 1000;
        let fname = b"/usr/bin/ping";
        l.filename[..fname.len()].copy_from_slice(fname);
        l
    }

    #[test]
    fn parse_round_trips_the_wire_bytes() {
        let l = sample();
        // SAFETY: reading a repr(C) Copy struct as its own bytes.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &l as *const Lineage as *const u8,
                core::mem::size_of::<Lineage>(),
            )
        };
        let got = parse(bytes).expect("full-length record parses");
        assert_eq!(got.count, 3);
        assert_eq!(got.chain[0].pid, 213541);
        assert_eq!(got.cmdline_len, 13);
    }

    #[test]
    fn parse_rejects_a_short_record() {
        assert!(parse(&[0u8; 8]).is_none());
    }

    #[test]
    fn renders_process_parent_and_ancestry() {
        let out = render_text(&sample());
        assert!(
            out.contains("process.name=ping process.pid=213541"),
            "{out}"
        );
        assert!(out.contains(r#"process.cmdline="ping 8.8.8.8""#), "{out}");
        assert!(
            out.contains("process.parent.name=fish process.parent.pid=210139"),
            "{out}"
        );
        assert!(
            out.contains("process.ancestry=fish(210139) < systemd(1)"),
            "{out}"
        );
        // the whole point: no ugly deep nesting
        assert!(!out.contains("parent.parent"), "{out}");
    }

    #[test]
    fn comm_trims_at_nul() {
        assert_eq!(comm_str(&comm("ls")), "ls");
        assert_eq!(comm_str(&comm("sshd-session")), "sshd-session");
    }

    #[test]
    fn cmdline_joins_nul_separated_argv() {
        assert_eq!(cmdline_str(&sample()), "ping 8.8.8.8");
    }

    #[test]
    fn empty_event_renders_nothing() {
        assert_eq!(render_text(&Lineage::zeroed()), "");
    }

    #[test]
    fn renders_json_process_object() {
        let j = render_json(&sample());
        assert!(j.starts_with('{') && j.ends_with('}'), "{j}");
        assert!(
            j.contains(r#""process":{"name":"ping","pid":213541"#),
            "{j}"
        );
        assert!(j.contains(r#""cmd_line":"ping 8.8.8.8""#), "{j}");
        assert!(
            j.contains(r#""parent_process":{"name":"fish","pid":210139}"#),
            "{j}"
        );
        assert!(j.contains(r#""ancestry":["#), "{j}");
    }

    #[test]
    fn json_escapes_quotes_and_backslashes() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn parse_never_panics_on_any_length() {
        // A malformed/short/overlong record must never crash the reader (banken's "inert data"
        // bar): a hostile kernel-or-ringbuf byte sequence degrades to None, never a panic.
        for len in 0..(core::mem::size_of::<Lineage>() + 8) {
            let v = std::vec::from_elem(0xABu8, len);
            let _ = parse(&v);
        }
        assert!(parse(&std::vec::from_elem(0u8, core::mem::size_of::<Lineage>())).is_some());
    }

    // --- property tests -------------------------------------------------------------------------
    // Invariants over generated inputs, complementing the coverage-guided fuzz target (which drives
    // the destructive parse path). No `proptest`/`rand` dependency: a seeded xorshift keeps the
    // generator deterministic and the crate's dep tree empty.

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn byte(&mut self) -> u8 {
            self.next_u64() as u8
        }
    }

    /// A fully-random event: `count` and `cmdline_len` are left unclamped (they may exceed the
    /// array bounds) and every byte is arbitrary, so the renderers face hostile field values.
    fn random_lineage(r: &mut Rng) -> Lineage {
        let mut l = Lineage::zeroed();
        l.time_ns = r.next_u64();
        l.count = r.u32();
        l.cmdline_len = r.u32();
        l.argv_total_len = r.u32();
        l.uid = r.u32();
        l.gid = r.u32();
        for b in l.filename.iter_mut() {
            *b = r.byte();
        }
        for b in l.cmdline.iter_mut() {
            *b = r.byte();
        }
        for a in l.chain.iter_mut() {
            a.pid = r.u32();
            for b in a.comm.iter_mut() {
                *b = r.byte();
            }
        }
        l
    }

    fn as_bytes(l: &Lineage) -> Vec<u8> {
        // SAFETY: reading a repr(C) Copy struct as its own bytes.
        unsafe {
            core::slice::from_raw_parts(
                l as *const Lineage as *const u8,
                core::mem::size_of::<Lineage>(),
            )
        }
        .to_vec()
    }

    /// Quote-aware, escape-respecting structural check: braces/brackets match and nest, and every
    /// string is closed. A JSON-escaping bug (an unescaped `"` in a value) desyncs the scanner and
    /// trips this.
    fn json_well_formed(s: &str) -> bool {
        let mut stack: Vec<u8> = Vec::new();
        let mut in_str = false;
        let mut esc = false;
        for &c in s.as_bytes() {
            if in_str {
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    in_str = false;
                }
                continue;
            }
            match c {
                b'"' => in_str = true,
                b'{' => stack.push(b'}'),
                b'[' => stack.push(b']'),
                b'}' | b']' => {
                    if stack.pop() != Some(c) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        stack.is_empty() && !in_str
    }

    #[test]
    fn prop_renderers_never_panic_and_emit_well_formed_json() {
        let mut r = Rng::new(0xDEAD_BEEF);
        for _ in 0..5000 {
            let l = random_lineage(&mut r);
            let _ = render_text(&l); // must not panic on any field values
            let j = render_json(&l);
            assert!(
                json_well_formed(&j),
                "render_json emitted malformed JSON: {j}"
            );
            let m = render_mimi(&l, "2026-11-02T00:00:00Z");
            assert!(
                json_well_formed(&m),
                "render_mimi emitted malformed JSON: {m}"
            );
        }
    }

    #[test]
    fn prop_parse_serialize_round_trips_arbitrary_events() {
        let mut r = Rng::new(0x1234_5678_9ABC_DEF0);
        for _ in 0..5000 {
            let l = random_lineage(&mut r);
            let got = parse(&as_bytes(&l)).expect("a full-length record always parses");
            assert_eq!(got.time_ns, l.time_ns);
            assert_eq!(got.count, l.count);
            assert_eq!(got.cmdline_len, l.cmdline_len);
            assert_eq!(got.argv_total_len, l.argv_total_len);
            assert_eq!(got.uid, l.uid);
            assert_eq!(got.gid, l.gid);
            assert_eq!(got.filename, l.filename);
            assert_eq!(got.cmdline, l.cmdline);
            for (g, e) in got.chain.iter().zip(l.chain.iter()) {
                assert_eq!(g.pid, e.pid);
                assert_eq!(g.comm, e.comm);
            }
        }
    }

    #[test]
    fn prop_cmdline_str_is_bounded_and_nul_free() {
        let mut r = Rng::new(0xA5A5_5A5A);
        for _ in 0..5000 {
            let l = random_lineage(&mut r);
            let s = cmdline_str(&l);
            // Bound on *chars*, not bytes: from_utf8_lossy maps each byte to at most one char, but
            // an invalid byte becomes a 3-byte replacement char, so the byte length can exceed the
            // buffer. What must hold is that no more input than the buffer was ever consumed.
            assert!(
                s.chars().count() <= l.cmdline.len(),
                "cmdline_str consumed past the buffer"
            );
            assert!(!s.contains('\0'), "cmdline_str leaked a NUL");
        }
    }

    #[test]
    fn prop_comm_str_ignores_bytes_after_the_first_nul() {
        let mut r = Rng::new(0x0F0F_F0F0);
        for _ in 0..5000 {
            let mut comm = [0u8; COMM_LEN];
            for b in comm.iter_mut() {
                *b = r.byte();
            }
            let first_nul = comm.iter().position(|&c| c == 0).unwrap_or(comm.len());
            let before = comm_str(&comm);
            assert!(!before.contains('\0'));
            // scrambling the bytes after the first NUL must not change the result
            let mut scrambled = comm;
            for b in scrambled[first_nul..].iter_mut() {
                *b = r.byte();
            }
            if first_nul < scrambled.len() {
                scrambled[first_nul] = 0; // keep the terminator in place
            }
            assert_eq!(before, comm_str(&scrambled));
        }
    }

    // --- golden tests ---------------------------------------------------------------------------
    // The wire contract between the probe (no_std) and the loader (std), which build separately: a
    // reordered or resized field would silently desync the two halves. `offset_of!` pins the
    // `#[repr(C)]` layout exactly -- stronger and lower-maintenance than a captured byte blob -- and
    // the two render goldens freeze the exact output format against accidental drift.

    #[test]
    fn golden_wire_layout() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<Lineage>(), 576, "Lineage wire size changed");
        assert_eq!(align_of::<Lineage>(), 8);
        assert_eq!(offset_of!(Lineage, time_ns), 0);
        assert_eq!(offset_of!(Lineage, count), 8);
        assert_eq!(offset_of!(Lineage, cmdline_len), 12);
        assert_eq!(offset_of!(Lineage, argv_total_len), 16);
        assert_eq!(offset_of!(Lineage, uid), 20);
        assert_eq!(offset_of!(Lineage, gid), 24);
        assert_eq!(offset_of!(Lineage, filename), 28);
        assert_eq!(offset_of!(Lineage, cmdline), 284);
        assert_eq!(offset_of!(Lineage, chain), 412);
        assert_eq!(size_of::<Ancestor>(), 20, "Ancestor wire size changed");
        assert_eq!(align_of::<Ancestor>(), 4);
        assert_eq!(offset_of!(Ancestor, pid), 0);
        assert_eq!(offset_of!(Ancestor, comm), 4);
    }

    #[test]
    fn golden_render_text() {
        assert_eq!(
            render_text(&sample()),
            "process.name=ping process.pid=213541 process.cmdline=\"ping 8.8.8.8\"\n\
             process.parent.name=fish process.parent.pid=210139\n\
             process.ancestry=fish(210139) < systemd(1)"
        );
    }

    #[test]
    fn golden_render_json() {
        assert_eq!(
            render_json(&sample()),
            concat!(
                r#"{"time_ns":0,"process":{"name":"ping","pid":213541,"cmd_line":"ping 8.8.8.8","#,
                r#""parent_process":{"name":"fish","pid":210139}},"#,
                r#""ancestry":[{"name":"ping","pid":213541},{"name":"fish","pid":210139},"#,
                r#"{"name":"systemd","pid":1}]}"#
            )
        );
    }

    #[test]
    fn golden_render_mimi() {
        // The shared contract fixture: banken's mimi parser is tested against a byte-for-byte copy
        // of this same file, so a change here is a contract change that must move both sides.
        // `just contract` checks the two repos' copies still match.
        let fixture = include_str!("../../testdata/mimi_event.golden.jsonl");
        assert_eq!(
            render_mimi(&sample(), "2026-11-02T00:00:00Z"),
            fixture.trim_end()
        );
    }

    #[test]
    fn rfc3339_known_epochs() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "1970-01-01T00:00:01.000000000Z");
        assert_eq!(
            rfc3339_utc(86_400_000_000_000),
            "1970-01-02T00:00:00.000000000Z"
        );
        // the Unix "billennium": 1_000_000_000 s since the epoch = 2001-09-09 01:46:40 UTC.
        assert_eq!(
            rfc3339_utc(1_000_000_000_000_000_000),
            "2001-09-09T01:46:40.000000000Z"
        );
    }
}
