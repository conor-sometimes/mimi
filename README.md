# mimi

**mimi** (耳, "ears") is the eBPF telemetry sensor for [banken](https://github.com/conor-sometimes/banken)
(番犬, "watchdog"). It watches the kernel - process execs today, file and network next - and emits
structured events for banken to detect on. A separate binary from banken, so **banken-core stays
pure-Go with no kernel component**: the kernel-adjacent, `unsafe`-by-nature part lives here, in Rust,
where the unsafe is small, marked, and checked by the kernel's BPF verifier.

Status: **graduating to the banken bar.** A Rust + [aya](https://aya-rs.dev) program that attaches
to `sched_process_exec` and, for every exec, captures the executable path, argv, uid/gid and the
full ancestry (walking `task_struct->real_parent` to pid 1), and emits them as one OCSF-shaped JSON
line banken ingests directly. One self-contained binary - aya embeds the BPF object - **no C**: the
probe and the loader are both Rust. The probe assembles the event in a per-CPU scratch map (off the
512-byte BPF stack) and counts any ring-buffer drops. (The live load on 6.x is the one step that
still needs a privileged run; everything up to it is built and tested.)

## Architecture

```mermaid
flowchart LR
    subgraph KERNEL["kernel"]
        K["sched_process_exec"] --> PR["mimi probe<br/>eBPF · Rust · no C<br/>walks real_parent, reads argv"]
    end
    subgraph USER["userspace"]
        LD["mimi loader<br/>Rust"] --> EV["Event schema<br/>mimi-types - the wire contract"]
    end
    PR -->|RingBuf| LD
    EV -->|stream| BK["banken<br/>Go brain"]
    BK --> AL["OCSF alert"]
```

mimi and banken are **decoupled**: they speak a wire schema, not linked code, so the sensor is
swappable (mimi, or Falco/Tetragon via an adapter) and banken never grows a kernel component. The
schema is the contract (`mimi-types`): the loader emits banken's OCSF `process` / `parent_process`
objects directly, the same nested-process model every EDR uses.

banken consumes mimi as a **continuous stream** (not a polled log), so end-to-end detection latency
is *capture + match*, not bounded by any scan interval - two independently-timed components would
compound latency ("miss the bus"). Events carry a capture timestamp (`time_ns`) so that latency is a
measured number.

## Event schema (`mimi-types`)

One `#[repr(C)]` layout shared no_std by the probe and std by the loader, so the two halves can never
disagree on the bytes. The loader emits each event as one JSON line whose `process` object is
banken's own OCSF process object (so it maps onto the brain with no translation); `--text` prints a
human view instead.

```json
{"schema":"mimi/2","kind":"exec","time":"2026-11-02T00:00:00Z","capture_ns":0,
 "process":{"pid":213541,"name":"ping","cmd_line":"ping 8.8.8.8",
            "file":{"path":"/usr/bin/ping","name":"ping"},"user":{"uid":"1000","gid":"1000"},
            "parent_process":{"pid":210139,"name":"fish"}},
 "ancestry":[{"pid":213541,"name":"ping"},{"pid":210139,"name":"fish"},{"pid":1,"name":"systemd"}]}
```

`process`/`parent_process` are OCSF (one parent level, as OCSF / SentinelOne); the full chain is
mimi's `ancestry` extension, not `.parent.parent` nesting. The `schema` version lets banken refuse
or downgrade on skew, and the shared fixture (`testdata/mimi_event.golden.jsonl`) is tested on both
sides so the two repos cannot drift (`just contract`).

## Dependencies

Every dependency is audit surface, so the bar is hardening/function value vs the cost of auditing its
whole tree. mimi keeps **`aya`** (the loader), **`anyhow`** (error context in a root daemon) and
**`libc`** (the memlock bump); the aya template's `tokio`/`clap`/`log` freeloaders are stripped.
Versions are exact-pinned, `Cargo.lock` is committed, Dependabot proposes bumps, and `cargo-deny`
(`deny.toml`) gates advisories, licenses and sources. `just tree` prints the audit surface.

## Toolchain

The **userspace builds on stable**; only the **probe needs a pinned nightly**, because the BPF target
has no prebuilt `core`, so aya builds it from source with `-Z build-std` (nightly-only). The nightly
is pinned (`rust-toolchain.toml`) - frozen, reproducible - and its LLVM must match the `bpf-linker`
mimi links with. nixpkgs' prebuilt `bpf-linker` lags, so build `bpf-linker 0.12` against nixpkgs'
LLVM 23 (with `libLLVM.so` from the `lib` output on the linker path). The painless path is the
[workbench](https://github.com/conor-sometimes/workbench) env, which pins all of it (fenix-style
nightly plus a nix-built `bpf-linker` 0.12 against LLVM 23, RPATH set), so there is no hand setup:

```sh
nix run github:conor-sometimes/workbench#mimi -- -c 'cargo build'   # the whole toolchain, pinned
```

## Build and test

```sh
just            # the gate: fmt + clippy + test + cargo-deny
just test       # unit tests of the schema + parse/render logic (no kernel)
just build      # full build: compiles the probe and embeds it
just run        # build + run (needs root to load the probe)
```

## Portability

The PoC reads `task_struct` by hardcoded offsets, so it runs on exactly its build kernel. The
first-class sensor uses **CO-RE** (relocate the offsets against each kernel's BTF at load) so one
binary runs on any BTF-capable kernel - which is what the planned **live distro matrix** (boot each
distro's own kernel, load mimi, assert it captures an exec) both requires and proves.

## License

MIT. mimi links aya, which is dual MIT / Apache-2.0.
