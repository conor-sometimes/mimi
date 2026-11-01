use std::env;
use std::path::PathBuf;

/// Building the BPF program has an undeclared dependency on the `bpf-linker` binary (aya links the
/// BPF bytecode with it), so rebuild when that binary changes. We locate it with a plain PATH scan
/// rather than pull the `which` crate (and its rustix / windows-sys tree) in for one lookup -- the
/// "no freeloader deps" rule: a whole dependency subtree is not worth one `find`.
fn main() {
    let linker = find_on_path("bpf-linker")
        .expect("bpf-linker not found on PATH -- see README \"Toolchain\"");
    println!("cargo:rerun-if-changed={}", linker.display());
}

fn find_on_path(bin: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}
