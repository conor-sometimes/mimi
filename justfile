# mimi's gate -- the banken bar. `just` lists targets; `just default` runs the whole thing. It runs
# on the pinned nightly (rust-toolchain.toml): the probe build needs it (build-std for the BPF
# target), and we test on the same toolchain for simplicity.

default: fmt-check clippy test deny

# Format (write locally; check in CI).
fmt:
    cargo fmt
fmt-check:
    cargo fmt --check

# Lints as errors, across the schema + userspace logic.
clippy:
    cargo clippy -p mimi-types --features user --all-targets -- -D warnings

# Unit tests of the shared schema + the parse/render logic (no kernel needed).
test:
    cargo test -p mimi-types --features user

# Supply-chain gate: advisories, licenses, sources (deny.toml). The fuzz crate is its own workspace
# (cargo-fuzz builds it with special flags), so gate it explicitly too -- the instrumented build
# must not be the one place with a floating dependency.
deny:
    cargo deny check
    cargo deny --manifest-path fuzz/Cargo.toml check

# The sensor<->brain contract: render_mimi must still equal the shared fixture that banken parses
# from its side (`just contract` there). The two repos' testdata/mimi_event.golden.jsonl must stay
# byte-identical, so a schema change has to move both halves of the family.
contract:
    cargo test -p mimi-types --features user golden_render_mimi

# Full build: compiles the BPF probe and embeds it in the mimi binary. Needs bpf-linker on PATH
# matching the nightly's LLVM -- see README "Toolchain".
build:
    cargo build --release

# The dependency tree -- the audit surface, in one place.
tree:
    cargo tree -e normal

# Run the sensor (needs root/CAP_BPF to load the probe).
run: build
    sudo ./target/release/mimi

# Point git at the repo's tracked hooks (core.hooksPath): no AI attribution in commit messages,
# no em/en dashes in messages or staged content. Run once after cloning.
install-hooks:
    git config core.hooksPath .githooks
    @echo "core.hooksPath -> .githooks"
