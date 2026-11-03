{
  # mimi's reproducible build. The three-way LLVM coherence that aya needs -- rustc's LLVM ==
  # bpf-linker's LLVM == what aya-build links -- is fragile assembled by hand, so this freezes it:
  #
  #   * fenix pins the exact nightly (nightly-2026-10-31, rustc 1.101 / LLVM 23.1) with rust-src, so
  #     the probe's `-Z build-std` for the BPF target is reproducible.
  #   * a bpf-linker 0.12 built against nixpkgs llvmPackages_23 (23.1.0), so its LLVM matches the
  #     nightly's and it carries its own RPATH to libLLVM.
  #
  # `nix develop` gives that toolchain a shell; `nix build .#mimi` builds the self-contained binary
  # (loader + embedded probe) hermetically with crane, so `services.mimi.package` has a default and
  # the one-switch (services.banken.mimi.enable) deploys with nothing built by hand.
  description = "mimi: eBPF telemetry sensor for banken (Rust + aya)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    { self, nixpkgs, fenix, crane }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      # Everything a system needs, shared by devShells and packages.
      perSystem =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # The pinned nightly from rust-toolchain.toml, resolved reproducibly by fenix (with
          # rust-src, needed for the probe's -Z build-std of the BPF target).
          toolchain =
            (fenix.packages.${system}.toolchainOf {
              channel = "nightly";
              date = "2026-10-31";
              sha256 = "sha256-07UyQu51OrDSHsy37ts4KC/NChHMfh5ZPY9QrihIXYo=";
            }).withComponents
              [
                "cargo"
                "rustc"
                "rust-src"
                "rustfmt"
                "clippy"
              ];

          # The same pinned nightly PLUS the musl target's std, combined into one sysroot, so the
          # userspace crate can build `--target x86_64-unknown-linux-musl` into a fully-static,
          # copy-and-run binary for any Linux distro (banken+mimi shipping to a non-NixOS host), not
          # just NixOS. The musl rust-std must be the SAME nightly as `toolchain`: the probe's
          # build-std and the userspace std have to come from one compiler, so it reuses the exact
          # nightly date + manifest sha256 (fenix keys one hash per nightly, covering all targets).
          # Only the userspace crate (`-p mimi`) goes to musl; mimi-ebpf still targets bpfel, so this
          # shell still needs bpf-linker + the rustup-shim (see the `.#musl` devShell below).
          muslToolchain = fenix.packages.${system}.combine [
            toolchain
            (fenix.packages.${system}.targets."x86_64-unknown-linux-musl".toolchainOf {
              channel = "nightly";
              date = "2026-10-31";
              sha256 = "sha256-07UyQu51OrDSHsy37ts4KC/NChHMfh5ZPY9QrihIXYo=";
            }).rust-std
          ];

          # bpf-linker 0.12 against LLVM 23.1 (nixpkgs ships 0.9.15). It selects LLVM via a
          # `llvm-<major>` feature (llvm-config from the dev output) and links libLLVM.so (lib output).
          bpf-linker = pkgs.rustPlatform.buildRustPackage rec {
            pname = "bpf-linker";
            version = "0.12.0";
            src = pkgs.fetchFromGitHub {
              owner = "aya-rs";
              repo = "bpf-linker";
              tag = "v${version}";
              hash = "sha256-y4jlEs9oF5jLlLkJHqXUMsHOeLUhTCDeqwnYzp8H9yI=";
            };
            cargoHash = "sha256-MSjwNgFa847R8joc8oreVpWDujsKR9duooycmlaiB0U=";
            buildNoDefaultFeatures = true;
            buildFeatures = [ "llvm-23" ];
            nativeBuildInputs = [ pkgs.llvmPackages_23.llvm.dev ];
            buildInputs = [
              pkgs.zlib
              pkgs.libxml2
              pkgs.llvmPackages_23.llvm.lib
            ];
            doCheck = false;
          };

          # aya-build 0.2.0 (aya-rs/aya, tag aya-build-v0.2.0, `build_ebpf`) routes every rustc/cargo
          # invocation through `rustup run <toolchain> ...` the moment it finds a `rustup` on PATH --
          # including the `rustc_version` probe that fails with "failed to get rustc version meta". This
          # shell provides the nightly DIRECTLY via fenix: there is no rustup, and the three-way LLVM
          # coherence (see the header) depends on exactly nightly-2026-10-31, never whatever a `rustup
          # toolchain install nightly` would pull. But `nix develop` keeps the ambient PATH, and GitHub's
          # runners ship a stray rustup with no `nightly` installed, so aya-build's probe dies there.
          # This shim shadows any ambient rustup (devShell bins are prepended to PATH): it answers
          # `rustup run <toolchain> <cmd...>` by exec'ing <cmd...> against the fenix toolchain already on
          # PATH, so the build stays hermetic -- the nix toolchain, never a rustup-fetched one -- whether
          # or not the host has a rustup. Drop the shim once aya-build can use the ambient toolchain.
          rustup-shim = pkgs.writeShellScriptBin "rustup" ''
            if [ "$1" = "run" ] && [ "$#" -ge 3 ]; then
              shift 2   # drop `run` and the toolchain name; the fenix toolchain on PATH is the only one
              exec "$@"
            fi
            echo "rustup-shim: only 'rustup run <toolchain> <cmd...>' is supported in this hermetic shell (got: $*)" >&2
            exit 1
          '';

          craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);
          # The same crane, but the musl sysroot -- for the fully-static ship binary below.
          craneLibMusl = (crane.mkLib pkgs).overrideToolchain (_: muslToolchain);

          # The self-contained mimi binary: the loader with the BPF probe embedded. build.rs drives
          # a cargo-in-cargo `-Z build-std` compile of the probe for the BPF target, so it needs the
          # nightly + rust-src (the toolchain) and bpf-linker on PATH (nativeBuildInputs). Building
          # only -p mimi keeps mimi-ebpf a build-script artifact, not a host member. The musl ship
          # build (mimiMuslPackage) is the same recipe with the musl sysroot and target, so the args
          # are shared -- only the toolchain and CARGO_BUILD_TARGET differ.
          mimiArgs = {
            pname = "mimi";
            version = "0.1.0";
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            cargoExtraArgs = "--package mimi";
            nativeBuildInputs = [ bpf-linker ];
            doCheck = false;
            meta.mainProgram = "mimi";
            # The probe is compiled with -Z build-std for the BPF target, so the sandboxed build
            # needs std's own dependencies (rustc-literal-escaper, ...) vendored too, not just the
            # project's -- else the inner cargo cannot resolve them offline. Vendor both Cargo.locks:
            # the project's and the toolchain's rust-src library lock.
            cargoVendorDir = craneLib.vendorMultipleCargoDeps {
              cargoLockList = [
                ./Cargo.lock
                "${toolchain}/lib/rustlib/src/rust/library/Cargo.lock"
              ];
            };
          };
          mimiPackage = craneLib.buildPackage mimiArgs;

          # The fully-static musl ship binary, built hermetically so a VM test (checks.vm-musl) can
          # prove the STATIC binary -- not just the gnu one -- still loads the probe and emits OCSF.
          # Only the userspace crate targets musl; aya-build's inner cargo targets bpfel explicitly,
          # so CARGO_BUILD_TARGET here does not reach the probe compile, and crt-static (.cargo/
          # config.toml) is target-scoped. The userspace is pure Rust (aya loads via syscalls, libc
          # is only the memlock bump), so Rust links a self-contained musl -- no musl C toolchain.
          mimiMuslPackage = craneLibMusl.buildPackage (
            mimiArgs
            // {
              pname = "mimi-musl";
              CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            }
          );
        in
        {
          inherit
            pkgs
            toolchain
            bpf-linker
            rustup-shim
            muslToolchain
            mimiPackage
            mimiMuslPackage
            ;
        };
    in
    {
      # services.mimi: the sensor as a hardened systemd service. Usually turned on via banken's
      # services.banken.mimi.enable (the one switch); import this alongside banken's module. The
      # module wraps module.nix and defaults services.mimi.package to this flake's own mimi package,
      # so the one switch deploys turnkey (overridable with a plain mkForce/assignment).
      nixosModules.default =
        { pkgs, lib, ... }:
        {
          imports = [ ./module.nix ];
          config.services.mimi.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.mimi;
        };
      nixosModules.mimi = self.nixosModules.default;

      packages = forAllSystems (
        system:
        let
          s = perSystem system;
        in
        {
          mimi = s.mimiPackage;
          mimi-musl = s.mimiMuslPackage;
          default = s.mimiPackage;
        }
      );

      # Runtime VM tests, x86_64-linux only (runNixOSTest needs a KVM builder of the test's system):
      #   vm           -- the unit starts, stays up (no 209 crash-loop) and captures to its sink;
      #   kernel-<ver> -- the same, booted on each of a spread of LTS kernels, proving CO-RE resolves
      #                   offsets from each kernel's own BTF rather than assuming one layout.
      checks = nixpkgs.lib.genAttrs [ "x86_64-linux" ] (
        system:
        let
          s = perSystem system;
          pkgs = s.pkgs;
          args = {
            inherit pkgs;
            mimiModule = self.nixosModules.default;
          };
        in
        {
          vm = import ./tests/vm.nix args;
          # The same unit test, but forcing the fully-static MUSL binary as the service package: it
          # proves the static ship binary still loads the probe (CO-RE off the VM kernel's BTF) and
          # emits an OCSF exec event -- musl changes libc, not how aya loads BPF (syscalls).
          vm-musl = import ./tests/vm.nix (
            args
            // {
              name = "mimi-unit-musl";
              mimiPackage = s.mimiMuslPackage;
            }
          );
        }
        // import ./tests/kernels.nix args
      );

      devShells = forAllSystems (
        system:
        let
          s = perSystem system;
        in
        {
          # build.rs finds bpf-linker on PATH; mkShell's stdenv supplies cc for the userspace link.
          # rustup-shim shadows any ambient rustup so aya-build 0.2.0 drives the fenix toolchain
          # directly rather than a (missing) rustup-managed `nightly` -- see its note above.
          default = s.pkgs.mkShell {
            packages = [
              s.toolchain
              s.bpf-linker
              s.rustup-shim
            ];
          };

          # The fully-static musl ship build:
          #   nix develop .#musl -c cargo build --release --target x86_64-unknown-linux-musl -p mimi
          # produces the copy-and-run binary for any Linux distro. It is the default shell with the
          # toolchain swapped for muslToolchain (host nightly + rust-src + the musl std): build.rs
          # still compiles the mimi-ebpf probe for bpfel, so bpf-linker and the rustup-shim are still
          # required here. Only the userspace crate (`-p mimi`) is built for musl.
          musl = s.pkgs.mkShell {
            packages = [
              s.muslToolchain
              s.bpf-linker
              s.rustup-shim
            ];
          };
        }
      );
    };
}
