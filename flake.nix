{
  # mimi's reproducible build environment. The three-way LLVM coherence that aya needs -- rustc's
  # LLVM == bpf-linker's LLVM == what aya-build links -- is fragile when assembled by hand (rustup +
  # `cargo install bpf-linker` + a stray LD_LIBRARY_PATH), so this freezes it:
  #
  #   * fenix pins the exact nightly (nightly-2026-10-31, rustc 1.101 / LLVM 23.1) with rust-src, so
  #     the probe's `-Z build-std` for the BPF target is reproducible rather than whatever rustup had.
  #   * a bpf-linker 0.12 built against nixpkgs llvmPackages_23 (23.1.0) -- nixpkgs' own bpf-linker is
  #     0.9.15 with an older LLVM -- so its LLVM major matches the nightly's. Being nix-built, it
  #     carries its own RPATH to libLLVM, so nothing needs LD_LIBRARY_PATH set.
  #
  # `nix develop` then gives `cargo build` (the probe + embed) a coherent toolchain on any machine.
  # Later outputs (packages.mimi, nixosModules.mimi for services.banken.mimi.enable) build on this.
  description = "mimi: eBPF telemetry sensor for banken (Rust + aya)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, fenix }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      # services.mimi: the sensor as a hardened systemd service. Usually turned on via banken's
      # services.banken.mimi.enable (the one switch); import this alongside banken's module.
      nixosModules.default = import ./module.nix;
      nixosModules.mimi = import ./module.nix;

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # The pinned nightly from rust-toolchain.toml, resolved reproducibly by fenix. The sha256
          # covers the toolchain manifest for that date; nix prints the correct value on first build.
          toolchain =
            (fenix.packages.${system}.toolchainOf {
              channel = "nightly";
              date = "2026-10-31";
              sha256 = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            }).withComponents
              [
                "cargo"
                "rustc"
                "rust-src"
                "rustfmt"
                "clippy"
              ];

          # bpf-linker 0.12 against LLVM 23.1 (nixpkgs ships 0.9.15). Modelled on nixpkgs'
          # pkgs/by-name/bp/bpf-linker/package.nix: it selects its LLVM via a `llvm-<major>` feature
          # and finds it through llvm-config (provided by llvmPackages_23.llvm in nativeBuildInputs).
          bpf-linker = pkgs.rustPlatform.buildRustPackage rec {
            pname = "bpf-linker";
            version = "0.12.0";
            src = pkgs.fetchFromGitHub {
              owner = "aya-rs";
              repo = "bpf-linker";
              tag = "v${version}";
              hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
            };
            cargoHash = "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
            buildNoDefaultFeatures = true;
            buildFeatures = [ "llvm-23" ];
            nativeBuildInputs = [ pkgs.llvmPackages_23.llvm ];
            buildInputs = [
              pkgs.zlib
              pkgs.libxml2
            ];
            # llvm-sys shells out to llvm-config, unavailable when cross-compiling.
            doCheck = false;
          };
        in
        {
          default = pkgs.mkShell {
            # mimi's build.rs finds bpf-linker on PATH (a plain scan, no `which` crate); rustc drives
            # it as the linker for the bpf target via aya-build. mkShell's stdenv supplies cc for the
            # userspace link.
            packages = [
              toolchain
              bpf-linker
            ];
          };
        }
      );
    };
}
