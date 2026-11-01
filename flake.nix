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

          craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

          # The self-contained mimi binary: the loader with the BPF probe embedded. build.rs drives
          # a cargo-in-cargo `-Z build-std` compile of the probe for the BPF target, so it needs the
          # nightly + rust-src (the toolchain) and bpf-linker on PATH (nativeBuildInputs). Building
          # only -p mimi keeps mimi-ebpf a build-script artifact, not a host member.
          mimiPackage = craneLib.buildPackage {
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
        in
        {
          inherit
            pkgs
            toolchain
            bpf-linker
            mimiPackage
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
          pkgs = nixpkgs.legacyPackages.${system};
          args = {
            inherit pkgs;
            mimiModule = self.nixosModules.default;
          };
        in
        { vm = import ./tests/vm.nix args; } // import ./tests/kernels.nix args
      );

      devShells = forAllSystems (
        system:
        let
          s = perSystem system;
        in
        {
          # build.rs finds bpf-linker on PATH; mkShell's stdenv supplies cc for the userspace link.
          default = s.pkgs.mkShell {
            packages = [
              s.toolchain
              s.bpf-linker
            ];
          };
        }
      );
    };
}
