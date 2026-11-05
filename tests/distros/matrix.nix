# mimi's cross-distro CO-RE matrix, as a consumer of mayfly
# (github.com/conor-sometimes/mayfly). It installs the shipped fully-static musl
# binary as a hardened systemd unit and asserts, on each real vendor distro, that
# the eBPF probe attaches via CO-RE off that kernel's own BTF and captures a fresh
# canary exec as a mimi/2 OCSF event. mayfly does the booting, provisioning and
# teardown; nothing in the engine names mimi.
#
# This matrix is how the 5.14-kernel tracepoint-offset bug was found: real vendor
# kernels (5.14 to newest) exercise the probe where the NixOS VM tests (all 6.x)
# cannot. Returns the mkMatrix result (apps, checks, readme) for flake.nix.
{ pkgs, lib, mayfly, self }:
let
  system = pkgs.stdenv.hostPlatform.system;
in
mayfly.lib.mkMatrix {
  inherit pkgs;

  distros = {
    ubuntu-2404.enable = true;
    ubuntu-2204.enable = true;
    debian-13.enable = true;
    fedora-44.enable = true;
    rocky-9.enable = true;
    alma-10.enable = true;
    amazonlinux-2023.enable = true;
    opensuse-leap-16.enable = true;
  };

  # A wide matrix on one host: boot one distro at a time. Drop this (or set
  # "auto") on a big host.
  concurrency = 1;

  install = {
    # The fully-static musl build (copy-and-run on non-NixOS): the bytes mimi
    # ships, not the gnu/NixOS build. The probe is embedded in the binary.
    binary = "${self.packages.${system}.mimi-musl}/bin/mimi";
    # A fixed path the unit's ExecStart names.
    installPath = "/usr/local/bin/mimi";
    # A long-running daemon: mayfly enables and starts it, then the test runs.
    unit = ./mimi.service;
  };

  # Exit 0 = the unit stayed up, the probe loaded off this distro's BTF, and the
  # canary exec was captured as a mimi/2 OCSF event. See check.sh.
  test = ./check.sh;
}
