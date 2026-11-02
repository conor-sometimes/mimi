# NixOS module: mimi, the eBPF telemetry sensor. A long-running service (unlike banken's timer): it
# loads the probe once and streams OCSF-shaped events continuously to a sink file that banken tails.
#
#   imports = [ mimi.nixosModules.default ];   # flake
#   imports = [ "${mimi}/module.nix" ];        # or a pinned checkout
#   services.mimi.enable = true;
#
# Usually you do not enable this directly: `services.banken.mimi.enable = true` turns it on and wires
# banken to its output (see banken's module). mimi is a listener only; it never enforces.
#
# The unit mirrors the canonical contrib/mimi.service, hardened to banken's bar: it drops root to a
# DynamicUser with just the two capabilities loading a tracepoint + reading a ring buffer need
# (CAP_BPF + CAP_PERFMON, kernel 5.8+), and nothing else.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.mimi;
in
{
  options.services.mimi = {
    enable = lib.mkEnableOption "the mimi eBPF telemetry sensor";

    package = lib.mkOption {
      type = lib.types.package;
      # The flake's nixosModule defaults this to its own packages.<system>.mimi (the hermetic build:
      # fenix nightly + vendored build-std for the BPF target + the matching bpf-linker), so the one
      # switch deploys with nothing built by hand. Imported as a bare module instead of via the
      # flake, set this to such a package yourself.
      description = ''
        The mimi package (the probe is embedded in the binary). The flake's nixosModule defaults it
        to the flake's own hermetically-built mimi; override to pin your own.
      '';
    };

    sink = lib.mkOption {
      type = lib.types.str;
      default = "/var/log/mimi/events.jsonl";
      description = ''
        File mimi appends its OCSF event stream to, for a consumer (banken) to tail. A durable file
        (not a bare pipe) so a banken restart or a rule reload never loses events; banken's cursor
        picks up where it left off. The continuous low-latency socket path is a later refinement.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.mimi = {
      description = "mimi: eBPF telemetry sensor for banken";
      documentation = [ "https://github.com/conor-sometimes/mimi" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "exec";
        # mimi writes the OCSF event stream to the sink file itself (--sink), as the service user in
        # its own writable LogsDirectory. It does NOT use systemd's StandardOutput=append:, which
        # fails to set up under DynamicUser (the manager opens the fd before the LogsDirectory path
        # exists -- exit 209/STDOUT). mimi's status and diagnostics go to the journal instead.
        ExecStart = "${lib.getExe cfg.package} --sink ${cfg.sink}";
        # Events go to the --sink file (mimi opens it itself); mimi's status, preflight self-check,
        # and every error line go to stderr. Route BOTH stdout and stderr to the journal so
        # `journalctl -u mimi` shows the real failure (a missing capability, unreadable tracefs, an
        # unwritable sink) -- the original crash-loop showed only "exit 1" because stderr inherited an
        # append: sink. StandardError is set explicitly (not left to inherit StandardOutput) so a
        # later change to StandardOutput can never again bury mimi's diagnostics in the event file.
        StandardOutput = "journal";
        StandardError = "journal";
        LogsDirectory = lib.mkIf (lib.hasPrefix "/var/log/mimi" cfg.sink) "mimi";
        # The default sink lives in LogsDirectory (writable, owned by the DynamicUser). A sink set
        # elsewhere needs its directory made writable and pre-created by the operator.
        ReadWritePaths = lib.optional (!lib.hasPrefix "/var/log/mimi" cfg.sink) (builtins.dirOf cfg.sink);
        Restart = "on-failure";
        RestartSec = 2;

        # Loading a tracepoint program and reading a ring buffer needs CAP_BPF + CAP_PERFMON;
        # reading the tracepoint id from tracefs (/sys/kernel/tracing, root-owned 0700) needs
        # CAP_DAC_READ_SEARCH. On a HARDENED host those split BPF caps are not enough: with
        # kernel.unprivileged_bpf_disabled=1 and kernel.perf_event_paranoid=3 (nixos-hardening),
        # BPF_MAP_CREATE and the perf attach return EPERM unless the process holds CAP_SYS_ADMIN,
        # which bypasses both gates. A sysctl is kernel-wide and a unit capability cannot override
        # it, so the fix lives here, scoped to this one dynamic-user service, not host-wide.
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_BPF" "CAP_PERFMON" "CAP_SYS_ADMIN" "CAP_DAC_READ_SEARCH" ];
        CapabilityBoundingSet = [ "CAP_BPF" "CAP_PERFMON" "CAP_SYS_ADMIN" "CAP_DAC_READ_SEARCH" ];
        LimitMEMLOCK = "infinity";

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        IPAddressDeny = "any";
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "bpf" "perf_event_open" ];
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";
        # An attacker who OOMs the box must not reap the sensor.
        OOMScoreAdjust = -900;
      };
    };
  };
}
