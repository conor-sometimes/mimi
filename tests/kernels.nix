# CO-RE across kernels (the multi-kernel load matrix): boot mimi.service on a spread of LTS kernels,
# each with its own task_struct/mm_struct layout, and prove the ONE binary loads its probe with
# offsets resolved from THAT kernel's BTF (not hardcoded) and captures an exec. This is what "loads
# on any BTF-capable kernel" has to mean -- exercised, not claimed. Before this, mimi had only ever
# been loaded on the build host's 6.18.59.
#
# Each kernel is its own VM test (its own boot), exposed as a flake check:
#   nix build .#checks.x86_64-linux.kernel-6_6 -L      (needs KVM)
{ pkgs, mimiModule }:
let
  lib = pkgs.lib;

  # A spread of in-tree LTS kernels; the span of layouts is the point, and each resolves its own
  # task_struct offsets from BTF (e.g. tgid lands at 1524 on 6.1 vs 1924 on the 6.18 build host). (If
  # nixpkgs drops one at EOL -- 5.15 was removed as EOL within 26.11 -- remove it here; the remaining
  # kernels still make the matrix.)
  kernels = {
    "kernel-6_1" = pkgs.linuxPackages_6_1;
    "kernel-6_6" = pkgs.linuxPackages_6_6;
    "kernel-6_12" = pkgs.linuxPackages_6_12;
    # Newest mainline nixpkgs ships: a new mainline kernel is covered automatically on the next
    # nixpkgs bump. 6.1 is the floor of this matrix: 5.10 and 5.15 are both gone from the pinned
    # nixpkgs (EOL), so nothing older can be exercised without a pinned external kernel.
    "kernel-latest" = pkgs.linuxPackages_latest;
  };

  mk = name: kpkgs: pkgs.testers.runNixOSTest {
    name = "mimi-${name}";
    nodes.machine = {
      imports = [ mimiModule ];
      services.mimi.enable = true;
      boot.kernelPackages = kpkgs;
      virtualisation.memorySize = 2048;
    };
    testScript = ''
      import json

      machine.wait_for_unit("multi-user.target")
      kver = machine.succeed("uname -r").strip()

      # The unit loads its probe on THIS kernel and stays up (offsets came from its BTF, not the
      # build kernel's -- a wrong offset would fault the probe or mis-capture).
      machine.wait_for_unit("mimi.service")
      machine.sleep(3)
      status = machine.execute("systemctl is-active mimi.service")[1].strip()
      if status != "active":
          print(machine.execute("journalctl -u mimi.service --no-pager | tail -40")[1])
      assert status == "active", f"mimi.service not active on {kver}: {status!r}"
      restarts = int(machine.succeed("systemctl show -p NRestarts --value mimi.service").strip() or "0")
      assert restarts == 0, f"mimi.service crash-looped on {kver} ({restarts} restarts)"

      # A real exec is captured, with the fields CO-RE reads out of this kernel's task_struct correct.
      machine.wait_for_file("/var/log/mimi/events.jsonl")
      machine.succeed("cp \"$(command -v bash)\" /tmp/mimicanary && /tmp/mimicanary -c true")
      machine.wait_until_succeeds("grep -q '\"name\":\"mimicanary\"' /var/log/mimi/events.jsonl")
      evs = [json.loads(l) for l in machine.succeed("cat /var/log/mimi/events.jsonl").splitlines() if l.strip()]
      cand = [e for e in evs if e.get("process", {}).get("name") == "mimicanary"]
      assert cand, f"no mimicanary exec captured on {kver}"
      assert cand[0]["process"]["file"]["path"] == "/tmp/mimicanary", cand[0]

      print(f"MIMI CO-RE PASS on kernel {kver}: probe loaded from BTF, canary exec captured correctly")
    '';
  };
in
lib.mapAttrs mk kernels
