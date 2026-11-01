# Runtime test of the mimi NixOS unit itself: a VM with services.mimi.enable = true. It asserts the
# hardened unit actually STARTS and STAYS UP (DynamicUser + CAP_BPF/CAP_PERFMON + the --sink file
# write), loads the probe via CO-RE off the VM kernel's own BTF (a different kernel than the build
# host), and streams captured execs to its sink in the mimi/2 schema banken ingests.
#
# This is the coverage that was missing when a StandardOutput=append: unit shipped to hokkaido and
# crash-looped (exit 209/STDOUT): no test had ever *started* the unit. The NRestarts assertion below
# fails on exactly that regression.
#
#   nix build .#checks.x86_64-linux.vm -L    (needs KVM)
{ pkgs, mimiModule }:
pkgs.testers.runNixOSTest {
  name = "mimi-unit";

  nodes.machine = {
    imports = [ mimiModule ];
    services.mimi.enable = true;
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    import json

    machine.wait_for_unit("multi-user.target")
    # Diagnostic: the sensor attaches a tracepoint, which needs tracefs visible in the unit's
    # sandbox. Print what the unit can see so any sandbox regression is self-evident in the log.
    print(machine.execute("findmnt -t tracefs,debugfs || true")[1])

    # The unit starts...
    machine.wait_for_unit("mimi.service")

    # ...and STAYS up -- not crash-looping (209/STDOUT or a failed tracepoint attach both restart
    # on-failure every ~2s). On failure dump the journal so the real cause is in the test log.
    machine.sleep(3)
    status = machine.execute("systemctl is-active mimi.service")[1].strip()
    if status != "active":
        print(machine.execute("journalctl -u mimi.service --no-pager | tail -40")[1])
        print(machine.execute("systemctl show mimi.service -p NRestarts -p ExecMainStatus")[1])
    assert status == "active", f"mimi.service not active: {status!r}"
    restarts = int(machine.succeed("systemctl show -p NRestarts --value mimi.service").strip() or "0")
    assert restarts == 0, f"mimi.service restarted {restarts} times (crash-loop)"

    # The probe loaded (CO-RE off this kernel's BTF) and mimi is writing its own sink file.
    machine.wait_for_file("/var/log/mimi/events.jsonl")
    machine.wait_until_succeeds("test -s /var/log/mimi/events.jsonl")

    # A fresh exec is captured end to end: copy bash (an argv[0]-agnostic real binary -- not a shell
    # builtin, and not a coreutils multicall that would refuse a renamed argv[0]) to a uniquely-named
    # path (<=15 chars so the name survives the kernel's 16-byte comm) and run it, then find it in the
    # stream.
    machine.succeed("cp \"$(command -v bash)\" /tmp/mimicanary && /tmp/mimicanary -c true")
    # Select the canary's OWN exec by process.name (its comm). A bare substring match would also hit
    # the test-runner's command line, which mentions "mimicanary" too.
    machine.wait_until_succeeds("grep -q '\"name\":\"mimicanary\"' /var/log/mimi/events.jsonl")
    evs = [json.loads(l) for l in machine.succeed("cat /var/log/mimi/events.jsonl").splitlines() if l.strip()]
    cand = [e for e in evs if e.get("process", {}).get("name") == "mimicanary"]
    assert cand, "no exec event with process.name == mimicanary"
    ev = cand[0]
    # The captured event is the mimi/2 OCSF-shaped schema, mapping onto banken's process object.
    assert ev["schema"] == "mimi/2" and ev["kind"] == "exec", ev
    assert ev["process"]["file"]["path"] == "/tmp/mimicanary", ev

    print("MIMI UNIT PASS: service stays up, probe loaded via CO-RE, canary exec captured to sink")
  '';
}
