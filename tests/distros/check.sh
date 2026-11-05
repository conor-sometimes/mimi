#!/usr/bin/env bash
# mimi on this distro, end to end (adapted from mimi's own tests/vm.nix). Runs
# as root in the guest. It asserts the hardened unit STARTS and STAYS UP (no
# 209/STDOUT crash-loop, no failed tracepoint attach), that the probe loaded via
# CO-RE off THIS kernel's BTF (mimi is writing its own sink file), and that a
# fresh canary exec is captured end to end as the mimi/2 OCSF schema banken
# ingests. Exit 0 = pass; on any failure the journal and the sink tail are
# dumped so the real cause is in the log.
set -uo pipefail

SINK=/var/log/mimi/events.jsonl

fail() {
  echo "MIMI CHECK FAIL: $*"
  echo "---- journalctl -u mimi (last 40) ----"
  journalctl -u mimi.service --no-pager 2>/dev/null | tail -40 || true
  echo "---- systemctl show mimi ----"
  systemctl show mimi.service -p NRestarts -p ExecMainStatus -p ActiveState -p SubState 2>/dev/null || true
  echo "---- tracefs/debugfs visibility ----"
  findmnt -t tracefs,debugfs 2>/dev/null || true
  echo "---- sink tail ----"
  tail -5 "$SINK" 2>/dev/null || echo "(no sink file)"
  echo "MIMI CHECK FAIL: $*"
  exit 1
}

# Diagnostic: the sensor attaches a tracepoint, which needs tracefs visible.
echo "tracefs/debugfs: $(findmnt -t tracefs,debugfs -n 2>/dev/null | tr '\n' ' ')"

# The unit starts and STAYS up (not crash-looping: 209/STDOUT or a failed
# tracepoint attach both restart on-failure every ~2s).
for _ in $(seq 1 60); do
  [ "$(systemctl is-active mimi.service 2>/dev/null)" = "active" ] && break
  sleep 1
done
status="$(systemctl is-active mimi.service 2>/dev/null)"
[ "$status" = "active" ] || fail "mimi.service not active: $status"

sleep 3
restarts="$(systemctl show -p NRestarts --value mimi.service 2>/dev/null || echo 0)"
[ "${restarts:-0}" = "0" ] || fail "mimi.service restarted $restarts times (crash-loop)"

# The probe loaded (CO-RE off this kernel's BTF) and mimi is writing its sink.
for _ in $(seq 1 60); do
  [ -s "$SINK" ] && break
  sleep 1
done
[ -s "$SINK" ] || fail "sink $SINK never became non-empty (probe did not load / attach)"

# A fresh exec captured end to end: copy bash (an argv[0]-agnostic real binary,
# not a shell builtin, and not a coreutils multicall that refuses a renamed
# argv[0]) to a uniquely-named path (<=15 chars so the name survives the
# kernel's 16-byte comm) and run it, then find it in the stream.
cp "$(command -v bash)" /tmp/mimicanary && /tmp/mimicanary -c true

# Select the canary's OWN exec by process.name (its comm). A bare substring
# match would also hit this script's command line, which mentions "mimicanary".
for _ in $(seq 1 60); do
  grep -q '"name":"mimicanary"' "$SINK" && break
  sleep 1
done
grep -q '"name":"mimicanary"' "$SINK" || fail "no exec event with process.name == mimicanary in the sink"

# The captured event is the mimi/2 OCSF schema, mapping onto banken's process
# object: assert schema, kind and the resolved binary path exactly (mirrors
# tests/vm.nix). python3 ships on the Ubuntu cloud image.
python3 - "$SINK" <<'PY' || fail "mimicanary event did not match mimi/2 exec schema (see above)"
import json, sys
sink = sys.argv[1]
cand = []
with open(sink) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("process", {}).get("name") == "mimicanary":
            cand.append(e)
if not cand:
    print("no exec event with process.name == mimicanary")
    sys.exit(1)
ev = cand[0]
ok = (ev.get("schema") == "mimi/2"
      and ev.get("kind") == "exec"
      and ev.get("process", {}).get("file", {}).get("path") == "/tmp/mimicanary")
if not ok:
    print("event mismatch:", json.dumps(ev))
    sys.exit(1)
print("matched event:", json.dumps(ev))
PY

. /etc/os-release
echo "MIMI CHECK PASS on ${PRETTY_NAME}: unit stays up, probe loaded via CO-RE, canary exec captured as a mimi/2 OCSF event"
