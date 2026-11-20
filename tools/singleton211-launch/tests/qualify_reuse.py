#!/usr/bin/python3
"""Native four-name reuse experiment; run explicitly on an authorized systemd host as root."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

assert os.geteuid() == 0
tag = "js211-gc-fixture-" + uuid.uuid4().hex
evidence = Path("/var/lib/jetstreamer") / tag
evidence.mkdir(mode=0o755)
links = Path("/run/systemd/system")
producer, guard, timer, retain = [tag + x for x in (".service", "-guard.service", "-guard.timer", ".target")]
pg, pt = (tag + "-peer.service", tag + "-peer.timer")
records = []
installed = {}


def command(*args):
    c = subprocess.run(args, text=True, capture_output=True, timeout=12)
    records.append({"argv": args, "stdout": c.stdout, "stderr": c.stderr, "rc": c.returncode})
    c.check_returncode()
    return c.stdout


def show(name, *keys):
    out = command("/usr/bin/systemctl", "show", name, "--all", "--property=" + ",".join(keys))
    return dict(line.split("=", 1) for line in out.splitlines())


def load(source, name, data):
    dest = source / name
    if name.endswith(".service"):
        data += "\n[Service]\nMemoryMax=64M\nMemorySwapMax=0\nTasksMax=32\nCPUQuota=100%\nRuntimeMaxSec=50s\nRestart=no\nNoNewPrivileges=yes\n"
    dest.write_text(data)
    dest.chmod(0o444)
    path = links / name
    path.symlink_to(dest)
    installed[name] = dest


def remove(name):
    assert (links / name).readlink() == installed[name]
    (links / name).unlink()
    del installed[name]


def wait(fn):
    end = time.monotonic() + 8
    while time.monotonic() < end:
        value = fn()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError("condition expired")


def peer():
    g = show(pg, "ActiveState", "SubState", "InvocationID", "ExecMainStatus")
    t = show(pt, "ActiveState", "SubState", "InvocationID")
    if g["SubState"] != "dead" or g["ExecMainStatus"] != "0" or not re.fullmatch("[0-9a-f]{32}", g["InvocationID"]):
        return None
    if t["SubState"] != "waiting" or not re.fullmatch("[0-9a-f]{32}", t["InvocationID"]):
        return None
    obj = "/org/freedesktop/systemd1/unit/" + "".join(ch if ch.isalnum() else f"_{ord(ch):02x}" for ch in pt)
    dtype, value = command("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1", obj,
                           "org.freedesktop.systemd1.Timer", "NextElapseUSecMonotonic").split()
    assert dtype == "t" and int(value) > time.monotonic_ns() // 1000
    return [g, t, int(value)]


def fixture(generation, gate_marker, guard_marker):
    source = evidence / generation
    source.mkdir()
    ge, he = source / "startup.env", source / "guard.env"
    # Native ExecStart calls Python directly, with each mandatory braced digest argument.
    helper = source / "hold.py"
    helper.write_text("import os,sys,time\nfrom pathlib import Path\nr=Path(sys.argv[1]); expected=(r/'plan').read_bytes(); import hashlib\nassert hashlib.sha256(expected).hexdigest()==sys.argv[2]\n(r/'gate-proof').write_text(str(os.getpid())+' '+os.environ['INVOCATION_ID']+' '+sys.argv[2]); time.sleep(40)\n")
    check = source / "check.py"
    check.write_text("import hashlib,sys,os\nfrom pathlib import Path\nr=Path(sys.argv[1]); assert hashlib.sha256((r/'guard-plan').read_bytes()).hexdigest()==sys.argv[2]; (r/'guard-proof').write_text(os.environ['INVOCATION_ID']+' '+sys.argv[2])\n")
    load(source, producer, f"[Service]\nType=exec\nEnvironmentFile={ge}\nExecStart=/usr/bin/python3 {helper} {source} ${{HORIZON211_STARTUP_PLAN_SHA256}}\n")
    load(source, guard, f"[Service]\nType=oneshot\nEnvironmentFile={he}\nExecStart=/usr/bin/python3 {check} {source} ${{HORIZON211_GUARD_PLAN_SHA256}}\n")
    load(source, timer, f"[Timer]\nOnActiveSec=1s\nOnUnitActiveSec=30s\nAccuracySec=1s\nUnit={guard}\n")
    load(source, retain, f"[Unit]\nDefaultDependencies=no\nIgnoreOnIsolate=yes\nAfter={producer} {guard} {timer}\n")
    for name in [producer, guard, timer, retain]:
        manager = show(name, "FragmentPath", "InvocationID", "ActiveState", "LoadState")
        assert manager["ActiveState"] == "inactive" and manager["LoadState"] == "loaded"
        assert manager["InvocationID"] == "" and Path(manager["FragmentPath"]).resolve(strict=True) == source / name
    # All four already loaded even though neither argument file existed yet.
    (source / "plan").write_text(gate_marker)
    dig = hashlib.sha256(gate_marker.encode()).hexdigest()
    ge.write_text("HORIZON211_STARTUP_PLAN_SHA256=" + dig + "\n")
    ge.chmod(0o444)
    command("/usr/bin/systemctl", "start", retain)
    command("/usr/bin/systemctl", "start", producer)
    wait((source / "gate-proof").exists)
    pid, iid, actual = (source / "gate-proof").read_text().split()
    owner = show(producer, "MainPID", "InvocationID")
    assert [pid, iid, actual] == [owner["MainPID"], owner["InvocationID"], dig]
    (source / "guard-plan").write_text(guard_marker + iid)
    gd = hashlib.sha256((guard_marker + iid).encode()).hexdigest()
    he.write_text("HORIZON211_GUARD_PLAN_SHA256=" + gd + "\n")
    he.chmod(0o444)
    command("/usr/bin/systemctl", "start", timer)
    wait((source / "guard-proof").exists)
    gid, actual = (source / "guard-proof").read_text().split()
    assert actual == gd and gid != iid
    wait(lambda: show(guard, "ActiveState")["ActiveState"] == "inactive")
    command("/usr/bin/systemctl", "stop", producer, timer)
    assert show(guard, "InvocationID")["InvocationID"] == gid
    assert show(producer, "InvocationID")["InvocationID"] == iid
    for name in [producer, retain, guard, timer]:
        remove(name)
    command("/usr/bin/systemctl", "stop", retain)
    for name in [producer, guard, timer, retain]:
        wait(lambda: show(name, "LoadState", "Job", "ActiveState") ==
             {"LoadState":"not-found", "Job":"", "ActiveState":"inactive"})
    return dict(producer_iid=iid, guard_iid=gid, startup_sha=dig, guard_sha=gd)


try:
    for name in [producer, guard, timer, retain, pg, pt]:
        assert not (links / name).is_symlink() and not (links / name).exists()
        assert show(name, "LoadState") == {"LoadState":"not-found"}
    load(evidence, pg, "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n")
    load(evidence, pt, f"[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=60s\nAccuracySec=1s\nUnit={pg}\n")
    command("/usr/bin/systemctl", "start", pt)
    p = wait(peer)
    once = fixture("qualification", "first startup", "first guard")
    assert peer() == p
    twice = fixture("production", "second startup", "second guard")
    assert peer() == p and all(once[k] != twice[k] for k in once)
    (evidence / "success.json").write_text(json.dumps(dict(peer=p, qualification=once, production=twice), indent=2))
finally:
    # Scope every cleanup operation to this unique fixture's still-owned definitions.
    for name in (timer, pt, producer, guard, pg, retain):
        if name in installed and (links / name).is_symlink() and (links / name).readlink() == installed[name]:
            try:
                command("/usr/bin/systemctl", "stop", name)
                remove(name)
            except Exception as e:
                records.append({"cleanup":name,"error":str(e)})
    (evidence / "commands.json").write_text(json.dumps(records, indent=2))
    print(evidence)
