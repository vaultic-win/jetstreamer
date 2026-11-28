"""Read an enrolled 162 actor, its exclusive 166 loan and its remaining split filesystem budget."""
from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import time

G = 1 << 30
M = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch162-first-hourly-completion-20261127-v2"
PACKAGE = ROOT / "issued-split-v1"
DATA = ROOT / "split-v1"
ENROLL = ROOT / "SPLIT162_ENROLLMENT.json"
DONOR = {"path": str(ROOT/"SPLIT_AND_166_WATCHERS_1795819276953592886.json"),
         "sha256": "64aa76de4fb179a650488d3d53c05050aff7b4fa97ef60c61d3726e42545133c"}
UNIT = "horizon-qualify-162-first-hourly-completion-20261127-v2.service"
TIMER = "horizon-guard-162-first-hourly-completion-20261127-v2.timer"
FIELD = "current_private162_split_completion"
CONTROL = 64*M
IMAGE = 8*G


def need(ok, message):
    if not ok:
        raise ValueError(message)


def frozen(path, expected=None):
    path = Path(path)
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_nlink == 1 and not st.st_mode & 0o022, "untrusted local binding " + str(path))
    data = path.read_bytes()
    end = path.lstat()
    need((st.st_dev, st.st_ino, st.st_ctime_ns, st.st_size) == (end.st_dev, end.st_ino, end.st_ctime_ns, len(data)),
         "changed local binding " + str(path))
    ref = {"path":str(path), "sha256":sha256(data).hexdigest()}
    need(expected is None or ref == expected, "different local binding " + str(path))
    return data, ref


def read(path, expected=None):
    data, ref = frozen(path, expected)
    return json.loads(data), ref


def bound(ref):
    return read(ref["path"], ref)[0]


def state(name):
    keys = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID,Job"
    r = subprocess.run(["/usr/bin/systemctl", "show", "--all", "-p", keys, "--", name],
                       capture_output=True, text=True, timeout=15)
    s = dict(line.split("=",1) for line in r.stdout.splitlines())
    need(r.returncode in (0,4) and s.get("Id") == name, "scope not found " + name)
    return s


def idle(name):
    s = state(name)
    need(s["ActiveState"] in ("inactive","failed") and not s["Job"] and not s.get("ControlGroup")
         and s.get("MainPID","0") == s.get("ControlPID","0") == "0", "expected drained owner " + name)
    return s


def package(spec):
    seal = PACKAGE/"deployment-seal-receipt.json"
    plan, ref = read(seal, spec["operator"])
    need(spec["donor"] == DONOR and plan["destination"] == str(PACKAGE), "unexpected 162 package or donor")
    active = bound(spec["writer_active"])
    ready = bound(active["ready"])
    need(ready["split162_provider"] == ref and not active["producer_mutations"], "writer did not enroll the 162 provider")
    available = {m["name"]:m for m in plan["members"]}
    for name in ("status162.py","layout.py","launch.py"):
        p = PACKAGE/name
        data, _ = frozen(p, {"path":str(p), "sha256":available[name]["sha256"]})
        need(len(data) == available[name]["bytes"] and not p.lstat().st_mode & 0o222, "unsealed 162 price input")
    return runpy.run_path(str(PACKAGE/"status162.py")), ref


def process_ticks(pid):
    return int((Path("/proc")/str(pid)/"stat").read_text().rsplit(") ",1)[1].split()[19])


def resident(layout, actor):
    pid, unit = actor["actor"]["producer_pid"], actor["unit"]
    group = layout.CGROUP
    procs = [(pid, actor["actor"]["start_ticks"])]
    if actor["worker"]:
        procs.append((actor["worker"]["pid"],actor["worker"]["start_ticks"]))
    def members():
        return sorted(map(int,(group/"cgroup.procs").read_text().split()))
    expected = sorted(p for p,_ in procs)
    need(members() == expected and int((group/"memory.max").read_text()) == 62*G
         and int((group/"memory.swap.max").read_text()) == int((group/"memory.swap.current").read_text()) == 0,
         "unmatched or swapping 162 population")
    stats = dict(line.split() for line in (group/"memory.stat").read_text().splitlines())
    anon = 0
    for p,t in procs:
        proc = Path("/proc")/str(p)
        need(process_ticks(p) == t and (proc/"cgroup").read_text().strip() == "0::"+unit["ControlGroup"],
             "changed 162 process identity")
        anon += next(int(line.split()[1])*1024 for line in (proc/"smaps_rollup").read_text().splitlines()
                     if line.startswith("Pss_Anon:"))
        need(process_ticks(p) == t, "replaced 162 process")
    scratch = Path("/proc")/str(pid)/"root"/layout.RUN.relative_to("/")/"scratch"
    fs = os.statvfs(scratch)
    used = (fs.f_blocks - fs.f_bfree)*fs.f_frsize
    need(0 <= used <= 36*G and fs.f_blocks*fs.f_frsize == 36*G and members() == expected,
         "different 162 scratch or population")
    return min(62*G, min(int(stats["anon"]),anon) + min(int(stats["shmem"]),used))


def current(fleet):
    rows = fleet["actual_executing_replays"] + fleet["actual_active_bootstraps"] + fleet["actual_active_private_diagnostics"]
    registered = [r for r in rows if r["epoch"] == 162]
    if not ENROLL.exists():
        need(not registered and not fleet.get(FIELD) and not os.path.lexists(DATA)
             and not os.path.lexists(ROOT/"barrier/allow"), "162 preceded its registered loan")
        for name in (UNIT,TIMER,TIMER.replace(".timer",".service")):
            idle(name)
        return None
    spec, enrollment = read(ENROLL)
    status, operator = package(spec)
    layout = status["api"]()
    row = status["current"](fleet)
    if row is None:
        need(not DATA.exists() and not (ROOT/"barrier/allow").exists(), "incomplete 162 lease or hold")
        idle(TIMER)
        idle(TIMER.replace(".timer",".service"))
        return None
    lease, lease_ref = read(DATA/"LEASE.json")
    intent = bound(row["actor"]["intent"])
    pre = bound(lease["prestart"])
    need(row["epoch"] == 162 and row["phase"] in ("held","bootstrap","worker","terminal")
         and row["profile"] == lease["profile"] == intent["profile"] == layout.profile(36)
         and row["donor"] == lease["donor"] == pre["donor"] == DONOR
         and lease["unit"] == intent["unit"] == row["unit"]["Id"] == UNIT
         and lease["owner_enrollment"] == pre["enrollment"] == enrollment and intent["lease"] == lease_ref
         and intent["prestart"] == lease["prestart"] and pre["phase"] == "prestart" and pre["fits"]
         and pre["exclusive_166_lease"] is True and lease["boot_id"] == pre["boot_id"] == row["actor"]["boot_id"]
         and not intent["canonical_publication_authorized"], "162 is outside its one 166 loan")
    evidence = dict(epoch=162, phase=row["phase"], unit=row["unit"], held_owner=row["held_owner"],
                    start_ticks=row["actor"]["start_ticks"], invocation_id=row["producer_invocation_id"],
                    lease=lease_ref, enrollment=enrollment, operator=operator, terminal=row["terminal"],
                    donor=DONOR, guard=row.get("guard"), guard_plan=row.get("guard_plan"),
                    worker=row.get("worker"), mounts=row.get("mounts"), profile=row["profile"])
    if row["phase"] == "terminal":
        idle(UNIT)
        idle(TIMER)
        idle(TIMER.replace(".timer",".service"))
        need(row["terminal"], "162 terminal is unbound")
        return dict(evidence, disk=None, realized_ram=0, sampled_at=time.time())
    plan = row["disk"]
    need(plan["maximum"] == IMAGE and plan["fixed_control"] == CONTROL and 0 <= plan["remaining"] <= IMAGE
         and plan["floor"] >= layout.MIN_FLOOR, "changed 162 disk or guard")
    if row["phase"] == "held":
        need(not row["release"] and not row["worker"] and not layout.ALLOW.exists()
             and not (DATA/"GRANT.json").exists(), "released actor presented as a 162 hold")
    return dict(evidence, disk=plan, realized_ram=resident(layout,row), sampled_at=time.time())


def recheck(fleet, row):
    after = current(fleet)
    if after is None or row is None:
        need(after is row, "162 crossed enrollment during the quote")
    else:
        keys = ("phase","unit","held_owner","start_ticks","invocation_id","lease","enrollment","operator","terminal",
                "donor","guard_plan","worker","mounts","profile")
        need(all(after[k] == row[k] for k in keys), "162 changed during the quote")
    return after


def geometry(base, remaining, control, issued_floor):
    output169 = base["remaining_output"]
    need(0 <= output169 <= 8*G and type(remaining) is int and 0 <= remaining <= IMAGE and control >= CONTROL
         and base["required_home"] == base["guard_floor"]+output169
         and base["home_margin"] == base["available_home"]-base["required_home"], "invalid joint 162 and 169 HOME shape")
    # F169 and F162 are fixed guard floors. The two mutable outputs can grow in
    # parallel above the higher of those floors and the separately protected commitments.
    floor = max(base["guard_floor"], issued_floor, base["protected_home"] + CONTROL + control)
    required = floor + output169 + remaining
    return dict(guard_floor=floor, required_home=required, home_margin=base["available_home"]-required)


def charge(base, row):
    """Protect an admitted 162 in a 169 quote. Both producer envelopes are already in its six-slot budget."""
    need("split162" not in base and base["fits"] == (base["ram_margin"] >= 0 and base["home_margin"] >= 0),
         "duplicate 162 charge or unsupported 169 fit")
    if row is None:
        return base
    fleet = bound(base["fleet"])
    after = recheck(fleet,row)
    if row["phase"] == "terminal":
        # Retain the output and its control reservation even after the tmpfs and guard drain.
        remaining, floor = IMAGE, 0
        realized = 0
    else:
        remaining = max(row["disk"]["remaining"], after["disk"]["remaining"])
        floor = max(row["disk"]["floor"], after["disk"]["floor"])
        realized = min(row["realized_ram"],after["realized_ram"]) if row["sampled_at"] <= base["started_unix_seconds"] else 0
    amounts = geometry(base,remaining,CONTROL,floor)
    ram = base["ram_margin"]+realized
    return dict(base, split162=row, realized_162_ram=realized, ram_margin=ram,
                fits=amounts["home_margin"]>=0 and ram>=0) | amounts
