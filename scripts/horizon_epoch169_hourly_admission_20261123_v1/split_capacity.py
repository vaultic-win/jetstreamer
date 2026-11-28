"""Price the separate disk output of 169 in the shared, four-peer booking."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import runpy
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
CONTROL = RT / "epoch169-hourly-admission-20261123-v1"
WRITER = RT / "survivor172-cadence-20261122-v1"
G, M = 1 << 30, 1 << 20
SEVEN = "137e983862022f0d559771c2074134758363af92ea5ed6a63eeeb80223be273f"
LEGACY_LEDGER = "5bb2552e1bbe3fa52826be1c2c5b630ae8a243974d4a6ed11f9a52eacc4ce832"
DIR = CONTROL / "issued-split-v1"
actor = runpy.run_path(str(HERE / "split_actor.py"))
need = actor["need"]


def seal():
    need(HERE == DIR and os.geteuid() == 0 and __debug__, "expected the sealed 169 price")
    doc, ref = actor["receipt"](DIR / "deployment-seal-receipt.json")
    need(doc["destination"] == str(DIR) and len(doc["members"]) == len({m["name"] for m in doc["members"]}),
         "invalid 169 deployment")
    for member in doc["members"]:
        path = DIR / member["name"]
        st = path.lstat()
        need(path.parent == DIR and path.resolve() == path and st.st_uid == 0 and
             st.st_nlink == 1 and not st.st_mode & 0o222 and st.st_size == member["bytes"] and
             hashlib.sha256(path.read_bytes()).hexdigest() == member["sha256"], "changed 169 member " + str(path))
    return ref


def native_owners(n, fleet, observed, peer162):
    rows = fleet["actual_executing_replays"] + fleet["actual_active_bootstraps"] + fleet["actual_active_private_diagnostics"]
    peers = [r for r in rows if r["epoch"] not in (169, 162)]
    need(sorted(r["epoch"] for r in peers) == [146, 167, 170, 172], "the four-peer booking changed")
    enrolled = fleet.get(actor["FIELD"])
    actor["check_fleet"](fleet, enrolled, observed["binding"] if observed and observed["phase"] != "terminal" else None)
    actual = list(peers)
    if observed and observed["phase"] != "terminal":
        actual.append(observed)
    if peer162 and peer162["phase"] != "terminal":
        actual.append(peer162)
    need(n.active_units("horizon-qualify-*") == {r["unit"]["Id"] for r in actual}, "different native replay fleet")
    for row in actual:
        recorded = row["unit"]
        props = actor["actor"]["props"](recorded["Id"], ["Id", "InvocationID", "MainPID", "ControlGroup", "ActiveState", "Job"])
        proc = Path("/proc") / props["MainPID"]
        start = row.get("start_ticks") or row["processes"][0][1]
        need(all(recorded[key] == value for key, value in props.items()) and props["ActiveState"] == "active"
             and not props["Job"] and re.fullmatch("[a-f0-9]{32}", props["InvocationID"])
             and (proc / "cgroup").read_text().strip() == "0::/system.slice/" + props["Id"]
             and props["ControlGroup"] == "/system.slice/" + props["Id"]
             and int((proc / "stat").read_text().rsplit(") ", 1)[1].split()[19]) == start, "native replay identity changed")
    return [{"epoch": r["epoch"], "unit": r["unit"]["Id"], "invocation_id":r["unit"]["InvocationID"]} for r in actual]


def resident(row):
    if not row or row["phase"] == "terminal":
        return 0
    paid = row["binding"]
    group = Path("/sys/fs/cgroup") / row["unit"]["ControlGroup"].lstrip("/")
    pids = sorted(p[0] for p in paid["processes"])
    need(sorted(map(int, (group / "cgroup.procs").read_text().split())) == pids
         and (group / "memory.swap.current").read_text().strip() == "0", "169 changed its paid cgroup")
    mem = {k: int(v) for k,v in (line.split() for line in (group / "memory.stat").read_text().splitlines())}
    anon = 0
    for pid in pids:
        rss = (Path("/proc") / str(pid) / "smaps_rollup").read_text().splitlines()
        anon += next(int(line.split()[1])*1024 for line in rss if line.startswith("Pss_Anon:"))
    pid = paid["processes"][0][0]
    scratch = actor["scratch"]["SCRATCH"]
    need(actor["scratch"]["native"](pid) == paid["private_scratch_mount"], "169 mount changed during RAM census")
    st = os.statvfs(Path("/proc") / str(pid) / "root" / scratch.relative_to("/"))
    tmp = (st.f_blocks-st.f_bfree)*st.f_frsize
    need(sorted(map(int, (group / "cgroup.procs").read_text().split())) == pids, "169 population crossed RAM sample")
    return min(68*G, min(mem["anon"], anon) + min(mem["shmem"], tmp))

def floor_and_margin(available, other_margin, current):
    outside = actor["CONTROL"]
    remaining = actor["OUTPUT"]
    others = available - other_margin
    floor = others + outside
    if current:
        need(current["phase"] in ("held", "bootstrap", "worker") and current["disk"]["fixed_control"] == outside,
             "unknown 169 charge")
        remaining = current["disk"]["remaining"]
        need(0 <= remaining <= actor["OUTPUT"], "169 exceeds the guarded output contract")
        floor = max(floor, current["disk"]["floor"])
    return dict(protected_home=others, guard_floor=floor, remaining_output=remaining,
                required_home=floor + remaining, available_home=available, home_margin=available - floor - remaining)


def optional_memory(fleet, fleet_ref, study):
    # The full native roster is checked independently. Only these four funded
    # incumbents have an independently matched kernel-memory lower bound.
    data = {}
    try:
        audit, amount = study["audit_resident"]()
        if audit["fleet"] == fleet_ref:
            data.update(audit=audit, audit_bytes=amount)
    except (OSError, ValueError, ProcessLookupError):
        pass
    kernels = {}
    limits = {146:68*G, 167:42*G, 170:48*G, 172:68*G}
    for row in fleet["actual_executing_replays"] + fleet["actual_active_private_diagnostics"]:
        epoch, saved = row["epoch"], row["unit"]
        if epoch not in limits:
            continue
        props = study["unitprops"](saved["Id"],"Id,InvocationID,MainPID,ControlGroup,MemoryMax,MemorySwapMax,ActiveState")
        group = Path("/sys/fs/cgroup" + props["ControlGroup"])
        need(all(saved[k] == props[k] for k in ("Id","InvocationID","MainPID","ControlGroup","ActiveState"))
             and props["ActiveState"] == "active" and int(props["MemoryMax"]) == limits[epoch]
             and props["MemorySwapMax"] == "0" and int((group/"memory.max").read_text()) == limits[epoch]
             and (group/"memory.swap.max").read_text().strip()=="0" and props["MainPID"] in (group/"cgroup.procs").read_text().split(),
             "different kernel-residency owner")
        mem = {k:int(v) for k,v in (line.split() for line in (group/"memory.stat").read_text().splitlines())}
        cost = sum(mem[k] for k in ("kernel_stack","pagetables","slab_unreclaimable"))
        need(0 <= cost <= mem["kernel"], "incoherent cgroup kernel accounting")
        upper = mem["anon"] + (mem["file_mapped"] if epoch in (146,172) else 0)
        kernels[epoch] = dict(id=props, inode=group.stat().st_ino, lower=max(0,min(cost,limits[epoch]-upper)))
    need(set(kernels) == set(limits), "missing incumbent kernel charge")
    return dict(data,kernel=kernels)


def optional_reduction(before, after, raw, base):
    audit = 0
    if before.get("audit") and before["audit"] == after.get("audit"):
        need(all("audit" not in k for k in raw["joint"]["guard_samples"]), "audit already discounted")
        audit = min(before["audit_bytes"],after["audit_bytes"])
    a,b=before["kernel"],after["kernel"]
    need(all(a[k]["id"] == b[k]["id"] and a[k]["inode"] == b[k]["inode"] for k in a), "kernel sample crossed an owner")
    low={k:min(a[k]["lower"],b[k]["lower"]) for k in a}
    kern=(min(low[146]+low[172],136*G-raw["joint"]["resident_lower_bytes"])
          + min(low[167],42*G-raw["tail_ram_resident"]) + min(low[170],48*G-base["realized_170_anon"]))
    need(0 <= kern <= sum(low.values()), "inconsistent incumbent memory bounds")
    return dict(audit= audit, kernel=kern)


def terminal_charges(recovery, rooms, copier, compiler):
    code=HERE/"terminal_ram.py"
    need(hashlib.sha256(code.read_bytes()).hexdigest()=="203fdea3bbe271973dbae87f33342f063b746e470d977eac44972ebc079cce16", "different temporary-charge model")
    proof = actor["actor"]["pinned"](dict(path=str(RT/"epoch162-first-hourly-completion-20261127-v2/JOINT_162_169_TEMPORARY_RAM_1795820068503180684.json"),
                                            sha256="6f31ff2da79484874d72c36107cb6b8359d6369997d0afd4d86e3ff1f6b0bede"))
    def doc(p, digest=None):
        path=Path(p)
        st=path.lstat()
        need(path.resolve()==path and st.st_uid==0 and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             not st.st_mode&0o022 and st.st_size<=16<<20, "unsafe terminal input")
        raw=path.read_bytes()
        need(path.stat().st_ctime_ns==st.st_ctime_ns and (not digest or hashlib.sha256(raw).hexdigest()==digest),
             "changed terminal input")
        return json.loads(raw)
    def quiet(unit):
        keys="Id,LoadState,ActiveState,MainPID,ControlPID,ControlGroup,InvocationID,Job"
        result=subprocess.run(["/usr/bin/systemctl","show","--all","-p",keys,unit],capture_output=True,text=True,timeout=10)
        props=dict(line.split("=",1) for line in result.stdout.splitlines())
        need(result.returncode == 0 or result.returncode == 4 and props.get("LoadState") == "not-found",
             "cannot inspect retired temporary owner")
        need(props["Id"]==unit and props["ActiveState"] in ("inactive","failed") and not props["Job"]
             and not props["ControlGroup"] and props["MainPID"]==props["ControlPID"]=="0", "temporary charge is live")
        return props
    result=runpy.run_path(str(code))["reconcile"](RT, dict(compiler_recovery=recovery),
           dict(rooms=rooms,input170=copier,compiled_baseline=compiler),doc,quiet,need)
    frozen=proof["temporary_charge_closures"]
    need(result["compiler_excess_ram"]==frozen["compiler_excess_ram"]==G and
         result["concluded_copier_ram"]==frozen["concluded_copier_ram"]==G and not result["ending_disk_bytes"]
         and [r["invocation"] for r in result["compiler_terminals"]]==[r["invocation"] for r in frozen["compiler_terminals"]]
         and result["input_terminal"]["invocation"]==frozen["input_terminal"]["invocation"], "different releases")
    return result

def verification168(funded):
    # Use the same slice census and serial scanner identity as the 170 turnover.
    core = SimpleNamespace(**runpy.run_path(str(HERE / "successor_price.py")))
    return runpy.run_path(str(HERE / "verification_reservation.py"))["reservation"](core, funded)


def quote(*, include_writer_overhead=0, separate_162=False):
    deployment = seal()
    path = HERE / "campaign-price.py"
    need(hashlib.sha256(path.read_bytes()).hexdigest() == LEGACY_LEDGER, "auxiliary charge model changed")
    campaign = runpy.run_path(str(path))
    n = campaign["bound_tools"]()
    prior_fleet = max(RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    fleet_before, fleet_ref = actor["receipt"](prior_fleet)
    peer = runpy.run_path(str(HERE / "peer162.py"))
    row162 = peer["current"](fleet_before)
    before = time.time()
    study = runpy.run_path(str(HERE/"witness-admission.py"))
    initial_paid = optional_memory(fleet_before,fleet_ref,study)
    actor_before = actor["current"](fleet_before)
    paid_before = resident(actor_before)
    provider = runpy.run_path(str(HERE / "live_168_170_price.py"))
    base, live = provider["live_price"](separate_169=True, native162=row162)
    raw = base["raw"]
    need(raw["fleet"] == fleet_ref, "fleet turned over during the admission sample")
    actor["recheck"](fleet_before, actor_before)
    fleet = n.accepted_fleet(raw["fleet"])
    population = native_owners(n, fleet, live, row162)
    funded = fleet["retry9_auxiliary_commitments"]
    compiler = n.compiler_reservation()
    recovery = n.recovery_reservation(compiler)
    serial = n.repeated_serial_slot(raw, funded)
    nfit = n.op.fixed(n.op.OUT / "n/FIT_park_1795809508414636995.json", "d29c600faed2d82b23e03a184f87f92a7128c5c2778160917838615a14603d09")
    accepted = n.op.bound(nfit)
    incumbent168 = verification168(funded)
    holder = campaign["holding"](n)
    gcs = campaign["input_cost"](n)
    micro = campaign["micro_cost"](n)
    v47 = WRITER / "V47_PACKAGE_FIT_1795815901128138852.json"
    booked = actor["actor"]["pinned"](dict(path=str(v47), sha256=SEVEN))
    need(booked["fits"] and booked["additional_home_bytes"] == 43933696
         and booked["additional_RAM_bytes"] == 192*M and booked["bookings"]["extra_output_bytes"] == 1398267904
         and serial == accepted["price"]["one_serial_slot"] and serial["repeated_serial_bytes"] == 2*G and accepted["fit"]
         and accepted["post_phase_ram"] == 2567569408 and accepted["ram"] == 2*G and accepted["disk"] == 16*M
         and compiler["terminal"] and compiler["image_physically_funded_bytes"] == 4*G
         and raw["replacement143"] is None and raw["guarded_hourly_remaining"] == 64*G and not raw["resource_credit_bytes"]
         and raw["auxiliary"]["serial_restore_overlap_already_reserved"] == 123350028052, "a funded commitment changed")
    rooms = n.margins(base, funded, compiler["image_physically_funded_bytes"], serial["repeated_serial_bytes"])
    # The prior V47 disk top-up includes the 170 recorder and the scheduled 168
    # build and qualification outputs. Each independent serial slot stays paid.
    fixed = booked["bookings"]["extra_output_bytes"] + booked["additional_home_bytes"] + include_writer_overhead + incumbent168["additional_home"]
    disk = rooms["remaining_home"] - 16*M - gcs["additional_home"] - micro["retained_evidence"] - fixed
    requested = recovery["maximum_memory"] + booked["additional_RAM_bytes"]
    extra = optional_reduction(initial_paid,optional_memory(fleet,fleet_ref,study),raw,base)
    cleared = terminal_charges(recovery,rooms,gcs,compiler)
    paid = min(paid_before, resident(live))
    ram = paid - incumbent168["additional_ram"] + rooms["post_reservation_ram_margin"] - (requested - funded["build_memory_bytes"]) - gcs["additional_ram"] - micro["witness_ram"]
    ram += extra["kernel"] + extra["audit"] + cleared["compiler_excess_ram"] + cleared["concluded_copier_ram"]
    funding = runpy.run_path(str(HERE / "split_booking.py"))
    original = funding["prove"](base, dict(rooms=rooms), live, row162)
    need(original["same_169_compute"] and holder == campaign["holding"](n) and gcs == campaign["input_cost"](n)
         and micro == campaign["micro_cost"](n) and compiler == n.compiler_reservation()
         and recovery == n.recovery_reservation(compiler) and population == native_owners(n, fleet, live, row162),
         "native funding or owner crossed the quote")
    need(verification168(funded) == incumbent168, "168 verification listener changed during price")
    actor["recheck"](fleet, live)
    home = floor_and_margin(base["available_home"], disk, live)
    need(n.accepted_fleet(raw["fleet"]) == fleet, "sole fleet changed")
    peer["recheck"](fleet, row162)
    result = dict(schema="horizon-169-split-current-native-price-v1", phase="postguard" if live else "prestart",
                native=base, fleet=raw["fleet"], provider=deployment, observed_actors=population, actor=live,
                accounting=dict(rooms=rooms, old_six_owner_lineage=original, serial=serial, original_n=nfit,
                                compiler=compiler, recovery=recovery, holding=holder, input170=gcs, recorder170=micro,
                                fixed_HOME=fixed, terminal_ram=cleared, realized_incumbent_memory=extra, verification168_listener=incumbent168, writer_overhead=include_writer_overhead, funding_V47=dict(path=str(v47), sha256=SEVEN)),
                realized_169_anonymous_and_noswap_shmem=paid, ram_margin=ram, **home, fits=ram >= 0 and home["home_margin"] >= 0,
                resource_credit_bytes=0, started_unix_seconds=before, recorded_unix_seconds=time.time())
    if separate_162:
        return result, row162
    return peer["charge"](result, row162)
