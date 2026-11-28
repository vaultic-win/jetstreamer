"""Validate the sequential 141/143 handoff and the reservations shared with epoch 170."""
from datetime import datetime
from pathlib import Path
import hashlib
import json
import stat
import re
import time

G, M = 1 << 30, 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT/"epoch143-first-hourly-20261127-v1"
OLD = RT/"epoch141-first-hourly-20261127-v1"
UNIT = "horizon-qualify-143-first-hourly-20261127-v1.service"
FIRST = "horizon-qualify-141-first-hourly-20261127-v1.service"
SHA = "84e2846e7c33a1a6b7793861f918344be2af10d8132dc380450345f59903a19f"
ARM = "8ad5a7df1b9f45e4dd9f5bde5587c38c24301ee7844583e8929434f540a347b8"
ACCEPT = OLD/"terminal-capture-v1/PRIVATE_FIRST_HOURLY_ACCEPTANCE.json"


def first_closed(core):
    core.need(ACCEPT.is_file(), "waiting for verified first 141 archive acceptance")
    a, ref = core.read(ACCEPT)
    arm, ar = core.read(ACCEPT.with_name("ARMED.json"), ARM)
    terminal = core.bound(a["native_terminal"])
    st = terminal["properties"]
    manifest = Path(a["segment_manifest"]["path"])
    core.need(manifest == Path("/home/sol/.jetstreamer-private/epoch141-first-hourly-20261127-v1/epoch-141-first-hourly.jet.segment.json")
              and manifest.stat().st_size < 1<<20, "different closed 141 manifest")
    data = manifest.read_bytes()
    core.need(hashlib.sha256(data).hexdigest() == a["segment_manifest"]["sha256"], "141 manifest changed")
    core.need(a["schema"] == "horizon-141-private-first-hourly-acceptance-v1" and a["epoch"] == 141
              and a["terminal_slot"] == 60921282 and len(a["target_journal"]) == 355
              and a["armed"] == ar and a["bindings"] == arm["bindings"] == terminal["bindings"]
              and terminal["armed"] == ar and terminal["actor"] == arm["actor"]
              and st["Id"] == FIRST and st["InvocationID"] == a["producer_invocation_id"] == arm["actor"]["producer_invocation_id"]
              and st["Result"] == "success" and st["ExecMainStatus"] == st["MainPID"] == st["ControlPID"] == "0"
              and a["output_slot_start"] == 60912000 and a["output_slot_count"] == 9283 and a["original_target_count"] == 355
              and json.loads(data)["archive_sha256"] == a["archive"]["sha256"]
              and not a["publication_authorized"] and a["resource_credit_bytes"] == 0, "141 close did not return its exact envelope")
    core.inactive(FIRST)
    core.inactive(FIRST.replace("-qualify-","-guard-"))
    clock = core.state(FIRST.replace("-qualify-","-guard-").replace(".service",".timer"), "Id,ActiveState,Job")
    core.need(clock["ActiveState"] == "inactive" and not clock["Job"], "141 guard still occupies the shared envelope")
    return ref


def guard(core, base, unit, plan_refs, iid, mode):
    state = core.state(unit)
    plan, plan_ref = core.read(base/"ACTUAL_GUARD_PLAN.json")
    path = Path(plan["receipt_directory"])
    timer = unit.replace("-qualify-","-guard-").replace(".service",".timer")
    gt = core.state(timer, "Id,ActiveState,InvocationID,Triggers,BindsTo,Job")
    gs = core.state(timer.replace(".timer",".service"), "Id,ExecStart,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax")
    hourly = unit == UNIT
    budget = (40 if hourly else 48)*G
    cap = plan["maximum_root_physical_bytes"]
    root = Path("/home/sol/.jetstreamer-private/epoch143-first-hourly-20261127-v1") if hourly else core.TREE
    core.need(path == plan_refs and state["ActiveState"] == "active" and state["InvocationID"] == plan["invocation_id"] == iid
              and re.fullmatch("[0-9a-f]{32}",iid) and state["Id"] == plan["unit"] == unit
              and state["CPUQuotaPerSecUSec"] == ("2s" if hourly else "6s") and state["MemoryMax"] == str(budget)
              and state["MemorySwapMax"] == "0" and not state["Job"] and plan["filesystem"] == "/home/sol"
              and plan["worker_root"] == str(root) and (cap == 64*G if hourly else 0 < cap <= 384*G)
              and gt["ActiveState"] == "active" and not gt["Job"] and gt["Triggers"] == gs["Id"]
              and gt["BindsTo"] == (unit if hourly else "") and gs["CPUQuotaPerSecUSec"] == "1s"
              and gs["MemoryMax"] == str(G) and gs["MemorySwapMax"] == "0"
              and plan_ref["path"]+" --plan-sha256 "+plan_ref["sha256"] in gs["ExecStart"]
              and not (path/"stop-intent.json").exists(), "unguarded replacement "+unit)
    s, sr = core.read(max(path.glob("sample-*.json"),key=lambda p:p.stat().st_mtime_ns))
    pid = int(state["MainPID"])
    core.need(s["plan_sha256"] == plan_ref["sha256"] and s["producer_stop_enabled"] and s["producer"]["pid"] == pid
              and s["producer_invocation_id"] == iid and s["trip_reason"] is s["root_physical_observation_error"] is s["worker_observation_error"] is None
              and not s["root_physical_observation"]["exceeds_budget"] and 0 <= time.time()-s["recorded_unix_seconds"] <= 120
              and s["minimum_free_bytes"] == plan["minimum_free_bytes"] <= s["available_bytes"], "stale or tripped guard")
    proc = Path("/proc")/str(pid)
    core.need(s["producer"]["invocation_id"] == iid and state["ControlGroup"] == "/system.slice/"+unit
              and (proc/"cgroup").read_text().strip() == "0::"+state["ControlGroup"], "changed native actor")
    if hourly:
        executable = ROOT/"tools-v1/guard"
        guard_digest = "dfea30dafc769c5af59cce61137fb73b70665de2abab05c747dbc32de641dc96"
        core.need("path="+str(executable)+" ;" in gs["ExecStart"] and "--self-sha256 "+guard_digest+" ;" in gs["ExecStart"],
                  "different 143 guard executable")
    if mode == "gate":
        core.need(not s["workers"] and (Path("/proc")/str(pid)/"exe").samefile(ROOT/"tools-v1/hold-143")
                  and not (ROOT/"barrier/allow").exists(),"143 is not the exact unreleased gate")
    if hourly and mode == "released":
        owner, _ = core.read(ROOT/"HELD_OWNER.json")
        booking = core.bound(owner["booking"])
        core.need(owner["producer_invocation_id"] == iid and owner["producer_pid"] == pid and owner["guard_plan"] == plan_ref
                  and owner["guard_timer_invocation_id"] == gt["InvocationID"] and (ROOT/"barrier/allow").read_text() == iid
                  and booking["contract"] == owner["contract"] == core.read(ROOT/"contract-v1/LAUNCH_PROFILE.json",SHA)[1]
                  and booking["RAM_bytes"] == 41*G and booking["HOME_bytes"] == 64*G+64*M, "unbooked 143 worker")
        source = core.bound(core.bound(booking["contract"])["source_reference"])
        node = source["images_and_genesis"]["node"]["path"]
        worker_sha = source["images_and_genesis"]["worker"]["sha256"]
        run = root
        permit = ROOT/"barrier/allow"
    elif not hourly:
        owner, owner_ref = core.read(base/"SUCCESSOR_ACTOR.json")
        scope = core.bound(owner["interface"])
        guard_exe = Path(scope["guard_seal"]["path"]).with_name("guard")
        core.need("path="+str(guard_exe)+" ;" in gs["ExecStart"]
                  and "--self-sha256 "+scope["guard_sha"]+" ;" in gs["ExecStart"], "different 170 guard executable")
        if mode == "held170":
            gate = Path(scope["profile"]["sealed_package"]["path"]).with_name("gate")
            core.need(not s["workers"] and (proc/"exe").samefile(gate) and not Path(scope["barrier"]).exists()
                      and not (base/"SUCCESSOR_RELEASE.json").exists()
                      and owner["unit"] == unit and owner["producer_pid"] == pid and owner["producer_invocation_id"] == iid
                      and owner["start_ticks"] == int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19])
                      and owner["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      "170 gate already released or replaced")
            owner = None
        else:
            release, _ = core.read(base/"SUCCESSOR_RELEASE.json")
            core.need(release["actor"] == owner_ref and release["interface"] == owner["interface"] and release["guard_plan"] == plan_ref
                      and release["guard_timer_invocation_id"] == gt["InvocationID"] and release["producer_invocation_id"] == iid,
                      "different 170 release")
            node = scope["profile"]["node"]["path"]
            worker_sha = scope["profile"]["worker"]
            run = Path(scope["run"])
            permit = Path(scope["barrier"])
    else:
        owner = None
    cg = Path("/sys/fs/cgroup/system.slice")/unit
    pids = {int(p) for p in (cg/"cgroup.procs").read_text().split()}
    core.need(pid in pids and (mode not in ("held170","gate") or pids == {pid}) and len(pids)<=2
              and not (set(p[0] for p in s["workers"])-pids), "changed producer roster")
    roster=[(p,int((Path("/proc")/str(p)/"stat").read_text().rsplit(") ",1)[1].split()[19])) for p in sorted(pids)]
    if owner:
        meta = permit.lstat()
        core.need(owner["unit"] == unit and owner["producer_invocation_id"] == iid and (pid, owner["start_ticks"]) in roster
                  and owner["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                  and (proc/"exe").samefile(node) and permit.read_text() == iid and stat.S_ISREG(meta.st_mode)
                  and meta.st_uid == meta.st_gid == 0 and meta.st_nlink == 1 and not meta.st_mode & 0o222,
                  "producer identity or permit changed")
        for child in pids - {pid}:
            exe = Path("/proc")/str(child)/"exe"
            target = exe.resolve(strict=True)
            core.need(target.name == "historical-worker" and target.is_relative_to(run/"scratch"),
                      "unbound historical worker")
            with exe.open("rb") as file:
                core.need(hashlib.file_digest(file, "sha256").hexdigest() == worker_sha, "changed historical worker")
    return dict(unit=unit,iid=iid,manager=state,plan=plan_ref,sample=sr,timer=gt["InvocationID"],
                floor=plan["minimum_free_bytes"],cap=cap,low=core.physical(s),high=core.peak(s),roster=roster)


def auxiliary(core, fleet):
    m_path = RT/"epoch185-lanem-holding-20261127-v1/MEASURED_LOCAL_RECLAMATION.json"
    measured, mr = core.read(m_path, "798ee9c4446496d3ef965d3c01ce9912cd65b48a380fc6258b5403ea6bd304ea")
    complete = core.bound(measured["native_complete"])
    terminal = core.bound(measured["native_terminal"])
    core.need(terminal["success"] and terminal["invocation_id"] == complete["invocation"]
              and measured["host_source_absent"] and measured["host_quarantine_absent"]
              and measured["conservative_incremental_capacity_bytes"] == complete["measured_freed_bytes"]
              and measured["restore_reservation_bytes"] == 123350028052, "different 185 M retirement")
    # Only extend a historical head which preceded this measurement. Live
    # statvfs always caps both prices. Never add the retirement a second time.
    sampled = datetime.fromisoformat(core.bound(fleet)["sampled_at_utc"])
    incremental = (measured["conservative_incremental_capacity_bytes"]
                   if datetime.fromisoformat(measured["observed_utc"]) > sampled else 0)

    # The serial park allocation and its restore overlap remain in the fleet baseline.
    park, pr = core.read(RT/"epoch185-lanem-holding-20261127-v1/PARK_ADMISSION.json",
                         "f8e45c96f33686d57834398c4a1f331faea0a54439359840f45ddc349df9faeb")
    serial = core.bound(park["serial_slot"])
    core.need(park["restore_overlap_bytes"] == 123350028052 and serial["additional_memory_bytes"] == 2*G,
              "holding reservation changed")
    fourth, fr = core.read(RT/"epoch141-foundation-fourth-bootstrap-20261127-v1/ANZA_INPUT_AND_FOUNDATION_HANDOFF.json",
                           "0731668c4fd6b959e2b21feaf4aae9cc5a82562daae9d8864fdc7f09dd9d82cd")
    core.need(fourth["retained_noswap_tmpfs_cap"] == 2304*M and fourth["earlier_fetch_cgroup_limit_bytes"] == 4*G
              and fourth["additional_home_limit_bytes"] == 4*M, "changed fourth-bootstrap staging")
    fourth_root = Path(fr["path"]).parent
    dispatch, dispatch_ref = core.read(fourth_root/"FOUNDATION_EXECUTION_HANDOFF.json",
                                       "1ac8a0b3dad3b965f675398214add1f35c0471bdb3b46dca0e268c33862cba4a")
    custody = core.bound(dispatch["custody"])
    local = core.bound(fourth["input"])
    end = core.bound(custody["native_terminal"])
    mount = Path(fourth["ram_backed_staging_dir"])
    core.need(dispatch["predecessor_retirement"] == mr and custody["local_bootstrap_receipt"] == fourth["input"]
              and local["sha256"] == fourth["sha256"] == custody["sha256"]
              and local["bytes"] == fourth["actual_file_bytes"] == custody["bytes"]
              and custody["authenticated_post_readback"]["authenticated"] and end["success"],
              "different fourth bootstrap transfer or custody")
    core.inactive(end["unit"])
    disposition, dr = core.read(fourth_root/"STAGING_UNMOUNT.json",
                                "f7583a3314ac7adb6532a29f9ba581c36b47898ea19c405edc70d349d7c4df3b")
    receiver = core.bound(disposition["receiver"])
    census = disposition["namespaces_after"]
    core.need(disposition["remote_custody"] == receiver["anza_remote_custody"] == dispatch["custody"]
              and receiver["handoff"] == dispatch_ref and receiver["receiver_invocation"] == "19e647e734264a8cbcdcbd8c55c622dc"
              and receiver["sha256"] == local["sha256"] and receiver["bytes"] == local["bytes"]
              and disposition["original_tmpfs_fully_drained"] and disposition["local_mount_drained"]
              and disposition["reservation_release_bytes"] == 4*G and disposition["home_archive_credit_bytes"] == 0
              and census["observed"] == 36 and not census["bound"] and not census["inaccessible"]
              and Path(disposition["source_mount"]) == mount, "fourth staging return was not confirmed")
    mount_rows = Path("/proc/1/mountinfo").read_text().splitlines()
    in_host = any(str(mount) == line.split()[4] or " - tmpfs horizon141-fourth-bootstrap " in line for line in mount_rows)
    core.need(not in_host and not Path(local["destination"]).exists()
              and (not mount.exists() or mount.stat().st_dev == mount.parent.stat().st_dev), "fourth staging is occupied again")

    return dict(park=pr,serial_restore_overlap_already_reserved=park["restore_overlap_bytes"],fourth=fr,
                measured_185_m=mr,incremental_185_m_after_fleet=incremental,
                fourth_execution_handoff=dispatch_ref,fourth_ram_return=dr,fourth_host_tmpfs_drained=True,
                fourth_ram=0,parallel_controls_ram=2*G,selector_already_reserved=4*G,
                controller_ram=512*M,watcher_ram=32*M,controller_home=128*M,
                evidence_home=64*M+32*M+4*M+2*M)
