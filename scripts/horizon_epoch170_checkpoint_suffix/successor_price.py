"""Reprice the bounded epoch 170 successor using the accepted epoch 167 fleet projection."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

G = 1 << 30
M = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
DEP = RT / "epoch170-from-73726716-20261127-v1"
ATTEMPT = DEP / "attempt-2" if Path(__file__).resolve().parent.parent == DEP / "attempt-2" else DEP
OLD = RT / "epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1"
B140 = RT / "epoch140-suffix-recording-20261127-retry2"
B185 = RT / "epoch185-lanek-holding-20261125-v1"
BRIDGE = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service"
UNIT = "horizon-qualify-170-from-73726716-20261127-v1.service"
TREE = Path("/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1")
ORIG = "3a5e311489834552ab5fda89379f9481"
FLEET_SHA = "bdcebe2758f2191c7b6e82392626de3b25a52400d69618302873274c73254872"
PROGRESS = "753ade79e4e3873c18eb0cec83d17f879d8e0e08fa45b97c740e8f6c3a6a5fe6"
FIELDS = "Id,ActiveState,InvocationID,MainPID,ControlPID,Job,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,ControlGroup"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def cmd(*argv, timeout=120):
    return subprocess.check_output(argv, text=True, timeout=timeout)


def state(unit, fields=FIELDS):
    p = subprocess.run(["/usr/bin/systemctl", "show", "--all", "-p", fields, "--", unit],
                       text=True, capture_output=True, timeout=30)
    record = dict(line.split("=", 1) for line in p.stdout.splitlines())
    need(p.returncode in (0, 4) and record["Id"] == unit and set(fields.split(",")) <= record.keys(),
         "cannot identify " + unit)
    return record


def read(path, sha=None):
    path = Path(path)
    need(path.is_relative_to(RT) and path.resolve(strict=True) == path, "foreign evidence " + str(path))
    s = path.stat()
    need(stat.S_ISREG(s.st_mode) and not s.st_mode & 0o022 and s.st_uid == 0 and s.st_size <= 32*M,
         "untrusted evidence " + str(path))
    b = path.read_bytes()
    h = hashlib.sha256(b).hexdigest()
    need(sha is None or sha == h, "changed evidence " + str(path))
    return json.loads(b), {"path": str(path), "sha256": h}


def bound(ref):
    return read(ref["path"], ref["sha256"])[0]


def current_fleet():
    path = max(RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda f: f.stat().st_mtime_ns)
    fleet, ref = read(path)
    previous = fleet
    cursor = ref
    seen = set()
    while cursor["sha256"] not in seen:
        seen.add(cursor["sha256"])
        if cursor["sha256"] == FLEET_SHA:
            break
        cursor = previous["previous_Root_operational_review"]
        previous = bound(cursor)
    need(cursor["sha256"] == FLEET_SHA and fleet["resource_credit_bytes"] == fleet["all_reservation_ending_bytes"] == 0
         and fleet["all_active_status_reports_authenticated_readback"], "different fleet authority")
    when = dt.datetime.fromisoformat(fleet["sampled_at_utc"]).timestamp()
    need(0 <= time.time()-when <= 1900, "cadence needs its current accepted fleet")
    return fleet, ref


def availability():
    v = os.statvfs("/home/sol")
    ram = next(int(l.split()[1])*1024 for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemAvailable:"))
    return v.f_bavail*v.f_frsize, ram


def physical(s):
    walk = s["root_physical_observation"]
    return min(walk["first"]["physical_bytes"], walk["second"]["physical_bytes"])


def peak(s):
    walk = s["root_physical_observation"]
    return max(walk["first"]["physical_bytes"], walk["second"]["physical_bytes"])


def protected(unit, procs, timer_iid, anchor, mem, quota, resident, guard_timer=None):
    o = bound(anchor)
    row = state(unit)
    need(row["ActiveState"] == "active" and row["InvocationID"] == o["producer_invocation_id"] and not row["Job"]
         and int(row["MainPID"]) == procs[0][0] and row["ControlGroup"] == "/system.slice/"+unit
         and row["MemoryMax"] == str(mem) and row["MemorySwapMax"] == "0" and row["CPUQuotaPerSecUSec"] == quota,
         "incumbent identity or limits changed "+unit)
    timer = guard_timer or unit.replace("-qualify-", "-guard-").replace(".service", ".timer")
    tm = state(timer,"Id,ActiveState,InvocationID,Job")
    need(tm["ActiveState"] == "active" and tm["InvocationID"] == timer_iid and not tm["Job"], "guard changed "+unit)
    group = Path("/sys/fs/cgroup"+row["ControlGroup"])
    need(set(map(int,(group/"cgroup.procs").read_text().split())) == {p[0] for p in procs}, "process roster "+unit)
    pss = 0
    for pid, ticks, dev, ino in procs:
        proc = Path("/proc")/str(pid)
        exe = (proc/"exe").stat()
        need((int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19]), exe.st_dev, exe.st_ino) == (ticks,dev,ino)
             and (proc/"cgroup").read_text().strip() == "0::/system.slice/"+unit, "changed native row "+str(pid))
        if resident:
            pss += next(int(line.split()[1])*1024 for line in (proc/"smaps_rollup").read_text().splitlines()
                        if line.startswith("Pss:"))
    memstat = dict(line.split() for line in (group/"memory.stat").read_text().splitlines())
    directory = Path(anchor["path"]).parent
    need(not (directory/"stop-intent.json").exists(), "guard trip "+unit)
    sample, ref = read(max(directory.glob("sample-*.json"), key=lambda f: f.stat().st_mtime_ns))
    need(sample["producer"] == o["producer"] and sample["plan_sha256"] == o["plan_sha256"]
         and sample["producer_stop_enabled"] and sample["trip_reason"] is None
         and 0 <= time.time()-sample["recorded_unix_seconds"] <= 120
         and sample["worker_observation_error"] is sample["root_physical_observation_error"] is None
         and not sample["root_physical_observation"]["exceeds_budget"] and len(sample["workers"]) == 1
         and sample["workers"][0][0] == procs[1][0] and sample["available_bytes"] >= sample["minimum_free_bytes"],
         "no fresh guarded owner "+unit)
    return ref, physical(sample), min(pss, int(memstat["anon"])+int(memstat["file_mapped"]), mem)


def tree_bytes():
    vals = [int(cmd("/usr/bin/du", "-sx", "-B1", str(TREE)).split()[0]) for _ in range(2)]
    return min(vals), max(vals)


def inactive(unit):
    s = state(unit)
    need(s["ActiveState"] in ("inactive","failed") and s["MainPID"] == s["ControlPID"] == "0" and not s["Job"],
         "still occupied "+unit)
    return s


def scope(attempt=ATTEMPT):
    need(attempt in (DEP, DEP / "attempt-2"), "unknown successor pricing attempt")
    sha = ("b1977d6a8b65b654349b98a66748b77439b3539869bf1f4e758d2d76ea0851d3"
           if attempt != DEP else "30ba2b754885f8ba7cf9abc04d9453bb1b8a030b0534b31d1801543ea8c4906a")
    interface, ref = read(attempt/"BOUNDED_SUCCESSOR_WRITER_INTERFACE.json", sha)
    if attempt != DEP:
        failed = bound(interface["failed_predecessor"])
        preflight = bound(interface["private_state_native_preflight"])
        need(failed["guard_drained"] and failed["node_exited_before_worker"] and failed["private_segment_absent"]
             and preflight["old_failure"]==interface["failed_predecessor"] and preflight["original_run_unchanged"]
             and preflight["native_checkpoint_route_accepted"] and not preflight["worker_executed"],
             "retry is not bound to the startup correction")
    return interface, ref


def price(phase, *, attempt=ATTEMPT, live_tree_bounds=None, held_replacement=None, hourly_replacement=None):
    if held_replacement is not None:
        need(phase == "held" and held_replacement == "horizon-qualify-170-from-73746882-20261127-v1.service",
             "unknown replacement actor")
        incoming = RT / "epoch170-from-73746882-20261127-v1"
        release, release_ref = read(DEP / "attempt-2/SUCCESSOR_RELEASE.json",
                                    "b0bb87af6c93f61c90727d9dfcf775d469d567e7baf8246f0a436b74284820fa")
        original = bound(release["actor"])
        exit_record, _ = read(incoming / "predecessor-exit/PID1_EXIT.json")
        terminal = exit_record["properties"]
        need(exit_record["release"] == release_ref and exit_record["actor"] == original
             and terminal["Id"] == UNIT and terminal["InvocationID"] == original["producer_invocation_id"]
             and terminal["MainPID"] == terminal["ControlPID"] == terminal["ExecMainStatus"] == "0"
             and terminal["Result"] == "success" and terminal["ExecMainCode"] == "1",
             "replacement lacks its exact clean predecessor")
        inactive(UNIT)
    if live_tree_bounds is not None:
        lower, upper = live_tree_bounds
        need(phase == "held" and type(lower) is int and type(upper) is int and 0 < lower <= upper,
             "invalid live guard tree bounds")
    interface, iref = scope(attempt)
    fleet, fref = current_fleet()
    progress, progress_ref = read(RT/"epoch167-checkpoint-tail-20261127-v1/FIRST_PROTECTED_PROGRESS.json", PROGRESS)
    release = bound(progress["release"])
    post = bound(release["post_guard_capacity"])
    intent = bound(release["intent"])
    base = intent["quote"]["exact_native_fit"]
    rosters = bound(base["prior_fit"])["native"]["released_167"]["tracked_processes"]
    tail = progress["actor"]["unit"]
    anchors = base["live_guards"]
    peer_rows = fleet["actual_executing_replays"]
    need({x["epoch"] for x in peer_rows} == {146,172} and len(peer_rows) == 2, "changed incumbent fleet")
    before = availability()
    residents = loss = 0
    samples = {}
    for peer in peer_rows:
        u = peer["unit"]["Id"]
        samples[u], lower, memory = protected(u,rosters[u],peer["guard_timer"]["InvocationID"],anchors[u],68*G,
                                              "6.250000s" if peer["epoch"]==146 else "500ms",True)
        loss += max(0, peak(bound(anchors[u])) - lower)
        residents += memory
    samples[tail], tail_lower, _ = protected(tail,progress["processes"],progress["guard"]["timer_invocation_id"],
                                               progress["guard"]["sample"],42*G,"3s",False)
    old = bound(interface["old_actor"])
    if phase == "live":
        old_progress, _ = read(OLD/"FIRST_PROTECTED_WORKER.json")
        samples[BRIDGE], old_lower, _ = protected(BRIDGE, old_progress["actor"]["processes"],old_progress["guard"]["timer_invocation_id"],
                                                   anchors[BRIDGE],48*G,"6s",False)
        old_upper = old_lower
        terminal = None
    else:
        exit_event, terminal = read(DEP/"bridge-exit-capture-v1/PID1_EXIT.json")
        s = exit_event["properties"]
        need(exit_event["actor"] == old and s["InvocationID"] == ORIG and s["Id"] == BRIDGE
             and s["Result"] == "success" and s["ExecMainCode"] == "1" and s["ExecMainStatus"] == "0"
             and s["MainPID"] == s["ControlPID"] == "0", "bridge exit did not accept exact producer")
        inactive(BRIDGE)
        old_lower, old_upper = live_tree_bounds if live_tree_bounds is not None else tree_bytes()
    old_scoped = 0
    old_loss = max(0,peak(bound(anchors[BRIDGE]))-old_lower)
    if phase in ("start","held"):
        old_guard=bound(anchors[BRIDGE])
        # The 167 ledger included this exact scoped bridge-growth term once.
        # Replace it only after the closed comparison: the retained tree stays
        # on disk and the new 40 GiB is measured against that entire tree.
        done, _=read(DEP/"CLOSED_BRIDGE_COMPARISON.json")
        need(done["release"]==interface["old_release"] and done["pid1_exit"]["native"]["InvocationID"]==ORIG
             and done["pid1_exit"]["native"]["Result"]=="success" and done["checkpoints"][-1]["slot"]==73726716
             and len(done["closed_segment"]["sha256"])==64,"no accepted original bridge")
        old_scoped = base["remaining_170_bytes"]
        need(old_scoped==old_guard["maximum_root_physical_bytes"]-physical(old_guard)
             and post["required_home_bytes"]==base["complete_required_HOME_bytes"]-base["remaining_167_bytes"]+intent["run_guard_cap_bytes"]
             and old_guard["plan_sha256"]=="94763c96a0f243d6f75bd315f10c664d9cec73c7b09ddd81605e773f641472d5",
             "the accepted 167 price cannot isolate old 170 growth")
        old_loss = 0
    loss += old_loss
    # The 167 price covers the original 170 RAM independently of its current RSS.
    # Reuse the six-core/48 GiB payload slot and the separate one-core/1 GiB guard.
    # Keep the entire host envelope, replacing only the measured original bridge term.
    incumbent_home = post["required_home_bytes"] - tail_lower + loss - old_scoped
    incumbent_ram = post["required_ram_bytes"] + base["resident_lower_bound_bytes"] - residents
    booking, booking_ref = read(B140/"WRITER_BOOKING_111808_CROSS_CADENCE.json",
                                "e687eddf9e2b48b39e2a39ba6059a92a0f18c71178c8733d2636cfb07fccbac6")
    held, held_ref = read(B140/"HELD_OWNER.json")
    loan, loan_ref = read(B140/"CPU_LOAN_ACTIVE.json")
    need(held["invocation_id"] == loan["candidate_invocation"] and loan["booking"] == booking_ref
         and loan["live_bridge_invocation"] == ORIG and loan["bridge_cpu_quota_micros"] == 6000000
         and loan["producer_cpu_quota_micros"] + loan["guard_cpu_quota_micros"] == 3000000, "wrong 140 loan")
    s140 = state(held["unit"])
    charged140_home = booking["HOME_bytes"]
    charged140_ram = booking["RAM_bytes"]
    end140 = None
    if s140["ActiveState"] == "active":
        need(s140["InvocationID"]==held["invocation_id"] and s140["MemoryMax"]==str(26*G)
             and s140["CPUQuotaPerSecUSec"]=="2s" and not s140["Job"], "changed 140")
        work, _ = read(B140/"FIRST_PROTECTED_PROGRESS.json")
        need(work["held_owner"]==held_ref and work["producer_invocation_id"]==held["invocation_id"]
             and work["producer_pid"]==held["pid"],"different 140 worker")
        procs = []
        for pid,ticks in [(held["pid"],held["start_ticks"]),(work["worker_pid"],work["worker_start_ticks"])]:
            ex = (Path("/proc")/str(pid)/"exe").stat()
            procs.append([pid,ticks,ex.st_dev,ex.st_ino])
        sample, lower, memory = protected(held["unit"],procs,held["guard_timer_invocation_id"],
                                          work["guard_after"]["receipt"],26*G,"2s",True,held["guard_timer"])
        # Realized bytes are already absent from MemAvailable and statvfs.
        charged140_home -= min(lower,44*G)
        charged140_ram -= memory
        samples[held["unit"]] = sample
    else:
        inactive(held["unit"])
        returned = B140/"CPU_LOAN_RETURN.json"
        if returned.exists():
            end,end140=read(returned)
            need(end["candidate_invocation"]==held["invocation_id"] and end["loan"]==loan_ref
                 and end["producer_and_guard_drained"],"foreign loan return")
            inactive(end["guard_unit"])
            timer=state(end["guard_timer"],"Id,ActiveState,Job")
            need(timer["ActiveState"]=="inactive" and not timer["Job"],"140 guard still owns resources")
            charged140_ram = 0
            charged140_home = 64*M

    k = state("horizon-exact-185-lanek-retirement.service")
    if k["ActiveState"] == "active":
        need(k["InvocationID"]=="4a19c7b07b924bd78ebb32f56b896d07" and k["MemoryMax"]==str(G)
             and k["CPUQuotaPerSecUSec"]=="1s", "changed lane K")
    else:
        inactive(k["Id"])
    rr = {"lane_k": read(B185/"RETIREMENT_READY_AFTER_PARK.json",
                         "779130ebc83c44edb4f97e66bff8779b66ac8a7b2f1ee0e3cbd3b1e2031a130a")[1]}
    # Keep independent holding, retirement, exit capture, and parent hourly-build budgets.
    # Preserve the full 140 booking throughout the comparison and the successor.
    rr["141_build"] = read(RT/"root111808-live166167170-20261127-v1/ROOT_HOURLY_141_BUILD_FIT.json")[1]
    build=bound(rr["141_build"])
    settlement,rr["141_build_settlement"] = read(RT/"epoch141-hourly-original-build-20261127-v1/compiler-settlement-v1/BUILD_SCRATCH_SETTLEMENT.json",
                                               "2d9c3ace307843664887887097a0f048289502b19087d7a0b52af336cc54f51d")
    need(settlement["booking"]==rr["141_build"] and settlement["owner"]=="/root"
         and settlement["settled_unused_future_scratch_reservation_bytes"]==build["candidate_home_scratch_cap_bytes"]==1536*M
         and settlement["remaining_home_scratch_reservation_bytes"]==settlement["credited_new_physical_free_bytes"]==0
         and settlement["retained_output_allowance_bytes"]==build["candidate_home_retained_output_bytes"]==128*M
         and settlement["ram_reservation_release_bytes"]==settlement["cpu_reservation_release_micros"]==0,
         "different compiler settlement")
    inactive(settlement["terminal_compiler"]["unit"])
    extra_home = 4*M + settlement["retained_output_allowance_bytes"] + charged140_home + 2*M
    extra_ram = 3*G + 32*M + build["candidate_ram_bytes"] + charged140_ram
    successor = phase in ("start","held")
    if successor:
        budget, rr["new_170_budget"]=read(DEP/"BOUNDED_GROWTH_FROM_ORIGINAL_170.json",
                                          "04bb488a00b2cb853d6e21cb0b4ee3b12f4033fd9ff4fb7fbbe9ace1ad68a911")
        need(budget["successor_interface"]==interface.get("original_interface",iref) and budget["bounded_growth_limit"]==36*G
             and budget["margin_above_prior_peak"]>2*G and budget["original_slots"]>=budget["successor_slots"],
             "different bounded work set")
        profile141,rr["reserved_141"]=read(RT/"epoch141-first-hourly-20261127-v1/contract-v1/LAUNCH_PROFILE.json",
                                         "73a120db97d72a03c05c39139098a10cd6c84802f0f5472a1251f341976ce131")
        need(end140 and profile141["producer_CPU_quota_micros"]+profile141["guard_CPU_quota_micros"]==3000000
             and profile141["producer_RAM_bytes"]+profile141["guard_RAM_bytes"]==31*G
             and profile141["guarded_HOME_bytes"]==44*G and profile141["separate_evidence_HOME_bytes"]==64*M,
             "141 reservation changed or 140 loan remains outstanding")
        extra_home += profile141["guarded_HOME_bytes"]+profile141["separate_evidence_HOME_bytes"]
        extra_ram += profile141["producer_RAM_bytes"]+profile141["guard_RAM_bytes"]
    units={line.split()[0] for line in cmd("/usr/bin/systemctl","list-units","--plain","--no-legend",
         "--type=service","--state=running,activating,deactivating","horizon-qualify-*").splitlines()}
    expected={r["unit"]["Id"] for r in peer_rows}|{tail}
    if phase=="live": expected.add(BRIDGE)
    if phase=="held": expected.add(held_replacement or UNIT)
    if successor and profile141["unit"] in units:
        s141=state(profile141["unit"])
        need(s141["CPUQuotaPerSecUSec"]=="2s" and s141["MemoryMax"]==str(30*G)
             and s141["MemorySwapMax"]=="0" and not s141["Job"] and len(s141["InvocationID"])==32,
             "141 exceeds its full charged contract")
        expected.add(profile141["unit"])
    if hourly_replacement is not None:
        hourly_unit = "horizon-qualify-143-first-hourly-20261127-v1.service"
        observed = state(hourly_unit)
        need(successor and profile141["unit"] not in units and observed["ActiveState"] == "active"
             and observed["InvocationID"] == hourly_replacement and len(hourly_replacement) == 32
             and observed["MemoryMax"] == str(40*G) and observed["MemorySwapMax"] == "0"
             and observed["CPUQuotaPerSecUSec"] == "2s" and not observed["Job"],
             "143 differs from its priced hourly replacement")
        expected.add(hourly_unit)
    need(units == expected, "replay owner changed: "+repr(units ^ expected))
    bound(iref)
    after = availability()
    freed = 0
    retired = B185/"MEASURED_LOCAL_RECLAMATION.json"
    if retired.exists():
        result, rr["measured_185"] = read(retired)
        need(result["execution_invocation"]=="4a19c7b07b924bd78ebb32f56b896d07" and result["host_source_absent"]
             and result["host_quarantine_absent"], "wrong local reclamation")
        if dt.datetime.fromisoformat(result["observed_utc"]) > dt.datetime.fromisoformat(fleet["sampled_at_utc"]):
            freed = max(0,min(result["allocated_bytes_removed"],result["measured_net_free_bytes"]))
    historical_home_limit = fleet["complete_cycle_conservative_available_DATA_bytes"] + freed
    home = min(before[0],after[0],historical_home_limit)
    ram = min(before[1],after[1])
    candidate = budget["bounded_growth_limit"] if successor else 0
    required_ram = incumbent_ram+extra_ram
    floor = max(incumbent_home+extra_home,max(bound(ref)["minimum_free_bytes"] for ref in samples.values()))
    full_cap = 384*G
    need(old_upper <= full_cap, "original whole-tree cap exceeded")
    cap = min(full_cap,old_upper+candidate)
    required_home = floor+candidate
    _, final_ref=current_fleet()
    need(final_ref==fref,"accepted fleet changed during price")
    return dict(schema="horizon-170-successor-complete-fleet-fit-v1",phase=phase,observed=int(time.time()),
        interface=iref,fleet=fref,closed_bridge=terminal,charged_167=progress_ref,guard_samples=samples,
        active_140=s140,charged140_home=charged140_home,charged140_ram=charged140_ram,return140=end140,booking140=booking_ref,held140=held_ref,loan140=loan_ref,extra=rr,active185=k,
        guard_sibling_allowance=G,producer_allowance=48*G,producer_quota_micros=6000000,guard_quota_micros=1000000,
        required_home=required_home,required_ram=required_ram,available_home=home,available_ram=ram,
        historical_home_limit=historical_home_limit,
        replaced_original_scoped_growth=old_scoped,resident_lower_bytes=residents,terminal_tree_bounds=[old_lower,old_upper],candidate_growth=candidate,
        guard_floor=floor,guard_cap=cap,home_margin=home-required_home,ram_margin=ram-required_ram,
        fits=home>=required_home and ram>=required_ram and cap>=old_upper+candidate,
        archive_publication_authorized=False,resource_credit_bytes=0)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("phase", choices=["live","closed","start","held"])
    print(json.dumps(price(p.parse_args().phase), sort_keys=True))
