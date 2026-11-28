"""Reprice the returned 159 compute loan on the native fleet, retaining all other bookings."""
import fcntl
import json
from pathlib import Path
import runpy
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as c

LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
ORIGINAL = c.RT / "epoch143-first-hourly-20261127-v1/booking-price-v53"
ORIGINAL_SEAL = "64ef98ccb5c3369e7b730d976983ccd9152e5f7caec9264f850092a3ca4f1c2e"
GAP = c.RT / "epoch170-from-73760367-20261128-v1"
GAP_UNIT = "horizon-qualify-170-from-73760367-20261128-v1.service"
GAP_IID = "d8ea1fcfbd6646839b9593752f4afdef"
DONOR = "0341586ebc5fd04e0f354fc3081774fdc1d952558dc456542cb79599f4ff6b62"
EXITS = {
    "horizon-epoch159-bounded-vote-trace-20261123-v1.service":
        ("epoch159-bounded-reference-20261123-v1", "31055f49783e564588f662448abde35e150035a0275ece6a80dab142cacd6909"),
    "horizon-epoch159-vote-feature-reference-20261123-v1.service":
        ("epoch159-vote-feature-reference-20261123-v1", "6ff486746b482102a2da9452480f009f11aba4242e85bfee95948ebfb5e3c5b0"),
}


def state(unit):
    fields = "Id,ActiveState,SubState,LoadState,MainPID,ControlPID,ControlGroup,Job,InvocationID,Restart,TriggeredBy,Triggers"
    report = subprocess.run(["/usr/bin/systemctl", "show", "--all", "-p", fields, "--", unit],
                            capture_output=True, timeout=15, text=True)
    rows = dict(row.split("=", 1) for row in report.stdout.splitlines() if "=" in row)
    c.need(report.returncode in (0,4) and rows["Id"] == unit and not rows["Job"], "changing unit " + unit)
    return rows


def returned_loan():
    donor, ref = c.read(c.RT / "epoch159-bounded-reference-20261123-v1/HEAD131757-132005-donor.json", DONOR)
    c.need(donor["charged_reference"]["cpu_cores"] == 2
           and donor["producer_cores_retained"] == 1 and donor["producer_ram_retained"] == 20*c.G,
           "different 159 loan")
    rows = {}
    for unit, (name, digest) in EXITS.items():
        exit_record, exit_ref = c.read(c.RT / name / "attempt-v1/driver-exit.json", digest, sealed=False)
        manager = state(unit)
        c.need(manager["ActiveState"] in ("inactive", "failed") and manager["MainPID"] == manager["ControlPID"] == "0"
               and not any(manager[field] for field in ("ControlGroup", "TriggeredBy", "Triggers"))
               and manager["Restart"] == "no" and (not manager["InvocationID"] or manager["InvocationID"] == exit_record["iid"])
               and not (Path("/sys/fs/cgroup/system.slice") / unit / "cgroup.procs").exists(), "159 loan occupied " + unit)
        rows[unit] = dict(exit=exit_ref, manager=manager)
    return dict(scope=ref, exits=rows, reserved_for_169_cpu_micros=2_000_000, returned_booking_ram=48*c.G)


def bound(reference, *, sealed=True):
    return c.read(Path(reference["path"]), reference["sha256"], sealed=sealed)[0]


def gap_disposition(native):
    progress, progress_ref = c.read(GAP / "FIRST_PROTECTED_PROGRESS.json",
                                    "2f31a88b4f179262386db0c291821c8dde6ae3a82ea46e76479815fa84482d9f")
    actor = bound(progress["actor"])
    release = bound(progress["release"])
    plan = bound(release["guard_plan"])
    raw = native["raw"]
    c.need(actor["producer_invocation_id"] == progress["producer_invocation_id"] == plan["invocation_id"] == GAP_IID
           and plan["unit"] == actor["unit"] == GAP_UNIT and release["actor"] == progress["actor"]
           and release["interface"]["sha256"] == "3f375caf9273b81cb84c5908695c27c0e4dbc6406f5ab53ebc1e1611ddf2a69f"
           and raw["reserved_following_170_growth_bytes"] == raw["joint"]["candidate_growth"] == 36*c.G
           and native["independent_gap_funding"]["new_guard_cpu_micros"] == c.GUARD_CPU,
           "lost registered 170 ownership, output or separate guard")
    result = dict(unit=GAP_UNIT, invocation=GAP_IID, actor=progress["actor"], first_progress=progress_ref,
                  release=progress["release"], guard_plan=release["guard_plan"], guard_floor=plan["minimum_free_bytes"],
                  continuing_output_reservation=36*c.G)
    live = native["independent_gap170"]
    manager = state(GAP_UNIT)
    if live is not None:
        c.need(live["unit"] == GAP_UNIT and live["invocation"] == manager["InvocationID"] == GAP_IID
               and live["pid"] == actor["producer_pid"] == int(manager["MainPID"]) and live["actor"] == result["actor"]
               and live["phase"] in ("bootstrap","worker") and live["guard_plan"] == result["guard_plan"]
               and live["release"] == result["release"] and manager["ActiveState"] == "active",
               "different concurrent 170 worker")
        return dict(**result, phase=live["phase"], floor_currently_enforced=True)
    intent, ir = c.read(GAP/"guard-receipts/stop-intent.json",
                        "d273dad0851b24ecfad432cb7c41460ccbd75af980075c0017935f928163f60a", sealed=False)
    end, er = c.read(GAP/"guard-receipts/stop-completion.json",
                     "f172a50e67d53e91798e2ee6c723ad4e699e03ac36ce7c2a7bf67b6bc6a08c69", sealed=False)
    sample = intent["sample"]
    c.need(manager["ActiveState"] in ("inactive","failed") and not manager["ControlGroup"]
           and manager["MainPID"] == manager["ControlPID"] == "0" and not manager["TriggeredBy"]
           and intent["producer_invocation_id"] == end["producer_invocation_id"] == GAP_IID
           and intent["plan_sha256"] == end["plan_sha256"] == result["guard_plan"]["sha256"]
           and end["intent"] == ir["path"] and end["terminal"]["pid"] == 0 and not end["scratch_deleted"]
           and intent["reason"] == sample["trip_reason"] == "filesystem-floor"
           and sample["minimum_free_bytes"] == result["guard_floor"] > sample["available_bytes"]
           and all(row["epoch"] != 170 for row in native["observed_actors"]), "170 disappearance lacks exact closure")
    return dict(**result, phase="stopped-by-guard", stop_intent=ir, stop_completion=er,
                stop_shortfall=sample["minimum_free_bytes"]-sample["available_bytes"], floor_currently_enforced=False)


def verified_provider(directory, expected):
    seal, ref = c.read(directory / "deployment-seal-receipt.json", expected)
    c.need(seal["destination"] == str(directory) and len({row["name"] for row in seal["members"]}) == len(seal["members"]),
           "different whole-roster directory")
    for row in seal["members"]:
        member = directory / row["name"]
        c.need(member.parent == directory and member.stat().st_size == row["bytes"], "foreign roster member")
        c.stable(member, expected=row["sha256"], sealed=True)
    return ref


def calculate(whole, custody_ref, loan):
    base = whole["base_169"]
    back = base["native"]["stopped_169_compute_handoff"]
    paid = base["accounting"]["old_six_owner_lineage"]
    gap = gap_disposition(base["native"])
    c.need(back["terminal"] == bound(custody_ref)["terminal"]
           and whole["resource_credit_bytes"] == base["resource_credit_bytes"] == 0
           and back["retained_guard_ram"] == c.GUARD_RAM and back["retained_169_output_bytes"] == 8*c.G
           and back["retained_159_ram"] == paid["temporary159_loan_memory"] == 48*c.G
           and paid["static_169_cpu"] == c.PRODUCER_CPU + c.GUARD_CPU + base["native"]["independent_gap_funding"]["new_guard_cpu_micros"]
           and base["native"]["independent_gap_funding"]["cpu_donor"] == loan["scope"]
           and whole["home_margin"] == whole["available_home"] - whole["required_home"]
           and whole["ram_margin"] == whole["available_ram"] - whole["required_ram"],
           "different loan, old reservation or native accounting")
    incremental_ram = c.RAM - back["retained_159_ram"]
    # Existing raw free space already excludes the old partial. Keep its entire
    # future 8 GiB output reservation as well. The retry receives a new distinct tree.
    required_floor = whole["required_home"] + c.CONTROL_BYTES
    if gap["floor_currently_enforced"]:
        required_floor = max(required_floor, gap["guard_floor"])
    home = whole["available_home"] - required_floor - c.HOME_OUTPUT
    ram = whole["ram_margin"] - incremental_ram
    return dict(schema="horizon-169-hourly-retry-price-v1", recorded_unix=time.time(),
                predecessor_custody=custody_ref, whole_roster=whole, epoch170=gap, returned_159_loan=loan,
                producer_memory_max=c.RAM, guard_memory_max=c.GUARD_RAM, producer_cpu_micros=c.PRODUCER_CPU,
                guard_cpu_micros=c.GUARD_CPU, new_home_output=c.HOME_OUTPUT, new_home_control=c.CONTROL_BYTES,
                incremental_home_bytes=whole["home_margin"]-home, incremental_ram_bytes=incremental_ram,
                guard_floor=required_floor, home_margin=home, ram_margin=ram, fits=min(home,ram)>=0,
                resource_credit_bytes=0, canonical_publication_authorized=False)


def prepare_quote():
    ref = verified_provider(ORIGINAL, ORIGINAL_SEAL)
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        source = runpy.run_path(str(ORIGINAL / "price_hourly143.py"))
        custody, cr = c.read(c.CONTROL/"PREDECESSOR_CUSTODY.json",
                             "31a30e9eb09e11514c64b9c7102871aeefa58a543c77dff576588b07b0327b0b")
        keep = custody["retained_incomplete_archive"]
        path = Path(keep["path"])
        before = c.identity(path.lstat())
        c.need(all(keep[k] == v for k, v in before.items()), "retained 169 partial changed")
        loan = returned_loan()
        result = calculate(source["complete_roster"](), cr, loan)
        c.need(before == c.identity(path.lstat()) and returned_loan() == loan, "169 custody or 159 loan changed")
        result.update(stage="prepare-only", admission=False, provider=ref)
        return result


if __name__ == "__main__":
    receipt = prepare_quote()
    ref = c.recorded(c.CONTROL / f"PREPARE_QUOTE_{time.time_ns()}.json", receipt)
    print(json.dumps(dict(receipt=ref, home_margin=receipt["home_margin"], ram_margin=receipt["ram_margin"],
                          epoch170=receipt["epoch170"]["phase"], fits=receipt["fits"])))
