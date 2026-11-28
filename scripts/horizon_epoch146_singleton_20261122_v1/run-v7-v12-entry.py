"""Release the existing 146 bounded entry after the sealed epoch 145 verifier."""

import argparse
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
EPOCH = ROOT / "epoch146-singleton-20261122-v1"
DEPLOYMENTS = {
    "v7": "tools-post145-v7-v12-sequence-20261125-v1",
    "v9": "tools-post145-v9-v12-sequence-20261125-v1",
    "v10": "tools-post145-v10-v12-sequence-20261126-v1",
    "independent": "tools-post145-independent-v12-sequence-20261126-v1",
}
GENERATION = next((version for version, directory in DEPLOYMENTS.items()
                   if Path(__file__).resolve().parent.name == directory), "v7")
DEPLOYMENT = EPOCH / DEPLOYMENTS[GENERATION]
LEGACY = EPOCH / "tools-post145-v6-v8-sequence-20261125-v1"
LEGACY_SHA = "13c45accc31c3c3db84f43701a310eb4aae3cd3ec4bc1c92cd8f7845ef046365"
WATCH = EPOCH / "tools-post145-v6-v8-operator-20261125-v1"
WATCH_SHA = "d60fc69ba8330a2dd246f83f6f1347ad93966d7865a3d8694284dc02332ec096"
PROVIDER_NAME = ("tools-homefloor-145-post-independent-entry146-v1" if GENERATION == "independent"
                 else f"tools-homefloor-145-post-{GENERATION}-build-v1")
PROVIDER = ROOT / "incident-replay-fit-20261121-v1" / PROVIDER_NAME / "post-stop-fit"
PROVIDER_SHA = {
    "v7": "db8beab61152a7852b890b1c8b1d985c83c4d9ae9bd4c0db6138887367b950cc",
    "v9": "f650a4acb3f901ba82fe36e6014d6b48176c9365d4750ba80d71debeaa3942c6",
    "v10": "4c8907433fddc6a19cf7708fafb3b0e977aba6f00d38f73d87d14cb8ea87d436",
}.get(GENERATION)
CADENCE = ROOT / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v12-entry146"
CADENCE_SHA = "6899ee7708ca74e9bf2a04cb932ce2fc75dff18e16866149b1dbeea3887496ac"
FAMILY145 = ROOT / "epoch145-semantic-continuity-20261121-v1"
checker, CHECKER145_SHA, handoff, OWNER145 = {
    "v7": ("tools-v7-168-stop-v2", "589d1da9f51c305be8699a9dc01e443c9ec2367d1f67e7905ba67fdeb0d35c7b",
           "v7-168-stop-name-handoff", "f7043fd6595a4151b659d4b098bede11"),
    "v9": ("tools-v9-census-recovery", "8766c269034824f114eb1906e1913188f615309b51243e8e23ca111936efeebd",
           "v9-census-name-handoff", "ebdfc34db47c4e7699ea5ccbada5d604"),
    "v10": ("tools-v10-census-recovery", "29aac4e0527dcea47f4e9bcb14c5e071b67b8d749669873cc04d7cd1cc5d4e75",
            "v10-census-name-handoff", "104f023c5cd24a55b6585ef525b80067"),
}["v10" if GENERATION == "independent" else GENERATION]
CHECKER145 = FAMILY145 / checker
SEMANTIC145 = FAMILY145 / handoff / "SEMANTIC_COMPLETION.json"
COMPLETE145 = ROOT / "epoch145-guarded-export-20261121-v1/state" / OWNER145 / "complete.json"
LEASE_FIELD = "epoch146_bounded_entry_lease"
HOLD_SECONDS = 320
PROVIDER_SECONDS = 142
INDEPENDENT145 = ROOT / "epoch145-parallel-full-verification-20261126-v1"
INDEPENDENT_CANDIDATES = {
    "cb3313b857d94b9f82e06d5c033c0ac5":
        (INDEPENDENT145, "horizon-145-parallel-full-verification-20261126-v1.service"),
    "a89c1de125694cb3bdcef19a8c82848a":
        (INDEPENDENT145 / "scaled-candidate-v1", "horizon-145-scaled-independent-verification-20261126-v1.service"),
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def ref(path, digest):
    return {"path": str(path), "sha256": digest}


def sealed_package(evidence, package, digest=None):
    binding = evidence["bound"](package / "deployment-seal-receipt.json")
    seal = evidence["checked"](binding)
    require((digest is None or binding["sha256"] == digest)
            and seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            and seal["destination"] == str(package) and seal["remote_mutations"] is False,
            f"foreign sealed package {package}")
    members = {}
    for row in seal["members"]:
        name = row["name"]
        path = package / name
        require(Path(name).name == name and name not in members
                and evidence["bound"](path)["sha256"] == row["sha256"]
                and f"{stat.S_IMODE(path.lstat().st_mode):04o}" == row["mode"],
                f"changed sealed member {path}")
        members[name] = row
    return members


def independent_completion(phase):
    iid = phase.get("completed_invocation_id")
    require(iid in INDEPENDENT_CANDIDATES and phase.get("stage") == "independent-semantic-complete-v10-drained"
            and phase.get("Id") == "horizon-holding-export145-20261121-v1.service"
            and phase.get("MainPID") == "0" and phase.get("previous_verifier_invocation_id") == OWNER145
            and type(phase.get("resource_credit_bytes")) is int and phase["resource_credit_bytes"] == 0,
            "epoch 146 requires a clean independent 145 completion and exact V10 handback")
    path, unit = INDEPENDENT_CANDIDATES[iid]
    require(phase.get("verifier_unit") == unit and
            set(phase.get("native_handback", ())) == {"started", "stopping", "stopped"}
            and all(phase["native_handback"].values()), "foreign independent verifier or V10 terminal")
    for role, want in (("semantic_receipt", path / "INDEPENDENT_TERMINAL_ACCEPTED.json"),
                       ("collector", path / "capture-independent-terminal.py"),
                       ("selection", PROVIDER.parent / "independent145-selection.json")):
        binding = phase.get(role, {})
        require(binding.get("path") == str(want) and isinstance(binding.get("sha256"), str)
                and re.fullmatch("[0-9a-f]{64}", binding["sha256"]), f"foreign independent 145 {role}")
    return phase


def completion_contract(phase):
    if GENERATION == "independent":
        return independent_completion(phase)
    require(phase["stage"] == f"{GENERATION}-semantic-complete-drained"
            and phase["completed_invocation_id"] == OWNER145
            and phase["checker_seal"] == ref(CHECKER145 / "deployment-seal-receipt.json", CHECKER145_SHA)
            and phase["completion"]["path"] == str(COMPLETE145)
            and phase["semantic_receipt"]["path"] == str(SEMANTIC145),
            f"epoch 146 requires the exact drained {GENERATION.upper()} semantic owner")
    return phase


def writer_contract(writer):
    require(writer["consumer_seal"] == ref(CADENCE / "deployment-seal-receipt.json", CADENCE_SHA),
            "epoch 146 requires the qualified V12 status consumer")
    return writer


def quote_contract(quote, accepted, claim, phase, writer, now):
    require(quote["schema"] == "horizon-incident-replay-fit-v1"
            and quote["epoch"] == 145 and quote["fleet"] == accepted
            and quote["phase145"] == phase and quote["status_registration"] == writer
            and quote["fits"] is True and quote["candidate"] is None
            and quote["resource_credit_bytes"] == 0 and quote["replay_launch_authorized"] is False
            and quote["bounded_qualification"] == claim
            and (claim["scratch_bytes"], claim["memory_bytes"], claim["additional_cpu_quota_micros"]) ==
                (8 << 20, 192 << 20, 0)
            and 0 <= now - quote["recorded_unix_seconds"] <= 120
            and quote["available_HOME_bytes"] >= quote["complete_required_HOME_bytes"]
            and quote["available_memory_bytes"] >= quote["required_available_memory_bytes"],
            "native fit does not fund this held epoch 146 lease")
    retry5 = quote["retry5_complete_booking"]
    donor = quote["epoch159_donor_cover"]
    require(set(quote["survivors"]) == {"172"} and set(quote["replacements"]) in ({"167"}, {"167", "168"})
            and retry5["schema"] == "horizon-168-retry5-complete-booking-v1" and retry5["funded"] is True
            and retry5["retained_source"] == quote["retry5_retained_source"]
            and retry5["candidate_remaining_bytes"] == quote["bookings"]["168"]["remaining_bytes"]
            and retry5["complete_required_HOME_bytes"] == quote["complete_required_HOME_bytes"]
            and retry5["retained_base_HOME_bytes"] == donor["native_home_required"]
            and quote["native_before_registered_floor"] <= donor["native_home_required"]
            and len(quote["prefix_before"]) > 0 and len(quote["prefix_after"]) > 0
            and donor["fleet"] == accepted and donor["credited_retirement_bytes"] == 0
            and (donor["general_slot_cpu_micros"], donor["general_slot_memory_bytes"]) ==
                (1_000_000, 2 << 30),
            "native fit dropped the retry5 booking or epoch 145 post-delivery coverage")


def original_inputs(legacy):
    bound = legacy["bound"]
    draft_ref = bound(legacy["DRAFT"], legacy["DRAFT_SHA"])
    draft = json.loads(Path(draft_ref["path"]).read_bytes())
    image = draft["launcher"]
    bound(image["path"], image["sha256"])
    argv = draft["launcher_argv_preview"]
    require(argv[0] == legacy["SYSD"] and argv[-1] == image["path"], "different sealed launch argv")
    for key in ("launcher_runtime", "static_preflight"):
        bound(draft[key]["path"], draft[key]["sha256"])
    entry = json.loads(Path(draft["static_preflight"]["path"]).read_bytes())
    for mount in entry["observed_mounts"]:
        file = Path(mount["source"])
        st = file.lstat()
        ident = mount["identity"]
        require(file.resolve(strict=True) == file and stat.S_ISREG(st.st_mode)
                and (st.st_dev, st.st_ino, st.st_size, st.st_uid, st.st_gid, st.st_nlink,
                     st.st_mtime_ns, st.st_ctime_ns, stat.S_IMODE(st.st_mode)) ==
                    (ident["device"], ident["inode"], ident["bytes"], ident["uid"], ident["gid"],
                     ident["links"], ident["mtime_ns"], ident["ctime_ns"], int(ident["mode"], 8)),
                "the bounded launcher's read-only input changed")
    return draft


def holding_unused(path):
    st = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode)
            and (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_nlink, stat.S_IMODE(st.st_mode)) ==
                (64512, 95818311, 0, 0, 1, 0o600), "different holding transition lock")
    token = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
    require(not any(token in line.split() for line in Path("/proc/locks").read_text().splitlines()),
            "the holding transition is occupied")


def systemctl(*args):
    return subprocess.check_output(("/usr/bin/systemctl", *args), text=True, timeout=10)


def waiting_timer(fleet, cfg, names):
    timer = names["timer"]
    service = timer.removesuffix(".timer") + ".service"
    listed = systemctl("list-units", "--type=timer", "--state=waiting,running", "--plain",
                       "--no-legend", "horizon-observer-*.timer")
    state = dict(line.split("=", 1) for line in systemctl(
        "show", "-p", "Id,ActiveState,SubState,Triggers,InvocationID", timer).splitlines())
    command = systemctl("show", "-p", "ExecStart", service)
    observer = "/var/lib/jetstreamer/horizon_runtime_data/resident-observer-20261121-v1/observer/jetstreamer-horizon-observe"
    require(fleet["sole_next_timer"] == timer and cfg["output"] == str(names["sample"])
            and [line.split()[0] for line in listed.splitlines() if line.strip()] == [timer]
            and state == dict(Id=timer, ActiveState="active", SubState="waiting", Triggers=service,
                              InvocationID=state["InvocationID"])
            and re.fullmatch("[0-9a-f]{32}", state["InvocationID"])
            and f"{observer} {fleet['sole_next_observer']['path']} " in command,
            "foreign observer timer, command or output")
    return state


def remaining(bounded, claim):
    row = bounded["manager146"](bounded["MANAGER146"] + ",ExecMainStartTimestampMonotonic")
    elapsed = time.monotonic() - int(row["ExecMainStartTimestampMonotonic"]) / 1_000_000
    require(row["InvocationID"] == claim["invocation_id"] and int(row["MainPID"]) == claim["pid"]
            and 0 <= elapsed < HOLD_SECONDS, "the original held scope changed or expired")
    return HOLD_SECONDS - elapsed


def offer(evidence, provider, predecessor, phase, writer, cfg, names, timer, legacy, draft, watch):
    due = evidence["utc"](cfg["not_before_utc"]).timestamp()
    require(20 < due - time.time() <= 180, "outside the original observer arm window")
    bounded = provider["bounded142"]
    lease = bounded["LEASE146"]
    accepted_path = names["out"] / "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
    offer_path = names["out"] / "ENTRY146_LEASE_OFFER.json"
    require(not any(os.path.lexists(path) for path in (accepted_path, offer_path, lease)),
            "the scheduled attempt already has a fleet, lease or offer")
    actor = None

    def arm():
        nonlocal actor
        print(f"watching {names['sample']}", flush=True)
        time.sleep(max(due - time.time() - 17, 0))
        require(10 <= due - time.time() <= 20, "missed the original held launch window")
        legacy["idle"](legacy["manager"](bounded), lease)
        holding_unused(legacy["HOLD_LOCK"])
        require(waiting_timer(provider["fleet_head"](predecessor)[0], cfg, names) == timer
                and provider["registered_status"]() == writer
                and completion_contract(provider["phase145"](145, predecessor)) == phase
                and 10 <= due - time.time(), "fleet, completion or writer crossed the held launch window")
        log = legacy["LOG"]
        prior = log.lstat() if log.exists() else None
        subprocess.run(draft["launcher_argv_preview"], check=True, timeout=5)
        actor = legacy["find_held"](bounded, provider["s"], draft["static_preflight"], due,
                                    prior.st_size if prior else 0, prior, draft["launcher"]["path"])
        mask = os.umask(0o377)
        try:
            evidence["durable"](lease, actor)
        finally:
            os.umask(mask)
        require(stat.S_IMODE(lease.lstat().st_mode) == 0o400, "held lease permissions changed")

    watch(names["sample"], time.monotonic() + due - time.time() + 110, arm)
    registered = evidence["bound"](lease)
    claim = bounded["held146"](provider["s"], registered)
    require(actor is not None and claim["invocation_id"] == actor["invocation_id"]
            and remaining(bounded, claim) >= HOLD_SECONDS - 110
            and not os.path.lexists(accepted_path) and provider["registered_status"]() == writer,
            "the held identity, cadence or offer window changed")
    observer = evidence["bound"](names["sample"])
    evidence["ensure_dir"](names["out"])
    evidence["durable"](offer_path, {"schema": "horizon-epoch146-cadence-offer-v1", "lease": registered,
                                     "fleet_predecessor": predecessor, "observer": observer})
    print(json.dumps({"lease": registered, "offer": evidence["bound"](offer_path)}, sort_keys=True), flush=True)
    return accepted_path, registered, claim, due + 128


def release(evidence, provider, predecessor, phase, writer, draft, accepted_path, registered, claim, deadline):
    while not accepted_path.is_file() and time.time() < deadline:
        time.sleep(0.25)
    require(accepted_path.is_file(), "V12 did not accept the lease within the release budget")
    accepted = evidence["bound"](accepted_path)
    fleet, _ = provider["fleet_head"](accepted)
    require(fleet.get(LEASE_FIELD) == registered and fleet["previous_Root_operational_review"] == predecessor,
            "V12 did not accept the exact held lease and predecessor")
    bounded = provider["bounded142"]
    fit_path = accepted_path.with_name("ENTRY146_RELEASE_FIT.json")
    require(not os.path.lexists(fit_path) and remaining(bounded, claim) > PROVIDER_SECONDS + 5
            and provider["registered_status"]() == writer
            and bounded["held146"](provider["s"], registered) == claim,
            "lease lacks a free quote path, current writer or enough hold time")
    args = (str(PROVIDER), "145", accepted["path"], accepted["sha256"])
    proc = subprocess.run(args, capture_output=True, text=True, timeout=PROVIDER_SECONDS + 1)
    require(proc.returncode == 0 and not proc.stderr, f"sealed capacity provider declined: {proc.stderr.strip()}")
    quote = json.loads(proc.stdout)
    quote_contract(quote, accepted, claim, phase, writer, int(time.time()))
    require(provider["registered_status"]() == writer
            and bounded["held146"](provider["s"], registered) == claim
            and remaining(bounded, claim) > 2, "writer or held generation changed during pricing")
    provider["fleet_head"](accepted)
    evidence["durable"](fit_path, quote)
    fit = evidence["bound"](fit_path)
    # The unchanged issuer acquires the shared transition lock and keeps it through native drain.
    subprocess.run((draft["launcher"]["path"], "--issue-release", accepted["path"],
                    accepted["sha256"], fit["sha256"]), check=True, timeout=500)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("fleet", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("--provider-sha256", help="sealed provider receipt SHA-256 for the independent handoff")
    opts = parser.parse_args()
    require((GENERATION == "independent") == (opts.provider_sha256 is not None)
            and (opts.provider_sha256 is None or re.fullmatch("[0-9a-f]{64}", opts.provider_sha256)),
            "the independent handoff requires its exact provider seal SHA-256")
    require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode
            and re.fullmatch("[0-9a-f]{64}", opts.sha256), "use a privileged isolated interpreter")
    evidence = runpy.run_path(str(ROOT / "prefix140-status-cadence-20261122-v1/cadence-tools/evidence.py"))
    if opts.run:
        require(Path(__file__).resolve() == DEPLOYMENT / Path(__file__).name
                and Path(__file__).name in sealed_package(evidence, DEPLOYMENT), "unsealed epoch 146 entry operator")
    sealed_package(evidence, LEGACY, LEGACY_SHA)
    legacy = runpy.run_path(str(LEGACY / "run_sequence.py"))
    draft = original_inputs(legacy)
    provider_seal = sealed_package(evidence, PROVIDER.parent, opts.provider_sha256 or PROVIDER_SHA)
    cadence_seal = sealed_package(evidence, CADENCE, CADENCE_SHA)
    require(provider_seal["bounded142.py"]["sha256"] == cadence_seal["bounded142.py"]["sha256"],
            "V12 and the native price qualify different bounded entry behavior")
    provider = runpy.run_path(str(PROVIDER))
    predecessor = ref(opts.fleet, opts.sha256)
    fleet, _ = provider["fleet_head"](predecessor)
    phase = completion_contract(provider["phase145"](145, predecessor))
    writer = writer_contract(provider["registered_status"]())
    cfg = evidence["sealed"](fleet["sole_next_observer"])
    names = evidence["names"](cfg["not_before_utc"])
    timer = waiting_timer(fleet, cfg, names)
    require(LEASE_FIELD not in fleet, "the current fleet already carries a bounded entry lease")
    bounded = provider["bounded142"]
    legacy["idle"](legacy["manager"](bounded), bounded["LEASE146"])
    holding_unused(legacy["HOLD_LOCK"])
    if opts.check:
        print(json.dumps({"fleet": predecessor, "writer": writer, "completion": phase,
                          "due_utc": cfg["not_before_utc"], "mutated": False}, sort_keys=True))
        return
    sealed_package(evidence, WATCH, WATCH_SHA)
    watch = runpy.run_path(str(WATCH / "offer_close_event.py"))["wait_closed"]
    accepted = offer(evidence, provider, predecessor, phase, writer, cfg, names, timer, legacy, draft, watch)
    release(evidence, provider, predecessor, phase, writer, draft, *accepted)


if __name__ == "__main__":
    main()
