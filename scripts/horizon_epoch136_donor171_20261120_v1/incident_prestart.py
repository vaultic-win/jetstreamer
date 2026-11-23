"""Price the 136 prestart against the installed V17 provider and the ready audit."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
NATIVE = ROOT / "incident-replay-fit-20261121-v1/tools-v17"
CADENCE = ROOT / "prefix140-status-cadence-20261122-v1/cadence-tools"
ADAPTER = ROOT / "epoch166-retry10-delivery-20261121-v1/capacity-tools-bounded/publication-fit"
NATIVE_SEAL = "039534af05bc3bd1f0d54d196cbef5a13b89d24697d8789216faf7bde90f20b7"
CADENCE_SEAL = "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e"
PRICE = "924c72177d61b8340f8ff75caba72d4cfe5228df4b27111e56d2656a9d8d2aa8"
ADAPTER_SHA = "729ceda384e4def082967e24758f2e58f18f2d068ad41bae5358cf9cb60b5fb0"
CAP = 72 << 30
V20 = ROOT / "incident-replay-fit-20261121-v1/tools-v20"
V7 = ROOT / "epoch136-joint-writer-20261122-v7b"
RETRY_WRITER = ROOT / "epoch136-joint-writer-20261122-v7c"
V5N_WRITER = ROOT / "epoch136-joint-writer-20261123-v8"
V5N_PROVIDER = ROOT / "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-136-v1"
SEALER = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def immutable_bytes(path):
    metadata = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == metadata.st_gid == 0 and metadata.st_nlink == 1
            and metadata.st_mode & 0o222 == 0 and metadata.st_size <= 32 << 20, str(path))
    raw = path.read_bytes()
    after = path.lstat()
    require(len(raw) == metadata.st_size and os.path.samestat(metadata, after)
            and metadata.st_ctime_ns == after.st_ctime_ns, "unstable root evidence " + str(path))
    return raw


def pin(path, expected):
    raw = immutable_bytes(path)
    require(hashlib.sha256(raw).hexdigest() == expected, "changed deployed member " + str(path))
    return raw


def check_package(path, digest):
    seal = json.loads(pin(path / "deployment-seal-receipt.json", digest))
    require(seal["destination"] == str(path) and seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            and seal["sealer_sha256"] == SEALER and seal["remote_mutations"] is False, "foreign sealed directory")
    for row in seal["members"]:
        require(Path(row["name"]).name == row["name"], "foreign member")
        pin(path / row["name"], row["sha256"])
    return seal


def fixture_provider(provider, directory):
    image, sealref = provider["image"], provider["seal"]
    require(set(provider) == {"image", "seal"} and sealref["path"] == str(directory/"deployment-seal-receipt.json")
            and image["path"] == str(directory/"post-stop-fit"), "wrong fixture price source")
    seal = check_package(directory, sealref["sha256"])
    rows = [row for row in seal["members"] if row["name"] == "post-stop-fit"]
    require(len(rows) == 1 and rows[0]["sha256"] == image["sha256"] and rows[0]["mode"] == "0555",
            "wrong fixture price image")
    return directory/"post-stop-fit"


def capture_fixture(native_path, path, digest):
    # A running verifier performs its own census. Retry only that recognized
    # transient, then collect every measurement again under the original quota.
    for attempt in range(3):
        result = subprocess.run([native_path, "145", path, digest], capture_output=True, timeout=150)
        if result.returncode == 0:
            return json.loads(result.stdout)
        transient = any(reason in result.stderr for reason in
                        (b"foreign 145 descendants", b"capacity generation changed during collection"))
        if not transient or attempt == 2:
            raise ValueError(result.stderr.decode(errors="replace")[-1800:])
        time.sleep(2)


def price(native, native_floor, prefix_before, prefix_after, disk_now, memory_total, waiter=None, *, v5n=False):
    candidate = native["candidate136"]
    require(candidate["cap"] == CAP and candidate["remaining"] == CAP
            and candidate["occupied"] is (waiter is not None) and native["complete_cpu_quota_micros"] == 64_000_000
            and native["resource_credit_bytes"] == native["stopped_generation_resident_credit_bytes"] == 0
            and native["replay_launch_authorized"] is False, "incompatible or occupied native reservation")
    require(prefix_before["registration"] == prefix_after["registration"]
            and prefix_before["child"] == prefix_after["child"]
            and prefix_before["complete_result"] == prefix_after["complete_result"], "prefix owner changed")
    for state in (prefix_before, prefix_after):
        require(0 <= state["remaining_DATA_growth_bytes"] <= state["maximum_HOME_allocation_bytes"] == 16 << 20
                and state["additional_cpu_quota_micros"] == state["additional_memory_bytes"] ==
                state["resource_credit_bytes"] == state["archive_staging_bytes"] == 0,
                "unbounded prefix growth or additional entitlement")
    prefix = max(s["remaining_DATA_growth_bytes"] for s in (prefix_before, prefix_after))
    # The payload keeps every absolute incumbent stop floor *before* adding the 72 GiB.
    # V17 also books those 72 GiB, so recompute without it on the very same measured trees.
    protected = max(native_floor + prefix, candidate.get("guard_floor", 0))
    available = min(disk_now, native["available_HOME_bytes"])
    if v5n:
        donor = native["epoch159_donor_cover"]
        require(donor["fleet"] == native["fleet"] and donor["credited_retirement_bytes"] == 0
                and donor["native_home_required"] >= native["complete_required_HOME_bytes"]
                and donor["remaining_home_bytes"] >= 0, "unbound original 169/159 donor reservation")
        protected = max(protected, donor["native_home_required"] - CAP)
        available = min(available, donor["native_home_required"] + donor["remaining_home_bytes"])
    require(protected + CAP >= native["complete_required_HOME_bytes"], "incomplete absolute home floor")
    require(memory_total >= native["complete_memory_plus_reserve_bytes"], "physical RAM changed")
    return dict(protected_raw_floor_bytes=protected, candidate_remaining_growth_bytes=CAP,
                complete_required_HOME_bytes=protected + CAP, available_HOME_bytes=available,
                disk_fits=available >= protected + CAP,
                memory_fits=native["available_memory_bytes"] >= native["required_available_memory_bytes"],
                complete_memory_plus_reserve_bytes=native["complete_memory_plus_reserve_bytes"],
                total_memory_bytes=memory_total, remaining_prefix140_bytes=prefix,
                unfenced_with_candidate_cpu_micros=68_250_000, new_resource_credit_bytes=0)


def inspect(path, digest, waiter, mode, provider, fence=None, fixture=False, retry=False, v5n=False):
    require(not (retry or v5n) or (fixture and not (retry and v5n)), "invalid worker profile")
    writer = V5N_WRITER if v5n else RETRY_WRITER if retry else V7
    require(mode in ("preflight", "session"), "unknown writer mode")
    expected = dict(image=dict(path=str(NATIVE / "post-stop-fit"), sha256=PRICE),
                    seal=dict(path=str(NATIVE / "deployment-seal-receipt.json"), sha256=NATIVE_SEAL))
    directory = V5N_PROVIDER if v5n else V20 if fixture else NATIVE
    if fixture:
        fixture_provider(provider, directory)
        expected = provider
    else:
        require(provider == expected, "new fleet needs the explicit V17 plan")
        check_package(NATIVE, NATIVE_SEAL)
    check_package(CADENCE, CADENCE_SEAL)
    pin(ADAPTER, ADAPTER_SHA)
    sys.path.insert(0, str(CADENCE))
    from evidence import checked
    from retired_public_audit import observe_public
    from prefix140_storage import storage
    ref = dict(path=str(path), sha256=digest)
    fleet = checked(ref)
    prior_audit = checked(fleet["current_audit_progress"]["observation"])
    recorded = checked(fleet["current_home_cycle_capacity"])
    ready = fleet["active_ready_range_audit_obligation"]
    historical = fleet["continuing_audit_obligation"]
    require(historical["current_storage"]["pricing_basis_only"] is True
            and historical["current_storage"]["included_in_current_aggregate"] is False
            and historical["current_storage"]["remaining_DATA_growth_bytes"] == 18 << 30
            and ready["current_observation"] == fleet["current_audit_progress"]["observation"]
            and ready["current_storage"] == recorded["audit_storage"], "unbound audit transition")
    def audit():
        seen, paid, witness = observe_public(Path("/home/sol").stat().st_dev, historical)
        require(witness == recorded["audit_owner_witness"] and witness["native"]["ActiveState"] == "active"
                and seen["active_ready_workers"] == prior_audit["active_ready_workers"]
                and paid["output_budget"] == ready["current_storage"]["output_budget"]
                and paid["maximum_host_allocation_bytes"] == ready["maximum_output_allocation_bytes"] == 256 << 20,
                "changed ready audit controller, workers or HOME policy")
        return witness, seen["active_ready_workers"], paid
    first, workers, before_ready = audit()
    before = storage()
    if mode == "preflight":
        require(waiter is None and fence is None, "preflight cannot claim an actor or donor")
        if fixture:
            native = capture_fixture(directory / "post-stop-fit", path, digest)
        else:
            bridge = runpy.run_path(str(ADAPTER))
            native = json.loads(bridge["capture_provider"](directory / "post-stop-fit", str(path), digest))
    else:
        proc = Path("/proc") / str(os.getppid())
        argv = [os.fsdecode(v) for v in (proc / "cmdline").read_bytes().split(b"\0") if v]
        require(len(argv) == 6 and argv[1] == "session", "foreign session owner")
        plan = json.loads(pin(Path(argv[2]), argv[3]))
        require("holding145_prestart_ready" in plan, "136 session requires a registered and drained 145 boundary")
        owner = plan["controller_deployment"]
        package = Path(owner["path"]).parent
        check_package(package, owner["sha256"])
        require(package.parent.parent == ROOT and package.name == "controller"
                and (package / "admit136").samefile(proc / "exe"), "wrong writer deployment")
        from private136 import observation
        require(not fixture or package == writer / "controller", "different V7 writer")
        session = runpy.run_path(str(package / "prestart_session.py"))
        context = {"fixture_provider": fixture_provider, "retry": retry} if fixture else {}
        if v5n:
            context.update(v5n=True, check_package=check_package, read_immutable=immutable_bytes)
        native = session["capture_context"](ref, fence, waiter, **context, pin=pin, checked=checked,
                                            runpy=runpy, json=json, observation=observation)
    require(native["fleet"] == ref and native["schema"] == "horizon-incident-replay-fit-v1"
            and 0 <= time.time() - native["recorded_unix_seconds"] < 120, "wrong native price")
    module = runpy.run_path(str(directory / "post-stop-fit"))
    if fixture and mode == "preflight":
        prospective = json.loads(immutable_bytes(writer / "production-plan.json"))
        require(prospective["joint_fit_145"] == expected, "prospective native provider changed")
        controller = writer / "controller"
        binding = prospective["controller_deployment"]
        require(binding["path"] == str(controller / "deployment-seal-receipt.json"), "wrong fixture controller")
        deployment = check_package(controller, binding["sha256"])
        member_name = "v5n_boundary.py" if v5n else "fixture_boundary.py"
        member = [r for r in deployment["members"] if r["name"] == member_name]
        require(len(member) == 1 and member[0]["mode"] == "0444", "missing fixture semantic reader")
        fixture_module = runpy.run_path(str(controller / member_name))
        if v5n:
            require(prospective["holding145_semantic_worker"] == fixture_module["SEMANTIC_RESULT"] and
                    prospective["holding145_completion"] == fixture_module["COMPLETION_TOOLS"],
                    "different prospective V5n completion generation")
            joined = fixture_module["inspect"](pin, check_package, immutable_bytes,
                       fixture_module["read_inputs"], lambda _: native["phase145"])
            require(not joined["semantic_pending"], "V5n is still proving private semantic output")
        else:
            fixture_module["ordinary_phase"](prospective, native["phase145"], checked, pin, runpy, module["s"], retry=retry)
    floor, _, _ = module["disk_budget"](native["original_aggregate_HOME_bytes"], dict(remaining=0),
        native["bookings"], 145, native["survivors"], native["replacements"], native["active168_guard_floor"],
        native["closed_prestart_remaining"])
    last, last_workers, after_ready = audit()
    after = storage()
    require(first == last and workers == last_workers, "audit changed during native fit")
    disk = os.statvfs("/home/sol")
    total = int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1]) * 1024
    result = price(native, floor, before, after, disk.f_bavail * disk.f_frsize, total, waiter, v5n=v5n)
    return dict(result, schema="horizon-136-writer-joint-fit-v1", fleet=ref, provider_seal=expected["seal"],
                authoritative_joint_fit=native, audit=first, ready_workers=workers,
                ready_growth_before=before_ready, ready_growth_after=after_ready,
                prefix_before=before, prefix_after=after, waiting_candidate=waiter,
                activation_compatible=mode == "session" and result["disk_fits"] and result["memory_fits"],
                replay_launch_authorized=False,
                next_gate=("exclusive prestart after original V5n success and before V13h" if v5n else
                           "successful V5F completion and exclusive prestart before V13" if fixture else
                           "successful V5e completion and exclusive prestart before V11"))


if __name__ == "__main__":
    print(json.dumps(inspect(Path(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3]),
                             sys.argv[4], json.loads(sys.argv[5]),
                             json.loads(sys.argv[6]) if len(sys.argv) >= 7 else None,
                             fixture=sys.argv[7:] in (["fixture-semantic"], ["retry-semantic"], ["v5n-semantic"]),
                             retry=sys.argv[7:] == ["retry-semantic"],
                             v5n=sys.argv[7:] == ["v5n-semantic"]), sort_keys=True))
