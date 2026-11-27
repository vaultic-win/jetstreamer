#!/usr/bin/python3
"""Check or dispatch the private epoch 168 V4 assembly under the campaign lock."""
import argparse
from contextlib import contextmanager
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import tempfile
import time

HOME = Path("/home/sol")
PRIVATE = HOME / ".jetstreamer-private"
HERE = PRIVATE / "epoch168-assembly-operator-20261127-v1"
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = RT / "epoch168-joint-checkpoint-reduced-run-20261126-v1"
TOOLS = BASE / "private-assembly-tools-20261127-v2"
QUAL = BASE / "assembly-source-native-qualification-20261127-v1"
ROTATION = RT / "epoch186-closed-partial-rotation-20261127-v1"
MAIN185 = RT / "epoch185-lanem-main-holding-20261127-v1"
SEVENTH = RT / "epoch141-foundation-seventh-bootstrap-20261127-v1"
REPO = HOME / "workspace/jetstreamer"
OUTPUT = PRIVATE / "epoch168-private-assembly-20261127-v1/output"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
UNIT = "horizon-assemble-168-private-20261127-v1.service"
EVENT_UNIT = "horizon-168-assembly-on-reclamation-20261127-v1"
RELEASES = {
    "185": MAIN185 / "MEASURED_LOCAL_RECLAMATION.json",
    "186m": ROTATION / "M_SERIAL_HANDBACK.json",
    "186n": ROTATION / "n/RETIRED.json",
}
ASSEMBLER = TOOLS / "horizon-168-source-views"
ASSEMBLER_SHA = "a42303fdb80321d670534dc02ea5d117ce591b892d2f730d7b84d80e5a164829"
COMMIT = "39d52a0defdfdd2f7c0ea8f5f31d4a0de014f630"
MIB = 1 << 20
GIB = 1 << 30
ARCHIVE = 128 * GIB
EVIDENCE = 64 * MIB
REUSED_MEMORY = 4 * GIB
PEAK = ARCHIVE + EVIDENCE
MEMORY = 8 * GIB
CPU = 1_000_000
CPU_TOTAL = 64_000_000
SERIAL = 123_350_028_052
FIELDS = "Id,ActiveState,SubState,MainPID,ControlPID,InvocationID,ControlGroup,MemoryMax,MemorySwapMax,Job"
PINS = {
    "qualification": (QUAL / "QUALIFIED_REPORT.json", "1fdbd34bc1edee4db9781f5ba27b3f9d5b6443c717a07ce6fd08ea3f7940bd3b"),
    "qualification_native": (QUAL / "NATIVE_ACCEPTANCE.json", "63067817b1dfb2bd11b4c184dd089aec8cb58d9b19ab1bc93112a7171cae7044"),
    "lineage": (BASE / "lineage-binding-20261127-v3/LINEAGE_BINDING.json", "4c5d0946e0f37e8695411e9859152682aea85c1d05221df7434183e00d96c65f"),
    "finalized_edge": (QUAL / "SELECTED_FINALIZED_EDGE.json", "afb2a5fa4e41be7bdd68e341f9658faf8cd89902b34ab6b42d8ad39d19560516"),
    "assembler": (ASSEMBLER, ASSEMBLER_SHA),
    "deployment": (TOOLS / "deployment-seal-receipt.json", "7bdc200595b8aaaa343457118a7a129d1d947cd7002bec0ee5409fd2112bcd18"),
    "186m_profile": (ROTATION / "m/profile.json", "03e37da3b386ddadba226cf3fd654356723acd88f9461351f54801a0d89237d9"),
    "186n_profile": (ROTATION / "n/profile.json", "f57d5ed937ac7995a057f0227c400b6e2e70a21903cebf77bedd05a5474453b0"),
    "rotation_pricer": (ROTATION / "tools/rotation.py", "9fbd3d4029d3f415f83d6d6fe03b2b97f7509e212da299c806c643467d36f801"),
    "seventh_assignment": (SEVENTH / "SERIAL_ASSIGNMENT.json", "19e79eebf95c26680a9cd81836ce8cf041d0123850d5d92f5d87a9be90698a78"),
    "eighth_source": (RT / "epoch141-eighth-original-source-packet-20261127-v1/EIGHTH_SOURCE_PACKET.json", "dac263259ee719bc3d01e326ca72eb74786ea062ca2b0aad00eac1eba7200480"),
    "source185": (MAIN185 / "package/EXPECTED.json", "e4e9216caad33766d35013357e8c414f49667341440e5cb6976a828f4050d8d1"),
    "retired199": (RT / "epoch199-bootstrap-cache-review-20261127-v1/retirement/COMPLETE.json", "73eb9c095cedbed80ddad6b18861cca1339d694ea466d0d9ecf79407d3b3506e"),
}


def need(ok, error):
    if not ok:
        raise RuntimeError(error)


def ref(path, expected=None):
    path = Path(path)
    m = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode)
         and m.st_uid == 0 and not m.st_mode & 0o022, f"untrusted evidence {path}")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    need(expected is None or expected == digest, f"changed SHA-256 for {path}")
    return {"path": str(path), "sha256": digest}


def bound(reference):
    path = Path(reference["path"])
    ref(path, reference["sha256"])
    return json.loads(path.read_bytes())


def read(path):
    return bound(ref(path))


def command(*argv, **options):
    return subprocess.check_output(list(map(str, argv)), timeout=45, **options)


def native(unit):
    p = subprocess.run(
        ["/usr/bin/systemctl", "show", "--all", "-p", FIELDS, "--", unit],
        capture_output=True, text=True, timeout=15,
    )
    s = dict(line.split("=", 1) for line in p.stdout.splitlines())
    need(p.returncode in (0, 4) and s.get("Id") == unit, f"cannot inspect {unit}")
    return s


def cpu_quota(group):
    quota, period = (Path("/sys/fs/cgroup") / group.lstrip("/") / "cpu.max").read_text().split()
    return None if quota == "max" else (int(quota) * 1_000_000 + int(period) - 1) // int(period)


def native_roster():
    listing = command("/usr/bin/systemctl", "list-units", "--type=service",
                      "--state=running,activating,deactivating", "--no-legend", "--plain",
                      "horizon*", "jetstreamer*", text=True)
    units = [line.split()[0] for line in listing.splitlines() if line.split()]
    rows = {}
    # Read current cgroup ceilings and invocation identities, independently of the pricing profiles.
    for unit in units:
        row = native(unit)
        if row["ActiveState"] == "active" and int(row["MainPID"]) > 0:
            group = row["ControlGroup"]
            need(group.startswith("/") and re.fullmatch(r"[0-9a-f]{32}", row["InvocationID"]),
                 f"unbound native owner {unit}")
            row["cpu_quota_micros"] = cpu_quota(group)
            rows[unit] = row
    return rows


def retirement_terms(pins, fleet):
    accepted = datetime.fromisoformat(fleet["sampled_at_utc"]).timestamp()
    cache = bound(pins["retired199"])
    need(cache["status"] == "deleted" and cache["cache_device"] == HOME.stat().st_dev
         and not os.path.lexists(cache["cache_file"]) and cache["process_references"] == []
         and cache["r2_mutations"] is cache["remote_mutations"] is False, "199 cache retirement no longer matches")
    measured = cache["filesystem_available_bytes_after"] - cache["filesystem_available_bytes_before"]
    cache_when = datetime.fromisoformat(cache["recorded_at_utc"]).timestamp()
    credits = {"199_bootstrap": {
        "receipt": pins["retired199"], "observed_unix": cache_when,
        "inherited_screen_bytes": max(0, min(measured, cache["cache_allocated_bytes"])) if cache_when > accepted else 0,
    }}
    result = RELEASES["185"]
    credits["185_original"] = {"receipt": None, "inherited_screen_bytes": 0}
    if result.exists():
        result_ref = ref(result)
        reclaimed = bound(result_ref)
        done = bound(reclaimed["completion"])
        term = bound(reclaimed["native_terminal"])
        src = bound(pins["source185"])
        custody = bound(reclaimed["native_custody"])
        when = int(term["done_usec"]) / 1_000_000
        need(done["source_absent"] and done["quarantine_absent"] and done["authenticated_custody_revalidated"]
             and done["whole_readback_before_retirement"] and term["success"]
             and term["unit"] == "horizon-closed185-lanem-main-retire-20261127-v1.service"
             and done["invocation"] == term["invocation"] and done["operation"]["source"] == src["source"]
             and done["allocated_bytes_removed"] == src["source_identity"]["allocated_bytes"]
             and done["measured_freed_bytes"] == done["available_after"] - done["available_before"]
             and custody["sha256"] == src["sha256"] and custody["remote_sha256_readback"],
             "185 measured local reclamation does not bind the expected original")
        restored = os.path.lexists(src["source"])
        need(not os.path.lexists(done["operation"]["quarantine"]), "185 quarantine still exists")
        amount = max(0, min(done["allocated_bytes_removed"], done["measured_freed_bytes"]))
        need(amount == reclaimed["conservative_capacity_bytes"], "185 measured reclamation value changed")
        credits["185_original"] = {
            "receipt": result_ref, "observed_unix": when, "original_path_present": restored,
            "inherited_screen_bytes": amount if when > accepted and not restored else 0,
        }
    for lane in ("m", "n"):
        key = "186" + lane
        marker = RELEASES[key]
        credits[key] = {"receipt": None, "inherited_screen_bytes": 0}
        if marker.exists():
            marker_ref = ref(marker)
            settled = bound(marker_ref)
            settled_ref = settled["retirement"] if lane == "m" else marker_ref
            done = bound(settled_ref)
            source = bound(pins[key + "_profile"])
            move = bound(done["move"])
            unlink = bound(done["unlink"])
            custody = bound(read(ROTATION / lane / "PARK_ACCEPTED.json")["native_custody"])
            terminal = done["native_terminal"]
            need(done["success"] and terminal["success"] and terminal["invocation_id"] == done["invocation"] and terminal["unit"] == done["unit"]
                 and done["unit"].startswith(f"horizon-closed186-retire-{lane}-")
                 and done["source"] == move["source"] == unlink["source"] == source["source"]
                 and done["sha256"] == move["sha256"] == unlink["sha256"] == custody["sha256"] == source["sha256"]
                 and custody["remote_sha256_readback"] and custody["local_source_revalidated"]
                 and unlink["intent"] == done["move"] and move["quarantine"] == unlink["quarantine"]
                 and not os.path.lexists(move["quarantine"])
                 and done["allocated_bytes_removed"] == source["allocated"]
                 and done["measured_net_free_bytes"] == done["available_after"] - done["available_before"],
                 f"{key} local reclamation does not bind the exact native retirement")
            when = int(terminal["done_usec"]) / 1_000_000
            restored = os.path.lexists(source["source"])
            amount = max(0, min(done["allocated_bytes_removed"], done["measured_net_free_bytes"]))
            need(amount == done["conservative_capacity_bytes"], f"{key} measured reclamation changed")
            credits[key] = {
                "receipt": settled_ref, "observed_unix": when, "original_path_present": restored,
                "inherited_screen_bytes": amount if when > accepted and not restored else 0,
            }
    return credits


def available_home():
    fs = os.statvfs(HOME)
    return fs.f_bavail * fs.f_frsize


def sealed_sources(pins):
    build = read(TOOLS / "ASSEMBLY_BUILD_V2.json")
    need(build["commit"] == COMMIT and build["binary"]["sha256"] == ASSEMBLER_SHA
         and build["tests_passed"] == 11, "assembly source build changed")
    deployment = bound(pins["deployment"])
    need(deployment["destination"] == str(TOOLS) and deployment["publication_authorized"] is False,
         "wrong assembler deployment")
    for member in deployment["members"]:
        ref(TOOLS / member["name"], member["sha256"])
    need(bound(pins["qualification_native"])["invocation_id"] == "727ba3fef1814fb79af93cf42b8b7c0c",
         "source qualification invocation changed")
    layout = json.loads(command(ASSEMBLER, "--check-assembly-sources",
                                pins["lineage"]["path"], pins["lineage"]["sha256"]))
    return build, layout


def source_head(build, launch):
    # Use the repo's established SSH path and the actual remote branch tip. Read-only
    # checks may return a missing-object diagnostic when another controller has not fetched it.
    def git(*args, **options):
        return command("/usr/sbin/runuser", "-u", "sol", "--", "/usr/bin/git", "-C", REPO,
                       *args, **options)

    inherited = os.environ.get("SSH_AUTH_SOCK")
    candidates = ([Path(inherited)] if inherited else []) + sorted(Path("/tmp").glob("ssh-*/agent.*"))
    agent = None
    for candidate in candidates:
        try:
            st = candidate.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != HOME.stat().st_uid:
            continue
        probe = subprocess.run(
            ["/usr/sbin/runuser", "-u", "sol", "--", "/usr/bin/env", f"SSH_AUTH_SOCK={candidate}",
             "/usr/bin/ssh-add", "-l"], capture_output=True, timeout=5,
        )
        if probe.returncode == 0:
            agent = candidate
            break
    need(agent is not None, "no live repository SSH agent for sol")
    os.environ["SSH_AUTH_SOCK"] = str(agent)
    if launch:
        git("fetch", "--quiet", "origin", "refs/heads/account-updates")
    remote = git("ls-remote", "--exit-code", "origin", "refs/heads/account-updates", text=True).split()[0]
    git("merge-base", "--is-ancestor", COMMIT, remote)
    for name, expected in build["source_files"].items():
        need(hashlib.sha256(git("show", f"{COMMIT}:{name}")).hexdigest() == expected,
             f"sealed build input is different from the merged source: {name}")
    if launch:
        operator_source = "scripts/horizon_epoch168_joint_capacity_20261126_v1/joint-source-compare/dispatch_private_assembly.py"
        operator_sha = ref(HERE / "dispatch.py")["sha256"]
        need(hashlib.sha256(git("show", f"{remote}:{operator_source}")).hexdigest() == operator_sha,
             "deployed operator is not the merged campaign source")
    return remote


def output_gate():
    if not os.path.lexists(OUTPUT):
        return "absent; create during launch under the campaign lock"
    st = OUTPUT.lstat()
    need(OUTPUT.resolve(strict=True) == OUTPUT and st.st_uid == 0 and stat.S_ISDIR(st.st_mode)
         and stat.S_IMODE(st.st_mode) == 0o700 and st.st_dev == HOME.stat().st_dev,
         "output directory has the wrong custody, mode, or filesystem")
    need(not any(OUTPUT.iterdir()), "output directory already contains evidence or archive bytes")
    return "empty, root-owned 0700, HOME-backed"


def carried_resources(pins, fleet, core, roster):
    acceptance = bound(pins["qualification_native"])
    source_start = bound(acceptance["native_start"])
    intent = bound(source_start["intent"])
    prior = bound(intent["fit"])
    selected = prior["old_selector"]
    settled = bound(prior["bounded_native"])["terminal168_compute_settlement"]
    selector_end = bound(prior["terminal_native"])
    qualification = source_start["native"]
    need(selected == settled["active_selector"] and selected["cpu_quota_micros"] == prior["quota_micros"] == CPU
         and selected["memory_bytes"] == prior["reused_same_epoch_selector_bytes"] == REUSED_MEMORY
         and settled["replaced_168_memory_bytes"] - settled["released_memory_bytes"]
              == REUSED_MEMORY + settled["preserved_comparator_memory_bytes"]
         and settled["replaced_168_cpu_quota_micros"] == CPU + settled["preserved_comparator_cpu_quota_micros"]
         and not settled["other_operation_can_reuse"] and settled["released_cpu_quota_micros"] == 0
         and prior["producer_release_credit_bytes"] == 0
         and prior["price"]["live_quote"]["joint"]["charged_167"] == core["joint"]["charged_167"]
         and fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"]
         and bound(fleet["current_home_cycle_capacity"])["full172_admitted_cpu_quota_micros"]
              == settled["effective_complete_cpu_quota_micros"] == CPU_TOTAL,
         "the accepted fleet no longer proves the carried epoch 168 CPU and RAM slots")
    for unit, invocation, event in (
        (selected["unit"], selected["invocation_id"], selector_end["pid1_terminal_event"]),
        (acceptance["unit"], acceptance["invocation_id"], acceptance["pid1_terminal_event"]),
    ):
        owner = native(unit)
        need(event["UNIT"] == unit and event["INVOCATION_ID"] == invocation
             and event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
             and event["_PID"] == "1" and event["_UID"] == "0"
             and owner["ActiveState"] == "inactive" and owner["MainPID"] == owner["ControlPID"] == "0"
             and not owner["Job"] and unit not in roster,
             f"same-epoch reservation remains owned by {unit}")
    need(qualification["InvocationID"] == acceptance["invocation_id"]
         and qualification["CPUQuotaPerSecUSec"] == "1s"
         and int(qualification["MemoryMax"]) == REUSED_MEMORY and qualification["MemorySwapMax"] == "0",
         "original qualification used a different CPU or memory slot")
    unexpected = [unit for unit in roster if "168" in unit and not unit.startswith(EVENT_UNIT)]
    need(not unexpected, "another epoch 168 unit is active: " + ", ".join(unexpected))
    known = sum(row["cpu_quota_micros"] for unit, row in roster.items()
                if row["cpu_quota_micros"] is not None and not unit.startswith(EVENT_UNIT))
    need(known + CPU <= CPU_TOTAL, "live native finite CPU ceilings went over the complete host ceiling")
    return {
        "complete_cpu_quota_micros": CPU_TOTAL,
        "native_finite_cpu_plus_assembly_micros": known + CPU,
        "additional_cpu_quota_micros": 0,
        "same_epoch_reused_cpu_quota_micros": CPU,
        "same_epoch_reused_memory_bytes": REUSED_MEMORY,
        "additional_assembly_memory_bytes": MEMORY - REUSED_MEMORY,
        "carried_selector_fit": intent["fit"],
        "drained_selector": prior["terminal_native"],
        "drained_source_qualification": pins["qualification_native"],
    }


def quote(pins):
    code = runpy.run_path(pins["rotation_pricer"]["path"])
    rotation = code["recent_price"]()
    code["owners"](rotation)
    core = rotation["basis"]["live_quote"]
    fleet_ref = core["fleet"]
    fleet = bound(fleet_ref)
    credits = retirement_terms(pins, fleet)
    inherited = core["inherited_complete_margin"] + sum(x["inherited_screen_bytes"] for x in credits.values())
    eighth = bound(pins["eighth_source"])
    eighth_bytes = eighth["bootstrap"]["size"]
    eighth_total = eighth["budget"]["bootstrap_with_64_mib_minimum_free_bytes"]
    need(eighth_bytes == 2_921_574_455 and eighth_total == eighth_bytes + 64 * MIB,
         "eighth bootstrap envelope changed")
    pending = rotation["additional_holding_disk"] + eighth_total
    seventh = bound(pins["seventh_assignment"])
    need(rotation["serial_slot"] == SERIAL and rotation["additional_holding_disk"] >= seventh["byte_length"] + 4096
         and rotation["holding_ram_available_from_serial"] == 2 * GIB,
         "serial restore envelope or the full seventh input charge changed")
    realized = rotation["basis"]["charged_bootstrap_inputs_observed_resident"]
    home = min(core["home"], available_home())
    live_floor = max(core["max_guard_floor"], core["required_home"] - realized) + pending
    inherited_floor = home - (inherited - pending)
    floor = max(live_floor, inherited_floor)
    # The serial uploader/downloader and parallel controls are already in this
    # price. The shared selector carries its 4 GiB and 16 MiB in the provider.
    ram = core["ram"]
    retained_ram = ram - rotation["remaining_ram"]
    roster = native_roster()
    selector = roster.get("horizon-170-retained-prefix-select-20261127-v1.service")
    if selector:
        need(int(selector["MemoryMax"]) <= 4 * GIB and selector["MemorySwapMax"] == "0"
             and selector["cpu_quota_micros"] == 1_000_000, "selector exceeded its inherited ceiling")
    compute = carried_resources(pins, fleet, core, roster)
    required_ram = retained_ram + compute["additional_assembly_memory_bytes"]
    blockers = []
    if home < floor + PEAK:
        blockers.append(f"HOME short by {floor + PEAK - home} bytes")
    if ram < required_ram:
        blockers.append(f"RAM short by {required_ram - ram} bytes")
    return {
        "schema": "horizon-epoch168-private-assembly-complete-fit-v1",
        "observed_unix_seconds": int(time.time()), "fleet": fleet_ref,
        "available_home_bytes": home, "minimum_home_free_bytes": floor,
        "required_available_home_bytes": floor + PEAK, "booked_assembly_home_bytes": PEAK,
        **compute, "available_memory_bytes": ram, "required_available_memory_bytes": required_ram,
        "assembly_memory_bytes": MEMORY, "assembly_cpu_quota_micros": CPU,
        "inherited_home_margin_after_terms": inherited - pending, "live_home_floor_bytes": live_floor,
        "serial_restore_envelope_bytes": SERIAL, "seventh_input_bytes": seventh["byte_length"],
        "eighth_single_copy_bootstrap_bytes": eighth_bytes, "eighth_staging_and_evidence_bytes": eighth_total - eighth_bytes,
        "additional_holding_and_input_home_bytes": pending, "retirement_observations": credits,
        "native_roster": roster, "rotation_price": rotation, "resource_credit_bytes": 0,
        "fits": not blockers, "blockers": blockers, "publication_authorized": False,
    }


def put(path, document):
    with path.open("xb") as target:
        os.fchmod(target.fileno(), 0o400)
        target.write((json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
        target.flush()
        os.fsync(target.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return ref(path)


def create_plan(directory, pins, fit):
    basis = put(directory / "FIT.json", fit)
    expires = int(time.time()) + 180
    common = {
        "unit": UNIT, "output_directory": str(OUTPUT), "qualification": pins["qualification"],
        "minimum_home_free_bytes": fit["minimum_home_free_bytes"], "maximum_archive_bytes": ARCHIVE,
        "evidence_allowance_bytes": EVIDENCE, "memory_max_bytes": MEMORY, "cpu_quota_micros": CPU,
        "admission_expires_unix_seconds": expires, "publication_authorized": False,
    }
    keys = ("available_home_bytes", "required_available_home_bytes", "required_available_memory_bytes",
            "available_memory_bytes", "complete_cpu_quota_micros")
    admission = put(directory / "ADMISSION.json", {
        **common, **{key: fit[key] for key in keys},
        "schema": "horizon-epoch168-private-v4-assembly-admission-v1", "epoch": 168,
        "capacity_basis": basis, "booked_assembly_home_bytes": PEAK, "swap_bytes": 0,
        "resource_credit_bytes": 0, "all_existing_commitments_retained": True, "fits": True,
    })
    return put(directory / "PLAN.json", {
        **common, "schema": "horizon-epoch168-private-assembly-plan-v1", "admission": admission,
        "lineage": pins["lineage"], "qualification_native": pins["qualification_native"],
    })


def native_plan_check(plan):
    return json.loads(command(ASSEMBLER, "--check-private-assembly-plan", plan["path"], plan["sha256"]))


def screened(pins, source, layout):
    need(native(UNIT)["ActiveState"] == "inactive", "exact assembly unit already has a live or failed owner")
    out = output_gate()
    fit = quote(pins)
    fit.update(source_branch_head=source, source_layout=layout, inputs=pins, output_gate=out)
    return fit


def launch(pins, fit):
    need(fit["fits"], "; ".join(fit["blockers"]))
    need(time.time() - fit["observed_unix_seconds"] <= 25, "resource quote expired before booking")
    OUTPUT.parent.mkdir(mode=0o700, exist_ok=True)
    st = OUTPUT.parent.lstat()
    need(OUTPUT.parent.resolve() == OUTPUT.parent and st.st_uid == 0
         and stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700,
         "unexpected assembly parent custody")
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    output_gate()
    directory = Path(tempfile.mkdtemp(prefix="launch-", dir=HERE))
    plan = create_plan(directory, pins, fit)
    check = native_plan_check(plan)
    need(check["plan_sha256"] == plan["sha256"] and check["archive_bytes_written"] == 0,
         "native dry check did not accept the exact plan without writes")
    put(directory / "PLAN_CHECK.json", check)
    logfile = directory / "assembly.log"
    argv = ["/usr/bin/systemd-run", "--quiet", "--service-type=exec", "--unit=" + UNIT, "--slice=system.slice"]
    argv += launch_properties(plan, logfile, OUTPUT)
    shell = '"$1" --assemble-private "$2" "$3" 2>&1 | /usr/bin/head -c 33554432'
    argv += ["--", "/bin/bash", "-o", "pipefail", "-c", shell, "epoch168",
             str(ASSEMBLER), plan["path"], plan["sha256"]]
    put(directory / "LAUNCH_INTENT.json", {"argv": argv, "plan": plan, "publication_authorized": False})
    need(available_home() >= fit["required_available_home_bytes"], "HOME dropped below the sealed start floor")
    command(*argv)
    observed = native(UNIT)
    need(re.fullmatch(r"[0-9a-f]{32}", observed["InvocationID"]) is not None,
         "systemd did not return an invocation; inspect this exact unit before retry")
    need(observed["ControlGroup"] == "/system.slice/" + UNIT
         and observed["MemorySwapMax"] == "0" and int(observed["MemoryMax"]) == MEMORY
         and cpu_quota(observed["ControlGroup"]) == CPU, "unexpected launched native assembly envelope")
    return put(directory / "LAUNCH_NATIVE.json", observed)


def launch_properties(plan, logfile, output):
    properties = [
        "User=root", "CPUQuota=100%", "CPUQuotaPeriodSec=100ms", f"MemoryMax={MEMORY}", "MemorySwapMax=0",
        "TasksMax=256", "Restart=no", "UMask=0077", "LimitCORE=0", "NoNewPrivileges=yes", "ProtectSystem=strict",
        "ProtectHome=read-only", "ProtectControlGroups=yes", "ProtectKernelTunables=yes", "PrivateDevices=yes",
        "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE", "AmbientCapabilities=CAP_DAC_OVERRIDE",
        "ReadOnlyPaths=/tmp /var/tmp /dev/shm /run", f"ReadWritePaths={output}",
        "Environment=RUST_MIN_STACK=67108864", f"StandardOutput=append:{logfile}", "StandardError=inherit",
        f"ExecStartPre={ASSEMBLER} --check-private-assembly-plan {plan['path']} {plan['sha256']}",
    ]
    return ["--property=" + entry for entry in properties]


@contextmanager
def operation_lock():
    with LOCK.open("rb") as lock:
        st = os.fstat(lock.fileno())
        need(st.st_uid == 0 and stat.S_ISREG(st.st_mode) and not st.st_mode & 0o022 and st.st_nlink == 1,
             "invalid shared operation lock")
        until = time.monotonic() + 45
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                need(time.monotonic() < until, "campaign operation lock remains busy")
                time.sleep(.2)
        yield


def trusted_deployment():
    need(HERE.stat().st_uid == 0 and not HERE.stat().st_mode & 0o022
         and HERE.resolve() == HERE and HERE.stat().st_dev == HOME.stat().st_dev,
         "operator deployment must be sealed on HOME")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "launch", "on-reclamation"))
    args = parser.parse_args()
    need(os.geteuid() == 0 and __debug__, "run as root with Python assertions enabled")
    os.umask(0o077)
    trusted_deployment()
    pins = {name: ref(*source) for name, source in PINS.items()}
    build, layout = sealed_sources(pins)
    if args.action == "check":
        source = source_head(build, False)
        print(json.dumps(screened(pins, source, layout), indent=2, sort_keys=True))
        return
    if args.action == "launch":
        source = source_head(build, True)
        with operation_lock():
            fit = screened(pins, source, layout)
            print(json.dumps(fit, indent=2, sort_keys=True), flush=True)
            print(json.dumps(launch(pins, fit)), flush=True)
        return
    on_reclamation(pins, build, layout)


def on_reclamation(pins, build, layout):
    if native(UNIT)["ActiveState"] != "inactive" or os.path.lexists(OUTPUT / "epoch-168.jet"):
        return
    events = {name: ref(path) for name, path in RELEASES.items() if path.exists()}
    if not events:
        return
    digest = hashlib.sha256(json.dumps(events, sort_keys=True).encode()).hexdigest()
    result_path = HERE / f"RECLAMATION_EVENT_{digest}.json"
    if result_path.exists():
        return
    report = {"schema": "horizon-epoch168-private-assembly-reclamation-event-v1",
              "observed_unix_seconds": int(time.time()), "events": events, "launched": False}
    try:
        source = source_head(build, True)
        with operation_lock():
            if result_path.exists():
                return
            fit = screened(pins, source, layout)
            report["fit"] = fit
            if fit["fits"]:
                report["launch_native"] = launch(pins, fit)
                report["launched"] = True
            else:
                report["blockers"] = fit["blockers"]
                report["remaining_release_evidence"] = [
                    str(path) for name, path in RELEASES.items() if name not in events
                ]
                report["action"] = "Reprice on the next measured release, accepted owner transition, or explicitly assigned capacity."
    except (RuntimeError, ValueError, KeyError, OSError, AssertionError, subprocess.SubprocessError) as exc:
        report["gate_error"] = str(exc) or type(exc).__name__
        report["native_at_failure"] = native(UNIT)
        report["action"] = "Inspect the failed evidence or exact assembly unit before repricing the current fleet."
    put(result_path, report)
    print(result_path, flush=True)


if __name__ == "__main__":
    main()
