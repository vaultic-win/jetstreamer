"""Price the original five source-QA jobs as an independently fenced serial bootstrap."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

GIB = 1 << 30
MIB = 1 << 20
RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
PACKAGE = Path("/usr/local/lib/jetstreamer/horizon-native163-operator-source-QA-continuation-20261112-v7")
RECIPE_SHA = "cec4ae8d233923c1e43b7be2fae0b40b1dfc1e305ce772d2fc5a1dde12f5d715"
SOURCE_SEAL = "f851c12fbc53fbf2d7da02828fc0d8c8e824221277bbc132223d310aac0b9d49"
ORIGINAL_ROOT = "horizon-native163-consumer15-operator-source-qa-root-20261112-v5.service"
FAMILY = "horizon-native163-bootstrap-20261123"
SLICE = "horizonaudit-epoch163bootstrap.slice"
SLICE_DIR = Path("/sys/fs/cgroup/horizonaudit.slice") / SLICE
LABELS = ("clippy-production", "clippy-tests", "build-tests", "ordinary-tests", "production")
CHILD_BOUND = 512 * MIB
ROOT_BOUND = 256 * MIB
COVER = "horizon-145-drained-159-donor-cover-v1"
GENERAL_SLOT = (1_000_000, 2 * GIB)


def need(ok, error):
    if not ok:
        raise ValueError(error)


def pin(path, expected, compiler_input=False):
    path = Path(path)
    need(path.resolve(strict=True) == path, "redirected proof")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as src:
        st = os.fstat(src.fileno())
        custody = ((st.st_uid, st.st_gid) == (1001, 1001) and not st.st_mode & 0o002
                   if compiler_input else (st.st_uid, st.st_gid) == (0, 0) and not st.st_mode & 0o022)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and custody, "untrusted input: " + str(path))
        digest = hashlib.file_digest(src, "sha256").hexdigest()
        def identity(s):
            return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
        need(identity(st) == identity(os.fstat(src.fileno())) == identity(path.lstat()) and
             digest == expected, "changed original bytes: " + str(path))
        return {"path": str(path), "sha256": digest}


def checked(ref):
    p = Path(ref["path"])
    pin(p, ref["sha256"])
    data = p.read_bytes()
    need(hashlib.sha256(data).hexdigest() == ref["sha256"], "changed JSON bytes")
    return json.loads(data)


def commands(recipe):
    need(set(recipe["exact5_source_QA_recipes"]) == set(LABELS) and recipe["tests_expected_not_run"] == 11 and
         recipe["new_source_QA_runtime_and_seal_OS_budget_bytes"] == 512 * MIB and
         recipe["enabled_features"] == [], "changed source-only bootstrap")
    result = {}
    for label in LABELS:
        r = recipe["exact5_source_QA_recipes"][label]
        checked(r["parent_actual_argv"])
        a = r["candidate_argv"]
        need(a[:3] == ["/usr/bin/systemd-run", "--wait", "--pipe"] and
             a[3] == "--unit=horizon-native163-consumer15-operator-" + label + "-20261112-v3" and
             a.count("CPUQuota=200%") == a.count("MemoryMax=512M") == a.count("MemorySwapMax=0") ==
             a.count("TasksMax=128") == a.count("RuntimeMaxSec=40") == a.count("PrivateNetwork=yes") ==
             a.count("BindsTo=" + ORIGINAL_ROOT) == a.count("After=" + ORIGINAL_ROOT) == 1,
             "changed actor or sandbox: " + label)
        if label == "ordinary-tests":
            need(a[-3:] == ["/var/lib/jetstreamer/native163-consumer15-operator-source-qa-20261112-v1/work/build-tests",
                            "--test-threads=1", "--nocapture"], "changed ordinary fixture")
        else:
            program = recipe["compiler" if label in ("production", "build-tests") else "clippy"]["path"]
            need(a.count(program) == 1 and a[-2] == "-o", "changed compiler")
            for i, v in enumerate(a):
                if v == "--extern":
                    name, path = a[i+1].split("=", 1)
                    need(path == recipe["actual_direct_externs"][name]["path"], "different compiler dependency")
        result[label] = hashlib.sha256(json.dumps(a,separators=(",",":")).encode()).hexdigest()
    return result


def recipe():
    pin(PACKAGE / "deployment-seal-receipt.json", SOURCE_SEAL)
    r = checked({"path": str(PACKAGE / "recipe.json"), "sha256": RECIPE_SHA})
    for record in (r["compiler"], r["clippy"], *r["actual_direct_externs"].values()):
        pin(record["path"], record["sha256"], compiler_input=True)
    return r, commands(r)


def inspect_price(native, general, scope, now, age=180):
    need(native["schema"] == "horizon-incident-replay-fit-v1" and native["epoch"] == 145 and native["fits"]
         and native["candidate"] is None and not native["replay_launch_authorized"]
         and native["resource_credit_bytes"] == 0 and native["complete_cpu_quota_micros"] == 64_000_000
         and native["complete_memory_plus_reserve_bytes"] == 810_658_050_048 and
         0 <= now - native["recorded_unix_seconds"] <= age, "stale or unjoined complete price")
    v = native["epoch159_donor_cover"]
    need(v["schema"] == COVER and v["fleet"] == native["fleet"] and
         v["native_recorded_unix_seconds"] == native["recorded_unix_seconds"] and
         v["credited_retirement_bytes"] == v["build_HOME_bytes"] == v["build_RAM_bytes"] == 0 and
         v["diagnostic"]["invocation_id"] == "fd406b11e15040cb9039dd9fdc48f63d" and
         v["diagnostic"]["scratch"]["retired"] == "c299a6b09f5f84d06abf83ef8a31393ea59d3a4024fa4c0da7bc0089949c9b58",
         "missing original diagnostic/retirement coverage")
    phase = native["phase145"]
    need(phase["invocation_id"] == scope and re.fullmatch("[0-9a-f]{32}",scope) and
         phase["stage"] in ("controller","leased-worker") and
         native["candidate136"]["occupied"] is False and len(native["survivors"]) == 1
         and set(native["replacements"]) == {"166","167","168","170"}, "expected active 145 and five paid producers")
    slot = (general["build_cpu_quota_micros"],general["build_memory_bytes"])
    need(slot == GENERAL_SLOT == (v["general_slot_cpu_micros"],v["general_slot_memory_bytes"]) and
         general["build_and_native_qualification_serial"] and general["build_fixed_image_bytes"] >= 128 * MIB and
         general["build_outside_allowance_bytes"] >= 16 * MIB and
         v["original_guard_cpu_micros"] == 1_000_000 and v["original_guard_memory_bytes"] == GIB,
         "different independent build or guard funding")
    # Fixed HOME image pays all persistent metadata and child products. The outside
    # allowance covers the immutable source and its final ≤12 MiB operator image.
    charge = (128 + 16) * MIB
    required = max(native["complete_required_HOME_bytes"], v["native_home_required"])
    margin = min(native["available_HOME_bytes"] - required, v["remaining_home_bytes"]) - charge
    need(margin >= 0 and native["available_memory_bytes"] >=
         native["required_available_memory_bytes"] + ROOT_BOUND + CHILD_BOUND,
         "insufficient residual RAM or HOME")
    return dict(fleet=native["fleet"], verifier=scope, verifier_stage=phase["stage"],
                recorded_unix_seconds=native["recorded_unix_seconds"], scope="five source-QA commands only",
                aggregate_slice=SLICE, aggregate_cpu_quota_micros=slot[0], aggregate_memory_bytes=slot[1],
                supervisor_memory_bytes=ROOT_BOUND, child_memory_bytes=CHILD_BOUND,
                original_child_cpu_quota_micros=2_000_000, original_child_memory_swap_max=0,
                HOME_image_bytes=128*MIB, outside_HOME_bytes=16*MIB, HOME_margin_bytes=margin,
                focused_donor_cpu_micros=0, focused_donor_memory_bytes=0, donor_lock_required=False,
                restore_memory_shortfall=max(0,786_326_978_560-native["available_memory_bytes"]),
                consumer_phases_authorized=False, restore_authorized=False, dispatch_authorized=False)


def effective(root, *, actor=False):
    """Run inside the booked service before any ordinary test, rustc or clippy."""
    parent = SLICE_DIR
    expected = f"0::/horizonaudit.slice/{SLICE}/{root}"
    need(Path("/proc/self/cgroup").read_text().strip() == expected, "unexpected current unit")
    for target, cpu, memory in [(parent,1,GENERAL_SLOT[1]),(parent/root,2,CHILD_BOUND if actor else ROOT_BOUND)]:
        quota,period = map(int,(target/"cpu.max").read_text().split())
        need(quota == cpu * period and int((target/"memory.max").read_text()) == memory and
             (target/"memory.swap.max").read_text().strip() == "0", "wrong effective cgroup envelope")
    members = {p.parent.name for p in parent.glob("*.service/cgroup.procs") if p.read_text().strip()}
    supervisor = FAMILY + "-root.service"
    children = {FAMILY + "-" + label + ".service" for label in LABELS}
    need(supervisor in members and members <= children | {supervisor} and len(members & children) <= 1 and
         (parent/"cgroup.procs").read_text().strip() == "" and
         not any(p.is_dir() for unit in parent.glob("*.service") for p in unit.iterdir()),
         "unexpected descendants or concurrent compiler")


if __name__ == "__main__":
    import argparse
    import time
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("native", type=Path)
    p.add_argument("sha256")
    p.add_argument("verifier")
    args = p.parse_args()
    n = checked({"path":str(args.native),"sha256":args.sha256})
    fleet = checked(n["fleet"])
    _, phases = recipe()
    print(json.dumps(dict(inspect_price(n, fleet["retry9_auxiliary_commitments"], args.verifier, time.time()),
                          original_commands=phases), sort_keys=True))
