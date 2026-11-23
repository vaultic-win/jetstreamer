"""Exercise the real successor's origin gate inside a read-only service namespace; stop at a controlled invalid eligibility digest."""

from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, os, subprocess, time, sys

if os.geteuid() != 0 or not sys.flags.isolated or not __debug__:
    raise SystemExit("root python3 -IB required")
work = Path("/home/sol/.jetstreamer-private/epoch166-retry10-consumer-review-20261123")
build = work / "build"
hold = Path(
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry10-holding-20261122-v1"
)
orig = hold / "retirement-tools/jetstreamer-r2"
orig_alias = (
    Path("/home/sol/.jetstreamer-private/horizon-root-runtime-data")
    / hold.name
    / "retirement-tools/jetstreamer-r2"
)
dest = hold / "retirement-tools-park-v5"
elf = dest / "jetstreamer-r2"


def ref(p):
    with p.open("rb") as f:
        d = hashlib.file_digest(f, "sha256").hexdigest()
    return {"path": str(p), "sha256": d}


def save(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    if path.exists():
        assert path.read_bytes() == data
    else:
        with path.open("xb") as f:
            os.fchmod(f.fileno(), 0o400)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        fd = os.open(path.parent, os.O_DIRECTORY)
        os.fsync(fd)
        os.close(fd)
    return ref(path)


def run(*args):
    return subprocess.check_output(args, text=True)


expected = "57b05bbcfa72fd4d6a6be68673c219299daeade65359236085e7a06be9b2515c"
orig_id = (orig.stat().st_dev, orig.stat().st_ino)
orig_seal = ref(orig.with_name("deployment-seal-receipt.json"))
assert (
    orig_seal["sha256"]
    == "ac04d6adffe8326365a45adde19ac0638c608583e28c8665b515efb4280b8ea7"
)
assert (
    orig.samefile(orig_alias)
    and ref(orig_alias)["sha256"] == ref(orig)["sha256"] == expected
)
qual = ref(Path(sys.argv[1]))
assert (
    qual["sha256"] == sys.argv[2]
    and Path(qual["path"]).stat().st_uid == 0
    and Path(qual["path"]).stat().st_mode & 0o222 == 0
)
q = json.loads(Path(qual["path"]).read_bytes())
actual = ref(Path(q["image"]["path"]))
assert actual == q["image"]
git = ["runuser", "-u", "sol", "--", "git", "-C", "/home/sol/workspace/jetstreamer"]
for before, after in [
    ("e0214452e559a67632512a1d539a9b6fd8b00290", q["published_source_commit"]),
    (q["published_source_commit"], "origin/account-updates"),
]:
    subprocess.run(git + ["merge-base", "--is-ancestor", before, after], check=True)
park_case = q["actual_park_test"]
assert ref(Path(park_case["path"])) == park_case
park_result = Path(park_case["path"]).read_text()
assert (
    "test holding::epoch166_retry10_retire::independent_tests::genuine_park_dispatch_after_reload ... ok"
    in park_result
    and "1 passed; 0 failed" in park_result
)
failure = ref(work / "PARK_DISPATCH_FAILURE_9dcefb54_20261123.json")
assert (
    failure["sha256"]
    == "3be28439aca0a20fa90ec895661fc5542f6e33b47b299e9383f3428c6c5256d5"
)
case = q["actual_manager_test"]
assert ref(Path(case["path"])) == case
assert (
    "test holding::epoch166_retry10_retire::consumers::reviewed_managers::tests::actual_retired_managers_and_activation_namespace ... ok"
    in Path(case["path"]).read_text()
)
assert (
    len(q["test_groups"]) == 5
    and sum(x["passed"] for x in q["test_groups"].values()) >= 135
)
for result in q["test_groups"].values():
    assert ref(Path(result["log"]["path"])) == result["log"]
assert (
    q["referenced_recorded_consumer_graph_sha256"]
    == "07ae6660326e9b2331f7c4119fbbddc007b4b1b0d174bd681bafb877b6642210"
)
probe = work / "manager-only-1795406682279710514/PASSED.json"
assert (
    ref(probe)["sha256"]
    == "5e849d9e557090a43e776885c3f64f71ad1e0da0ea4661897934faeb404599f0"
)
sealer = Path(
    "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment"
)
seal_h = ref(sealer)["sha256"]
assert seal_h == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
plan = save(
    work / "PARK_DISPATCH_OPTIMIZED_SEAL_PLAN.json",
    {
        "schema": "jetstreamer-sealed-deployment-plan-v1",
        "destination": str(dest),
        "members": [
            {
                "name": "jetstreamer-r2",
                "source": actual["path"],
                "sha256": actual["sha256"],
                "mode": 0o555,
            }
        ],
    },
)
if not dest.exists():
    subprocess.run(
        [
            sealer,
            plan["path"],
            "--plan-sha256",
            plan["sha256"],
            "--self-sha256",
            seal_h,
        ],
        check=True,
    )
seal = ref(dest / "deployment-seal-receipt.json")
assert (
    json.loads(Path(seal["path"]).read_bytes())["plan_sha256"] == plan["sha256"]
    and ref(elf)["sha256"] == actual["sha256"]
    and elf.stat().st_mode & 0o777 == 0o555
)
control = build / "invalid-eligibility-for-origin-probe.json"
save(control, {"schema": "negative-fixture-eligibility-only"})
elig = hold / "package/eligibility.json"
origin_plan = hold / "package/plan.json"
ph = ref(origin_plan)["sha256"]
assert ph == "cee159c094d1d77778a24d7b563a6a6bdd295786652ff73745258bb086f33b04"
real_elig = ref(elig)
assert (
    real_elig["sha256"]
    == "8a562db940f376847374d006e1d9fe5b2f5c4b802b4c318953636d45388788bd"
)
# The CLI opens its transition lock before dispatch. Isolate its full state for this probe.
fake = build / "origin-probe-state"
fake.mkdir(mode=0o700, exist_ok=True)
(fake / "receipts").mkdir(mode=0o700, exist_ok=True)
lock = fake / "transition.lock"
if not lock.exists():
    with lock.open("xb") as f:
        os.fchmod(f.fileno(), 0o600)
realstate = Path("/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1")
assert (
    fake.stat().st_uid == 0
    and fake.stat().st_mode & 0o777 == 0o700
    and lock.stat().st_ino != (realstate / "transition.lock").stat().st_ino
    and not list((fake / "receipts").iterdir())
)
archive = json.loads(origin_plan.read_bytes())["source"]
base = [
    "systemd-run",
    "--wait",
    "--pipe",
    "--collect",
    "--service-type=exec",
    "-p",
    "CPUQuota=100%",
    "-p",
    "MemoryMax=256M",
    "-p",
    "MemorySwapMax=0",
    "-p",
    "TasksMax=128",
    "-p",
    "PrivateNetwork=yes",
    "-p",
    "ProtectSystem=strict",
    "-p",
    "ProtectHome=read-only",
    "-p",
    "NoNewPrivileges=true",
    "-p",
    "UMask=0077",
    "-p",
    "RuntimeMaxSec=60",
    "-p",
    f"BindReadOnlyPaths={control}:{elig}",
    "-p",
    f"BindPaths={fake}:{realstate}",
    "-p",
    f"ReadWritePaths={realstate}",
    "-p",
    "InaccessiblePaths=" + archive,
]
results = []
for mode, cmd_path, why in [
    (
        "separate",
        elf,
        "epoch 166 consumer census requires the exact existing park plan and sealed lifecycle tool",
    ),
    ("bound", orig, "holding evidence digest differs: path=" + str(elig)),
]:
    uid = "horizon-166-manager-origin-" + mode + "-" + str(time.time_ns())
    commands = base + ["--unit=" + uid]
    if mode == "bound":
        commands += ["-p", f"BindReadOnlyPaths={elf}:{orig}"]
        verify_alias = """
import hashlib, os, pathlib, stat, sys
historical, deployed = map(pathlib.Path, sys.argv[1:3])
orig_dev, orig_ino, bound_dev, bound_ino = map(int, sys.argv[3:7])
for path, dev, ino, digest in [(historical, orig_dev, orig_ino, sys.argv[7]), (deployed, bound_dev, bound_ino, sys.argv[8])]:
    with path.open("rb") as handle:
        st = os.fstat(handle.fileno())
        assert path.resolve(strict=True) == path and (st.st_dev, st.st_ino) == (dev, ino)
        assert st.st_uid == 0 and st.st_nlink == 1 and stat.S_ISREG(st.st_mode) and not st.st_mode & 0o222
        assert hashlib.file_digest(handle, "sha256").hexdigest() == digest
assert not historical.samefile(deployed)
print("ORIGINAL_AND_BOUND_CANDIDATE_VERIFIED", flush=True)
os.execv(sys.argv[9], sys.argv[9:])
"""
        commands += [
            "/usr/bin/python3",
            "-IB",
            "-c",
            verify_alias,
            str(orig_alias),
            str(orig),
            *map(str, orig_id),
            str(elf.stat().st_dev),
            str(elf.stat().st_ino),
            expected,
            actual["sha256"],
        ]
    commands += [
        str(cmd_path),
        "holding-census166-retry10-consumers",
        str(origin_plan),
        "--spec-sha256",
        ph,
        "--self-sha256",
        actual["sha256"],
    ]
    result = subprocess.run(commands, capture_output=True, text=True, timeout=75)
    log = result.stdout + result.stderr
    save(
        work / ("ORIGIN_PROBE_" + uid + ".json"),
        {"mode": mode, "cmd": commands, "returncode": result.returncode, "log": log},
    )
    assert result.returncode and why in log, (mode, log[-1600:])
    if mode == "bound":
        assert (
            "ORIGINAL_AND_BOUND_CANDIDATE_VERIFIED" in result.stdout
            and orig.samefile(orig_alias)
        )
    assert (
        ref(elig) == real_elig
        and ref(orig)["sha256"] == expected
        and (orig.stat().st_dev, orig.stat().st_ino) == orig_id
    )
    results.append(
        {
            "mode": mode,
            "unit": uid,
            "argv": commands,
            "rc": result.returncode,
            "evidence": log,
        }
    )
doc = save(
    work / "QUALIFIED_PARK_DISPATCH_SUCCESSOR_MOUNT.json",
    {
        "time": datetime.now(timezone.utc).isoformat(),
        "native_qualification": qual,
        "park_dispatch_failure": failure,
        "park_dispatch_test": park_case,
        "candidate": ref(elf),
        "seal": seal,
        "sealer": ref(sealer),
        "original": ref(orig),
        "original_inode": orig_id,
        "original_alias": ref(orig_alias),
        "original_seal": orig_seal,
        "plan": ref(origin_plan),
        "original_eligibility": real_elig,
        "cases": results,
        "production_bind_property": f"BindReadOnlyPaths={elf}:{orig}",
        "production_argv": [
            str(orig),
            "holding-census166-retry10-consumers",
            str(origin_plan),
            "--spec-sha256",
            ph,
            "--self-sha256",
            actual["sha256"],
        ],
        "qualification_only": True,
        "census_started": False,
        "retirement_authorized": False,
        "remote_operation": False,
    },
)
print(doc)
