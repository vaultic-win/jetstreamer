#!/usr/bin/python3 -IB
"""Sole booked epoch 159 diagnostic. The campaign owner supplies the physical grant."""

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess as sp
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import feature19
import feature156

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch159-bounded-reference-20261123-v1"
PACKAGE = ROOT / "package-v1"
ATTEMPT = ROOT / "attempt-v1"
UNIT = "horizon-epoch159-bounded-vote-trace-20261123-v1.service"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
HOME = Path("/home/sol")
PRIVATE = HOME / ".jetstreamer-private"
DEP = PRIVATE / "epoch157-terminal-reference-sealed-20261122-v1/package"
WORKER = Path(
    "/usr/local/lib/jetstreamer/deploy-epochs150-173-20261004-v4-epoch157-qualified/jetstreamer-historical-worker-v1-5-6"
)
SEAL = "deployment-seal-receipt.json"
UID = 1001
GID = 1001
MIB = 1 << 20
GIB = 1 << 30
IMAGES = {"scratch": (24 * GIB, 524288), "evidence": (8 * MIB, 256)}
CAP = 8 * MIB
LIMITS = {
    "cpu_cores": 2,
    "memory_bytes": 48 * GIB,
    "swap_bytes": 0,
    "scratch_bytes": 24 * GIB,
    "other_home_bytes": 32 * MIB,
}
PYTHON = "/usr/bin/python3"
DONORS = (
    "horizon-qualify-169-focused-hourly-20261123-v1.service",
    "horizon-qualify-169-focused-20261120-g4.service",
)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def now():
    return dt.datetime.now(dt.timezone.utc)


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def record(path, obj):
    with path.open("x") as f:
        os.fchmod(f.fileno(), 0o400)
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def root_file(path, digest, *, immutable=True):
    md = path.lstat()
    need(
        path.resolve(strict=True) == path
        and stat.S_ISREG(md.st_mode)
        and md.st_uid == 0
        and md.st_nlink == 1
        and md.st_mode & (0o222 if immutable else 0o022) == 0
        and sha(path) == digest,
        "different root evidence: " + str(path),
    )
    return json.loads(path.read_bytes())


def verify_package():
    check = json.loads((PACKAGE / SEAL).read_bytes())
    need(
        Path(check["destination"]) == PACKAGE
        and check["schema"] == "jetstreamer-sealed-deployment-receipt-v1",
        "wrong service deployment",
    )
    for entry in check["members"]:
        p = PACKAGE / entry["name"]
        st = p.lstat()
        need(
            p.parent == PACKAGE
            and stat.S_ISREG(st.st_mode)
            and st.st_uid == 0
            and st.st_nlink == 1
            and st.st_mode & 0o222 == 0
            and sha(p) == entry["sha256"],
            "changed service file",
        )
    return sha(PACKAGE / SEAL)


def check_feature_donor():
    if UNIT not in (feature19.UNIT, feature156.UNIT):
        return
    # The deployed V5m provider validates the free donor lock before and after its native price.
    # Check before opening that lock, including the short dispatch-intent interval.
    raw = sp.check_output(
        [
            "systemctl",
            "show",
            "-p",
            "ActiveState,MainPID,ControlPID,Job,ExecStart,InvocationID",
            feature19.VERIFIER,
        ],
        text=True,
    )
    state = dict(line.split("=", 1) for line in raw.splitlines())
    uses_current_provider = (
        state["InvocationID"] == "dba04d40f1b046b4875d7e27e0ff224a"
        or "/tools-v5m/export145 " in state["ExecStart"]
    )
    drained = (
        state["ActiveState"] in ("inactive", "failed")
        and not state["Job"]
        and state["MainPID"] == state["ControlPID"] == "0"
    )
    if UNIT == feature156.UNIT:
        uses_current_provider = True
    need(not uses_current_provider or drained, "the epoch 145 verifier still requires a free donor lock")


def grant(digest):
    g = root_file(ROOT / "ADMISSION.json", digest)
    need(
        g["schema"] == "horizon-epoch159-bounded-grant-v1"
        and g["actual_grant"] is True
        and g["unit"] == UNIT
        and g["limits"] == LIMITS
        and g["package_sha256"] == verify_package(),
        "foreign or unpaid grant",
    )
    need(
        dt.timedelta(0)
        <= now() - dt.datetime.fromisoformat(g["priced_at_utc"])
        <= dt.timedelta(minutes=30),
        "expired physical price",
    )
    need(
        Path(g["fleet"]["path"]).parent.parent == RT
        and Path(g["fleet"]["path"]).name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json",
        "wrong fleet scope",
    )
    for key in ("fleet", "price"):
        ref = g[key]
        root_file(Path(ref["path"]), ref["sha256"], immutable=False)
    need(
        g["donor_lock"] == {"path": str(LOCK), "dev": LOCK.stat().st_dev, "ino": LOCK.stat().st_ino}
        and g["donor_idle_units"]
        and all(
            isinstance(u, str) and re.fullmatch(r"[A-Za-z0-9._@-]+\.service", u)
            for u in g["donor_idle_units"]
        )
        and DONORS[0] in g["donor_idle_units"]
        and any("136" in u for u in g["donor_idle_units"]),
        "missing checked donor units",
    )
    if UNIT in (feature19.UNIT, feature156.UNIT):
        profile = feature19 if UNIT == feature19.UNIT else feature156
        check_feature_donor()
        settled = root_file(profile.SETTLEMENT, profile.SETTLEMENT_SHA)
        need(settled["iid"] == profile.PREVIOUS_INVOCATION, "previous trace has not settled")
        enrolled = root_file(profile.DONOR_UNITS, profile.DONOR_UNITS_SHA)
        need(
            set(enrolled["donor_idle_units"]).issubset(g["donor_idle_units"]),
            "feature differential omitted an existing donor unit",
        )
    return g


@contextlib.contextmanager
def borrow(g):
    check_feature_donor()
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_feature_donor()
        st = os.fstat(fd)
        need(
            st.st_nlink == 1
            and st.st_uid == 0
            and stat.S_IMODE(st.st_mode) == 0o600
            and (st.st_dev, st.st_ino) == (g["donor_lock"]["dev"], g["donor_lock"]["ino"]),
            "foreign donor lock",
        )
        for unit in g["donor_idle_units"]:
            raw = sp.check_output(
                ["systemctl", "show", "-p", "ActiveState,Job,MainPID,ControlPID", unit],
                text=True,
            )
            v = dict(line.split("=", 1) for line in raw.splitlines())
            need(
                v["ActiveState"] in ("inactive", "failed")
                and v["MainPID"] == v["ControlPID"] == "0"
                and not v["Job"],
                "busy donor: " + unit,
            )
        for name in ("START_INTENT.json",):
            need(
                not (RT / "epoch169-hourly-admission-20261123-v1" / name).exists(),
                "169 has an outstanding intent",
            )
        yield
    finally:
        os.close(fd)


def node_argv(check_inputs=False):
    cfg = json.loads((PACKAGE / "inputs.json").read_bytes())
    # bwrap's implicit parent directories are mode 0700. Create only sandbox
    # directory entries, leaving the real host's private ancestors untouched.
    parents = {Path("/opt"), Path("/run"), Path("/run/systemd")}
    for item in [DEP / "cbor2", *(Path(cfg[k]["path"]) for k in ("bootstrap", "genesis"))]:
        parents.update(p for p in item.parents if p != Path("/"))
    dirs = [
        arg
        for p in sorted(parents, key=lambda p: (len(p.parts), str(p)))
        for arg in ("--perms", "0755", "--dir", str(p))
    ]
    cmd = [
        "/usr/bin/bwrap",
        "--die-with-parent",
        "--unshare-ipc",
        "--unshare-uts",
        "--clearenv",
        *dirs,
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C",
        "--setenv",
        "HOME",
        "/work",
        "--setenv",
        "TMPDIR",
        "/work",
        "--setenv",
        "INVOCATION_ID",
        os.environ.get("INVOCATION_ID", "preflight"),
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--symlink",
        "usr/bin",
        "/bin",
        "--ro-bind",
        "/etc",
        "/etc",
        "--ro-bind",
        "/run/systemd/resolve",
        "/run/systemd/resolve",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--ro-bind",
        "/sys",
        "/sys",
        "--ro-bind",
        str(PACKAGE),
        "/opt/epoch159",
    ]
    for key in ("bootstrap", "genesis"):
        p = cfg[key]["path"]
        cmd += ["--ro-bind", p, p]
    # The sealed Python CBOR module and extension remain independently pinned.
    cmd += ["--ro-bind", str(DEP / "cbor2"), str(DEP / "cbor2")]
    so = DEP / "_cbor2.cpython-312-x86_64-linux-gnu.so"
    cmd += ["--ro-bind", str(so), str(so)]
    if not check_inputs:
        cmd += [
            "--bind",
            str(ATTEMPT / "scratch"),
            "/work",
            "--bind",
            str(ATTEMPT / "evidence"),
            "/evidence",
            "--chdir",
            "/work",
        ]
    cmd += [
        "--remount-ro",
        "/",
        "--",
        "/usr/bin/setpriv",
        "--reuid=1001",
        "--regid=1001",
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--",
        PYTHON,
        "-IB",
        "/opt/epoch159/trace.py",
    ]
    cmd.extend(profile_args())
    return cmd + (["check-mounted-inputs"] if check_inputs else ["replay", "/work", "/evidence"])


def profile_args():
    if UNIT == feature19.UNIT:
        return ["--feature19"]
    if UNIT == feature156.UNIT:
        return ["--feature156"]
    return []


def system_argv(digest):
    props = [
        "Type=exec",
        "MemoryMax=51539607552",
        "MemorySwapMax=0",
        "CPUQuota=200%",
        "TasksMax=256",
        "RuntimeMaxSec=7800",
        "TimeoutStopSec=30",
        "KillMode=control-group",
        "ExitType=cgroup",
        "PrivateMounts=yes",
        "LimitCORE=0",
        "UMask=0077",
        "StandardOutput=null",
        "StandardError=null",
        "Restart=no",
        "ProtectSystem=strict",
        f"ReadWritePaths={ROOT} {LOCK}",
    ]
    return [
        "systemd-run",
        f"--unit={UNIT}",
        *["--property=" + v for v in props],
        "--",
        PYTHON,
        "-IB",
        str(PACKAGE / "service.py"),
        *profile_args(),
        "run",
        digest,
    ]


def allocate(name):
    size, inodes = IMAGES[name]
    path = ATTEMPT / (name + ".ext4")
    mnt = ATTEMPT / name
    mnt.mkdir(mode=0o700)
    with path.open("xb") as f:
        os.fchmod(f.fileno(), 0o600)
        os.posix_fallocate(f.fileno(), 0, size)
        os.fsync(f.fileno())
        need(os.fstat(f.fileno()).st_blocks * 512 >= size, "unfunded image")
    st = path.stat()
    record(
        ATTEMPT / (name + "-identity.json"),
        {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size},
    )
    mkfs = [
        "/usr/sbin/mkfs.ext4",
        "-q",
        "-F",
        "-b",
        "4096",
        "-m",
        "0",
        "-N",
        str(inodes),
        "-E",
        "nodiscard,lazy_itable_init=0,lazy_journal_init=0",
        str(path),
    ]
    sp.run(mkfs, check=True)
    need(path.stat().st_blocks * 512 >= size, "mkfs discarded its funded space")
    sp.run(["mount", "-o", "loop,nodiscard,nodev,nosuid,noexec", path, mnt], check=True)
    os.chown(mnt, UID, GID)
    os.chmod(mnt, 0o700)
    return mnt


def limited_log(proc, path):
    total = 0
    with path.open("xb") as f:
        while chunk := proc.stdout.read(65536):
            if total < CAP:
                f.write(chunk[: CAP - total])
            total += len(chunk)
        f.flush()
        os.fsync(f.fileno())
    return total


def copy_receipts():
    total = blocks = 0
    out = ATTEMPT / "retained"
    out.mkdir(mode=0o700)
    results = {}
    for p in sorted((ATTEMPT / "evidence").iterdir()):
        if p.name == "lost+found":
            continue
        st = p.lstat()
        need(
            re.fullmatch(r"[a-z0-9-]+\.json", p.name) and stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
            "unexpected trace evidence",
        )
        total += st.st_size
        blocks += (st.st_size + 4095) // 4096 * 4096
        need(total <= CAP and blocks <= CAP and len(results) < 128, "receipt cap")
        data = p.read_bytes()
        json.loads(data)
        dest = out / p.name
        with dest.open("xb") as f:
            os.fchmod(f.fileno(), 0o400)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        results[p.name] = sha(dest)
    fd = os.open(out, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return results


def run(digest):
    g = grant(digest)
    intent = json.loads((ROOT / "DISPATCH_INTENT.json").read_bytes())
    need(
        intent["grant"] == digest and intent["unit"] == UNIT,
        "grant has no matching sole dispatch intent",
    )
    iid = os.environ["INVOCATION_ID"]
    need(
        re.fullmatch(r"[a-f0-9]{32}", iid)
        and Path("/proc/self/cgroup").read_text().strip() == "0::/system.slice/" + UNIT
        and ROOT.stat().st_dev == HOME.stat().st_dev,
        "foreign execution scope",
    )
    cg = Path("/sys/fs/cgroup/system.slice") / UNIT
    quota, period = map(int, (cg / "cpu.max").read_text().split())
    need(
        quota == 2 * period
        and int((cg / "memory.max").read_text()) == LIMITS["memory_bytes"]
        and (cg / "memory.swap.max").read_text().strip() == "0",
        "incorrect effective limits",
    )
    with borrow(g):
        ATTEMPT.mkdir(mode=0o700)
        record(
            ATTEMPT / "start.json",
            {"iid": iid, "grant": digest, "utc": now().isoformat(), "unit": UNIT},
        )
        try:
            for name in IMAGES:
                allocate(name)
            with sp.Popen(node_argv(), stdout=sp.PIPE, stderr=sp.STDOUT) as p:
                logged = limited_log(p, ATTEMPT / "driver.log")
                code = p.wait()
            rows = copy_receipts()
            record(
                ATTEMPT / "driver-exit.json",
                {
                    "iid": iid,
                    "code": code,
                    "log_bytes_seen": logged,
                    "retained": rows,
                    "utc": now().isoformat(),
                },
            )
        finally:
            for name in reversed(IMAGES):
                target = ATTEMPT / name
                if target.is_mount():
                    sp.run(["umount", target], check=True)
        # Both images survive terminal failure or supervisor interruption for ROOT to reconcile.
        need(code == 0, "native diagnostic did not pass; retained files in attempt-v1")
        need("outcome.json" in rows and "hello.json" in rows, "no complete trace")
        record(
            ATTEMPT / "success.json",
            {"iid": iid, "utc": now().isoformat(), "outcome": rows["outcome.json"]},
        )


def retire_scratch():
    start = json.loads((ATTEMPT / "start.json").read_bytes())
    terminal = json.loads((ATTEMPT / "driver-exit.json").read_bytes())
    need(
        start["iid"] == terminal["iid"]
        and terminal["retained"].get("outcome.json") == sha(ATTEMPT / "retained/outcome.json"),
        "unreconciled run: retain scratch",
    )
    v = dict(
        line.split("=", 1)
        for line in sp.check_output(
            [
                "systemctl",
                "show",
                "-p",
                "ActiveState,InvocationID,MainPID,ControlPID,Job",
                UNIT,
            ],
            text=True,
        ).splitlines()
    )
    need(
        v["ActiveState"] in ("failed", "inactive")
        and v["InvocationID"] in ("", start["iid"])
        and v["MainPID"] == v["ControlPID"] == "0"
        and not v["Job"],
        "service active",
    )
    members = Path("/sys/fs/cgroup/system.slice") / UNIT / "cgroup.procs"
    need(not members.exists() or not members.read_text().strip(), "undrained cgroup")
    p = ATTEMPT / "scratch.ext4"
    key = json.loads((ATTEMPT / "scratch-identity.json").read_bytes())
    st = p.lstat()
    need(
        (st.st_dev, st.st_ino, st.st_size) == (key["dev"], key["ino"], IMAGES["scratch"][0])
        and st.st_nlink == 1
        and not sp.check_output(["losetup", "-j", p]).strip(),
        "foreign or attached image",
    )
    p.unlink()
    record(
        ATTEMPT / "scratch-retired.json",
        {
            "iid": start["iid"],
            "dev": st.st_dev,
            "ino": st.st_ino,
            "utc": now().isoformat(),
        },
    )


def main():
    global ROOT, PACKAGE, ATTEMPT, UNIT
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--feature19", action="store_true")
    mode.add_argument("--feature156", action="store_true")
    p.add_argument(
        "action",
        choices=["recipe", "check-mounted-inputs", "dispatch", "run", "retire-scratch"],
    )
    p.add_argument("sha", nargs="?")
    a = p.parse_args()
    if a.feature19 or a.feature156:
        profile = feature19 if a.feature19 else feature156
        ROOT = RT / profile.RUNTIME
        PACKAGE = ROOT / "package-v1"
        ATTEMPT = ROOT / "attempt-v1"
        UNIT = profile.UNIT
    need(
        os.geteuid() == 0 and sys.flags.isolated and __debug__,
        "isolated root operator required",
    )
    if a.action == "recipe":
        print(
            json.dumps(
                {
                    "service": system_argv("<ADMISSION_SHA256>"),
                    "sandbox": node_argv(),
                    "limits": LIMITS,
                    "lock": str(LOCK),
                },
                indent=2,
            )
        )
    elif a.action == "check-mounted-inputs":
        verify_package()
        sp.run(node_argv(check_inputs=True), check=True)
    elif a.action == "retire-scratch":
        retire_scratch()
    else:
        need(a.sha and re.fullmatch("[a-f0-9]{64}", a.sha), "expected admission digest")
        if a.action == "run":
            try:
                run(a.sha)
            except BaseException as exc:
                target = ATTEMPT if ATTEMPT.is_dir() else ROOT
                record(
                    target / "service-failure.json",
                    {
                        "utc": now().isoformat(),
                        "error": str(exc)[:2048],
                        "iid": os.environ.get("INVOCATION_ID"),
                        "grant": a.sha,
                    },
                )
                raise
        else:
            g = grant(a.sha)
            with borrow(g):
                need(not ATTEMPT.exists(), "an existing invocation owns the attempt")
                record(
                    ROOT / "DISPATCH_INTENT.json",
                    {"grant": a.sha, "utc": now().isoformat(), "unit": UNIT},
                )
            sp.run(system_argv(a.sha), check=True)


if __name__ == "__main__":
    main()
