"""Identify the clean output projection, immutable inputs and the producer's actual tmpfs."""
import json
import os
from pathlib import Path
import runpy
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as c

START = "snapshot-73238440-GDXFwepRMYKGWDv947uUN9cfoMpunPFDLJHn4cgJx5A5.tar.zst"
MANIFEST = "epoch-hashes-169-focused.txt"
INDEX168 = c.PRIVATE / "epoch169-focused-diagnostic-20261117-v1/v158"
INDEX169 = c.PRIVATE / "epoch169-standard-lane-20261109-v1/output/compact-indexes/169"


def inspect(pid):
    proc = Path("/proc") / str(pid)
    root = proc / "root"
    mountlines = (proc / "mountinfo").read_text().splitlines()
    def projected(path):
        return root / path.relative_to("/")
    def check(source, dest, *, writable):
        matches = [line.split() for line in mountlines if line.split()[4] == str(dest)]
        c.need(len(matches) == 1, "missing or stacked projection " + str(dest))
        first = source.stat()
        actual = projected(dest).stat()
        flags = os.statvfs(projected(dest)).f_flag
        c.need(os.path.samestat(first, actual) and first.st_dev == c.HOME.stat().st_dev
               and bool(flags & os.ST_RDONLY) != writable
               and ("rw" if writable else "ro") in matches[0][5].split(","),
               "wrong device, inode or access " + str(dest))
        return dict(path=str(dest), mount_id=int(matches[0][0]), device=actual.st_dev,
                    inode=actual.st_ino, writable=writable)

    dest = c.OLD / "v158"
    run = c.OLD / "hourly-run"
    data = {name:check(c.RETRY / name,c.OLD / name,writable=True) for name in ("v158","hourly-run")}
    for key, source, target in (
        ("snapshot", c.OLD/"inputs"/START, c.OLD/"inputs"/START),
        ("checkpoints", c.RETRY/"v158"/MANIFEST, dest/MANIFEST),
        ("genesis", INDEX168/"genesis.tar.bz2", dest/"genesis.tar.bz2"),
        ("index168", INDEX168/"compact-indexes/168", dest/"compact-indexes/168"),
        ("index169", INDEX169, dest/"compact-indexes/169"),
    ):
        data[key] = check(source, target, writable=False)
    module = runpy.run_path(str(Path(__file__).with_name("scratch_mount.py")))
    data["scratch"] = module["native"](pid)
    checks = ("scratch", "compact-indexes/168", "compact-indexes/169")
    c.need(all(projected(dest/name).is_dir() for name in checks)
           and all(projected(run/name).is_dir() for name in ("tmp","private"))
           and data["snapshot"]["inode"] == 97463884, "different runtime projection")
    return data


def fixture():
    c.need((os.geteuid(),os.getegid()) == (1001,1003), "wrong fixture identity")
    group = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().removeprefix("0::/")
    limits = {v:(group/v).read_text().strip() for v in ("memory.max","memory.high","memory.swap.max","cpu.max")}
    c.need(limits == {"memory.max":str(c.RAM), "memory.high":str(52*c.G), "memory.swap.max":"0", "cpu.max":"200000 100000"},
           "different native producer limits")
    data = inspect(os.getpid())
    dest = c.OLD / "v158"
    run = c.OLD / "hourly-run"
    for p in (dest/"scratch", run/"tmp", run/"private"):
        s = p.stat()
        c.need((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)) == (1001,1003,0o700)
               and not any(p.iterdir()), "occupied retry directory")
    for path in ((dest/c.BASE_NAME), (dest/c.BASE_NAME).with_suffix(".jet.segment.json")):
        c.need(not os.path.lexists(path), "predecessor output visible in retry")
    # A write and immediate unlink in the projection proves only the new inode
    # can receive output. The held grant will recheck all mount identities.
    for location in (dest,run,dest/"scratch"):
        marker = location/(".fixture-" + str(os.getpid()))
        with marker.open("xb") as fd:
            fd.write(b"private epoch 169 retry\n")
        try:
            if location != dest/"scratch":
                c.need(marker.samefile(c.RETRY/location.name/marker.name), "probe wrote through to predecessor")
        finally:
            marker.unlink()
    return dict(schema="horizon-169-retry-native-namespace-v1", limits=limits, mounts=data,
                uid=os.geteuid(), gid=os.getegid(), useful_worker_launched=False)


if __name__ == "__main__":
    print(json.dumps(fixture(), sort_keys=True))
