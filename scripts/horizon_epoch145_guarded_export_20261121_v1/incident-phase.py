"""Observe the dedicated frozen-145 verifier from the funded incident census."""
import hashlib
import os
from pathlib import Path
import stat
import sys

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
UNIT = "horizon-holding-export145-20261121-v1.service"
VERSION = Path(__file__).resolve().parent.name
FIXTURE_REJOIN = VERSION == "tools-v5f"
TIMER_REJOIN = VERSION in ("tools-v5e", "tools-v5f")
FOCUSED_REJOIN = VERSION in ("tools-v5d", "tools-v5e", "tools-v5f")
TIMEOUT_REJOIN = VERSION in ("tools-v5c", "tools-v5d", "tools-v5e", "tools-v5f")
REJOIN = VERSION in ("tools-v5b", "tools-v5c", "tools-v5d", "tools-v5e", "tools-v5f")
PKG = BASE / "epoch145-semantic-continuity-20261121-v1" / (VERSION if REJOIN else "tools-v5")
IMAGE = PKG / "export145"
STATE = BASE / "epoch145-guarded-export-20261121-v1/state"
OLD = "add576f115cc4d3b897f47d024af72fd"
OLD_FAILURE = "33e011228a58df3c2a82ca49013a7d524eeca1e849fc59993effe5d2faf18e74"
OLD_RECOVERY = "9cdcfdb688ee018b9cddd43c9c5ba129712195e11d6c8172104a7f4a9a160a28"
if REJOIN:
    OLD = "5e0e20bc974149f096ea4bab10b15e1b"
    OLD_FAILURE = "00de799e968fa8c6e31a76284f0610bcc84bbe617193361ef457629b7294d38f"
    OLD_RECOVERY = "03cf2deacc6d38f5107bb894c59ced4ba2381aac425a1e3d9c401260053ca04f"
if TIMEOUT_REJOIN:
    OLD = "dc043eb78c4a4349b0098760dc764a1f"
    OLD_FAILURE = "baa00ca8b52aca80b105bf5582f955af8a3f9e22ce662908ce7a75afccfb1943"
    OLD_RECOVERY = "e992566275e63b28a020c847c02637626b245161a2e39f843ac1da4d64793b2f"
if FOCUSED_REJOIN:
    OLD = "d37f36f898a44932a19fd50d7014a6fe"
    OLD_FAILURE = "6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29"
    OLD_RECOVERY = "a3d623b47ea9612824d102714703b0d095db18e07bf8ce3570ec08331ad84e81"
if TIMER_REJOIN:
    OLD = "e6551a0bb8a14b989902e15c9ecc0751"
    OLD_FAILURE = "9ef9c938290ea2b43d3b2ce4aa617f08b33f4c893961e63f53ba3f48768e215f"
    OLD_RECOVERY = "55d2a0504271e8a1eea2ca8c105a288be9497f1a2b80177279481692d06e041f"
if FIXTURE_REJOIN:
    OLD = "a99ed8b51e8a482b805b8a36a11b2700"
    OLD_FAILURE = "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"
    OLD_RECOVERY = "6e06652ea695717b18fc29b955e463da8dc2dde16f8173da552df707c478e624"
HOME = Path("/home/sol/.jetstreamer-private")
OUTPUT = HOME / "epoch145-prefix-extract-funded-20261121-v1/.tmp36MvkN"
SOURCE = HOME / "epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet"
MANIFEST = SOURCE.with_suffix(".jet.segment.json")
LOCK = HOME / "r2-holding-state-dev-samjohnson-v1/transition.lock"


def argv(pid):
    return [os.fsdecode(x) for x in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if x]


def own_probe(s, parent, members, epoch, provider):
    # The check itself runs synchronously as the controller's direct child. A
    # different process checking the peer cannot claim this exception.
    me = os.getpid()
    if me not in members:
        return members
    actual = argv(me)
    s.need(epoch == 145 and os.getppid() == parent and __debug__ and sys.flags.isolated
           and len(actual) == 6 and actual[2:4] == [str(provider), "145"]
           and Path(actual[0]).resolve() == Path("/usr/bin/python3").resolve()
           and s.same_file(Path(f"/proc/{me}/exe"), Path("/usr/bin/python3"))
           and s.process(me)[2] == "0::/system.slice/" + UNIT, "foreign 145 admission probe")
    return tuple(p for p in members if p != me)


def inspect(s, leased, m, members, epoch, provider, profile):
    """Return None for another image. Caller supplies its hash-pinned sealed profile."""
    pid = int(m["MainPID"])
    if pid < 2 or not IMAGE.exists() or not s.same_file(Path(f"/proc/{pid}/exe"), IMAGE):
        return None
    group = "0::/system.slice/" + UNIT
    generation = m["InvocationID"]
    s.need(s.iid(generation) and generation != OLD and m["Id"] == UNIT
           and m["ControlGroup"] == group[3:] and m["ActiveState"] == "active"
           and m["SubState"] == "running" and not m["Job"] and m["NRestarts"] == "0"
           and m["ControlPID"] == "0" and m["CPUQuotaPerSecUSec"] == "1s"
           and m["MemoryMax"] == str(2 << 30) and m["MemorySwapMax"] == "0", "foreign incident 145 controller")
    seal, seal_ref = s.read(PKG / "deployment-seal-receipt.json", profile["seal_sha256"])
    build, build_ref = s.read(PKG / "build-proof.json", profile["build_sha256"])
    image_sha = profile["image_sha256"]
    rows = {r["name"]: r["sha256"] for r in seal["members"]}
    s.need(seal["destination"] == str(PKG) and rows["export145"] == image_sha
           and rows["build-proof.json"] == build_ref["sha256"] and build["verifier_sha256"] == image_sha,
           "foreign sealed 145 image")
    with IMAGE.open("rb") as stream:
        s.need(hashlib.file_digest(stream, "sha256").hexdigest() == image_sha, "145 image bytes changed")
    f, failed = s.read(STATE / OLD / "failed.json", OLD_FAILURE)
    _, previous = s.read(STATE / OLD / "recovery-started.json", OLD_RECOVERY)
    expected_failure = f["error"] == "stopped worker fresh-census deadline" if REJOIN else "exit status: 124" in f["error"]
    if TIMEOUT_REJOIN:
        expected_failure = f["error"].rstrip().endswith("'horizon-qualify-168-full-metered-20261121-v1.service']' timed out after 10 seconds")
    if FOCUSED_REJOIN:
        expected_failure = f["error"].rstrip().endswith("ValueError: cadence publisher absent")
    if TIMER_REJOIN:
        expected_failure = f["error"].rstrip().endswith("tools-v14/retire-original-timers.py'), 'inspect']' timed out after 20 seconds")
    if FIXTURE_REJOIN:
        expected_failure = f["error"].rstrip().endswith("ValueError: unregistered replay process 227497")
    s.need(f["iid"] == OLD and expected_failure, "foreign original failure")
    state = STATE / generation
    parent = Path(f"/proc/{pid}")
    registered = argv(pid)
    s.need(len(registered) == 5 and registered[:2] == [str(IMAGE), "recover-full-output"]
           and registered[-1] == image_sha and Path(registered[2]).name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
           and Path(registered[2]).parent.parent == BASE and s.process(pid)[2] == group
           and ("INVOCATION_ID=" + generation).encode() in (parent / "environ").read_bytes().split(b"\0"),
           "foreign recovery command")
    s.read(Path(registered[2]), registered[3])
    ticks = s.process(pid)[1]
    fixed = (64512, 95818311)
    lm = LOCK.stat()
    s.need((lm.st_dev, lm.st_ino) == fixed and any(
        os.path.samestat(fd.stat(), lm) and any(" FLOCK " in line and " WRITE " in line
        for line in (parent / "fdinfo" / fd.name).read_text().splitlines())
        for fd in (parent / "fd").iterdir()), "145 serial owner changed")
    observed = own_probe(s, pid, members, epoch, provider)
    window = {"mode": "recover-full-output", "native_parent": {"pid": pid, "start_ticks": ticks},
              "continuity_seal": seal_ref, "continuity_build": build_ref,
              "failed_predecessor": failed, "prior_started": previous}
    if observed == (pid,):
        s.need(epoch == 145 and os.getpid() in members, "145 participant has no leased child")
        return {"invocation_id": generation, "stage": "controller", "window": window}
    s.need(len(observed) == 2 and pid in observed, "foreign 145 descendants")
    child = next(p for p in observed if p != pid)
    pp, ct, pg = s.process(child)
    cp = Path(f"/proc/{child}")
    s.need((pp, pg) == (pid, group) and s.same_file(cp / "exe", IMAGE)
           and argv(child) == [str(IMAGE), "recover-worker", str(pid), image_sha]
           and ("INVOCATION_ID=" + generation).encode() in (cp / "environ").read_bytes().split(b"\0"),
           "foreign recovery worker")
    started, started_ref = s.read(state / "recovery-started.json")
    predecessor = ("failed_manager_query" if TIMEOUT_REJOIN else
                   "failed_fresh_census" if REJOIN else "failed_preincident_verifier")
    if FOCUSED_REJOIN:
        predecessor = "failed_status_owner"
    if TIMER_REJOIN:
        predecessor = "failed_timer_inspection"
    if FIXTURE_REJOIN:
        predecessor = "failed_qualification_census"
    s.need(started["iid"] == generation and started["image"] == image_sha
           and started["r2_mutations"] is False and started["file"] == str(OUTPUT)
           and started["prior_frozen_recovery"][predecessor]["current_boot_failure"]["failure"] == failed
           and not any((state / n).exists() for n in ("failed.json", "complete.json", "verified-frozen.json")),
           "145 left its native frozen read phase")
    objects = {}
    for path, ino, size in ((SOURCE, 100214450, 105633748687), (MANIFEST, 100214429, 1809),
                            (OUTPUT, 103237059, 105610995833)):
        m = path.lstat()
        s.need(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode)
               and (m.st_dev, m.st_ino, m.st_size, m.st_nlink, m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode))
               == (64512, ino, size, 1, 0, 0, 0o400), "different leased 145 file")
        objects[(64512, ino)] = str(path)
    window.update(native_child={"pid": child, "start_ticks": ct}, recovery=started_ref,
                  leases_parent=leased(pid, objects), leases_worker=leased(child, objects))
    s.need(s.process(pid)[1:] == (ticks, group) and s.process(child) == (pid, ct, group),
           "145 phase changed during capture")
    return {"invocation_id": generation, "stage": "leased-worker", "window": window}
