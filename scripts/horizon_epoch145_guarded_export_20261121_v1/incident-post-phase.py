"""Price the original paid epoch 145 after its frozen semantic reader succeeds."""
import hashlib
import os
from pathlib import Path
import stat
import sys

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PKG = ROOT / "epoch145-semantic-continuity-20261121-v1/tools-v7"
VERSION = Path(__file__).resolve().parent.name
FOCUSED_SUCCESSOR = VERSION == "tools-v9"
RETRIED_SEMANTIC = VERSION == "tools-v10"
TIMER_SUCCESSOR = VERSION == "tools-v11"
TIMEOUT_SUCCESSOR = VERSION in ("tools-v8", "tools-v9", "tools-v10", "tools-v11")
if TIMEOUT_SUCCESSOR:
    PKG = PKG.parent / VERSION
IMAGE = PKG / "export145"
STATE = ROOT / "epoch145-guarded-export-20261121-v1/state"
PUBLICATION = ROOT / "epoch145-publication-20261121-v1"
HOME = Path("/home/sol/.jetstreamer-private")
OUTPUT = HOME / "epoch145-prefix-extract-funded-20261121-v1"
ARCHIVE = OUTPUT / "epoch-145.jet"
SIDECAR = OUTPUT / "epoch-145.jet.sha256"
HOLDING = HOME / "r2-holding-state-dev-samjohnson-v1/transition.lock"
UNIT = "horizon-holding-export145-20261121-v1.service"
CGROUP = "/system.slice/" + UNIT
PIPE = Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1/consumer-bench-image-20261120-v1/regular-consumer-true-updates-8822f0ba8391/horizon_pipeline")
VERIFIER = PUBLICATION / "current-reader-tools-v2/verify_archive"
UPLOADER = PUBLICATION / "uploader-tools/jetstreamer-r2"
BOOTSTRAP = "dc043eb78c4a4349b0098760dc764a1f"
ADVANCING = "c8c4a5572906fb348658759ed4c81a7edaf4ee790faab391d700ad9fd4e4c199"
ADVANCING_NAME = "V5B_ACTUAL_ADVANCING_WORKER.json"
if TIMEOUT_SUCCESSOR:
    PIPE = Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1/public-rseek-reconnect-56bf2bf0937f/horizon_pipeline")
    BOOTSTRAP = "d37f36f898a44932a19fd50d7014a6fe"
    ADVANCING = "6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76"
    ADVANCING_NAME = "V5C_ACTUAL_ADVANCING_WORKER.json"
if RETRIED_SEMANTIC:
    BOOTSTRAP = "e6551a0bb8a14b989902e15c9ecc0751"
    ADVANCING = "3a41dac31746938b482133b9ff224f9d9d821569cc16f63c83f872fe907c13e0"
    ADVANCING_NAME = "V5D_RETRY1_ACTUAL_ADVANCING_WORKER.json"


if TIMER_SUCCESSOR:
    PIPE = Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1/fast-range-residency-0f29fd116ef5/horizon_pipeline")
    ADVANCING_NAME = "V5E_ACTUAL_ADVANCING_WORKER.json"


def argv(pid):
    return [os.fsdecode(x) for x in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if x]


def procids(path):
    return tuple(sorted(map(int, (path / "cgroup.procs").read_text().split())))


def generation(s, parent, mode, args, fleet, m, profile):
    seal, sr = s.read(PKG / "deployment-seal-receipt.json", profile["seal_sha256"])
    build, br = s.read(PKG / "build-proof.json", profile["build_sha256"])
    members = {x["name"]: x["sha256"] for x in seal["members"]}
    h = profile["image_sha256"]
    s.need(seal["destination"] == str(PKG) and members["export145"] == h
           and build["verifier_sha256"] == h and members["build-proof.json"] == br["sha256"]
           and len(args) == (6 if mode == "publish" else 5) and args[0] == str(IMAGE)
           and args[-1] == h and fleet.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
           and fleet.parent.parent == ROOT and s.iid(m["InvocationID"])
           and m["Id"] == UNIT and m["ControlGroup"] == CGROUP and m["ActiveState"] == "active"
           and m["SubState"] == "running" and not m["Job"] and m["NRestarts"] == "0"
           and m["ControlPID"] == "0" and m["CPUQuotaPerSecUSec"] == "1s"
           and m["MemoryMax"] == str(2 << 30) and m["MemorySwapMax"] == "0"
           and s.process(parent)[2] == "0::" + CGROUP, "unknown 145 publication manager")
    with IMAGE.open("rb") as stream:
        s.need(hashlib.file_digest(stream, "sha256").hexdigest() == h, "changed 145 controller")
    s.read(fleet, args[3])
    lock = HOLDING.stat()
    p = Path("/proc") / str(parent)
    s.need((lock.st_dev, lock.st_ino) == (64512, 95818311) and any(
        os.path.samestat(fd.stat(), lock) and any(" FLOCK " in l and " WRITE " in l
            for l in (p / "fdinfo" / fd.name).read_text().splitlines()) for fd in (p / "fd").iterdir())
        and ("INVOCATION_ID=" + m["InvocationID"]).encode() in (p / "environ").read_bytes().split(b"\0"),
        "different holding owner")
    return sr, br


def completion(s, build=None):
    if TIMER_SUCCESSOR:
        # The price observer authenticates the build receipt against the sealed
        # deployment before passing its ID-bound original worker reference.
        advancing = s.bound(build["prior_phase"], PKG.parent / ADVANCING_NAME)
        bootstrap = advancing["invocation_id"]
        manager = s.bound(advancing["manager"], PKG.parent / "V5E_ACTUAL_MANAGER.json")
        intent = s.bound(manager["intent"], PKG.parent / "V5E_START_INTENT.json")
        s.need(s.iid(bootstrap) and manager["new"]["InvocationID"] == bootstrap and
               intent["schema"] == "horizon-145-retry-after-timer-inspection-intent-v1" and
               intent["old"] == "e6551a0bb8a14b989902e15c9ecc0751" and
               intent["failure"] == build["old_failure"] and intent["recovery"] == build["old_start"] and
               intent["failure"]["sha256"] == "9ef9c938290ea2b43d3b2ce4aa617f08b33f4c893961e63f53ba3f48768e215f",
               "different original timer recovery")
    else:
        bootstrap = BOOTSTRAP
        advancing, _ = s.read(PKG.parent / ADVANCING_NAME, ADVANCING)
    if FOCUSED_SUCCESSOR and (PKG.parent / "V5D_START_INTENT.json").exists():
        intent, original = s.read(PKG.parent / "V5D_START_INTENT.json")
        advancing, _ = s.read(PKG.parent / "V5D_ACTUAL_ADVANCING_WORKER.json")
        bootstrap = advancing["invocation_id"]
        s.need(s.iid(bootstrap) and bootstrap != BOOTSTRAP and intent["old"] == BOOTSTRAP and
               intent["schema"] == "horizon-145-focused-census-recovery-intent-v1" and
               not (STATE / BOOTSTRAP / "complete.json").exists(), "ambiguous semantic predecessor")
        manager = s.bound(advancing["manager"], PKG.parent / "V5D_ACTUAL_MANAGER.json")
        s.need(manager["intent"] == original and manager["new"]["InvocationID"] == bootstrap,
               "different paid semantic recovery")
    old = STATE / bootstrap
    start, start_ref = s.read(old / "recovery-started.json", advancing["start"]["sha256"])
    verified, vr = s.read(old / "verified-frozen.json")
    done, dr = s.read(old / "complete.json")
    extracted, er = s.read(old / "extraction-complete.json")
    e = extracted["extraction"]
    s.need(advancing["invocation_id"] == start["iid"] == verified["iid"] == done["iid"]
           == extracted["actor_iid"] == bootstrap and done["receipt"] == er
           and done["recovered_from"] == extracted["original_export"] == "de6780b860b3467bae21fbd19176ca14"
           and extracted["verified_frozen"] == vr and extracted["recovery_evidence"] == start_ref
           and verified["r2_mutations"] is False and start["r2_mutations"] is False
           and done["r2_mutations"] is False and extracted["archive_publication_authorized"] is False
           and e["epoch"] == 145 and e["archive"] == str(ARCHIVE) and e["archive_bytes"] == 105610995833
           and e["output_slot_count"] == 432000 and e["independent_output_reread_passed"] is True
           and not (old / "failed.json").exists() and not (OUTPUT / ".tmp36MvkN").exists(),
           "unverified original paid archive promotion")
    return dr, e


def ordinary_full(s, parent, children, gen, extraction):
    if not children:
        return []
    s.need(len(children) == 1, "extra full verifier")
    child = children[0]
    args = argv(child)
    report = PUBLICATION / ("full-" + gen)
    permitted = [
        ["/usr/bin/sha256sum", "--", str(ARCHIVE)],
        [str(VERIFIER), str(ARCHIVE), "--full", "--threads", "1", "--anchor", "62639999",
         "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB", "--expected-terminal", "63071999",
         "4zqmYpqcustpx2BQ2gB6y7v1HsvZpPGeyaRKFEsbThum", "--expected-provenance-sha256",
         extraction["expected_output_provenance_sha256"]],
        [str(PIPE), "145", str(OUTPUT), "--verify-only", "--threads", "1",
         "--verification-report", str(report / "plugin-report.json")],
    ]
    pp, ticks, cg = s.process(child)
    s.need(args in permitted and s.same_file(Path(f"/proc/{child}/exe"), Path(args[0]))
           and (pp, cg) == (parent, "0::" + CGROUP), "foreign full verification child")
    return [[child, ticks, args[0]]]


def network_members(s, parent, leaf, gen, full_iid):
    if not leaf.exists():
        return []
    s.need(not any(x.is_dir() for x in leaf.iterdir()), "nested delegated publication group")
    group = "0::" + CGROUP + "/publication"
    who = procids(leaf)
    actors = {p: s.process(p) for p in who}
    roots = [p for p, (pp, _, _) in actors.items() if pp == parent]
    s.need(all(cg == group and (pp == parent or pp in actors) for pp, _, cg in actors.values())
           and len(roots) == int(bool(who)), "unowned publication subtree")
    if not who:
        return []
    root = roots[0]
    args = argv(root)
    exe = Path(f"/proc/{root}/exe")
    repo = "/home/sol/workspace/jetstreamer"
    name = "refs/heads/account-updates"
    target = name + ":refs/remotes/origin/account-updates"
    local = PUBLICATION / ("full-" + full_iid)
    receipts = PUBLICATION / ("network-" + gen) / "receipts"
    plan = local / "delivery-plan.json"
    _, pr = s.read(plan)
    allowed = [[str(UPLOADER), "inventory", str(OUTPUT), "--epochs", "145-145"],
               [str(UPLOADER), "sync", str(OUTPUT), "--epochs", "145-145", "--receipt-directory", str(receipts),
                "--current-reader-plan", str(plan), "--current-reader-plan-sha256", pr["sha256"],
                "--concurrency", "1", "--part-size-mib", "64"], ["/usr/bin/ssh-add", "-l"]]
    allowed += [["/usr/bin/git", "-C", repo, *a] for a in (["remote", "get-url", "origin"],
                ["ls-remote", "--exit-code", "origin", name], ["fetch", "origin", target])]
    s.need(args in allowed and s.same_file(exe, Path(args[0])), "foreign publication root")
    # The sealed uploader starts its current-reader validators in this leaf. Git
    # and SSH may also create descendants. Every PID must be rooted at the one
    # exact allowed command and be charged to the same capped service.
    for child in actors:
        seen = set()
        while child != root:
            s.need(child in actors and child not in seen, "unrooted publication payload")
            seen.add(child)
            child = actors[child][0]
    rows = [[p, actors[p][1], str(Path(f"/proc/{p}/exe").readlink())] for p in who]
    s.need(procids(leaf) == who and all(s.process(p) == actors[p] for p in who), "publication child changed")
    return rows


def inspect(s, leased, m, members, epoch, provider, profile):
    parent = int(m["MainPID"])
    if parent < 2 or not IMAGE.exists() or not s.same_file(Path(f"/proc/{parent}/exe"), IMAGE):
        return None
    args = argv(parent)
    s.need(len(args) in (5, 6) and args[1] in ("post-full", "publish"), "unknown paid publication phase")
    mode, gen = args[1], m["InvocationID"]
    sr, br = generation(s, parent, mode, args, Path(args[2]), m, profile)
    ticks = s.process(parent)[1]
    seen = set(members)
    if os.getpid() in seen:
        probe = argv(os.getpid())
        s.need(epoch == 145 and os.getppid() == parent and sys.flags.isolated and __debug__
               and probe[1:4] == ["-IB", str(provider), "145"] and len(probe) == 6
               and s.same_file(Path("/proc/self/exe"), Path("/usr/bin/python3")), "foreign 145 capacity probe")
        seen.remove(os.getpid())
    s.need(parent in seen, "holding controller absent")
    seen.remove(parent)
    done, e = completion(s, s.bound(br, PKG / "build-proof.json") if TIMER_SUCCESSOR else None)
    meta = ARCHIVE.lstat()
    s.need((meta.st_dev, meta.st_ino, meta.st_size, meta.st_nlink, meta.st_uid, meta.st_gid,
            stat.S_IMODE(meta.st_mode)) == (64512, 103237059, 105610995833, 1, 0, 0, 0o400)
           and ARCHIVE.resolve(strict=True) == ARCHIVE and stat.S_ISREG(meta.st_mode), "different canonical archive")
    locks = {(meta.st_dev, meta.st_ino): str(ARCHIVE)}
    cgroup = Path("/sys/fs/cgroup" + CGROUP)
    dirs = {x.name for x in cgroup.iterdir() if x.is_dir()}
    if mode == "post-full":
        s.need(not dirs, "extra verification group")
        workers = ordinary_full(s, parent, sorted(seen), gen, e)
    else:
        s.need(not seen and dirs <= {"publication"} and s.iid(args[4]) and args[4] != gen,
               "extra publication group or member")
        label = (e["archive_sha256"] + "  epoch-145.jet\n").encode()
        sm = SIDECAR.lstat()
        s.need(SIDECAR.resolve(strict=True) == SIDECAR and stat.S_ISREG(sm.st_mode)
               and (sm.st_dev, sm.st_uid, sm.st_gid, sm.st_nlink, stat.S_IMODE(sm.st_mode), sm.st_size)
               == (64512, 0, 0, 1, 0o400, len(label)) and SIDECAR.read_bytes() == label,
               "foreign local checksum")
        locks[(sm.st_dev, sm.st_ino)] = str(SIDECAR)
        workers = network_members(s, parent, cgroup / "publication", gen, args[4])
    window = {"mode": mode, "native_parent": {"pid": parent, "start_ticks": ticks}, "workers": workers,
              "completion": done, "leases_parent": leased(parent, locks), "seal": sr, "build": br}
    s.need(s.process(parent)[1:] == (ticks, "0::" + CGROUP) and procids(cgroup) == tuple(sorted(members))
           and argv(parent) == args, "145 generation crossed observation")
    return {"invocation_id": gen, "stage": mode, "window": window}
