"""Build the 170 reader from an accepted hourly replay and prove its bootstrap before installation."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import following_prepare as f
from closed_successor import persist

ROOT = f.ROOT / "epoch170-from-73766969-ram-20261128-v1"
UNIT = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"
SCOPE = dict(path=str(ROOT/"AFTER_FLOOR_WRITER_INTERFACE.json"),
             sha256="a4ca94b87bb1a301d76eacab1b3421dd52f96b5a4e5d0074b73dd6a3d3a63078")
RECIPE = dict(path=str(f.ROOT/"epoch170-from-73760367-ram-20261128-v3/package/build.json"),
              sha256="8b4323986500f1f5580ba4d12e5844e31966e83657f395d0c64e8dbd6ce62c5f")
QA = dict(path=str(ROOT/"READER_SOURCE_QA.json"),
          sha256="9c0a5f45adb96ea5a4bd7161ffc053784c977b4ba2ff75332c82590a236f987a")


def bindings():
    release_ref = f.reference(ROOT/"SUCCESSOR_RELEASE.json")
    progress_ref = f.reference(ROOT/"FIRST_PROTECTED_PROGRESS.json")
    release, progress = f.read(release_ref), f.read(progress_ref)
    actor = f.read(release["actor"])
    iid = actor["producer_invocation_id"]
    f.need(release["actor"] == progress["actor"] and release_ref == progress["release"]
           and actor["unit"] == UNIT and release["producer_invocation_id"] == progress["producer_invocation_id"] == iid
           and progress["scope"] == release["interface"] == actor["interface"] == SCOPE
           and actor["producer_pid"] == progress["producer_pid"] and progress["worker"]["pid"] > 0
           and release["guard_timer_invocation_id"] == progress["guard_timer_invocation_id"]
           and not progress["canonical_publication_authorized"], "inconsistent guarded progress")
    return dict(invocation=iid,release=release_ref,progress=progress_ref,actor=release["actor"],scope=SCOPE)


def build():
    group = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().removeprefix("0::/")
    f.need(group.name.startswith("horizon-170-hourly-reader-build-")
           and [(group/name).read_text().strip() for name in ("memory.max","memory.swap.max","cpu.max","pids.max")]
           == [str(704 << 20),"0","50000 100000","64"], "different reader compiler cgroup")
    fs = os.statvfs("/tmp")
    mount = subprocess.check_output(["findmnt","-n","-o","FSTYPE,OPTIONS","-T","/tmp"],text=True).split()
    f.need(mount[0] == "tmpfs" and "noswap" in mount[1].split(",")
           and fs.f_frsize*fs.f_blocks <= 96 << 20, "different compiler scratch")
    proof = bindings()
    recipe = f.read(RECIPE)
    qa = f.read(QA)
    verified = f.read(qa["fixture_result"])
    f.need(qa["source_scope"] == SCOPE and set(verified["tests"]) == {"previous","hourly-test","hourly-refusal"}
           and not qa["reader_inputs_bound_to_live_producer"], "unknown reader source fixture")
    repo = HERE.parents[1]
    revision = f.git(repo,"rev-parse","HEAD").decode().strip()
    f.git(repo,"merge-base","--is-ancestor",revision,"origin/account-updates")
    for path,digest in verified["source"].items():
        f.need(f.reference(repo/path)["sha256"] == digest
               and (repo/path).read_bytes() == f.git(repo,"show",revision+":"+path), "different checked reader source")
    for path,digest in recipe["externs"].items():
        f.need(f.reference(path)["sha256"] == digest, "reader dependency changed")
    cmd, = [list(c) for c in recipe["commands"] if c[-2:] == ["-o","/tmp/gap-checkpoints"]]
    f.need(f.reference(cmd[0])["sha256"] == recipe["compiler"], "reader compiler changed")
    entry, = [n for n,arg in enumerate(cmd) if arg.endswith("/gap_checkpoints.rs")]
    cmd[entry] = str(HERE/"after_floor_hourly_checkpoints.rs")
    elf, dep = Path("/tmp/hourly-checkpoints"), Path("/tmp/hourly-checkpoints.d")
    cmd[1] = "--emit=dep-info="+str(dep)+",link"
    cmd[-1] = str(elf)
    env = dict(os.environ, LC_ALL="C", PATH="/usr/bin:/bin", TMPDIR="/tmp",
               HORIZON_HOURLY170_READ_INVOCATION=proof["invocation"],
               HORIZON_HOURLY170_READ_RELEASE=proof["release"]["sha256"],
               HORIZON_HOURLY170_READ_PROGRESS=proof["progress"]["sha256"])
    with open("/run/lock/horizon-native-serial-compiler.lock","rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        subprocess.run(cmd,cwd="/tmp",env=env,check=True)
    deps = dep.read_text().splitlines()[0].split(": ",1)[1].split()
    sources = {str(Path(p).relative_to(repo)):f.reference(p)["sha256"] for p in deps}
    f.need(all(verified["source"].get(k) == v for k,v in sources.items())
           and str((HERE/"after_floor_hourly_checkpoints.rs").relative_to(repo)) in sources,
           "compiled reader differs from the checked source set")
    bootstrap = json.loads(subprocess.check_output([elf,"bootstrap"],text=True))
    f.need(bootstrap["release"] == proof["release"] and bootstrap["actor"] == proof["actor"]
           and bootstrap["evidence"]["comparison"] == "bootstrap" and bootstrap["checkpoints"][0]["slot"] == 73_766_969
           and not bootstrap["canonical_publication_authorized"], "different live bootstrap")
    closed = subprocess.run([elf,"closed"],capture_output=True)
    f.need(closed.returncode != 0 and not (ROOT/"hourly-exit/PID1_EXIT.json").exists(),
           "reader did not refuse an incomplete live segment")
    out = ROOT/"hourly-reader-build"/os.environ["INVOCATION_ID"]
    out.mkdir(mode=0o700)
    dest = out/elf.name
    persist(dest,elf.read_bytes())
    dest.chmod(0o500)
    f.need(dest.stat().st_size < 4 << 20,"reader exceeds the evidence budget")
    result = f.save(out/"BUILD.json",dict(bindings=proof,unit=group.name,invocation=os.environ["INVOCATION_ID"],
              source_revision=revision,source=sources,recipe=RECIPE,source_qa=QA,command=cmd,compiler=recipe["compiler"],
              binary=f.reference(dest),bootstrap=bootstrap,closed_refusal=closed.stderr.decode(),canonical_publication_authorized=False))
    print(json.dumps(result),flush=True)


if __name__ == "__main__":
    build()
