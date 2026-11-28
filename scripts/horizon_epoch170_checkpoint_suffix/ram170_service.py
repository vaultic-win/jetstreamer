"""Derive the RAM-backed retry unit from the accepted private gap service."""
from pathlib import Path

from derive_gap_price import one
import following_prepare as f
from ram170_capacity import OLD, OLD_UNIT, ROOT, UNIT, RAM, TMPFS

ORIGINAL = "4f456407bf9b7aef21ec9a0a578b0a882138aadc118f99aece253d6e1cdda49c"
ORIGINAL_SEAL = "548549e25d74551f2705d084e8e9a674bb718dcc19daa7e2529867f225bb5deb"
BUILD = "1b8a5dc49647957a0c3cf420036176cd5fd2bdf8a9b41de634d74731ddeae25c"


def service():
    original = OLD/"package"/OLD_UNIT
    f.need(f.reference(original)["sha256"]==ORIGINAL, "different source service")
    source=original.read_text()
    old_run=Path(f.read(f.reference(OLD/"LAYOUT.json"))["run"])
    f.need(old_run.name=="from-73760367-to-73766969-v1", "different original working area")
    run=old_run.with_name("from-73760367-to-73766969-ram-v1")
    source=source.replace(str(old_run),str(run)).replace(str(OLD)+"/package/",str(ROOT)+"/package/")
    source=one(source,str(OLD)+"/barrier:",str(ROOT)+"/barrier:")
    source=one(source,"MemoryMax=51539607552",f"MemoryMax={RAM}")
    source=one(source,"MemoryHigh=49392123904",f"MemoryHigh={RAM-(4<<30)}")
    marker="TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777,size=64M"
    source=one(source,marker,marker+"\n"+f"TemporaryFileSystem={run}/scratch:rw,nosuid,nodev,exec,noswap,mode=0700,uid=1001,gid=1003,size={TMPFS}")
    f.need(str(old_run) not in source and source.count(str(ROOT)+"/package/")==2
           and source.count("BindReadOnlyPaths=")==13 and source.count("ReadWritePaths=")==1,
           "changed private unit mount scopes")
    return source


def package(staging, path):
    seal=f.read(dict(path=str(OLD/"package/deployment-seal-receipt.json"),sha256=ORIGINAL_SEAL))
    build_ref=dict(path=str(path/"BUILD.json"),sha256=BUILD)
    build=f.read(build_ref)
    f.need(build["invocation"]=="53a2940327bf46d4af3d0ca79d4de7ac" and
           set(build["outputs"])=={"gate","guard","gap-checkpoints"}, "different accepted native artifacts")
    members={}
    for entry in seal["members"]:
        name=entry["name"]
        original=OLD/"package"/name
        f.need(original.parent==OLD/"package" and f.reference(original)["sha256"]==entry["sha256"],
               "original package changed")
        if name in ("gate","guard","build.json","SHA256SUMS",OLD_UNIT):
            continue
        members[name]=(original,0o444)
    for name,sha in build["outputs"].items():
        f.need(f.reference(path/name)["sha256"]==sha, "compiled executable changed")
        members[name]=(path/name,0o555)
    members["build.json"]=(path/"BUILD.json",0o444)
    unit=staging/UNIT
    unit.write_text(service())
    members[UNIT]=(unit,0o444)
    return members
