"""Reseal the unissued interval-two retry after validating its compiled guard against the live plan."""
from pathlib import Path
import json
import os
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch162-second-replay-20261128-v2")
OLD = ROOT / "issued-split-v2"
OUT = ROOT / "issued-split-v3"
OLD_INTERFACE = "c010fe101d3edafb732bbf87f7f8de7fd41a11d9b8b967e14ac5a4f372a8e279"
VALIDATED = "d088976717c0f7b7ce216ca55489e50fb2531cc187d9b6617135908cc528cf60"
GUARD = "6c66c053a29cf45e5b17715aeba3ee263c7324e16bcd41494956599ffd6724e6"
NATIVE = "7b90ecb62355df801fb8ca0bc2ea5ddc1ee57bed"


def prepare(commit):
    l = runpy.run_path(str(OLD / "layout.py"))
    need, save, bind = l["need"], l["save"], l["bound"]
    original, interface = l["pinned"](ROOT / "RETRY_INTERFACE.json", OLD_INTERFACE)
    qa, qa_ref = l["pinned"](ROOT / "RETRY_NATIVE_GUARD_VALIDATED.json", VALIDATED)
    need(os.geteuid() == 0 and __debug__ and qa["guard"]["sha256"] == GUARD and qa["native_source"] == NATIVE
         and not qa["production_started"] and qa["original_rejected"] == original["guard"]["sha256"]
         and [c["exit"] for c in qa["checks"]] == [0,1,1,1]
         and not (ROOT / "SPLIT162_ENROLLMENT.json").exists() and not l["DATA"].exists() and not l["RUN"].exists(),
         "prior package is not a failed static fixture with an unissued operator")
    git = ["git", "-c", "safe.directory=" + str(HERE.parent.parent), "-C", str(HERE.parent.parent)]
    for revision in (commit,NATIVE):
        subprocess.run([*git, "merge-base", "--is-ancestor", revision, "origin/account-updates"], check=True)
    source = Path(__file__).resolve()
    need(subprocess.check_output([*git, "show", commit + ":" + str(source.relative_to(HERE.parent.parent))]) == source.read_bytes(),
         "unmerged operator correction")
    helper = runpy.run_path(str(HERE / "second_interval.py"))
    seal = helper["seal"]
    seal.__globals__["BASE"] = ROOT
    stage = ROOT / "second-guard-correction-inputs"
    stage.mkdir(mode=0o700, exist_ok=True)
    need(stage.resolve() == stage and stage.stat().st_uid == 0 and stage.stat().st_mode & 0o077 == 0, "foreign correction directory")
    guard = Path(qa["guard"]["path"])
    need(l["digest"](guard) == GUARD and not guard.stat().st_mode & 0o222, "changed qualified guard")
    guarded = seal({"guard":(guard,0o555)}, ROOT / "guard-v3", save)
    guard_ref = dict(path=str(ROOT / "guard-v3/guard"), sha256=GUARD)
    scope = dict(bind(original["scope"]), first_hourly_guard=guard_ref, guard_deployment=guarded,
                 native_guard_validation=qa_ref, static_fixture_predecessor=interface, source_commit=commit)
    scope_ref = save(ROOT / "SCOPE-V3.json",scope,0o400)
    members = {}
    for member in bind(original["provider"])["members"]:
        name = member["name"]
        if not name.endswith(".py"):
            continue
        old = OLD / name
        need(old.parent == OLD and l["digest"](old) == member["sha256"], "changed prior operator")
        src = old.read_text()
        if name == "layout.py":
            for before, after in (('PKG = BASE / "issued-split-v2"','PKG = BASE / "issued-split-v3"'),
                                  ("SCOPE-V2.json", "SCOPE-V3.json"), (original["scope"]["sha256"], scope_ref["sha256"]),
                                  (original["guard"]["path"], guard_ref["path"]), (original["guard"]["sha256"], GUARD)):
                src = helper["exact"](src,before,after)
        if name == "status162.py":
            src = helper["exact"](src, str(OLD), str(OUT))
        compile(src,name,"exec")
        out = stage / name
        save(out,src.encode())
        members[name] = (out,0o444)
    origin = stage / "ORIGIN.json"
    save(origin,dict(source=commit, native_revision=NATIVE, predecessor=interface, native_fixture=qa_ref,
                     corrected_guard=guard_ref, corrected_scope=scope_ref))
    members[origin.name] = (origin,0o444)
    operator = seal(members,OUT,save)
    reader = dict(path=str(OUT/"status162.py"),sha256=l["digest"](OUT/"status162.py"))
    return save(ROOT / "RETRY_INTERFACE_V3.json",
                dict(original,provider=operator,reader=reader,scope=scope_ref,guard=guard_ref,guard_validation=qa_ref),0o400)


if __name__ == "__main__":
    print(json.dumps(prepare(sys.argv[1])))
