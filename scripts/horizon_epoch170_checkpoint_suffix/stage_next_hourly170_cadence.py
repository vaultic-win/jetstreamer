"""Derive the proposed V76 from the actual sealed V75 without activating it."""
import argparse
import ast
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE),str(HERE.parent/"horizon_epoch143_bounded_entry_20261126_v1/writer")]
from derive143_bootstrap_retry import read_package
from derive_next_hourly170_writer import ENROLL_OPTION, ROOT, cycle as enroll_cycle, members
from derive_ram170_writer import once
from following_prepare import ROOT as RUNTIME, git, need, read, reference, save, seal
from closed_successor import persist

WRITER = RUNTIME/"survivor172-cadence-20261122-v1"
OLD = WRITER/"tools-cold168-retry5-failed166-v75-entry146"
NEW = OLD.with_name("tools-cold168-retry5-failed166-v76-entry146-r2")


def lift(source, before=75, after=76):
    normal,commands = source.split("def main():",1)
    versions = f", {before-1}, {before})"
    need(versions in normal,"missing predecessor cadence version")
    normal = normal.replace(versions,f", {before-1}, {before}, {after})")
    entries = [line for line in normal.splitlines() if line.strip().startswith(f"{before}: ")]
    need(entries,"missing writer version bindings")
    for line in entries:
        replacement = line.replace(f"{before}:",f"{after}:",1)
        replacement = replacement.replace(f"transition_v{before}.V{before-1}",f"transition_v{after}.V{before}")
        normal = once(normal,line,line+"\n"+replacement)
    match, = re.finditer(r"^( *)import transition_v"+str(before)+r"$",normal,re.M)
    indent = match[1]
    anchor = indent+f"import transition_v{before}"
    normal = once(normal,anchor,anchor+"\n"+indent+f"if FAILED166_VERSION >= {after}:\n"
                  +indent+f"    import transition_v{after}")
    match, = re.finditer(r"^( *)modules.append\(transition_v"+str(before)+r"\)$",normal,re.M)
    indent = match[1]
    anchor = indent+f"modules.append(transition_v{before})"
    normal = once(normal,anchor,anchor+"\n"+indent+f"if FAILED166_VERSION >= {after}:\n"
                  +indent+f"    modules.append(transition_v{after})")
    anchor = f"    elif FAILED166_VERSION == {before}:\n        transition_v{before}.validate(globals(), ready, receipt)"
    normal = once(normal,anchor,anchor.replace(str(before),str(after))+"\n"+anchor)
    starts = list(re.finditer(r"^    if FAILED166_VERSION == "+str(before)+r" and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+",
                             commands,re.M))
    need(len(starts)==5,"different predecessor handoff commands")
    for block in reversed(starts):
        copied = block[0].replace(f"== {before}",f"== {after}").replace(f"v{before}",f"v{after}").replace(f"V{before}",f"V{after}")
        commands = commands[:block.start()]+copied+commands[block.start():]
    result = normal+"def main():"+commands
    ast.parse(result)
    return result


def versioned_transition(owner,previous,ready):
    body = (HERE/"transition_v76.py").read_text()
    body = once(body,"V75_OWNER = None","V75_OWNER = "+repr(owner))
    body = once(body,"V75_PACKAGE = None","V75_PACKAGE = "+repr(previous))
    body = once(body,"V75_READY_SHA = None","V75_READY_SHA = "+repr(ready))
    body = once(body,"V75_PACKAGE = "+repr(previous),
                "V75_PACKAGE = "+repr(previous)+"\nV75_SHA = "+repr(owner["sha256"])+"\nV75_SEAL = "+repr(previous["sha256"]))
    return body.encode()


def stage(scope,previous,owner):
    active = read(owner)
    ready = read(active["ready"])
    need(owner["path"] == str(WRITER/"FAILED166_CADENCE_V75_ACTIVE.json")
         and previous["path"] == str(OLD/"deployment-seal-receipt.json")
         and ready["package"] == previous and active["new"]["program"] == str(OLD/"status_cycle.py"),
         "different V75 package and active owner")
    source = read_package(OLD,previous["sha256"])
    repo = HERE.parents[1]
    revision = git(repo,"rev-parse","HEAD").decode().strip()
    tracked = [Path(__file__).resolve(),HERE/"derive_next_hourly170_writer.py",
               HERE/"next_hourly170_contract.py",HERE/"transition_v76.py"]
    git(repo,"merge-base","--is-ancestor",revision,"origin/account-updates")
    for path in tracked:
        need(git(repo,"show",f"{revision}:{path.relative_to(repo)}")==path.read_bytes(),
             "unpublished V76 source "+path.name)
    updates = members(scope)
    code = lift(source["status_cycle.py"][0].decode())
    code = once(code,"    if version in (46, 69):","    if version in (46, 69, 76):")
    updates["status_cycle.py"] = enroll_cycle(code,76).encode()
    updates["transition_v76.py"] = versioned_transition(owner,previous,active["ready"]["sha256"])
    cut = source["cutover75.py"][0].decode()
    cut = re.sub(r"(cutover|[vV])(74|75)",lambda m:m[1]+str(int(m[2])+1),cut)
    old_active = read(ready["old_owner"])
    old_seal = read(old_active["ready"])["package"]["sha256"]
    cut = once(cut,old_seal,previous["sha256"])
    cut = once(cut,'NEW = BASE / "tools-cold168-retry5-failed166-v76-entry146"',
               "NEW = BASE / "+repr(NEW.name))
    cut = once(cut,ready["old_owner"]["sha256"],owner["sha256"])
    updates["cutover76.py"] = cut.encode()
    for name in ("full170_status.py","cold170_status.py","joint168_status.py"):
        text = source[name][0].decode()
        anchor = repr(OLD.name)+")"
        need(anchor in text,"missing V75 program allowlist "+name)
        updates[name] = text.replace(anchor,repr(OLD.name)+", "+repr(NEW.name)+")").encode()
    path = ROOT/"writer-v76-r2-source"
    path.mkdir(mode=0o700,exist_ok=True)
    need(path.resolve(strict=True)==path and path.stat().st_uid==0 and not path.stat().st_mode & 0o077,
         "unsafe V76 source stage")
    entries = {name:(OLD/name,mode) for name,(_,mode) in source.items() if name!="SHA256SUMS"}
    for name,body in updates.items():
        ast.parse(body,filename=name)
        persist(path/name,body)
        entries[name] = path/name,source[name][1] if name in source else 0o444
    origin = save(path/"SOURCE.json",dict(revision=revision,previous=previous,owner=owner,scope=scope,
        source_sha256={str(p.relative_to(repo)):reference(p)["sha256"] for p in tracked},updates=sorted(updates)))
    entries["SOURCE.json"] = Path(origin["path"]),0o444
    return seal(NEW,entries,path/"SEAL_PLAN.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface_sha256")
    parser.add_argument("v75_package_sha256")
    parser.add_argument("v75_owner_sha256")
    args = parser.parse_args()
    print(json.dumps(stage(dict(path=str(ROOT/"NEXT_HOURLY_WRITER_INTERFACE.json"),sha256=args.interface_sha256),
        dict(path=str(OLD/"deployment-seal-receipt.json"),sha256=args.v75_package_sha256),
        dict(path=str(WRITER/"FAILED166_CADENCE_V75_ACTIVE.json"),sha256=args.v75_owner_sha256)),sort_keys=True))
