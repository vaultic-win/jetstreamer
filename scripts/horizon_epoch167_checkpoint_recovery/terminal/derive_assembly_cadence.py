"""Derive and preflight the V73 sole writer from the pinned V72 package."""
import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent.parent
WRITERS = SCRIPTS / "horizon_epoch143_bounded_entry_20261126_v1/writer"
COMMON = SCRIPTS / "horizon_epoch170_checkpoint_suffix"
sys.path[:0] = [str(WRITERS), str(COMMON)]
from closed_successor import persist
from derive143_bootstrap_retry import read_package
from derive69 import following_block, one
from following_prepare import need, reference, save, seal

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "survivor172-cadence-20261122-v1"
OLD = ROOT / "tools-cold168-retry5-failed166-v72-entry146"
NEW = ROOT / "tools-cold168-retry5-failed166-v73-entry146"
EVIDENCE = RT / "epoch167-assembly-20261127-v1/assembly-forecast-evidence-v1"
PIN = "1ce0186cb6b339ee8189f24d9ee8620eb85047fb64c5b6293a1522bbe82c2146"
ACTIVE = "16100229f345b290452df1d071d6b1986b6e32a6d03b6b1e12c8e0b3cf51c174"
FORECAST = "9126af6f1701a3061f35130a11397ac4397ba4a135757ded2f537b5715fda3d6"


def cycle(source):
    normal, commands = source.split("def main():", 1)
    normal = normal.replace(", 71, 72)", ", 71, 72, 73)")
    for line in normal.splitlines():
        if line.strip().startswith(("72: (transition_v72.", "72: 'fb9db4e77")):
            addition = line.replace("72:", "73:", 1).replace("transition_v72.V71", "transition_v73.V72")
            normal = one(normal, line, line + "\n" + addition)
    normal = following_block(normal, "import transition_v72", ["if FAILED166_VERSION >= 73:",
            "    import transition_v73", "    import assembly_forecast", "    import assembly_cadence"])
    normal = following_block(normal, "modules.append(transition_v72)", ["if FAILED166_VERSION >= 73:",
            "    modules.extend([transition_v73, assembly_cadence, assembly_forecast])"])
    validate = "    elif FAILED166_VERSION == 72:\n        transition_v72.validate(globals(), ready, receipt)"
    normal = one(normal, validate, validate.replace("72", "73") + "\n" + validate)
    # Take the measurement before remote status operations and persist it once per original clock.
    context = "           prior=checked(fleet['authenticated_status_audit']),new_rows={},rows={},metered168_row=None)"
    normal = one(normal, context, context + """
    if FAILED166_VERSION >= 73:
        previous167 = fleet['complete_active_status_receipts'].get('167')
        if previous167 and assembly_cadence.owns(checked(previous167)):
            c.assembly167 = assembly_cadence.freeze(c)""")
    branch = "        elif epoch == 167 and getattr(c, 'failed167', None):"
    normal = one(normal, branch, """        elif epoch == 167 and FAILED166_VERSION >= 73 and assembly_cadence.owns(old):
            after,extra=assembly_cadence.forecast(c,original,old,cold167_status.TERMINAL_FIELD)
        elif epoch == 167 and FAILED166_VERSION >= 73 and prior['phase'] in ('upload','readback'):
            # A separately admitted delivery owns its phase and status.
            return
""" + branch)
    fleet = "    return fleet\n\n\ndef track_timer"
    normal = one(normal, fleet, """    if FAILED166_VERSION >= 73:
        assembly_cadence.install(fleet,a['receipts'].get('167'))
""" + fleet)
    blocks = list(re.finditer(r"^    if FAILED166_VERSION == 72 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+", commands, re.M))
    need(len(blocks) == 5, "unexpected V72 command set")
    for block in reversed(blocks):
        addition = block[0].replace("== 72", "== 73").replace("v72", "v73").replace("V72", "V73")
        commands = commands[:block.start()] + addition + commands[block.start():]
    return normal + "def main():" + commands


def cutover(text):
    text = re.sub(r"(cutover|[vV])(71|72)", lambda m: m[1]+str(int(m[2])+1), text)
    text = one(text, 'ORIGINAL_SEAL = "0c48be5c716513e7de5eb41b61894a39bcffb576cf90f1433443a91dff5ef809"',
               f'ORIGINAL_SEAL = "{PIN}"')
    text = one(text, 'OLD_OWNER = "1d9087ae207f193876a0d3e289141e0b21852a9e9b6012344fe4d0871970b463"',
               f'OLD_OWNER = "{ACTIVE}"')
    anchor = "producers=owners, assembly=assembly, verification168=native, guards=guards,"
    return one(text, anchor, "assembly167=transition_v73.assembly.owner_binding(), " + anchor)


def files():
    old = read_package(OLD, PIN)
    updates = {"status_cycle.py":cycle(old["status_cycle.py"][0].decode()).encode(),
               "cutover73.py":cutover(old["cutover72.py"][0].decode()).encode()}
    for name in ("assembly_cadence.py", "assembly_forecast.py", "transition_v73.py"):
        updates[name] = (HERE / name).read_bytes()
    need(hashlib.sha256(updates["assembly_forecast.py"]).hexdigest() == FORECAST, "different qualified forecast")
    for name, count in (("full170_status.py",1), ("cold170_status.py",5), ("joint168_status.py",3)):
        data = old[name][0].decode()
        ending = repr(OLD.name) + ")"
        need(data.count(ending) == count, "different qualified package list in " + name)
        updates[name] = data.replace(ending, repr(OLD.name) + ", " + repr(NEW.name) + ")").encode()
    for name, data in updates.items():
        ast.parse(data, filename=name)
    return old, updates


def stage(revision):
    os.umask(0o077)
    repo = SCRIPTS.parent
    work = EVIDENCE / "writer-v73-source"
    work.mkdir(mode=0o700, exist_ok=True)
    need(work.resolve() == work and work.lstat().st_uid == 0 and not work.lstat().st_mode & 0o077,
         "unsafe writer source stage")
    git = ["/usr/bin/git", "-c", "safe.directory=" + str(repo), "-c", "safe.directory=/home/sol/workspace/jetstreamer",
           "-C", str(repo)]
    tip = subprocess.check_output(git + ["rev-parse","refs/remotes/origin/account-updates"], text=True).strip()
    subprocess.run(git + ["merge-base","--is-ancestor", revision, tip], check=True)
    inputs = [Path(__file__), HERE/"transition_v73.py", HERE/"assembly_forecast.py", HERE/"assembly_cadence.py",
              HERE/"test_assembly_cadence.py", WRITERS/"derive143_bootstrap_retry.py", WRITERS/"derive69.py",
              WRITERS/"derive63.py", COMMON/"following_prepare.py", COMMON/"closed_successor.py"]
    for source in inputs:
        rel = str(source.relative_to(repo))
        need(subprocess.check_output(git+["show", revision+":"+rel]) == source.read_bytes(),
             "unpublished writer input "+rel)
    old, changes = files()
    members = {name:(OLD/name, mode) for name, (_,mode) in old.items() if name != "SHA256SUMS"}
    for name, content in changes.items():
        persist(work/name, content)
        members[name] = (work/name, old[name][1] if name in old else 0o444)
    save(work/"SOURCE.json", dict(commit=revision, source_files={str(p.relative_to(repo)):reference(p)["sha256"] for p in inputs},
            predecessor=reference(OLD/"deployment-seal-receipt.json"), changed_members=sorted(changes)))
    return seal(NEW, members, work/"SEAL_PLAN.json")


def preflight():
    latest = max(RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p:p.stat().st_mtime_ns)
    head = reference(latest)
    args = ["/usr/bin/python3","-IB",str(NEW/"status_cycle.py"),"--check-v73-handoff",head["path"],head["sha256"]]
    ready = json.loads(subprocess.check_output(args))
    need(ready["package"] == reference(NEW/"deployment-seal-receipt.json") and ready["fleet"] == head
         and ready["old_owner"]["sha256"] == ACTIVE and ready["epoch167_assembly_forecast"]["sha256"] == FORECAST,
         "different V73 preflight")
    return save(EVIDENCE / ("PENDING_V73_"+head["sha256"][:12]+"_"+hashlib.sha256(json.dumps(ready,sort_keys=True).encode()).hexdigest()[:10]+".json"),ready)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    flags = p.add_mutually_exclusive_group(required=True)
    flags.add_argument("--stage")
    flags.add_argument("--preflight", action="store_true")
    flags.add_argument("--inspect", action="store_true")
    args = p.parse_args()
    if args.stage:
        result = stage(args.stage)
    elif args.preflight:
        result = preflight()
    else:
        original, changes = files()
        result = {"retained": len(original), "changes": sorted(changes)}
    print(json.dumps(result))
