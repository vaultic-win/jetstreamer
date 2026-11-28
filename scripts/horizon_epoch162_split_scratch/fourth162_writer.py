"""Derive the V74 cadence from the sealed V73, keeping each earlier receiver on its original interval."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import fourth_interval as run
from derive_third162_writer import one

SCRIPTS = HERE.parent
WRITERS = SCRIPTS/"horizon_epoch143_bounded_entry_20261126_v1/writer"
COMMON = SCRIPTS/"horizon_epoch170_checkpoint_suffix"
sys.path[:0] = [str(WRITERS),str(COMMON)]
from derive69 import following_block
from derive143_bootstrap_retry import read_package
from following_prepare import reference, seal
from closed_successor import persist

ROOT = run.RT/"survivor172-cadence-20261122-v1"
OLD = ROOT/"tools-cold168-retry5-failed166-v73-entry146"
NEW = OLD.with_name("tools-cold168-retry5-failed166-v74-entry146")
SEAL = "9a35d3e4d2330a061cd6139d7a8229eb36671c05b67f90dd46082fb5874b22e8"
ACTIVE = "81d8916b2e50ff8989b48c948f6f49c6eed92232b3bdcac05986ccd64bf6aa70"
ROUTE = "0f6df848524300f1bc9a50baef5681d4b92a9028cc0a7bad9acaeae5cf6e88f6"
PROGRESS = "44ddccee5cd6c6efafc7596d8518d94da142f430a2bcffdb772cc1e17604e782"


def published(commit, sources):
    checkout = SCRIPTS.parent
    git = ["git","-c","safe.directory="+str(checkout),"-C",str(checkout)]
    run.need(re.fullmatch("[a-f0-9]{40}",commit), "expected full source revision")
    subprocess.run([*git,"merge-base","--is-ancestor",commit,"origin/account-updates"],check=True)
    for p in sources:
        rel = str(p.relative_to(checkout))
        run.need(subprocess.check_output([*git,"show",commit+":"+rel]) == p.read_bytes(), "unpublished source "+rel)


def contract(pin):
    interface = dict(path=str(run.BASE/"INTERFACE.json"),sha256=pin)
    info = run.bind(interface)
    scope = run.bind(info["scope"])
    provider = run.bind(info["provider"])
    reader = Path(info["reader"]["path"])
    run.need(info["scope"] == reference(run.BASE/"SCOPE.json") and info["previous"] == scope["previous"] == reference(run.PRIOR)
             and info["previous"]["sha256"] == run.PRIOR_SHA and info["field"] == run.FIELD and info["unit"] == run.UNIT
             and (info["first_slot"],info["last_slot"]) == (run.SLOTS[0]+1,run.SLOTS[1]) and scope["position_count"] == 7051
             and reader == run.BASE/"operator-v1/status162.py" and reference(reader) == info["reader"]
             and provider["destination"] == str(reader.parent) and any(m["name"] == reader.name and m["sha256"] == info["reader"]["sha256"]
                                                                       for m in provider["members"]), "foreign fourth 162 scope")
    return interface, info


def router(old):
    # Only the new copy changes its storage fields and checkpoint. Keep the prior
    # module itself intact so every older wire receipt still resolves identically.
    text = old.replace("third","fourth").replace("second162_reserved_route","third162_route").replace("prior.second","prior.third")
    for before,after in (("prior.SECOND","prior.UNIT"),("second_terminal","third_terminal"),("second checkpoint","third checkpoint"),
                         ("second replay custody","third replay custody"),("private162_second_reserved_held","private162_third_held"),
                         ("69_998_120","70_004_938"),("70_004_937","70_011_988"),("6818","7051"),
                         ("c64af2c83b994e299e375b44dee7ce21",run.OLD_IID),
                         ("b43c8d3a1df6a2b3aa11c4d64076b59cbea6fe0cb735ed12159fb24034339577",run.PRIOR_SHA)):
        run.need(before in text,"unrecognized third route "+before)
        text = text.replace(before,after)
    return text


def cycle(source):
    normal, commands = source.split("def main():",1)
    run.need(", 72, 73)" in normal,"missing version list")
    normal = normal.replace(", 72, 73)",", 72, 73, 74)")
    for line in normal.splitlines():
        if line.strip().startswith(("73: (transition_v73.","73: 'fb9db4e77")):
            normal = one(normal,line,line+"\n"+line.replace("73:","74:",1).replace("transition_v73.V72","transition_v74.V73"))
    normal = following_block(normal,"import assembly_cadence",["if FAILED166_VERSION >= 74:","    import transition_v74"])
    normal = following_block(normal,"import third162_route as second162_route",["third162_route = second162_route",
            "if FAILED166_VERSION >= 74:","    import fourth162_route as second162_route"])
    normal = one(normal,"modules += [second162_route, second162_route.third, second162_route.progress]",
                        "modules += [third162_route, third162_route.third, third162_route.progress]")
    normal = following_block(normal,"modules.append(third162_bindings)",["if FAILED166_VERSION >= 74:",
            "    import fourth162_bindings","    modules.extend([second162_route,second162_route.fourth,second162_route.progress,fourth162_bindings])"])
    normal = following_block(normal,"modules.extend([transition_v73, assembly_cadence, assembly_forecast])",[
            "if FAILED166_VERSION >= 74:", "    modules.append(transition_v74)"])
    anchor = "    elif FAILED166_VERSION == 73:\n        transition_v73.validate(globals(), ready, receipt)"
    normal = one(normal,anchor,anchor.replace("73","74")+"\n"+anchor)
    blocks = list(re.finditer(r"^    if FAILED166_VERSION == 73 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+",commands,re.M))
    run.need(len(blocks)==5,"different V73 handoff commands")
    for block in reversed(blocks):
        added = block[0].replace("== 73","== 74").replace("v73","v74").replace("V73","V74")
        commands = commands[:block.start()]+added+commands[block.start():]
    return normal+"def main():"+commands


def members(original, interface, info):
    def get(name):
        return original[name][0].decode()
    for n,pin in (("third162_route.py",ROUTE),("third162_progress.py",PROGRESS)):
        run.need(hashlib.sha256(original[n][0]).hexdigest() == pin,"different V73 "+n)
    scope = dict(INTERFACE=interface,SCOPE=info["scope"],OPERATOR=info["provider"],READER=info["reader"])
    progress = get("third162_progress.py").replace("162-third-replay-", "162-fourth-replay-")
    progress = one(one(progress,"69_998_120 <= slot <= 70_004_937","70_004_938 <= slot <= 70_011_988"),
                   run.OLD_GUARD_SHA,info["guard"]["sha256"])
    cutover = re.sub(r"(cutover|[vV])(72|73)",lambda m:m[1]+str(int(m[2])+1),get("cutover73.py"))
    cutover = one(one(cutover,"1ce0186cb6b339ee8189f24d9ee8620eb85047fb64c5b6293a1522bbe82c2146",SEAL),
                  "16100229f345b290452df1d071d6b1986b6e32a6d03b6b1e12c8e0b3cf51c174",ACTIVE)
    # V62 and V68 each exercise their historical reader on its own cohort.
    # Validate and project the new actor only in those narrower views.
    v62 = one(get("transition_v62.py"),"    fleet = earlier_fleet(fleet)",
              "    from fourth162_route import earlier_fleet as before_fourth\n    fleet = earlier_fleet(before_fourth(fleet))")
    v68 = one(get("transition_v68.py"),"    old = route.second_terminal(fleet)",
              "    from fourth162_route import earlier_fleet\n    fleet = earlier_fleet(fleet)\n    old = route.second_terminal(fleet)")
    new = {"fourth162_route.py":router(get("third162_route.py")).encode(), "fourth162_progress.py":progress.encode(),
           "fourth162_status.py":Path(info["reader"]["path"]).read_bytes(), "fourth162_bindings.py":"".join(f"{k} = {v!r}\n" for k,v in scope.items()).encode(),
           "fourth162_provider.json":(json.dumps(info["provider"],sort_keys=True)+"\n").encode(),
           "transition_v74.py":(HERE/"transition_v74.py").read_bytes(),"status_cycle.py":cycle(get("status_cycle.py")).encode(),
           "transition_v62.py":v62.encode(),"transition_v68.py":v68.encode(),"cutover74.py":cutover.encode()}
    for name,count in (("full170_status.py",1),("cold170_status.py",5),("joint168_status.py",3)):
        text = get(name)
        anchor = repr(OLD.name)+")"
        run.need(text.count(anchor)==count,"changed allowed writer packages in "+name)
        new[name] = text.replace(anchor,repr(OLD.name)+", "+repr(NEW.name)+")").encode()
    # V70 authenticates and removes a live 169 diagnostic for the earlier
    # 169 receivers. Their intermediate 143 handoffs still bind the actual
    # latest head and may see exactly this projection of that same head.
    for version in (64,65,67):
        name = f"transition_v{version}.py"
        body = one(get(name),"    need(checked(head) == fleet,",
                   "    from adjacent169_route import legacy_fleet\n    confirmed = checked(head)\n"
                   "    need(confirmed == fleet or legacy_fleet(confirmed) == fleet,")
        new[name] = body.encode()
    for n,body in new.items():
        if n.endswith(".py"):
            ast.parse(body,filename=n)
    return new


def stage(revision,pin):
    sources = [Path(__file__),HERE/"transition_v74.py",HERE/"fourth_interval.py",HERE/"derive_third162_writer.py",
               HERE/"third_interval.py",HERE/"third_inputs.py",HERE/"second_interval.py",WRITERS/"derive69.py",WRITERS/"derive63.py",
               WRITERS/"derive143_bootstrap_retry.py",COMMON/"following_prepare.py",COMMON/"closed_successor.py"]
    published(revision,sources)
    original = read_package(OLD,SEAL)
    interface,info = contract(pin)
    updates = members(original,interface,info)
    path = run.BASE/"writer-v74-source"
    path.mkdir(mode=0o700,exist_ok=True)
    run.need(path.resolve()==path and path.stat().st_uid==0 and not path.stat().st_mode & 0o077,"unsafe V74 staging")
    entries = {n:(OLD/n,m) for n,(_,m) in original.items() if n!="SHA256SUMS"}
    for n,raw in updates.items():
        persist(path/n,raw)
        entries[n] = path/n,original[n][1] if n in original else 0o444
    persist(path/"SOURCE.json",(json.dumps(dict(revision=revision,files={str(p.relative_to(SCRIPTS.parent)):reference(p)["sha256"] for p in sources},
        interface=interface,predecessor=reference(OLD/"deployment-seal-receipt.json"),changes=sorted(updates)),indent=2)+"\n").encode())
    return seal(NEW,entries,path/"SEAL_PLAN.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("interface_sha")
    args = parser.parse_args()
    print(json.dumps(stage(args.revision,args.interface_sha),sort_keys=True))
