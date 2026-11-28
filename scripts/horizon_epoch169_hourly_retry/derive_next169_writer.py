"""Build V78's successor registration from the exact incumbent V77; activate separately."""
import argparse
import ast
import json
from pathlib import Path
import re
import runpy
import sys

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE),str(HERE.parent/"horizon_epoch170_checkpoint_suffix"),
                str(HERE.parent/"horizon_epoch143_bounded_entry_20261126_v1/writer")]
import derive_next169_price as price
import next169_operator as op
from stage_next_hourly170_cadence import lift
from following_prepare import seal

need, one = op.need, op.one
CADENCE = op.prior.RT/"survivor172-cadence-20261122-v1"
NEW = CADENCE/"tools-cold168-retry5-failed166-v78-entry146"


def module_updates(files):
    info = op.bind(price.INTERFACE)
    pkg = op.bind(info["provider"])
    need(pkg["destination"] == str(op.PKG) and info["reader"] == op.reference(op.PKG/"status169.py")
         and info["field"] == op.FIELD and info["previous_lease"] == op.LEASE and info["previous"] == op.HISTORY,
         "changed successor scope or reader")
    bindings = dict(INTERFACE=price.INTERFACE, SCOPE=info["scope"], OPERATOR=info["provider"], READER=info["reader"],
                    PREVIOUS=op.HISTORY,PREVIOUS_HELD=op.HELD,PREVIOUS_GRANT=op.GRANT,DONOR=op.LEASE)
    prog = files["adjacent169_progress.py"][0].decode()
    old = op.bind(op.INTERFACE)
    prog = prog.replace("from-73245218","from-73252243").replace("73_245_219 <= slot <= 73_252_243","73_252_244 <= slot <= 73_259_077")
    prog = one(prog,old["guard"]["sha256"],op.GUARD["sha256"])
    need(op.UNIT in prog and str(op.RUN/"scratch") in prog and "73_252_244 <= slot <= 73_259_077" in prog,
         "changed old progress-reader layout")
    # Historical 169 terminals used external receipt references. Both compact
    # intervals return a PID1 journal record and use the retained measured size.
    wire = files["split_wire.py"][0].decode()
    wire = one(wire,"row['unit']['Id'] != "+repr(op.prior.UNIT),
               "row['unit']['Id'] not in ("+repr(op.prior.UNIT)+", "+repr(op.UNIT)+")")
    # V70 proves the original fleet digest before handing its projected copy
    # to the older receiver. Only then remove the exact new live 169 row.
    historic = files["transition_v70.py"][0].decode()
    anchor = '    need(checked(head) == fleet, "different fleet while enrolling the adjacent epoch 169 owner")'
    historic = one(historic,anchor,anchor+'\n    import next169_route\n    fleet = next169_route.legacy_fleet(fleet)')
    return {"next169_route.py":(HERE/"next169_writer.py").read_bytes(),
            "next169_bindings.py":"".join(f"{k} = {v!r}\n" for k,v in bindings.items()).encode(),
            "next169_status.py":Path(info["reader"]["path"]).read_bytes(),
            "next169_provider.json":(json.dumps(info["provider"],sort_keys=True)+"\n").encode(),
            "next169_progress.py":prog.encode(),"split_wire.py":wire.encode(),"transition_v70.py":historic.encode()}


def cycle(source):
    body = lift(source,77,78)
    anchor = "                        import adjacent169_route as retry169_status"
    body = one(body,anchor,anchor+'''
                        adjacent169_prior = retry169_status
                        if FAILED166_VERSION >= 78:
                            import next169_route as retry169_status''')
    anchor = "                                    modules += [retry169_status,retry169_status.live,retry169_status.progress,retry169_status.refs]"
    return one(body,anchor,anchor+'''
                                    if FAILED166_VERSION >= 78:
                                        modules += [adjacent169_prior,adjacent169_prior.live,adjacent169_prior.progress,adjacent169_prior.refs]''')


def build(files, old, owner, package, runner):
    updates = module_updates(files)
    updates["status_cycle.py"] = cycle(files["status_cycle.py"][0].decode()).encode()
    transition = (HERE/"transition_v78.py").read_text()
    for key, value in (("V77_OWNER",owner),("V77_PACKAGE",package),("V77_READY",runner["ready"]["sha256"])):
        transition = one(transition,key+" = None",key+" = "+repr(value))
    transition = one(transition,"assembly = prior.assembly",
        "V77_SHA = V77_OWNER['sha256']\nV77_SEAL = V77_PACKAGE['sha256']\nassembly = prior.assembly")
    updates["transition_v78.py"] = transition.encode()
    old_ready = op.bind(runner["ready"])
    ancestry = op.bind(old_ready["old_owner"])
    parent_seal = op.bind(ancestry["ready"])["package"]
    cut = files["cutover77.py"][0].decode()
    cut = re.sub(r"(cutover|[vV])(76|77)",lambda m:m[1]+str(int(m[2])+1),cut)
    for role, name in (("OLD",old.name),("NEW",NEW.name)):
        cut, count = re.subn("^"+role+r" = BASE / [^\n]+",role+" = BASE / "+repr(name),cut,flags=re.M)
        need(count==1,"unrecognized "+role+" writer path")
    cut = one(cut,parent_seal["sha256"],package["sha256"])
    cut = one(cut,old_ready["old_owner"]["sha256"],owner["sha256"])
    updates["cutover78.py"] = cut.encode()
    for name in ("full170_status.py","cold170_status.py","joint168_status.py"):
        code = files[name][0].decode()
        old_reg = repr(old.name)+")"
        need(old_reg in code,"missing V77 writer registration "+name)
        updates[name] = code.replace(old_reg,repr(old.name)+", "+repr(NEW.name)+")").encode()
    return updates


def stage(revision,package_sha,owner_sha):
    paths = [Path(__file__).resolve(),HERE/"next169_writer.py",HERE/"transition_v78.py",HERE/"derive_next169_price.py",
             HERE/"next169_operator.py",HERE.parent/"horizon_epoch170_checkpoint_suffix/stage_next_hourly170_cadence.py"]
    op.published(revision,paths)
    owner = op.pinned(CADENCE/"FAILED166_CADENCE_V77_ACTIVE.json",owner_sha)
    runner = op.bind(owner)
    old = Path(runner["new"]["program"]).parent
    need(old.parent==CADENCE and re.fullmatch(r"tools-cold168-retry5-failed166-v77-entry146(?:-r2)?",old.name),
         "different V77 runtime")
    prior = op.pinned(old/"deployment-seal-receipt.json",package_sha)
    ready = op.bind(runner["ready"])
    need(ready["package"] == prior and ready["adjacent169_interface"] == op.INTERFACE
         and ready["next_hourly170_interface"] and ready["fourth162_interface"],"incomplete incumbent V77")
    package = op.bind(prior)
    files = {}
    for m in package["members"]:
        path = old/m["name"]
        need(path.parent == old and path.resolve(strict=True) == path and m["name"] not in files
             and path.stat().st_uid==0 and not path.stat().st_mode & 0o222 and path.stat().st_nlink==1
             and op.digest(path)==m["sha256"],"changed predecessor writer "+m["name"])
        files[m["name"]] = path.read_bytes(),int(m["mode"],8)
    updates = build(files,old,owner,prior,runner)
    save = runpy.run_path(str(op.PKG/"layout.py"))["save"]
    directory = op.BASE/"writer-v78-source"
    directory.mkdir(exist_ok=True,mode=0o700)
    need(directory.resolve()==directory and directory.stat().st_uid==0 and not directory.stat().st_mode & 0o077,
         "unsafe V78 staging")
    entries = {n:(old/n,mode) for n,(_,mode) in files.items() if n!="SHA256SUMS"}
    for name,data in updates.items():
        if name.endswith(".py"):
            ast.parse(data,filename=name)
        save(directory/name,data)
        entries[name] = directory/name,files[name][1] if name in files else 0o444
    origin = save(directory/"SOURCE.json",dict(source_commit=revision,previous=prior,owner=owner,
        successor=price.INTERFACE,donor=op.LEASE,predecessor=op.HISTORY,updated=sorted(updates)))
    entries["SOURCE.json"] = Path(origin["path"]),0o444
    return seal(NEW,entries,directory/"SEAL_PLAN.json")


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("revision")
    cli.add_argument("v77_package_sha")
    cli.add_argument("v77_active_sha")
    args = cli.parse_args()
    print(json.dumps(stage(args.revision,args.v77_package_sha,args.v77_active_sha),sort_keys=True),flush=True)
