"""Enroll the qualified 54 GiB fourth 162 receiver on the incumbent writer and donor."""
import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compact_fourth162 as compact
import fourth162_writer as writer
import issue_fourth162 as original

BASE = compact.BASE
FULL, SMALL = compact.ORIGINAL_SHA, "d0aeddbde2ebef0a6a015dfd06e8917c0842cd7701f1b559fdb3887acd88d396"
QUAL = "3dff8feb69707a03ee4dda3c6db45b9977a025839565d762b13cc2bdd6396773"
V35 = original.p.NEW
V36 = V35.with_name("issued-price-v36")
PRICE_PIN = "7da7fe2d6e75ac6ebab4f6eec7d5a9b191c0704557beea1404716bbe0683a3a2"
V74 = writer.NEW
V75 = V74.with_name("tools-cold168-retry5-failed166-v75-entry146")
WRITER_PIN = "9c162fcc08c7c21277ab73c85d9e69f3ef060535bdc9086558e2ad44c5c4c889"
ACTIVE = "4d965c653dee245c39632d10ab050b565c471d4d68440a4225668ddffc565f42"
G = 1 << 30
need, one = compact.need, compact.exact
KERNEL_PEER = writer.run.RT/"epoch169-hourly-admission-20261123-v1/issued-split-v1/peer162.py"
KERNEL_PEER_SHA = "cf69f9a999c4b5ae81ca6d32bd215578164751291e6cde66261ee0b5b18547d0"


def contract():
    full, previous = writer.contract(FULL)
    interface = dict(path=str(compact.INTERFACE), sha256=SMALL)
    info = compact.bind(interface)
    model = compact.bind(info["scope"])
    qualified = compact.bind(info["kernel_qualification"])
    receipt = compact.bind(info["provider"])
    reader = Path(info["reader"]["path"])
    layout = runpy.run_path(str(compact.PACKAGE/"layout.py"))
    profile = layout["profile"](36)
    need(info["full_size_interface"] == full and model["full_size_interface"] == full
         and info["kernel_qualification"]["sha256"] == QUAL and model["kernel_qualification"] == info["kernel_qualification"]
         and qualified["profile"] == profile and profile["producer_memory_max"] == 54*G
         and profile["combined_ram"] == 55*G and profile["scratch_bytes"] == 36*G
         and info["scope"] == compact.reference(compact.SCOPE) and model["previous"] == previous["previous"]
         and all(info[k] == previous[k] for k in ("field","unit","first_slot","last_slot","previous","bootstrap","terminal","gate","guard","guard_validation"))
         and receipt["destination"] == str(compact.PACKAGE) and reader == compact.PACKAGE/"status162.py"
         and info["reader"] == compact.reference(reader) and any(m["name"] == reader.name and m["sha256"] == info["reader"]["sha256"] for m in receipt["members"]),
         "different compact 162 geometry, custody or executable")
    return full, previous, interface, info


def replace_cap(native, first, last, predecessor):
    """Replace once the 62 GiB producer inside its 63 GiB exclusive donor."""
    compare_samples(first, last)
    selected = first["enrolled"]
    need("fourth162_effective_cap" not in native and native["ram_margin"] == native["available_ram"] - native["required_ram"]
         and predecessor["phase"] == "terminal" and predecessor["owner"]["invocation_id"] == first["custody"]["invocation_id"]
         and first["custody"]["terminal"] == TERMINAL and not native["resource_credit_bytes"],
         "unknown or already reconciled fourth 162 producer")
    if selected:
        need((first["phase"] == "precharged" and not first["owner"] or first["owner"] and first["enrollment"])
             and all(0 <= row["resident"] <= 54*G for row in (first,last)),
             "different fourth owner or resident set")
    else:
        need(first["phase"] == "precharged" and not first["owner"] and not first["enrollment"]
             and not any(row["resident"] for row in (first,last)), "unregistered fourth 162 owner")
    replacement = 8*G if selected else 0
    native["fourth162_effective_cap"] = dict(selected=selected, donor_ram=63*G, previous_producer_max=62*G,
        producer_max=62*G-replacement, guard_max=G, replaced_reserved_bytes=replacement,
        previous_required_ram=native["required_ram"], interface=INTERFACE, qualification=QUALIFICATION, resource_credit_bytes=0)
    native["required_ram"] -= replacement
    native["ram_margin"] += replacement


def price_files(revision):
    full, previous, interface, info = contract()
    files = writer.read_package(V35,PRICE_PIN)
    def change(member, before, after):
        raw, mode = files[member]
        files[member] = one(raw.decode(),before,after).encode(),mode
    uses = {n:v.count(bytes(V35)) for n,(v,_) in files.items() if n.endswith(".py") and bytes(V35) in v}
    need(uses == {"capacity.py":1,"continuation_price.py":1,"successor_price.py":3}, "different V35 identity")
    for n in uses:
        raw, mode = files[n]
        files[n] = raw.replace(bytes(V35),bytes(V36)),mode
    peer = "fourth162_peer.py"
    change(peer,"PKG = ROOT/'operator-v1'","PKG = ROOT/'operator-54-v1'")
    for k,old,new in (("INTERFACE",full,interface),("PROVIDER",previous["provider"],info["provider"]),("READER",previous["reader"],info["reader"])):
        change(peer,k+" = "+repr(old),k+" = "+repr(new))
    anchor = '    if "fourth162_reader" not in ready and "fourth162_provider" not in ready:'
    change(peer,anchor,f'''    if ready.get("fourth162_interface") == {full!r}:
        directory = Path(active["new"]["program"]).parent
        legacy = dict(path=str(directory/"fourth162_status.py"),sha256={previous["reader"]["sha256"]!r})
        need(ready["fourth162_provider"] == {previous["provider"]!r} and ready["fourth162_scope"] == {previous["scope"]!r}
             and ready["fourth162_reader"] == legacy and ready["fourth162_predecessor"] == TERMINAL
             and peer["read"](directory/"fourth162_provider.json")[0] == ready["fourth162_provider"], "different V74 registration")
        peer["frozen"](legacy["path"],legacy)
        return False
'''+anchor)
    for before,after in (('profile["combined_ram"] == 63*G','profile["combined_ram"] == 55*G'),
                         ('profile["producer_memory_max"] == 62*G','profile["producer_memory_max"] == 54*G'),
                         ('0 <= v <= 62*G for v in measured','0 <= v <= 54*G for v in measured'),
                         ('producer_cap=62*G)','producer_cap=(54 if before["enrolled"] else 62)*G)'),
                         ('resident = peer["resident"](layout, row)','resident = compact_resident(layout,row)')):
        change(peer,before,after)
    need(compact.digest(KERNEL_PEER) == KERNEL_PEER_SHA, "different 162 population sampler")
    source = KERNEL_PEER.read_text()
    trees = {n.name:ast.get_source_segment(source,n) for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}
    sampler = trees["process_ticks"]+"\n\n"+trees["resident"].replace("def resident(","def compact_resident(")
    need(sampler.count("62*G")==2, "different full-cap population check")
    here = Path(__file__).read_text()
    adjust = ast.get_source_segment(here,next(n for n in ast.parse(here).body if getattr(n,"name",None)=="replace_cap"))
    raw,mode = files[peer]
    files[peer] = raw+b"\n"+sampler.replace("62*G","54*G").encode()+b"\n\n"+adjust.encode()+f'\n\nQUALIFICATION = {info["kernel_qualification"]!r}\n'.encode(),mode
    anchor='    last169 = adjacent["sample"](operations[2],fleet,first["writer"])'
    change("after_stop.py",anchor,'''    compact162 = runpy.run_path(str(directory/"fourth162_peer.py"))
    sample162 = compact162["sample"](operations[2],fleet,first["writer"],first["third_162"])
    compact162["replace_cap"](native,first["fourth_162"],sample162,first["third_162"])
'''+anchor)
    change("successor_price.py",'observed["MemoryMax"] == str(62*G)',
           f'observed["MemoryMax"] == str((54 if native162["unit"]["Id"] == {info["unit"]!r} else 62)*G)')
    change("fourth162_price.py",'ROOT/"operator-v1/layout.py"','ROOT/"operator-54-v1/layout.py"')
    anchor='    scope = layout["scope"]()'
    change("fourth162_price.py",anchor,anchor+f'\n    need(spec["interface"] == {interface!r} and scope["kernel_qualification"] == {info["kernel_qualification"]!r}, "different compact fourth profile")')
    anchor='    former = module["report169"](whole["base_169"]["actor"])'
    change("fourth162_price.py",anchor,'''    cap = whole["base_169"]["native"]["fourth162_effective_cap"]
    need(cap["selected"] and cap["producer_max"] == profile["producer_memory_max"] == 54*G and cap["guard_max"] == G
         and cap["donor_ram"] == whole["donor_compute"]["usable_166_ram"] == 63*G and cap["replaced_reserved_bytes"] == 8*G
         and cap["interface"] == spec["interface"] and cap["qualification"] == scope["kernel_qualification"]
         and not cap["resource_credit_bytes"], "unfunded fourth producer")
'''+anchor)
    meta = json.loads(files["SOURCE.json"][0])
    need(meta["fourth162_interface"] == full, "V35 registered another fourth operator")
    meta.update(revision=revision,prior_shared_price=compact.reference(V35/"deployment-seal-receipt.json"),
                fourth162_full_size_interface=full,fourth162_interface=interface,fourth162_qualification=info["kernel_qualification"],
                population_sampler=dict(path=str(KERNEL_PEER),sha256=KERNEL_PEER_SHA))
    files["SOURCE.json"] = (json.dumps(meta,indent=2)+"\n").encode(),0o444
    return files


def writer_files(revision):
    full, prior, interface, info = contract()
    files = writer.read_package(V74,WRITER_PIN)
    def body(n):
        return files[n][0].decode()
    cycle, command = body("status_cycle.py").split("def main():",1)
    need(cycle.count(", 73, 74)") >= 100,"different writer version matrix")
    cycle = cycle.replace(", 73, 74)",", 73, 74, 75)")
    for line in cycle.splitlines():
        if line.strip().startswith(("74: (transition_v74.", "74: 'fb9db4e77")):
            cycle = one(cycle,line,line+"\n"+line.replace("74:", "75:",1).replace("transition_v74.V73","transition_v75.V74"))
    for anchor,addition in (("import transition_v74","import transition_v75"),("modules.append(transition_v74)","modules.append(transition_v75)")):
        cycle = writer.following_block(cycle,anchor,["if FAILED166_VERSION >= 75:","    "+addition])
    anchor="    elif FAILED166_VERSION == 74:\n        transition_v74.validate(globals(), ready, receipt)"
    cycle = one(cycle,anchor,anchor.replace("74","75")+"\n"+anchor)
    blocks = list(re.finditer(r"^    if FAILED166_VERSION == 74 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+",command,re.M))
    need(len(blocks)==5,"different V74 commands")
    for block in reversed(blocks):
        extra = block[0].replace("== 74","== 75").replace("v74","v75").replace("V74","V75")
        command = command[:block.start()]+extra+command[block.start():]
    cutover = re.sub(r"(cutover|[vV])(73|74)",lambda m:m[1]+str(int(m[2])+1),body("cutover74.py"))
    cutover = one(one(cutover,writer.SEAL,WRITER_PIN),writer.ACTIVE,ACTIVE)
    bindings = dict(INTERFACE=interface,SCOPE=info["scope"],OPERATOR=info["provider"],READER=info["reader"])
    updates = {"status_cycle.py":(cycle+"def main():"+command).encode(),"cutover75.py":cutover.encode(),
               "transition_v75.py":(HERE/"transition_v75.py").read_bytes(),
               "fourth162_status.py":Path(info["reader"]["path"]).read_bytes(),
               "fourth162_bindings.py":"".join(f"{key} = {value!r}\n" for key,value in bindings.items()).encode(),
               "fourth162_provider.json":(json.dumps(info["provider"],sort_keys=True)+"\n").encode()}
    for n,count in (("full170_status.py",1),("cold170_status.py",5),("joint168_status.py",3)):
        ending = repr(V74.name)+")"
        text = body(n)
        need(text.count(ending)==count,"different accepted writers in "+n)
        updates[n] = text.replace(ending,repr(V74.name)+", "+repr(V75.name)+")").encode()
    updates["SOURCE.json"] = (json.dumps(dict(revision=revision,predecessor=compact.reference(V74/"deployment-seal-receipt.json"),
        old_operator=prior["provider"],compact_operator=info["provider"],interface=interface,changed=sorted(updates)),indent=2)+"\n").encode()
    for n,raw in updates.items():
        files[n] = raw,files[n][1] if n in files else 0o444
    return files


def deploy(kind, revision):
    directory, dest = (("shared-price-v36-source",V36) if kind=="price" else ("writer-v75-source",V75))
    full, prior, interface, compact_info = contract()
    files = price_files(revision) if kind=="price" else writer_files(revision)
    files.pop("SHA256SUMS",None)
    layout = runpy.run_path(str(compact.PACKAGE/"layout.py"))
    root = BASE/directory
    root.mkdir(mode=0o700,exist_ok=True)
    need(root.stat().st_uid==0 and root.resolve()==root and not root.stat().st_mode & 0o077,"unsafe deployment staging")
    original_dir = V35 if kind=="price" else V74
    entries = {}
    for n,(raw,mode) in files.items():
        if n.endswith(".py"):
            ast.parse(raw,filename=n)
        path = original_dir/n
        if not path.is_file() or path.read_bytes()!=raw:
            path = root/n
            layout["save"](path,raw,mode)
        entries[n] = path,mode
    result = writer.seal(dest,entries,root/"SEAL_PLAN.json")
    return layout["save"](BASE/("FOURTH_COMPACT_"+kind.upper()+".json"),dict(package=result,interface=interface,
        full_size=full,kernel=compact_info["kernel_qualification"],source_commit=revision,
        predecessor=compact.reference(original_dir/"deployment-seal-receipt.json")),0o400)


def spec(layout, revision):
    issue = layout.pinned(BASE/"FOURTH_COMPACT_PRICE.json")[0]
    full, _, interface, info = contract()
    active = max(writer.ROOT.glob("FAILED166_CADENCE_V*_ACTIVE.json"),key=lambda p:int(p.name.split("_V")[1].split("_")[0]))
    intent, ref = layout.pinned(active)
    ready = layout.bound(intent["ready"])
    directory = original.latest_provider()
    price = directory/"fourth162_price.py"
    current = compact.reference(directory/"deployment-seal-receipt.json")
    package = layout.bound(current)
    preceding_quote = dict(path=str(BASE/"FOURTH_54_PRICE_1795872281650073077.json"),
                           sha256="fe0893edb1dddd9d3fe07b6d4dac17d650ede2b6d36347948bf5599b1521eaac")
    proof = {}
    if directory != V36:
        denied = layout.bound(preceding_quote)
        need(denied["whole_roster"]["package"]==issue["package"] and denied["phase"]=="prestart"
             and denied["home_margin"]==-11_578_705_228 and not denied["fits"]
             and denied["ram_margin"]==13_573_349_376 and denied["held_invocation"] is None,
             "different original 162 decision")
        link = current
        lineage = []
        for version in range(int(directory.name.removeprefix("issued-price-v")),36,-1):
            root = V36.with_name(f"issued-price-v{version}")
            pkg = layout.bound(link)
            need(link["path"]==str(root/"deployment-seal-receipt.json") and pkg["destination"]==str(root),
                 "noncontiguous shared price lineage")
            record, source_ref = layout.pinned(root/"SOURCE.json")
            need(any(m["name"]=="SOURCE.json" and m["sha256"]==source_ref["sha256"] for m in pkg["members"])
                 and record["fourth162_interface"]==interface and record["fourth162_qualification"]==info["kernel_qualification"]
                 and any(m["name"]=="fourth162_peer.py" and m["sha256"]==compact.digest(V36/"fourth162_peer.py") for m in pkg["members"]),
                 "new roster changed the compact 162 provider")
            lineage.append(link)
            link = record["prior_shared_price"]
        need(link==issue["package"] and lineage and ready["next_hourly170_interface"]==record["next_hourly170_interface"],
             "new roster and writer did not inherit V36 and the next 170 registration")
        proof = dict(original_unissued_price=preceding_quote,price_lineage=lineage+[link])
    need(issue["source_commit"]=="ceb07bd403e3f2a39f3e00e75428e97e7fefc929" and issue["interface"]==interface
         and issue["predecessor"]==compact.reference(V35/"deployment-seal-receipt.json") and issue["full_size"]==full
         and package["destination"]==str(directory) and any(m["name"]==price.name and m["sha256"]==compact.digest(price) for m in package["members"])
         and ready["fourth162_provider"]==info["provider"] and ready["fourth162_scope"]==info["scope"]
         and ready["fourth162_reader"]["sha256"]==info["reader"]["sha256"] and ready["fourth162_interface"]==interface
         and ready["fourth162_predecessor"]==info["previous"] and ready["fourth162_kernel_qualification"]==info["kernel_qualification"]
         and ready["epoch167_assembly_owner"] and ready["adjacent169_interface"],"unregistered compact 162 issuer")
    return dict(schema="horizon-private-162-fourth-enrollment-v1",writer_active=ref,operator=info["provider"],
             donor=dict(path=str(layout.DONOR),sha256=layout.DONOR_SHA),capacity=compact.reference(price),whole_roster=current,
             third_terminal=info["previous"],interface=interface,guard_validation=info["guard_validation"],
             bootstrap=info["bootstrap"]["verified_local_custody"],source_commit=revision,kernel_qualification=info["kernel_qualification"],**proof)


def act(mode, revision):
    writer.published(revision,[Path(__file__).resolve(),HERE/"transition_v75.py",HERE/"compact_fourth162.py",HERE/"issue_fourth162.py",
        HERE/"fourth162_writer.py",HERE/"fourth_interval.py",HERE/"derive_third162_writer.py",writer.WRITERS/"derive69.py",
        writer.WRITERS/"derive143_bootstrap_retry.py",writer.COMMON/"following_prepare.py"])
    launch = runpy.run_path(str(compact.PACKAGE/"launch.py"))
    layout = launch["l"]
    need(os.geteuid()==0 and __debug__ and layout.PKG==compact.PACKAGE,"run the sealed 54 GiB issuer")
    with launch["LOCK"].open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if mode in ("price","writer"):
            need(original.latest_provider() in (V35,V36), "superseded price")
            return deploy(mode, revision)
        if mode=="preflight":
            head = compact.reference(max(writer.run.RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns))
            actual = json.loads(subprocess.check_output(["/usr/bin/python3","-IB",str(V75/"status_cycle.py"),"--check-v75-handoff",head["path"],head["sha256"]]))
            need(actual["old_owner"]["sha256"]==ACTIVE and actual["fleet"]==head and actual["package"]==compact.reference(V75/"deployment-seal-receipt.json"),"foreign V75 handoff")
            return layout.save(BASE/("PENDING_V75_"+head["sha256"][:12]+".json"),actual,0o400)
        entry = spec(layout, revision)
        if layout.DATA.exists():
            old, enrolled = layout.pinned(launch["ENROLL"])
            actor, held = layout.pinned(layout.DATA/"HELD_OWNER.json")
            grant, gr = layout.pinned(layout.DATA/"GRANT.json")
            need(old == entry and grant["held"]==held and grant["iid"]==actor["producer_invocation_id"]
                 and grant["writer"]==enrolled and layout.bound(grant["postguard"])["fits"],"different existing compact grant")
            return dict(grant=gr,invocation=grant["iid"])
        pre = layout.save(BASE/("FOURTH_54_PREVIEW_"+str(time.time_ns())+".json"),dict(entry,preview=True),0o400)
        q = runpy.run_path(entry["capacity"]["path"])["quote"]("prestart",None,layout.profile(36),pre)
        proof = layout.save(BASE/("FOURTH_54_PRICE_"+str(time.time_ns())+".json"),q,0o400)
        result = dict(price=proof,fits=q["fits"],home_margin=q["home_margin"],ram_margin=q["ram_margin"],floor=q["guard_floor"])
        if mode=="launch" and q["fits"]:
            launch["validate_quote"](q,"prestart",None,pre)
            result["enrollment"] = layout.save(launch["ENROLL"],entry,0o400)
            result["launch"] = launch["launch"]()
        return result


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("price","writer","preflight","quote","launch"))
    p.add_argument("revision")
    args=p.parse_args()
    print(json.dumps(act(args.mode,args.revision),sort_keys=True),flush=True)
