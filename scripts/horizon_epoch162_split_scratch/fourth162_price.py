"""Reconcile the fourth epoch 162 receiver against issued V34 and the two completed predecessor images."""
import ast
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import fourth162_writer as writer
from fourth_interval import BASE, OLD_IID, PRIOR_SHA, RT, UNIT, need
from derive_third162_writer import one

OLD = RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v34"
NEW = OLD.with_name("issued-price-v35")
PIN = "ad1f1290a6eb58ebdda44475ea4f69e726d8afb6c53cbd90ea597ee1c8302c27"
INTERFACE_SHA = "6102a47dd71ee77c34cd7992cf268cad14c8f4f8c829699bd14d28582df6572b"


def next_peer(source, interface, info):
    previous = source[source.index("INTERFACE = "):source.index("def registered_writer(")]
    bindings = dict(INTERFACE=interface,PROVIDER=info["provider"],READER=info["reader"])
    source = one(source,previous,"".join(f"{k} = {v!r}\n" for k,v in bindings.items())+"\n\n")
    # Replace endpoints together: the old terminal is the fourth bootstrap.
    tokens = {"third":"fourth","second":"third","69_998_120":"70_004_938","70_004_937":"70_011_988",
              "69_998_119":"70_004_937","c64af2c83b994e299e375b44dee7ce21":OLD_IID,
              "b43c8d3a1df6a2b3aa11c4d64076b59cbea6fe0cb735ed12159fb24034339577":PRIOR_SHA,
              "162-second-replay-20261128-v3":"162-third-replay-20261128-v1",
              "119080492":"120197325","1_662_214_309":"1_727_657_545",
              "728f3c0ef56670b4747dc0ad4dfc5f084e10d793c907ef9c5639ddb22b1c4ac9":"ef72d591464effbab8122bde38214982f295eb32c954310e8c358a0dd5cc78ec"}
    pattern = re.compile("|".join(map(re.escape,sorted(tokens,key=len,reverse=True))))
    source = pattern.sub(lambda m:tokens[m.group()],source)
    source = one(source,"retaining both earlier segments","retaining the earlier segments")
    source = one(source,'archived_failures=earlier["unreleased_predecessor"]','previous=earlier["custody"]')
    source = one(source,'and final["third_162_accounting"]["phase"] == "terminal"','and final["second_162_accounting"]["phase"] == "terminal"')
    source = one(source,'final["third_162_accounting"]["resident_lower_bytes"] == final["realized_162_ram"] == 0',
                 'final["second_162_accounting"]["resident_lower_bytes"] == final["realized_162_ram"] == final["third162_producer_residency"]["realized_bytes"] == 0')
    source = one(source,'quote["prospective_162_interval_two"]["additional_home"] == OUTPUT+CONTROL',
                 'previous["charged"] and previous["additional_home"] == OUTPUT+CONTROL')
    source = one(source,'previous["unreleased_predecessor"] == after["custody"]["archived_failures"]',
                 'previous["previous"] == after["custody"]["previous"]')
    # This file also carries the complete recorded issuer, worker, guard, disk,
    # release and cgroup checks from the sealed predecessor peer.
    return source


def next_price(source):
    source = source.replace("third","fourth").replace("second_terminal","third_terminal")
    source = one(source,"def geometry(whole, phase, held, free, available_ram, drawdown):",
                 "def geometry(whole, phase, held, free, available_ram, drawdown, *, proposal=False):")
    source = one(source,'and accounting["charged"] and accounting["writer_enrolled"]',
                 'and accounting["charged"] and (accounting["writer_enrolled"] or proposal and phase == "prestart" and not accounting["enrollment"])')
    source = one(source,'    runway143 = whole["epoch143_remaining_replay_home"]','''    adjacent = whole["adjacent_169_accounting"]
    runway169 = adjacent["remaining_output"] if adjacent["charged"] and adjacent["phase"] != "terminal" else 0
    need(0 <= runway169 <= 4*G, "unbounded adjacent 169 output")
    runway143 = whole["epoch143_remaining_replay_home"]''')
    source = one(source,'runway143 == raw["guarded_hourly_remaining"]',
                 'runway143 == raw["guarded_hourly_remaining"] - (whole.get("epoch143_dormant_tree") or {}).get("physical_bytes",0)')
    source = one(source,'growth = runway143+runway170+remaining','growth = runway143+runway169+runway170+remaining')
    source = one(source,'whole["guard_floor"]-runway143-runway170','whole["guard_floor"]-runway143-runway169-runway170')
    source = one(source,'whole["epoch143_protected_sibling_floor"]-runway170-remaining',
                 'whole["epoch143_protected_sibling_floor"]-runway169-runway170-remaining')
    source = one(source,'max(raw["guard_floor"],','max(9_470_567_509_909,raw["guard_floor"],')
    source = one(source,'max(shared,whole["epoch143_protected_runway_required_home"],floor+growth)',
                 'max(shared,whole["epoch143_protected_runway_required_home"],whole.get("fourth162_joint_guard_requirement",0),whole.get("adjacent169_joint_guard_requirement",0),floor+growth)')
    return one(source,'protected_170_runway=runway170','protected_169_runway=runway169,protected_170_runway=runway170')


def build(files, interface, info, revision):
    need(interface["sha256"] == INTERFACE_SHA and info["unit"] == UNIT and info["previous"]["sha256"] == PRIOR_SHA,
         "different fourth 162 operator")
    history = json.loads(files["SOURCE.json"][0])
    need(history["third162_interface"]["sha256"] == "0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3"
         and history["prior_shared_price"]["path"] == str(OLD.with_name("issued-price-v33")/"deployment-seal-receipt.json"),
         "missing V34 predecessor")
    counts = {n:blob.count(bytes(OLD)) for n,(blob,_) in files.items() if bytes(OLD) in blob}
    need(counts == {"capacity.py":1,"continuation_price.py":1,"successor_price.py":3},"changed V34 provider identity")
    for n in counts:
        blob,mode = files[n]
        files[n] = blob.replace(bytes(OLD),bytes(NEW)),mode

    def edit(n,old,new):
        data,mode = files[n]
        files[n] = one(data.decode(),old,new).encode(),mode

    files["fourth162_peer.py"] = next_peer(files["third162_peer.py"][0].decode(),interface,info).encode(),0o444
    files["fourth162_price.py"] = next_price(files["third162_price.py"][0].decode()).encode(),0o444
    # Project only the exact new actor out of older 162 readers. The prior
    # third package and its custody evidence remain independently callable.
    old = '''def third_peer():
    return runpy.run_path(str(Path(__file__).with_name("third162_peer.py")))'''
    edit("second162_peer.py",old,'''def fourth_peer():
    return runpy.run_path(str(Path(__file__).with_name("fourth162_peer.py")))


def third_peer():
    prior = runpy.run_path(str(Path(__file__).with_name("third162_peer.py")))
    fourth = fourth_peer()
    def before(peer,fleet):
        return fourth["prior_fleet"](peer,fleet)
    return dict(prior, prior_fleet=lambda peer,fleet: prior["prior_fleet"](peer,before(peer,fleet)),
                sample=lambda peer,fleet,writer,second: prior["sample"](peer,before(peer,fleet),writer,second))''')
    anchor = "    third_before = second['third_peer']()['sample'](peer162,fleet,writer,second_before)"
    edit("following_peers.py",anchor,anchor+"\n    fourth_before = second['fourth_peer']()['sample'](peer162,fleet,writer,third_before)")
    edit("following_peers.py","third_162=third_before, adjacent_169=adjacent_before","third_162=third_before, fourth_162=fourth_before, adjacent_169=adjacent_before")
    prior_owner = "runpy.run_path(str(Path(__file__).with_name('third162_peer.py')))['occupant'](first['second_162'],first['third_162'])"
    next_owner = "runpy.run_path(str(Path(__file__).with_name('fourth162_peer.py')))['occupant'](first['third_162'],first['fourth_162'])"
    for prefix in ("    second = ","native162="):
        edit("after_stop.py",prefix+prior_owner,prefix+next_owner)
    anchor = "    native['third_162_before'] = first['third_162']"
    edit("after_stop.py",anchor,anchor+"\n    native['fourth_162_before'] = first['fourth_162']")
    edit("successor_price.py",'"horizon-qualify-162-third-replay-20261128-v1.service"),',
         '"horizon-qualify-162-third-replay-20261128-v1.service","horizon-qualify-162-fourth-replay-20261128-v1.service"),')
    edit("capacity.py","'adjacent169_peer.py','adjacent169_price.py'}","'adjacent169_peer.py','adjacent169_price.py','fourth162_peer.py','fourth162_price.py'}")
    edit("capacity.py","third162=False, adjacent169=False):","third162=False, adjacent169=False, fourth162=False):")
    anchor = "    third['apply_resident'](base,final,early_third,later_third)"
    edit("capacity.py",anchor,anchor+'''
    fourth = second['fourth_peer']()
    early_fourth = base['native']['fourth_162_before']
    later_fourth = fourth['sample'](peer,fleet,base['writer'],later_third)
    fourth['apply_resident'](base,final,early_fourth,later_fourth)''')
    anchor = "    third['reserve'](custody,early_third,later_third,third162)"
    edit("capacity.py",anchor,anchor+"\n    fourth['reserve'](custody,early_fourth,later_fourth,fourth162)")
    edit("capacity.py","return adjacent['protect'](third['protect_live'](protected))",
         "return adjacent['protect'](fourth['protect_live'](third['protect_live'](protected)))")
    anchor = '    result = runpy.run_path(str(STOPPED.parent/"third162_peer.py"))["protect_hourly_170"](result,whole)'
    edit("capacity.py",anchor,anchor+"\n"+anchor.replace("third162_peer","fourth162_peer"))
    anchor = '    checked = []'
    edit("price143_floor_retry.py",anchor,'''    fourth = quote["fourth_162_accounting"]
    if fourth["phase"] in ("held","bootstrap","worker"):
        owner = fourth["owner"]
        plan = core.bound(owner["guard_plan"])
        core.need(fourth["enrollment"] and fourth["charged"] and plan["minimum_free_bytes"] == fourth["observed_floor"]
                  and plan["unit"] == owner["unit"]["Id"] and plan["invocation_id"] == owner["invocation_id"],
                  "different protected fourth 162 owner")
        guards[plan["unit"]] = plan
'''+anchor)
    # Interval three is required closed whenever this shared price is issued.
    # Adjacent 169's combined guard floors and startup must see interval four.
    for n in ("adjacent169_peer.py","adjacent169_price.py"):
        edit(n,'third=whole["third_162_accounting"]','third=whole["fourth_162_accounting"]')
    edit("adjacent169_price.py",'whole.get("third162_joint_guard_requirement",0)','whole.get("fourth162_joint_guard_requirement",0)')
    history.update(revision=revision,prior_shared_price=dict(path=str(OLD/"deployment-seal-receipt.json"),sha256=PIN),
                   fourth162_interface=interface,fourth162_previous=info["previous"])
    files["SOURCE.json"] = (json.dumps(history,indent=2)+"\n").encode(),0o444
    for n,(data,_) in files.items():
        if n.endswith(".py"):
            ast.parse(data,filename=n)
    return files


def members(revision):
    interface,info = writer.contract(INTERFACE_SHA)
    return build(writer.read_package(OLD,PIN),interface,info,revision)
