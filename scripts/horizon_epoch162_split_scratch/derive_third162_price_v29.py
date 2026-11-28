"""Extend the sealed V28 roster with third-interval 162 custody, native census and pricing."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/"horizon_epoch170_checkpoint_suffix"))
from derive_serial157_v23 import f, once, read_package
from third_inputs import BASE, PREVIOUS, PREVIOUS_SHA

OLD = f.ROOT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v28"
NEW = OLD.with_name("issued-price-v29")
PEER_SHA = "2cdcdf1611223595f51bc022ca626168afa27726ab767a59aae754238af7e606"


def peer_source(old, interface, info):
    """Reuse the complete, previously issued guard, held, release and image checks."""
    before = old[old.index("def registered_writer("):old.index("def sample(peer")]
    capture = old[old.index("def sample_retry("):old.index("def apply(")]
    capture = once(capture,'interface["closure"] == CLOSURE','interface["previous"] == TERMINAL')
    capture = once(capture,'69_991_077','69_998_120')
    capture = once(capture,'69_998_119','70_004_937')
    capture = once(capture,'horizon-guard-162-second-replay-20261128-v3','horizon-guard-162-third-replay-20261128-v1')
    before = before.replace("second162_reserved_", "third162_")
    before = once(before,'and ready["package"]["path"]', 'and ready["third162_interface"] == INTERFACE and ready["third162_predecessor"] == TERMINAL\n'
                  '                 and ready["package"]["path"]')
    constants = dict(INTERFACE=interface,PROVIDER=info["provider"],READER=info["reader"])
    bindings = "".join(f"{k} = {v!r}\n" for k,v in constants.items())
    text = (HERE/"third162_account.py").read_text()
    return text+"\n\nimport runpy\nPKG = ROOT/'operator-v1'\n"+bindings+"\n\n"+(before+capture).replace("second 162","third 162")+'''
def sample(peer, fleet, writer, second):
    previous = custody(peer,second)
    booked = enrollment(peer,INTERFACE)
    row = sample_retry(peer,fleet,writer)
    need(not booked or row["enrolled"], "booked third 162 is absent from the active writer")
    return dict(row,enrollment=booked,custody=previous)
'''


def build(files, previous, interface, info, revision):
    history = json.loads(files["SOURCE.json"][0])
    f.need(previous["path"] == str(OLD/"deployment-seal-receipt.json")
           and history["prior_shared_price"]["path"] == str(OLD.with_name("issued-price-v27")/"deployment-seal-receipt.json")
           and {"reclamation_price.py","after_floor170_price.py"} <= files.keys()
           and sha256(files["second162_peer.py"][0]).hexdigest() == PEER_SHA, "unqualified V28 predecessor")
    counts = {k:data.count(bytes(OLD)) for k,(data,_) in files.items() if bytes(OLD) in data}
    f.need(counts == {"capacity.py":1,"continuation_price.py":1,"successor_price.py":3},"different V28 self references")
    for key in counts:
        source,mode = files[key]
        files[key] = source.replace(bytes(OLD),bytes(NEW)),mode

    def edit(name, old, new):
        blob,mode = files[name]
        files[name] = once(blob.decode(),old,new).encode(),mode

    f.need(info["previous"] == dict(path=str(PREVIOUS),sha256=PREVIOUS_SHA)
           and info["unit"] == "horizon-qualify-162-third-replay-20261128-v1.service"
           and info["field"] == "current_private162_third_hourly" and (info["first_slot"],info["last_slot"]) == (69_998_120,70_004_937)
           and info["provider"]["path"] == str(BASE/"operator-v1/deployment-seal-receipt.json")
           and info["reader"]["path"] == str(BASE/"operator-v1/status162.py") and interface["path"] == str(BASE/"INTERFACE.json"),
           "unknown third 162 interval, provider or reader")
    files["third162_peer.py"] = peer_source(files["second162_peer.py"][0].decode(),interface,info).encode(),0o444
    files["third162_price.py"] = (HERE/"third162_price.py").read_bytes(),0o444

    # Retain the second reader and the nested validators of the two unreleased
    # gates. Only project out the authenticated third row when invoking them.
    edit("second162_peer.py","def predecessor_view(peer, fleet):",'''def third_peer():
    return runpy.run_path(str(Path(__file__).with_name("third162_peer.py")))


def predecessor_view(peer, fleet):
    return second_view(peer, third_peer()["prior_fleet"](peer,fleet))


def second_view(peer, fleet):''')
    edit("second162_peer.py","return dict(sample_retry(peer, fleet, writer), unreleased_predecessor=history)",
         'return dict(sample_retry(peer, third_peer()["prior_fleet"](peer,fleet), writer), unreleased_predecessor=history)')
    anchor = "    second_before = second['sample'](peer162, fleet, writer)"
    edit("following_peers.py",anchor,anchor+"\n    third_before = second['third_peer']()['sample'](peer162,fleet,writer,second_before)")
    edit("following_peers.py","second_162=second_before, writer=writer","second_162=second_before, third_162=third_before, writer=writer")
    occupied = "runpy.run_path(str(Path(__file__).with_name('third162_peer.py')))['occupant'](first['second_162'],first['third_162'])"
    edit("after_stop.py","    second = first['second_162']['owner']","    second = "+occupied)
    edit("after_stop.py","native162=first['second_162']['owner']","native162="+occupied)
    anchor = "    native['second_162_before'] = first['second_162']"
    edit("after_stop.py",anchor,anchor+"\n    native['third_162_before'] = first['third_162']")
    edit("successor_price.py",'and native162["unit"]["Id"] == "horizon-qualify-162-second-replay-20261128-v3.service",',
         'and native162["unit"]["Id"] in ("horizon-qualify-162-second-replay-20261128-v3.service",'
         '"horizon-qualify-162-third-replay-20261128-v1.service"),')
    edit("capacity.py","'reclamation_price.py','after_floor170_price.py'}",
         "'reclamation_price.py','after_floor170_price.py','third162_peer.py','third162_price.py'}")
    edit("capacity.py","def complete_roster(prep143, *, hourly170=False):","def complete_roster(prep143, *, hourly170=False, third162=False):")
    anchor = "    second['apply'](need, base, final, before, after)"
    edit("capacity.py",anchor,anchor+'''
    third = second['third_peer']()
    later_third = third['sample'](peer,fleet,base['writer'],after)
    early_third = base['native']['third_162_before']
    third['compare_samples'](early_third,later_third)''')
    anchor = "    return runpy.run_path(str(STOPPED.parent / 'price143_floor_retry.py'))['protect'](core, custody)"
    edit("capacity.py",anchor,"    third['reserve'](custody,early_third,later_third,third162)\n"+
         anchor.replace("return ","protected = ")+"\n    return third['protect_live'](protected)")
    anchor = '    return runpy.run_path(str(STOPPED.parent/"after_floor170_price.py"))["candidate"](core,whole,phase)'
    edit("capacity.py",anchor,anchor.replace("return ","result = ")+
         '\n    return runpy.run_path(str(STOPPED.parent/"third162_peer.py"))["protect_hourly_170"](result,whole)')
    anchor = "    checked = []"
    edit("price143_floor_retry.py",anchor,'''    third = quote["third_162_accounting"]
    if third["phase"] in ("held","bootstrap","worker"):
        owner = third["owner"]
        plan = core.bound(owner["guard_plan"])
        core.need(third["enrollment"] and third["charged"] and plan["minimum_free_bytes"] == third["observed_floor"]
                  and plan["unit"] == owner["unit"]["Id"] and plan["invocation_id"] == owner["invocation_id"],
                  "different protected third 162 owner")
        guards[plan["unit"]] = plan
'''+anchor)
    history.update(revision=revision,prior_shared_price=previous,third162_interface=interface,third162_previous=info["previous"])
    files["SOURCE.json"] = (json.dumps(history,indent=2)+"\n").encode(),0o444
    for name,(data,_) in files.items():
        if name.endswith(".py"):
            ast.parse(data,filename=name)
    return files


def members(stage, revision, prior_seal, interface):
    ids = f.read(interface)
    scope = f.read(ids["scope"])
    previous = dict(path=str(OLD/"deployment-seal-receipt.json"),sha256=prior_seal)
    f.need(scope["previous"] == ids["previous"] and scope["position_count"] == 6_818
           and f.read(ids["provider"])["destination"] == str(BASE/"operator-v1")
           and f.reference(Path(ids["reader"]["path"])) == ids["reader"], "different sealed third 162 operator")
    files = build(read_package(OLD,prior_seal),previous,interface,ids,revision)
    stage.mkdir(mode=0o700, exist_ok=True)
    f.need(stage.resolve(strict=True) == stage and stage.stat().st_uid == 0 and not stage.stat().st_mode & 0o077,
           "untrusted shared price staging")
    save = runpy.run_path(str(BASE/"operator-v1/layout.py"))["save"]
    rows = {}
    for name,(data,mode) in files.items():
        path = stage/name
        save(path,data,mode)
        rows[name] = path,mode
    return rows
