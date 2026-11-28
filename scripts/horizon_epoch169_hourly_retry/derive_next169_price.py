"""Extend the 172-aware complete roster for the next compact epoch 169 Bank interval."""
import ast
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import next169_operator as operator

need, one = operator.need, operator.one
ROOT = operator.prior.RT/"epoch162-first-hourly-completion-20261127-v2"
OLD, NEW = ROOT/"issued-price-v39", ROOT/"issued-price-v40"
V36 = operator.pinned(ROOT/"issued-price-v36/deployment-seal-receipt.json",
                      "98b3a522347c532c2d9985b6d82ff25b6abfa7d18dc93b24d6213ecdc19ac9e4")
V37 = operator.pinned(ROOT/"issued-price-v37/deployment-seal-receipt.json",
                      "230e3cf5e73d68185bc89e097f760f89d680a11b08b953cca3af401e3374c146")
INTERFACE = operator.pinned(operator.BASE/"INTERFACE_48.json",
                            "31e0ea5a8ade106a209c2ecd2bf2ba9b684903f691aed956f369f201cf766bb2")
V38 = operator.pinned(ROOT/"issued-price-v38/deployment-seal-receipt.json",
                      "94e5b8e1b77f265c6c3affc1cbac3f1a646931f3e1c2875b4edf55c91f0addcd")
REFUSAL = operator.pinned(operator.prior.RT/"epoch162-fourth-replay-20261128-v1/FOURTH_54_PRICE_1795872281650073077.json",
                          "fe0893edb1dddd9d3fe07b6d4dac17d650ede2b6d36347948bf5599b1521eaac")


def functions(source):
    return {node.name: ast.get_source_segment(source,node) for node in ast.parse(source).body
            if isinstance(node,ast.FunctionDef)}


def peer(source, info):
    need(hashlib.sha256(source.encode()).hexdigest() == "fee90f85fb562dd58dcc5a9a24d9c13fb44b883d134c9d51787a9a9309909f1b",
         "changed compact peer")
    old = functions(source)
    bindings = dict(INTERFACE=INTERFACE, PROVIDER=info["provider"], READER=info["reader"],
                    OLD_INTERFACE=operator.INTERFACE, OLD_UNIT=operator.prior.UNIT, OLD_IID=operator.IID,
                    UNIT=operator.UNIT, FIELD=operator.FIELD, TERMINAL=operator.HISTORY, HELD=operator.HELD,
                    GRANT=operator.GRANT, DONOR=operator.LEASE)
    parts = [(HERE/"next169_account.py").read_text(), "G = 1 << 30\nOUTPUT = 4*G\nCONTROL = 64 << 20",
             f"ROOT = Path({str(operator.BASE)!r})\nPKG = ROOT/'operator-48-v1'",
             "\n".join(f"{k} = {v!r}" for k,v in bindings.items())]
    # Reuse the sealed predecessor's guard, live owner, enrollment, residency
    # and output charging paths. Only the new receipt and runtime identities move.
    for name in ("need","prior_fleet","enrollment","measure_resident","sample","live","stable",
                 "reserve","runways","protect","protect_170","registered_writer","sample_retry"):
        chunk = old[name]
        if name == "registered_writer":
            start = chunk.index('    if ready.get("adjacent169_interface")')
            stop = chunk.index('    if "adjacent169_reader" not in ready')
            chunk = chunk[:start]+chunk[stop:]
        chunk = (chunk.replace("adjacent169_", "next169_").replace("adjacent169_joint", "next169_joint")
                 .replace("adjacent_169_", "next_169_").replace("ADJACENT169_ENROLLMENT", "NEXT169_ENROLLMENT")
                 .replace("169-adjacent-enrollment", "169-next-enrollment").replace("from-73245218","from-73252243")
                 .replace("73_245_219","73_252_244").replace("73_252_243","73_259_077"))
        parts.append(chunk)
    return "\n\n".join(parts)+"\n"


def price(source):
    need(hashlib.sha256(source.encode()).hexdigest() == "44769b368fa98c85d33517a0bff7c2fdf595b5eb6720630ca793db5280a6b28e",
         "changed compact price")
    source = (source.replace("adjacent169_", "next169_").replace("adjacent169=", "next169=")
              .replace("adjacent_169_accounting","next_169_accounting").replace("adjacent_169_predecessor","next_169_predecessor")
              .replace("169-adjacent-fleet","169-next-fleet").replace("ADJACENT_PRICE_DECLINED","NEXT_PRICE_DECLINED")
              .replace("from-73245218","from-73252243"))
    return one(source, 'effective["previous_required_ram"]-8*G==native["required_ram"]',
               'effective["previous_required_ram"]-8*G-native["next_169_resident_bytes"]==native["required_ram"]')


def extend(files, directory, revision, predecessor):
    info = operator.bind(INTERFACE)
    need(info["previous_lease"] == operator.LEASE and info["previous"] == operator.HISTORY
         and info["provider"]["sha256"] == "cdc4f838891897a3d7288410c6ed51bc8ef30501725d2d7126bb17f4943d1cbb",
         "different successor operator")
    history = json.loads(files["SOURCE.json"][0])
    need(history["prior_shared_price"] == V38 and history["next_hourly170_interface"]
         and history["original172_archive_finalization"] == "973e3314cf7666298920d750322675c6c0c0d42dbbf665a089681041ba97f845"
         and "finalizing172.py" in files and history["publication168_admission"] and history["fourth162_interface"]["sha256"] ==
         "d0aeddbde2ebef0a6a015dfd06e8917c0842cd7701f1b559fdb3887acd88d396",
         "wrong 168, 170 or 162 registration")
    for name,(data,mode) in list(files.items()):
        if name.endswith(".py") and bytes(directory) in data:
            files[name] = data.replace(bytes(directory),bytes(NEW)),mode

    def edit(name, previous, new):
        raw,mode = files[name]
        files[name] = one(raw.decode(), previous, new).encode(),mode

    files["next169_peer.py"] = peer(files["adjacent169_peer.py"][0].decode(),info).encode(),0o444
    files["next169_price.py"] = price(files["adjacent169_price.py"][0].decode()).encode(),0o444
    follow = "following_peers.py"
    anchor = "    adjacent = runpy.run_path(str(Path(__file__).with_name('adjacent169_peer.py')))"
    edit(follow,anchor,anchor+"\n    nxt = runpy.run_path(str(Path(__file__).with_name('next169_peer.py')))")
    for name,trail in (("current",""),("recheck",", row")):
        anchor = f'original169["{name}"](receiver["predecessor_view"](adjacent["prior_fleet"](peer162,full)){trail})'
        edit(follow,anchor,anchor.replace("peer162,full","peer162,nxt['prior_fleet'](peer162,full)"))
    anchor = "    adjacent_before = adjacent['sample'](peer162,fleet,writer)"
    edit(follow,anchor,"    prior_view = nxt['prior_fleet'](peer162,fleet)\n"+anchor.replace("peer162,fleet","peer162,prior_view")
         +"\n    next_before = nxt['sample'](peer162,fleet,writer)")
    edit(follow,"adjacent_169=adjacent_before, writer=writer","adjacent_169=adjacent_before, next_169=next_before, writer=writer")
    name = "after_stop.py"
    anchor = '    old_fleet = adjacent["prior_fleet"](operations[2],fleet)'
    edit(name,anchor,'''    nxt = runpy.run_path(str(directory/"next169_peer.py"))
    prior_view = nxt["prior_fleet"](operations[2],fleet)
    old_fleet = adjacent["prior_fleet"](operations[2],prior_view)''')
    edit(name,"    census169 = new169 or retry169",'''    next_owner = nxt["live"](first["next_169"])
    core.need(not new169 and first["adjacent_169"]["phase"] == "terminal","169 predecessor compute remains occupied")
    census169 = next_owner or new169 or retry169''')
    anchor = '    last169 = adjacent["sample"](operations[2],fleet,first["writer"])'
    edit(name,anchor,anchor.replace("operations[2],fleet","operations[2],prior_view"))
    anchor = '    adjacent["apply"](native,first["adjacent_169"],last169)'
    edit(name,anchor,anchor+'\n    last_next = nxt["sample"](operations[2],fleet,first["writer"])\n    nxt["apply"](native,first["next_169"],last_next)')
    old_unit = repr(operator.prior.UNIT)
    edit("successor_price.py",old_unit+")",old_unit+", "+repr(operator.UNIT)+")")
    edit("successor_price.py",'retry169["unit"]=='+old_unit,'retry169["unit"] in ('+old_unit+", "+repr(operator.UNIT)+")")
    edit("price143_floor_retry.py",'"adjacent_169_owner", "after_floor170"','"adjacent_169_owner", "next_169_owner", "after_floor170"')
    edit("capacity.py","'compact169_residency.py'","'compact169_residency.py','next169_peer.py','next169_price.py'")
    edit("capacity.py","adjacent169=False, fourth162=False):","adjacent169=False, fourth162=False, next169=False):")
    anchor = '    adjacent["reserve"](custody,adjacent169)'
    edit("capacity.py",anchor,anchor+'''
    nxt = runpy.run_path(str(STOPPED.parent/"next169_peer.py"))
    nxt["checked_reserve"](custody,next169)''')
    anchor = "    finished = adjacent['protect'](fourth['protect_live'](third['protect_live'](protected)))"
    edit("capacity.py",anchor,anchor+"\n    finished = nxt['protect'](finished)")
    anchor = '    return json.loads(proc.stdout)'
    edit("capacity.py",anchor,"    return nxt['final_runway'](json.loads(proc.stdout))")
    anchor = '    return runpy.run_path(str(STOPPED.parent/"adjacent169_peer.py"))["protect_170"](result,whole)'
    edit("capacity.py",anchor,anchor.replace("return ","result = ")+"\n"+anchor.replace("adjacent169_","next169_"))
    anchor = '    need(0 <= runway169 <= 4*G, "unbounded adjacent 169 output")'
    edit("fourth162_price.py",anchor,'''    following = whole["next_169_accounting"]
    need(adjacent["phase"] == "terminal" and runway169 == 0, "overlapping 169 bookings")
    runway169 = following["remaining_output"] if following["charged"] and following["phase"] != "terminal" else 0
'''+anchor)
    edit("fourth162_price.py",'whole.get("adjacent169_joint_guard_requirement",0),floor+growth',
         'whole.get("adjacent169_joint_guard_requirement",0),whole.get("next169_joint_guard_requirement",0),floor+growth')
    history.update(revision=revision, prior_shared_price=predecessor, next169_interface=INTERFACE,
                   next169_predecessor=operator.HISTORY, next169_donor=operator.LEASE, fourth162_original_unissued_price=REFUSAL)
    files["SOURCE.json"] = (json.dumps(history,indent=2)+"\n").encode(),0o444
    for name,(body,_) in files.items():
        if name.endswith(".py"):
            ast.parse(body,filename=name)
    return files
