"""Extend the exact V32 whole-roster decision without dropping any prior sublease."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adjacent_inputs as a
from derive_adjacent_writer import INTERFACE

PROVIDERS = a.RT/"epoch162-first-hourly-completion-20261127-v2"
OLD, NEW = (PROVIDERS/f"issued-price-v{n}" for n in (32,33))
PIN = "e13723eb011c032468ec617ef13d79fa73bfea441ad1b169dff3e424debd1297"
REF = dict(path=str(OLD/"deployment-seal-receipt.json"),sha256=PIN)
one = a.shared.exact


def shared_members():
    seal = a.bind(REF)
    a.need(seal["destination"] == str(OLD),"foreign shared price seal")
    files={}
    for m in seal["members"]:
        path = OLD/m["name"]
        s = path.lstat()
        data = path.read_bytes()
        a.need(path.parent == OLD and path.resolve(strict=True)==path and s.st_uid==0 and s.st_nlink==1
               and not s.st_mode & 0o222 and len(data)==m["bytes"] and sha256(data).hexdigest()==m["sha256"]
               and m["name"] not in files,"modified or duplicated V32 member")
        a.need(m["mode"] == "0444", "unexpected V32 member mode")
        files[m["name"]] = data,0o444
    return files


def peer(previous,info):
    # This is the proven split-layout monitor. Only the ownership identities,
    # physical bounds and the predecessor funding source differ for epoch 169.
    a.need(sha256(previous.encode()).hexdigest()=="fe4d0873a4054b1b10a1be6fde3a8e47a22c7b9647be639e65ff1ce052291d2d",
           "different V32 split guard reader")
    begin,end=previous.index("def registered_writer("),previous.index("def sample(peer, fleet, writer, second):")
    text=previous[begin:end].replace("third162_","adjacent169_").replace("status162.py","status169.py")
    text=text.replace("69_998_120","73_245_219").replace("70_004_937","73_252_243")
    text=text.replace("horizon-guard-162-third-replay-20261128-v1","horizon-guard-169-from-73245218-20261128-v1")
    text=text.replace("phase=phase, unit=row","phase=phase, unit=row").replace("epoch=162","epoch=169")
    text=one(text,"layout.profile(36)","layout.profile(44)")
    text=one(text,"SPLIT162_ENROLLMENT.json","ADJACENT169_ENROLLMENT.json")
    text=one(text,'pre["exclusive_166_lease"]','pre["exclusive_169_lease"]')
    text=one(text,'== peer["DONOR"]','== DONOR')
    text=one(text,'== 63*G','== 57*G')
    text=one(text,'== 62*G','== 56*G')
    text=one(text,'resident = peer["resident"](layout, row)','resident = measure_resident(layout,row)')
    text=text.replace("third 162","adjacent 169")
    bindings=dict(INTERFACE=INTERFACE,PROVIDER=info["provider"],READER=info["reader"])
    base=(HERE/"adjacent_account.py").read_text().replace("def resident(layout,row):","def measure_resident(layout,row):")
    return base+"\n"+"".join(f"{key} = {value!r}\n" for key,value in bindings.items())+"\n"+text


def build(revision):
    info=a.bind(INTERFACE)
    files=shared_members()
    history=json.loads(files["SOURCE.json"][0])
    a.need(history["registered_writer_v69"].endswith("/tools-cold168-retry5-failed166-v69-entry146-r2")
           and history["prior_shared_price"]["sha256"]=="0950cbf45b59881553fa21d5fac776b512746481f9e8c8365fe6e00342816f86",
           "different V32 identity")
    counts={n:b.count(bytes(OLD)) for n,(b,_) in files.items() if n.endswith(".py") and bytes(OLD) in b}
    a.need(counts=={"capacity.py":1,"continuation_price.py":1,"successor_price.py":3},"unregistered V32 self references")
    for n in counts:
        b,mode=files[n]
        files[n]=b.replace(bytes(OLD),bytes(NEW)),mode
    def edit(name,old,new):
        b,mode=files[name]
        files[name]=one(b.decode(),old,new).encode(),mode
    files["adjacent169_peer.py"]=peer(files["third162_peer.py"][0].decode(),info).encode(),0o444
    files["adjacent169_price.py"]=(HERE/"adjacent_price.py").read_bytes(),0o444
    edit("capacity.py","'price143_held_tree.py','held143_ram_terminal.py'}",
         "'price143_held_tree.py','held143_ram_terminal.py','adjacent169_peer.py','adjacent169_price.py'}")
    anchor="    peer169 = dict(original169)"
    edit("following_peers.py",anchor,"    adjacent = runpy.run_path(str(Path(__file__).with_name('adjacent169_peer.py')))\n"+anchor)
    edit("following_peers.py",'original169["current"](receiver["predecessor_view"](full))',
         'original169["current"](receiver["predecessor_view"](adjacent["prior_fleet"](peer162,full)))')
    edit("following_peers.py",'original169["recheck"](receiver["predecessor_view"](full), row)',
         'original169["recheck"](receiver["predecessor_view"](adjacent["prior_fleet"](peer162,full)), row)')
    anchor="    third_before = second['third_peer']()['sample'](peer162,fleet,writer,second_before)"
    edit("following_peers.py",anchor,anchor+"\n    adjacent_before = adjacent['sample'](peer162,fleet,writer)")
    edit("following_peers.py","third_162=third_before, writer=writer,","third_162=third_before, adjacent_169=adjacent_before, writer=writer,")
    anchor='    retry169 = receiver["census"](fleet)'
    edit("after_stop.py",anchor,'''    adjacent = runpy.run_path(str(directory/"adjacent169_peer.py"))
    old_fleet = adjacent["prior_fleet"](operations[2],fleet)
    retry169 = receiver["census"](old_fleet)
    new169 = adjacent["live"](first["adjacent_169"])
    core.need(not retry169, "fourth 169 still occupies adjacent compute")
    census169 = new169 or retry169''')
    edit("after_stop.py",'gap170=gap170 or effective,retry169=retry169)','gap170=gap170 or effective,retry169=census169)')
    edit("after_stop.py","    owners = observations(core,fleet,raw,first,gap170 or effective,retry169)",
         "    owners = observations(core,fleet,raw,first,gap170 or effective,census169)")
    edit("after_stop.py","and observations(core,fleet,raw,first,gap170 or effective,retry169)==owners",
         "and observations(core,fleet,raw,first,gap170 or effective,census169)==owners")
    edit("after_stop.py","and receiver['census'](fleet)==retry169","and receiver['census'](old_fleet)==retry169")
    anchor="    fourth['apply'](core,native,fourth_before,fourth_after,first['row169'])"
    edit("after_stop.py",anchor,anchor+'''
    last169 = adjacent["sample"](operations[2],fleet,first["writer"])
    adjacent["apply"](native,first["adjacent_169"],last169)''')
    edit("successor_price.py",'        actual = state("horizon-qualify-169-hourly-retry-20261128-v4.service")',
         f'''        allowed_169 = ("horizon-qualify-169-hourly-retry-20261128-v4.service",{a.UNIT!r})
        need(retry169["unit"] in allowed_169,"unrecognized 169 candidate")
        actual = state(retry169["unit"])''')
    edit("successor_price.py",'and actual["Id"] == retry169["unit"] == "horizon-qualify-169-hourly-retry-20261128-v4.service"',
         'and actual["Id"] == retry169["unit"] and actual["Id"] in allowed_169')
    edit("price143_floor_retry.py",'"independent_retry169", "after_floor170"','"independent_retry169", "adjacent_169_owner", "after_floor170"')
    edit("capacity.py","def complete_roster(prep143, *, hourly170=False, third162=False):",
         "def complete_roster(prep143, *, hourly170=False, third162=False, adjacent169=False):")
    anchor="    third['reserve'](custody,early_third,later_third,third162)"
    edit("capacity.py",anchor,anchor+'''
    adjacent = runpy.run_path(str(STOPPED.parent/"adjacent169_peer.py"))
    adjacent["reserve"](custody,adjacent169)''')
    edit("capacity.py","    return third['protect_live'](protected)","    return adjacent['protect'](third['protect_live'](protected))")
    anchor='    return runpy.run_path(str(STOPPED.parent/"third162_peer.py"))["protect_hourly_170"](result,whole)'
    edit("capacity.py",anchor,anchor.replace("return ","result = ")+'\n    return runpy.run_path(str(STOPPED.parent/"adjacent169_peer.py"))["protect_170"](result,whole)')
    history.update(prior_shared_price=REF,revision=revision,adjacent169_interface=INTERFACE,adjacent169_previous=info["previous"])
    files["SOURCE.json"]=(json.dumps(history,indent=2)+"\n").encode(),0o444
    for n,(data,_) in files.items():
        if n.endswith(".py"):
            ast.parse(data,filename=n)
    return files
