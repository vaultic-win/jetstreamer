"""Add one native epoch 170 successor to a sealed shared price lineage."""
import ast
import json
from pathlib import Path

from derive_serial157_v23 import f, once, read_package
from next_hourly170 import ROOT, UNIT

HERE = Path(__file__).resolve().parent


def members(stage, revision, old, prior_seal, scope, observer):
    old = Path(old)
    number = int(old.name.removeprefix("issued-price-v"))
    f.need(number >= 35 and old.name == f"issued-price-v{number}","unknown shared anchor")
    new = old.with_name(f"issued-price-v{number+1}")
    files = read_package(old,prior_seal)
    history = json.loads(files["SOURCE.json"][0])
    proof = f.read(scope)
    f.need(scope["path"] == str(ROOT/"NEXT_HOURLY_WRITER_INTERFACE.json")
           and proof["expected_producer_unit"] == UNIT
           and observer["path"] == str(ROOT/"observer-modules-v1/deployment-seal-receipt.json")
           and f.read(observer)["destination"] == str(ROOT/"observer-modules-v1")
           and history["after_floor170_interface"] == proof["previous_interface"]
           and "next_hourly170_roster.py" not in files,"different predecessor, observer or price lineage")
    for name,(body,mode) in list(files.items()):
        if name.endswith(".py") and bytes(old) in body:
            files[name] = body.replace(bytes(old),bytes(new)),mode

    def edit(name, old, new):
        body,mode = files[name]
        files[name] = once(body.decode(),old,new).encode(),mode

    edit("after_stop.py","    effective = active_hourly or live_successor",'''    next_hourly_ops = runpy.run_path(str(directory/'next_hourly170_roster.py'))
    next_hourly = next_hourly_ops['owner'](core,fleet)
    active_next_hourly = next_hourly if next_hourly and next_hourly['phase'] != 'terminal' else None
    core.need(not next_hourly or hourly and hourly['phase'] == 'terminal'
              and not live_successor,'two interval owners claim epoch 170')
    effective = active_next_hourly or active_hourly or live_successor''')
    edit("after_stop.py","    hourly_before = residency['sample'](core,hourly_view,hourly)",'''    hourly_before = residency['sample'](core,hourly_view,hourly)
    next_view = {'receiver': next_hourly_ops['receiver']}
    next_hourly_before = residency['sample'](core,next_view,next_hourly)''')
    edit("after_stop.py","    native['after_floor170'] = hourly",
         "    native['after_floor170'] = hourly\n    native['next_hourly170'] = next_hourly")
    edit("after_stop.py","    hourly170['apply_residency'](core,native,residency,hourly_before,hourly_after)",'''    hourly170['apply_residency'](core,native,residency,hourly_before,hourly_after)
    next_hourly_after = residency['sample'](core,next_view,next_hourly)
    next_hourly_ops['apply_residency'](core,native,residency,next_hourly_before,next_hourly_after)''')
    old_check = "    core.need(hourly170['stable'](hourly170['owner'](core,fleet,directory))==hourly170['stable'](hourly)"
    edit("after_stop.py",old_check,old_check+"""
              and next_hourly_ops['stable'](next_hourly_ops['owner'](core,fleet))==next_hourly_ops['stable'](next_hourly)""")
    writer = "            writer_package = 'tools-cold168-retry5-failed166-v69-entry146-r2'"
    edit("following_peers.py",writer,writer+"""
        elif version == 76:
            writer_package = 'tools-cold168-retry5-failed166-v76-entry146-r2'""")
    paths = "    dirs.append(writer / 'tools-cold168-retry5-failed166-v69-entry146-r2')"
    edit("following_peers.py",paths,paths+"\n    dirs.append(writer / 'tools-cold168-retry5-failed166-v76-entry146-r2')")
    edit("price143_floor_retry.py",'"adjacent_169_owner", "after_floor170")',
         '"adjacent_169_owner", "after_floor170", "next_hourly170")')
    edit("price143_floor_retry.py",'newer = native.get("after_floor170")',
         'newer = native.get("next_hourly170") or native.get("after_floor170")')
    old_tree = '        if gap170 and gap170["unit"] == "horizon-qualify-170-from-73766969-ram-20261128-v1.service" and gap170["phase"] in ("worker","bootstrap"):'
    edit("successor_price.py",old_tree,f'''        if gap170 and gap170["unit"] == "{UNIT}" and gap170["phase"] in ("worker","bootstrap"):
            need(phase == "start" and live_tree_bounds is None, "mixed guarded 170 scopes")
            module = runpy.run_path(str(Path(__file__).with_name("next_hourly170_roster.py")))
            after_ram_tree = module["guarded_bounds"](gap170,TREE,bound,state,cmd,Path(__file__).parent)
            old_lower, old_upper = after_ram_tree["bounds"]
        el'''+old_tree.lstrip())
    old_actor = '        if gap170["unit"] == "horizon-qualify-170-from-73766969-ram-20261128-v1.service":'
    edit("successor_price.py",old_actor,
         '        if gap170["unit"] in ("horizon-qualify-170-from-73766969-ram-20261128-v1.service", '
         + repr(UNIT) + "):")
    a = "'after_floor170_price.py',"
    edit("capacity.py",a,a+"'next_hourly170_roster.py',")
    keep = "    return adjacent['protect'](fourth['protect_live'](third['protect_live'](protected)))"
    edit("capacity.py",keep,'''    finished = adjacent['protect'](fourth['protect_live'](third['protect_live'](protected)))
    return runpy.run_path(str(STOPPED.parent/'next_hourly170_roster.py'))['register'](core,finished)''')

    template = (HERE/"next_hourly170_roster.py").read_text()
    template = once(template,"SCOPE = None","SCOPE = " + repr(scope))
    template = once(template,"RECEIVER = None","RECEIVER = " + repr(observer))
    files["next_hourly170_roster.py"] = template.encode(),0o444
    history.update(revision=revision,prior_shared_price=dict(path=str(old/"deployment-seal-receipt.json"),sha256=prior_seal),
                   next_hourly170_interface=scope,next_hourly170_receiver=observer)
    files["SOURCE.json"] = (json.dumps(history,indent=2)+"\n").encode(),0o444
    for name,(content,_) in files.items():
        if name.endswith(".py"):
            ast.parse(content,filename=name)
    stage = Path(stage)
    stage.mkdir(mode=0o700)
    for name,(content,_) in files.items():
        (stage/name).write_bytes(content)
    return new,{name:(stage/name,mode) for name,(_,mode) in files.items()}
