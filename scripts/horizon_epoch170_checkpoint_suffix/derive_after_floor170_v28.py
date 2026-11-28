"""Add the hourly 170 producer to the accepted V27 census and substitute its paid working set."""
import ast
import json
from pathlib import Path

from derive_serial157_v23 import f, once, read_package

HERE = Path(__file__).resolve().parent
OLD = f.ROOT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v27"
NEW = OLD.with_name("issued-price-v28")
V26 = dict(path=str(OLD.with_name("issued-price-v26")/"deployment-seal-receipt.json"),
           sha256="07ae0724f9b912604f56827b27a8236e16b93b20b6b7790c14063511dd6458f6")
ROOT = f.ROOT/"epoch170-from-73766969-ram-20261128-v1"
UNIT = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"


def members(stage, revision, prior_seal, scope, receiver):
    previous = dict(path=str(OLD/"deployment-seal-receipt.json"),sha256=prior_seal)
    files = read_package(OLD,prior_seal)
    history = json.loads(files["SOURCE.json"][0])
    f.need(history["prior_shared_price"] == V26 and "reclamation_price.py" in files,"unregistered V27 predecessor")
    f.need(scope["path"] == str(ROOT/"AFTER_FLOOR_WRITER_INTERFACE.json") and f.read(scope)["expected_producer_unit"] == UNIT
           and receiver["path"] == str(ROOT/"observer-modules-v1/deployment-seal-receipt.json")
           and f.read(receiver)["destination"] == str(ROOT/"observer-modules-v1"),"unregistered 170 receiver")
    counts = {name:content.count(bytes(OLD)) for name,(content,_) in files.items() if bytes(OLD) in content}
    f.need(counts == {"capacity.py":1,"continuation_price.py":1,"successor_price.py":3},"different V27 self bindings")
    for name in counts:
        source,mode = files[name]
        files[name] = source.replace(bytes(OLD),bytes(NEW)),mode

    def edit(name, old, new):
        content,mode = files[name]
        files[name] = once(content.decode(),old,new).encode(),mode

    edit("capacity.py","'price143_floor_retry.py','reclamation_price.py'}","'price143_floor_retry.py','reclamation_price.py','after_floor170_price.py'}")
    edit("capacity.py","def complete_roster(prep143):","def complete_roster(prep143, *, hourly170=False):")
    edit("capacity.py","    booked = after_ram['account'](merged, core, STOPPED.parent)",'''    replacement = runpy.run_path(str(STOPPED.parent/'after_floor170_price.py'))
    selected = replacement['select'](core,merged,STOPPED.parent,hourly170)
    booked = after_ram['account'](merged,core,STOPPED.parent,successor=selected)
    if selected:
        need(booked['after_ram170_accounting']['phase'] == 'booked', 'there is no 170 disk booking to replace')
        booked['after_ram170_accounting']['superseded_by'] = replacement['SCOPE']''')
    data,mode = files["capacity.py"]
    files["capacity.py"] = data + b'''
def after_floor170_roster(phase):
    if phase not in ("start","held"):
        raise ValueError("unregistered hourly 170 phase")
    whole = complete_roster(False,hourly170=phase == "start")
    core = runpy.run_path(str(STOPPED.parent/"continuation_price.py"))["prior"]
    return runpy.run_path(str(STOPPED.parent/"after_floor170_price.py"))["candidate"](core,whole,phase)
''',mode
    edit("after_ram170_admission.py","def account(whole, core, directory):","def account(whole, core, directory, *, successor=False):")
    edit("after_ram170_admission.py","    if intent:\n        whole.update(rotated(whole))",
         "    if intent and not successor:\n        whole.update(rotated(whole))")
    edit("after_ram170_admission.py","home_increment=28*G if intent else 0,ram_delta=-8*G if intent else 0,",
         "home_increment=28*G if intent and not successor else 0,ram_delta=-8*G if intent and not successor else 0,")
    anchor = "    stopped_ref = stopped(core,current,fleet,successor)"
    edit("after_stop.py",anchor,'''    hourly170 = runpy.run_path(str(directory/'after_floor170_price.py'))
    hourly = hourly170['owner'](core,fleet,directory)
    active_hourly = hourly if hourly and hourly['phase'] != 'terminal' else None
    core.need(not (active_hourly and live_successor), 'two successor 170 owners')
    effective = active_hourly or live_successor
'''+anchor)
    edit("after_stop.py","    core.need(not (gap170 and successor), 'two 170 owners claim the reservation')",
         "    core.need(not (gap170 and (successor or hourly)), 'two 170 owners claim the reservation')")
    for anchor in ("gap170=gap170 or live_successor,retry169=retry169)",
                   "owners = observations(core,fleet,raw,first,gap170 or live_successor,retry169)",
                   "and observations(core,fleet,raw,first,gap170 or live_successor,retry169)==owners"):
        edit("after_stop.py",anchor,anchor.replace("gap170 or live_successor","gap170 or effective"))
    edit("after_stop.py","    native['after_ram170'] = successor",
         "    native['after_ram170'] = successor\n    native['after_floor170'] = hourly")
    anchor = "    resident_before = residency['sample'](core, live, gap170)"
    edit("after_stop.py",anchor,anchor + """
    hourly_view = {'receiver': lambda actual: hourly170['receiver'](actual,directory)}
    hourly_before = residency['sample'](core,hourly_view,hourly)""")
    anchor = "    residency['apply'](core, native, resident_before, resident_after)"
    edit("after_stop.py",anchor,anchor + """
    hourly_after = residency['sample'](core,hourly_view,hourly)
    hourly170['apply_residency'](core,native,residency,hourly_before,hourly_after)""")
    edit("after_stop.py","    core.need(receiver['census'](fleet)==retry169",
         "    core.need(hourly170['stable'](hourly170['owner'](core,fleet,directory))==hourly170['stable'](hourly)\n              and receiver['census'](fleet)==retry169")
    anchor = '        if gap170 and gap170["unit"] == "horizon-qualify-170-from-73766969-20261127-v1.service"'
    edit("successor_price.py",anchor,'''        if gap170 and gap170["unit"] == "''' + UNIT + '''" and gap170["phase"] in ("worker","bootstrap"):
            need(phase == "start" and live_tree_bounds is None, "mixed prospective and issued 170 bounds")
            module = runpy.run_path(str(Path(__file__).with_name("after_floor170_price.py")))
            after_ram_tree = module["guarded_bounds"](gap170,TREE,bound,state,cmd,Path(__file__).parent)
            old_lower, old_upper = after_ram_tree["bounds"]
        el'''+anchor.lstrip())
    anchor = '        actual = state(unit)\n        need(Path(__file__).resolve().parent'
    edit("successor_price.py",anchor,'        if gap170["unit"] == "'+UNIT+'":\n            unit = gap170["unit"]\n'+anchor)
    edit("price143_floor_retry.py",'("after_ram170", "ram_gap170", "independent_retry169")',
         '("after_ram170", "ram_gap170", "independent_retry169", "after_floor170")')
    edit("price143_floor_retry.py","    floor = max(9_470_567_509_909,",
         "    quote['observed_sibling_guard_floors'] = list(checked)\n    floor = max(9_470_567_509_909,")
    anchor = "        floor = guards[unit]"
    edit("price143_floor_retry.py",anchor,'''        newer = native.get("after_floor170")
        if epoch == 170 and newer and newer["phase"] == "held" and not newer["guard_plan"]:
            core.need(newer["unit"] == unit and newer["invocation"] == invocation and not newer["release"],
                      "unprotected 170 is not the registered closed gate")
            continue
'''+anchor)
    price = once((HERE/"after_floor170_price.py").read_text(),"SCOPE_DIGEST = None","SCOPE_DIGEST = "+repr(scope["sha256"]))
    price = once(price,"RECEIVER_DIGEST = None","RECEIVER_DIGEST = "+repr(receiver["sha256"]))
    files["after_floor170_price.py"] = price.encode(),0o444
    history.update(revision=revision,prior_shared_price=previous,after_floor170_interface=scope,after_floor170_receiver=receiver)
    files["SOURCE.json"] = (json.dumps(history,indent=2)+"\n").encode(),0o444
    stage.mkdir(mode=0o700)
    rows = {}
    for name,(content,mode) in files.items():
        if name.endswith(".py"):
            ast.parse(content,filename=name)
        path = stage/name
        path.write_bytes(content)
        rows[name] = path,mode
    return rows
