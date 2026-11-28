"""Carry the V14 roster through the exact closed epoch 167 tail without reassigning its envelope."""
import ast
from pathlib import Path

import following_prepare as f
from derive_gap_price import one
from derive_third_ram_price import THIRD, SCOPE

BASE = f.ROOT / "epoch162-first-hourly-completion-20261127-v2"
PREVIOUS = BASE / "issued-price-v14"
DEST = BASE / "issued-price-v15"
SEAL = "f119d6aeaa1dcacd2bbd6f9e3d647ecb1e8816bc3e6915a659add40bedd41dd0"


def extend(name, source):
    if name in ("capacity.py","continuation_price.py","successor_price.py"):
        f.need(source.count(str(PREVIOUS)) == (3 if name == "successor_price.py" else 1), "different V14 provider path")
        source = source.replace(str(PREVIOUS),str(DEST))
    if name == "capacity.py":
        source = one(source, "'fourth169_residency.py'", "'fourth169_residency.py','closed167_tail.py'")
        marker = "    return dict(schema='horizon-168-post-assembly-six-owner-price-v1', base_169=base"
        source = one(source, marker, "    runpy.run_path(str(STOPPED.parent/'closed167_tail.py'))['reserve'](vars(core),final,base['native'])\n" + marker)
    elif name == "successor_price.py":
        anchor = '    samples[tail], tail_lower, _ = protected(tail,progress["processes"],progress["guard"]["timer_invocation_id"],\n                                               progress["guard"]["sample"],42*G,"3s",False)'
        source = one(source, anchor, """    import runpy
    tail167 = runpy.run_path(str(Path(__file__).with_name("closed167_tail.py")))["observed"]
    closed167 = tail167(globals(),fleet,progress,progress_ref)
    tail_lower = closed167["occupied_archive_lower_bytes"]""")
        source = one(source, 'for r in peer_rows}|{tail}', 'for r in peer_rows}')
        source = one(source, 'floor = max(incumbent_home+extra_home,max(', 'floor = max(closed167["guard_floor"],incumbent_home+extra_home,max(')
        source = one(source, '    bound(iref)\n    after = availability()',
                     '    bound(iref)\n    need(tail167(globals(),fleet,progress,progress_ref)==closed167,"167 custody changed during fleet pricing")\n    after = availability()')
        source = one(source, 'charged_167=progress_ref,guard_samples=samples,','charged_167=progress_ref,closed_167_tail=closed167,guard_samples=samples,')
    elif name == "continuation_price.py":
        source = one(source,'    tail_resident = anonymous(tail["actor"]["unit"], tail["actor"]["producer_invocation_id"],\n                              [p[:2] for p in tail["processes"]], 42*G)',
                     '''    closed167 = joint["closed_167_tail"]
    need(closed167["record"] == joint["charged_167"] and closed167["invocation"] == tail["actor"]["producer_invocation_id"]
         and closed167["retained_ram"] == 42*G and closed167["released_ram"] == 0, "lost the closed 167 reservation")
    tail_resident = 0''')
    elif name == "after_stop.py":
        source = one(source, "core.need(set(native) == {146,167,172}", """core.need(raw["joint"]["closed_167_tail"]["invocation"] == fleet["current_bounded167_checkpoint_tail"]["actor"]["producer_invocation_id"]
              and fleet["current_bounded167_checkpoint_tail"]["phase"] == "terminal" and set(native) == {146,172}""")
    return source


def members(staging, revision):
    ref = dict(path=str(PREVIOUS/"deployment-seal-receipt.json"),sha256=SEAL)
    previous = f.read(ref)
    f.need(previous["destination"] == str(PREVIOUS), "unknown V14 provider")
    staging.mkdir(mode=0o700)
    files={}
    for member in previous["members"]:
        name=member["name"]
        path=PREVIOUS/name
        f.need(path.parent==PREVIOUS and f.reference(path)["sha256"]==member["sha256"],"V14 source changed "+name)
        if name == "SOURCE.json":
            continue
        source=extend(name,path.read_text())
        ast.parse(source,filename=name)
        dest=staging/name
        dest.write_text(source)
        files[name]=(dest,0o444)
    helper=Path(__file__).with_name("closed167_tail.py")
    files[helper.name]=(helper,0o444)
    history=f.read(f.reference(PREVIOUS/"SOURCE.json"))
    manifest=staging/"SOURCE.json"
    f.save(manifest,dict(history,revision=revision,live_fourth169_v14=ref,closed_167_native_module=f.reference(helper)["sha256"]))
    files[manifest.name]=(manifest,0o444)
    return files
