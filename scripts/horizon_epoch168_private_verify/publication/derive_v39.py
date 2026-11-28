"""Rebind V38's incumbent census to the original epoch 172 after replay."""

import ast
import json
from pathlib import Path

from derive_v38 import PRICES, f, read_package

HERE = Path(__file__).resolve().parent
OLD = PRICES / "issued-price-v38"
NEW = PRICES / "issued-price-v39"
PREDECESSOR = "94e5b8e1b77f265c6c3affc1cbac3f1a646931f3e1c2875b4edf55c91f0addcd"
FINAL_SHA = "973e3314cf7666298920d750322675c6c0c0d42dbbf665a089681041ba97f845"


def change(source, old, new):
    f.need(source.count(old) == 1, "different V38 source near " + old[:72])
    return source.replace(old, new)


def members(directory, revision):
    previous = f.reference(OLD / "deployment-seal-receipt.json")
    f.need(previous["sha256"] == PREDECESSOR, "different issued V38 provider")
    files = read_package(OLD, PREDECESSOR)
    for name, (body, mode) in list(files.items()):
        if name.endswith(".py"):
            files[name] = body.replace(bytes(OLD), bytes(NEW)), mode
    helper = (HERE / "finalizing172.py").read_bytes()
    files["finalizing172.py"] = helper, 0o444
    code = files["successor_price.py"][0].decode()
    code = change(code,
        '    peer_rows = fleet["actual_executing_replays"]\n'
        '    need({x["epoch"] for x in peer_rows} == {146,172} and len(peer_rows) == 2, "changed incumbent fleet")',
        '''    peers172 = runpy.run_path(str(Path(__file__).with_name("finalizing172.py")))
    peer_rows = [r for r in fleet["actual_executing_replays"] if r["epoch"] != 172]
    need([r["epoch"] for r in peer_rows] == [146], "changed incumbent fleet")''')
    # runpy is imported at module scope; drop the function import so the
    # preceding call resolves the standard module.
    code = change(code, '    import runpy\n    tail167 =', '''    observed172, guard172, lower172 = peers172["observe"](globals(), fleet, rosters, anchors)
    unit172 = observed172["producer_unit"]
    samples[unit172] = guard172
    loss += max(0, peak(bound(anchors[unit172])) - lower172)
    tail167 =''')
    code = change(code, '    if phase=="live": expected.add(BRIDGE)',
                  '    if observed172["phase"] == "finalizing": expected.add(unit172)\n    if phase=="live": expected.add(BRIDGE)')
    code = change(code, '    after = availability()', '''    checked172, next_guard, lower172_after = peers172["observe"](globals(), fleet, rosters, anchors)
    need(all(checked172[k] == v for k,v in observed172.items() if k != "guard_sample"),
         "original 172 crossed native phase during quote")
    samples[unit172] = next_guard
    incumbent_home += max(0, peak(bound(anchors[unit172])) - min(lower172,lower172_after)) - max(0, peak(bound(anchors[unit172])) - lower172)
    after = availability()''')
    code = change(code, 'closed_167_tail=closed167,guard_samples=samples,',
                  'closed_167_tail=closed167,original_172_accounting=checked172,guard_samples=samples,')
    files["successor_price.py"] = code.encode(), 0o444
    code = files["after_stop.py"][0].decode()
    code = change(code, "    core.need(raw[\"joint\"][\"closed_167_tail\"]", '''    owner172 = raw["joint"]["original_172_accounting"]
    saved172 = native.pop(172, None)
    core.need(not saved172 or (saved172["Id"], saved172["InvocationID"]) == (owner172["producer_unit"], owner172["invocation_id"]),
              "different original 172 survivor")
    core.need(raw["joint"]["closed_167_tail"]''')
    code = change(code, "and set(native) == {146,172} and first", "and set(native) == {146} and first")
    code = change(code, "    if raw['replacement143']:", '''    if owner172["phase"] == "finalizing":
        native[172] = dict(Id=owner172["producer_unit"], InvocationID=owner172["invocation_id"])
    if raw['replacement143']:''')
    files["after_stop.py"] = code.encode(), 0o444
    code = files["capacity.py"][0].decode()
    code = change(code, "'fourth162_price.py','compact169_residency.py'}", "'fourth162_price.py','compact169_residency.py','finalizing172.py'}")
    code = change(code, '    native = Path(\'/var/lib/jetstreamer/horizon_runtime_data/epoch168-exact-publication-v1/admission-tools-v3/publication\')',
                  '''    registered["original_172_accounting"] = base["native"]["raw"]["joint"]["original_172_accounting"]
    native = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch168-exact-publication-v1/admission-tools-v3/publication')''')
    files["capacity.py"] = code.encode(), 0o444
    history = json.loads(files["SOURCE.json"][0])
    history.update(revision=revision, prior_shared_price=previous, original172_archive_finalization=FINAL_SHA)
    files["SOURCE.json"] = (json.dumps(history,indent=2) + "\n").encode(), 0o444
    directory.mkdir(mode=0o700)
    rows = {}
    for name, (blob, mode) in files.items():
        if name.endswith(".py"):
            ast.parse(blob.decode(), filename=name)
        path = directory / name
        path.write_bytes(blob)
        rows[name] = path, mode
    return rows
