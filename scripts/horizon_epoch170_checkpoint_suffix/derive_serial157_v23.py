"""Lift V22 intact and delegate the lane-j serial holder to its native 157 operator."""
import json
from pathlib import Path
import sys

import following_prepare as f
from derive_ram170_writer import once

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent / "horizon_epoch143_bounded_entry_20261126_v1/writer"))
from derive143_bootstrap_retry import read_package

OLD = f.ROOT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v22"
NEW = OLD.with_name("issued-price-v23")
PREVIOUS = dict(path=str(OLD / "deployment-seal-receipt.json"),
                sha256="e8d13381e4089ab239c9dd1b2bf5025fc297ab1f9ba654e3fc8f1aeaf2c202ee")


def members(stage, revision):
    files = read_package(OLD, PREVIOUS["sha256"])
    for name,count in (("capacity.py",1),("continuation_price.py",1),("successor_price.py",3)):
        source, mode = files[name]
        f.need(source.count(bytes(OLD)) == count, "different V22 self bindings in " + name)
        files[name] = source.replace(bytes(OLD),bytes(NEW)),mode
    src,mode = files["capacity.py"]
    source = once(src.decode(), "'second143_terminal.py'}","'second143_terminal.py','serial157_operator.py'}")
    source = once(source, "    return after_ram['account'](merged, core, STOPPED.parent)", """    booked = after_ram['account'](merged, core, STOPPED.parent)
    return runpy.run_path(str(STOPPED.parent / 'serial157_operator.py'))['account'](booked, core)""")
    files["capacity.py"] = (source.encode(),mode)
    src,mode = files["following_peers.py"]
    anchor = "    if any(name.startswith('horizon-closed157-park-lanej-') for name in units):"
    code = once(src.decode(),anchor,"""    if any(name.startswith(('horizon-closed157-retire-lanej-', 'horizon-closed157-restore-lanej-')) for name in units):
        callback = runpy.run_path(str(Path(__file__).with_name('serial157_operator.py')))
        return callback['holder'](core,units)
""" + anchor)
    files["following_peers.py"] = (code.encode(),mode)
    helper = HERE / "serial157_operator.py"
    files[helper.name] = (helper.read_bytes(),0o444)
    history = json.loads(files["SOURCE.json"][0])
    history.update(revision=revision, prior_shared_price=PREVIOUS)
    files["SOURCE.json"] = ((json.dumps(history,indent=2)+"\n").encode(),0o444)
    stage.mkdir(mode=0o700)
    result = {}
    for name,(data,mode) in files.items():
        dest = stage/name
        dest.write_bytes(data)
        result[name] = dest, mode
    return result
