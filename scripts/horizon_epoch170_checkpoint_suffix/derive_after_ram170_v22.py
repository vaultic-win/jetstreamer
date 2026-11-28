"""Derive the complete after-RAM 170 admission from the exact V21 shared roster."""
import ast
import json
from pathlib import Path

import following_prepare as prep
from derive_after_ram170_price import extend
from derive_ram170_writer import once

OLD = prep.ROOT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v21"
NEW = OLD.with_name("issued-price-v22")
PREVIOUS = dict(path=str(OLD / "deployment-seal-receipt.json"),
                sha256="44c7ba8eee3623cbda920288714053f89d8fb7456e3c8bf9b2119164f3f05ac4")


def members(stage, revision):
    sealed = prep.read(PREVIOUS)
    prep.need(sealed["destination"] == str(OLD), "different V21 owner")
    files = {}
    for item in sealed["members"]:
        name = item["name"]
        path = OLD / name
        prep.need(path.parent == OLD and path.resolve(strict=True) == path and name not in files
                  and prep.reference(path)["sha256"] == item["sha256"], "different V21 member " + name)
        files[name] = path.read_bytes(), int(item["mode"], 8)
    for name, count in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        source, mode = files[name]
        prep.need(source.count(bytes(OLD)) == count, "changed V21 path in " + name)
        files[name] = source.replace(bytes(OLD), bytes(NEW)), mode
    source, mode = files["capacity.py"]
    marker = '        merged["epoch143_installed_guard_floor"] = installed'
    source = once(source.decode(), marker,
                  '        merged["epoch143_pre_floor_home_margin"] = merged["home_margin"]\n' + marker)
    files["capacity.py"] = source.encode(), mode
    files = extend(files)
    terminal = Path(__file__).resolve().parents[1] / "horizon_epoch143_bounded_entry_20261126_v1/writer/second143_terminal.py"
    files["second143_terminal.py"] = (terminal.read_bytes(), 0o444)
    source, mode = files["capacity.py"]
    files["capacity.py"] = (once(source.decode(), "'after_ram170_admission.py'}",
                                "'after_ram170_admission.py','second143_terminal.py'}").encode(), mode)
    source, mode = files["shared_hourly143.py"]
    idle = '    if native["ActiveState"] == "inactive":'
    code = once(source.decode(), idle, """    if native["ActiveState"] == "failed":
        import runpy
        second = runpy.run_path(str(Path(__file__).with_name("second143_terminal.py")))["closed"](core)
        return dict(closure, second_released_terminal=second), None
""" + idle)
    files["shared_hourly143.py"] = (code.encode(), mode)
    history = json.loads(files["SOURCE.json"][0])
    history.update(revision=revision, prior_shared_price=PREVIOUS)
    files["SOURCE.json"] = ((json.dumps(history, indent=2) + "\n").encode(), 0o444)
    stage.mkdir(mode=0o700)
    result = {}
    for name, (content, mode) in files.items():
        if name.endswith(".py"):
            ast.parse(content, filename=name)
        dest = stage / name
        dest.write_bytes(content)
        result[name] = dest, mode
    return result
