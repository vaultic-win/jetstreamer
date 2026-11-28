"""Derive V25 from the full V24 price, preserving the prior epoch profiles and reservations."""
import ast
import json
from pathlib import Path

from derive_serial157_v23 import f, once, read_package

HERE = Path(__file__).resolve().parent
OLD = f.ROOT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v24"
NEW = OLD.with_name("issued-price-v25")
PREVIOUS = dict(path=str(OLD / "deployment-seal-receipt.json"),
                sha256="2eb4c47c465c23adfa2b4667a6ac37f92954d418d8d7d460e98b67d6d79be695")


def members(stage, revision):
    files = read_package(OLD, PREVIOUS["sha256"])
    for name, count in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        source, mode = files[name]
        f.need(source.count(bytes(OLD)) == count, "different V24 source path in " + name)
        files[name] = source.replace(bytes(OLD), bytes(NEW)), mode

    def edit(name, old, new):
        source, mode = files[name]
        files[name] = once(source.decode(), old, new).encode(), mode

    edit("capacity.py", "'second143_terminal.py','serial157_operator.py'}",
         "'second143_terminal.py','serial157_operator.py','after_ram170_tree.py'}")
    edit("after_ram170_admission.py", "def owner(core, fleet, directory):",
         "def owner(core, fleet, directory, *, guard_evidence=None):")
    anchor = '        if seen:\n            phase = "worker"'
    edit("after_ram170_admission.py", anchor,
         '        if guard_evidence is not None:\n            guard_evidence.update(guard)\n' + anchor)
    anchor = '    return whole\n'
    edit("after_ram170_admission.py", anchor, '''    live_tree = whole["base_169"]["native"]["raw"]["joint"].get("after_ram170_tree")
    if live_tree:
        floor = live_tree["minimum_free_bytes"]
        whole["epoch170_installed_guard_floor"] = floor
        whole["home_margin"] = min(whole["home_margin"], whole["available_home"] - floor)
        whole["fits"] = whole["fits"] and whole["available_home"] > floor
''' + anchor)
    edit("after_stop.py", """    successor = after_ram['owner'](core,fleet,directory)
    live_successor = successor if successor and successor['phase'] != 'terminal' else None""",
         """    tree_guard = {}
    successor = after_ram['owner'](core,fleet,directory,guard_evidence=tree_guard)
    live_successor = dict(successor, tree_guard=tree_guard) if successor and successor['phase'] != 'terminal' else None""")
    edit("successor_price.py", '    if phase == "live":\n        old_progress',
         '    after_ram_tree = None\n    if phase == "live":\n        old_progress')
    anchor = "        old_lower, old_upper = live_tree_bounds if live_tree_bounds is not None else tree_bytes()"
    edit("successor_price.py", anchor, '''        if gap170 and gap170["unit"] == "horizon-qualify-170-from-73766969-20261127-v1.service" and gap170["phase"] in ("worker","bootstrap"):
            need(phase == "start" and live_tree_bounds is None, "mixed issued and prospective tree bounds")
            observe_tree = runpy.run_path(str(Path(__file__).with_name("after_ram170_tree.py")))["observe"]
            after_ram_tree = observe_tree(gap170, TREE, bound, state, cmd)
            old_lower, old_upper = after_ram_tree["bounds"]
        else:
    ''' + anchor)
    anchor = "        archive_publication_authorized=False,resource_credit_bytes=0)"
    edit("successor_price.py", anchor, """        archive_publication_authorized=False,resource_credit_bytes=0,
        **({"after_ram170_tree": after_ram_tree} if after_ram_tree is not None else {}))""")
    files["after_ram170_tree.py"] = (HERE / "after_ram170_tree.py").read_bytes(), 0o444
    files["serial157_operator.py"] = (HERE / "serial157_operators.py").read_bytes(), 0o444
    history = json.loads(files["SOURCE.json"][0])
    history.update(revision=revision, prior_shared_price=PREVIOUS)
    files["SOURCE.json"] = ((json.dumps(history, indent=2) + "\n").encode(), 0o444)
    stage.mkdir(mode=0o700)
    result = {}
    for name, (source, mode) in files.items():
        if name.endswith(".py"):
            ast.parse(source, filename=name)
        dest = stage / name
        dest.write_bytes(source)
        result[name] = dest, mode
    return result
