"""Keep the V52 status pipeline and timer while admitting the corrected 143 release screen."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

from derive49 import one
import derive52

HERE = Path(__file__).resolve().parent
OLD = derive52.NEW
NEW = OLD.with_name(OLD.name.replace("v52", "v53"))
V52_SEAL = "eb325e1a0dd2c3c280576f97c4530b18bf3228815176feb8b726c913352eafb9"
V52_OWNER = "ede08352a67056909967fa5961c1b19987ab894a8a46a0514e5613d9cc5e086b"


def cycle(source):
    source = source.replace(", 52)", ", 52, 53)")
    first = source.index("    if FAILED166_VERSION == 52 and len(sys.argv) == 4:")
    last = source.index("    if FAILED166_VERSION == 51 and len(sys.argv) == 4:", first)
    # Keep the existing version-specific command bodies for recovery.
    entries = source[first:last]
    source = source[:first] + "V53_ENTRY_BLOCK\n" + source[last:]
    validation = "    elif FAILED166_VERSION == 52:\n        transition_v52.validate(globals(), ready, receipt)"
    source = one(source, validation, "V53_VALIDATE_BLOCK")
    source = source.replace("FAILED166_VERSION == 52", "FAILED166_VERSION in (52, 53)")
    source = one(source, "V53_VALIDATE_BLOCK", validation + "\n" + validation.replace("52", "53"))
    source = one(source, "V53_ENTRY_BLOCK\n", entries.replace("52", "53") + entries)
    anchor = "                        import transition_v52"
    source = one(source, anchor, anchor + "\n                        if FAILED166_VERSION == 53:\n                            import transition_v53")
    anchor = "                            modules += [transition_v52, progress162]"
    source = one(source, anchor, anchor + "\n                            if FAILED166_VERSION == 53:\n                                modules.append(transition_v53)")
    anchor = "                52: (transition_v52.V51_SHA, transition_v52.V51_SEAL),"
    source = one(source, anchor, anchor + "\n                53: (transition_v53.V52_SHA, transition_v53.V52_SEAL),")
    anchor = "                    52: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    return one(source, anchor, anchor + "\n" + anchor.replace("52:", "53:"))


def cutover(source):
    for tag in ("cutover", "v", "V"):
        source = source.replace(tag + "52", tag + "53").replace(tag + "51", tag + "52")
    source = source.replace(derive52.SEAL, V52_SEAL).replace(derive52.ACTIVE, V52_OWNER)
    first = source.index("def preserve143():")
    last = source.index("def endpoints(", first)
    # The prior listener finished its assignment. Retain the reconciled failure
    # across the handoff while the normal 143 launcher owns the new admission.
    source = source[:first] + '''def preserve143():
    if (TARGET / "HELD_OWNER.json").exists():
        return dict(assigned=released143())
    import status_cycle
    profile = status_cycle.first_hourly143
    history, _ = profile.bootstrap_history(profile.EPOCH143)
    need(history["reconciliation"] and not profile.process_ids()
         and not (TARGET / "barrier/allow").exists(), "143 is between booking and release")
    return dict(retained=history)


''' + source[last:]
    source = one(source, "    for unit, assignment in transition_v53.assignments(fleet).items():",
                 """    active, closed = transition_v53.native_assignments(fleet)
    for unit, iid in closed.items():
        if unit in expected:
            need(expected[unit]["InvocationID"] == iid, "unexpected private terminal during cutover")
            del expected[unit]
    for unit, assignment in active.items():""")
    old = '''        if sys.argv[1:] == ["--rebind-listener"]:
            result = rebind_listener()
        elif len(sys.argv) == 3 and sys.argv[1] == "--cutover":'''
    return one(source, old, '''        if len(sys.argv) == 3 and sys.argv[1] == "--cutover":''').replace(
        'use --rebind-listener or --cutover READY.json', 'use --cutover READY.json')


def stage(workspace, reader_sha):
    raw = (OLD / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != V52_SEAL:
        raise ValueError("different incumbent writer package")
    workspace.mkdir(mode=0o700)
    members = {}
    for item in json.loads(raw)["members"]:
        name = item["name"]
        path = OLD / name
        if path.parent != OLD or path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("different sealed predecessor member " + name)
        if name != "SHA256SUMS":
            members[name] = dict(name=name, source=str(path), sha256=item["sha256"], mode=int(item["mode"], 8))

    def add(name, source):
        ast.parse(source, filename=name)
        path = workspace / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), mode=0o444, sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    add("transition_v53.py", (HERE / "transition_v53.py").read_text())
    add("cutover53.py", cutover((OLD / "cutover52.py").read_text()))
    for name in ("full170_status.py", "cold170_status.py", "joint168_status.py"):
        source = (OLD / name).read_text()
        anchor = "'" + OLD.name + "')"
        if anchor not in source:
            raise ValueError("missing prior receiver " + name)
        add(name, source.replace(anchor, "'" + OLD.name + "', '" + NEW.name + "')"))
    reader = derive52.E143.parent / "cadence" / "first_hourly143.py"
    if hashlib.sha256(reader.read_bytes()).hexdigest() != reader_sha:
        raise ValueError("143 reader differs from the qualified source")
    add("first_hourly143.py", reader.read_text())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--reader-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(stage(args.workspace.resolve(), args.reader_sha256), sort_keys=True, indent=2))
