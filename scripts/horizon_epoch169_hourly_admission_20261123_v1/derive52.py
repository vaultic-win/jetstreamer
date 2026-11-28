"""Derive the coordinated writer from the exact V51 deployment and checked epoch modules."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

from derive49 import one

HERE = Path(__file__).resolve().parent
E143 = HERE.parent / "horizon_epoch143_bounded_entry_20261126_v1" / "writer"
E162 = HERE.parent / "horizon_epoch162_split_status"
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1")
OLD = ROOT / "tools-cold168-retry5-failed166-v51-entry146"
NEW = ROOT / "tools-cold168-retry5-failed166-v52-entry146"
SEAL = "778fec83f9fb484c9d4705aa884bdd9bffb32d2a7d7d7e5719eb37b913ebc58c"
ACTIVE = "7353e093feb5763907b9e76ac58fa35d8cf869af686dae85a0b91e58c8857c62"
REBOUND = "e814a5d0ebfd028b5a38ccd60a4fa15ea8433fa33b8a83d5bbb5bc610023a4c9"
V50_SEAL = "dd12e26e1050e42797c117c62a3b34c4f84f45e05dc47aa5060b4807421b45d2"
V50_ACTIVE = "1a97e2971f8222d98412392054d540fda66efa609721b1d7caa28f402125eb22"
V50_REBOUND = "76e9bad312e85015599a9fd6025284677e0b713718f424d30140adb504190d2d"


def advance_names(source):
    for tag in ("cutover", "v", "V"):
        source = source.replace(tag + "51", tag + "52").replace(tag + "50", tag + "51")
    return source.replace(V50_SEAL, SEAL).replace(V50_ACTIVE, ACTIVE).replace(V50_REBOUND, REBOUND)


def cycle(source):
    # The predecessor retains separate branches and authority tables for older packages.
    source = source.replace(", 51)", ", 51, 52)")
    source = one(source, "elif FAILED166_VERSION == 51:\n                    import transition_v50",
                 "elif FAILED166_VERSION in (51, 52):\n                    import transition_v50")
    anchor = "                    import transition_v51"
    source = one(source, anchor, anchor + """
                    if FAILED166_VERSION == 52:
                        import transition_v52
                        import progress162""")
    anchor = "elif FAILED166_VERSION == 51:\n                        modules.append(transition_v51)"
    source = one(source, anchor, anchor.replace("== 51", "in (51, 52)") + """
                        if FAILED166_VERSION == 52:
                            modules += [transition_v52, progress162]""")
    for anchor in ("                51: (transition_v51.V50_SHA, transition_v51.V50_SEAL),",
                   "                    51: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"):
        source = one(source, anchor, anchor + "\n" + advance_names(anchor).replace("51:", "52:"))
    anchor = "    elif FAILED166_VERSION == 51:\n        transition_v51.validate(globals(), ready, receipt)"
    source = one(source, anchor, anchor + "\n" + anchor.replace("51", "52"))
    first = source.index("    if FAILED166_VERSION == 51 and len(sys.argv) == 4:")
    last = source.index("    if FAILED166_VERSION == 50 and len(sys.argv) == 4:", first)
    source = source[:first] + source[first:last].replace("51", "52") + source[first:]
    source = one(source, "if FAILED166_VERSION == 51 and saved_census.exists():",
                 "if FAILED166_VERSION in (51, 52) and saved_census.exists():")
    anchor = "            c.split162 = status162.observe(c, callback162)"
    source = one(source, anchor, anchor + """
            if FAILED166_VERSION == 52 and c.split162:
                c.split162 = progress162.reconcile(c.split162, c.sample)""")
    # A persisted census is an immutable input when resuming its own partial writes.
    anchor = "            after,extra=split_wire.forecast(c,row,prior,old,original,delivery_eta.estimate)"
    source = one(source, anchor, """            forecast_row = progress162.wire_row(row) if FAILED166_VERSION == 52 and epoch == 162 else row
            after,extra=split_wire.forecast(c,forecast_row,prior,old,original,delivery_eta.estimate)
            if epoch == 162 and row.get('private162_journal_progress'):
                extra['private162_journal_progress'] = row['private162_journal_progress']""")
    return source


def transition(source):
    source = advance_names(source).replace("failed166_package'](50)", "failed166_package'](51)")
    source = one(source, "    rolling.retained_population(fleet,cfg)", """    import gap170_status
    gap170_status.interface()
    rolling.retained_population(fleet,gap170_status.history_config(fleet,cfg))""")
    return one(source, "split_wire_receiver=bound(current.with_name('split_wire.py'))",
               """gap170_interface=gap170_status.INTERFACE,
               gap170_receiver=bound(current.with_name('gap170_status.py')),
               journal162_receiver=bound(current.with_name('progress162.py')),
               split_wire_receiver=bound(current.with_name('split_wire.py'))""")


def stage(work):
    sys.path.insert(0, str(E143))
    import derive_gap170
    seal = (OLD / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(seal).hexdigest() != SEAL:
        raise ValueError("different V51 deployment")
    work.mkdir(mode=0o700)
    members = {}
    for member in json.loads(seal)["members"]:
        name = member["name"]
        path = OLD / name
        if path.parent != OLD or path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != member["sha256"]:
            raise ValueError("different predecessor member " + name)
        if name != "SHA256SUMS":
            members[name] = dict(name=name, source=str(path), mode=int(member["mode"], 8), sha256=member["sha256"])

    def add(name, data):
        if isinstance(data, str):
            data = data.encode()
        ast.parse(data, filename=name)
        path = work / name
        path.write_bytes(data)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), mode=0o444, sha256=hashlib.sha256(data).hexdigest())

    add("status_cycle.py", derive_gap170.cycle(cycle((OLD / "status_cycle.py").read_text())))
    add("transition_v52.py", transition((OLD / "transition_v51.py").read_text()))
    add("cutover52.py", advance_names((OLD / "cutover51.py").read_text()))
    for name in ("full170_status.py", "cold170_status.py", "joint168_status.py"):
        original = (OLD / name).read_text()
        before = "'" + OLD.name + "')"
        if before not in original:
            raise ValueError("missing receiver " + name)
        add(name, original.replace(before, "'" + OLD.name + "', '" + NEW.name + "')"))
    for name, data in derive_gap170.members(OLD).items():
        add(name, data)
    hourly = (E143.parent / "cadence" / "first_hourly143.py").read_bytes()
    if hashlib.sha256(hourly).hexdigest() != "9ac2cfcc44731055d76d2c2853a3bf47369fb3ade1707090f9d6c78228df3a50":
        raise ValueError("different 143 retry observer")
    add("first_hourly143.py", hourly)
    add("progress162.py", (E162 / "progress162.py").read_bytes())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.workspace.resolve()), indent=2, sort_keys=True))
