"""Add epoch 143 to the inherited single-writer status protocol."""
import ast
import hashlib
import json
from pathlib import Path
import sys

from derive49 import one
import derive53

HERE = Path(__file__).resolve().parent
OLD = derive53.NEW
NEW = OLD.with_name(OLD.name.replace("v53", "v54"))
SEAL = "73358657891cd2a9961d9bff0f8964fac0aa6fda5761271b14a61f06c573e3dc"
OWNER = "dd10d5bea7b0faac47d92993c058aeee926751af8def1bb4b29ef0d6986473e9"


def cycle(s):
    s = s.replace(", 53)", ", 53, 54)")
    anchor = "                        if FAILED166_VERSION == 53:\n                            import transition_v53"
    s = one(s, anchor, anchor.replace("== 53", "in (53, 54)") +
            "\n                        if FAILED166_VERSION == 54:\n                            import transition_v54\n                            import hourly143_status")
    anchor = "                            if FAILED166_VERSION == 53:\n                                modules.append(transition_v53)"
    s = one(s, anchor, anchor.replace("== 53", "in (53, 54)") +
            "\n                            if FAILED166_VERSION == 54:\n                                modules += [transition_v54, hourly143_status]")
    start = s.index("    if FAILED166_VERSION == 53 and len(sys.argv) == 4:")
    end = s.index("    if FAILED166_VERSION == 52 and len(sys.argv) == 4:", start)
    s = s[:start] + s[start:end].replace("53", "54") + s[start:]
    for anchor in ("    elif FAILED166_VERSION == 53:\n        transition_v53.validate(globals(), ready, receipt)",
                   "                53: (transition_v53.V52_SHA, transition_v53.V52_SEAL),",
                   "                    53: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"):
        new = (anchor.replace("53:", "54:") if "fb9d" in anchor else
               anchor.replace("53", "54").replace("V52", "V53"))
        s = one(s, anchor, anchor + "\n" + new)
    anchor = "    if FULL146_CADENCE:\n        c.status146 = full146_status.baseline"
    s = one(s, anchor, """    if FAILED166_VERSION == 54:
        c.status143 = hourly143_status.baseline(refs.pop('143', None))
""" + anchor)
    anchor = "    original = checked(c.prior['inventory'], root=False)"
    s = one(s, anchor, """    if FAILED166_VERSION == 54:
        need(143 in statuses and 143 not in ready and 143 not in archives,
             'epoch 143 status or archive inventory changed')
        authenticated(store,143,c.status143)
        statuses = statuses - {143}
""" + anchor)
    anchor = "    if FULL146_CADENCE and c.status146:"
    s = one(s, anchor, """    if FAILED166_VERSION == 54:
        one143 = {'143': c.status143}
        read_statuses(store, one143, target)
        if (target/'epoch-143.intent.json').exists():
            publish(c, store, one143, target, 143)
        refs.update(one143)
        c.status143 = refs['143']
""" + anchor)
    anchor = "    for e,r in refs.items(): authenticated(store,int(e),r)"
    s = one(s, anchor, "    if FAILED166_VERSION == 54:\n        c.status143 = refs['143']\n" + anchor)
    s = one(s, "if k not in ('140','146','162')", "if k not in ('140','143','146','162')")
    anchor = "        elif epoch == 146 and FULL146_CADENCE:"
    s = one(s, anchor, """        elif FAILED166_VERSION == 54 and epoch == 143:
            row, = (row for profile, row in c.first_hourly if profile.epoch == 143)
            after,extra = hourly143_status.forecast(c, row, old)
            extra['private143_origin'] = bound(hourly143_status.INITIAL)
""" + anchor)
    anchor = "        hourly_population.install(fleet, c.first_hourly)"
    s = one(s, anchor, anchor + """\n        if FAILED166_VERSION == 54:
            hourly143_status.install(fleet, fleet[hourly143_status.PROFILE.field])""")
    anchor = "        while True:\n            head=one_cycle(head,ref,proof)"
    return one(s, anchor, """        if FAILED166_VERSION == 54:
            hourly143_status.start(head, status.Storage())
""" + anchor)


def cutover(s):
    for tag in ("cutover", "v", "V"):
        s = s.replace(tag+"53", tag+"54").replace(tag+"52", tag+"53")
    return s.replace(derive53.V52_SEAL, SEAL).replace(derive53.V52_OWNER, OWNER)


def stage(folder):
    raw = (OLD / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SEAL:
        raise ValueError("different V53 writer")
    folder.mkdir(mode=0o700)
    members = {}
    for item in json.loads(raw)["members"]:
        name = item["name"]
        path = OLD / name
        if path.parent != OLD or path.resolve(strict=True) != path or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("changed V53 member " + name)
        if name != "SHA256SUMS":
            members[name] = dict(name=name, source=str(path), sha256=item["sha256"], mode=int(item["mode"], 8))

    def add(name, source):
        ast.parse(source, filename=name)
        path = folder / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), mode=0o444, sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    add("cutover54.py", cutover((OLD / "cutover53.py").read_text()))
    add("transition_v54.py", (HERE / "transition_v54.py").read_text())
    add("hourly143_status.py", (HERE.parent / "horizon_epoch143_bounded_entry_20261126_v1/writer/hourly143_status.py").read_text())
    for name in ("full170_status.py", "cold170_status.py", "joint168_status.py"):
        source = (OLD / name).read_text()
        anchor = "'" + OLD.name + "')"
        if anchor not in source:
            raise ValueError("missing writer receiver " + name)
        add(name, source.replace(anchor, "'" + OLD.name + "', '" + NEW.name + "')"))
    # Preserve the default calls of both previously enrolled split producers.
    source = one((OLD / "split_wire.py").read_text(), "def archive(row):", "def archive(row, path=None):")
    add("split_wire.py", one(source, "name = PATHS[row['epoch']]", "name = PATHS[row['epoch']] if path is None else path"))
    source = one((OLD / "initial162.py").read_text(), "def conditional_create(store, raw):",
                 "def conditional_create(store, raw, epoch=162):\n    need(epoch in (143, 162), 'unregistered status creation')\n    target = f'epoch-{epoch}.epoch-status.json'")
    source = one(source, "store.pending == (KEY,", "store.pending == (target,")
    add("initial162.py", one(source, "return store.put(162,", "return store.put(epoch,"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
