"""Enroll the 169 retry on the existing status writer and its original clock."""
import ast
import hashlib
import json
from pathlib import Path
import sys

import derive54
from derive49 import one

HERE = Path(__file__).resolve().parent
OLD = derive54.NEW
NEW = OLD.with_name(OLD.name.replace("v54", "v55"))
V54_SEAL = "195a33aa8b0c388e980ccf3d0d7817daaba33363688bec2f31b99509dd9cd737"
V54_OWNER = "3b6783ca59a9924358fb54724309977c5b951c923cd40dd0818332203b50d880"


def cycle(source):
    # Keep the predecessor's individual CLI entries and validation, but inherit
    # all its ordinary 143 publish, startup, inventory and installation paths.
    source = source.replace(", 54)", ", 54, 55)")
    start = source.index("    if FAILED166_VERSION == 54 and len(sys.argv) == 4:")
    end = source.index("    if FAILED166_VERSION == 53 and len(sys.argv) == 4:", start)
    entries = source[start:end]
    source = source[:start] + "V55_ENTRIES\n" + source[end:]
    validation = "    elif FAILED166_VERSION == 54:\n        transition_v54.validate(globals(), ready, receipt)"
    source = one(source, validation, "V55_VALIDATION")
    source = source.replace("FAILED166_VERSION == 54", "FAILED166_VERSION in (54, 55)")
    source = one(source, "V55_ENTRIES\n", entries.replace("54", "55") + entries)
    source = one(source, "V55_VALIDATION", validation.replace("54", "55") + "\n" + validation)
    for anchor, addition in (
        ("                            import hourly143_status",
         "                        if FAILED166_VERSION == 55:\n                            import transition_v55\n                            import retry169_status"),
        ("                                modules += [transition_v54, hourly143_status]",
         "                            if FAILED166_VERSION == 55:\n                                modules += [transition_v55, retry169_status]"),
        ("                54: (transition_v54.V53_SHA, transition_v54.V53_SEAL),",
         "                55: (transition_v55.V54_SHA, transition_v55.V54_SEAL),"),
        ("                    54: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',",
         "                    55: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"),
    ):
        source = one(source, anchor, anchor + "\n" + addition)
    source = one(source, "and split_status169.accept_assignment(r)],",
                 "and (retry169_status.accept_assignment(r) if FAILED166_VERSION == 55 else split_status169.accept_assignment(r))],")
    source = one(source, "        c.split169 = split_status169.observe(c, cycle.observed_lane)", """        if FAILED166_VERSION == 55:
            c.retry169, c.split169, c.prior169_context = retry169_status.observe(c, cycle.observed_lane)
        else:
            c.split169 = split_status169.observe(c, cycle.observed_lane)""")
    anchor = "        split_status169.project(c, c.split169)"
    source = one(source, anchor, anchor + """
        if FAILED166_VERSION == 55 and c.retry169:
            need(c.split169 and c.split169['phase'] == 'terminal' and '169' not in native_owners
                 and 169 not in c.new_rows, 'epoch 169 replacement overlaps another producer')
            if c.retry169['phase'] in ('bootstrap', 'worker'):
                native_owners = dict(native_owners, retry169=c.retry169)
            retry169_status.receiver()['project'](c, c.retry169)""")
    anchor = "        split_status169.reader()['recheck'](c.fleet, c.split169)"
    source = one(source, anchor, """        if FAILED166_VERSION == 55:
            split_status169.reader()['recheck'](c.prior169_context.fleet, c.split169)
            retry169_status.recheck(c)
        else:
    """ + anchor)
    anchor = "        cap[split_status169.FIELD] = c.split169"
    source = one(source, anchor, anchor + """
    if FAILED166_VERSION == 55 and c.retry169:
        cap[retry169_status.FIELD] = c.retry169""")
    anchor = "        diagnostic_count += int(split_status169.active(c.split169)) + int(status162.active(c.split162))"
    source = one(source, anchor, anchor + """
    if FAILED166_VERSION == 55:
        diagnostic_count += int(split_status169.active(c.retry169))""")
    anchor = "        split_status169.install(fleet, c.split169)"
    source = one(source, anchor, anchor + """
        if FAILED166_VERSION == 55:
            retry169_status.install(fleet, c.retry169)""")
    anchor = "        elif epoch == 146 and FULL146_CADENCE:"
    source = one(source, anchor, """        elif FAILED166_VERSION == 55 and epoch == 169 and c.retry169 and (
                c.retry169['phase'] != 'terminal' or old.get('private169_retry_terminal') != c.retry169['terminal']):
            after, extra = retry169_status.forecast(c, c.retry169, prior, old, original, delivery_eta.estimate)
""" + anchor)
    anchor = "            extra.update(split_status169.status_fields(c.split169))"
    return one(source, anchor, anchor + """
            if FAILED166_VERSION == 55 and c.retry169:
                extra.update(retry169_status.receiver()['status_fields'](c.retry169))
                extra['private_transaction_progress'] = c.retry169['transaction_replay_claimed']""")


def cutover(source):
    for prefix in ("cutover", "v", "V"):
        source = source.replace(prefix + "54", prefix + "55").replace(prefix + "53", prefix + "54")
    return source.replace(derive54.SEAL, V54_SEAL).replace(derive54.OWNER, V54_OWNER)


def transition(source):
    source = source.replace("epoch 143 status writer", "epoch 169 retry writer")
    source = source.replace("V53_", "V54_").replace("package\"](53)", "package\"](54)")
    source = source.replace("V53_ACTIVE", "V54_ACTIVE").replace(derive54.SEAL, V54_SEAL).replace(derive54.OWNER, V54_OWNER)
    source = one(source, "from transition_v53 import native_assignments", """from transition_v53 import native_assignments as earlier_assignments
import retry169_status as retry""")
    marker = "def ready(api, head, seal):"
    source = one(source, marker, """def native_assignments(fleet):
    api = retry.receiver()
    before = api['observe'].predecessor_view(fleet)
    active, closed = earlier_assignments(before)
    row = api['observe'].current(fleet)
    if row and row['phase'] == 'terminal':
        closed[retry.UNIT] = row['invocation_id']
    elif row:
        active[retry.UNIT] = dict(unit=retry.UNIT, iid=row['invocation_id'],
                                  pid=str(row['actor']['producer_pid']), intent=row['intent'])
    return active, closed


""" + marker)
    anchor = '    config = fleet["sole_next_observer"]'
    source = one(source, anchor, """    report.baseline(checked(fleet['complete_active_status_audit'])['receipts']['143'])
    registered = fleet['current_private169_hourly']
    custody = checked(checked(retry.SCOPE)['predecessor'])
    need(registered['phase'] == 'terminal' and registered['terminal'] == custody['terminal']
         and registered['invocation_id'] == custody['producer_invocation'], 'different prior hourly closure')
""" + anchor)
    return one(source, "                                   terminal_private_invocations=closed,",
               "                                   private169_retry_scope=retry.SCOPE, private169_retry_cadence=retry.CADENCE,\n                                   terminal_private_invocations=closed,")


def wire(source):
    source = one(source, "def forecast(c, row, previous, old, original, delivery):",
                 "def forecast(c, row, previous, old, original, delivery, *, status_key=None, archive_reader=archive):")
    source = one(source, "key = IDENTITIES[epoch]", "key = status_key or IDENTITIES[epoch]")
    source = one(source, "part = archive(row) if active_worker", "part = archive_reader(row) if active_worker")
    anchor = "    need(admitted['producer_invocation_id'] == iid, 'incorrect private status start')"
    return one(source, anchor, """    owner_iid = admitted.get('producer_invocation_id')
    if not owner_iid and row.get('unit', {}).get('Id') == 'horizon-qualify-169-hourly-retry-20261128-v1.service':
        owner_iid = admitted['invocation_id']
    need(owner_iid == iid, 'incorrect private status start')""")


def stage(folder):
    raw = (OLD / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != V54_SEAL:
        raise ValueError("different V54 package")
    folder.mkdir(mode=0o700)
    members = {}
    for item in json.loads(raw)["members"]:
        name = item["name"]
        path = OLD / name
        if path.parent != OLD or path.resolve(strict=True) != path or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("changed V54 member " + name)
        if name != "SHA256SUMS":
            members[name] = dict(name=name, source=str(path), sha256=item["sha256"], mode=int(item["mode"], 8))

    def add(name, source):
        ast.parse(source, filename=name)
        path = folder / name
        path.write_text(source)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), mode=0o444, sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    add("status_cycle.py", cycle((OLD / "status_cycle.py").read_text()))
    add("cutover55.py", cutover((OLD / "cutover54.py").read_text()))
    add("transition_v55.py", transition((OLD / "transition_v54.py").read_text()))
    add("retry169_status.py", (HERE / "retry169_status.py").read_text())
    add("split_wire.py", wire((OLD / "split_wire.py").read_text()))
    for name, count in (("full170_status.py", 1), ("cold170_status.py", 5), ("joint168_status.py", 3)):
        anchor = "'" + OLD.name + "')"
        source = (OLD / name).read_text()
        if source.count(anchor) != count:
            raise ValueError("changed writer enrollment in " + name)
        add(name, source.replace(anchor, "'" + OLD.name + "', '" + NEW.name + "')"))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=list(members.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
