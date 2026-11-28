"""Reuse the qualified native 170 observer for a separate writer field and checkpoint."""
import ast
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
NATIVE_SHA = "0d3552abf6180eaf15f0abce075984b74102672721adc063cd5a2be3e61f77df"


def native(source):
    if hashlib.sha256(source).hexdigest() != NATIVE_SHA:
        raise ValueError("different accepted fourth-window observer")
    text = source.decode().replace("fourth170_contract", "gap170_contract")
    text = text.replace("from gap170_contract import INTERFACE, ROOT, interface, closed_comparison",
                        "from gap170_contract import INTERFACE, ROOT, interface, checkpoint")
    text = text.replace('from-73766969-20261127', 'from-73760367-20261128').replace('from-73766969-v1','from-73760367-v1')
    text = text.replace("current_private170_bounded_successor", "current_private170_checkpoint_gap")
    text = text.replace('"successor170_interface"', '"gap170_interface"')
    text = text.replace('"closed_comparison"', '"independent_checkpoint"')
    text = text.replace("closed_comparison=", "independent_checkpoint=")
    text = text.replace("closed_comparison(", "checkpoint(")
    text = text.replace('"retained_170_bounded_predecessor_comparison"', '"retained_170_gap_checkpoint"')
    ast.parse(text)
    return text.encode()


def members(previous):
    return {"gap170_native.py": native((previous / "fourth170_native.py").read_bytes()),
            **{name:(HERE/name).read_bytes() for name in ("gap170_contract.py", "gap170_status.py")}}


def cycle(source):
    """Apply after the base V52 derivation; the existing 170 receiver keeps its fields."""
    def replace(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("missing or duplicate gap integration anchor: " + old)
        source = source.replace(old, new)

    def after(old, addition):
        replace(old, old + "\n" + addition)

    after("            import rolling170_fourth_status as successor170_status",
          "        if FAILED166_VERSION == 52:\n            import gap170_status")
    old = "    successor_prior = successor170_status.retained_population(c.fleet, c.cfg) if FAILED166_VERSION >= 42 else None"
    replace(old, """    if FAILED166_VERSION == 52:
        gap_prior = gap170_status.retained_population(c.fleet, c.cfg)
        previous_cfg = gap170_status.history_config(c.fleet, c.cfg)
    else:
        gap_prior, previous_cfg = None, c.cfg
    successor_prior = successor170_status.retained_population(c.fleet, previous_cfg) if FAILED166_VERSION >= 42 else None""")
    replace("private_successor=successor_prior or bridge_prior)", "private_successor=gap_prior or successor_prior or bridge_prior)")
    replace("    c.bridge170_prior = successor_prior or bridge_prior",
            "    c.bridge170_prior = gap_prior or successor_prior or bridge_prior")
    after("        successor170_status.project(c, c.successor170)", """    if FAILED166_VERSION == 52:
        c.gap170 = gap170_status.observe(c, gap_prior, cycle.observed_lane)
        if gap170_status.active(c.gap170):
            need(not bridge170_status.active(c.bridge170) and not successor170_status.active(c.successor170)
                 and '170' not in native_owners and 170 not in c.new_rows and c.stopped170,
                 'checkpoint gap overlaps another epoch 170 producer')
            if c.gap170['phase'] != 'held':
                native_owners = dict(native_owners, gap170=c.gap170)
        gap170_status.project(c, c.gap170)""")
    after("        successor170_status.recheck(c.successor170)",
          "    if FAILED166_VERSION == 52:\n        gap170_status.recheck(c.gap170)")
    after("        cap[successor170_status.FIELD] = c.successor170",
          "    if FAILED166_VERSION == 52 and c.gap170:\n        cap[gap170_status.FIELD] = c.gap170")
    after("        diagnostic_count += int(successor170_status.active(c.successor170))",
          "    if FAILED166_VERSION == 52:\n        diagnostic_count += int(gap170_status.active(c.gap170))")
    after("        successor170_status.install(fleet, c.successor170)",
          "    if FAILED166_VERSION == 52:\n        gap170_status.install(fleet, c.gap170)")
    anchor = "        durable(intent,dict(epoch=epoch,key=status.key(epoch),previous_receipt=original,conditional_header='If-Match',"
    replace(anchor, """        if FAILED166_VERSION == 52 and epoch == 170 and c.gap170:
            extra.update(gap170_status.status_fields(c.gap170))
""" + anchor)
    anchor = "        for module in modules:"
    replace(anchor, """        if FAILED166_VERSION == 52:
            modules += [gap170_status, gap170_status.contract, gap170_status.gap]
""" + anchor)
    old = "            prior = successor170_status.retained_population(fleet, sealed(ready['config'])) or prior"
    replace(old, """            previous_cfg = sealed(ready['config'])
            gap_prior = None
            if FAILED166_VERSION == 52:
                need(ready['gap170_interface'] == gap170_status.INTERFACE, 'different independent epoch 170 gap')
                gap_prior = gap170_status.retained_population(fleet, previous_cfg)
                previous_cfg = gap170_status.history_config(fleet, previous_cfg)
            older = successor170_status.retained_population(fleet, previous_cfg)
            prior = gap_prior or older or prior""")
    anchor = "    if FAILED166_VERSION == 51 and len(sys.argv) == 4:"
    replace(anchor, """    if FAILED166_VERSION == 52 and len(sys.argv) == 4 and sys.argv[1] == '--enroll-gap-170':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        os.umask(0o077)
        print(json.dumps(gap170_status.enroll(globals(), head, bound(ROOT/'FAILED166_CADENCE_V52_ACTIVE.json'))))
        return
""" + anchor)
    ast.parse(source)
    return source
