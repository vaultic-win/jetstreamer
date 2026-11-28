"""Derive the complete shared roster with the first 143 closure and next hourly owner."""

from pathlib import Path
import json
import sys

from derive143_bootstrap_retry import ROOT, change, read_package
from derive143_v53 import member_plan

PREVIOUS = ROOT.parent / "epoch162-first-hourly-completion-20261127-v2/issued-price-v16"
TARGET = PREVIOUS.with_name("issued-price-v17")
PREVIOUS_SEAL = "672d07cd19de104a183ad13839de78c0d5f08f01c87a8c8efaaac01511fc3037"


def extend(name, source):
    if name in ("capacity.py", "continuation_price.py", "successor_price.py"):
        count = 3 if name == "successor_price.py" else 1
        if source.count(str(PREVIOUS)) != count:
            raise ValueError("unrecognized V16 self references in " + name)
        source = source.replace(str(PREVIOUS), str(TARGET))
    if name == "successor_price.py":
        source = change(source, '    need(0 <= time.time()-when <= 1900, "cadence needs its current accepted fleet")',
                        '''    if getattr(__import__("sys").modules[__name__], "prepare143_only", False):
        if time.time() - when > 1900:
            runpy.run_path(str(Path(__file__).with_name("shared_hourly143.py")))["preparation_anchor"](globals(),fleet,ref)
    else:
        need(0 <= time.time()-when <= 1900, "cadence needs its current accepted fleet")''')
        # The module is instantiated by spec, rather than ordinary import.
        source = source.replace('getattr(__import__("sys").modules[__name__], "prepare143_only", False)',
                                'globals().get("prepare143_only", False)')
        source = change(source, "import os\n", "import os\nimport runpy\n")
        source = change(source, 'hourly_unit = "horizon-qualify-143-first-hourly-20261127-v1.service"',
                        'hourly_unit = "horizon-qualify-143-second-hourly-20261128-v1.service"')
    elif name == "continuation_price.py":
        source = change(source, '''
        rs = state(rollover.UNIT)
        if rs["ActiveState"] == "active":
            replacement = guarded_hourly143(rollover, rs)''', '''
    shared143 = runpy.run_path(str(Path(__file__).with_name("shared_hourly143.py")))
    closed143, replacement = shared143["owner"](vars(prior), prior.current_fleet()[0])''')
        source = change(source, "import os\n", "import os\nimport runpy\n")
        source = change(source, 'hourly_resident = anonymous(replacement["unit"],replacement["iid"],replacement["roster"],40*G)',
                        'hourly_resident = 0  # Keep the resident allowance until a stable second-hour native proof.')
        source = change(source, "replacement143=replacement,auxiliary=aux,",
                        "replacement143=replacement,closed143=closed143,auxiliary=aux,")
    elif name == "after_stop.py":
        source = change(source, "def price(helper, directory):", "def price(helper,directory, *, prep143=False):")
        source = change(source, "    core = current['prior']\n", "    core = current['prior']\n    core.prepare143_only = prep143\n")
    elif name == "capacity.py":
        source = change(source, "'reserved162_suballocations.py','ram170_residency.py'",
                        "'reserved162_suballocations.py','shared_hourly143.py','ram170_residency.py'")
        source = change(source, "def common(enrollment, *, read_only=False):",
                        "def common(enrollment, *, read_only=False, prep143=False):")
        source = change(source, "        base, row = after['price'](helper,directory)",
                        """        if entry == STOPPED:
            base, row = after['price'](helper,directory,prep143=prep143)
        else:
            base, row = after['price'](helper,directory)""")
        source = change(source, """def whole_roster():
    \"\"\"Return the lock holder's current 168 scan fit, including the sixth 162 output on either side of issuance.\"\"\"
    peer, layout, proof, donor, base, row, fleet, own = common(None,read_only=True)""",
                        """def whole_roster():
    return complete_roster(False)


def prepare143_roster():
    \"\"\"Internal quote for preparing the closed 143 slot while the sole cadence recovers.\"\"\"
    return complete_roster(True)


def complete_roster(prep143):
    peer, layout, proof, donor, base, row, fleet, own = common(None,read_only=True,prep143=prep143)""")
        source = change(source, "    latest = runpy.run_path(str(STOPPED.parent/'following_peers.py'))['current_writer']",
                        "    core.prepare143_only = prep143\n"
                        "    latest = runpy.run_path(str(STOPPED.parent/'following_peers.py'))['current_writer']")
        source = change(source, "resource_credit_bytes=0, recorded_unix_seconds=time.time(), **final)",
                        """resource_credit_bytes=0, recorded_unix_seconds=time.time(), preparation_only=prep143,
                closed_143=base['native']['raw']['closed143'], **final)""")
    return source


def derive(work, revision):
    files = read_package(PREVIOUS, PREVIOUS_SEAL)
    for name, (data, mode) in files.items():
        if name not in ("capacity.py","continuation_price.py","successor_price.py","after_stop.py"):
            continue
        files[name] = (extend(name, data.decode()).encode(), mode)
    files["shared_hourly143.py"] = (Path(__file__).with_name("shared_hourly143.py").read_bytes(),0o444)
    source = json.loads(files["SOURCE.json"][0])
    source.update(revision=revision, prior_shared_price=dict(
        path=str(PREVIOUS / "deployment-seal-receipt.json"), sha256=PREVIOUS_SEAL))
    files["SOURCE.json"] = ((json.dumps(source,indent=2)+"\n").encode(),0o444)
    return member_plan(files, work, TARGET)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]), sys.argv[2]),indent=2))
