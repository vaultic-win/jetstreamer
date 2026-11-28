"""Bind the verification-mode repair to the closed 143 preparation allocation."""

import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_v53 import member_plan
from derive143_build_preparation import BASE, BUILD

NEW = BASE / "preparation-build-v3"
OLD_COMMIT = "645aeaac6465e30dd599d591702f6e25b4ac8307"
OLD_PRICE = "c1d09d2382e6dfb6d9eb7520d910ddefac252e713575c21e6df8f47bc10e488e"
TERMINAL = "e3337993ebc5ff75dd39c26a462bc8b4757a914289a2770ae221784535175daa"
IID = "4a1629f9884b406bb104a745053eb5b3"


def derive(stage, old_seal, revision, price, price_sha):
    files = read_package(BUILD, old_seal)
    source, mode = files["dispatch143_second_build.py"]
    s = source.decode()
    for before, after in (
        (BUILD.name, NEW.name),
        ("hourly-build-20261128-v1", "hourly-build-20261128-v2"),
        ('"build-guard-v1"', '"build-guard-v2"'),
        ('"BUILD_ADMISSION_V2.json"', '"BUILD_ADMISSION_V3.json"'),
        ('/prepare143_second_gate.py build"', '/prepare143_second_gate.py build-v2"'),
        ('f"build-{iid}.json"', 'f"build-v2-{iid}.json"'),
        ("issued-price-v19", price),
        (OLD_PRICE, price_sha),
        (OLD_COMMIT, revision),
        ('["prepare143_roster"]()', '["whole_roster"]()'),
        ('quote["preparation_only"] and', 'not quote["preparation_only"] and'),
    ):
        s = s.replace(before, after)
    marker = '    capacity = sealed(PRICE,PRICE_SHA)'
    s = change(s, marker, marker + f'''
    terminal = BASE / "failed-{IID}/TERMINAL.json"
    need(ref(terminal)["sha256"] == "{TERMINAL}", "lost the previous terminal")
    old = native("horizon-qualify-143-second-hourly-20261128-v1.service",
                 "Id,ActiveState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus")
    need(old["InvocationID"] == "{IID}" and old["ActiveState"] == "failed"
         and old["MainPID"] == old["ControlPID"] == "0" and not old["Job"]
         and old["Result"] == "exit-code" and old["ExecMainStatus"] == "1",
         "previous 143 producer has not drained")''')
    files["dispatch143_second_build.py"] = (s.encode(), mode)
    gate, mode = files["prepare143_second_gate.py"]
    gate = gate.decode().replace('"build","fixture"', '"build","build-v2","fixture"')
    anchor = '    if Path("/proc/self/cgroup").read_text().strip()'
    gate = change(gate, anchor, '''    if action == "build-v2":
        unit = "horizon-prepare-143-hourly-build-20261128-v2.service"
''' + anchor)
    files["prepare143_second_gate.py"] = (gate.encode(),mode)
    files["SOURCE.json"] = ((json.dumps(dict(
        branch="account-updates", revision=revision, prior_build_seal=old_seal,
        price_seal=price_sha, terminal_sha256=TERMINAL), indent=2) + "\n").encode(), 0o444)
    return member_plan(files, stage, NEW)


if __name__ == "__main__":
    stage, old_seal, revision, price, price_sha = sys.argv[1:]
    print(json.dumps(derive(Path(stage), old_seal, revision, price, price_sha), indent=2))
