"""Read the failed V5f from PID 1 and exercise the narrow recovery attribution."""
from copy import deepcopy
from pathlib import Path
import json
import runpy
import sys


def verify(provider):
    loaded = runpy.run_path(str(provider))
    s = loaded["s"]
    ext = loaded["extensions"]
    manager = s.show(ext["VERIFIER_UNIT"])
    iid = ext["FAILED_GUARD_FIXTURE"]
    native = loaded["phase145"](145)
    assert native["failure"]["sha256"] == "38d828362fed1910cc60c605200380576c165168738dbf00520ce2b2522a0fcd"
    assert native["InvocationID"] == iid and native["source_checkpoint_exists"] is False
    incident = s.bound(native["qualification_census_incident"], loaded["D"] / "GUARD142_V5F_TERMINAL.json")
    state = Path(native["failure"]["path"]).parent
    failed = s.bound(native["failure"], state / "failed.json")
    started = s.bound(native["recovery"], state / "recovery-started.json")
    failures = []
    for case in ("wrong boot", "foreign qualifier", "wrong holder IID", "wrong original PID1",
                 "foreign verifier generation", "late holder", "earlier failed.json", "other failure",
                 "other provider", "different source receipt", "no manager drain"):
        record = deepcopy(incident)
        owner = dict(manager)
        failure = dict(failed)
        start = deepcopy(started)
        events = record["observed_pid1"]
        if case == "wrong boot": record["boot"] = "0"*32
        if case == "foreign qualifier": events[0]["UNIT"] += "2"
        if case == "wrong holder IID": events[1]["INVOCATION_ID"] = "0"*32
        if case == "wrong original PID1": events[2]["_PID"] = "9"
        if case == "foreign verifier generation": owner["InvocationID"] = "0"*32
        if case == "late holder": events[1]["__REALTIME_TIMESTAMP"] = events[-1]["__REALTIME_TIMESTAMP"]
        if case == "earlier failed.json": failure["at"] -= 900
        if case == "other failure": failure["error"] += " changed"
        if case == "other provider": start["fresh_fit"]["provider_seal"]["sha256"] = "0"*64
        if case == "different source receipt": record["recovery"]["sha256"] = "0"*64
        if case == "no manager drain": owner["ControlGroup"] = "/system.slice/still-live.service"
        try:
            ext["guard_fixture_failure"](s, record, owner, start, failure,
                                         native["recovery"], native["failure"], state)
        except ValueError:
            failures.append(case)
        else:
            raise AssertionError("accepted " + case)
    return dict(failed=native, rejected=failures, fixture_launched=False, production_started=False)


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))
