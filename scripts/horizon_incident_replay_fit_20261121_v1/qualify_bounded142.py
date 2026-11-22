"""Offline controls for the exact bounded 142 incident. No node is executed."""
from copy import deepcopy
from pathlib import Path
import json
import runpy
import sys


def verify(bounded, s):
    route, expected = bounded["contract"](s)
    incident, ref = s.read(bounded["INCIDENT"], bounded["INCIDENT_SHA"])
    receipt = s.bound(incident["qualifier"], bounded["Q"] / "NORMAL_ENTRY_QUALIFIED.json")
    digest = receipt["complete_digest"]
    m = incident["managers"]["qualification"]
    actual = deepcopy(expected)
    actual.update(pid=int(m["ExecMainPID"]), snapshot=[digest["device"], digest["inode"],
                  digest["verified_snapshot_bytes"]], worker_noexec=digest["worker_noexec"],
                  argv=route["argv"], fs_limit=[digest["fs_limit"]]*2, image_digest=route["node"]["sha256"])
    bounded["check"](s, actual, expected)
    tests = {"pid": 227498, "boot": "0"*32, "cgroup": "0::/system.slice/"+m["Id"],
             "comm": "historical-work", "members": [227497,227498],
             "argv": [*route["argv"], "--force"], "exe": route["worker"]["path"], "image": [2304,6161087,47753136],
             "image_digest": "0"*64, "uid": [0]*4, "gid": [0]*4, "fs_limit": [-1,-1],
             "inputs_match": False, "inputs_readonly": False, "snapshot": [1795,524757,4297291805],
             "private_network": False, "worker_noexec": False, "scratch_tmpfs": False, "scratch_bytes": 16<<20}
    tests.update({"manager."+key: "crossed" for key in actual["manager"]})
    for key,value in tests.items():
        wrong = deepcopy(actual)
        if key.startswith("manager."):
            wrong["manager"][key.split(".")[1]]=value
        else:
            wrong[key]=value
        try:
            bounded["check"](s, wrong, expected)
        except ValueError as exc:
            s.need(str(exc).startswith("unregistered replay process "), "unrelated fixture failure")
        else:
            raise ValueError("accepted crossed bounded probe "+key)
    for pid,comm,group in ((227498,actual["comm"],actual["cgroup"]), (227497,"historical-work",actual["cgroup"]),
                           (227497,actual["comm"],"0::/system.slice/"+m["Id"])):
        s.need(bounded["observe"](s,pid,comm,0,group) is None,"foreign live probe accepted")
    # Replay just the census dispatch against a virtual /proc. Its positive identity was
    # reconstructed above; another parent or historical-worker must still take the denial path.
    from types import SimpleNamespace
    from unittest.mock import patch
    provider = runpy.run_path(str(Path(__file__).with_name("post-stop-fit")))
    census = provider["census"]
    class Entry:
        def __init__(self, pid, comm):
            self.name = str(pid)
            self.comm = comm
        def __truediv__(self, name):
            if name != "comm":
                raise AssertionError(name)
            return SimpleNamespace(read_text=lambda: self.comm)
    class Proc:
        def __init__(self, name):
            if name != "/proc":
                raise AssertionError(name)
        def iterdir(self):
            return [entry]
    def simulated_observe(reader, pid, comm, tick, group):
        if (pid, comm, group) != (bounded["PID"], "jetstreamer-nod", "0::"+bounded["GROUP"]):
            return bounded["observe"](reader, pid, comm, tick, group)
        bounded["check"](reader, current, expected)
        return dict(pid=pid, invocation_id=current["manager"]["InvocationID"])
    census_cases = []
    for name, pid, comm, group, iid in (
        ("authentic bounded route", 227497, actual["comm"], actual["cgroup"], m["InvocationID"]),
        ("unregistered native replay", 227498, actual["comm"], "0::/system.slice/unregistered.service", m["InvocationID"]),
        ("unregistered worker", 227498, "historical-work", actual["cgroup"], m["InvocationID"]),
        ("reused PID in another replay", 227497, actual["comm"], "0::/system.slice/unregistered.service", m["InvocationID"]),
        ("crossed qualifier generation", 227497, actual["comm"], actual["cgroup"], "f"*32)):
        current=deepcopy(actual)
        current["manager"]["InvocationID"]=iid
        entry=Entry(pid, comm)
        status=SimpleNamespace(need=s.need, process=lambda p: (1, 123, group))
        replacements=dict(Path=Proc, s=status, fit=SimpleNamespace(units=lambda:set()),
                          bounded142=dict(observe=simulated_observe))
        with patch.dict(census.__globals__, replacements):
            try:
                population, matched = census({}, {}, None, {"occupied":False}, 145, {})
            except ValueError as exc:
                s.need(name != "authentic bounded route" and str(exc)=="unregistered replay process "+str(pid),
                       "unrelated replay-census fixture failure")
            else:
                s.need(name=="authentic bounded route" and population=={} and matched==dict(pid=227497, invocation_id=bounded["IID"]),
                       "foreign replay accepted by native census")
        census_cases.append(name)
    return dict(incident=ref, exact_route=receipt["route"], confirmed_pid=int(m["ExecMainPID"]),
                native_census_controls=census_cases, crossed_fields=sorted(tests), native_replay_started=False,
                scope="Offline contract replay from native manager, input route and terminal receipt; no historical /proc image retained.")


if __name__ == "__main__":
    module=runpy.run_path(str(Path(__file__).with_name("post-stop-fit")))
    print(json.dumps(verify(module["bounded142"],module["s"]),sort_keys=True))
