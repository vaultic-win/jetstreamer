"""Offline controls for the exact bounded 142 incident. No node is executed."""
from copy import deepcopy
from pathlib import Path
import json
import runpy
import sys
from types import SimpleNamespace
from unittest.mock import patch


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


def verify146(bounded, s):
    entry, entry_ref = s.read(bounded["ENTRY146"], bounded["ENTRY146_SHA"])
    unit = bounded["PROBE146"]
    group = "0::/horizonaudit.slice/" + unit
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    pid, ticks = 42, 12345
    original = dict(schema="horizon-epoch146-bounded-entry-lease-v1", preflight=entry_ref,
                    boot=boot, unit=unit, pid=pid, start_ticks=ticks,
                    invocation_id="d1ac6c5e9ae14769801d74c299f5a599")
    lease = deepcopy(original)
    lease_ref = dict(path=str(bounded["LEASE146"]), sha256="1"*64)
    accepted = []

    def bound(ref, path):
        s.need(ref == lease_ref and path == bounded["LEASE146"], "foreign test lease reference")
        return lease

    def live(reader, route, expected, start):
        s.need(route["argv"] == entry["planned_argv"] and start == ticks, "wrong native test route")
        s.need(expected["snapshot"][2] == 4459684282 and expected["inputs_readonly"]
               and expected["worker_noexec"] and expected["private_network"]
               and expected["scratch_bytes"] == 8<<20 and expected["scratch_tmpfs"]
               and expected["manager"]["MemoryMax"] == str(192<<20)
               and expected["manager"]["TasksMax"] == "64", "missing bounded entry envelope")
        accepted.append(expected)

    reader = SimpleNamespace(bound=bound, need=s.need, read=s.read)
    observe = bounded["observe146"]
    with patch.dict(observe.__globals__, verify_live=live):
        claim = observe(reader,pid,"jetstreamer-nod",ticks,group,lease_ref)
        s.need(claim["registration"] == lease_ref and claim["memory_bytes"] == 192<<20
               and claim["scratch_bytes"] == 8<<20 and claim["additional_cpu_quota_micros"] == 0,
               "incorrect bounded epoch 146 accounting")
        variants = {"boot":"0"*32,"pid":pid+1,"start_ticks":ticks+1,"unit":"wrong.service",
                    "preflight":dict(entry_ref,sha256="0"*64),"invocation_id":"0"*32}
        for field,value in variants.items():
            lease = dict(original, **{field:value})
            try:
                observe(reader,pid,"jetstreamer-nod",ticks,group,lease_ref)
            except ValueError as exc:
                s.need(str(exc)=="different bounded epoch 146 lease","unrelated epoch 146 fixture failure")
            else:
                raise ValueError("accepted changed bounded epoch 146 " + field)
        s.need(observe(reader,pid,"historical-work",ticks,group,lease_ref) is None
               and observe(reader,pid,"jetstreamer-nod",ticks,"0::/system.slice/"+unit,lease_ref) is None
               and len(accepted)==1,"foreign process reached the epoch 146 live reader")
    return dict(preflight=entry_ref, accepted_fixture=True, rejected_fields=sorted(variants),
                live_node_executed=False)


if __name__ == "__main__":
    module=runpy.run_path(str(Path(__file__).with_name("post-stop-fit")))
    result=verify(module["bounded142"],module["s"])
    if sys.argv[1:] == ["--with-146"]:
        result["bounded146"]=verify146(module["bounded142"],module["s"])
    print(json.dumps(result,sort_keys=True))
