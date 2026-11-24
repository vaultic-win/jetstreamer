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


def verify146(bounded, s, census):
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

    vanished_while_checking = False
    terminal = False

    def live(reader, route, expected, start):
        if vanished_while_checking:
            raise ProcessLookupError(pid)
        s.need(route["argv"] == entry["planned_argv"] and start == ticks, "wrong native test route")
        s.need(expected["snapshot"][2] == 4459684282 and expected["inputs_readonly"]
               and expected["worker_noexec"] and expected["private_network"]
               and expected["scratch_bytes"] == 8<<20 and expected["scratch_tmpfs"]
               and expected["manager"]["MemoryMax"] == str(192<<20)
               and expected["manager"]["TasksMax"] == "64", "missing bounded entry envelope")
        accepted.append(expected)

    processes = {}

    class Process:
        def __init__(self, pid):
            self.name = str(pid)

        def __truediv__(self, name):
            assert name == "comm"
            return SimpleNamespace(read_text=lambda: processes[int(self.name)][0])

    class Proc:
        def __init__(self, path):
            assert path == "/proc"

        def iterdir(self):
            return [Process(pid) for pid in processes]

    def process(pid):
        details = processes[pid][1]
        if isinstance(details, Exception):
            raise details
        return details

    def ended(claim):
        s.need(claim["pid"] == pid and claim["invocation_id"] == original["invocation_id"],
               "terminal check used a foreign registration")
        return terminal

    def old_probe(reader, old_pid, comm, start, old_group):
        if (old_pid, comm, old_group) == (bounded["PID"], "jetstreamer-nod", "0::" + bounded["GROUP"]):
            return dict(pid=old_pid, invocation_id=bounded["IID"])

    reader = SimpleNamespace(bound=bound, need=s.need, read=s.read, process=process)
    observe = bounded["observe146"]
    adapter = dict(bounded, observe=old_probe, terminal146=ended)

    def capture(registration=lease_ref):
        return census({}, {}, None, {"occupied":False}, 145, {}, entry_lease=registration)

    def reject(call, exception, message):
        try:
            call()
        except exception as exc:
            s.need(str(exc) == message, "unrelated epoch 146 fixture failure")
        else:
            raise ValueError("missing rejection: " + message)

    with patch.dict(observe.__globals__, verify_live=live, terminal146=ended), \
            patch.dict(census.__globals__, Path=Proc, s=reader, fit=SimpleNamespace(units=lambda:set()),
                       bounded142=adapter):
        claim = observe(reader,pid,"jetstreamer-nod",ticks,group,lease_ref)
        s.need(claim["registration"] == lease_ref and claim["memory_bytes"] == 192<<20
               and claim["scratch_bytes"] == 8<<20 and claim["additional_cpu_quota_micros"] == 0,
               "incorrect bounded epoch 146 accounting")
        variants = {"boot":"0"*32,"pid":pid+1,"start_ticks":ticks+1,"unit":"wrong.service",
                    "preflight":dict(entry_ref,sha256="0"*64),"invocation_id":"0"*32}
        for field,value in variants.items():
            lease = dict(original, **{field:value})
            reject(lambda:observe(reader,pid,"jetstreamer-nod",ticks,group,lease_ref),
                   ValueError,"different bounded epoch 146 lease")
        lease = dict(original, start_ticks=0)
        reject(capture,ValueError,"different bounded epoch 146 lease")
        lease = deepcopy(original)
        s.need(observe(reader,pid,"historical-work",ticks,group,lease_ref) is None
               and observe(reader,pid,"jetstreamer-nod",ticks,"0::/system.slice/"+unit,lease_ref) is None
               and len(accepted)==1,"foreign process reached the epoch 146 live reader")

        reject(lambda:capture(dict(lease_ref, sha256="2"*64)),ValueError,"foreign test lease reference")
        s.need(capture(None)==({},None),"unexpected reservation without a fleet lease")
        processes[pid] = ("python3", (1,ticks,group))
        held = capture()
        processes[pid] = ("jetstreamer-nod", (1,ticks,group))
        running = capture()
        s.need(held==running==({},claim) and len(accepted)==2,"held-to-exec changed the reservation or skipped live verification")
        reject(lambda:capture(None),ValueError,"unregistered replay process " + str(pid))
        processes[pid] = ("jetstreamer-nod", (1,ticks+1,group))
        reject(capture,ValueError,"different bounded epoch 146 lease")
        processes[pid] = ("jetstreamer-nod", (1,ticks,"0::/system.slice/unregistered.service"))
        reject(capture,ValueError,"unregistered replay process " + str(pid))
        processes[pid] = ("historical-work", (1,ticks,group))
        reject(capture,ValueError,"unregistered replay process " + str(pid))
        processes[pid] = ("jetstreamer-nod", ProcessLookupError(pid))
        reject(capture,ProcessLookupError,str(pid))
        terminal = True
        s.need(capture()==held,"positively identified exit during /proc scan dropped the reservation")
        processes[pid] = ("jetstreamer-nod", (1,ticks,group))
        vanished_while_checking = True
        s.need(capture()==held,"positively identified exit during native verification dropped the reservation")
        terminal = False
        reject(capture,ProcessLookupError,str(pid))
        processes.clear()
        s.need(capture()==held and capture(None)==({},None),"terminal or fleet release changed the reservation incorrectly")
        old_pid = bounded["PID"]
        processes[old_pid] = ("jetstreamer-nod", (1,ticks,"0::"+bounded["GROUP"]))
        reject(capture,ValueError,"overlapping bounded entry probes")
        s.need(capture(None)==({},dict(pid=old_pid, invocation_id=bounded["IID"])),
               "changed historic 142 census")
    return dict(preflight=entry_ref, accepted_fixture=True, rejected_fields=sorted(variants),
                transition_controls=["held", "native exec", "identified exit during scan", "identified exit during verification",
                                     "terminal reserved", "successor fleet release", "overlapping 142 rejected"],
                terminal_controls=verify146_terminal(bounded, s, claim),
                live_node_executed=False)


def verify146_terminal(bounded, s, claim):
    unit, group, pid = claim["unit"], bounded["GROUP146"], claim["pid"]
    terminal = dict(Id=unit, InvocationID=claim["invocation_id"], ExecMainPID=str(pid), MainPID="0",
                    ControlPID="0", ActiveState="failed", SubState="failed", Job="", NRestarts="0",
                    ControlGroup="")
    rows = []
    pid_visible = False
    cgroup_members = ""

    def show(command, **kwargs):
        s.need(command[:3] == ["/usr/bin/systemctl", "show", "-p"] and command[-1] == unit,
               "foreign terminal provider command")
        return "\n".join(f"{k}={v}" for k,v in rows.pop(0).items())

    class TerminalPath:
        def __init__(self, name):
            self.path = Path(name)

        def __truediv__(self, key):
            return TerminalPath(self.path / key)

        def exists(self):
            s.need(self.path == Path("/proc") / str(pid), "foreign terminal process check")
            return pid_visible

        def read_text(self):
            s.need(self.path == Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.procs",
                   "foreign terminal cgroup check")
            return cgroup_members

    fn = bounded["terminal146"]
    controls = ["exact terminal", "crossed invocation", "crossed main process", "active manager",
                "remaining process", "remaining cgroup member", "changing manager"]
    with patch.dict(fn.__globals__, Path=TerminalPath, subprocess=SimpleNamespace(check_output=show)):
        rows = [terminal,terminal]
        s.need(fn(claim),"exact terminal denied")
        for crossed in (dict(terminal, InvocationID="9"*32),dict(terminal, ExecMainPID=str(pid+1)),
                        dict(terminal, ActiveState="active")):
            rows = [crossed]
            s.need(not fn(claim),"foreign terminal accepted")
        rows = [terminal]
        pid_visible = True
        s.need(not fn(claim),"terminal accepted with live process")
        rows = [terminal]
        pid_visible = False
        cgroup_members = str(pid)
        s.need(not fn(claim),"terminal accepted with live cgroup")
        rows = [terminal,dict(terminal, InvocationID="9"*32)]
        cgroup_members = ""
        s.need(not fn(claim),"terminal accepted while manager changed")
    return controls


if __name__ == "__main__":
    module=runpy.run_path(str(Path(__file__).with_name("post-stop-fit")))
    result=verify(module["bounded142"],module["s"])
    if sys.argv[1:] == ["--with-146"]:
        result["bounded146"]=verify146(module["bounded142"],module["s"],module["census"])
    print(json.dumps(result,sort_keys=True))
