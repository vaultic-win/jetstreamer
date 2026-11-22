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
    return dict(incident=ref, exact_route=receipt["route"], confirmed_pid=int(m["ExecMainPID"]),
                crossed_fields=sorted(tests), native_replay_started=False,
                scope="Offline contract replay from native manager, input route and terminal receipt; no historical /proc image retained.")


if __name__ == "__main__":
    module=runpy.run_path(str(Path(__file__).with_name("post-stop-fit")))
    print(json.dumps(verify(module["bounded142"],module["s"]),sort_keys=True))
