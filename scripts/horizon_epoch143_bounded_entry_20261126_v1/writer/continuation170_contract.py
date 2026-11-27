"""Validate the exact second bounded epoch 170 route and predecessor readback."""
from pathlib import Path
import stat

from evidence import BASE, bound, checked, need

ROOT = BASE/"epoch170-from-73746882-20261127-v1"
INTERFACE = dict(path=str(ROOT/"BOUNDED_SUCCESSOR_WRITER_INTERFACE.json"),
                 sha256="6e7eed43d0593e9ffe6d5df59cb27f92da518af40c96fb7d09fadb63a5990255")
UNIT = "horizon-qualify-170-from-73746882-20261127-v1.service"
TIMER = "horizon-guard-170-from-73746882-20261127-v1.timer"


def interface():
    scope = checked(INTERFACE)
    proof = checked(scope["source_preflight"])
    need(scope["schema"] == "horizon-170-bounded-continuation-writer-interface-v2"
         and (scope["bootstrap"],scope["first_new_slot"],scope["last"]) == (73746882,73746883,73766969)
         and scope["expected_producer_unit"] == UNIT and scope["expected_guard_timer"] == TIMER
         and scope["expected_guard_unit"] == TIMER.replace(".timer",".service")
         and scope["recording"] == "private" and not scope["admission_or_release"]
         and proof["route_accepted"] and not proof["worker_executed"]
         and proof["namespace"] == scope["namespace"] and proof["scope"] == [73746883,73766969],
         "different second bounded 170 route")
    return scope


def closed_comparison(scope):
    ref = bound(Path(scope["closed_comparison"]))
    v = checked(ref)
    e = v["evidence"]
    segment = e["closed_segment"]
    manifest_path = Path(segment["manifest"]["path"])
    m = manifest_path.lstat()
    need(m.st_uid == 1001 and m.st_gid == 1003 and stat.S_IMODE(m.st_mode) == 0o600,
         "different closed 170 manifest custody")
    manifest = checked(segment["manifest"],root=False)
    terminal = e["pid1_exit"]["native"]
    need(v["schema"] == "horizon-170-successor-closed-checkpoint-comparison-v1"
         and v["release"] == scope["old_release"] and v["actor"] == scope["old_actor"]
         and terminal["InvocationID"] == "04b0750aead84a83914d18edea9c8736"
         and terminal["Result"] == "success" and terminal["ExecMainCode"] == "1" and terminal["ExecMainStatus"] == "0"
         and e["comparison"] == "closed" and not v["canonical_publication_authorized"]
         and [p["slot"] for p in v["checkpoints"]] == [73726716,73746882]
         and manifest["terminal"] == v["checkpoints"][-1] and manifest["archive_sha256"] == segment["sha256"]
         and manifest["output_slot_start"] == 73726717 and manifest["output_slot_count"] == 20166,
         "different second bounded 170 predecessor")
    return ref
