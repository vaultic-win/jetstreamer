"""Keep the retained epoch 251 assignment through its independent holding readback."""
from pathlib import Path
import os
import sys

sys.path[:0] = ["/var/lib/jetstreamer/horizon250-holding-readback-v219", "/run/horizon249-251-rotation-v205-a1"]
import holding250
import peer251
from holding250 import D, bound, partition, ref

PARK = peer251.BASE + "-park.service"
VERIFY = peer251.BASE + "-verify.service"


def completed(unit, receipt, book, result):
    done = bound(receipt)
    assert done["booking"] == holding250.record(unit, "booking.json")
    assert done["original"] == book["original"] and done["result"] == result
    assert done["source_retained"] and not done["archive_ready"] and done["resource_credit"] == 0
    assert done["process"] == holding250.record(unit, "process.json") and bound(done["process"])["exit"] == 0
    running = bound(holding250.record(unit, "running.json"))
    assert running["booking"] == done["booking"] and running["assignment"] == book["assignment"]
    assert running["owner"]["InvocationID"] == done["invocation_id"]
    assert done["manager"] == holding250.record(unit, "pid1.json")
    end, = [r for r in bound(done["manager"]) if r.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448"]
    assert (end["_BOOT_ID"], end["_PID"], end["_UID"], end["UNIT"], end["INVOCATION_ID"], end.get("UNIT_RESULT", "success")) == (
        book["boot"].replace("-", ""), "1", "0", unit, done["invocation_id"], "success")
    holding250.inactive(unit)


def state():
    park_ref = holding250.record(PARK, "completion.json")
    assert park_ref["sha256"] == "a88b2bf3322ae5b442168c52927b15dd4d3bd85192e0f75afea45d07b859a31b"
    park = bound(park_ref)
    book = bound(park["booking"])
    assert park["invocation_id"] == "93fcaa47db5f4c7aba270738f598dc42"
    assert book["boot"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert book["assignment"] == ref(peer251.STATE / "assignment.json")
    assert bound(book["assignment"])["bytes"] == 616 << 20 and not bound(book["assignment"])["automatic_release"]
    completed(PARK, park_ref, book, park["result"])
    holding250.validate_source(book["original"])
    result = dict(park=park_ref, verify=None, complete=None)
    live = peer251.active()
    directory = D / VERIFY.removesuffix(".service")
    if not directory.exists():
        assert not live
        holding250.inactive(VERIFY)
        return result, {}
    result["verify"] = holding250.record(VERIFY, "booking.json")
    v = bound(result["verify"])
    for key in ("assignment", "original", "image", "endpoint_sha256", "actor", "handoff", "build", "lock", "boot", "service_bytes"):
        assert v[key] == book[key]
    assert v["prior"] == park_ref and v["unit"] == VERIFY and v["operation"] == "verify" and not v["retirement"]
    if (directory / "completion.json").exists():
        assert not live
        result["complete"] = holding250.record(VERIFY, "completion.json")
        completed(VERIFY, result["complete"], v, dict(park["result"], operation="verify"))
        return result, {}
    assert live == {VERIFY}
    start = bound(holding250.record(VERIFY, "running.json"))
    assert start["booking"] == result["verify"] and start["assignment"] == book["assignment"]
    m = start["owner"]
    assert m == partition.props(VERIFY, list(m))
    return result, {VERIFY: (m["InvocationID"], int(m["MainPID"]), holding250.LIMIT, {41})}


def issue(phase, service, controller, outside):
    from funding import price
    assert (phase, service, controller, outside) == ("horizon251-concurrent-private-verify", 128, 64, 0)
    assert partition.locked(peer251.LOCK, os.getpid()) and partition.locked(partition.LOCK, os.getpid())
    witness, live = state()
    assert not live and not witness["verify"]
    previous = bound(bound(witness["park"])["booking"])
    fit = price(576 << 20, 1 << 20, 1 << 20, closed_disk=True)
    before250 = bound(fit["holding250"]["park"])
    assert previous["resource_booking"]["holding"]["booking"] == before250["booking"]
    return dict(current_fit=fit, fleet=fit["fleet"], assignment=bound(previous["assignment"])["rotation_parent"],
                holding=dict(booking=before250["booking"]), predecessor=witness["park"], general_capacity_credit=0)
