"""Check the epoch 170 release bindings without a producer or a guard timer."""

from copy import deepcopy
from pathlib import Path
import time
import unittest

import bindings170 as bindings


FLEET = dict(path="/fleet", sha256="a"*64)
READY = dict(path="/inputs-ready", sha256="b"*64)
INPUTS = dict(path="/inputs", sha256="c"*64)
INTENT = dict(path="/intent", sha256="d"*64)
POST = dict(path="/post", sha256="e"*64)
PLAN = dict(path="/plan", sha256="f"*64)
FIRST = dict(path="/first", sha256="1"*64)
IID = "a"*32
CAP, GROWTH = 384 << 30, 96 << 30
REGISTRATION = dict(consumer_seal=dict(path=str(bindings.OBSERVER/"deployment-seal-receipt.json"),
                                       sha256=bindings.OBSERVER_SEAL))
CONTRACT = dict(ready=READY, inputs=INPUTS)


def prestart():
    return dict(schema="horizon-incident-replay-fit-v1", fits=True, replay_launch_authorized=False,
                resource_credit_bytes=0, phase145={"stage":"v5u-drained"}, fleet=FLEET,
                recorded_unix_seconds=int(time.time()), status_registration=REGISTRATION,
                hourly170_diagnostic=dict(stage="prestart", inputs_ready=READY, inputs=INPUTS,
                    resource_fit=True, launch_compatible=True, retained_booking_bytes=CAP,
                    private_growth_bytes=GROWTH, additive_charge_bytes=0,
                    additive_memory_bytes=0, additive_cpu_quota_micros=0))


def provider(registration=REGISTRATION):
    return dict(s=None, fit=None, fleet_head=lambda ref:({"ref":ref}, None),
                registered_status=lambda:registration)


class Bindings170(unittest.TestCase):
    def test_prestart_requires_capacity_and_launch_compatibility(self):
        current = prestart()
        expected = dict(path="/prestart", sha256="2"*64)
        route = dict(sealed=lambda _: (current, expected), drained145=lambda *_:None, CAP=CAP, GROWTH=GROWTH)
        result = bindings.positive_prestart(provider(), route, CONTRACT)
        self.assertEqual(result, (current, expected, current["hourly170_diagnostic"], {"ref":FLEET}))
        for key, value in (("resource_fit", False), ("launch_compatible", False),
                           ("additive_charge_bytes", 1), ("additive_memory_bytes", -1)):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "held epoch 170 prestart"):
                changed = deepcopy(current)
                changed["hourly170_diagnostic"][key] = value
                bindings.positive_prestart(provider(), dict(route, sealed=lambda _: (changed,expected)), CONTRACT)

    def test_prestart_rejects_an_unmatched_fleet_monitor(self):
        current = prestart()
        wrong = dict(consumer_seal=dict(path="/original-monitor", sha256="4"*64))
        route = dict(sealed=lambda _: (current, {}), drained145=lambda *_:None, CAP=CAP, GROWTH=GROWTH)
        with self.assertRaisesRegex(ValueError, "diagnostic-aware fleet monitor"):
            bindings.positive_prestart(provider(wrong), route, CONTRACT)

    def test_grant_records_the_exact_held_owner_and_guard(self):
        intent = dict(invocation_id=IID,pid=321,start_ticks=987, boot_id="same-boot",
                      guard_plan=PLAN,first_guard=FIRST,log_device_inode=[42,73])
        post = dict(fits=True, replay_launch_authorized=False, fleet=FLEET,
                    status_registration=REGISTRATION, recorded_unix_seconds=int(time.time()),
                    hourly170_diagnostic=dict(stage="post-guard", launch_compatible=True, resource_fit=True,
                        inputs=INPUTS, intent=INTENT, receipt=FIRST))
        route = dict(INTENT=Path("/intent"), POST=Path("/post"), UNIT="170.service", CAP=CAP, GROWTH=GROWTH,
                     sealed=lambda path: (intent,INTENT) if path == Path("/intent") else (post,POST),
                     owner=lambda *_:dict(intent=INTENT), sample=lambda *_:dict(receipt=FIRST))
        result = bindings.grant(provider(), route, CONTRACT, {"validate_grant":lambda *_:None}, prestart(), {})
        self.assertEqual((result["invocation_id"], result["pid"], result["start_ticks"]), (IID,321,987))
        self.assertEqual(result["native_post_guard_fit_sha256"], POST["sha256"])
        self.assertEqual(result["guard_plan_sha256"], PLAN["sha256"])
        self.assertEqual(result["first_guard_sha256"], FIRST["sha256"])
        self.assertEqual(result["log_device_inode"], [42,73])
        self.assertFalse(result["archive_publication_authorized"])
        changed = dict(route, sample=lambda *_:dict(receipt=PLAN))
        with self.assertRaisesRegex(ValueError, "actor or guard changed"):
            bindings.grant(provider(), changed, CONTRACT, {"validate_grant":lambda *_:None}, prestart(), {})


if __name__ == "__main__":
    unittest.main()
