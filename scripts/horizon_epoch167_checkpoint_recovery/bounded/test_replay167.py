"""Exercise admission and checkpoint bindings without starting a producer."""
import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import replay167 as route


class Admission(unittest.TestCase):
    def fixture(self):
        now = int(time.time())
        iid, timer_iid, guard_iid = "1"*32, "2"*32, "3"*32
        actor = dict(producer_invocation_id=iid, producer_pid=123, ready_at=now-1)
        plan = dict(schema="jetstreamer-horizon-standalone-guard-plan-v1", unit=route.UNIT,
                    invocation_id=iid, worker_root=str(route.RUN), filesystem=str(route.HOME),
                    receipt_directory=str(route.ROOT/"guard-receipts"), maximum_root_physical_bytes=(route.GROWTH+4096),
                    maximum_worker_vmas=route.MAX_VMAS, minimum_free_bytes=route.ORIGINAL_FLOOR)
        plan_ref = route.ref(route.ROOT/"ACTUAL_GUARD_PLAN.json", "a"*64)
        sample_ref = route.ref(route.ROOT/"guard-receipts"/f"sample-{guard_iid}.json", "b"*64)
        sample = dict(schema="jetstreamer-horizon-standalone-guard-sample-v1", guard_invocation_id=guard_iid,
                      plan=plan_ref["path"], plan_sha256=plan_ref["sha256"], guard_sha256=route.GUARD_SHA,
                      producer_invocation_id=iid, producer=dict(invocation_id=iid, pid=123, cgroup=route.CGROUP,
                                                           active="active", restarts=0),
                      recorded_unix_seconds=now, producer_stop_enabled=True, trip_reason=None,
                      worker_observation_error=None, root_physical_observation_error=None, workers=[],
                      minimum_free_bytes=route.ORIGINAL_FLOOR, maximum_root_physical_bytes=(route.GROWTH+4096),
                      available_bytes=route.ORIGINAL_FLOOR+1000,
                      root_physical_observation=dict(exceeds_budget=False,
                                                     first=dict(physical_bytes=(route.GROWTH+4096)-10, vanished_entries=0),
                                                     second=dict(physical_bytes=(route.GROWTH+4096)-20, vanished_entries=0)))
        timer = dict(ActiveState="active", SubState="waiting", Job="", InvocationID=timer_iid, Triggers=route.GUARD_SERVICE)
        service = dict(TriggeredBy=route.TIMER, CPUQuotaPerSecUSec="250ms", MemoryMax=str(route.GUARD_MEMORY),
                       MemorySwapMax="0", ExecStart=f"{route.GUARD} {route.GUARD_SHA} {plan_ref['path']} {plan_ref['sha256']}")
        return plan, sample, actor, plan_ref, sample_ref, timer, service

    def test_existing_booking_and_measurement(self):
        price = dict(booking=dict(cap_bytes=route.CAP, physical_bytes=800),
                     growth=200, strongest_floor=1000, bounded_cap=1000)
        self.assertEqual(route.physical_budget(price, 1000, 800, 1200), (1000, 200, 1200))
        self.assertEqual(route.physical_budget(price, 1000, 790, 1220), (1010, 210, 1220))
        for cap, observed, available, armed in ((1001,800,1300,1000), (1000,800,1199,1000),
                                               (1000,790,1219,1010), (1000,790,1220,1000)):
            with self.assertRaises(ValueError):
                route.physical_budget(price, cap, observed, available, armed=armed)

    def test_split_budget_preserves_other_retained_bytes(self):
        baseline, outside = 12288, 7 << 30
        row = dict(retained_outside_run_bytes=outside, run_baseline_physical_bytes=baseline,
                   measured_candidate_leaf_bytes=baseline, run_guard_cap_bytes=route.GROWTH+baseline,
                   bounded_whole_tree_cap_bytes=outside+route.GROWTH+baseline)
        book = dict(physical_bytes=outside+baseline)
        result = route.split_budget(row, book, route.GROWTH, False)
        self.assertEqual(result["retained_outside_run_bytes"], outside)
        self.assertEqual(result["run_guard_cap_bytes"], baseline+route.GROWTH)
        for field in row:
            with self.subTest(field=field), self.assertRaises(ValueError):
                route.split_budget(dict(row, **{field:row[field]+1}), book, route.GROWTH, False)
        held = dict(row, measured_candidate_leaf_bytes=baseline+4096)
        self.assertEqual(route.split_budget(held, dict(physical_bytes=outside+baseline+4096),
                                            route.GROWTH, True), result)

    def test_native_guard_crossing_and_conservative_measurement(self):
        args = self.fixture()
        proof = route.sample_proof(*args)
        self.assertEqual(proof["physical_bytes"], (route.GROWTH+4096)-20)
        for index, field, value in (
            (0, "invocation_id", "8"*32), (1, "workers", [[123,1]]),
            (1, "recorded_unix_seconds", 1), (1, "trip_reason", "over-cap"),
            (1, "available_bytes", route.ORIGINAL_FLOOR-1), (5, "ActiveState", "inactive"),
            (6, "CPUQuotaPerSecUSec", "1s"),
        ):
            wrong = copy.deepcopy(args)
            wrong[index][field] = value
            with self.assertRaises(ValueError, msg=field):
                route.sample_proof(*wrong)

    def test_checkpoint_generations_and_end(self):
        rows = {}
        for bucket, selection, anchor, name, generation, size, crc, md5 in route.CHECKPOINT_ROWS:
            exact = dict(bucket=bucket, name=f"{anchor}/hourly/{name}", generation=generation,
                         size=size, crc32c=crc, md5Hash=md5)
            rows[bucket] = {selection: dict(exact, independently_authenticated_generation_get=exact)}
        route.checkpoint_evidence(dict(regions=rows))
        self.assertEqual(route.node_argv()[4], "--qualification-end-slot=72515090")
        self.assertEqual(route.gate_environment()["JETSTREAMER_HISTORICAL_TRACE_EPOCH167"], "1")
        rows["mainnet-beta-ledger-us-ny5"]["nearest_after"]["generation"] = "foreign"
        with self.assertRaises(ValueError):
            route.checkpoint_evidence(dict(regions=rows))

    def test_append_only_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"sealed.json"
            first = route.atomic(path, b"first\n")
            self.assertEqual(first["sha256"], route.digest(b"first\n"))
            self.assertEqual(path.stat().st_nlink, 1)
            with self.assertRaises(ValueError):
                route.atomic(path, b"second\n")
            self.assertEqual(path.read_bytes(), b"first\n")

    def test_release_preserves_exact_actor_document(self):
        pending = dict(path="/prestart", sha256="d"*64)
        actor = dict(producer_invocation_id="4"*32)
        guard = dict(floor=150, cap=70, sample=dict(path="/guard", sha256="a"*64))
        post = dict(schema="horizon-epoch167-bounded-stage-price-v1", phase="post-guard", intent=pending,
                    actor=actor, resource_credit_bytes=0, archive_publication_authorized=False,
                    replay_launch_authorized=False, first_guard=guard, guard_floor_bytes=150,
                    whole_tree_remaining_bytes=50, required_home_bytes=200,
                    native=dict(recorded_unix_seconds=int(time.time()), required_ram=10, writer="same", writer_binding="binding", fleet="fleet"))
        with tempfile.TemporaryDirectory() as directory, patch.object(route, "ROOT", Path(directory)), \
             patch.object(route, "native_owner", return_value=actor), patch.object(route, "read", return_value=post), \
             patch.object(route, "intent_data", return_value=({"armed_floor": 150, "bounded_cap_bytes": 1000, "run_guard_cap_bytes": 70},)), \
             patch.object(route, "reread_guard", return_value=guard), \
             patch.object(route, "snapshot_stamp", return_value=(200, 10)), \
             patch.object(route, "fleet_authority", return_value=(None, "same")):
            (route.ROOT/"barrier").mkdir()
            result = route.release(pending, route.ref(route.ROOT/"POST_GUARD_CAPACITY.json", "c"*64))
            self.assertEqual(Path(result["permit"]["path"]).read_bytes(), b"4"*32)
            self.assertEqual(json.loads(Path(result["receipt"]["path"]).read_text())["actor"], actor)


if __name__ == "__main__":
    unittest.main()
