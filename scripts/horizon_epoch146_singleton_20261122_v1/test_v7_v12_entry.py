from copy import deepcopy
import json
from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

scope = runpy.run_path(str(Path(__file__).with_name("run-v7-v12-entry.py")))
release = scope["release"]
run_scope = release.__globals__
ref = scope["ref"]


class BoundedEntry(unittest.TestCase):
    def setUp(self):
        self.predecessor = ref("/fixture/predecessor/ROOT_COMPLETE_OPERATIONAL_FLEET.json", "a" * 64)
        self.path = Path("/fixture/accepted/ROOT_COMPLETE_OPERATIONAL_FLEET.json")
        self.accepted = ref(self.path, "b" * 64)
        self.lease = ref("/fixture/lease.json", "c" * 64)
        self.phase = {
            "stage": "v7-semantic-complete-drained", "completed_invocation_id": scope["OWNER145"],
            "checker_seal": ref(scope["CHECKER145"] / "deployment-seal-receipt.json", scope["CHECKER145_SHA"]),
            "completion": ref(scope["COMPLETE145"], "d" * 64),
            "semantic_receipt": ref(scope["SEMANTIC145"], "e" * 64),
        }
        self.writer = {
            "consumer_seal": ref(scope["CADENCE"] / "deployment-seal-receipt.json", scope["CADENCE_SHA"]),
            "invocation_id": "3" * 32,
        }
        self.claim = {
            "registration": self.lease, "invocation_id": "4" * 32,
            "pid": 642, "start_ticks": 73, "scratch_bytes": 8 << 20,
            "memory_bytes": 192 << 20, "additional_cpu_quota_micros": 0,
        }
        source = ref("/fixture/retry4_source.json", "1" * 64)
        self.quote = {
            "schema": "horizon-incident-replay-fit-v1", "epoch": 145, "fleet": self.accepted,
            "phase145": self.phase, "status_registration": self.writer,
            "fits": True, "candidate": None, "resource_credit_bytes": 0,
            "replay_launch_authorized": False, "bounded_qualification": self.claim,
            "recorded_unix_seconds": 1000, "available_HOME_bytes": 2_000_000,
            "complete_required_HOME_bytes": 1_000_000, "available_memory_bytes": 1 << 40,
            "required_available_memory_bytes": 1 << 39, "survivors": {"172": {}},
            "replacements": {"167": {}}, "retry5_retained_source": source,
            "bookings": {"168": {"remaining_bytes": 100_000}},
            "retry5_complete_booking": {
                "schema": "horizon-168-retry5-complete-booking-v1", "funded": True,
                "retained_source": source, "candidate_remaining_bytes": 100_000,
                "complete_required_HOME_bytes": 1_000_000, "retained_base_HOME_bytes": 900_000,
            },
            "native_before_registered_floor": 700_000, "prefix_before": {"child": "fixture"},
            "prefix_after": {"child": "fixture"},
            "epoch159_donor_cover": {
                "fleet": self.accepted, "credited_retirement_bytes": 0, "native_home_required": 900_000,
                "general_slot_cpu_micros": 1_000_000, "general_slot_memory_bytes": 2 << 30,
            },
        }

    def check_price(self, quote, now=1001):
        return scope["quote_contract"](quote, self.accepted, self.claim, self.phase, self.writer, now)

    def test_rejects_existing_v6_or_v8_gate(self):
        self.assertEqual(scope["completion_contract"](self.phase), self.phase)
        with self.assertRaisesRegex(ValueError, "V7 semantic"):
            scope["completion_contract"](dict(self.phase, stage="v6-semantic-complete-drained"))
        self.assertEqual(scope["writer_contract"](self.writer), self.writer)
        with self.assertRaisesRegex(ValueError, "V12 status"):
            scope["writer_contract"](dict(self.writer, consumer_seal=ref("/fixture/v8", "f" * 64)))

    def test_successor_entry_binds_its_provider_and_rejects_other_completions(self):
        source = Path(__file__).with_name("run-v7-v12-entry.py")
        routes = {"v9": "20261125", "v10": "20261126"}
        accepted = {"v7": self.phase}
        operators = {}
        with TemporaryDirectory() as temporary:
            for version, date in routes.items():
                package = Path(temporary) / f"tools-post145-{version}-v12-sequence-{date}-v1"
                package.mkdir()
                operator = package / "run-v7-v12-entry.py"
                operator.write_bytes(source.read_bytes())
                successor = runpy.run_path(str(operator))
                self.assertIn(f"tools-homefloor-145-post-{version}-build-v1", str(successor["PROVIDER"]))
                operators[version] = successor["completion_contract"]
                accepted[version] = {
                    "stage": f"{version}-semantic-complete-drained",
                    "completed_invocation_id": successor["OWNER145"],
                    "checker_seal": ref(successor["CHECKER145"] / "deployment-seal-receipt.json",
                                        successor["CHECKER145_SHA"]),
                    "completion": ref(successor["COMPLETE145"], "d" * 64),
                    "semantic_receipt": ref(successor["SEMANTIC145"], "e" * 64),
                }
        for version, check in operators.items():
            for other, completion in accepted.items():
                with self.subTest(version=version, receipt=other):
                    if version == other:
                        self.assertEqual(check(completion), completion)
                    else:
                        with self.assertRaisesRegex(ValueError, f"{version.upper()} semantic"):
                            check(completion)

    def test_price_retains_both_replay_rosters_and_delivery_coverage(self):
        self.check_price(self.quote)
        self.quote["replacements"]["168"] = {}
        self.check_price(self.quote)
        for field, wrong in (
            ("survivors", {}), ("replacements", {"167": {}, "168": {}, "166": {}}),
            ("retry5_retained_source", None), ("prefix_before", {}), ("resource_credit_bytes", 1),
            ("status_registration", {}), ("bounded_qualification", {}), ("fleet", self.predecessor),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check_price(dict(self.quote, **{field: wrong}))
        for group, field in (("epoch159_donor_cover", "general_slot_memory_bytes"),
                             ("retry5_complete_booking", "candidate_remaining_bytes")):
            crossed = deepcopy(self.quote)
            crossed[group][field] = 0
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check_price(crossed)
        with self.assertRaises(ValueError):
            self.check_price(self.quote, now=1121)

    def test_only_accepted_exact_lease_reaches_original_issuer(self):
        fit_path = self.path.with_name("ENTRY146_RELEASE_FIT.json")
        fit = ref(fit_path, "f" * 64)
        files = {self.path: self.accepted, fit_path: fit}
        issued = []
        stored = []
        live = {scope["LEASE_FIELD"]: self.lease, "previous_Root_operational_review": self.predecessor}
        provider = {
            "fleet_head": lambda _: (live, ()), "registered_status": lambda: self.writer,
            "bounded142": {"held146": lambda _, registration: self.claim if registration == self.lease else None},
            "s": object(),
        }
        evidence = {"bound": lambda path: files[path], "durable": lambda path, data: stored.append((path, data))}
        original = "/fixture/existing-held-entry"

        def command(args, **kwargs):
            issued.append((args, kwargs))
            return type("Result", (), {"returncode": 0, "stdout": json.dumps(self.quote), "stderr": ""})()

        with patch.object(Path, "is_file", return_value=True), patch.object(scope["os"].path, "lexists", return_value=False), \
                patch.object(scope["time"], "time", return_value=1001), \
                patch.object(scope["subprocess"], "run", side_effect=command), \
                patch.dict(run_scope, remaining=lambda *_: 160):
            call = lambda: release(evidence, provider, self.predecessor, self.phase, self.writer,
                                   {"launcher": {"path": original}}, self.path, self.lease, self.claim, 1005)
            live[scope["LEASE_FIELD"]] = ref("/fixture/foreign", "1" * 64)
            with self.assertRaisesRegex(ValueError, "exact held lease"):
                call()
            self.assertEqual(issued, [])
            live[scope["LEASE_FIELD"]] = self.lease
            call()
            self.assertEqual(stored, [(fit_path, self.quote)])
            self.assertEqual(issued[1][0], (original, "--issue-release", str(self.path),
                                             self.accepted["sha256"], fit["sha256"]))


if __name__ == "__main__":
    unittest.main()
