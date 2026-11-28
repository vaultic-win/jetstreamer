"""Exercise the successor in an isolated V47 package with no producer or systemd writes."""

import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import sys
import unittest
from unittest.mock import patch

package = Path(sys.argv.pop(1))
sys.path.insert(0, str(package))
import status_cycle as cycle
import cutover47 as cutover
import rolling170_fourth_status as rolling
import watch143_versions as watch


class SuccessorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = rolling.interface()
        cls.head = max(
            cycle.BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
            key=lambda p: p.stat().st_mtime_ns,
        )
        cls.fleet = cycle.checked(cycle.bound(cls.head))
        cls.row = cls.fleet[rolling.FIELD]
        cls.config = cycle.sealed(cls.fleet["sole_next_observer"])

    def test_ordinary_entry_and_retained_population(self):
        self.assertEqual(cycle.FAILED166_VERSION, 47)
        self.assertEqual(cycle.successor170_status, rolling)
        self.assertEqual(rolling.retained_population(self.fleet, self.config), self.row)
        self.assertEqual(
            rolling.contract.previous_owner(self.row, self.scope), self.row
        )
        prior = self.row
        self.assertEqual(prior["release"], self.scope["old_release"])
        with (
            patch.object(rolling.following, "ACTOR", package / "absent"),
            patch.object(rolling.history, "observe", return_value=prior),
        ):
            result = rolling.observe(None, prior, None)
        self.assertIs(result, prior)

    def test_cannot_replace_live_predecessor(self):
        with (
            patch.object(rolling.following, "ACTOR", package / "status_cycle.py"),
            patch.object(rolling.history, "observe", return_value=self.row),
            patch.object(rolling.following, "observe") as attempt,
        ):
            with self.assertRaisesRegex(ValueError, "closed cleanly"):
                rolling.observe(None, self.row, None)
        attempt.assert_not_called()

    def terminal(self):
        return dict(
            self.row,
            phase="terminal",
            native_terminal={
                "MESSAGE_ID": "7ad2d189f7e94e70a38c781354912448",
                "INVOCATION_ID": rolling.contract.PREVIOUS_IID,
                "UNIT": self.row["actor"]["unit"],
                "_PID": "1",
                "_UID": "0",
            },
            observer_config=None,
        )

    def test_foreign_terminal_is_rejected(self):
        terminal = self.terminal()
        self.assertIs(
            rolling.contract.previous_owner(terminal, self.scope, terminal=True),
            terminal,
        )
        for bad in (
            dict(terminal, actor_ref={}),
            dict(terminal, release={}),
            dict(
                terminal,
                native_terminal=dict(
                    terminal["native_terminal"], INVOCATION_ID="foreign"
                ),
            ),
            dict(
                terminal,
                native_terminal=dict(
                    terminal["native_terminal"],
                    MESSAGE_ID="98e322203f7a4ed290d09fe03c09fe15",
                ),
            ),
        ):
            with (
                self.subTest(bad=bad["native_terminal"]["MESSAGE_ID"]),
                self.assertRaises(ValueError),
            ):
                rolling.contract.previous_owner(bad, self.scope, terminal=True)

    def test_terminal_turnover_preserves_older_owners(self):
        term = self.terminal()
        next_row = dict(
            interface=rolling.INTERFACE,
            phase="held",
            observer_config=None,
            unit={"Id": rolling.following.UNIT},
        )
        fleet = copy.deepcopy(self.fleet)
        fleet["actual_active_private_diagnostics"] = [
            r
            for r in fleet["actual_active_private_diagnostics"]
            if r["unit"]["Id"] != self.row["unit"]["Id"]
        ]
        with (
            patch.object(rolling.following, "ACTOR", package / "status_cycle.py"),
            patch.object(rolling.history, "observe", return_value=term),
            patch.object(rolling.following, "observe", return_value=next_row),
            patch.object(
                rolling.following,
                "closed_comparison",
                return_value={"sha256": "fixture"},
            ),
        ):
            selected = rolling.observe(None, self.row, None)
            rolling.install(fleet, selected)
        self.assertEqual(fleet[rolling.PREVIOUS_FIELD], term)
        self.assertEqual(
            fleet[rolling.history.FAILED_FIELD],
            self.fleet[rolling.history.FAILED_FIELD],
        )
        self.assertEqual(
            fleet["retained_170_first_bounded_terminal"],
            self.fleet["retained_170_first_bounded_terminal"],
        )
        self.assertEqual(
            [
                r
                for r in fleet["actual_active_private_diagnostics"]
                if r["unit"]["Id"] == rolling.following.UNIT
            ],
            [selected],
        )
        self.assertEqual(selected["preceding_terminal_owner"], term)

    def test_fourth_guard_and_enrollment(self):
        head = {"key": "head"}
        writer = {"key": "writer"}
        ready = {"key": "ready"}
        plan = {"key": "plan"}
        fake_iid = "b" * 32
        actor_ref = {"key": "actor"}
        rows = {
            "head": {rolling.FIELD: self.row},
            "writer": {"ready": ready},
            "ready": {
                "successor170_interface": rolling.INTERFACE,
                "prior_successor170_interface": rolling.history.INTERFACE,
            },
            "plan": {
                "unit": rolling.following.UNIT,
                "invocation_id": fake_iid,
                "receipt_directory": self.scope["guard_receipts"],
            },
        }
        with (
            patch.object(rolling, "checked", side_effect=lambda r: rows[r["key"]]),
            patch.object(rolling, "bound", return_value=plan),
            patch.object(rolling.history.retry.native, "idle"),
            patch.object(
                rolling.following,
                "read_actor",
                return_value=(actor_ref, {"producer_invocation_id": fake_iid}),
            ),
            patch.object(
                rolling.following.native,
                "props",
                return_value={"ActiveState": "active", "InvocationID": "guard"},
            ),
            patch.object(rolling.following, "guard", return_value=({}, False)) as guard,
            patch.object(
                rolling.following, "enroll", return_value="accepted"
            ) as enroll,
        ):
            self.assertEqual(rolling.enroll({}, head, writer), "accepted")
            guard.assert_called_once()
            enroll.assert_called_once()
            guard.return_value = ({}, True)
            with self.assertRaisesRegex(ValueError, "started a worker"):
                rolling.enroll({}, head, writer)
            self.assertEqual(enroll.call_count, 1)

    def test_listener_follows_exact_v46_and_committed_v47(self):
        old = watch.resolve()
        self.assertEqual(old[4], 46)
        prior = cycle.checked(old[0])
        pk = cycle.bound(package / "deployment-seal-receipt.json")
        active_ref = {
            "path": str(watch.original.WRITER / "FAILED166_CADENCE_V47_ACTIVE.json"),
            "sha256": "7" * 64,
        }
        ready_ref = {"path": "fixture-ready", "sha256": "1" * 64}
        future = dict(
            prior["new"],
            pid=3,
            invocation_id="a" * 32,
            program=str(package / "status_cycle.py"),
        )
        active = dict(new=future, old=prior["new"], ready=ready_ref)
        ready = dict(
            package=pk,
            old_owner=old[0],
            retained_143_listener=watch.LISTENER,
            retained_143_phase=cycle.checked(watch.LISTENER)["phase"],
            hourly_reader=cycle.bound(package / "first_hourly143.py"),
        )
        old_bound = watch.bound
        old_checked = watch.checked
        old_exists = Path.exists

        def bound(path):
            return active_ref if str(path) == active_ref["path"] else old_bound(path)

        def checked(ref):
            if ref == active_ref:
                return active
            if ref == ready_ref:
                return ready
            return old_checked(ref)

        manager = {
            "ActiveState": "active",
            "Job": "",
            "MainPID": "3",
            "InvocationID": future["invocation_id"],
        }
        with (
            patch.object(
                Path, "exists", lambda p: str(p) == active_ref["path"] or old_exists(p)
            ),
            patch.object(watch, "checked", side_effect=checked),
            patch.object(watch, "bound", side_effect=bound),
            patch.object(watch, "state", return_value=manager),
        ):
            new = watch.resolve()
            self.assertEqual(
                (new[0], new[3].name, new[4]), (active_ref, "booking-price-v47", 47)
            )
            event = {
                "_SYSTEMD_INVOCATION_ID": future["invocation_id"],
                "MESSAGE": json.dumps({"epoch143_writer_active": new[0]}),
            }
            self.assertTrue(watch.activation_event(event, new))
            self.assertFalse(
                watch.activation_event(
                    dict(event, _SYSTEMD_INVOCATION_ID="foreign"), new
                )
            )
            manager["InvocationID"] = "foreign"
            self.assertIsNone(watch.resolve())
            ready["retained_143_listener"] = {}
            with self.assertRaisesRegex(ValueError, "inherit"):
                watch.resolve()

    def test_writer_handoff_requires_the_rebound_listener(self):
        with patch.object(cutover, "released143", return_value=None):
            with self.assertRaises(FileNotFoundError):
                cutover.preserve143()
        value = {"path": "accepted-143"}
        with (
            patch.object(cutover, "released143", return_value=value),
            patch.object(cutover, "systemctl") as systemctl,
        ):
            self.assertEqual(cutover.rebind_listener(), {"assigned": value})
            systemctl.assert_not_called()

    def test_all_four_previous_signed_points_and_closed_manifest(self):
        c = rolling.contract
        old = c.predecessor.interface()
        dirs = Path(old["guard_seal"]["path"]).parent
        refs = [
            dict(path=str(dirs / f"reference-{slot}.json"), sha256=h)
            for (slot, _), h in zip(c.CHECKPOINTS, c.SIGNED, strict=True)
        ]
        points = [
            dict(c.checked(ref), accounts_hash=h, slot_complete=True)
            for ref, (_, h) in zip(refs, c.CHECKPOINTS, strict=True)
        ]
        prev = c.checked(self.scope["old_release"])
        evidence = {
            "comparison": "closed",
            "closed_segment": {"sha256": "sample-sha"},
            "pid1_exit": {
                "native": {
                    "InvocationID": c.PREVIOUS_IID,
                    "Result": "success",
                    "ExecMainCode": "1",
                    "ExecMainStatus": "0",
                }
            },
            "signed_checkpoints": refs,
            "signed_endpoint": refs[-1],
        }
        report = dict(
            schema="horizon-170-successor-closed-checkpoint-comparison-v1",
            evidence=evidence,
            release=self.scope["old_release"],
            actor=self.scope["old_actor"],
            interface=c.predecessor.INTERFACE,
            predecessor=prev["closed_comparison"],
            checkpoints=points,
            canonical_publication_authorized=False,
        )
        manifest = dict(
            terminal=points[-1],
            archive_sha256="sample-sha",
            output_slot_start=73746883,
            output_slot_count=20087,
        )
        c.verify_comparison(self.scope, report, manifest)
        with self.assertRaisesRegex(ValueError, "predecessor closure"):
            c.verify_comparison(
                self.scope, report, dict(manifest, output_slot_count=20086)
            )
        report["checkpoints"][2] = dict(points[2], bank_hash="wrong")
        with self.assertRaisesRegex(ValueError, "signed checkpoint"):
            c.verify_comparison(self.scope, report, manifest)

    def test_cutover_inherits_one_timer_and_is_idempotent(self):
        old = cycle.checked(cycle.bound(cutover.OLD_ACTIVE))["new"]
        future = dict(
            old,
            pid=300,
            invocation_id="f" * 32,
            program=str(package / "status_cycle.py"),
        )
        timer = self.fleet["sole_next_timer"]
        observation = {"Id": timer, "NextElapseUSecRealtime": "fixture"}
        proposed = dict(
            fleet=cycle.bound(self.head),
            timer=timer,
            completed_sample=None,
            old_owner=cycle.bound(cutover.OLD_ACTIVE),
            package=cycle.bound(package / "deployment-seal-receipt.json"),
        )
        with TemporaryDirectory() as directory:
            temp = Path(directory)
            candidate = temp / "input.json"
            candidate.write_text(json.dumps(proposed))
            manager = temp / "units"
            wd = manager / (cutover.WRITER + ".d")
            wd.mkdir(parents=True)
            (wd / "old-v46-entry146.conf").write_text(str(cutover.OLD))
            ready, active = temp / "READY.json", temp / "ACTIVE.json"

            def fake_action(action, *units):
                if action == "restart":
                    self.assertEqual(units, (cutover.WRITER,))
                    active.write_text(
                        json.dumps(dict(new=future, old=old, ready=cutover.ref(ready)))
                    )
                else:
                    self.assertEqual((action, units), ("daemon-reload", ()))

            def cmd(*args):
                if args[0] == "/usr/bin/date":
                    return str(int(time.time()) + 900)
                self.assertEqual(args[3], "--check-v47-handoff")
                return json.dumps(proposed)

            with (
                patch.multiple(
                    cutover, READY=ready, ACTIVE=active, SYSTEMD_DIRECTORY=manager
                ),
                patch.object(cutover, "old_process", return_value=True),
                patch.object(cutover, "owner"),
                patch.object(cutover, "preserve143"),
                patch.object(
                    cutover, "endpoints", return_value={"actors": "identical"}
                ),
                patch.object(cutover, "clock", return_value=observation) as clock,
                patch.object(cutover, "command", side_effect=cmd),
                patch.object(
                    cutover, "systemctl", side_effect=fake_action
                ) as systemctl,
                patch.object(
                    cutover,
                    "state",
                    return_value={"ExecStart": str(package / "status_cycle.py")},
                ),
            ):
                result = cutover.cutover(candidate)
                self.assertEqual(result, cutover.ref(active))
                self.assertEqual(cutover.cutover(candidate), result)
                self.assertEqual(systemctl.call_count, 2)
                self.assertTrue(
                    all(call.args == (timer,) for call in clock.call_args_list)
                )

    def test_booking_and_listener_keep_native_limits(self):
        import importlib.util

        booker = watch.original.TARGET / "booking-price-v47"
        spec = importlib.util.spec_from_file_location(
            "fixture_booker", booker / "prepare143.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(booker))
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path.pop(0)
        with self.assertRaisesRegex(ValueError, "V47 booking writer pin"):
            module.prepare(28800, ["a", "b"])
        self.assertEqual(module.funding.TREE, 64 << 30)
        self.assertEqual(module.funding.RAM, 41 << 30)
        self.assertEqual(module.funding.EVIDENCE, 64 << 20)


if __name__ == "__main__":
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SuccessorTest)
    )
    raise SystemExit(not result.wasSuccessful())
