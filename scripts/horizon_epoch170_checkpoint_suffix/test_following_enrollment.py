"""Exercise both active writer versions and reject crossing their bounded interfaces."""

import os
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

import continuation_dispatch as dispatch


class EnrollmentWriterTests(TestCase):
    def setUp(self):
        context = ExitStack()
        self.addCleanup(context.close)
        self.root = Path(context.enter_context(TemporaryDirectory()))
        self.base = self.root / "survivor172-cadence-20261122-v1"
        self.base.mkdir()
        self.q = dispatch.q
        context.enter_context(patch.object(self.q, "RT", self.root))
        self.docs = {}
        context.enter_context(
            patch.object(self.q, "bound", lambda ref: self.docs[ref["path"]])
        )
        context.enter_context(
            patch.object(self.q, "read", lambda path: (self.docs[str(path)], {"path": str(path)}))
        )
        self.iid = "4f" * 16
        self.state = {
            "ActiveState": "active",
            "InvocationID": self.iid,
            "MainPID": str(os.getpid()),
        }
        context.enter_context(patch.object(self.q, "state", lambda unit: self.state))
        self.current = {"path": "current", "sha256": "c" * 64}
        self.prior = {"path": "prior", "sha256": "p" * 64}
        self.interface = {
            "old_release": {"path": "release"},
            "previous_interface": self.prior,
        }
        self.docs["release"] = {"interface": self.prior}

    def stage(self, version):
        pkg = self.base / f"tools-cold168-retry5-failed166-v{version}-entry146"
        pkg.mkdir()
        program = pkg / "status_cycle.py"
        program.write_bytes(b"fixture")
        seal = str(pkg / "deployment-seal-receipt.json")
        self.docs[seal] = {
            "destination": str(pkg),
            "members": [
                {"name": program.name, "sha256": sha256(b"fixture").hexdigest()}
            ],
        }
        self.docs["ready"] = {
            "package": {"path": seal},
            "successor170_interface": self.current,
            "prior_successor170_interface": self.prior,
        }
        active = self.base / f"FAILED166_CADENCE_V{version}_ACTIVE.json"
        ticks = int(Path("/proc/self/stat").read_text().rsplit(") ", 1)[1].split()[19])
        self.docs[str(active)] = {
            "schema": "horizon-epoch166-cadence-rejoin-active-v1",
            "producer_mutations": False,
            "ready": {"path": "ready"},
            "new": {
                "unit": "fixture",
                "program": str(program),
                "invocation_id": self.iid,
                "pid": os.getpid(),
                "start_ticks": ticks,
            },
        }
        self.docs[str(dispatch.operator.ENROLLING_FOLLOWING / "binding.json")] = {
            "writer_active": {"path": str(active)}
        }
        return program

    def test_v46_uses_the_retry_interface(self):
        program = self.stage(46)
        with patch.object(self.q, "RETRY", True):
            self.assertEqual(
                dispatch.enrollment_writer(self.interface, self.current), program
            )

    def test_v47_checks_the_predecessors_release_and_native_writer(self):
        program = self.stage(47)
        with patch.object(self.q, "OPERATOR", dispatch.operator.ENROLLING_FOLLOWING):
            self.assertEqual(
                dispatch.enrollment_writer(self.interface, self.current), program
            )
            self.docs["ready"]["prior_successor170_interface"] = self.current
            with self.assertRaisesRegex(ValueError, "active writer"):
                dispatch.enrollment_writer(self.interface, self.current)
            self.docs["ready"]["prior_successor170_interface"] = self.prior
            self.state["InvocationID"] = "9b" * 16
            with self.assertRaisesRegex(ValueError, "active writer"):
                dispatch.enrollment_writer(self.interface, self.current)

    def test_reconciled_operator_consumes_only_the_matching_v48_handoff(self):
        self.stage(47)
        predecessor = self.base/"FAILED166_CADENCE_V47_ACTIVE.json"
        anchor = {"path": str(predecessor)}
        original = self.docs[str(predecessor)]["new"]
        original["lock"] = {"path": "/tmp/fixture", "device": 12, "inode": 15, "fd": 3}
        program = self.stage(48)
        successor = self.base/"FAILED166_CADENCE_V48_ACTIVE.json"
        successor.touch()
        self.docs[str(successor)]["old"] = original
        self.docs[str(successor)]["new"]["lock"] = original["lock"]
        self.docs["ready"]["old_owner"] = anchor
        self.docs[str(dispatch.operator.RECONCILED_FOLLOWING/"binding.json")] = {"writer_active": anchor}
        with patch.object(self.q, "OPERATOR", dispatch.operator.RECONCILED_FOLLOWING):
            self.assertEqual(dispatch.enrollment_writer(self.interface, self.current), program)
            self.docs["ready"]["old_owner"] = {"path": "different"}
            with self.assertRaisesRegex(ValueError, "did not inherit"):
                dispatch.enrollment_writer(self.interface, self.current)

    def test_split_operator_tracks_all_transitions_through_v49(self):
        previous, owner = None, None
        for version in (47,48,49):
            program = self.stage(version)
            path = self.base / f"FAILED166_CADENCE_V{version}_ACTIVE.json"
            path.touch()
            ref = {"path": str(path)}
            value = self.docs[str(path)]
            value["new"]["lock"] = {"path":"/tmp/fixture", "device":11, "inode":24, "fd":3}
            ready_ref = {"path":f"ready{version}"}
            self.docs[ready_ref["path"]] = self.docs["ready"].copy()
            value["ready"] = ready_ref
            if version == 47:
                self.docs[str(dispatch.operator.SPLIT_FOLLOWING/"binding.json")] = {"writer_active":ref}
            else:
                self.docs[ready_ref["path"]]["old_owner"] = previous
                value["old"] = owner
            previous, owner = ref, value["new"]
        with patch.object(self.q,"OPERATOR",dispatch.operator.SPLIT_FOLLOWING):
            self.assertEqual(dispatch.enrollment_writer(self.interface,self.current),program)
            self.docs["ready49"]["old_owner"] = {"path":"foreign"}
            with self.assertRaisesRegex(ValueError,"V49 did not inherit"):
                dispatch.enrollment_writer(self.interface,self.current)


if __name__ == "__main__":
    main()
