"""Exercise the live price with hard links, sparse files and changing scratch names."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import after_ram170_tree as tree


def run(*args):
    return subprocess.check_output(args, text=True)


class ClosedOccupancy(unittest.TestCase):
    def test_replay_churn_is_excluded_and_immutable_links_are_counted_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "tree"
            root.mkdir()
            old = root / "archives"
            old.mkdir()
            archive = old / "archive.jet"
            archive.write_bytes(b"x" * 16384)
            os.link(archive, root / "another-name")
            sparse = old / "sparse"
            sparse.touch()
            with sparse.open("r+b") as handle:
                handle.truncate(1 << 30)
            expected = int(run("/usr/bin/du", "-sx", "-B1", "--", str(root)).split()[0])
            active = root / "active"
            active.mkdir()
            os.link(archive, active / "from-archive")
            child = active / "accounts"
            child.mkdir()
            (child / "churn").write_bytes(b"y" * (1 << 18))
            observed = []

            def churn(*args):
                child.rename(active / "old-accounts")
                child.mkdir()
                (child / "new").write_bytes(b"z" * 8192)
                for path in (active / "old-accounts").iterdir():
                    path.unlink()
                (active / "old-accounts").rmdir()
                observed.append(args)
                return run(*args)

            self.assertEqual(tree.closed_bytes(churn, root, active), [expected, expected])
            self.assertEqual(len(observed), 2)
            self.assertIn("--exclude=" + str(active), observed[0])
            self.assertLess(expected, 1 << 20)

    def test_foreign_symlink_and_wildcard_roots_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "tree"
            root.mkdir()
            outside = root.parent / "outside"
            outside.mkdir()
            linked = root / "link"
            linked.symlink_to(outside)
            for value in (outside, linked, root, root / "active*"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    tree.closed_bytes(run, root, value)


class PhysicalSamples(unittest.TestCase):
    def setUp(self):
        self.plan = dict(maximum_root_physical_bytes=1000, minimum_free_bytes=35)
        self.sample = dict(producer_stop_enabled=True, trip_reason=None, recorded_unix_seconds=200,
                           worker_observation_error=None, root_physical_observation_error=None, available_bytes=50,
                           minimum_free_bytes=35, maximum_root_physical_bytes=1000,
                           root_physical_observation=dict(first=dict(physical_bytes=90), second=dict(physical_bytes=110),
                                                         maximum_physical_bytes=1000, conservative_physical_bytes=110,
                                                         exceeds_budget=False))

    def test_upper_bound_uses_larger_scan(self):
        self.assertEqual(tree.native_scans(self.sample, self.plan, 206), [90, 110])

    def test_errors_caps_and_staleness_are_rejected(self):
        for key, change in (("sample", {"recorded_unix_seconds": 85}),
                            ("sample", {"root_physical_observation_error": "read failed"}),
                            ("sample", {"trip_reason": "physical budget"}),
                            ("sample", {"available_bytes": 34}),
                            ("walk", {"conservative_physical_bytes": 90}),
                            ("walk", {"exceeds_budget": True}),
                            ("walk", {"first": {"physical_bytes": 1001}, "conservative_physical_bytes": 1001}),
                            ("walk", {"maximum_physical_bytes": 999})):
            sample = copy.deepcopy(self.sample)
            (sample if key == "sample" else sample["root_physical_observation"]).update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                tree.native_scans(sample, self.plan, 209)

    def test_different_issued_scope_fails_before_any_read(self):
        with self.assertRaisesRegex(ValueError, "different 170 tree owner"):
            tree.observe(dict(unit=tree.UNIT, phase="worker", interface={}), None, None, None, None)


if __name__ == "__main__":
    unittest.main()
