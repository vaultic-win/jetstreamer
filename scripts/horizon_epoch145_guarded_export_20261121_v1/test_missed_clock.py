"""Replay the original registered 12:47 RSS rejection and its 13:17 replacement."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import runpy
import unittest

m = runpy.run_path(str(Path(__file__).with_name("missed_clock.py")))
ROOT, read, clock = m["ROOT"], m["read"], m["clock"]
PRIOR = dict(path=str(ROOT / "root121757-live166167170-20261123-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
             sha256="937c0e995d7a5b8d1361979486ce8ed62051ba15802e5841b9d005de0c3b573c")
REAL = "2263383ef93cd20221f08ffb3b24e0cc108a82c154955a8e148e837b5f19608c"
NEXT = ROOT / "root131757-live166167170-20261123-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"


def at(minute, second=0):
    return int(datetime(2026, 11, 23, 13, minute, second, tzinfo=timezone.utc).timestamp())


class ClockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fleet, _ = read(PRIOR["path"], PRIOR)
        cls.actual = {}

        def record(path, expected=None):
            value = read(path, expected)
            cls.actual[Path(path)] = value
            return value
        cls.good = clock(PRIOR, cls.fleet, at(20), record)

    def setUp(self):
        self.rows = deepcopy(self.actual)

    def get(self, path, expected=None):
        path = Path(path)
        if path not in self.rows:
            raise FileNotFoundError(path)
        v, b = self.rows[path]
        if expected is not None and b != expected:
            raise ValueError("changed bound evidence")
        return v, b

    def test_real_positive(self):
        self.assertEqual(self.good["fleet"], {"path": str(NEXT), "sha256": REAL})
        self.assertEqual(clock(PRIOR, self.fleet, at(20), self.get), self.good)

    def test_no_registration(self):
        del self.rows[next(k for k in self.rows if k.name == "REGISTERED.json")]
        self.assertEqual(clock(PRIOR, self.fleet, at(20), self.get), {"state": "ordinary"})

    def test_pending_has_one_fixed_deadline(self):
        del self.rows[NEXT]
        a = clock(PRIOR, self.fleet, at(0), self.get)
        self.assertEqual((a["state"], a["expected_fleet"], a["deadline"]), ("pending", str(NEXT), at(22, 57)))
        self.assertEqual(a, clock(PRIOR, self.fleet, at(22, 57), self.get))
        with self.assertRaisesRegex(ValueError, "did not complete in time"):
            clock(PRIOR, self.fleet, at(22, 58), self.get)

    def test_foreign_or_partial_replacement(self):
        good = Path(self.rows[NEXT][0]["observer"]["path"])
        reg = next(k for k in self.rows if k.name == "REGISTERED.json")
        bad = next(k for k in self.rows if k.name == "TERMINAL.json")
        sample = Path(self.rows[bad][0]["failed_sample"]["path"])
        cfg = Path(self.rows[reg][0]["config"]["path"])
        for path, keys, value in [
                (NEXT, ["previous_Root_operational_review", "sha256"], "0"*64),
                (NEXT, ["owner"], "/second"), (NEXT, ["observer", "sha256"], "0"*64),
                (good, ["host_resident_memory", "after", "status"], "unavailable"),
                (good, ["host_resident_memory","before","rss","aggregate_rss_bytes"], 1),
                (good, ["cadence", "minimum_interval_seconds"], 0),
                (good, ["cadence", "previous_sample_sha256"], "0"*64),
                (bad, ["error"], "unrelated failure"), (bad, ["fleet", "sha256"], "0"*64),
                (cfg, ["minimum_interval_seconds"], 0), (sample, ["cadence","observed_interval_seconds"], 1799),
                (reg, ["config", "sha256"], "0"*64)]:
            with self.subTest(keys=keys):
                self.rows = deepcopy(self.actual)
                target = self.rows[path][0]
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(ValueError):
                    clock(PRIOR, self.fleet, at(20), self.get)

    def test_future_report(self):
        with self.assertRaises(ValueError):
            clock(PRIOR, self.fleet, at(16), self.get)


if __name__ == "__main__":
    unittest.main()
