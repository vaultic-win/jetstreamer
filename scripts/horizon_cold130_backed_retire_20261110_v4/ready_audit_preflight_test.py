"""Exercise ready workers handing their exact ranges to accepted reports."""
from pathlib import Path
import runpy
import unittest


probe = runpy.run_path(str(Path(__file__).with_name("ready_audit_preflight.py")))
check = probe["complete_population"]


class Coverage(unittest.TestCase):
    def test_current_mixed_and_completed(self):
        regions = [[101, 135], [144, 144]]
        for active, done, n in ((regions, [], 0), (regions[:1], regions[1:], 1), ([], regions, 36)):
            summary = dict(passed=n, archives=36, pending=36-n, failed=0, complete=n == 36)
            check(active, done, {"eligible_ranges": regions}, summary)
            for field in summary:
                wrong = dict(summary, **{field: not summary[field] if field == "complete" else summary[field] + 1})
                with self.subTest(field=field, n=n), self.assertRaises(ValueError):
                    check(active, done, {"eligible_ranges": regions}, wrong)

    def test_duplicate_missing_or_foreign_range(self):
        scope = {"eligible_ranges": [[101, 135], [144, 144]]}
        summary = dict(passed=1, archives=36, pending=35, failed=0, complete=False)
        for active in ([], [[144, 144]], [[130, 135]], [[101, 135], [101, 135]]):
            with self.subTest(active=active), self.assertRaises(ValueError):
                check(active, [[144, 144]], scope, summary)


if __name__ == "__main__":
    unittest.main()
