from copy import deepcopy
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest

scope = runpy.run_path(str(Path(__file__).with_name("retry5_fit.py")))


def need(value, reason):
    if not value:
        raise ValueError(reason)


class Retry5Reproduction(unittest.TestCase):
    def test_full_growth_keeps_retry5_once_and_honors_its_absolute_floor(self):
        cap, growth, lag = 512 << 30, 2 << 30, 8 << 30
        donor_home = 9_000_000_000_000
        native = dict(epoch=145, fits=True, complete_required_HOME_bytes=donor_home - 5000,
                      full166_zero_remaining_native_HOME_bytes=donor_home - 9000,
                      active168_guard_floor=0, retry5_retained_source={"path": "/retained"},
                      stopped_cold168={"terminal": {"path": "/stopped"}, "measured_physical_bytes": cap - growth},
                      bookings={"168": {"remaining_bytes": 0}}, reproduction166_owner={"pid": 42})
        current = dict(physical_bytes=cap - growth, remaining_bytes=growth)
        retained = dict(physical_bytes=cap - growth, remaining_bytes=0)
        donor = dict(native_home_required=donor_home, native_home_available=donor_home + lag + growth + 1000)
        cold168 = dict(CAP=cap, OUTSIDE_CAP_STOP_ALLOWANCE=lag)
        for guard in (0, donor_home + lag + 500):
            with self.subTest(guard=guard):
                n = dict(deepcopy(native), active168_guard_floor=guard)
                quote = scope["price166"](SimpleNamespace(need=need), n, current, retained, donor, cold168)
                expected_current = max(donor_home + lag, guard) + growth
                expected_zero = max(donor_home + lag - 4000, guard) + growth
                self.assertEqual(quote["complete_required_HOME_bytes"], expected_current)
                self.assertEqual(quote["full166_retry5_projection"]["funded_zero_remaining_HOME_bytes"], expected_zero)
                self.assertEqual(quote["reproduction166_owner"], native["reproduction166_owner"])
                self.assertEqual(quote["epoch159_donor_cover"]["native_home_required"], donor_home)
        crossed = dict(deepcopy(native), full166_zero_remaining_native_HOME_bytes=donor_home)
        with self.assertRaisesRegex(ValueError, "base and donor projections"):
            scope["price166"](SimpleNamespace(need=need), crossed, current, retained, donor, cold168)

if __name__ == "__main__":
    unittest.main()
