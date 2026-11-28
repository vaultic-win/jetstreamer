import unittest

from floor143 import G, M, MAX_STARTUP_CUSHION, quote_guard_floor


class GuardFloorTest(unittest.TestCase):
    def setUp(self):
        self.old = 9_507_419_406_229
        self.margin = 56_539_251_901
        self.remaining = 64 * G - 16384

    def quote(self, moving, armed=None, raw_floor=None, margin=None):
        if raw_floor is None:
            raw_floor = max(moving, armed or 0) + self.remaining + 64 * M
        return quote_guard_floor(
            dict(guard_floor=raw_floor, guarded_hourly_remaining=self.remaining),
            dict(required_home=moving + 36 * G + 44 * G + 64 * M),
            [9_470_567_509_909], self.margin if margin is None else margin,
            None if armed is None else dict(floor=armed))

    def test_guard_can_hold_when_peer_accounted_usage_moves(self):
        before = self.quote(self.old)
        armed = before["guard_floor_bytes"]
        self.assertEqual(armed, self.old + MAX_STARTUP_CUSHION)
        self.assertEqual(before["additional_home_charge_bytes"], MAX_STARTUP_CUSHION)
        after = self.quote(self.old + G, armed)
        self.assertTrue(after["guard_floor_fits"])
        self.assertEqual(after["guard_floor_bytes"], armed)
        self.assertEqual(after["required_guard_floor_bytes"], self.old + G)
        self.assertEqual(after["additional_home_charge_bytes"], 0)

    def test_exact_floor_passes_and_one_byte_short_refuses(self):
        armed = self.quote(self.old)["guard_floor_bytes"]
        self.assertTrue(self.quote(armed, armed)["guard_floor_fits"])
        self.assertFalse(self.quote(armed + 1, armed)["guard_floor_fits"])

    def test_one_byte_omitted_from_held_reservation_refuses(self):
        armed = self.quote(self.old)["guard_floor_bytes"]
        with self.assertRaisesRegex(ValueError, "lost the armed floor"):
            self.quote(self.old, armed, armed + self.remaining + 64 * M - 1)

    def test_tight_headroom_pays_for_a_smaller_cushion(self):
        self.assertEqual(self.quote(self.old, margin=100)["additional_home_charge_bytes"], 50)
        self.assertEqual(self.quote(self.old, margin=-1)["additional_home_charge_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
