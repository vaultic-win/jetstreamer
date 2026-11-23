"""Original negative observations must still be rejected before the candidate can advance."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import feature156
import service


class BackportTest(unittest.TestCase):
    def test_original_first_child_and_preboundary_state(self):
        feature156.check_checkpoint({"slot": 68687834, "bank_hash": "EFqpcE6fy4Ay8b3Qe81Sau3hyMLFLthQTY2FM9Bh94cL"})
        with self.assertRaisesRegex(ValueError, "signed Bank"):
            feature156.check_checkpoint({"slot": 68687834, "bank_hash": "5yUrdVmbsPTJbAY1kvq3KmaZkTkwRXwHyR6kZHSQ6km2"})
        state = feature156.spec()["original_last_158_checkpoint"]
        feature156.check_checkpoint(state)
        with self.assertRaisesRegex(ValueError, "checkpoint"):
            feature156.check_checkpoint(dict(state, transaction_count=state["transaction_count"] - 1))

    def test_byte_order_fee_and_success(self):
        rows = [("ab" * 64, None, 5000), ("cd" * 64, {"custom": 2}, 5000)]
        expected = feature156.transaction_digest(rows)
        self.assertNotEqual(feature156.transaction_digest(rows[::-1]), expected)
        self.assertNotEqual(feature156.transaction_digest([rows[0], (rows[1][0], None, 5000)]), expected)
        self.assertNotEqual(feature156.transaction_digest([(rows[0][0], None, 0), rows[1]]), expected)

    def test_predecessor_requires_free_allocation_and_different_dispatch(self):
        with patch.object(service, "UNIT", feature156.UNIT):
            self.assertEqual(service.profile_args(), ["--feature156"])
            self.assertIn("MemorySwapMax=0", " ".join(service.system_argv("receipt")))
            state = "ActiveState=active\nMainPID=17\nControlPID=0\nJob=\nInvocationID=other\nExecStart=/tools-v5n/export145\n"
            with patch.object(service.sp, "check_output", return_value=state):
                with self.assertRaisesRegex(ValueError, "145 verifier"):
                    service.check_feature_donor()


if __name__ == "__main__":
    unittest.main()
