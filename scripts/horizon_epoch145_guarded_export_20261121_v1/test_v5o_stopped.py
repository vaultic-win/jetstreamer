"""Exercise the stopped quote against the retained host receipts."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v5o_stopped as stopped


@unittest.skipUnless(os.geteuid() == 0 and stopped.TERMINAL.is_file(), "retained epoch 145 host evidence required")
class StoppedStatusOwnerTest(unittest.TestCase):
    def test_original_inode_and_failure(self):
        phase = stopped.stopped_phase(None, SimpleNamespace(members=lambda unit: []))
        self.assertEqual(phase["InvocationID"], stopped.IID)
        self.assertEqual(phase["candidate"]["inode"], 103237059)
        self.assertFalse(phase["source_checkpoint_exists"])
        self.assertEqual(phase["resource_credit_bytes"], 0)

    def test_foreign_terminal_digest_is_rejected(self):
        with patch.object(stopped, "TERMINAL_SHA", "0" * 64), self.assertRaises(ValueError):
            stopped.historical()

    def test_another_cgroup_member_blocks_the_quote(self):
        fit = SimpleNamespace(members=lambda unit: [2])
        with self.assertRaisesRegex(ValueError, "stopped V5o manager or cgroup"):
            stopped.stopped_phase(None, fit)


if __name__ == "__main__":
    unittest.main()
