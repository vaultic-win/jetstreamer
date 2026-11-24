"""Exercise the stopped-verifier quote with the retained host evidence."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v5p_stopped as stopped


@unittest.skipUnless(os.geteuid() == 0 and stopped.TERMINAL.is_file(), "retained epoch 145 host evidence required")
class PublicAuditTurnoverTest(unittest.TestCase):
    def test_stopped_generation_retains_candidate_without_a_checkpoint(self):
        phase = stopped.stopped_phase(None, SimpleNamespace(members=lambda _: []))
        self.assertEqual(phase["InvocationID"], stopped.IID)
        self.assertEqual(phase["candidate"]["inode"], 103237059)
        self.assertEqual(phase["public_audit_terminal"]["sha256"], stopped.TERMINAL_SHA)
        self.assertFalse(phase["source_checkpoint_exists"])
        self.assertEqual(phase["resource_credit_bytes"], 0)

    def test_foreign_terminal_digest_is_rejected(self):
        with patch.object(stopped, "TERMINAL_SHA", "0" * 64), self.assertRaises(ValueError):
            stopped.historical()

    def test_live_claimant_blocks_the_quote(self):
        fit = SimpleNamespace(members=lambda _: [2])
        with self.assertRaisesRegex(ValueError, "stopped V5p manager or cgroup"):
            stopped.stopped_phase(None, fit)


if __name__ == "__main__":
    unittest.main()
