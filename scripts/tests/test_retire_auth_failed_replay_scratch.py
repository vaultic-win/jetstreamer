import json
from pathlib import Path
import subprocess
from subprocess import CompletedProcess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import retire_auth_failed_replay_scratch as retire


class AuthFailedScratchRetirementTests(unittest.TestCase):
    def test_direct_cli_help_is_cwd_independent(self) -> None:
        with TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [sys.executable, str(Path(retire.__file__).resolve()), "--help"],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def make_run(self, root: Path, start: int = 159, end: int = 162) -> tuple[Path, dict]:
        run = root / "work" / f"root-cohort-{start}-{end}" / "run-12-34"
        run.mkdir(parents=True, mode=0o700)
        run.chmod(0o700)
        for name in ("archives", "inputs", "scratch"):
            (run / name).mkdir(mode=0o700)
        state = {
            "schema": retire.RUN_STATE_SCHEMA,
            "status": "running-private",
            "start_epoch": start,
            "end_epoch": end,
            "manifest_fingerprint": "sha256:" + "a" * 64,
        }
        state_path = run / "cohort-state.json"
        state_path.write_text(json.dumps(state) + "\n")
        state_path.chmod(0o600)
        item = {
            "label": f"{start}-{end}",
            "start_epoch": start,
            "end_epoch": end,
            "run_directory": str(run),
            "scratch": str(run / "scratch"),
            "cohort_state_sha256": retire.base.sha256_file(state_path),
        }
        return run, item

    @patch("scripts.retire_reboot_interrupted_replay_scratch.os.path.ismount", return_value=False)
    def test_validate_empty_cursor_free_run(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            run, item = self.make_run(Path(temporary))
            evidence = retire.validate_run(item, allow_missing_scratch=False)
            self.assertEqual(evidence["scratch"], str(run / "scratch"))
            self.assertGreaterEqual(evidence["scratch_physical_bytes"], 0)

    @patch("scripts.retire_reboot_interrupted_replay_scratch.os.path.ismount", return_value=False)
    def test_rejects_download_fragment(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            run, item = self.make_run(Path(temporary))
            (run / "inputs" / "payload").write_bytes(b"partial")
            with self.assertRaisesRegex(retire.RetirementError, "inputs is not empty"):
                retire.validate_run(item, allow_missing_scratch=False)

    @patch("scripts.retire_reboot_interrupted_replay_scratch.os.path.ismount", return_value=False)
    def test_accepts_only_missing_scratch_after_intent(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            run, item = self.make_run(Path(temporary))
            (run / "scratch").rmdir()
            with self.assertRaisesRegex(retire.RetirementError, "scratch is absent"):
                retire.validate_run(item, allow_missing_scratch=False)
            evidence = retire.validate_run(item, allow_missing_scratch=True)
            self.assertIsNone(evidence["scratch_identity"])

    @patch("scripts.retire_auth_failed_replay_scratch.subprocess.run")
    def test_journal_requires_both_bound_failures(self, run) -> None:
        unit = "producer.service"
        invocation = "1" * 32
        entries = [
            {
                "_SYSTEMD_UNIT": unit,
                "_SYSTEMD_INVOCATION_ID": invocation,
                "__REALTIME_TIMESTAMP": "100",
                "MESSAGE": retire.AUTH_FAILURE,
            },
            {
                "_SYSTEMD_UNIT": unit,
                "_SYSTEMD_INVOCATION_ID": invocation,
                "__REALTIME_TIMESTAMP": "101",
                "MESSAGE": retire.DOWNLOAD_FAILURE + " 123",
            },
        ]
        run.return_value = CompletedProcess([], 0, "\n".join(json.dumps(item) for item in entries), "")
        evidence = retire.validate_failure_journal("2" * 32, {
            "producer_unit": unit,
            "producer_invocation_id": invocation,
        })
        self.assertEqual(evidence["matching_entries"], 2)


if __name__ == "__main__":
    unittest.main()
