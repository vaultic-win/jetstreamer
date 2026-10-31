import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import retire_reboot_interrupted_replay_scratch as retire


FINGERPRINT = "sha256:" + "a" * 64


class RebootInterruptedScratchRetirementTest(unittest.TestCase):
    def make_run(self, root: Path) -> tuple[dict[str, object], Path]:
        destination = root / ("destination-" + "b" * 64)
        run = destination / "work" / "root-cohort-183-184" / "run-123-456"
        for directory in (
            destination,
            destination / "work",
            run.parent,
            run,
            run / "archives",
            run / "inputs",
            run / "scratch",
        ):
            directory.mkdir(exist_ok=True)
            directory.chmod(0o700)
        state = {
            "end_epoch": 184,
            "manifest_fingerprint": FINGERPRINT,
            "schema": retire.RUN_STATE_SCHEMA,
            "start_epoch": 183,
            "status": "running-private",
        }
        (run / "cohort-state.json").write_text(json.dumps(state))
        (run / "cohort-state.json").chmod(0o600)
        archive = run / "archives" / "epoch-183.jet"
        archive.write_bytes(b"partial")
        (run / "inputs" / "snapshot.tar.zst").write_bytes(b"snapshot")
        item: dict[str, object] = {
            "label": "183-184",
            "start_epoch": 183,
            "end_epoch": 184,
            "manifest_fingerprint": FINGERPRINT,
            "run_directory": str(run),
            "scratch": str(run / "scratch"),
            "cohort_state_sha256": retire.sha256_file(run / "cohort-state.json"),
            "partial_archives": [retire.file_identity(archive)],
        }
        return item, run

    def test_run_validation_preserves_partial_archive_and_input(self) -> None:
        with tempfile.TemporaryDirectory(dir=".") as raw:
            item, run = self.make_run(Path(raw).resolve())
            evidence = retire.validate_run(item, allow_missing_scratch=False)
            self.assertEqual(evidence["label"], "183-184")
            self.assertIsNotNone(evidence["scratch_identity"])
            self.assertEqual(Path(evidence["archives"][0]["path"]).name, "epoch-183.jet")
            retire.delete_exact_tree(run / "scratch")
            preserved = retire.validate_run(item, allow_missing_scratch=True)
            self.assertIsNone(preserved["scratch_identity"])
            self.assertTrue((run / "archives" / "epoch-183.jet").is_file())
            self.assertTrue((run / "inputs" / "snapshot.tar.zst").is_file())

    def test_run_validation_rejects_archive_change_and_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(dir=".") as raw:
            item, run = self.make_run(Path(raw).resolve())
            (run / "archives" / "epoch-183.jet").write_bytes(b"changed-longer")
            with self.assertRaisesRegex(retire.RetirementError, "archive identity changed"):
                retire.validate_run(item, allow_missing_scratch=False)
            item["partial_archives"] = [
                retire.file_identity(run / "archives" / "epoch-183.jet")
            ]
            (run / "archives" / "epoch-183.jet.sha256").write_text("bad")
            item["partial_archives"] = sorted(
                [
                    retire.file_identity(run / "archives" / "epoch-183.jet"),
                    retire.file_identity(run / "archives" / "epoch-183.jet.sha256"),
                ],
                key=lambda value: value["path"],
            )
            with self.assertRaisesRegex(retire.RetirementError, "sidecar"):
                retire.validate_run(item, allow_missing_scratch=False)

    def test_process_scan_checks_command_maps_links_and_fds(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw).resolve()
            target = proc / "scratch"
            target.mkdir()
            store = target / "store"
            store.write_bytes(b"x")
            process = proc / "123"
            process.mkdir()
            (process / "cmdline").write_bytes(os.fsencode(str(target)))
            (process / "maps").write_bytes(os.fsencode(str(target)))
            (process / "fd").mkdir()
            (process / "fd" / "4").symlink_to(store)
            (process / "cwd").symlink_to(target)
            (process / "root").symlink_to(proc)
            (process / "exe").symlink_to(proc / "binary")
            with mock.patch.object(retire, "ancestor_pids", return_value={os.getpid()}):
                self.assertEqual(
                    retire.process_references(target, proc),
                    ["pid 123 cmdline", "pid 123 maps", "pid 123 cwd", "pid 123 fd 4"],
                )

    def test_caller_command_is_ignored_but_caller_map_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw).resolve()
            target = proc / "scratch"
            target.mkdir()
            process = proc / "123"
            process.mkdir()
            (process / "cmdline").write_bytes(os.fsencode(str(target)))
            (process / "maps").write_bytes(b"")
            (process / "fd").mkdir()
            for name in ("cwd", "root", "exe"):
                (process / name).symlink_to(proc)
            with mock.patch.object(retire, "ancestor_pids", return_value={123}):
                self.assertEqual(retire.process_references(target, proc), [])
            (process / "maps").write_bytes(os.fsencode(str(target)))
            with mock.patch.object(retire, "ancestor_pids", return_value={123}):
                self.assertEqual(retire.process_references(target, proc), ["pid 123 maps"])

    def test_plan_rejects_reused_labels_and_wrong_boot(self) -> None:
        item = {
            "label": "134",
            "scratch": "/private/run/scratch",
            "controller_unit": "controller.service",
            "producer_unit": "producer.service",
            "producer_invocation_id": "c" * 32,
            "last_progress_realtime_micros": 1,
            "last_progress_message": "progress",
        }
        plan = {
            "schema": retire.PLAN_SCHEMA,
            "previous_boot_id": "a" * 32,
            "current_boot_id": "b" * 32,
            "shutdown": {"realtime_micros": 1, "command": "sudo shutdown -r 0"},
            "runs": [item, dict(item)],
            "intent_receipt": "/intent",
            "completion_receipt": "/completion",
        }
        with mock.patch.object(retire, "read_boot_id", return_value="b" * 32):
            with self.assertRaisesRegex(retire.RetirementError, "unique"):
                retire.validate_plan(plan, check_journal=False)
        plan["runs"] = [item]
        with mock.patch.object(retire, "read_boot_id", return_value="d" * 32):
            with self.assertRaisesRegex(retire.RetirementError, "boot IDs"):
                retire.validate_plan(plan, check_journal=False)


if __name__ == "__main__":
    unittest.main()
