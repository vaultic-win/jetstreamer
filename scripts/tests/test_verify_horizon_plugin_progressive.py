from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
SCRIPT = SCRIPTS / "verify_horizon_plugin_progressive.sh"
WATCHER = SCRIPTS / "watch_horizon_plugin_progressive.sh"
BOUNDARY_SCRIPT = SCRIPTS / "verify_horizon_boundaries_progressive.sh"
RANGE_SCRIPT = SCRIPTS / "verify_horizon_range.sh"


class ProgressivePluginVerificationTests(unittest.TestCase):
    def test_watcher_skips_archive_with_exact_existing_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            state = root / "state"
            receipts = state / "receipts"
            receipts.mkdir(parents=True)
            pipeline = root / "horizon_pipeline"
            pipeline.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            pipeline.chmod(pipeline.stat().st_mode | stat.S_IXUSR)
            marker = root / "unexpected-dispatch"
            verifier = root / "verifier"
            verifier.write_text(
                f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="ascii"
            )
            verifier.chmod(verifier.stat().st_mode | stat.S_IXUSR)

            archive = archives / "epoch-7.jet"
            archive.write_bytes(b"archive")
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            (archives / "epoch-7.jet.sha256").write_text(
                f"{archive_sha}  epoch-7.jet\n", encoding="ascii"
            )
            pipeline_sha = hashlib.sha256(pipeline.read_bytes()).hexdigest()
            verifier_sha = hashlib.sha256(verifier.read_bytes()).hexdigest()
            (receipts / "epoch-7.plugin.ok").write_text(
                f"{archive_sha} {pipeline_sha} {verifier_sha}\n", encoding="ascii"
            )

            result = subprocess.run(
                [
                    str(WATCHER),
                    str(verifier),
                    str(pipeline),
                    str(archives),
                    str(state),
                    "7",
                    "7",
                    pipeline_sha,
                    verifier_sha,
                    "1",
                    "1",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertIn("plugin verification complete", result.stdout)

    def test_receipt_is_published_with_file_scoped_fsync(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            state = root / "state"
            pipeline = root / "horizon_pipeline"
            pipeline.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            pipeline.chmod(pipeline.stat().st_mode | stat.S_IXUSR)

            archive = archives / "epoch-7.jet"
            archive.write_bytes(b"archive")
            archive_sha = hashlib.sha256(b"archive").hexdigest()
            (archives / "epoch-7.jet.sha256").write_text(
                f"{archive_sha}  epoch-7.jet\n", encoding="ascii"
            )

            result = subprocess.run(
                [
                    str(SCRIPT),
                    str(pipeline),
                    str(archives),
                    str(state),
                    "7",
                    "7",
                    "1",
                    "1",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = state / "receipts" / "epoch-7.plugin.ok"
            fields = receipt.read_text(encoding="ascii").split()
            self.assertEqual(
                fields,
                [
                    archive_sha,
                    hashlib.sha256(pipeline.read_bytes()).hexdigest(),
                    hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                ],
            )

    def test_full_range_receipts_are_durably_published(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            state = root / "state"
            verifier = root / "verify_archive"
            verifier.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            verifier.chmod(verifier.stat().st_mode | stat.S_IXUSR)

            archive = archives / "epoch-7.jet"
            archive.write_bytes(b"archive")
            archive_sha = hashlib.sha256(b"archive").hexdigest()
            (archives / "epoch-7.jet.sha256").write_text(
                f"{archive_sha}  epoch-7.jet\n", encoding="ascii"
            )

            result = subprocess.run(
                [
                    str(RANGE_SCRIPT),
                    str(verifier),
                    str(archives),
                    str(state),
                    "7",
                    "7",
                    "1",
                    "1",
                    "1",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            full_receipt = state / "receipts" / "epoch-7.full.ok"
            chain_receipt = state / "receipts" / "ordered-chain.ok"
            self.assertTrue(full_receipt.is_file())
            self.assertTrue(chain_receipt.is_file())
            self.assertEqual(stat.S_IMODE(full_receipt.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(chain_receipt.stat().st_mode), 0o600)
            self.assertEqual(full_receipt.read_text().split()[0], archive_sha)

    def test_full_range_uses_segment_mode_for_internal_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            state = root / "state"
            invocation_log = root / "invocations"
            verifier = root / "verify_archive"
            verifier.write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {invocation_log}\nexit 0\n",
                encoding="ascii",
            )
            verifier.chmod(verifier.stat().st_mode | stat.S_IXUSR)

            for epoch in (7, 8):
                archive = archives / f"epoch-{epoch}.jet"
                archive.write_bytes(f"archive-{epoch}".encode("ascii"))
                archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
                (archives / f"epoch-{epoch}.jet.sha256").write_text(
                    f"{archive_sha}  epoch-{epoch}.jet\n", encoding="ascii"
                )

            result = subprocess.run(
                [
                    str(RANGE_SCRIPT),
                    str(verifier),
                    str(archives),
                    str(state),
                    "7",
                    "8",
                    "2",
                    "1",
                    "1",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            invocations = invocation_log.read_text(encoding="ascii").splitlines()
            chain_invocations = [line for line in invocations if "--chain" in line]
            self.assertEqual(len(chain_invocations), 1, invocations)
            self.assertIn("--segment", chain_invocations[0])
            self.assertIn(str(archives / "epoch-7.jet"), chain_invocations[0])
            self.assertIn(str(archives / "epoch-8.jet"), chain_invocations[0])

    def test_full_range_singleton_scans_without_claiming_an_internal_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            state = root / "state"
            invocation_log = root / "invocations"
            verifier = root / "verify_archive"
            verifier.write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {invocation_log}\nexit 0\n",
                encoding="ascii",
            )
            verifier.chmod(verifier.stat().st_mode | stat.S_IXUSR)

            archive = archives / "epoch-7.jet"
            archive.write_bytes(b"archive")
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            (archives / "epoch-7.jet.sha256").write_text(
                f"{archive_sha}  epoch-7.jet\n", encoding="ascii"
            )

            result = subprocess.run(
                [
                    str(RANGE_SCRIPT),
                    str(verifier),
                    str(archives),
                    str(state),
                    "7",
                    "7",
                    "1",
                    "1",
                    "1",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            invocations = invocation_log.read_text(encoding="ascii").splitlines()
            self.assertFalse(any("--chain" in line for line in invocations), invocations)
            self.assertTrue(
                any(
                    line.startswith(str(archive))
                    and "--full" not in line
                    and "--internal-full" not in line
                    for line in invocations
                ),
                invocations,
            )

    def test_full_range_accepts_explicit_prior_script_receipt_during_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            state = root / "state"
            receipts = state / "receipts"
            receipts.mkdir(parents=True)
            invocation_log = root / "invocations"
            verifier = root / "verify_archive"
            verifier.write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {invocation_log}\nexit 0\n",
                encoding="ascii",
            )
            verifier.chmod(verifier.stat().st_mode | stat.S_IXUSR)

            archive = archives / "epoch-7.jet"
            archive.write_bytes(b"archive")
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            (archives / "epoch-7.jet.sha256").write_text(
                f"{archive_sha}  epoch-7.jet\n", encoding="ascii"
            )
            verifier_sha = hashlib.sha256(verifier.read_bytes()).hexdigest()
            prior_script_sha = "a" * 64
            prior_receipt = f"{archive_sha} {verifier_sha} {prior_script_sha}\n"
            (receipts / "epoch-7.full.ok").write_text(
                prior_receipt, encoding="ascii"
            )

            result = subprocess.run(
                [
                    str(RANGE_SCRIPT),
                    str(verifier),
                    str(archives),
                    str(state),
                    "7",
                    "7",
                    "1",
                    "1",
                    "1",
                    prior_script_sha,
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (receipts / "epoch-7.full.ok").read_text(encoding="ascii"),
                prior_receipt,
            )
            invocations = invocation_log.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(invocations), 1, invocations)
            self.assertNotIn("--full", invocations[0])

    def test_full_range_transition_reuses_prior_receipts_and_checks_segment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            state = root / "state"
            receipts = state / "receipts"
            receipts.mkdir(parents=True)
            invocation_log = root / "invocations"
            verifier = root / "verify_archive"
            verifier.write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {invocation_log}\nexit 0\n",
                encoding="ascii",
            )
            verifier.chmod(verifier.stat().st_mode | stat.S_IXUSR)

            verifier_sha = hashlib.sha256(verifier.read_bytes()).hexdigest()
            prior_script_sha = "a" * 64
            for epoch in (7, 8):
                archive = archives / f"epoch-{epoch}.jet"
                archive.write_bytes(f"archive-{epoch}".encode("ascii"))
                archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
                (archives / f"epoch-{epoch}.jet.sha256").write_text(
                    f"{archive_sha}  epoch-{epoch}.jet\n", encoding="ascii"
                )
                (receipts / f"epoch-{epoch}.full.ok").write_text(
                    f"{archive_sha} {verifier_sha} {prior_script_sha}\n",
                    encoding="ascii",
                )

            result = subprocess.run(
                [
                    str(RANGE_SCRIPT),
                    str(verifier),
                    str(archives),
                    str(state),
                    "7",
                    "8",
                    "2",
                    "1",
                    "1",
                    prior_script_sha,
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            invocations = invocation_log.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(invocations), 1, invocations)
            self.assertIn("--chain", invocations[0])
            self.assertIn("--segment", invocations[0])
            self.assertNotIn("--full", invocations[0])

    def test_boundary_verifier_accepts_explicit_full_script_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = root / "archives"
            archives.mkdir()
            full_receipts = root / "full-receipts"
            full_receipts.mkdir()
            state = root / "state"
            verifier = root / "archive_boundaries"
            verifier.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            verifier.chmod(verifier.stat().st_mode | stat.S_IXUSR)

            full_verifier_sha = "b" * 64
            prior_script_sha = "a" * 64
            current_script_sha = "c" * 64
            for epoch in (7, 8):
                archive = archives / f"epoch-{epoch}.jet"
                archive.write_bytes(f"archive-{epoch}".encode("ascii"))
                archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
                (archives / f"epoch-{epoch}.jet.sha256").write_text(
                    f"{archive_sha}  epoch-{epoch}.jet\n", encoding="ascii"
                )
                (full_receipts / f"epoch-{epoch}.full.ok").write_text(
                    f"{archive_sha} {full_verifier_sha} {prior_script_sha}\n",
                    encoding="ascii",
                )

            result = subprocess.run(
                [
                    str(BOUNDARY_SCRIPT),
                    str(verifier),
                    str(archives),
                    str(full_receipts),
                    full_verifier_sha,
                    f"{current_script_sha},{prior_script_sha}",
                    str(state),
                    "7",
                    "8",
                    "1",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((state / "receipts" / "boundary-7-8.ok").is_file())

    def test_progressive_verifiers_never_call_syncfs(self) -> None:
        for script in (SCRIPT, WATCHER, BOUNDARY_SCRIPT, RANGE_SCRIPT):
            source = script.read_text(encoding="utf-8")
            self.assertNotIn("sync -f", source)
            self.assertNotIn("sync --file-system", source)
        for script in (SCRIPT, BOUNDARY_SCRIPT, RANGE_SCRIPT):
            source = script.read_text(encoding="utf-8")
            self.assertIn("os.fsync(descriptor)", source)


if __name__ == "__main__":
    unittest.main()
