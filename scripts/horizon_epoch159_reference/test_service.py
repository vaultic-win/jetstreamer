import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import service


class ServiceTest(unittest.TestCase):
    def test_log_is_drained_after_cap(self):
        with TemporaryDirectory() as d, patch.object(service, "CAP", 121):
            f = Path(d) / "log"
            proc = type("Process", (), {"stdout": io.BytesIO(b"x" * 100000)})()
            self.assertEqual(service.limited_log(proc, f), 100000)
            self.assertEqual(f.read_bytes(), b"x" * 121)

    def test_intent_never_overwritten(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "intent"
            service.record(p, {"v": 2})
            with self.assertRaises(FileExistsError):
                service.record(p, {"v": 3})
            self.assertEqual(json.loads(p.read_bytes()), {"v": 2})

    def test_receipt_extraction_bound_and_link(self):
        for kind in ("valid", "oversize", "link"):
            with (
                self.subTest(kind=kind),
                TemporaryDirectory() as d,
                patch.object(service, "ATTEMPT", Path(d)),
                patch.object(service, "CAP", 4096),
            ):
                evidence = Path(d) / "evidence"
                evidence.mkdir()
                src = evidence / "outcome.json"
                if kind == "link":
                    src.symlink_to("/etc/passwd")
                else:
                    src.write_text(json.dumps("x" * (4096 if kind == "oversize" else 10)))
                if kind == "valid":
                    self.assertEqual(service.copy_receipts(), {"outcome.json": service.sha(src)})
                else:
                    with self.assertRaises(ValueError):
                        service.copy_receipts()

    def test_service_caps_and_no_restart(self):
        argv = service.system_argv("0" * 64)
        self.assertIn("--property=CPUQuota=200%", argv)
        self.assertIn("--property=MemoryMax=51539607552", argv)
        self.assertIn("--property=MemorySwapMax=0", argv)
        self.assertIn("--property=ExitType=cgroup", argv)
        self.assertIn("--property=Restart=no", argv)
        self.assertIn("--property=StandardError=null", argv)
        self.assertLess((24 << 30) + service.CAP * 3, (24 << 30) + service.LIMITS["other_home_bytes"])

    def test_sandbox_exposes_only_its_two_host_writable_directories(self):
        with patch.object(service, "PACKAGE", Path(__file__).resolve().parent):
            cmd = service.node_argv()
            writable = [cmd[i + 2] for i, v in enumerate(cmd) if v == "--bind"]
            self.assertEqual(writable, ["/work", "/evidence"])
            self.assertIn("--clear-groups", cmd)
            self.assertIn("--no-new-privs", cmd)
            self.assertIn("--bounding-set=-all", cmd)
            self.assertEqual(cmd[-3:], ["replay", "/work", "/evidence"])

    def test_interlock_refuses_competitor(self):
        if os.geteuid() != 0:
            self.skipTest("root owner required")
        with (
            TemporaryDirectory() as d,
            patch.object(service, "LOCK", Path(d) / "lock"),
            patch.object(service, "RT", Path(d)),
        ):
            service.LOCK.touch(mode=0o600)
            st = service.LOCK.stat()
            g = {"donor_lock": {"dev": st.st_dev, "ino": st.st_ino}, "donor_idle_units": []}
            with service.borrow(g), self.assertRaises(BlockingIOError):
                with service.borrow(g):
                    pass


if __name__ == "__main__":
    unittest.main()
