"""Regressions for the original 136 hard-stop floor and the prestart interlock."""
import copy
import fcntl
import os
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
price = runpy.run_path(str(HERE / "incident_prestart.py"))["price"]
session = runpy.run_path(str(HERE / "prestart_session.py"))
CAP = 72 << 30


def inputs():
    row = dict(cap=CAP, remaining=CAP, occupied=False)
    native = dict(candidate136=row, complete_cpu_quota_micros=64_000_000,
                  complete_required_HOME_bytes=CAP + 50, available_HOME_bytes=CAP + 101,
                  complete_memory_plus_reserve_bytes=500, available_memory_bytes=470,
                  required_available_memory_bytes=450, resource_credit_bytes=0,
                  stopped_generation_resident_credit_bytes=0, replay_launch_authorized=False)
    prefix = dict(remaining_DATA_growth_bytes=1, maximum_HOME_allocation_bytes=16<<20,
                  registration={"scope": "140"}, child={"pid": "10"}, complete_result=None,
                  additional_cpu_quota_micros=0, additional_memory_bytes=0,
                  resource_credit_bytes=0, archive_staging_bytes=0)
    return native, prefix


class Price(unittest.TestCase):
    def test_protects_incumbent_threshold_before_full_reserved_candidate(self):
        n, p = inputs()
        x = price(n, 100, p, p, n["available_HOME_bytes"], 510)
        self.assertEqual(x["complete_required_HOME_bytes"], CAP + 101)
        self.assertTrue(x["disk_fits"] and x["memory_fits"])
        self.assertFalse(price(n, 100, p, p, CAP+100, 510)["disk_fits"])

    def test_does_not_compound_prefix_above_its_frozen_guard(self):
        n, p = inputs()
        n["candidate136"].update(occupied=True, guard_floor=102)
        n["complete_required_HOME_bytes"] = CAP + 102
        result = price(n, 100, p, p, CAP+105, 510, waiter={"iid": "expected"})
        self.assertEqual(result["complete_required_HOME_bytes"], CAP+102)
        with self.assertRaises(ValueError):
            price(n, 100, p, p, CAP+105, 510)

    def test_crossed_or_unbounded_prefix_and_borrowed_storage_fail(self):
        n, p = inputs()
        for key, value in (("child", {"pid":"11"}), ("maximum_HOME_allocation_bytes", 2<<30),
                           ("additional_cpu_quota_micros", 1000), ("resource_credit_bytes", 1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                price(n, 100, p, dict(p, **{key:value}), CAP+105, 510)
        wrong = copy.deepcopy(n)
        wrong["candidate136"]["remaining"] -= 1
        with self.assertRaises(ValueError):
            price(wrong, 100, p, p, CAP+105, 510)
        self.assertFalse(price(dict(n, available_memory_bytes=449), 100, p, p, CAP+105, 510)["memory_fits"])


class Boundary(unittest.TestCase):
    def test_writer_fleet_selector_and_post_dispatcher_must_all_match(self):
        writer = dict(pid=12, start_ticks=34, invocation_id="a"*32)
        head = dict(path="/fleet", sha256="b"*64)
        selector = dict(path="/READY.json", sha256="c"*64)
        complete = dict(path="/complete.json", sha256="d"*64)
        proof = dict(schema="horizon-145-136-writer-boundary-v1", writer=writer, fleet=head,
                     selector=selector, post_submission_held=True, semantic_complete=complete)
        verify = session["boundary"]
        self.assertEqual(verify(proof, writer, head, selector), complete)
        for name, value in (("writer", dict(writer, start_ticks=33)), ("writer", dict(writer, pid=13)),
                            ("fleet", dict(head, sha256="e"*64)), ("selector", dict(selector, path="/other")),
                            ("post_submission_held", False), ("schema", "future")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify(dict(proof, **{name:value}), writer, head, selector)

    def test_guarded_waiter_spends_original_loan_and_retains_its_full_budget(self):
        pid = os.getpid()
        writer = dict(invocation_id="e"*32)
        plan = dict(path="/guard.json", sha256="f"*64)
        registry = dict(path=str(session["REGISTRY"]), sha256="a"*64)
        loan = dict(registry=registry, masked_standard_routes=["original169.service"],
                    cpu_quota_micros=4_250_000, unassigned_standard169_cpu_micros=4_750_000)
        fence = dict(standard169_cpu_lease=loan)
        waiter = dict(iid="c"*32, producer_pid=pid, start_ticks=112, guard_plan=plan,
                      writer_invocation_id=writer["invocation_id"])
        guard = dict(plan=plan, workers=[])
        live = dict(active_at_capture=True, phase="waiting-status-and-post-fit", native_start_ticks=112,
                    unit=dict(Id=session["PAYLOAD"], MainPID=str(pid), InvocationID=waiter["iid"]), guard=guard)
        def checked(ref):
            if ref == registry:
                return dict(standard_routes=["original169.service"])
            self.assertEqual(ref, plan)
            return dict(maximum_root_physical_bytes=64<<30, minimum_free_bytes=9<<40)
        fn = session["pending_candidate"]
        got = fn(waiter, fence, writer, checked, lambda:live)
        self.assertEqual((got["occupied"], got["cap"], got["remaining"], got["loan_micros"], got["guard_floor"]),
                         (True, CAP, CAP, 4_250_000, 9<<40))
        for wrong_fence, row, inspected in ((None, waiter, live), (fence, dict(waiter, start_ticks=110), live),
                                          (fence, dict(waiter, writer_invocation_id="d"*32), live),
                                          (fence, waiter, dict(live, guard=dict(guard, workers=[pid]))),
                                          (fence, waiter, dict(live, phase="worker")),
                                          (dict(standard169_cpu_lease=dict(loan, cpu_quota_micros=1)), waiter, live)):
            with self.assertRaises(ValueError):
                fn(row, wrong_fence, writer, checked, lambda:inspected)


@unittest.skipUnless(os.geteuid() == 0, "requires an actual root-owned operation lock")
class Lock(unittest.TestCase):
    def test_exclusive_lock_must_be_held_by_exact_pid_on_original_inode(self):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        observe = session["same_writer_lock"]
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "operation.lock"
            with path.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                m = os.fstat(stream.fileno())
                with self.assertRaises(ValueError):
                    observe(os.getpid(), path, boot, m.st_dev, m.st_ino)
                fcntl.flock(stream, fcntl.LOCK_SH|fcntl.LOCK_NB)
                with self.assertRaises(ValueError):
                    observe(os.getpid(), path, boot, m.st_dev, m.st_ino)
                fcntl.flock(stream, fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual(observe(os.getpid(), path, boot, m.st_dev, m.st_ino),
                                 f"/proc/{os.getpid()}/fd/{stream.fileno()}")
                for pid, expected_boot, inode in ((os.getppid(), boot, m.st_ino),
                                                  (os.getpid(), "different", m.st_ino),
                                                  (os.getpid(), boot, m.st_ino+1)):
                    with self.assertRaises(ValueError):
                        observe(pid, path, expected_boot, m.st_dev, inode)
                fcntl.flock(stream, fcntl.LOCK_UN)
                with self.assertRaises(ValueError):
                    observe(os.getpid(), path, boot, m.st_dev, m.st_ino)


if __name__ == "__main__":
    unittest.main()
