"""Qualify the independent gap's stopped, held and one-core donation paths."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import Mock, patch

import continuation_dispatch as dispatch
import gap170_capacity as capacity
import ram170_capacity as retry


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


class IndependentGapTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root = root
        self.core = SimpleNamespace(need=require)
        self.native = Mock()
        self.gap = Mock(
            ACTOR=root / "actor", RELEASE=root / "release",
            ENROLLMENT=root / "enrollment", native=self.native,
        )
        self.callback = SimpleNamespace(
            contract=Mock(), gap=self.gap, interface=lambda: {"plan_path": str(root / "plan")}
        )
        for active in (patch.object(capacity, "receiver", return_value=self.callback),
                       patch.object(capacity, "ROOT", root)):
            active.start()
            self.addCleanup(active.stop)

    def test_absent_actor_requires_native_idle_and_no_permit(self):
        self.assertIsNone(capacity.owner(self.core, {}))
        self.native.idle.assert_called_once_with(capacity.UNIT)
        self.gap.RELEASE.touch()
        with self.assertRaisesRegex(ValueError, "without an actor"):
            capacity.owner(self.core, {})

    def test_held_actor_joins_both_censuses_without_a_worker(self):
        self.gap.ACTOR.touch()
        self.gap.read_actor.return_value = ("actor", {"producer_invocation_id": "held", "producer_pid": 56})
        self.native.props.return_value = {"ActiveState": "active"}
        self.gap.release.return_value = (None, None)
        self.gap.live.return_value = ([[56, 99, 7, 4]], None, "held")
        owner = capacity.owner(self.core, {})
        self.assertEqual((owner["invocation"], owner["pid"], owner["unit"]), ("held", 56, capacity.UNIT))
        self.assertEqual(owner["phase"], "held")
        self.assertIsNone(owner["release"])
        self.gap.guard.assert_not_called()
        self.callback.contract.stopped_owner.assert_called_once()

    def test_retained_guard_and_single_bootstrap_are_charged(self):
        g = 1 << 30
        start = {"actor_cpu_micros": 3_000_000, "guard_cpu_micros": 1_000_000}
        donor = {"charged_reference": {"cpu_cores": 2}, "producer_cores_retained": 1}
        self.core.bound = lambda _: start
        self.core.read = lambda *_: (donor, "verified donor")
        native = dict(required_home=4*g, home_margin=6*g, historical_home_margin=7*g,
                      required_ram=10*g, ram_margin=2*g,
                      stopped_169_compute_handoff={"start": "issued", "available_producer_ram": 20*g})
        capacity.debit(self.core, native)
        self.assertEqual(native["required_home"] - 4*g, capacity.EXTRA_HOME)
        self.assertEqual(native["home_margin"], 6*g - capacity.EXTRA_HOME)
        self.assertEqual(native["historical_home_margin"], 7*g - capacity.EXTRA_HOME)
        self.assertEqual((native["required_ram"], native["ram_margin"]), (11*g, g))
        donor["charged_reference"]["cpu_cores"] = 3
        with self.assertRaisesRegex(ValueError, "no separate capacity"):
            capacity.debit(self.core, native)

    def test_gap_dispatch_check_holds_the_fleet_lock(self):
        lock = Mock()
        from contextlib import contextmanager

        @contextmanager
        def fleet_lock():
            lock.acquire()
            try:
                yield
            finally:
                lock.release()

        def price(phase):
            lock.acquire.assert_called_once()
            lock.release.assert_not_called()
            self.assertEqual(phase, "start")
            return {"fits": True, "home_margin": 20, "ram_margin": 12}

        operator = Mock()
        operator.static.return_value = ({}, "scope")
        operator.compare.return_value = "checkpoint"
        with (patch.object(dispatch, "operator", operator),
              patch.object(dispatch, "q", SimpleNamespace(price=price, writer=lambda: ("writer", "program"))),
              patch.object(dispatch, "admission_lock", fleet_lock)):
            result = dispatch.gap_dispatch("check")
        self.assertTrue(result["fits"])
        self.assertEqual(result["independent_checkpoint"], "checkpoint")
        operator.start.assert_not_called()
        lock.release.assert_called_once()


class RamReservationTests(TestCase):
    def test_storage_replacement_preserves_both_screens_and_both_guards(self):
        g = retry.G
        native = dict(raw=dict(reserved_following_170_growth_bytes=36*g,
                              joint=dict(candidate_growth=36*g,producer_allowance=48*g),
                              terminal_tree_bounds=[350*g,350*g],required_home=100*g,guard_floor=64*g),
                      independent_gap_funding=dict(new_guard_cpu_micros=1_000_000,cpu_donor="159"),
                      stopped_169_compute_handoff=dict(retained_159_ram=48*g,retained_guard_ram=g),
                      available_home=120*g, required_home=102*g, historical_home_margin=9*g,
                      available_ram=100*g,required_ram=65*g)
        prepared = dict(new_home_output=4*g,new_home_control=64<<20,incremental_ram_bytes=8*g,
                        producer_memory_max=56*g,guard_memory_max=g,returned_159_loan=dict(scope="159"),
                        producer_cpu_micros=2_000_000,guard_cpu_micros=1_000_000,
                        stage="prepare-only",admission=False)
        core = SimpleNamespace(need=require,read=lambda *_: (prepared,"169 quote"))
        retry.charge(core,native,"terminal")
        retry.reserve_169(core,native)
        home_charge = 4*g + (64 << 20)
        self.assertEqual(native["required_home"], 74*g + home_charge)
        self.assertEqual(native["home_margin"], 37*g - home_charge)
        self.assertEqual(native["ram_margin"], 19*g)
        self.assertTrue(native["ram_retry_cost"]["original_guard_still_budgeted"])
        native["raw"]["terminal_tree_bounds"] = [378*g,378*g]
        with self.assertRaisesRegex(ValueError,"retained 170 tree"):
            retry.charge(core,native,"terminal")

    def test_prestart_refuses_a_native_actor_before_the_next_fleet(self):
        core = SimpleNamespace(need=require,inactive=Mock(),state=lambda *_: {"ActiveState":"inactive","Job":""})
        with TemporaryDirectory() as tmp, patch.object(retry,"ROOT",Path(tmp)):
            fleet = {"actual_active_private_diagnostics":[]}
            self.assertIsNone(retry.before_issue(core,fleet))
            (Path(tmp)/"SUCCESSOR_START_INTENT.json").touch()
            with self.assertRaisesRegex(ValueError,"already issued"):
                retry.before_issue(core,fleet)


if __name__ == "__main__":
    main()
