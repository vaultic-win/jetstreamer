"""Exercise the read phase without requiring the following bootstrap or a live producer."""
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch
import json

import following_capacity as sizing


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


class ReadInputTests(TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.directory = root / "epoch170-following-bootstrap-20261127-v1"
        self.directory.mkdir()
        self.bindings = patch.object(sizing, "RT", root)
        self.bindings.start()
        self.addCleanup(self.bindings.stop)
        self.fleet = {"sampled_at_utc": datetime.now(timezone.utc).isoformat()}
        self.units = set()
        self.native = {"MemoryMax": str(sizing.GIB), "MemorySwapMax": "0", "CPUQuotaPerSecUSec": "500ms"}
        self.core = SimpleNamespace(need=require, state=lambda _:self.native,
                                    read=lambda p:(json.loads(p.read_bytes()),str(p)))
        self.provider = SimpleNamespace(active_units=lambda _:self.units)

    def charges(self):
        return sizing.incoming(self.core, self.provider, self.fleet, None)

    def test_can_close_before_input_authority(self):
        self.assertEqual(self.charges(),(None,0,0,0))
        self.units.add("horizon-input-170-73766969-gcs-v1.service")
        with self.assertRaisesRegex(ValueError,"unbound next-input"):
            self.charges()

    def test_issued_transfer_remains_fully_paid(self):
        intent = self.directory / "START_1.json"
        intent.write_text("{}")
        self.units.add("horizon-input-170-73766969-gcs-v1.service")
        self.assertEqual(self.charges(),(str(intent),sizing.INPUT_BYTES,sizing.INPUT_BYTES,sizing.GIB))
        self.native["MemorySwapMax"]="infinity"
        with self.assertRaisesRegex(ValueError,"unexpected input copier"):
            self.charges()

    def test_closed_input_keeps_historical_charge_until_following_census(self):
        (self.directory/"START_1.json").write_text("{}")
        custody=self.directory/"INPUT_CUSTODY.json"
        custody.write_text("{}")
        self.fleet["sampled_at_utc"]="2000-01-01T00:00:00+00:00"
        self.assertEqual(self.charges(),(str(custody),sizing.INPUT_BYTES,0,0))
        self.fleet["sampled_at_utc"]="2099-01-01T00:00:00+00:00"
        self.assertEqual(self.charges(),(str(custody),0,0,0))


class CompletePhaseTests(TestCase):
    def quote(self, phase):
        g, m = sizing.GIB, sizing.MIB
        fleet_ref = {"path":"f", "sha256":"a"}
        funds = {"build_memory_bytes":2*g}
        fleet = {"retry9_auxiliary_commitments":funds}
        paid = object()
        core = SimpleNamespace(need=require, availability=lambda:(156*g,80*g), inactive=lambda _:None,
                               current_fleet=lambda:(fleet,fleet_ref))
        def margins(basis, funding, physically_funded, duplicate):
            self.assertIs(funding,funds)
            self.assertEqual((physically_funded,duplicate),(4*g,2*g))
            build_charge = 4*g+16*m
            return dict(remaining_home=min(basis["available_home"]-basis["required_home"]-16*m,
                                           basis["historical_home_margin"]-build_charge),
                        post_reservation_ram_margin=basis["ram_margin"]+duplicate-512*m,
                        build_home=build_charge)
        provider = SimpleNamespace(op=paid,accepted_fleet=lambda ref:fleet,
                    repeated_serial_slot=lambda base,funds:{"repeated_serial_bytes":2*g},
                    compiler_reservation=lambda:{"image_physically_funded_bytes":4*g},
                    recovery_reservation=lambda _:{"maximum_memory":3*g},margins=margins)
        base = dict(phase=phase,guard_floor=64*g, required_home=96*g,
                    historical_home_margin=90*g, available_home=156*g,required_ram=70*g,available_ram=80*g,
                    dispatch_memory_bytes=512*m,joint={"producer_allowance":48*g},
                    terminal_tree_bounds=[190*g,191*g],replacement143=None,priced_170_invocation=None,
                    guarded_hourly_remaining=10*g,fleet=fleet_ref)
        assembly = dict(state="live",replay={"invocation143":None,"invocation170":None},floor=60*g,
                        incremental_home=5*g,incremental_ram=2*g)
        with patch.object(sizing,"load_holding",return_value=(provider,{})), \
             patch.object(sizing,"holding_owner",return_value=None), \
             patch.object(sizing,"incoming",return_value=(None,0,0,0)):
            return sizing.charge(core,base,assembly,None)

    def test_read_uses_the_producer_only_until_the_next_phase(self):
        read=self.quote("read")
        start=self.quote("start")
        self.assertTrue(read["fits"] and start["fits"])
        self.assertEqual(read["ram_margin"]-start["ram_margin"],48*sizing.GIB-512*sizing.MIB)
        self.assertEqual(read["guard_floor"],start["guard_floor"])
        self.assertEqual(read["home_margin"],start["home_margin"])
        self.assertEqual(start["guard_floor"],70*sizing.GIB+48*sizing.MIB)
        self.assertEqual(start["required_home"],start["guard_floor"]+37*sizing.GIB)
        self.assertEqual(start["sequential_read_RAM_difference"],0)


if __name__ == "__main__":
    main()
