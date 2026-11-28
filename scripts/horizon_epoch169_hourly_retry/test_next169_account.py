from copy import deepcopy
from unittest import TestCase, mock

import adjacent_account as older
import next169_account as follow


class NextIntervalBooking(TestCase):
    def setUp(self):
        self.g = 1 << 30
        self.lease = {"path":"previous/LEASE.json","sha256":"f"*64}
        self.interface = {"path":"previous/INTERFACE_48.json","sha256":"a"*64}
        self.iid = "b"*32
        patches = mock.patch.multiple(follow, create=True, G=self.g, OUTPUT=4*self.g, CONTROL=64<<20,
            DONOR=self.lease, OLD_INTERFACE=self.interface, OLD_IID=self.iid,
            need=older.need, stable=older.stable, live=lambda row:row["owner"])
        patches.start()
        self.addCleanup(patches.stop)

    def native(self):
        return dict(adjacent_169_effective_cap=dict(selected=True,interface=self.interface,producer_max=48*self.g,
                        guard_max=self.g,replaced_reserved_bytes=8*self.g,resource_credit_bytes=0,previous_required_ram=78*self.g),
                    adjacent_169_after=dict(phase="terminal",owner=dict(lease=self.lease,invocation_id=self.iid),
                        enrollment={"sha256":"c"*64},resident=0),adjacent_169_owner=None,adjacent_169_resident_bytes=0,
                    required_ram=70*self.g,available_ram=100*self.g,ram_margin=30*self.g,resource_credit_bytes=0)

    def test_reuse_one_compact_booking_and_only_bracketed_worker_residency(self):
        row = dict(phase="worker",previous=self.lease,enrolled=True,enrollment={"sha256":"e"*64},floor=100,
                   owner=dict(phase="worker",release={"sha256":"f"*64}),resident=12*self.g,remaining=3*self.g)
        native = self.native()
        follow.apply(native,row,dict(row,resident=10*self.g))
        self.assertEqual((native["required_ram"],native["ram_margin"]),(60*self.g,40*self.g))
        with self.assertRaises(ValueError):
            follow.apply(native,row,row)
        data = self.native()
        data["adjacent_169_after"]["owner"]["lease"] = {"sha256":"d"*64}
        with self.assertRaises(ValueError):
            follow.apply(data,row,row)
        with self.assertRaises(ValueError):
            follow.apply(self.native(),dict(row,phase="bootstrap"),dict(row,phase="bootstrap"))

    def test_unissued_successor_keeps_previous_ceiling_and_image_charge(self):
        row = dict(phase="precharged",previous=self.lease,enrolled=False,enrollment=None,owner=None,
                   floor=0,resident=0,remaining=4*self.g)
        native = self.native()
        follow.apply(native,row,row)
        self.assertEqual(native["required_ram"],70*self.g)
        previous = dict(charged=True,phase="terminal",owner=dict(lease=self.lease,invocation_id=self.iid),
                        resident_bytes=0,additional_home=4*self.g+(64<<20),additional_ram=0)
        full = {"adjacent_169_accounting":previous}
        with mock.patch.object(follow,"reserve",create=True) as charge:
            follow.checked_reserve(full,True)
            charge.assert_called_once_with(full,True)
            bad = deepcopy(full)
            bad["adjacent_169_accounting"]["additional_home"] -= 1
            with self.assertRaises(ValueError):
                follow.checked_reserve(bad,True)

    def test_publication_cost_is_present_in_shared_and_143_floor_once(self):
        fee = 16<<20
        for active in (False,True):
            for sibling in (99*self.g,102*self.g):
                with self.subTest(active=active,sibling=sibling):
                    base = 100*self.g
                    paid = fee if active else 0
                    goal = max(base,sibling)
                    q = dict(required_home=base+paid,epoch143_remaining_replay_home=2*self.g,
                        epoch143_protected_sibling_floor=sibling-2*self.g,epoch143_protected_runway_required_home=goal,
                        publication168_allocation=dict(charged=active,metadata_bytes=fee,resource_credit_bytes=0,
                                                       additional_ram=0,additional_home=paid))
                    orig = dict(phase="finalizing",retained_home_cap=288*self.g,producer_ram=68*self.g,
                                guard_ram=self.g,reservation_ending_bytes=0,resource_credit_bytes=0)
                    q.update(original_172_accounting=orig,base_169={"native":{"raw":{"joint":{"original_172_accounting":orig}}}})
                    out = follow.final_runway(q)
                    self.assertEqual(out["epoch143_protected_runway_required_home"],max(base+paid,sibling))
                    q["epoch143_protected_runway_required_home"] = goal-1
                    with self.assertRaises(ValueError):
                        follow.final_runway(q)
