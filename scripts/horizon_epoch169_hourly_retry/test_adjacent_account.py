import unittest

from adjacent_account import CONTROL, G, OUTPUT, TERMINAL, apply, protect, reserve
from adjacent_price import geometry


class AdjacentPricing(unittest.TestCase):
    def fourth(self):
        return dict(planned_169_retry=dict(fourth_scope=dict(path="/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-retry-20261128-v4/SCOPE.json"),
                                           additional_home=OUTPUT+CONTROL,additional_ram=8*G),
                    independent_retry169=None, fourth169_residency=dict(realized_bytes=0),
                    stopped_169_compute_handoff=dict(retained_159_ram=48*G,retained_guard_ram=G),
                    ram_margin=8*G,available_ram=80*G,required_ram=72*G,resource_credit_bytes=0)

    def test_closed_predecessor_and_one_incremental_image(self):
        row=dict(owner=None,phase="precharged",previous={"terminal":TERMINAL},enrolled=True,enrollment=None,
                 resident=0,remaining=OUTPUT,floor=0)
        native=self.fourth()
        apply(native,row,row)
        quote=dict(base_169={"native":native},required_home=10*G,home_margin=5*G,fits=True,resource_credit_bytes=0)
        reserve(quote,True)
        self.assertEqual(quote["adjacent_169_accounting"]["predecessor"],TERMINAL)
        self.assertEqual(quote["required_home"],10*G+OUTPUT+CONTROL)
        self.assertEqual(native["required_ram"],72*G)
        with self.assertRaises(ValueError):
            reserve(quote,True)
        with self.assertRaises(ValueError):
            apply(self.fourth(),row,dict(row,owner={"phase":"held"}))

    def test_sibling_runway_and_post_guard_floor(self):
        floor=9_700_000_000_000
        shared=floor+75*G
        q=dict(available_home=shared+100*G,available_ram=80*G,required_ram=72*G,
               required_home=shared,guard_floor=floor+30*G,home_margin=100*G,resource_credit_bytes=0,fits=True,
               epoch143_installed_guard_floor=None,epoch143_remaining_replay_home=56*G,
               epoch143_protected_sibling_floor=floor,observed_sibling_guard_floors=[floor],
               epoch143_protected_runway_required_home=shared,
               base_169={"native":{"raw":{"guarded_hourly_remaining":56*G,"guard_floor":floor,"replacement143":True}}},
               third_162_accounting={"phase":"worker","charged":True,"remaining_output":2*G},
               after_floor170_accounting={"replacement_selected":True,"home_growth":8*G},
               after_ram170_accounting={"home_growth_bytes":36*G},
               adjacent_169_accounting=dict(charged=True,writer_enrolled=True,additional_ram=0,additional_cpu=0,
                   resident_bytes=0,additional_home=OUTPUT+CONTROL,maximum_output=OUTPUT,remaining_output=OUTPUT,
                   enrollment=None,phase="precharged",owner=None,observed_floor=0))
        result=geometry(protect(q),"prestart",None,q["available_home"],q["available_ram"])
        self.assertTrue(result["fits"])
        self.assertGreaterEqual(result["required_home"],result["guard_floor"]+70*G)
        self.assertEqual(result["prestart_guard_cushion"],result["unarmed_home_margin"]//3)
        iid="1"*32
        q["adjacent_169_accounting"].update(phase="held",enrollment={"sha256":"f"*64},observed_floor=result["guard_floor"],
                                            owner={"invocation_id":iid,"phase":"held","release":None})
        post=geometry(q,"postguard",iid,q["available_home"],q["available_ram"])
        self.assertTrue(post["fits"])
        self.assertEqual(result["guard_floor"],post["guard_floor"])
        with self.assertRaises(ValueError):
            geometry(q,"postguard","2"*32,q["available_home"],q["available_ram"])
        short=geometry(q,"postguard",iid,result["required_home"]-1,q["available_ram"])
        self.assertFalse(short["fits"])
        self.assertLess(short["home_margin"],0)
        q["observed_sibling_guard_floors"].append(result["guard_floor"]+1)
        worsened=geometry(q,"postguard",iid,q["available_home"],q["available_ram"])
        self.assertFalse(worsened["fits"])
        self.assertGreater(worsened["minimum_fair_floor"],result["guard_floor"])


if __name__=="__main__":
    unittest.main()
