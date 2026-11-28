"""Check the second interval's precharged, held and hard-floor arithmetic."""
from copy import deepcopy
from pathlib import Path
import runpy
import unittest

price = runpy.run_path(str(Path(__file__).with_name("second_price_custody.py")))
G, M = price["G"], price["M"]

def base():
    frozen = dict(custody=price["FROZEN"],verification={"sha256":price["FIRST_VERIFIED"]},
        source={"inode":33},occupied_home_bytes=1791680512,rounded_output=1787240448,separate_staging_cap=64*M,
        prospective_materialization_bytes=1854349312,net_reduction=6735585280,guard_floor_unchanged=27*G,resource_credit_bytes=0)
    reserve = dict(first_producer=price["FIRST_INVOCATION"],retained_image={"inode":33},first_image_predecessor_reservation=8*G,
        retained_first_image_allowance=0,interval=[69991077,69998119],producer_and_guard_already_charged=True,
        additional_compute=0,additional_output=3*G,additional_control=64*M,additional_home=3*G+64*M,resource_credit_bytes=0)
    return dict(existing_162=dict(phase="terminal",invocation_id=price["FIRST_INVOCATION"],realized_ram=0,
                profile=dict(combined_ram=63*G,home_image=8*G)),frozen_first_162_image=frozen,
                prospective_162_interval_two=reserve,donor_compute={"usable_166_ram":63*G},guard_floor=27*G,
                required_home=41*G,required_ram=83*G,available_home=42*G,available_ram=85*G,fits=True)

def quote(n, disk=42*G, ram=85*G, floor=0):
    return price["geometry"](n,disk,ram,floor)

class Second162Price(unittest.TestCase):
    def test_resident_bytes_are_charged_once_and_armed_floor_retained(self):
        n = base()
        r = quote(n)
        self.assertEqual((r["home_margin"],r["ram_margin"],r["guard_floor"]),(G,2*G,38*G))
        n.update(second_162_accounting={"remaining_output":2*G},second_162_actor={"phase":"held"},required_home=40*G,available_home=41*G)
        held = quote(n,disk=41*G,floor=r["guard_floor"])
        self.assertEqual((held["required_home"],held["guard_floor"],held["home_margin"]),(40*G,38*G,G))
        self.assertFalse(quote(n,disk=39*G)["fits"])
        self.assertFalse(quote(n,ram=82*G)["fits"])
        self.assertFalse(quote(n,floor=42*G)["fits"])
    def test_rejects_foreign_custody_or_reservations(self):
        for k,field,value in (("frozen_first_162_image","custody",{}),("frozen_first_162_image","rounded_output",0),
                ("frozen_first_162_image","prospective_materialization_bytes",0),
                ("prospective_162_interval_two","additional_home",0),("prospective_162_interval_two","retained_first_image_allowance",8*G)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                n = base()
                n[k][field] = value
                quote(n)
        n = base()
        n["second_162_accounting"] = {"remaining_output":2*G}
        with self.assertRaises(ValueError):
            quote(n)
    def test_held_requires_common_actor_and_exact_identity(self):
        ref = {"path":"same","sha256":"d"*64}
        actor = {"producer_invocation_id":"a"*32}
        n = {"second_162_actor":dict(phase="held",held_owner=ref,**actor)}
        self.assertTrue(price["held_owner_matches"](n,actor,ref))
        self.assertFalse(price["held_owner_matches"]({},actor,ref))
        other = deepcopy(n)
        other["second_162_actor"]["producer_invocation_id"] = "b"*32
        self.assertFalse(price["held_owner_matches"](other,actor,ref))
        self.assertFalse(price["held_owner_matches"](n,actor,{"path":"other"}))


if __name__ == "__main__":
    unittest.main()
