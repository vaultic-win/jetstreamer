from unittest import TestCase, main
import frozen162_image as frozen

G, M = 1<<30, 1<<20


def need(ok,reason):
    if not ok: raise ValueError(reason)


class FrozenImageTests(TestCase):
    def setUp(self):
        self.base=dict(available_home=100*G,guard_floor=79*G,remaining_output=8*G,fits=True)
        self.final=dict(ram_margin=120*G,guard_floor=82*G,required_home=101*G+64*M,home_margin=-G-64*M,
                        fits=False,prospective_162_interval_two=dict(retained_first_image_allowance=8*G,additional_home=3*G+64*M))

    def test_only_future_image_term_changes(self):
        result=frozen.reprice(need,self.base,self.final,4096)
        self.assertEqual(result['net_reduction'],6735585280)
        self.assertEqual(self.final['required_home'],82*G+8*G+3*G+64*M+1854349312)
        self.assertEqual(self.final['guard_floor'],82*G)
        self.assertTrue(self.final['fits'])
        self.assertEqual(self.final['prospective_162_interval_two']['additional_home'],3*G+64*M)
        with self.assertRaisesRegex(ValueError,'changed 162 charges'):
            frozen.reprice(need,self.base,self.final,4096)

    def test_respects_other_failures(self):
        self.base['fits']=False
        frozen.reprice(need,self.base,self.final,4096)
        self.assertFalse(self.final['fits'])

    def test_refuses_unexplained_floor_or_different_image(self):
        self.final['guard_floor']-=G
        with self.assertRaisesRegex(ValueError,'HOME equation'):
            frozen.reprice(need,self.base,self.final,4096)

if __name__=='__main__': main()
