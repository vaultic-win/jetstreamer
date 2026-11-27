"""Exercise exact status creation, uncertain-response recovery and cadence adoption."""

import copy
import json
import os
import runpy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

m = SimpleNamespace(**runpy.run_path(str(Path(__file__).with_name("initial162.py"))))
ETAG = '"' + '3'*32 + '"'
ROW = {"held_owner":{"path":"held","sha256":"a"*64}, "producer_invocation_id":"1"*32,
       "actor":{"producer_pid":41,"producer_unit":"unit","boot_id":"1"*32}}
ENROLLED = {"path":"enrollment","sha256":"b"*64}
GRANT = {"path":"grant","sha256":"c"*64}


class Store:
    def __init__(self):
        self.s3 = SimpleNamespace(meta=SimpleNamespace(events=self))
        self.hook = self.raw = self.pending = None
        self.ready, self.archives = set(), {}
        self.puts = 0
        self.lost, self.read_error = False, False
        self.read_etag = ETAG

    def register_last(self, name, callback):
        assert name == m.EVENT and self.hook is None
        self.hook = callback

    def unregister(self, name, handler):
        assert name == m.EVENT and handler is self.hook
        self.hook = None

    def inventory(self):
        return ({162} if self.raw is not None else set(),self.ready,self.archives)

    def put(self, e, condition, raw):
        assert e == 162 and condition == "*"
        self.pending = (m.KEY, "*")
        request = SimpleNamespace(headers={"If-Match":"*"})
        try:
            self.hook(request)
            assert request.headers == {"If-None-Match":"*"} and self.raw is None
            self.puts += 1
            self.raw = raw
            if self.lost:
                raise ConnectionError("PUT response dropped")
            return ETAG
        finally:
            self.pending = None

    def get(self, e):
        if self.read_error:
            raise ConnectionError("GET interrupted")
        assert e == 162 and self.raw is not None
        return self.read_etag, self.raw


class InitialStatus(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=os.environ["STATUS162_TEST_ROOT"])
        self.addCleanup(self.folder.cleanup)
        self.files = tuple(Path(self.folder.name)/name for name in ("pending","response","final"))
        self.store = Store()
        delivery = {"total_millis":72000000,"observed_archive_bytes":21,"epoch":162,"phase_milliseconds":{"tail":72000000}}
        replay = (432000*100000+142)//143
        model = dict(route={"sha256":m.ROUTE_SHA},canonical_slots=432000,canonical_replay_ms=replay,
                     private_remaining_ms=6299990,bootstrap_ms=506272,delivery=delivery)
        status = dict(epoch=162,phase="verification",sampled_at_utc="2026-11-27T23:40:00Z",jet_size_bytes=21,
                      elapsed_execution_millis=10,estimated_remaining_millis=replay+6299990+506272+72000000)
        self.p = dict(schema=m.SCHEMA,epoch=162,key=m.KEY,conditional_header="If-None-Match",conditional_value="*",
                      previous_receipt=None,after_status=status,after_sha256=m.digest(m.body(status)),archive={"size":21},
                      forecast=model,producer_invocation_id=ROW["producer_invocation_id"],producer_pid=41,
                      sample_monotonic_us=11_000,exec_start_monotonic_us=1_000,private_phase="worker",guard={"sha256":"g"},
                      private162_split_held=ROW["held_owner"],private162_split_grant=GRANT,
                      private162_split_enrollment=ENROLLED,transaction_progress=None)

    @staticmethod
    def save(p, value):
        with p.open("x") as f:
            json.dump(value,f)
        p.chmod(0o400)
        return m.ref(p)

    def check(self, p):
        m.verify_proof(p, ROW, ENROLLED, GRANT)

    def apply(self):
        return m.publish(self.store,self.files,lambda: self.p,self.check,self.save)

    def test_normal_and_repeat(self):
        result = self.apply()
        self.assertEqual(result,self.apply())
        self.assertEqual(self.store.puts,1)
        self.assertIsNone(self.store.hook)
        self.assertEqual(m.adopted(ROW,None,result,ENROLLED,GRANT),result)

    def test_lost_response(self):
        self.store.lost = True
        self.apply()
        self.assertEqual(self.store.puts,1)
        self.assertIsNone(self.store.hook)

    def test_uncertain_readback(self):
        self.store.lost = self.store.read_error = True
        with self.assertRaises(ConnectionError):
            self.apply()
        self.assertTrue(self.files[0].exists())
        self.assertFalse(self.files[2].exists())
        self.store.read_error = False
        self.apply()
        self.assertEqual(self.store.puts,1)

    def test_etag_mismatch(self):
        self.store.read_etag = '"' + '4'*32 + '"'
        with self.assertRaisesRegex(ValueError,"ETag differs"):
            self.apply()
        self.assertFalse(self.files[2].exists())

    def test_foreign_before_and_after_pending(self):
        self.store.raw = b"different"
        with self.assertRaisesRegex(ValueError,"foreign"):
            self.apply()
        self.save(self.files[0],self.p)
        with self.assertRaisesRegex(ValueError,"readback differs"):
            self.apply()
        self.assertEqual(self.store.puts,0)

    def test_ready_and_canonical(self):
        self.store.ready.add(162)
        with self.assertRaisesRegex(ValueError,"canonical"):
            self.apply()
        self.store.ready.clear()
        self.store.archives[162] = ("etag",123)
        with self.assertRaisesRegex(ValueError,"canonical"):
            self.apply()
        self.assertEqual(self.store.puts,0)

    def test_published_disappearance(self):
        self.apply()
        self.store.raw = None
        with self.assertRaisesRegex(ValueError,"disappeared"):
            self.apply()
        self.assertEqual(self.store.puts,1)

    def test_scope_and_model(self):
        for field,value in (("producer_invocation_id","2"*32),("private162_split_grant",ENROLLED),
                            ("private162_split_enrollment",GRANT),("exec_start_monotonic_us",5000)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(dict(self.p,**{field:value}))
        for field,value in (("estimated_remaining_millis",6300000),("epoch",True),("jet_size_bytes",False),
                            ("elapsed_execution_millis",-1),("phase","replay")):
            wrong=dict(self.p["after_status"],**{field:value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(dict(self.p,after_status=wrong,after_sha256=m.digest(m.body(wrong))))

    def test_journal_window(self):
        observed=copy.deepcopy(self.p)
        observed["after_status"]["phase"]="replay"
        observed["after_sha256"]=m.digest(m.body(observed["after_status"]))
        progress=dict(first=dict(slot=69984001,transactions=4,monotonic_us=2000),
                      last=dict(slot=69984003,transactions=7,monotonic_us=7000),
                      selectors=dict(_SYSTEMD_UNIT="unit",_PID="41",_SYSTEMD_INVOCATION_ID="1"*32,_BOOT_ID="1"*32),
                      guard=observed["guard"],worker=dict(pid=43))
        observed["transaction_progress"]=progress
        self.check(observed)
        progress["last"]["transactions"]=4
        with self.assertRaisesRegex(ValueError,"nonadvancing"):
            self.check(observed)

    def test_only_descendants(self):
        initial=self.apply()
        older=m.checked(initial)
        new=dict(older, conditional_header="If-Match",previous_receipt=initial,
                 before_etag=older["after_etag"],before_status=older["after_status"],before_sha256=older["after_sha256"])
        r=self.save(Path(self.folder.name)/"updated",new)
        self.assertEqual(m.adopted(ROW,r,initial,ENROLLED,GRANT),r)
        bad=self.save(Path(self.folder.name)/"foreign",dict(new,before_sha256="e"*64))
        with self.assertRaisesRegex(ValueError,"predecessor"):
            m.adopted(ROW,bad,initial,ENROLLED,GRANT)


if __name__ == "__main__":
    unittest.main()
