import datetime as dt
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

# Exercise the same six-field projection with a controlled evidence resolver.
sys.path.insert(0,str(Path(__file__).resolve().parent))
from types import ModuleType
import importlib.util
spec = importlib.util.spec_from_file_location('private_wire', Path(__file__).with_name('split_wire.py'))
wire = importlib.util.module_from_spec(spec)
evidence = ModuleType('evidence')
def need(ok, msg):
    if not ok:
        raise ValueError(msg)
evidence.need = need
evidence.utc = lambda minute: dt.datetime.fromisoformat(minute.replace('Z','+00:00'))
evidence.checked = lambda ref: dict(archive={'size':501})
with patch.dict(sys.modules, evidence=evidence):
    spec.loader.exec_module(wire)

class PrivateWire(unittest.TestCase):
    def setUp(self):
        self.context=SimpleNamespace(now=evidence.utc('2026-11-27T23:48:08Z'),stamp='2026-11-27T23:48:08Z')
        self.iid='a'*32
        self.admission={'path':'intent','sha256':'b'*64}
        self.previous=dict(epoch=169,sampled_at_utc='2026-11-27T23:33:08Z',phase='replay',
                jet_size_bytes=200,estimated_remaining_millis=500000000,elapsed_execution_millis=600000)
        self.old=dict(producer_invocation_id=self.iid,hourly169_start_intent=self.admission,
                      measured_slots_per_second=2,planning_milliseconds={'interval_remaining':3600000})
        self.row=dict(epoch=169,phase='worker',unit={'InvocationID':self.iid},actor={'producer_pid':15},
                      hourly169_start_intent=self.admission,canonical_replay_claimed=False,archive_publication_authorized=False)
        self.ref=dict(path='old',sha256='c'*64)
    def result(self):
        with patch.object(wire,'archive',return_value={'size':401}):
            return wire.forecast(self.context,self.row,self.previous,self.old,self.ref,lambda c,e,n:dict(total_millis=200000))
    def test_carries_authenticated_same_owner_before_scheduled_window(self):
        body,receipt=self.result()
        self.assertEqual((body['phase'],body['jet_size_bytes'],body['elapsed_execution_millis']),('replay',401,1500000))
        self.assertEqual(receipt['carried_private_replay_status'],self.ref)
        self.assertFalse(receipt['measured_canonical_progress'])
        self.assertEqual(sum(receipt['planning_milliseconds'].values()),body['estimated_remaining_millis'])
    def test_refuses_foreign_owner(self):
        self.old['producer_invocation_id']='d'*32
        with self.assertRaisesRegex(ValueError,'another actor'):
            self.result()
    def test_measured162_journal_rate(self):
        self.row.update(epoch=162,held_owner=self.admission,producer_invocation_id=self.iid,transaction_replay_claimed=True,
                    native_diagnostic={'observation':{'useful_work':{'journal_invocation_id':self.iid,'slot_delta':3,
                    'elapsed_seconds':2,'transaction_delta':100,'last':{'slot':69984015}}}})
        self.old.update(private162_split_held=self.admission,split162_enrollment=self.ref)
        self.previous.update(epoch=162,phase='verification')
        body,r=self.result()
        self.assertEqual((body['phase'],r['measured_slots_per_second'],r['split162_enrollment']),('replay',1.5,self.ref))
        self.assertEqual(body['estimated_remaining_millis'],sum(r['planning_milliseconds'].values()))
    def test_terminal_closes_private_replay(self):
        self.row.update(phase='terminal',invocation_id=self.iid,terminal=self.ref)
        body,r=self.result()
        self.assertEqual((body['phase'],body['jet_size_bytes'],r['producer_invocation_id']),('verification',501,None))

if __name__=='__main__':
    unittest.main()
