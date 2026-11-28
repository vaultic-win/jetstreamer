"""Exercise the serial M12 handoff and the real resumable retirement/restore path."""
import hashlib
import io
import json
import os
import runpy
import time
from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

import m12_admission as m
import rotation as op


class M12Test(unittest.TestCase):
    def test_charged_serial_and_prospective_170(self):
        proof=dict(restore_overlap=op.SLOT,serial_ram=2*op.G,scanner_ram=2*op.G,credit=0,
                   following_growth=36*op.G,available=1000,floor=800)
        result=m.funding(proof,200,0)
        self.assertEqual(result['remaining_ram'],2*op.G)
        self.assertEqual(result['remaining_home'],200)
        self.assertEqual(m.funding(proof,200,-1)['remaining_ram'],0)
        for update in ({'restore_overlap':0},{'serial_ram':3*op.G},{'scanner_ram':0},
                       {'following_growth':0},{'credit':1},{'floor':799}):
            with self.subTest(update=update), self.assertRaisesRegex(ValueError,'funding'):
                m.funding(proof|update,200,1)
        self.assertEqual(m.funding(proof|dict(floor=1200),-200,1)['remaining_home'],-200)

    def test_scope(self):
        with mock.patch.object(op,'TOOLS',op.M12):
            op.deployment('park','m12')
            for args in (('retire','m'),('restore','n'),('precheck','m12')):
                with self.assertRaises(ValueError):op.deployment(*args)
        with mock.patch.object(op,'TOOLS',op.OUT/'tools'):
            with self.assertRaises(ValueError):op.deployment('park','m12')

    def test_route_keeps_original_and_clean_fourth_turnovers(self):
        cases=(({m.PREVIOUS},False,(m.SCOPE,)), (set(),False,(m.FOURTH,'start')),
               ({m.NEXT},True,(m.FOURTH,'held')), (set(),True,(m.STOPPED,)))
        for active,has_stop,expected in cases:
            with (self.subTest(active=active,has_stop=has_stop),mock.patch.object(m,'list_units',return_value=active),
                  mock.patch.object(Path,'exists',return_value=has_stop),
                  mock.patch.object(m,'external_price',side_effect=RuntimeError('fixture provider')) as invoke):
                with self.assertRaisesRegex(RuntimeError,'fixture provider'):m.price()
                invoke.assert_called_once_with(*expected)
        with mock.patch.object(m,'list_units',return_value={m.NEXT,m.PREVIOUS}),self.assertRaisesRegex(ValueError,'overlapping'):
            m.price()

    def test_holding_after_both_stops_charges_issued_162(self):
        receipt=lambda path,digest:dict(path=str(path),sha256=digest)
        terminal169=receipt(m.TERMINAL_169,'07e7f475687fecb9cb5fbd154951d84443e4a134c8889f0ce1d8857b884aef3e')
        states={
            str(m.STOP_169):dict(producer_invocation_id=m.IID_169),
            str(m.STOP_170):dict(producer_invocation_id=m.PREVIOUS_IID),
            str(m.PID1_170):dict(properties=dict(Id=m.PREVIOUS,InvocationID=m.PREVIOUS_IID,ExecMainCode='2',ExecMainStatus='15')),
        }
        actor=dict(phase='terminal',invocation_id=m.IID_169,terminal=terminal169,resource_credit_bytes=0)
        failed=dict(stop_completion=receipt(m.STOP_170,'68148f92fdbad715b40200416efb1ac6dc040111bb167d0d5d5ceb33241ed680'),
                    pid1_exit=receipt(m.PID1_170,'18ccc679eb54249a194df0dfc54876138dedb78db117373d6fee7b61e4468252'),
                    invocation_id=m.PREVIOUS_IID,pending_replay_growth_bytes=0,resource_credit_bytes=0,
                    retained_following_growth_bytes=36*op.G,retained_producer_ram=48*op.G,retained_guard_ram=op.G)
        raw=dict(phase='stopped',priced_170_invocation=None,assembly168=dict(state='queued-or-drained'),resource_credit_bytes=0,
                 auxiliary=dict(serial_restore_overlap_already_reserved=op.SLOT),candidate_170_growth_bytes=0,
                 failed_170=failed,reserved_following_170_growth_bytes=36*op.G)
        actors=[dict(epoch=n,unit=f'horizon-qualify-{n}-fixture.service',invocation_id=f'{n:032x}') for n in (146,167,172)]
        fleet=receipt('/fixture/fleet','7'*64)
        base=dict(actor=actor,native=dict(raw=raw),resource_credit_bytes=0,fleet=fleet,observed_actors=actors,
                  accounting=dict(rooms=dict(holding_ram_available_from_serial=2*op.G),
                                  verification168_listener=dict(scanner_ram_from_serial=2*op.G),holding=None),
                  home_margin=200,ram_margin=30)
        seal=receipt(m.STOPPED/'deployment-seal-receipt.json',m.PRICE[m.STOPPED][0])
        shared=dict(schema='horizon-168-post-assembly-six-owner-price-v1',base_169=base,package=seal,
                    prospective_162=True,existing_162=None,available_home=1000,fleet=fleet,resource_credit_bytes=0,
                    recorded_unix_seconds=time.time(),home_margin=10,ram_margin=20)
        def units(*patterns):
            return {a['unit'] for a in actors} if patterns==('horizon-qualify-*',) else set()
        with (mock.patch.object(m,'list_units',side_effect=units),mock.patch.object(Path,'exists',return_value=True),
              mock.patch.object(m,'external_price',return_value=(shared,seal)) as price_provider,
              mock.patch.object(op,'fixed',side_effect=receipt),mock.patch.object(op,'bound',side_effect=lambda ref:states[ref['path']]),
              mock.patch.object(m,'owners'),mock.patch('n_admission.serial_owner')):
            price=m.price()
            price_provider.assert_called_once_with(m.STOPPED)
            self.assertEqual(price['remaining_home'],200)
            self.assertEqual(price['remaining_ram'],2*op.G+30)
            self.assertEqual(price['verification_and_turnover']['interrupted']['terminal169'],terminal169)
            self.assertEqual(price['resource_credit_bytes'],0)
            actors.append(dict(epoch=162,unit='horizon-qualify-162-fixture.service',invocation_id='e'*32))
            shared.update(prospective_162=False,existing_162=dict(phase='held'))
            issued=m.price()
            self.assertEqual(issued['remaining_home'],10)
            self.assertEqual(issued['remaining_ram'],2*op.G+20)
            self.assertIn(actors[-1]['unit'],issued['owners'])
            for update in ({'phase':'held'}, {'priced_170_invocation':m.PREVIOUS_IID},
                           {'candidate_170_growth_bytes':36*op.G}, {'reserved_following_170_growth_bytes':0}):
                with self.subTest(raw=update),mock.patch.dict(raw,update),self.assertRaises(ValueError):
                    m.price()
            with mock.patch.dict(failed,{'pid1_exit':terminal169}),self.assertRaises(ValueError):
                m.price()
            with mock.patch.dict(actor,{'invocation_id':'a'*32}),self.assertRaises(ValueError):
                m.price()
            with mock.patch.dict(shared,{'prospective_162':True}),self.assertRaises(ValueError):
                m.price()

    def test_parent_admission_precedes_native_work(self):
        with TemporaryDirectory() as root:
            d=Path(root);phase='park'; token='1234';iid='c'*32
            name='horizon-closed186-park-m12-1234.service'
            e=dict(source='/fixture',retained_shared_serial_slot=op.SLOT,single_copy_peak=m.PINS[1]+op.META)
            st=dict(Id=name,InvocationID=iid,MainPID=str(os.getpid()),ActiveState='active',Job='',
                    ControlGroup='/system.slice/'+name,MemoryMax=str(2*op.G),MemorySwapMax='0',CPUQuotaPerSecUSec='2s')
            ref=dict(path=str(d/'start'),sha256='1'*64); expected=dict(path=str(d/'expected.json'),sha256=m.M12_EXP)
            proof=dict(unit=name,phase=phase,source='/fixture',extra_memory=2*op.G)
            records={ref['path']:proof,expected['path']:e}
            def write(p,obj):
                records[str(p)]=obj
                return {'path':str(p),'sha256':'0'*64}
            with (mock.patch.object(m,'ROOT',d), mock.patch.object(m,'manager',return_value=st),
                  mock.patch.object(op,'fixed',return_value=expected),mock.patch.object(op,'ref',side_effect=lambda p:dict(path=str(p))),
                  mock.patch.object(op,'bound',side_effect=lambda r:records[r['path']]),mock.patch.object(op,'save',side_effect=write)):
                with self.assertRaises(KeyError):
                    m.validate_arm(d,phase,token,name,iid,2*op.G)
                m.arm(d,phase,token,name,iid,ref,2*op.G)
                m.validate_arm(d,phase,token,name,iid,2*op.G)
                st['InvocationID']='d'*32
                with self.assertRaises(ValueError):
                    m.validate_arm(d,phase,token,name,iid,2*op.G)

    def test_successor_170_recognizes_live_holding_admission(self):
        src=Path(__file__).resolve().parent.parent/'horizon_epoch170_checkpoint_suffix/following_peers.py'
        if not src.is_file():
            src=m.FOURTH/'following_peers.py'
        reader=runpy.run_path(str(src))['m12_owner']
        with TemporaryDirectory() as temp:
            group=Path(temp)
            (group/'cgroup.procs').write_text('777\n')
            (group/'memory.max').write_text(str(2*op.G))
            (group/'memory.swap.max').write_text('0')
            (group/'cpu.max').write_text('200000 100000')
            name='horizon-closed186-park-m12-4321.service'
            expected=dict(source='/fixture',length=m.PINS[1],sha256=m.PINS[2],retained_shared_serial_slot=op.SLOT,
                          single_copy_peak=m.PINS[1]+op.META)
            expected_ref=dict(path=str(m.ROOT/'expected.json'),sha256=m.M12_EXP)
            rec=m.ROOT/'ADMISSION_park_4321.json'
            receipt=dict(path=str(rec),sha256='1'*64)
            st=dict(Id=name,MainPID='777',ActiveState='active',Job='',InvocationID='a'*32,
                    ControlGroup='/system.slice/'+name,MemoryMax=str(2*op.G),CPUQuotaPerSecUSec='2s',MemorySwapMax='0')
            admission=dict(unit=name,phase='park',invocation=st['InvocationID'],expected=expected_ref,
                           restore_slot=op.SLOT,restore_peak=expected['single_copy_peak'],ram=2*op.G,swap=0,canonical_publication=False)
            def get(path, sha256=None):
                if path==rec:return admission,receipt
                self.assertEqual((path,sha256),(m.ROOT/'expected.json',m.M12_EXP))
                return expected,expected_ref
            core=SimpleNamespace(read=get,need=op.need,state=lambda unit:st)
            with mock.patch.dict(reader.__globals__,{'Path':lambda path:group}):
                accepted=reader(core,{name})
                self.assertEqual(accepted['admission'],receipt)
                self.assertFalse(accepted['resource_credit_bytes'])
                with self.assertRaises(ValueError):
                    reader(core,{name,'horizon-closed186-park-m12-2.service'})
                admission['invocation']='b'*32
                with self.assertRaises(ValueError):
                    reader(core,{name})

    def test_dispatch_wait_and_already_armed(self):
        with TemporaryDirectory() as temp:
            path=Path(temp)/'ADMISSION.json'
            with self.assertRaisesRegex(ValueError,'timed out'):
                m.wait_arm(path,timeout=0.003)
            pending=path.with_suffix('.pending')
            pending.write_bytes(b'complete dispatch admission')
            native_select=m.select.select
            def dispatch_after_watch(*args):
                pending.rename(path)
                return native_select(*args)
            with mock.patch.object(m.select,'select',side_effect=dispatch_after_watch) as wait:
                m.wait_arm(path,timeout=1)
                wait.assert_called_once()
            self.assertEqual(path.read_bytes(),b'complete dispatch admission')
            m.wait_arm(path,timeout=0.003)

    @unittest.skipUnless(os.geteuid()==0,'root-owned authenticated receipts required')
    def test_private_retire_and_single_inode_restore(self):
        # Use the real on-disk rename/unlink intents, allocated bytes, private
        # holding response, exact-ETag request and authenticated disk readback.
        with TemporaryDirectory() as temp:
            d=Path(temp).resolve()
            src=d/'epoch-186.jet'; data=b'M12 fixture'*8192
            src.write_bytes(data);src.chmod(0o600)
            digest=hashlib.sha256(data).hexdigest()
            ident=op.stamp(src)
            row=dict(source=str(src),sha256=digest,identity=ident,lane='m',rotation_lane='m12',allocated=ident[7]*512)
            receipt=op.save(d/'START_FIXTURE.json',dict(fixture=True))
            with (mock.patch.object(op,'HOME',d),mock.patch.object(op,'census',return_value={}),
                  mock.patch.object(op.consumers,'system',return_value='/system.slice/fixture')):
                # A process failure after the rename must recover from quarantine
                # while preserving the original inode and first retirement intent.
                original_move=op.move
                def interrupted(*args):
                    original_move(*args)
                    raise RuntimeError('fixture interruption')
                with mock.patch.object(op,'move',side_effect=interrupted),self.assertRaises(RuntimeError):
                    op.retire(row,receipt,d,'fixture','0'*32)
                self.assertFalse(src.exists())
                self.assertEqual(op.stamp(src.with_name('.epoch186-retiring-'+digest))[1],ident[1])
                r=op.retire(row,receipt,d,'fixture','1'*32)
                self.assertEqual(r['allocated_bytes_removed'],row['allocated'])
                remote={'blob':dict(length=len(data),key='node_02/objects/'+digest+'.blob',etag='"aabb"')}
                expected={'length':len(data),'sha256':digest}
                class Receiver:
                    def __init__(self,body):self.body=body;self.calls=[]
                    def get_object(self,**args):
                        self.calls.append(args)
                        return dict(ETag='"aabb"',ContentLength=len(data),Body=io.BytesIO(self.body))
                with (mock.patch.object(m,'PINS',(ident[1],len(data),digest)),mock.patch.object(op,'owners'),
                      mock.patch.object(op,'s3',return_value={'BUCKET':'fixture'})):
                    with self.assertRaisesRegex(ValueError,'hash mismatch'):
                        op.restore(row,expected,remote,Receiver(data[:-1]+b'?'),{'floor':0})
                    self.assertFalse(src.exists())
                    good=Receiver(data)
                    restored=op.restore(row,expected,remote,good,{'floor':0})
                    self.assertEqual(good.calls,[{'Bucket':'fixture','Key':remote['blob']['key'],'IfMatch':'"aabb"'}])
                    self.assertEqual(src.read_bytes(),data)
                    self.assertEqual(src.stat().st_nlink,1)
                    self.assertTrue(restored['single_inode'] and restored['independent_disk_readback'])
                    again=op.restore(row,expected,remote,good,{'floor':0})
                    self.assertTrue(again['already_restored'])
                    self.assertEqual(len(good.calls),1)
                    src.write_bytes(data+b'mutated')
                    with self.assertRaises(ValueError):op.restore(row,expected,remote,good,{'floor':0})


if __name__=='__main__':unittest.main()
