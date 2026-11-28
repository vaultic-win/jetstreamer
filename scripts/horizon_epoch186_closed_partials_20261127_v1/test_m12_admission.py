"""Exercise the serial M12 handoff and the real resumable retirement/restore path."""
import hashlib
import io
import json
import os
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
