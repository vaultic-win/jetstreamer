"""Check simultaneous split outputs against each guard's actual floor."""
from unittest import TestCase
from unittest.mock import Mock, patch
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import following_peers as pricing


class SplitPeerCosts(TestCase):
    def test_absent_terminal_and_live_outputs(self):
        g, m = pricing.G, pricing.M
        self.assertEqual(pricing.peer_disk(None, 0), (0,0,0))
        self.assertEqual(pricing.peer_disk({'phase':'terminal'},8*g), (0,8*g,64*m))
        for phase in ('held','bootstrap','worker'):
            row = dict(phase=phase, disk=dict(floor=120*g,remaining=3*g,fixed_control=64*m))
            self.assertEqual(pricing.peer_disk(row,8*g), (120*g,3*g,64*m))
        row['disk']['remaining'] = 8*g+1
        with self.assertRaisesRegex(ValueError,'guarded split output'):
            pricing.peer_disk(row,8*g)

    def test_both_outputs_above_highest_floor(self):
        g, m = pricing.G, pricing.M
        basis = dict(guard_floor=100*g,required_home=110*g,available_home=145*g,historical_home_margin=50*g,
                     ram_margin=3*g,available_ram=20*g,phase='start',terminal_tree_bounds=[200*g,201*g],
                     candidate_170_growth_bytes=10*g)
        disks = [(105*g,5*g,64*m),(119*g,8*g,64*m)]
        q = pricing.amounts(basis,disks,2*g,g,2*g)
        self.assertEqual((q['guard_floor'],q['required_home'],q['home_margin'],q['ram_margin']),
                         (132*g,142*g,3*g,4*g))
        with self.assertRaisesRegex(ValueError,'duplicate'):
            pricing.amounts(basis|{'split_peers':{}},disks,2*g,g,2*g)
        self.assertFalse(pricing.amounts(basis|{'available_home':141*g},disks,2*g,g,2*g)['fits'])
        self.assertFalse(pricing.amounts(basis|{'phase':'start','terminal_tree_bounds':[379*g,380*g]},disks,0,0,0)['fits'])

    def test_successive_writer_versions_must_be_contiguous(self):
        with TemporaryDirectory() as tmp:
            d = Path(tmp)
            for version in (48,49,50,51):
                (d/f'FAILED166_CADENCE_V{version}_ACTIVE.json').touch()
            self.assertEqual(pricing.writer_versions(d,49),[49,50,51])
            (d/'FAILED166_CADENCE_V50_ACTIVE.json').unlink()
            with self.assertRaisesRegex(ValueError,'noncontiguous'):
                pricing.writer_versions(d,49)

    def test_holding_serial_rejects_duplicate_m12(self):
        support = SimpleNamespace(active_units=Mock(return_value=set()))
        previous = Mock(return_value={'existing':True})
        self.assertEqual(pricing.holding(None,support,previous),{'existing':True})
        def need(ok, reason):
            if not ok:
                raise ValueError(reason)
        support.active_units.return_value = {'horizon-closed186-park-m12-8.service','old-holding'}
        with self.assertRaisesRegex(ValueError,'several owners'):
            pricing.holding(SimpleNamespace(need=need),support,previous)

    def test_157_qualified_transfer_is_exclusive_and_bound_to_the_native_process(self):
        name = 'horizon-closed157-park-lanej-7.service'
        plan_hash = 'd3d19bcdcbb8de8752b28910194f26289b92b8af821dbb28b8269da628653c88'
        expected_hash = 'c4c24a560270605e2c0151ae802f64574785ea25a4592aa6e7b0b475160732e0'
        image_hash = '909248d8e4c1db4c3cd89e1a4f15205b4a59d442494f35b7635038152025bb7e'
        directory = pricing.RT/'epoch157-lanej-rotation-20261128-v1'
        package = directory/'park-package-v1'
        plan = dict(path=str(package/'plan.json'),sha256=plan_hash)
        expected = dict(path=str(package/'expected.json'),sha256=expected_hash)
        admission = dict(path=str(directory/'PARK_ADMISSION_7.json'),sha256='aa'*32)
        row = dict(schema='horizon-157-lanej-park-admission-v1',unit=name,plan=plan,expected=expected,
                   restore_peak=122423339643,restore_slot=123350028052,ram=2*pricing.G,cpu_micros=2000000,
                   swap=0,resource_credit_bytes=0,canonical_publication=False)
        start = dict(unit=name,admission=admission,invocation='01'*16,pid=123,start_ticks=99)
        evidence = {Path(plan['path']):({'length':122406562427,'sha256':'ab'*32},plan),
                    Path(expected['path']):({'park':plan,'sha256':'ab'*32},expected),
                    Path(admission['path']):(row,admission),directory/'PARK_START_7.json':(start,{'sha256':'bb'*32})}
        def read(path, pinned=None):
            value, ref = evidence[path]
            if pinned:
                self.assertEqual(ref['sha256'],pinned)
            return value,ref
        def need(ok, reason):
            if not ok:
                raise ValueError(reason)
        native = dict(Id=name,ActiveState='active',Job='',ControlPID='0',InvocationID=start['invocation'],
                      MainPID='123',MemoryMax=str(row['ram']),MemorySwapMax='0',CPUQuotaPerSecUSec='2s',
                      ControlGroup='/system.slice/'+name)
        core = SimpleNamespace(read=read,need=need,state=lambda unit:native.copy())
        support = SimpleNamespace(active_units=Mock(return_value={name}))
        previous = Mock(side_effect=AssertionError('foreign holding path'))
        with TemporaryDirectory() as d:
            root = Path(d)
            image = root/'jetstreamer-r2'
            image.touch()
            proc = root/'proc'/'123'
            proc.mkdir(parents=True)
            (proc/'exe').symlink_to(image)
            argv = [str(image),'holding-park',plan['path'],'--spec-sha256',plan_hash,'--self-sha256',image_hash]
            (proc/'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in argv)+b'\0')
            (proc/'stat').write_text('123 (task) '+' '.join(['0']*19+['99']))
            group = root/'group'
            group.mkdir()
            for path,value in [('cgroup.procs','123'),('memory.max',str(row['ram'])),
                               ('memory.swap.max','0'),('cpu.max','200000 100000')]:
                (group/path).write_text(value)
            locations = {'/proc':root/'proc','/sys/fs/cgroup'+native['ControlGroup']:group,
                         '/usr/local/lib/jetstreamer/horizon-holding-candidate-20261023-v1/jetstreamer-r2':image}
            with patch.object(pricing,'Path',side_effect=locations.__getitem__):
                self.assertEqual(pricing.holding(core,support,previous)['admission'],admission)
                (proc/'cmdline').write_bytes(b'wrong\0')
                with self.assertRaisesRegex(ValueError,'identity'):
                    pricing.holding(core,support,previous)
                support.active_units.return_value.add('another-holding.service')
                with self.assertRaisesRegex(ValueError,'more than one'):
                    pricing.holding(core,support,previous)
