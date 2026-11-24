"""Verify retry-4 recovery's new owner, original lock, and completed native sample."""
import ast
from copy import deepcopy
from pathlib import Path
import runpy
import unittest


HERE = Path(__file__).with_name('status_resume.py')
M = runpy.run_path(str(HERE))


class NewWriter(unittest.TestCase):
    def test_only_matching_live_generation_can_resume(self):
        package = M['PACKAGE']
        old = dict(unit='cadence', lock=dict(path='/consumer.lock', inode=100222432, device=64512, fd=3))
        new = dict(unit='cadence', program=str(package/'status_cycle.py'), invocation_id='a'*32,
                   pid=1234, start_ticks=4321, lock=dict(old['lock'], fd=6))
        current = dict(Id='cadence', MainPID='1234', InvocationID='a'*32)
        check = M['assert_actor']
        check(old, new, current, 1234, 4321, 6)
        for key,value in (('invocation_id', M['WRITER_IID']), ('start_ticks', 1),
                          ('pid', 9876), ('program', '/old/status_cycle.py')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                check(old, dict(new, **{key:value}), current, 1234, 4321, 6)
        changed=deepcopy(new)
        changed['lock']['inode']+=1
        with self.assertRaises(ValueError):
            check(old, changed, current, 1234, 4321, 6)
        for iid in (M['WRITER_IID'], M['REJECTED_IID']):
            with self.subTest(iid=iid), self.assertRaises(ValueError):
                check(old, dict(new, invocation_id=iid), dict(current, InvocationID=iid), 1234, 4321, 6)

    def test_first_cycle_consumes_the_sample_without_a_new_clock(self):
        source=HERE.with_name('status_cycle.py')
        one_cycle, = (node for node in ast.parse(source.read_text()).body
                      if isinstance(node, ast.FunctionDef) and node.name=='one_cycle')
        scope={}
        exec(compile(ast.Module(body=[one_cycle], type_ignores=[]), str(source), 'exec'),scope)
        head={'path':'/last-fleet'}
        cfg={'path':'/observer.json'}
        sample={'path':'/completed-sample'}
        actual_fleet={'sole_next_observer':cfg}
        class ContextReached(Exception):
            pass

        def context(*args):
            self.assertEqual(args[:4], (head, actual_fleet, sample, {'not_before_utc':M['CUT'], 'output':sample['path']}))
            raise ContextReached

        def unexpected_timer(*args):
            self.fail('attempted a new native observation')

        scope.update(checked=lambda _:actual_fleet, closure_members=lambda *_:None, advance_sample=unexpected_timer,
                     sealed=lambda _ref:dict(not_before_utc=M['CUT'],output=sample['path']),
                     need=M['need'], names=lambda _:dict(out=Path('/next')), ensure_dir=lambda _:None,
                     make_context=context)
        with self.assertRaises(ContextReached):
            scope['one_cycle'](head,cfg,None,sample)
        with self.assertRaises(ValueError):
            scope['one_cycle'](head,{'path':'/other'},None,sample)


if __name__ == '__main__':
    unittest.main()
