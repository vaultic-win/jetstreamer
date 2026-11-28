"""Exercise positive, changing-owner and already-charged 170 host quotes."""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

import ram170_residency as resident


G = 1 << 30


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


class ResidentQuote(TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.group = root / 'cgroup'
        self.group.mkdir()
        for name, value in {'memory.current': 22*G, 'memory.max': 56*G, 'memory.swap.max': 0,
                            'memory.swap.current': 0, 'cgroup.procs': '100\n103',
                            'memory.stat': f'anon {13*G}\nshmem {8*G}\nfile {10*G}\n'}.items():
            (self.group / name).write_text(str(value))
        self.proc = root / 'proc'
        (root / 'namespace').touch()
        for pid, amount in ((100, 3*G), (103, 8*G)):
            folder = self.proc / str(pid)
            (folder / 'ns').mkdir(parents=True)
            (folder / 'smaps_rollup').write_text(f'Pss_Anon: {amount//1024} kB\nPss_Shmem: 10000 kB\n')
            (folder / 'ns/mnt').hardlink_to(root / 'namespace')
        self.scope = dict(expected_producer_unit='registered-170', run='/private/run', guard_receipts=str(root),
                          profile=dict(producer_memory_bytes=56*G, scratch_noswap_tmpfs_bytes=40*G))
        self.actor = dict(unit='registered-170', producer_pid=100, start_ticks=254,
                          producer_invocation_id='this invocation', interface='registered scope')
        self.grant = dict(actor='registered actor', producer_invocation_id='this invocation', interface='registered scope',
                          guard_plan='registered plan', guard_timer_invocation_id='registered timer')
        self.mapping = dict(path='/private/run/scratch', device=12, bytes=40*G, inode=1, mount_id=888)
        self.guard = dict(plan='registered plan', sample='fresh worker sample', timer_invocation_id='registered timer')
        self.processes = [[100, 254, 18, 400], [103, 285, 12, 10]]
        self.owner = dict(unit='registered-170', pid=100, invocation='this invocation', guard_plan='registered plan',
                          release='registered grant', actor='registered actor', processes=self.processes, phase='worker')
        self.gap = SimpleNamespace(UNIT='registered-170', INTERFACE='registered scope', CGROUP=self.group,
                    RELEASE=root/'release', read_actor=lambda: ('registered actor', self.actor),
                    process=lambda pid: next(x for x in self.processes if x[0]==pid),
                    workspace=SimpleNamespace(mount=lambda pid, scratch: self.mapping),
                    guard=self.protect)
        callback = SimpleNamespace(gap=self.gap, interface=lambda: self.scope)
        self.live = dict(receiver=lambda core: callback)
        self.core = SimpleNamespace(need=need, read=lambda path: (self.grant, 'registered grant'))
        self.native = dict(available_ram=90*G, required_ram=100*G, ram_margin=-10*G,
                           required_home=6*G, home_margin=2*G, guard_floor=4*G, resource_credit_bytes=0,
                           raw=dict(priced_170_invocation=None), realized_170_anon=0, ram_gap170=self.owner,
                           ram_retry_cost=dict(producer_memory_max=56*G, scratch_tmpfs=40*G,
                                               original_guard_still_budgeted=True, resident_ram_credit=0))
        self.fs = SimpleNamespace(f_frsize=4096, f_blocks=40*G//4096, f_bfree=31*G//4096)
        for p in (patch.object(resident, 'PROC', self.proc), patch.object(resident.os, 'statvfs', self.space)):
            p.start()
            self.addCleanup(p.stop)

    def protect(self, scope, actor, worker, grant):
        self.assertIs(scope, self.scope)
        self.assertIs(actor, self.actor)
        self.assertIs(grant, self.grant)
        self.assertEqual(worker, {'pid': 103})
        return self.guard, True

    def space(self, path):
        self.assertEqual(path, self.proc / '100/root/private/run/scratch')
        return self.fs

    def sample(self):
        return resident.sample(self.core, self.live, self.owner)

    def test_lower_of_both_samples_and_all_bounds_applied_once(self):
        first = self.sample()
        self.assertEqual(first['realized_bytes'], 19*G)
        # Cgroup shmem limits the first sample, tmpfs allocation the second.
        self.fs.f_bfree = 33*G//4096
        (self.group/'memory.stat').write_text(f'anon {8*G}\nshmem {10*G}\n')
        self.guard = dict(self.guard, sample='new guard tick')
        last = self.sample()
        self.assertEqual(last['realized_bytes'], 15*G)
        resident.apply(self.core, self.native, first, last)
        self.assertEqual((self.native['required_ram'], self.native['ram_margin']), (85*G, 5*G))
        self.assertEqual(self.native['ram_retry_cost']['unrealized_producer_ram'], 41*G)
        self.assertEqual((self.native['required_home'], self.native['home_margin'], self.native['guard_floor']), (6*G, 2*G, 4*G))
        self.assertEqual(self.native['resource_credit_bytes'], 0)
        with self.assertRaisesRegex(ValueError, 'previously realized'):
            resident.apply(self.core, self.native, first, last)

    def test_actor_mismatch(self):
        self.actor['producer_invocation_id'] = 'different invocation'
        with self.assertRaisesRegex(ValueError, 'different protected'):
            self.sample()

    def test_process_change_across_reads(self):
        seen = []
        def process(pid):
            seen.append(pid)
            row = next(x for x in self.processes if x[0] == pid)
            return [pid, 999, *row[2:]] if len(seen) > 2 else row
        self.gap.process = process
        with self.assertRaisesRegex(ValueError, 'processes, mount or guard changed'):
            self.sample()

    def test_swap_limits_and_charges(self):
        for name in ('memory.swap.current', 'memory.swap.max', 'memory.max'):
            with self.subTest(name=name):
                path = self.group/name
                original = path.read_text()
                path.write_text('4096')
                with self.assertRaisesRegex(ValueError, 'limit or swap'):
                    self.sample()
                path.write_text(original)

    def test_foreign_guard_or_mount(self):
        self.guard['timer_invocation_id'] = 'different'
        with self.assertRaisesRegex(ValueError, 'guard did not observe'):
            self.sample()
        self.guard['timer_invocation_id'] = 'registered timer'
        self.mapping['device'] = 999
        with self.assertRaisesRegex(ValueError, 'outside its private mount'):
            self.sample()

    def test_crossed_or_missing_samples(self):
        first = self.sample()
        for replacement in (None, dict(first, release='new grant'), dict(first, processes=[[1, 2, 3, 4]]),
                            dict(first, guard=dict(first['guard'], plan='new guard'))):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, 'across host availability'):
                resident.apply(self.core, self.native, first, replacement)
        self.native['ram_gap170'] = dict(self.owner, invocation='foreign')
        with self.assertRaisesRegex(ValueError, 'across host availability'):
            resident.apply(self.core, self.native, first, first)

    def test_held_and_terminal_have_no_realization(self):
        for owner in (None, dict(self.owner, phase='held'), dict(self.owner, phase='bootstrap')):
            with self.subTest(owner=owner):
                self.assertIsNone(resident.sample(self.core, self.live, owner))
                n = dict(deepcopy(self.native), ram_gap170=owner)
                resident.apply(self.core, n, None, None)
                self.assertEqual(n['ram_margin'], -10*G)
                self.assertEqual(n['ram_retry_cost']['unrealized_producer_ram'], 56*G)
                with self.assertRaisesRegex(ValueError, 'previously realized'):
                    resident.apply(self.core, n, None, None)

    def test_current_cap_and_prior_component(self):
        (self.group/'memory.current').write_text(str(10*G))
        first = self.sample()
        self.assertEqual(first['realized_bytes'], 10*G)
        self.native['raw']['priced_170_invocation'] = self.owner['invocation']
        with self.assertRaisesRegex(ValueError, 'previously realized'):
            resident.apply(self.core, self.native, first, first)


if __name__ == '__main__':
    main()
