from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

import after_stop as prices


def need(ok, message):
    if not ok:
        raise ValueError(message)


class StoppedRoster(TestCase):
    def setUp(self):
        self.owners = {epoch: dict(Id=f'unit{epoch}',InvocationID=f'iid{epoch}') for epoch in (146,167,172)}
        self.fleet = dict(actual_executing_replays=[dict(epoch=n,unit=u) for n,u in self.owners.items()],
                          actual_active_private_diagnostics=[],actual_active_bootstraps=[])
        self.first = dict(row169=dict(phase='terminal',terminal={'sha256':prices.TERMINAL169}),row162=None)
        self.core = SimpleNamespace(need=need, cmd=Mock(), state=Mock())
        self.core.cmd.return_value = '\n'.join(self.owners[n]['Id']+' running' for n in self.owners)
        self.core.state.side_effect = lambda name: dict(self.owners[int(name[4:])],ActiveState='active',Job='')

    def owners_now(self):
        return prices.observations(self.core,self.fleet,dict(replacement143=None),self.first)

    def test_stale_worker_row_yields_to_native_terminal(self):
        self.fleet['actual_active_private_diagnostics'] = [dict(epoch=170,unit={'Id':'ended'})]
        self.assertEqual([r['epoch'] for r in self.owners_now()],[146,167,172])
        self.core.cmd.return_value += '\nended running'
        with self.assertRaisesRegex(ValueError,'native replay owners'):
            self.owners_now()

    def test_foreign_169_terminal_and_survivor_identity_fail_closed(self):
        self.first['row169']['terminal']['sha256'] = 'other'
        with self.assertRaisesRegex(ValueError,'169 terminal'):
            self.owners_now()
        self.first['row169']['terminal']['sha256'] = prices.TERMINAL169
        self.core.state.side_effect = lambda _: dict(ActiveState='active',Job='',InvocationID='other')
        with self.assertRaisesRegex(ValueError,'survivor invocation'):
            self.owners_now()

    def test_funding_preserves_159_and_the_169_guard(self):
        g = prices.G
        self.assertEqual(prices.ram_handoff(69*g,g,48*g,68*g),20*g)
        for terms in ((68,1,48,68),(69,0,48,68),(69,1,47,68),(69,1,48,67)):
            with self.assertRaisesRegex(ValueError,'different epoch 169'):
                prices.ram_handoff(*(x*g for x in terms))
