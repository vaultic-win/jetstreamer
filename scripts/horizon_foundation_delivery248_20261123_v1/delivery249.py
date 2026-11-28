"""Admit the closed 249 archive on the residual 211 allocation."""
from functools import partial
import sys
from pathlib import Path

from . import delivery248 as shared
from . import status248, terminal

D, V, CG = shared.D, shared.V, shared.CG
bound, ref = shared.bound, shared.ref
EPOCH, CPU = 249, 18
ORIGIN_IID = 'dbf4a4d19de84f31b3897da87622156e'
ROOT = D/'horizon-upload-249-ordinary-v214'
UNIT = ROOT.name+'.service'
BOOK = V/'horizon211-residual-delivery249-v214/assignment.json'
CLAIM = ROOT/'pipeline-claim.json'
PRIVATE = Path('/home/ubuntu/.jetstreamer-private/current-reader-delivery-249-20261119-v2')
DEPLOY = D/'horizon249-delivery-consumers-v214-a1/deployment.json'
PREFLIGHT = D/'horizon249-ordinary-delivery-after248-v213-a1/assessment.json'
FAST = D/'horizon-r2-public247-current-reader-v214/assignment.json'
KEY = 'epoch-249.epoch-status.json'
LENGTH = 180924777820
SHA = 'd6802f70fa854af0ca12e6c425d9b4fbdc0b443bec680a1b631993d6b3269ded'
owner = sys.modules[__name__]
process = partial(shared.process, owner=owner)
registered = partial(shared.registered, owner=owner)
live_binding = partial(shared.live_binding, owner=owner)
unfunded = partial(shared.unfunded, owner=owner)
prefix = partial(shared.prefix, owner=owner)
census = partial(shared.census, owner=owner)
select_schedule = partial(shared.select_schedule, owner=owner)

def inputs():
    base = shared.pin(PREFLIGHT,'f91cd9f92dad280c60358dd033697f5d9a2f70a4dae3a1f47ee699f3e5fb10b4')
    assessment = bound(base)
    parent, pre, _, _, _, _ = shared.inputs()
    assert shared.registered()[2]['preflight'] == parent and assessment['first_delivery'] == ref(shared.BOOK)
    assert (assessment['candidate_gross'],assessment['candidate_disk'],assessment['candidate_cpus']) == (shared.GROSS,shared.DISK,[18,19])
    assert assessment['archive_length'] == LENGTH and assessment['reader_plan']['sha256'] == '03e16ae1dada49958ff00a7dda1c3ef31c2f37c7503b02b7e0a677bb40863e07'
    observer = shared.pin(DEPLOY,'5db516085b37277c62e3694a76fe33e8f01506604822b1bf964114a2b4f43de7')
    return base, pre, observer, assessment['reader_plan'], assessment['handoff'], assessment['drain']

def available(winner,fit):
    _,_,parent,_ = shared.registered()
    fast = bound(ref(FAST))
    assert fast['donor'] == ref(shared.BOOK) and fit['reserved_211_delivery'] == fast['donor']
    assert fast['gross'] == 24159191040 and parent['reserve_before'] == winner['retained_211']
    assert parent['reserve_after'] == parent['reserve_before']-shared.GROSS
    balance = parent['reserve_after']-fast['gross']
    assert balance == fast['donor_after'] == 12224342528
    assert {r['epoch'] for r in bound(fit['fleet'])['active']} == {247,248,266}
    assert fit['public247_charge'] in (fast['gross'], fast['metadata'])
    return balance, dict(delivery248=ref(shared.BOOK),public247=ref(FAST))

def finite_owner():
    if not BOOK.exists():
        assert not CLAIM.exists() and not (CG/UNIT).exists()
        return {}
    _, claim, book, launch = registered()
    assert book['additional_assignments'] == dict(delivery248=ref(shared.BOOK),public247=ref(FAST))
    assert book['reserve_before'] == 12224342528 and book['reserve_after'] == 950053376
    if not (CG/UNIT).exists():
        manager = shared.props(UNIT,['MainPID','ActiveState','Job'])
        assert manager['MainPID'] == '0' and manager['ActiveState'] in ('inactive','failed') and not manager['Job']
        return {}
    live_binding()
    return {UNIT:(claim['invocation_id'],int(launch['unit']['MainPID']),shared.LIMIT,{CPU,CPU+1})}

def main():
    action, = sys.argv[1:]
    if action == 'status':
        status248.start(owner)
    elif action == 'terminal':
        terminal.capture(owner)
    else:
        assert action in ('check','issue')
        print(shared.issue(owner, check_only=action=='check'), flush=True)

if __name__ == '__main__':
    main()
