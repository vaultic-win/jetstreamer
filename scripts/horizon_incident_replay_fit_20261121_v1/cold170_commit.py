"""Bind the retry13 terminal to its original fleet owner and retained HOME booking."""
import hashlib
import json
from pathlib import Path
import runpy

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
DELIVERY = R / 'epoch170-cold-delivery-20261122-v13'
SOURCE = R / 'epoch170-retry13-rebook-20261122-v1'
CLOSURE = DELIVERY / 'guard-closure-tools'
SEAL = '54222b83d9d87dc900cb6a0e97a8c4e9e7e0d8763c429bb6e678f7033135a8d0'
IID = 'c44b5215f8d949159e7ce9cf911e9be1'
UNIT = 'horizon-qualify-170-replacement-local3retry13-20261122.service'
FIELD = 'cold170_local_commit'
DRAIN = 'cold170_guard_retirement'
OWNERS = 'current_homefloor_cold166_167_170_owners'
GROUPS = ('actual_executing_replays', 'actual_active_bootstraps', 'actual_active_private_diagnostics')
AD = {'path': str(SOURCE/'ACTUAL_ADMISSION_AND_PROTECTION.json'), 'sha256': 'f2748f58c5432fd8ccda6f5ad49b92dbdd01b7aa682558fd23230b8bc04e92a8'}
FIRST = {'path': str(SOURCE/'FIRST_PROTECTED_WORKER.json'), 'sha256': '11b55cd3872f9eafb61253f1f7e3e011260bae344407f6ed093f007d1dc7e558'}
LIVE = {'path': str(DELIVERY/'LIVE.json'), 'sha256': 'c73815d49529c42cc70f0e7ba11ab171f9b1ecdfb92c418afbe1b7631e57d898'}
PLAN = {'path': str(SOURCE/'ACTUAL_GUARD_PLAN.json'), 'sha256': 'c5322bbde82fdcfdd0b48b57ac0ebba6d439d8da4e3b622dbafe2b6a0618c31a'}
CAP = 384 << 30
LANE = Path('/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1')
RUN = LANE / 'replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry13-20261122'


def need(condition, why):
    if not condition:
        raise ValueError(why)


def validated_terminal_status(prior, current, due):
    """Accept only a qualified successor to the sole v2 writer."""
    package, previous_seal, previous_iid, previous_actor = prior
    package = package.parent/'tools-cold170-retry13-terminal-v1'
    qualified = current['qualified']
    need(qualified['predecessor_seal'] == previous_seal and current['intent']['old'] == previous_actor
         and current['intent']['qualified'] == current['qualified_ref']
         and current['active']['intent'] == current['intent_ref']
         and current['active']['qualified'] == current['qualified_ref']
         and current['active']['old'] == previous_actor
         and current['active']['schedule'] == current['intent']['schedule']
         and current['active']['admission'] == current['intent']['admission'] == AD
         and qualified['entry'] == qualified['package'] == due, 'foreign cold170 status handoff')
    actor=current['active']['new']
    need(actor['unit'] == previous_actor['unit'] and actor['program'] == str(package/'status_cycle.py')
         and len(actor['invocation_id']) == 32 and actor['invocation_id'] != previous_iid
         and all(actor['lock'][k] == previous_actor['lock'][k] for k in ('device','inode','path')),
         'cold170 status writer or lock changed')
    return package, due, actor['invocation_id'], actor


def registered_writer(s, prior):
    package = prior[0].parent/'tools-cold170-retry13-terminal-v1'
    prefix=package.parent/'COLD170_RETRY13_TERMINAL_V1_STATUS_ACTIVE.json'
    if not prefix.exists():
        return prior
    active,_=s.read(prefix)
    intent,ir=s.read(prefix.with_name('COLD170_RETRY13_TERMINAL_V1_STATUS_INTENT.json'))
    qualified,qr=s.read(prefix.with_name('COLD170_RETRY13_TERMINAL_V1_STATUS_QUALIFIED.json'))
    # The immutable full-price package pins the writer seal it was qualified for.
    binding, _=s.read(Path(__file__).resolve().with_name('cold170-writer.json'))
    reader=s.bound(binding['writer_seal'],package/'deployment-seal-receipt.json')
    need(reader['destination'] == str(package) and binding['predecessor_seal'] == prior[1],
         'wrong cold170 status predecessor or package')
    return validated_terminal_status(prior, dict(active=active,intent=intent,intent_ref=ir,
              qualified=qualified,qualified_ref=qr),binding['writer_seal'])


def guard():
    path = CLOSURE/'deployment-seal-receipt.json'
    raw = path.read_bytes()
    need(path.resolve(strict=True) == path and hashlib.sha256(raw).hexdigest() == SEAL, 'different cold170 guard closure seal')
    seal = json.loads(raw)
    members = {v['name']: v['sha256'] for v in seal['members']}
    need(seal['destination'] == str(CLOSURE), 'foreign guard closure directory')
    for name in ('peer_closures.py', 'closure.py'):
        p = CLOSURE/name
        need(p.resolve(strict=True) == p and hashlib.sha256(p.read_bytes()).hexdigest() == members[name],
             'unqualified cold170 closure input')
    return runpy.run_path(str(CLOSURE/'peer_closures.py'))['cold170']().guard


def bind(fleet, proof, adopting=False):
    terminal = proof['terminal']
    retirement = proof.get('guard_retirement')
    need(proof['producer_invocation_id'] == IID and proof['admission'] == AD and proof['first_worker'] == FIRST
         and proof['live'] == LIVE and proof['resource_credit_bytes'] == 0
         and terminal['path'] == str(DELIVERY/'TERMINAL_SUCCESS.json')
         and not fleet.get('recovered170_local_commit'), 'foreign epoch 170 local commit')
    if retirement is not None:
        need(retirement['path'] == str(DELIVERY/'TERMINAL_GUARD_DRAINED.json'), 'foreign epoch 170 guard retirement')
    rows = [r for g in GROUPS for r in fleet[g] if r['epoch'] == 170]
    owner = fleet.get(OWNERS, {}).get('170')
    if adopting and FIELD not in fleet:
        need(len(rows) == 1 and rows[0]['admission'] == AD and rows[0]['unit']['Id'] == UNIT
             and rows[0]['unit']['InvocationID'] == IID and owner and owner['actor']['producer_invocation_id'] == IID
             and owner['admission'] == AD and owner['first_worker'] == FIRST and DRAIN not in fleet,
             'prior fleet did not own the committed retry13 worker')
    else:
        need(not rows and not owner and fleet.get(FIELD) == terminal
             and (DRAIN not in fleet if retirement is None else
                  ((adopting and DRAIN not in fleet) or fleet.get(DRAIN) == retirement)),
             'local commit or guard retirement differs from fleet')
    return proof


def current(fleet, adopting=False):
    if not (DELIVERY/'TERMINAL_SUCCESS.json').exists():
        need(FIELD not in fleet and DRAIN not in fleet, 'fleet references an absent cold170 terminal')
        return None
    owner = guard()
    if owner.completion_path.exists():
        proof = owner.inspect()
    else:
        need(adopting, 'cold170 publication awaits original guard retirement')
        proof = owner.committed()
    return bind(fleet, proof, adopting)
