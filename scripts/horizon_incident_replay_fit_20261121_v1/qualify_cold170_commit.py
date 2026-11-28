#!/usr/bin/python3 -IB
"""Exercise terminal-only capacity with authenticated historical inputs and an offline closure."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import runpy
import sys
import time

here = Path(__file__).resolve().parent
route = runpy.run_path(str(here/'cold170_commit.py'))
publication = runpy.run_path(str(Path(sys.argv[1]).resolve()))
root = route['R']
delivery = route['DELIVERY']
price_path = delivery/'HELD_QA_PRICE_1795387812602574106.json'
read = lambda p: json.loads(p.read_bytes())
ref = lambda p: dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
need = route['need']
need(ref(price_path)['sha256']=='95de04b319c38920b833ed346a0a7b585380401b5ac14589398ae7c685d65eb1','foreign complete price')
price = read(price_path)
fleet = read(Path(price['fleet']['path']))
# The real root-owned receiver fixture has a synthetic PID 1 success envelope
# and a native committed inode. Never install it under the operational path.
fixture = delivery/'held-publication-qa-e524d80eb6fa4ffdad057fec8dc0dc04/test-receiver/authority/TERMINAL_SUCCESS.json'
native = read(fixture)
need(native['producer_invocation_id']==route['IID'] and native['source_admission']==route['AD'], 'wrong fixture generation')
term = dict(path=str(delivery/'TERMINAL_SUCCESS.json'), sha256=ref(fixture)['sha256'])
drained = dict(path=str(delivery/'TERMINAL_GUARD_DRAINED.json'),sha256='1'*64)
proof = dict(terminal=term, admission=route['AD'], first_worker=route['FIRST'], live=route['LIVE'],
             guard_retirement=drained, producer_invocation_id=route['IID'], resource_credit_bytes=0)
route['guard']()
assert route['current'](fleet,adopting=True) is None
assert route['bind'](fleet,proof,adopting=True)==proof
closed = copy.deepcopy(fleet)
for group in route['GROUPS']:closed[group]=[row for row in closed[group] if row['epoch']!=170]
del closed[route['OWNERS']]['170']
closed.update(cold170_local_commit=term,cold170_guard_retirement=drained)
assert route['bind'](closed,proof)==proof
v2root=root/'survivor172-cadence-20261122-v1'
v2=read(v2root/'COLD170_RETRY13_V2_STATUS_ACTIVE.json')['new']
v2seal=ref(v2root/'tools-cold170-retry13-v2/deployment-seal-receipt.json')
prior=(v2root/'tools-cold170-retry13-v2',v2seal,v2['invocation_id'],v2)
new=v2root/'tools-cold170-retry13-terminal-v1'
due=dict(path=str(new/'deployment-seal-receipt.json'),sha256='2'*64)
qr=dict(path='fixture/qualified',sha256='3'*64);ir=dict(path='fixture/intent',sha256='4'*64)
actor=dict(v2,program=str(new/'status_cycle.py'),invocation_id='f'*32)
intent=dict(old=v2,qualified=qr,schedule=fleet['sole_next_timer'],admission=route['AD'])
active=dict(intent,new=actor,intent=ir)
transition=dict(intent=intent,intent_ref=ir,active=active,qualified_ref=qr,
                qualified=dict(predecessor_seal=v2seal,entry=due,package=due))
assert route['validated_terminal_status'](prior,transition,due)==(new,due,'f'*32,actor)
cap = copy.deepcopy(price)
cap.update(closed_cold170=proof, epoch=145, recorded_unix_seconds=int(time.time()))
cap['population'].pop(route['UNIT']); cap['replacements'].pop('170')
cap['required_available_memory_bytes']+=cap['joined_resident_lower_bounds'].pop('170')
cap['bookings']['170']['measurement']='two complete stopped-tree walks'
def validate(v=cap,f=closed):
    return publication['validate'](v,f,v['fleet'],term,170,True)
expected=cap['complete_required_HOME_bytes']+publication['BOOK']
assert validate()==expected
rejects=[]
def reject(label,fn):
    try:fn()
    except (ValueError,AssertionError,KeyError):rejects.append(label)
    else:raise AssertionError(label)
for key,val in [('program','/foreign'),('invocation_id',v2['invocation_id']),('lock',dict(actor['lock'],inode=0))]:
    wrong=dict(transition,active=dict(active,new=dict(actor,**{key:val})))
    reject('different-writer-'+key,lambda:route['validated_terminal_status'](prior,wrong,due))
for field,val in [('first_worker',{}),('admission',{}),('live',{}),('producer_invocation_id','a'*32),('resource_credit_bytes',1)]:
    reject('wrong-'+field,lambda:route['bind'](closed,dict(proof,**{field:val})))
reject('live-worker-during-price',lambda:route['bind'](fleet,proof))
reject('first-adoption-without-owned-row',lambda:route['bind'](dict(fleet,actual_executing_replays=[],actual_active_bootstraps=[]),proof,True))
reject('old-170-commit',lambda:route['bind'](dict(closed,recovered170_local_commit=term),proof))
reject('wrong-retirement',lambda:validate(f=dict(closed,cold170_guard_retirement={})))
reject('old-full-price',lambda:validate(price))
reject('one-byte-short-home',lambda:validate(dict(cap,available_HOME_bytes=expected-1)))
reject('one-byte-short-memory',lambda:validate(dict(cap,available_memory_bytes=cap['required_available_memory_bytes']-1)))
reject('foreign-prepaid',lambda:validate(dict(cap,closed_prestart_remaining=dict(cap['closed_prestart_remaining'],**{'170':223316664320}))))
reject('active-producer-in-fleet',lambda:validate(f=dict(closed,actual_executing_replays=fleet['actual_executing_replays'],actual_active_bootstraps=fleet['actual_active_bootstraps'])))
reject('active-producer-in-census',lambda:validate(dict(cap,population=price['population'])))
reject('stale-full-price',lambda:validate(dict(cap,recorded_unix_seconds=int(time.time())-181)))
wrong=copy.deepcopy(cap);wrong['bookings']['170']['remaining_bytes']+=1
reject('changed-retained-tree',lambda:validate(wrong))
pending=dict(proof);pending.pop('guard_retirement')
reconciled=dict(closed);reconciled.pop('cold170_guard_retirement')
assert route['bind'](reconciled,pending,adopting=True)==pending
assert route['bind'](reconciled,proof,adopting=True)==proof
reject('guard-retirement-pending',lambda:validate(f=reconciled))
print(json.dumps(dict(positive=['bound-retry13-owner','bound-legacy-stops','committed-and-drained','stopped-full-price',
    'no-live-commit','adopt-before-guard-retirement','adopt-later-guard-retirement','same-service-writer-transition'],negative=rejects,real_fleet=price['fleet'],
    input_price=ref(price_path),authentic_fixture=ref(fixture),captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    synthetic_terminal=True,physical_capacity_claim=False,remote_writes=0),sort_keys=True))
