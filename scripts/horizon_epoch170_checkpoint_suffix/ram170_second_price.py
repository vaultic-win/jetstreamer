"""Price the second RAM-gap recording on the current joint roster."""
from pathlib import Path
import hashlib
import importlib.util
import os
import runpy
import time

RT=Path('/var/lib/jetstreamer/horizon_runtime_data')
FIRST=RT/'epoch170-from-73760367-ram-20261128-v1'
DEP=ATTEMPT=RT/'epoch170-from-73760367-ram-20261128-v2'
OPERATOR=DEP/'operator-v1'
UNIT='horizon-qualify-170-from-73760367-ram-20261128-v2.service'
PROVIDER=RT/'epoch162-first-hourly-completion-20261127-v2/issued-price-v11'
OBSERVER_SHA='5c8d82782a94087bb5622ee35a0daa5b71a3904973308647833750528e062f25'
INTERFACE_SHA='1a4439dc22ccb3345fd9e472acc517198a26a0401793173af0ff268db4249cfc'
STOP='c3d6b77afb2806afeeef0e3a118316874d6d5bad92fa79cb002cfec643691af4'
DRAIN='1db663cb2987c894ad070f3587325ca8cea1416c70ae1564b421da87386b9d48'
ENROLL_OPTION='--enroll-second-ram-gap-170'
G=1<<30
M=1<<20
RETRY=FOLLOWING=False
PRODUCER_MEMORY=56*G

# These historical primitives retain the original bootstrap and protected fleet.
path=FIRST/'operator-v1/ram170_price.py'
original_seal=path.parent/'deployment-seal-receipt.json'
if hashlib.sha256(original_seal.read_bytes()).hexdigest()!='bf43047f5274ee877aa977014700ec3dbd688b3454aa006aac1ccf0e97a91c43':
    raise ValueError('different first RAM issuer')
import json
previous=json.loads(original_seal.read_bytes())
for m in previous['members']:
    name=m['name'];p=path.parent/name
    if p.parent!=path.parent or hashlib.sha256(p.read_bytes()).hexdigest()!=m['sha256']:
        raise ValueError('changed first RAM issuer member')
spec=importlib.util.spec_from_file_location('ram170_first_issuer',path)
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
prior, TREE, ALIAS, BRIDGE, retained_guard = old.prior,old.TREE,old.ALIAS,old.BRIDGE,old.retained_guard
cmd, state, inactive, read, bound, need=old.cmd,old.state,old.inactive,old.read,old.bound,old.need


def scope():
    value, scope_ref=read(DEP/'RAM_GAP170_WRITER_INTERFACE.json',INTERFACE_SHA)
    original, old_ref=old.scope()
    end, er=read(FIRST/'PRIVATE_RAM_V1_FLOOR_STOP.json',STOP)
    drain, dr=read(FIRST/'PRIVATE_RAM_V1_GUARD_DRAIN.json',DRAIN)
    need(value['prior_ram_interface']==old_ref and value['previous_ram_terminal']==er and value['previous_ram_drain']==dr
         and drain['terminal']==er and drain['producer_and_guard_drained'] and not end['closed_segment']
         and value['expected_producer_unit']==value['profile']['host_unit']==UNIT and value['profile']['producer_memory_bytes']==PRODUCER_MEMORY
         and all(value[k]==original[k] for k in ('independent_checkpoint','source_packet','handoff'))
         and value['namespace']['sha256']=='b7159835ef383ebda33baaa509d8d8ff8476ba7d27a60928c46af61ace1333f0'
         and value['source_preflight']['sha256']=='0bf17593c143542898026ed0136487b89d02468437a272f1546a798006949a0c'
         and not value['publication_authorized'],'different second RAM scope or first custody')
    return value,scope_ref


def compare_predecessor():
    checkpoint=old.compare_predecessor()
    need(checkpoint==scope()[0]['independent_checkpoint'],'different second gap checkpoint')
    return checkpoint


def previous_guard():
    dr=scope()[0]['previous_ram_drain']
    handback=bound(dr);binding=handback['binding']
    need(binding['producer']==old.UNIT and binding['invocation_id']=='2f1418eb4b6842ca97fe2336df2e7877'
         and binding['release']==bound(handback['terminal'])['release'] and not inactive(old.UNIT)['ControlGroup']
         and not inactive(binding['guard'])['ControlGroup'],'first RAM guard or producer still owns compute')
    timer=state(binding['timer'],'Id,ActiveState,Job')
    need(timer['ActiveState']=='inactive' and not timer['Job'],'first RAM timer returned')
    return timer,binding['guard'],binding['release']


def transfer_guard(save):
    previous_guard()
    return scope()[0]['previous_ram_drain']


def writer(require_registration=True):
    _, scope_ref=scope(); binding,_=read(OPERATOR/'binding.json')
    provider_ref=binding['provider']; need(provider_ref['path']==str(PROVIDER/'deployment-seal-receipt.json'),'foreign provider')
    _,registered=old.package(PROVIDER,provider_ref['sha256'])
    need(registered==provider_ref and binding['second_ram_gap170_interface']==scope_ref,'different installed second issuer')
    peer=runpy.run_path(str(PROVIDER/'following_peers.py'))
    active=peer['current_writer'](prior,dict(path=str(peer['ISSUED']/'deployment-seal-receipt.json'),sha256=peer['SEAL169']))
    row=bound(active);ready=bound(row['ready']);program=Path(row['new']['program'])
    if not require_registration and 'second_ram_gap170_interface' not in ready:
        return active,None
    installed=bound(ready['package']);receiver,_=old.package(DEP/'observer-modules-v1',OBSERVER_SHA)
    images={m['name']:m['sha256'] for m in installed['members']}
    need(ready.get('second_ram_gap170_interface')==scope_ref and installed['destination']==str(program.parent)
         and all(images.get(m['name'])==m['sha256'] for m in receiver['members']) and ENROLL_OPTION in program.read_text(),
         'cadence has not enrolled the second RAM scope')
    return active,program


def price(phase, *, preliminary=False):
    need(Path(__file__).resolve().parent==OPERATOR and phase in ('start','held') and (phase=='start' or not preliminary),
         'unrecognized second-170 issuer or phase')
    before,_,release=previous_guard(); active,program=writer(require_registration=not preliminary)
    quote=runpy.run_path(str(PROVIDER/'capacity.py'))['whole_roster']()
    native=quote['base_169']['native'];cost=native['ram_retry_cost'];next162=quote['prospective_162_interval_two'];planned=native['planned_169_retry']
    row=native['ram_gap170']
    need(quote['package']==bound(read(OPERATOR/'binding.json')[1])['provider'] and quote['writer']==active and not quote['resource_credit_bytes']
         and planned['third_scope']['sha256']=='7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf'
         and next162['additional_home']==3*G+64*M and next162['additional_compute']==0
         and planned['additional_home']==4*G+64*M and planned['additional_ram']==cost['extra_ram']==8*G
         and cost['producer_memory_max']==PRODUCER_MEMORY and cost['home_growth']==8*G and cost['scratch_tmpfs']==40*G
         and cost['resident_ram_credit']==native['ram170_residency']['realized_bytes']==0,
         'different shared owner or paid reservations')
    if phase=='held':
        need(row and row['unit']==UNIT and row['actor']==read(DEP/'SUCCESSOR_ACTOR.json')[1] and row['phase']=='held' and not row['release'],
             'different held second 170')
    else:
        need(row is None and not os.path.lexists(DEP/'SUCCESSOR_ACTOR.json'),'second 170 already issued')
    raw=native['raw']; peer=native['independent_retry169'];floor=(peer.get('floor') or 0) if peer else 0
    result=old.geometry(quote,raw['terminal_tree_bounds'],raw['guard_floor'],floor)
    return dict(**result,phase=phase,observed=int(time.time()),fleet=quote['fleet'],writer=active,available_home=quote['available_home'],
                ram_margin=quote['ram_margin'],joint=raw['joint'],assembly168=raw['assembly168'],whole_roster=quote,prior_guard=before,
                previous_ram_release=release,writer_ready=program is not None,preliminary=preliminary,resource_credit_bytes=0,
                archive_publication_authorized=False)
