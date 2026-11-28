"""Price the third RAM-gap recording on the current joint roster."""
from pathlib import Path
import hashlib
import importlib.util
import os
import runpy
import time

RT=Path('/var/lib/jetstreamer/horizon_runtime_data')
SECOND=RT/'epoch170-from-73760367-ram-20261128-v2'
DEP=ATTEMPT=RT/'epoch170-from-73760367-ram-20261128-v3'
OPERATOR=DEP/'operator-v1'
UNIT='horizon-qualify-170-from-73760367-ram-20261128-v3.service'
PROVIDER=RT/'epoch162-first-hourly-completion-20261127-v2/issued-price-v15'
OBSERVER_SHA='1eac71ad427b6f67421199403e8f6782823d0052e98aec9793b7a7497f3ae0e3'
INTERFACE_SHA='b148b13e8ef0bfff8bb40992eb267068668dac71590908806fe6ded15dff7151'
STOP='31ae2a5041a3ac5b4876826047b920093debb7ef5d9747d0e578a54fae2ec896'
DRAIN='5ad6e6935de5042a5e12a18e32a930d50fb3aa3e343f35028263cec6647cd937'
ENROLL_OPTION='--enroll-third-ram-gap-170'
G=1<<30
M=1<<20
RETRY=FOLLOWING=False
PRODUCER_MEMORY=56*G

# These historical primitives retain the original bootstrap and protected fleet.
path=SECOND/'operator-v1/ram170_second_price.py'
original_seal=path.parent/'deployment-seal-receipt.json'
if hashlib.sha256(original_seal.read_bytes()).hexdigest()!='feec980c46dc438a4654cd872e161ce241e5c12936403daaf63880dcfa71aafb':
    raise ValueError('different first RAM issuer')
import json
previous=json.loads(original_seal.read_bytes())
for m in previous['members']:
    name=m['name'];p=path.parent/name
    if p.parent!=path.parent or hashlib.sha256(p.read_bytes()).hexdigest()!=m['sha256']:
        raise ValueError('changed first RAM issuer member')
spec=importlib.util.spec_from_file_location('ram170_second_issuer',path)
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
prior, TREE, ALIAS, BRIDGE, retained_guard = old.prior,old.TREE,old.ALIAS,old.BRIDGE,old.retained_guard
cmd, state, inactive, read, bound, need=old.cmd,old.state,old.inactive,old.read,old.bound,old.need


def scope():
    value, scope_ref=read(DEP/'RAM_GAP170_WRITER_INTERFACE.json',INTERFACE_SHA)
    original, old_ref=old.scope()
    end, er=read(SECOND/'PRIVATE_RAM_V2_FLOOR_STOP.json',STOP)
    drain, dr=read(SECOND/'PRIVATE_RAM_V2_GUARD_DRAIN.json',DRAIN)
    need(value['prior_ram_interface']==old_ref and value['previous_ram_terminal']==er and value['previous_ram_drain']==dr
         and drain['terminal']==er and drain['producer_and_guard_drained'] and not end['closed_segment']
         and value['expected_producer_unit']==value['profile']['host_unit']==UNIT and value['profile']['producer_memory_bytes']==PRODUCER_MEMORY
         and all(value[k]==original[k] for k in ('independent_checkpoint','source_packet','handoff'))
         and value['namespace']['sha256']=='27e2f83cf00c7ce27e082925087669c696f54069414a2d2d8ab741fa5a1b5567'
         and value['source_preflight']['sha256']=='06c8f0c39c540d4e2b3d073f6a10bc2e107fd81c59bdd72e379b855c39397446'
         and not value['publication_authorized'],'different third RAM scope or second custody')
    return value,scope_ref


def compare_predecessor():
    checkpoint=old.compare_predecessor()
    need(checkpoint==scope()[0]['independent_checkpoint'],'different third gap checkpoint')
    return checkpoint


def previous_guard():
    old.previous_guard()
    dr=scope()[0]['previous_ram_drain']
    handback=bound(dr);binding=handback['binding']
    need(binding['producer']==old.UNIT and binding['invocation_id']=='8a91ae07377042a3b929571f175527b3'
         and binding['release']==bound(handback['terminal'])['release'] and not inactive(old.UNIT)['ControlGroup']
         and not inactive(binding['guard'])['ControlGroup'],'second RAM guard or producer still owns compute')
    timer=state(binding['timer'],'Id,ActiveState,Job')
    need(timer['ActiveState']=='inactive' and not timer['Job'],'second RAM timer returned')
    return timer,binding['guard'],binding['release']


def transfer_guard(save):
    previous_guard()
    return scope()[0]['previous_ram_drain']


def writer(require_registration=True):
    _, scope_ref=scope(); binding,_=read(OPERATOR/'binding.json')
    provider_ref=binding['provider']; need(provider_ref['path']==str(PROVIDER/'deployment-seal-receipt.json'),'foreign provider')
    _,registered=old.old.package(PROVIDER,provider_ref['sha256'])
    need(registered==provider_ref and binding['third_ram_gap170_interface']==scope_ref,'different installed third issuer')
    peer=runpy.run_path(str(PROVIDER/'following_peers.py'))
    active=peer['current_writer'](prior,dict(path=str(peer['ISSUED']/'deployment-seal-receipt.json'),sha256=peer['SEAL169']))
    row=bound(active);ready=bound(row['ready']);program=Path(row['new']['program'])
    if not require_registration and 'third_ram_gap170_interface' not in ready:
        return active,None
    installed=bound(ready['package']);receiver,_=old.old.package(DEP/'observer-modules-v1',OBSERVER_SHA)
    images={m['name']:m['sha256'] for m in installed['members']}
    need(ready.get('third_ram_gap170_interface')==scope_ref and installed['destination']==str(program.parent)
         and all(images.get(m['name'])==m['sha256'] for m in receiver['members']) and ENROLL_OPTION in program.read_text(),
         'cadence has not enrolled the third RAM scope')
    return active,program


def price(phase, *, preliminary=False):
    need(Path(__file__).resolve().parent==OPERATOR and phase in ('start','held') and (phase=='start' or not preliminary),
         'unrecognized third-170 issuer or phase')
    before,_,release=previous_guard(); active,program=writer(require_registration=not preliminary)
    quote=runpy.run_path(str(PROVIDER/'capacity.py'))['whole_roster']()
    native=quote['base_169']['native'];cost=native['ram_retry_cost'];next162=quote['prospective_162_interval_two'];planned=native['planned_169_retry']
    row=native['ram_gap170']
    second162=quote['second_162_accounting']
    need(quote['package']==bound(read(OPERATOR/'binding.json')[1])['provider'] and quote['writer']==active and not quote['resource_credit_bytes']
         and planned['fourth_scope']['sha256']=='f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5'
         and second162['interface']['sha256']=='2192e657ff4cf56a9404dc41cf5d3223cb437afa3eb7225676b4116d95c18712'
         and second162['full_output_reservation']==3*G and second162['retained_control']==64*M
         and 0<=second162['remaining_output']<=3*G and second162['additional_compute']==0
         and next162['additional_home']==3*G+64*M and next162['additional_compute']==0
         and planned['additional_home']==4*G+64*M and planned['additional_ram']==cost['extra_ram']==8*G
         and cost['producer_memory_max']==PRODUCER_MEMORY and cost['home_growth']==8*G and cost['scratch_tmpfs']==40*G
         and cost['resident_ram_credit']==native['ram170_residency']['realized_bytes']==0,
         'different shared owner or paid reservations')
    if phase=='held':
        need(row and row['unit']==UNIT and row['actor']==read(DEP/'SUCCESSOR_ACTOR.json')[1] and row['phase']=='held' and not row['release'],
             'different held third 170')
    else:
        need(row is None and not os.path.lexists(DEP/'SUCCESSOR_ACTOR.json'),'third 170 already issued')
    raw=native['raw']; peer=native['independent_retry169'];floor=(peer.get('floor') or 0) if peer else 0
    result=old.old.geometry(quote,raw['terminal_tree_bounds'],raw['guard_floor'],floor)
    history, record=read(RT/'epoch166-closed-compact-indexes-20261128-v1/SHARED_HOME_DRAWDOWN_0400_053730.json',
                         'cb92e5a9b96960d0e2a98a7f2d9ce75d5ad221b84c4549955eea4ce05a0b87ab')
    need(history['worst_observed_90s_free_byte_decrease']==20_011_974_656
         and history['worst_stop_unix']-history['worst_start_unix']==83, 'changed observed peer drawdown')
    sustainable(result,history['worst_observed_90s_free_byte_decrease'])
    return dict(**result,shared_drawdown_evidence=record,phase=phase,observed=int(time.time()),fleet=quote['fleet'],writer=active,available_home=quote['available_home'],
                ram_margin=quote['ram_margin'],joint=raw['joint'],assembly168=raw['assembly168'],whole_roster=quote,prior_guard=before,
                previous_ram_release=release,writer_ready=program is not None,preliminary=preliminary,resource_credit_bytes=0,
                archive_publication_authorized=False)


def sustainable(result, allowance):
    """Keep the measured peer fluctuation available above the full output and constant guard floor."""
    if allowance <= 0 or "shared_drawdown_allowance" in result:
        raise ValueError("invalid or duplicate 170 shared drawdown allowance")
    previous = result["home_margin"]
    margin = previous - allowance
    result.update(shared_drawdown_allowance=allowance, margin_before_peer_drawdown=previous,
                  home_margin=margin, fits=result["fits"] and margin >= 0)
