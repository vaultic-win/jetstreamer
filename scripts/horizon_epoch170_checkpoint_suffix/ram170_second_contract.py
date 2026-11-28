"""Bind the second RAM receiver to the preserved first recording and drained guard."""
from pathlib import Path
from evidence import BASE, checked, need
import ram170_contract as first

ROOT=BASE/'epoch170-from-73760367-ram-20261128-v2'
UNIT='horizon-qualify-170-from-73760367-ram-20261128-v2.service'
INTERFACE_DIGEST = None
INTERFACE=dict(path=str(ROOT/'RAM_GAP170_WRITER_INTERFACE.json'),sha256=INTERFACE_DIGEST)
STOP=dict(path=str(first.ROOT/'PRIVATE_RAM_V1_FLOOR_STOP.json'),sha256='c3d6b77afb2806afeeef0e3a118316874d6d5bad92fa79cb002cfec643691af4')
DRAIN=dict(path=str(first.ROOT/'PRIVATE_RAM_V1_GUARD_DRAIN.json'),sha256='1db663cb2987c894ad070f3587325ca8cea1416c70ae1564b421da87386b9d48')
PREVIOUS='2f1418eb4b6842ca97fe2336df2e7877'
CHECKPOINT=first.CHECKPOINT


def interface():
    scope=checked(INTERFACE);prior=first.interface()
    stop=checked(STOP);drain=checked(DRAIN);entry=checked(scope['source_preflight']);ns=checked(scope['namespace'])
    profile=scope['profile']
    need(scope['schema']=='horizon-170-second-ram-gap-writer-interface-v1' and scope['prior_ram_interface']==first.INTERFACE
         and scope['previous_ram_terminal']==STOP and scope['previous_ram_drain']==DRAIN
         and stop['invocation_id']==drain['binding']['invocation_id']==PREVIOUS and not stop['closed_segment']
         and drain['producer_and_guard_drained'] and drain['terminal']==STOP
         and scope['expected_producer_unit']==profile['host_unit']==UNIT and scope['expected_guard_unit']==UNIT.replace('-qualify-','-guard-')
         and scope['expected_guard_timer']==scope['expected_guard_unit'].replace('.service','.timer')
         and profile['sealed_package']==scope['guard_seal'] and scope['guard_seal']['sha256']=='19a4426a03738d2094b2e6101e175c7b1b9e438efd49f03381cec6b44bfb5496'
         and scope['namespace']==entry['namespace']==profile['namespace'] and ns['unit']==entry['service'] and ns['layout']==scope['layout']
         and entry['route_accepted'] and not entry['worker_executed'] and entry['scope']==[73760368,73766969]
         and ns['report']['limits']['memory.max']==str(56<<30) and ns['report']['scratch']['bytes']==40<<30
         and ns['wrong_tmpfs_size_refused'] and ns['no_host_scratch_payload']
         and all(profile[k]==prior['profile'][k] for k in ('bootstrap','first','last','positions','checkpoints','node','worker',
             'producer_memory_bytes','scratch_noswap_tmpfs_bytes','new_home_total_bytes','new_control_bytes',
             'producer_cpu_quota_micros','guard_cpu_quota_micros','guard_memory_bytes'))
         and all(scope[k]==prior[k] for k in ('source_packet','independent_checkpoint','handoff','old_release','old_actor'))
         and not scope['publication_authorized'] and not scope['admission_or_release'],'different second RAM gap or prior custody')
    return scope


def checkpoint(scope):
    return first.checkpoint(scope)


def stopped_owner(fleet):
    first.stopped_owner(fleet)
    scope=interface();row=fleet['current_private170_ram_gap'];stop=checked(scope['previous_ram_terminal'])
    need(row['phase']=='terminal' and row['unit']['Id']==stop['unit'] and row['actor_ref']==stop['actor'] and row['release']==stop['release']
         and row['native_terminal']['INVOCATION_ID']==PREVIOUS and row['interface']==scope['prior_ram_interface']
         and not row['canonical_replay_claimed'] and not row['archive_publication_authorized'], 'changed first RAM recording')
    return row
