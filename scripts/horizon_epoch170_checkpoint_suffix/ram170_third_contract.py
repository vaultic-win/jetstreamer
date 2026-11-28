"""Bind the third RAM receiver to both interrupted recordings and drained guard."""
from pathlib import Path
from evidence import BASE, checked, need
import ram170_second_contract as prior_contract

ROOT=BASE/'epoch170-from-73760367-ram-20261128-v3'
UNIT='horizon-qualify-170-from-73760367-ram-20261128-v3.service'
INTERFACE_DIGEST = None
INTERFACE=dict(path=str(ROOT/'RAM_GAP170_WRITER_INTERFACE.json'),sha256=INTERFACE_DIGEST)
STOP=dict(path=str(prior_contract.ROOT/'PRIVATE_RAM_V2_FLOOR_STOP.json'),sha256='31ae2a5041a3ac5b4876826047b920093debb7ef5d9747d0e578a54fae2ec896')
DRAIN=dict(path=str(prior_contract.ROOT/'PRIVATE_RAM_V2_GUARD_DRAIN.json'),sha256='5ad6e6935de5042a5e12a18e32a930d50fb3aa3e343f35028263cec6647cd937')
PREVIOUS='8a91ae07377042a3b929571f175527b3'
CHECKPOINT=prior_contract.CHECKPOINT


def interface():
    scope=checked(INTERFACE);prior=prior_contract.interface()
    stop=checked(STOP);drain=checked(DRAIN);entry=checked(scope['source_preflight']);ns=checked(scope['namespace'])
    profile=scope['profile']
    need(scope['schema']=='horizon-170-third-ram-gap-writer-interface-v1' and scope['prior_ram_interface']==prior_contract.INTERFACE
         and scope['previous_ram_terminal']==STOP and scope['previous_ram_drain']==DRAIN
         and stop['invocation_id']==drain['binding']['invocation_id']==PREVIOUS and not stop['closed_segment']
         and drain['producer_and_guard_drained'] and drain['terminal']==STOP and drain['binding']['producer']==prior_contract.UNIT
         and stop['release']==drain['binding']['release'] and stop['release']['sha256']=='1b5869841e8bbf498dce09570d10c9cfc7cf003637eec618d12a033b4f4292d8'
         and stop['partial'] is None and stop['last_logged_progress'] is None and not stop['segment_manifest_present']
         and stop['guard_observed_workers'] and not stop['publication_authorized'] and not drain['resource_credit_bytes']
         and scope['expected_producer_unit']==profile['host_unit']==UNIT and scope['expected_guard_unit']==UNIT.replace('-qualify-','-guard-')
         and scope['expected_guard_timer']==scope['expected_guard_unit'].replace('.service','.timer')
         and profile['sealed_package']==scope['guard_seal'] and scope['guard_seal']['sha256']=='68d0e50fa2a69c98092f17ef43a0f861682c004eda140b7d8d14c61df48e59cd'
         and scope['namespace']==entry['namespace']==profile['namespace'] and ns['unit']==entry['service'] and ns['layout']==scope['layout']
         and entry['route_accepted'] and not entry['worker_executed'] and entry['scope']==[73760368,73766969]
         and ns['report']['limits']['memory.max']==str(56<<30) and ns['report']['scratch']['bytes']==40<<30
         and ns['wrong_tmpfs_size_refused'] and ns['no_host_scratch_payload']
         and all(profile[k]==prior['profile'][k] for k in ('bootstrap','first','last','positions','checkpoints','node','worker',
             'producer_memory_bytes','scratch_noswap_tmpfs_bytes','new_home_total_bytes','new_control_bytes',
             'producer_cpu_quota_micros','guard_cpu_quota_micros','guard_memory_bytes'))
         and all(scope[k]==prior[k] for k in ('source_packet','independent_checkpoint','handoff','old_release','old_actor'))
         and not scope['publication_authorized'] and not scope['admission_or_release'],'different third RAM gap or prior custody')
    return scope


def checkpoint(scope):
    return prior_contract.checkpoint(scope)


def stopped_owner(fleet):
    prior_contract.stopped_owner(fleet)
    scope=interface();row=fleet['current_private170_second_ram_gap'];stop=checked(scope['previous_ram_terminal'])
    need(row['phase']=='terminal' and row['unit']['Id']==stop['unit'] and row['actor_ref']==stop['actor'] and row['release']==stop['release']
         and row['native_terminal']['INVOCATION_ID']==PREVIOUS and row['interface']==scope['prior_ram_interface']
         and not row['canonical_replay_claimed'] and not row['archive_publication_authorized'], 'changed second RAM recording')
    return row
