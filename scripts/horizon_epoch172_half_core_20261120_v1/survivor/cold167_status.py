"""Follow the guarded, original-booking 167 relaunch in the existing fleet observer."""
import hashlib
import importlib.util
from pathlib import Path

from evidence import BASE, bound, checked, need

EPOCH = 167
ROOT = BASE / 'epoch167-source-index-rebook-20261122-v3'
NAME = '167-source-index-v3-20261122'
UNIT = 'horizon-qualify-' + NAME + '.service'
TIMER = 'horizon-guard-' + NAME + '.timer'
RUN = Path('/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-source-index-v1-20261121/cold-source-index-v3-20261122')
FIELD = 'current_homefloor_cold167_owners'
GUARD = BASE/'epoch167-cold-guard-20261122-v3'
BINDING = Path(__file__).resolve().with_name('generation.json')
EVENT = {'path':str(BASE/'four-homefloor-20261122-v1/R2_STOP_CORRECTIONS.json'),
         'sha256':'9719cca38d4d9f8fddb65529436c408139d884c1a7838b4ea323e39a8499a214'}
STOP_SHA = '50c7f072d70a1e3112c67034e4fc324a8597093871483c7c3af411bb52ea1c64'
SOURCE = BASE/'prefix140-status-cadence-20261122-v1/cadence-tools/recovered.py'
SOURCE_SHA = 'ba0b0fed25bf76d705b556d9a4eee9dc274e51a3b37b96f77877ed862f2e9fa4'


def generation():
    selected=checked(bound(BINDING))
    prepared=selected['prepared']
    guard=selected['guard_qualification']
    need(Path(prepared['path'])==ROOT/'PREPARED.json' and Path(guard['path'])==GUARD/'GUARD_QUALIFIED.json',
         'different cold 167 generation registration')
    reg=checked(prepared)
    first=checked(guard)
    identity=reg['baseline']['root']
    meta=RUN.stat()
    need(reg['epoch']==EPOCH and reg['profile']['fresh_attempt']==str(RUN)
         and reg['profile']['producer_unit']==UNIT and reg['profile']['guard_timer']==TIMER
         and identity==dict(path=str(RUN),device=meta.st_dev,inode=meta.st_ino),
         'different prepared worker or run inode')
    guard_image=GUARD/'tools/guard'
    need(first['guard']==bound(guard_image) and first['seal']==bound(GUARD/'tools/deployment-seal-receipt.json'),
         'different guard qualification, executable or seal')
    seal=checked(first['seal'])
    member,=(v for v in seal['members'] if v['name']=='guard')
    need(seal['destination']==str(guard_image.parent) and member['sha256']==first['guard']['sha256'],
         'incorrect sealed guard member')
    checked(first['contract']['contract'])
    checked(first['contract']['deployment_seal'])
    return selected,reg,first


def reader():
    # Give this generation its own route table. The historical reader in sys.modules
    # keeps all of its original routes and can still validate earlier observations.
    need(hashlib.sha256(SOURCE.read_bytes()).hexdigest()==SOURCE_SHA, 'changed recovered-worker reader')
    spec=importlib.util.spec_from_file_location('homefloor_recovered_167', SOURCE)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    binding,reg,proof=generation()
    module.ROUTES={EPOCH:(NAME,ROOT.name,RUN,reg['baseline']['root']['inode'],512)}
    module.QUAL=binding['guard_qualification']
    module.GUARD_SHA=proof['guard']['sha256']
    module.FIELD=FIELD
    module.EVENT=EVENT
    return module


def projection(row):
    first=checked(bound(ROOT/'FIRST_PROTECTED_WORKER.json'))
    need(row==first['observer_row'] and first['admission']==bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
         and row['range']==str(EPOCH) and row['producer_unit']==row['controller_unit']==UNIT
         and row['expected_producer_invocation_id']==row['expected_controller_invocation_id']==first['producer_invocation_id'],
         'cold 167 projection does not match the admitted worker')


def check_generation(fleet_ref, fleet, state):
    unit,actor=state
    binding,reg,_=generation()
    prepared=binding['prepared']
    intent=checked(bound(ROOT/'START_INTENT.json'))
    stop=checked(checked(EVENT)['reports'][str(EPOCH)])['guard_stop_completion']
    root=RUN.stat()
    need(intent['prepared']==prepared and intent['stable_root']==reg['baseline']['root']
         and intent['stable_root']==dict(path=str(RUN),device=root.st_dev,inode=root.st_ino)
         and intent['predecessor_stop']==reg['baseline']['predecessor_stop']==stop
         and stop['sha256']==STOP_SHA and fleet['current_four_homefloor_stops']==EVENT
         and reg['profile']['producer_unit']==unit['Id']==actor['producer_unit']==UNIT
         and reg['profile']['guard_timer']==TIMER, 'unbound cold 167 intent, actor or original stop')
    admission=checked(bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json'))
    post=checked(admission['post_guard_capacity'])
    need(admission['producer_invocation_id']==actor['producer_invocation_id']
         and admission['source']==prepared and admission['intent']==bound(ROOT/'START_INTENT.json')
         and post['fits'] and post['candidate']['producer_invocation_id']==actor['producer_invocation_id'],
         'different admitted cold 167 native price or owner')
    cursor=fleet_ref
    data=fleet
    target=admission['fleet']
    target_time=checked(target)['sampled_at_utc']
    while cursor!=target:
        cursor=data['previous_Root_operational_review']
        prior=checked(cursor)
        need(prior['sampled_at_utc']<data['sampled_at_utc'] and prior['sampled_at_utc']>=target_time,
             'cold 167 was admitted against a different fleet')
        data=prior


def reconcile(c, observed_lane):
    module=reader()
    state=module.native(EPOCH)
    c.commits={}
    c.histories={}
    c.recovered_owners={}
    c.recovered_ref=None
    if state is None:
        need(not c.fleet.get(FIELD) and not (ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json').exists()
             and all(row['range']!='167' for row in c.cfg['replays']), 'admitted cold 167 owner has stopped')
        return
    check_generation(c.fleet_ref,c.fleet,state)
    # full172 may already have projected its row. The recovered reader appends its own.
    c.next_cfg['replays']=[r for r in c.next_cfg['replays'] if r['range']!='167']
    module.sample_rows(c,observed_lane)
    need(set(c.new_rows)=={EPOCH} and set(c.recovered_owners)=={str(EPOCH)}, 'incomplete cold 167 protection')
    if c.new_rows[EPOCH]['observer_config']:
        projection(c.new_rows[EPOCH]['observer_config'])


def counts(c):
    rows=getattr(c,'new_rows',{})
    boot=sum(row['phase']!='replay' for row in rows.values())
    return dict(canonical_producer_count=1+len(rows),active_bootstraps=boot,
                current_replay_lanes=sum(bool(v) for v in c.advancing.values()))


def install(c,fleet):
    if not c.new_rows:
        return
    reader().install(fleet,c)
    fleet['current_homefloor_cold167_observation']=fleet.pop('recovered_workers_observation')
    fleet['useful_replay_count']=counts(c)['current_replay_lanes']
    row=next(r for r in fleet['epochs'] if r['epoch']==EPOCH)
    stopped=row.pop('current_home_floor_stop',row.get('original_home_floor_stop'))
    need(stopped and stopped['completion']['sha256']==STOP_SHA, 'original cold 167 stop disappeared')
    row['original_home_floor_stop']=stopped
    row['next_action']='Maintain the guarded cold successor and verify the resulting archive.'
