"""Follow the guarded 166 retry11 and retained 167 v3 through one native two-worker capture."""
import cold167_status as incumbent
from pathlib import Path
from evidence import BASE, bound, checked, need

ROOT=BASE/'epoch166-retry11-rebook-20261122-v1'
GUARD=BASE/'epoch166-retry11-guard-20261122-v1'
GUARD_SHA='d43d47340cc01d97cea8a37bdff9ac2d27762761c4cbb74f0d8740dda9e5ea22'
RUN=Path('/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1/replacement-local3retry10-20261121-v1/cold-retry11-20261122')
UNIT='horizon-qualify-166-independent-retry11-20261122.service'
TIMER='horizon-guard-166-independent-retry11-20261122.timer'
STOP='a72e48f26f716ac397b974d73040fec59c68957ce21be60634627039b3e7cab6'
FIELD='current_homefloor_cold166_167_owners'
BINDING=Path(__file__).resolve().with_name('retry11-generation.json')
TERMINAL_FIELD = 'cold166_retry11_write_version_failure'
TERMINAL = dict(path=str(ROOT/'WRITE_VERSION_TERMINAL_20261124.json'),
                sha256='d14e5b66958981056b8606e6354f08615c801ed9c1c5414747723c225d2c9bc0')


def failed_route(fleet=None):
    from owners import show

    terminal = checked(TERMINAL)
    intent = checked(terminal['intent'])
    admission = bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
    first_worker = bound(ROOT/'FIRST_PROTECTED_WORKER.json')
    admitted = checked(admission)
    worker = checked(first_worker)
    invocation = admitted['producer_invocation_id']
    exit_event = terminal['pid1_exit']
    timer = terminal['guard_timer_after']
    need(terminal['schema'] == 'horizon-epoch166-retry11-write-version-terminal-v1'
         and terminal['epoch'] == admitted['epoch'] == 166
         and worker['admission'] == admission
         and terminal['producer_invocation'] == worker['producer_invocation_id'] == invocation
         and exit_event['_PID'] == '1' and exit_event['UNIT'] == admitted['producer_unit'] == UNIT
         and exit_event['INVOCATION_ID'] == invocation and exit_event['EXIT_CODE'] == 'exited'
         and exit_event['EXIT_STATUS'] == '1' and intent['pid1_exit'] == exit_event
         and intent['error'] == terminal['error']
         and terminal['guard_timer_before']['InvocationID'] == admitted['timer_invocation_id']
         and terminal['guard_timer_before']['Triggers'] == TIMER.removesuffix('.timer') + '.service'
         and admitted['timer_unit'] == TIMER and timer == dict(ActiveState='inactive', Job='')
         and terminal['resource_credit_bytes'] == 0
         and terminal['local_payloads_mutated'] is False and terminal['r2_mutations'] is False,
         'different epoch 166 failure evidence or original reservation')
    producer = terminal['stopped_producer']
    guard_unit = TIMER.removesuffix('.timer') + '.service'
    guard = terminal['guard_after']
    for unit, state in ((UNIT, producer), (guard_unit, guard)):
        fields = ('ActiveState', 'MainPID', 'ControlPID', 'ControlGroup', 'Job')
        current = show(unit, fields)
        need(current == {key: state[key] for key in fields}
             and current['ActiveState'] in ('inactive', 'failed')
             and current['MainPID'] == current['ControlPID'] == '0'
             and not current['ControlGroup'] and not current['Job'],
             'failed epoch 166 producer or guard is still live')
    need(show(TIMER, tuple(timer)) == timer, 'failed epoch 166 guard timer is live')
    result = dict(terminal=TERMINAL, admission=admission, first_worker=first_worker,
                  producer_invocation_id=invocation, reservation_ending_bytes=0)
    if fleet is not None:
        registered = fleet.get(TERMINAL_FIELD)
        live = [row for group in ('actual_executing_replays', 'actual_active_bootstraps')
                for row in fleet[group] if row['epoch'] == 166]
        if registered is None:
            need(len(live) == 1 and live[0]['admission'] == admission
                 and live[0]['unit']['InvocationID'] == invocation
                 and live[0]['observer_config'] == worker['observer_row'],
                 'different prior epoch 166 fleet owner')
        else:
            need(registered == result and not live, 'conflicting epoch 166 terminal and live owner')
    return result

def generation():
    binding=checked(bound(BINDING))
    prepared=binding['prepared'];guard=binding['guard_qualification']
    need(Path(prepared['path'])==ROOT/'PREPARED.json' and guard==dict(path=str(GUARD/'GUARD_QUALIFIED.json'),sha256=GUARD_SHA),
         'different retry11 enrollment')
    row=checked(prepared);proof=checked(guard);baseline=row['baseline'];profile=baseline['profile'];root=RUN.lstat()
    need(row['epoch']==166 and row['profile']==profile and profile['fresh_attempt']==str(RUN) and
         baseline['root']==dict(path=str(RUN),device=root.st_dev,inode=93782068) and root.st_ino==93782068
         and RUN.resolve(strict=True)==RUN and profile['producer_unit']==UNIT and profile['guard_timer']==TIMER
         and profile['guard_binary_sha256']==proof['guard']['sha256'], 'retry11 prepared run or guard differs')
    need(proof['guard']==bound(GUARD/'tools/guard') and proof['seal']==bound(GUARD/'tools/deployment-seal-receipt.json'),
         'different retry11 guard image or deployment')
    seal=checked(proof['seal']);member,=(m for m in seal['members'] if m['name']=='guard')
    need(seal['destination']==str(GUARD/'tools') and member['sha256']==proof['guard']['sha256'],'wrong retry11 guard seal')
    for ref in proof['contract'].values():checked(ref)
    return prepared,baseline,guard,proof

def reader():
    module=incumbent.reader()
    existing=module.guard_budget
    module.ROUTES[166]=('166-independent-retry11-20261122',ROOT.name,RUN,93782068,288)
    module.FIELD=FIELD
    def guard_budget(epoch,root,plan,admission):
        if epoch!=166:return existing(epoch,root,plan,admission)
        prepared,_,_,proof=generation()
        need(root==ROOT and admission['source']==prepared and plan['maximum_root_physical_bytes']==288<<30
             and plan['data_fulfillment']==proof['contract'], 'different retry11 guard plan or booking')
        return 288,proof['guard']['sha256'],proof
    module.guard_budget=guard_budget
    return module

def check_generation(fleet_ref,fleet,state):
    unit,actor=state
    prepared,baseline,_,_=generation()
    intent_ref=bound(ROOT/'START_INTENT.json');intent=checked(intent_ref)
    stop=checked(checked(incumbent.EVENT)['reports']['166'])['guard_stop_completion']
    need(intent['prepared']==prepared and intent['stable_root']==baseline['root'] and
         intent['predecessor_stop']==baseline['predecessor_stop']==stop and stop['sha256']==STOP
         and fleet['current_four_homefloor_stops']==incumbent.EVENT and unit['Id']==actor['producer_unit']==UNIT,
         'unbound retry11 worker, intent or stopped reservation')
    ad=checked(bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json'));post=checked(ad['post_guard_capacity'])
    need(ad['source']==prepared and ad['intent']==intent_ref and ad['producer_invocation_id']==actor['producer_invocation_id']
         and post['epoch']==166 and post['fits'] and post['candidate']['producer_invocation_id']==actor['producer_invocation_id'],
         'different retry11 funded actor')
    target=ad['fleet'];old=checked(target)['sampled_at_utc']
    while fleet_ref!=target:
        fleet_ref=fleet['previous_Root_operational_review'];before=checked(fleet_ref)
        need(old<=before['sampled_at_utc']<fleet['sampled_at_utc'],'retry11 admission belongs to a different chain')
        fleet=before

def projection(row):
    if row['range']=='167':return incumbent.projection(row)
    first=checked(bound(ROOT/'FIRST_PROTECTED_WORKER.json'))
    need(row==first['observer_row'] and first['admission']==bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
         and row['range']=='166' and row['controller_unit']==row['producer_unit']==UNIT
         and first['producer_invocation_id']==row['expected_producer_invocation_id']==row['expected_controller_invocation_id'],
         'different retry11 worker projection')

def reconcile(c,observed_lane):
    module=reader()
    c.commits={};c.histories={}
    for epoch,check in ((166,check_generation),(167,incumbent.check_generation)):
        state=module.native(epoch)
        need(state,'missing admitted cold worker '+str(epoch))
        check(c.fleet_ref,c.fleet,state)
    c.next_cfg['replays']=[r for r in c.next_cfg['replays'] if r['range'] not in ('166','167')]
    module.sample_rows(c,observed_lane)
    need(set(c.new_rows)=={166,167} and set(c.recovered_owners)=={'166','167'},'incomplete cold owner set')
    previous=c.fleet.get(incumbent.FIELD)
    if previous:need(previous['167']['actor']==c.recovered_owners['167']['actor'],'incumbent 167 changed at handoff')
    for row in c.new_rows.values():
        need(row['observer_config'],'cold owner missing first protected worker')
        projection(row['observer_config'])

def install(c,fleet):
    if not c.new_rows:return
    reader().install(fleet,c)
    capture=fleet.pop('recovered_workers_observation')
    fleet['current_homefloor_cold166_167_observation']=capture
    fleet[incumbent.FIELD]={'167':c.recovered_owners['167']}
    fleet['current_homefloor_cold167_observation']=capture
    fleet['useful_replay_count']=incumbent.counts(c)['current_replay_lanes']
    for epoch,stop in ((166,STOP),(167,incumbent.STOP_SHA)):
        row=next(v for v in fleet['epochs'] if v['epoch']==epoch)
        original=row.pop('current_home_floor_stop',row.get('original_home_floor_stop'))
        need(original and original['completion']['sha256']==stop,'earlier guard stop lost')
        row['original_home_floor_stop']=original
        row['next_action']='Maintain the admitted worker and verify its resulting archive.'
