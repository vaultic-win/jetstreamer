"""Observe the funded 170 retry and keep 166 when it joins the same cadence."""
from pathlib import Path
import stat

import cold166_status as retry166
import cold167_status as cold167
from evidence import BASE, bound, checked, need

LOCAL = Path(__file__).resolve().parent
REGISTRATIONS = [attempt for attempt in ('retry11','retry12','retry13') if (LOCAL/f'{attempt}-170-generation.json').is_file()]
need(len(REGISTRATIONS)==1, 'ambiguous 170 generation')
ATTEMPT = REGISTRATIONS[0]
ROOT = BASE / f'epoch170-{ATTEMPT}-rebook-20261122-v1'
GUARD = BASE / f'epoch170-{ATTEMPT}-guard-20261122-v1'
NAME = f'170-replacement-local3{ATTEMPT}-20261122'
UNIT = 'horizon-qualify-' + NAME + '.service'
TIMER = 'horizon-guard-' + NAME + '.timer'
RUN = Path('/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1') / f'cold-{ATTEMPT}-20261122'
STOP = 'd670ce226f7ee5e24660dbd99b2d8174d72cd38f39487d10b17bcc4c0a85d50a'
FIELD = 'current_homefloor_cold166_167_170_owners'
BINDING = LOCAL / f'{ATTEMPT}-170-generation.json'
FAILED_RUN = ROOT / 'failed-replay-20261124T123309Z'
FAILED166_CADENCE = LOCAL.name in tuple(f'tools-cold168-retry4-failed166-v{version}' for version in (1, 2, 3))
FAILED_CADENCE = FAILED166_CADENCE or LOCAL.name == 'tools-cold168-retry4-failed170-v1'
FAILED_STATUS = 'cold170_retry13_execution_failure'
FAILED_TERMINAL = {'path': str(FAILED_RUN/'TERMINAL.json'),
                   'sha256': '16664fda43d296d115858ff67a173d6d0cccb5f2ac90d446aa797da34a2f6c9d'}
FAILED_DRAIN = {'path': str(FAILED_RUN/'ORPHAN_GUARD_DRAINED.json'),
                'sha256': 'e570c630afe4add0209a6af6ebd9da6cc0195bc0a5b4034dcf2716baf130bae7'}
ENROLLMENTS = {
    'retry11': ('8420a1b00afa2d643a24e36c5b12c82fdd0b43d5238c9045c0c0c53097021728',
                '36d057cd24d412190ca41f2d910969a1b37fd175cab51ab8c00bd61f6826416d', 113704962),
    'retry12': ('466f48f20716b258189e242eef4d4e2e54fbf6202e6ecd4ff008eb3dd0d10b19',
                '7ed9e4bffff3cdaad1bd8d0eda700c3b107e85a4b585bb067e4eca50bbab123c', 113836033),
    'retry13': ('654e6612f8ce9ee2f9f5c9f172f79f9ce5da4b0f6f02443c856f3a5228a5ca69',
                '34ee106fc4dd290e8ad447f1ff5ab15cfe538b7ca522785a87df106566e0645c', 113981945),
}
ANCHOR_SHA, GUARD_SHA, INODE = ENROLLMENTS[ATTEMPT]
FAILURES = {
    'retry12': ('60b0ff3a1b09b8c684fdf07ff300ddaebb89b4c80581a9b475a057a2d6aee801',
                '7a9f41a86d9240be89e3484fc01c3a31', 'post-guard floor or actor changed'),
    'retry13': ('ff337e45c1f4a3af3e0f44654a80ee00ffef2c9405ddc27e16c6883611a53151',
                'f26354f4e63748059e441cbbee250fdb', 'post-guard floor 8829245547088 exceeds armed floor 8739050197584'),
}


def generation():
    binding = checked(bound(BINDING))
    anchor, witness = binding['successor_root'], binding['guard_qualification']
    need(anchor == dict(path=str(ROOT/'SUCCESSOR_ROOT.json'), sha256=ANCHOR_SHA)
         and witness == dict(path=str(GUARD/'GUARD_QUALIFIED.json'), sha256=GUARD_SHA),
         'foreign 170 enrollment')
    original, proof = checked(anchor), checked(witness)
    if ATTEMPT in FAILURES:
        digest, iid, error = FAILURES[ATTEMPT]
        failure = checked(original['previous_start_failure'])
        need(original['previous_start_failure']['sha256'] == digest
             and failure['cgroup'] == [] and failure['producer_invocation_id'] == iid
             and failure['error'] == error, 'different preceding 170 startup failure')
    meta = RUN.lstat()
    identity = dict(path=str(RUN), device=meta.st_dev, inode=meta.st_ino)
    need((original['root'], original['device'], original['inode']) == (str(RUN), 64512, INODE)
         and (meta.st_dev, meta.st_ino) == (64512, INODE) and RUN.resolve(strict=True) == RUN
         and (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode)) == (1001, 1003, 0o700), '170 enrollment root changed')
    need(proof['schema'] == f'horizon-170-{ATTEMPT}-native-guard-qualified-v1' and not proof['physical_launch']
         and proof['guard'] == bound(GUARD/'tools/guard') and proof['seal'] == bound(GUARD/'tools/deployment-seal-receipt.json'),
         'different 170 guard')
    seal = checked(proof['seal'])
    member, = (m for m in seal['members'] if m['name'] == 'guard')
    need(seal['destination'] == str(GUARD/'tools') and member['sha256'] == proof['guard']['sha256'], 'wrong 170 guard seal')
    for ref in proof['contract'].values():
        checked(ref)
    return anchor, identity, proof


# Earlier sealed packages continue to follow their original lane populations.
cold168 = None
generation168 = [n for n in (2, 3, 4) if (LOCAL/f'retry{n}-168-generation.json').is_file()]
need(len(generation168)<=1, 'overlapping 168 receiver generations')
if generation168:
    need(ATTEMPT == 'retry13' and (LOCAL/'cold170_commit.py').is_file(), 'wrong 170 generation for 168')
    import cold168_status as cold168


def reader():
    module = retry166.reader()
    _, identity, proof = generation()
    module.ROUTES[170] = (NAME, ROOT.name, RUN, identity['inode'], 384)
    module.FIELD = FIELD
    original = module.guard_budget

    def guard_budget(epoch, root, plan, admission):
        if epoch != 170:
            return original(epoch, root, plan, admission)
        need(root == ROOT and admission.get('source',{}).get('path') == str(ROOT/'PREPARED.json') and plan['maximum_root_physical_bytes'] == 384 << 30
             and plan['data_fulfillment'] == proof['contract'], 'different 170 guard contract or booking')
        return 384, proof['guard']['sha256'], proof

    module.guard_budget = guard_budget
    if cold168:
        cold168.register(module)
    return module


def check_generation(fleet_ref, fleet, state):
    unit, actor = state
    anchor, identity, _ = generation()
    prepared = bound(ROOT/'PREPARED.json')
    registration = checked(prepared)
    # The native session can carry the root identity inline or by immutable receipt.
    baseline = registration.get('baseline',registration)
    if ATTEMPT=='retry13':
        expected=checked(anchor)['previous_start_failure']
        need(baseline['previous_cold_failure']==expected,'170 predecessor failure changed')
    stable_root = baseline.get('root',baseline.get('stable_root'))
    need(stable_root in (anchor,identity), '170 preparation belongs to another filesystem object')
    intent_ref = bound(ROOT/'START_INTENT.json')
    intent = checked(intent_ref)
    stop = checked(checked(cold167.EVENT)['reports']['170'])['guard_stop_completion']
    need(fleet['current_four_homefloor_stops'] == cold167.EVENT and stop['sha256'] == STOP and
         intent['predecessor_stop'] == baseline['predecessor_stop'] == stop and intent['prepared'] == prepared and
         intent['stable_root'] == stable_root and unit['Id'] == actor['producer_unit'] == UNIT, 'foreign 170 start')
    admitted = checked(bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json'))
    post = checked(admitted['post_guard_capacity'])
    need(admitted['source'] == prepared and admitted['intent'] == intent_ref and admitted['fleet'] == intent['fleet']
         and post['epoch'] == 170 and post['fits'] and post['bookings']['170']['cap_bytes'] == 384 << 30
         and post['candidate']['producer_invocation_id'] == admitted['producer_invocation_id'] == actor['producer_invocation_id'],
         '170 funding or actor differs')
    target = admitted['fleet']
    oldest = checked(target)['sampled_at_utc']
    while fleet_ref != target:
        fleet_ref = fleet['previous_Root_operational_review']
        prior = checked(fleet_ref)
        need(oldest <= prior['sampled_at_utc'] < fleet['sampled_at_utc'], '170 admission from another fleet')
        fleet = prior


def projection(row):
    if cold168 and row['range'] == '168':
        return cold168.projection(row)
    if row['range'] != '170':
        return retry166.projection(row)
    first = checked(bound(ROOT/'FIRST_PROTECTED_WORKER.json'))
    need(first['admission'] == bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json') and row == first['observer_row']
         and row['producer_unit'] == row['controller_unit'] == UNIT and
         row['expected_producer_invocation_id'] == row['expected_controller_invocation_id'] == first['producer_invocation_id'],
         'different 170 worker projection')


def terminal_route(fleet):
    if ATTEMPT == 'retry13' and (LOCAL/'cold170_commit.py').is_file():
        import cold170_commit
        return cold170_commit.current(fleet, adopting=True)
    return None


def failed_route(fleet=None):
    """Recognize only the drained retry13 execution failure and retain its booking."""
    if not FAILED_CADENCE or ATTEMPT != 'retry13' or not Path(FAILED_DRAIN['path']).exists():
        return None
    from owners import show
    terminal = checked(FAILED_TERMINAL)
    drain = checked(FAILED_DRAIN)
    plan = checked(drain['intent'])
    admission = checked(terminal['admission'])
    worker = checked(terminal['first_worker'])
    exited = terminal['manager_exit']
    iid = admission['producer_invocation_id']
    need(terminal['schema'] == 'horizon-epoch170-retry13-execution-failure-v1'
         and terminal['admission'] == bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
         and terminal['first_worker'] == bound(ROOT/'FIRST_PROTECTED_WORKER.json')
         and worker['admission'] == terminal['admission'] and worker['producer_invocation_id'] == iid
         and exited['_PID'] == '1' and exited['UNIT'] == admission['producer_unit'] == UNIT
         and exited['INVOCATION_ID'] == iid and exited['EXIT_CODE'] == 'exited' and exited['EXIT_STATUS'] == '1'
         and terminal['retained_run'] and not terminal['archive_ready'] and not terminal['publication_authorized']
         and terminal['reservation_ending_bytes'] == drain['reservation_ending_bytes'] == 0
         and plan['terminal'] == FAILED_TERMINAL and plan['no_live_producer']
         and drain['producer'] == terminal['producer'], 'unbound epoch 170 terminal or retained booking')
    producer, timer, guard = drain['producer'], drain['timer'], drain['guard']
    need(producer['Id'] == UNIT and producer['LoadState'] == 'not-found'
         and producer['MainPID'] == producer['ControlPID'] == '0' and not producer['Job']
         and timer['Id'] == admission['timer_unit'] == TIMER and timer['ActiveState'] == 'inactive'
         and not timer['Job'] and plan['timer']['InvocationID'] == admission['timer_invocation_id']
         and guard['Id'] == TIMER.removesuffix('.timer') + '.service', 'different failed epoch 170 native owners')
    need(show(UNIT, tuple(producer)) == producer and show(TIMER, tuple(timer)) == timer,
         'failed epoch 170 native owners changed')
    fields = ('Id', 'ActiveState', 'MainPID', 'ControlPID', 'Job')
    guard_now = show(guard['Id'], fields)
    need(guard_now['Id'] == guard['Id'] and guard_now['ActiveState'] in ('inactive', 'failed')
         and guard_now['MainPID'] == guard_now['ControlPID'] == '0' and not guard_now['Job'],
         'failed epoch 170 guard still active')
    result = dict(terminal=FAILED_TERMINAL, guard_drain=FAILED_DRAIN,
                  admission=terminal['admission'], first_worker=terminal['first_worker'],
                  producer_invocation_id=iid, reservation_ending_bytes=0)
    if fleet is not None:
        prior = fleet.get(FIELD, {}).get('170')
        if prior is not None:
            need(FAILED_STATUS not in fleet and prior['admission'] == result['admission']
                 and prior['first_worker'] == result['first_worker']
                 and prior['actor']['producer_invocation_id'] == iid, 'different failed epoch 170 fleet owner')
        else:
            need(fleet.get(FAILED_STATUS) == result, 'missing prior epoch 170 owner or terminal adoption')
    return result


def roster(module, fleet_ref, fleet, terminal=None, failed166=None):
    checks = {166: retry166.check_generation, 167: cold167.check_generation, 170: check_generation}
    if cold168:
        checks[168] = lambda ref, data, state: cold168.check_generation(ref, data, state, cold167.EVENT)
    enrolled = set()
    for epoch, check in checks.items():
        state = module.native(epoch)
        if (epoch == 170 and terminal) or (epoch == 166 and failed166):
            need(state is None, f'terminal cold{epoch} producer still active')
            continue
        if state is None:
            optional = {166: retry166}
            if cold168:
                optional[168] = cold168
            need(epoch in optional and not (optional[epoch].ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json').exists()
                 and all(str(epoch) not in fleet.get(field, {}) for field in (module.FIELD, FIELD, retry166.FIELD)),
                 'missing admitted cold worker '+str(epoch))
            # Inactive 168 belongs to this retry. The generic reader has a
            # historical 168 terminal path for a different unit.
            if epoch == 168:
                module.ROUTES.pop(168)
            continue
        check(fleet_ref, fleet, state)
        enrolled.add(epoch)
    return enrolled


def reconcile(c, observed_lane):
    module = reader()
    c.commits = {}
    c.histories = {}
    terminal = terminal_route(c.fleet)
    c.failed170 = failed_route(c.fleet)
    c.failed166 = retry166.failed_route(c.fleet) if FAILED166_CADENCE else None
    need(not (terminal and c.failed170), 'conflicting epoch 170 commit and failure')
    enrolled = roster(module, c.fleet_ref, c.fleet, terminal or c.failed170, c.failed166)
    if c.failed166:
        module.ROUTES.pop(166)
        need(all(r['range'] != '166' for r in c.cfg['replays']), 'failed epoch 166 remained in sampled roster')
    if c.failed170:
        module.ROUTES.pop(170)
        need(all(r['range'] != '170' for r in c.cfg['replays']), 'failed epoch 170 remained in sampled roster')
    if terminal:
        from copy import copy
        c.commits[170] = terminal
        module.ROUTES.pop(170)
        # A same-sample retry can already have frozen the original live set.
        # Keep that record and bind the reduced capture separately.
        prior = c.paths['out']/'RECOVERED_WORKERS.json'
        closed_dir = c.paths['out']/'after-cold170-commit'
        if prior.exists():
            from evidence import durable, ensure_dir
            prior_ref = bound(prior)
            earlier = checked(prior_ref)
            old = earlier['owners'].get('170')
            need(earlier['fleet'] == c.fleet_ref and earlier['sample'] == c.sample_ref
                 and old and old['admission'] == terminal['admission'] and old['first_worker'] == terminal['first_worker']
                 and old['actor']['producer_invocation_id'] == terminal['producer_invocation_id']
                 and set(earlier['measured']) <= earlier['owners'].keys(),
                 'different pre-terminal cold170 capture')
            kept = {k:v for k,v in earlier['owners'].items() if k != '170'}
            need(kept == module.ownership(c.fleet), 'surviving workers changed after cold170 commit')
            ensure_dir(closed_dir)
            target=closed_dir/'RECOVERED_WORKERS.json'
            reduced = dict(fleet=c.fleet_ref, sample=c.sample_ref, owners=kept,
                           measured={k:v for k,v in earlier['measured'].items() if k != '170'},
                           prior_same_sample_capture=prior_ref)
            if target.exists(): need(checked(bound(target)) == reduced, 'changed terminal recovery capture')
            else: durable(target,reduced)
        sample_context = copy(c)
        # The inherited capture helper recognizes only the predecessor retry10 field.
        sample_context.commits = {}
        sample_context.paths = dict(c.paths, out=closed_dir)
        c.next_cfg['replays'] = [row for row in c.next_cfg['replays'] if row['range'] != '170']
    else:
        sample_context = c
    c.next_cfg['replays'] = [row for row in c.next_cfg['replays'] if int(row['range']) not in enrolled]
    module.sample_rows(sample_context, observed_lane)
    if terminal:
        for attr in ('recovered_ref','recovered_owners','new_rows'):
            setattr(c,attr,getattr(sample_context,attr))
    need(set(c.recovered_owners) == {str(e) for e in enrolled}, 'cold owner roster changed during capture')
    admitted = {int(k) for k,v in c.recovered_owners.items() if v['admission']}
    need(set(c.new_rows) == admitted and enrolled-admitted <= {168}, 'cold admissions changed during capture')
    for epoch in enrolled:
        key = str(epoch)
        for field in (cold167.FIELD, retry166.FIELD, FIELD, module.FIELD):
            prior = c.fleet.get(field, {}).get(key)
            if prior:
                need(prior['actor'] == c.recovered_owners[key]['actor'], 'cold owner changed')
        if epoch == 168 and (epoch not in admitted or not c.recovered_owners[key]['first_worker']):
            need(epoch not in admitted or c.new_rows[epoch]['observer_config'] is None, 'unregistered 168 worker')
            continue
        projection(c.new_rows[epoch]['observer_config'])
    if cold168:
        # The shared archive observer selects this attribute for epoch 168.
        c.metered168_row = c.new_rows.get(168)


def install(c, fleet):
    from copy import copy
    live_context=copy(c)
    # Generic install_recovered uses the historical indexed/retry10 registers.
    live_context.commits={}
    reader().install(fleet, live_context)
    capture = fleet.pop('recovered_workers_observation')
    if cold168:
        fleet['current_homefloor_cold166_167_168_170_observation'] = capture
        fleet[FIELD] = {k:v for k,v in c.recovered_owners.items() if k != '168'}
    fleet['current_homefloor_cold166_167_170_observation'] = capture
    fleet[cold167.FIELD] = {'167': c.recovered_owners['167']}
    fleet['current_homefloor_cold167_observation'] = capture
    if 166 in c.new_rows:
        fleet[retry166.FIELD] = {key: c.recovered_owners[key] for key in ('166', '167')}
        fleet['current_homefloor_cold166_167_observation'] = capture
    if c.failed166:
        fleet[retry166.TERMINAL_FIELD] = c.failed166
        if '166' in fleet.get(retry166.FIELD, {}):
            fleet['historical_cold166_retry11_owner'] = fleet[retry166.FIELD]['166']
            fleet[retry166.FIELD] = {'167': c.recovered_owners['167']}
        row = next(v for v in fleet['epochs'] if v['epoch'] == 166)
        previous = row.pop('current_home_floor_stop', row.get('original_home_floor_stop'))
        need(previous['completion']['sha256'] == retry166.STOP, 'lost stopped predecessor of failed cold166')
        row.update(original_home_floor_stop=previous, cold166_retry11_write_version_failure=c.failed166,
                   state='verification', no_live_producer_claimed=True, current_repair_owner='/root', repair_open=True,
                   current_status_scope='Epoch 166 retry11 exited on a historical account write version gap.',
                   next_action='Reproduce the failing slot transition with the retained source and cursor evidence.')
    if 170 in c.commits:
        proof=c.commits[170]
        fleet['cold170_local_commit']=proof['terminal']
        if proof.get('guard_retirement'):
            fleet['cold170_guard_retirement']=proof['guard_retirement']
        row=next(v for v in fleet['epochs'] if v['epoch']==170)
        previous=row.pop('current_home_floor_stop',row.get('original_home_floor_stop'))
        need(previous['completion']['sha256']==STOP, 'lost stopped predecessor of committed cold170')
        row.update(original_home_floor_stop=previous, cold170_local_commit=proof['terminal'],
                   state='verification', no_live_producer_claimed=True, current_repair_owner='/root',
                   current_status_scope='Epoch 170 committed locally and awaits verification and public delivery.',
                   next_action='Verify and publish the retained epoch 170 archive.')
    if c.failed170:
        fleet[FAILED_STATUS] = c.failed170
        row = next(v for v in fleet['epochs'] if v['epoch'] == 170)
        previous = row.pop('current_home_floor_stop', row.get('original_home_floor_stop'))
        need(previous['completion']['sha256'] == STOP, 'lost stopped predecessor of failed cold170')
        row.update(original_home_floor_stop=previous, cold170_retry13_execution_failure=c.failed170,
                   state='verification', no_live_producer_claimed=True, current_repair_owner='/root', repair_open=True,
                   current_status_scope='Epoch 170 retry13 exited after a historical execution mismatch.',
                   next_action='Diagnose the exact failed transaction and qualify bounded checkpoint replay.')
    fleet['useful_replay_count'] = cold167.counts(c)['current_replay_lanes']
    stops = {166: retry166.STOP, 167: cold167.STOP_SHA, 170: STOP}
    if cold168:
        stops[168] = cold168.STOP
    for epoch in c.new_rows:
        row = next(v for v in fleet['epochs'] if v['epoch'] == epoch)
        original = row.pop('current_home_floor_stop', row.get('original_home_floor_stop'))
        need(original['completion']['sha256'] == stops[epoch], 'original cold guard stop lost')
        row['original_home_floor_stop'] = original
        row['next_action'] = 'Maintain the admitted worker and verify its resulting archive.'
