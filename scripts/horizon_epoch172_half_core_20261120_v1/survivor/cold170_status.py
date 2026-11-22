"""Observe the funded 170 retry and keep 166 when it joins the same cadence."""
from pathlib import Path
import stat

import cold166_status as retry166
import cold167_status as cold167
from evidence import BASE, bound, checked, need

ROOT = BASE / 'epoch170-retry11-rebook-20261122-v1'
GUARD = BASE / 'epoch170-retry11-guard-20261122-v1'
NAME = '170-replacement-local3retry11-20261122'
UNIT = 'horizon-qualify-' + NAME + '.service'
TIMER = 'horizon-guard-' + NAME + '.timer'
RUN = Path('/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/cold-retry11-20261122')
STOP = 'd670ce226f7ee5e24660dbd99b2d8174d72cd38f39487d10b17bcc4c0a85d50a'
FIELD = 'current_homefloor_cold166_167_170_owners'
BINDING = Path(__file__).resolve().with_name('retry11-170-generation.json')


def generation():
    binding = checked(bound(BINDING))
    anchor, witness = binding['successor_root'], binding['guard_qualification']
    need(anchor == dict(path=str(ROOT/'SUCCESSOR_ROOT.json'), sha256='8420a1b00afa2d643a24e36c5b12c82fdd0b43d5238c9045c0c0c53097021728')
         and witness == dict(path=str(GUARD/'GUARD_QUALIFIED.json'), sha256='36d057cd24d412190ca41f2d910969a1b37fd175cab51ab8c00bd61f6826416d'),
         'foreign 170 enrollment')
    original, proof = checked(anchor), checked(witness)
    meta = RUN.lstat()
    identity = dict(path=str(RUN), device=meta.st_dev, inode=meta.st_ino)
    need((original['root'], original['device'], original['inode']) == (str(RUN), 64512, 113704962)
         and (meta.st_dev, meta.st_ino) == (64512, 113704962) and RUN.resolve(strict=True) == RUN
         and (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode)) == (1001, 1003, 0o700), '170 enrollment root changed')
    need(proof['schema'] == 'horizon-170-retry11-native-guard-qualified-v1' and not proof['physical_launch']
         and proof['guard'] == bound(GUARD/'tools/guard') and proof['seal'] == bound(GUARD/'tools/deployment-seal-receipt.json'),
         'different 170 guard')
    seal = checked(proof['seal'])
    member, = (m for m in seal['members'] if m['name'] == 'guard')
    need(seal['destination'] == str(GUARD/'tools') and member['sha256'] == proof['guard']['sha256'], 'wrong 170 guard seal')
    for ref in proof['contract'].values():
        checked(ref)
    return anchor, identity, proof


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
    return module


def check_generation(fleet_ref, fleet, state):
    unit, actor = state
    anchor, identity, _ = generation()
    prepared = bound(ROOT/'PREPARED.json')
    registration = checked(prepared)
    # The native session can carry the root identity inline or by immutable receipt.
    baseline = registration.get('baseline',registration)
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
    if row['range'] != '170':
        return retry166.projection(row)
    first = checked(bound(ROOT/'FIRST_PROTECTED_WORKER.json'))
    need(first['admission'] == bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json') and row == first['observer_row']
         and row['producer_unit'] == row['controller_unit'] == UNIT and
         row['expected_producer_invocation_id'] == row['expected_controller_invocation_id'] == first['producer_invocation_id'],
         'different 170 worker projection')


def roster(module, fleet_ref, fleet):
    checks = {166: retry166.check_generation, 167: cold167.check_generation, 170: check_generation}
    enrolled = set()
    for epoch, check in checks.items():
        state = module.native(epoch)
        if state is None:
            need(epoch == 166 and not (retry166.ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json').exists()
                 and '166' not in fleet.get(FIELD, {}) and '166' not in fleet.get(retry166.FIELD, {}),
                 'missing admitted cold worker '+str(epoch))
            continue
        check(fleet_ref, fleet, state)
        enrolled.add(epoch)
    return enrolled


def reconcile(c, observed_lane):
    module = reader()
    c.commits = {}
    c.histories = {}
    enrolled = roster(module, c.fleet_ref, c.fleet)
    c.next_cfg['replays'] = [row for row in c.next_cfg['replays'] if int(row['range']) not in enrolled]
    module.sample_rows(c, observed_lane)
    need(set(c.new_rows) == enrolled and set(c.recovered_owners) == {str(e) for e in enrolled}, 'cold roster changed during capture')
    for epoch in enrolled:
        key = str(epoch)
        for field in (cold167.FIELD, retry166.FIELD, FIELD):
            prior = c.fleet.get(field, {}).get(key)
            if prior:
                need(prior['actor'] == c.recovered_owners[key]['actor'], 'cold owner changed')
        projection(c.new_rows[epoch]['observer_config'])


def install(c, fleet):
    reader().install(fleet, c)
    capture = fleet.pop('recovered_workers_observation')
    fleet['current_homefloor_cold166_167_170_observation'] = capture
    fleet[cold167.FIELD] = {'167': c.recovered_owners['167']}
    fleet['current_homefloor_cold167_observation'] = capture
    if 166 in c.new_rows:
        fleet[retry166.FIELD] = {key: c.recovered_owners[key] for key in ('166', '167')}
        fleet['current_homefloor_cold166_167_observation'] = capture
    fleet['useful_replay_count'] = cold167.counts(c)['current_replay_lanes']
    stops = {166: retry166.STOP, 167: cold167.STOP_SHA, 170: STOP}
    for epoch in c.new_rows:
        row = next(v for v in fleet['epochs'] if v['epoch'] == epoch)
        original = row.pop('current_home_floor_stop', row.get('original_home_floor_stop'))
        need(original['completion']['sha256'] == stops[epoch], 'original cold guard stop lost')
        row['original_home_floor_stop'] = original
        row['next_action'] = 'Maintain the admitted worker and verify its resulting archive.'
