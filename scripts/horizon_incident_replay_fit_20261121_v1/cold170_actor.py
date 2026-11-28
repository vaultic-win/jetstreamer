"""Bind the cold epoch 170 producer to its stopped 384 GiB booking and read-only inputs."""
import hashlib
from pathlib import Path
import stat

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
LANE = Path('/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1')
PREVIOUS_RUN = LANE / 'replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1'
RETRY13 = globals().get('RETRY13', False)
ATTEMPT = 13 if RETRY13 else 12 if RETRY12 else 11
RUN = PREVIOUS_RUN / f'cold-retry{ATTEMPT}-20261122'
NAME = f'170-replacement-local3retry{ATTEMPT}-20261122'
DIRECTORY = f'epoch170-retry{ATTEMPT}-rebook-20261122-v1'
NEW = R / DIRECTORY
OLD = R / 'epoch170-retry10-recovery-20261121-v1'
CLEAN = R / 'epoch170-closed-accounts-20261122-v1'
GUARD = R / f'epoch170-retry{ATTEMPT}-guard-20261122-v1'
PRIOR_IID = 'a456b826ce1c4634a2df66d66c5cc07f'
PRIOR_UNIT = 'horizon-qualify-170-replacement-local3retry10-20261121-v1.service'
STOP_SHA = 'd670ce226f7ee5e24660dbd99b2d8174d72cd38f39487d10b17bcc4c0a85d50a'
ROOT_SHA = ('654e6612f8ce9ee2f9f5c9f172f79f9ce5da4b0f6f02443c856f3a5228a5ca69' if RETRY13 else
            '466f48f20716b258189e242eef4d4e2e54fbf6202e6ecd4ff008eb3dd0d10b19' if RETRY12 else
            '8420a1b00afa2d643a24e36c5b12c82fdd0b43d5238c9045c0c0c53097021728')
ROOT_INODE = {11: 113704962, 12: 113836033, 13: 113981945}[ATTEMPT]
GUARD_SHA = ('34ee106fc4dd290e8ad447f1ff5ab15cfe538b7ca522785a87df106566e0645c' if RETRY13 else
             '7ed9e4bffff3cdaad1bd8d0eda700c3b107e85a4b585bb067e4eca50bbab123c' if RETRY12 else
             '36d057cd24d412190ca41f2d910969a1b37fd175cab51ab8c00bd61f6826416d')
FAILED = R / 'epoch170-retry11-rebook-20261122-v1'
FAILURE_SHA = '60b0ff3a1b09b8c684fdf07ff300ddaebb89b4c80581a9b475a057a2d6aee801'
FAILED_IID = '7a9f41a86d9240be89e3484fc01c3a31'
FAILED_UNIT = 'horizon-qualify-170-replacement-local3retry11-20261122.service'
FAILED_GUARD = 'horizon-guard-170-replacement-local3retry11-20261122'
RETURN_SHA = 'c9cf86c9b00d3403e715c14e7af22ea8162e105a222c1d8b9b79be190e97865d'
SCOPES_SHA = '989f450ba2bea735593b0278ff996ff877d7984439da48522198421dd5249025'
OLD_PROFILE_SHA = '1596f281f699b48f4e4c7e65adf1070e4961d604d38997a7747ffe60dc536782'
CAP = 384 << 30


PREVIOUS_FAILURES = [
    (FAILED, FAILURE_SHA, FAILED_IID, FAILED_UNIT, FAILED_GUARD,
     '9afecd75bf867464a8c41cbab5819a481d530da394a039d9c7c00c97317fe439'),
]
if RETRY13:
    PREVIOUS_FAILURES.append((R / 'epoch170-retry12-rebook-20261122-v1',
        'ff337e45c1f4a3af3e0f44654a80ee00ffef2c9405ddc27e16c6883611a53151',
        'f26354f4e63748059e441cbbee250fdb', 'horizon-qualify-170-replacement-local3retry12-20261122.service',
        'horizon-guard-170-replacement-local3retry12-20261122',
        'b3d5c6a79b5122083732999ab54ac89ec650c752de596f337f8cab699c60f735'))


def stable(s):
    root, source = s.read(NEW / 'SUCCESSOR_ROOT.json', ROOT_SHA)
    returned, proof = s.read(CLEAN / 'TWO_SCOPES_RETIRED.json', RETURN_SHA)
    profiles, _ = s.read(CLEAN / 'tools/profiles170.json', SCOPES_SHA)
    st = RUN.lstat()
    s.need(RUN.resolve(strict=True) == RUN and root['root'] == str(RUN) and root['parent'] == str(PREVIOUS_RUN)
           and (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode) ==
           (root['device'], root['inode'], root['uid'], root['gid'], root['mode']) ==
           (64512, ROOT_INODE, 1001, 1003, 0o40700)
           and root['worker_launched'] is False and returned['original_cap'] == CAP
           and returned['free_space_credit_bytes'] == 0, 'different 170 successor root or original cap')
    release = 0
    for attempt, ref in returned['docs'].items():
        v = s.bound(ref, CLEAN / 'state' / attempt / 'COMPLETE.json')
        enrolled = profiles['profiles'][attempt]
        target = Path(v['scope'])
        t = target.lstat()
        s.need(v['scope_empty'] and v['attempt'] == attempt and v['original_iid'] == enrolled['iid']
               and v['archive_or_snapshot_removed'] is False and v['resource_credit_bytes'] == 0
               and target == Path(enrolled['target']) and target.resolve(strict=True) == target
               and t.st_dev == 64512 and t.st_ino == enrolled['inode'] and not any(target.iterdir())
               and v['retired_tree_before_bytes'] == enrolled['expected_bytes']
               and v['scope_root_remaining_bytes'] == t.st_blocks * 512, '170 AccountsDb changed after cleanup')
        release += v['retired_tree_before_bytes'] - v['scope_root_remaining_bytes']
    s.need(set(returned['docs']) == {'local3retry9','local3retry10'}
           and release == returned['actual_retired_allocated_bytes'] == 120971882496,
           'incomplete 170 physical cleanup')
    result = dict(stable_root=source, cleanup=proof, original_cap=CAP, resource_credit_bytes=0)
    if RETRY12:
        for directory, failure_sha, iid, unit, _, actor_sha in PREVIOUS_FAILURES:
            failure, fr = s.read(directory / 'START_FAILURE.json', failure_sha)
            intent = s.bound(failure['intent'], directory / 'START_INTENT.json')
            actor, _ = s.read(directory / 'ACTUAL_PRODUCER_NATIVE.json', actor_sha)
            s.need(failure['cgroup'] == [] and failure['partial_retained']
                   and failure['producer_invocation_id'] == actor['producer_invocation_id'] == iid
                   and intent['producer_unit'] == actor['producer_unit'] == unit
                   and not (directory / 'ACTUAL_ADMISSION_AND_PROTECTION.json').exists(),
                   'different unadmitted 170 failure')
        s.need(root['previous_start_failure'] == fr, 'unbound most recent 170 failure')
        result['previous_start_failure'] = fr
    return result


def checked_input(s, stored, source):
    m = source.lstat()
    s.need(source.resolve(strict=True) == source and stat.S_ISREG(m.st_mode) and m.st_nlink == 1
           and (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns) ==
           tuple(stored[k] for k in ('device','inode','size','mtime_ns','ctime_ns'))
           and (m.st_uid, m.st_gid, m.st_mode) == tuple(stored[k] for k in ('uid','gid','mode')),
           'different retained 170 input: ' + str(source))


def mounted_inputs(s, prepared, intent, proc, readonly_mounts):
    origin, _ = s.read(OLD / 'profile.json', OLD_PROFILE_SHA)
    enrolled, _ = s.read(CLEAN / 'tools/profiles170.json', SCOPES_SHA)
    b = prepared['baseline']
    p = prepared['profile']
    s.need(b['profile'] == p and p['indexes'] == prepared['indexes']
           and intent['stable_root'] == b['root'] == {'path':str(RUN),'device':64512,'inode':ROOT_INODE},
           'unbound 170 prepared generation or stable root')
    pairs = {}
    for prior, expected, now in zip(origin['projections'][1:], enrolled['indexes'], p['indexes'], strict=True):
        source = Path(prior['source'])
        dest = RUN / Path(prior['target']).relative_to(PREVIOUS_RUN)
        checked_input(s, expected, source)
        s.need(source == Path(expected['path']) and now['path'] == str(source) and now['target'] == str(dest)
               and now['identity'] == prior['identity'] and now['sha256'] == prior['sha256'] == expected['sha256'],
               'foreign 170 compact index')
        pairs[dest] = source
    bootstrap = enrolled['profiles']['local3retry10']['preserved'][1]
    snapshot = b['snapshot']
    src = Path(bootstrap['path'])
    checked_input(s, bootstrap, src)
    s.need(snapshot['path'] == str(src) and snapshot['sha256'] == origin['bootstrap']['sha256']
           and snapshot['device'] == bootstrap['device'] and snapshot['inode'] == bootstrap['inode']
           and snapshot['length'] == bootstrap['size'] and snapshot['generation'] == 1634787467305970,
           'foreign 170 bootstrap generation')
    genesis = origin['projections'][0]
    pairs[RUN / 'output/genesis.tar.bz2'] = Path(genesis['source'])
    pairs[Path(origin['bootstrap']['path'])] = src
    s.need(len(pairs) == 5, 'missing 170 source mounts')
    readonly_mounts(s, proc, pairs)


def guard(s, prepared):
    qualified, _ = s.read(GUARD / 'GUARD_QUALIFIED.json', GUARD_SHA)
    image = GUARD / 'tools/guard'
    digest = prepared['profile']['guard_binary_sha256']
    seal = s.bound(qualified['seal'], image.parent / 'deployment-seal-receipt.json')
    contract = qualified['contract']
    terms = s.bound(contract['contract'], GUARD / 'contract/contract.json')
    s.bound(contract['deployment_seal'], GUARD / 'contract/deployment-seal-receipt.json')
    witness = s.bound(terms['qualified_native_witness'], GUARD / 'NATIVE_WITNESS.json')
    s.need(qualified['guard'] == dict(path=str(image), sha256=digest) and seal['destination'] == str(image.parent)
           and any(x['name'] == 'guard' and x['sha256'] == digest for x in seal['members'])
           and witness['native_identity']['executable'] == str(image) and witness['native_identity']['executable_sha256'] == digest
           and hashlib.sha256(image.read_bytes()).hexdigest() == digest, 'foreign 170 native guard image')
    return digest, contract


def observe(s, fit, native_actor, own):
    state = stable(s)
    if RETRY12:
        for _, _, _, failed_unit, failed_guard, _ in PREVIOUS_FAILURES:
            for unit in (failed_unit, failed_guard + '.service', failed_guard + '.timer'):
                manager = s.show(unit)
                s.need(manager['ActiveState'] == 'inactive' and not manager['Job'] and
                       (unit.endswith('.timer') or not fit.members(unit)), 'failed 170 generation returned')
    stopped, ref = s.read(OLD / 'guard-receipts/stop-completion.json', STOP_SHA)
    s.need(stopped['producer_invocation_id'] == PRIOR_IID and stopped['terminal']['active'] == 'inactive'
           and stopped['terminal']['pid'] == 0 and s.show(PRIOR_UNIT)['ActiveState'] == 'inactive'
           and not fit.members(PRIOR_UNIT), 'prior 170 owner returned')
    predecessor = {'original': {'producer_invocation_id': PRIOR_IID}, 'stop_completion': ref}
    row = native_actor(170, own, LANE, RUN, predecessor, generation=(DIRECTORY, NAME))
    if row is not None and RETRY12:
        prepared, _ = s.read(NEW / 'PREPARED.json')
        s.need(all(row['producer_invocation_id'] != item[2] for item in PREVIOUS_FAILURES)
               and prepared['baseline']['previous_cold_failure'] ==
               state['previous_start_failure'], 'different 170 retry12 predecessor')
    return row


def fund_prestart(s, price, retained, budget, registered_floor, *, cold168_profile=False, raw_with_retained168=None):
    """Price an unstarted epoch against the occupied bytes guaranteed by inactive peer siblings."""
    epoch = price['epoch']
    peers = price['survivors']
    charged = price['bookings']
    expected = {167, 170} if epoch == 166 else {167}
    if cold168_profile:
        s.need(epoch in (166, 168), 'wrong fifth-lane candidate')
        expected = {167, 170}
        other = 166 if epoch == 168 else 168
        if str(other) in price['replacements']:
            expected.add(other)
    s.need(epoch in (166, 168, 170) and price['candidate'] is None and set(retained) == expected
           and all(str(peer) in price['replacements'] for peer in expected)
           and '172' in peers, 'unexpected candidate or peers for nonexact startup price')
    guard172 = peers['172']['guard']
    paid172 = guard172['cap'] - guard172['remaining']
    s.need(0 <= paid172 <= guard172['cap'] == 288 << 30, 'invalid current occupancy for 172')
    books = dict(charged)
    for peer in sorted(retained):
        key = str(peer)
        book = charged[key]
        cap = {166: 288 << 30, 167: 512 << 30, 168: 288 << 30, 170: 384 << 30}[peer]
        s.need(0 < retained[peer] <= book['physical_bytes'] <= book['cap_bytes'] == cap,
               f'invalid current occupancy for {peer}')
        books[key] = dict(book, physical_bytes=retained[peer], remaining_bytes=cap - retained[peer])
    charged_peers = dict(peers, **{'172': dict(peers['172'], guard=dict(guard172, remaining=guard172['cap']))})
    # The original 172 host equation adds its remaining allowance once, after
    # the maximum of incumbent guard floors. Replacing occupancy with zero
    # adds exactly paid172 to that aggregate. disk_budget computes the rest.
    original_raw = price['original_aggregate_HOME_bytes']
    if 168 in retained:
        s.need(cold168_profile and raw_with_retained168 is not None and raw_with_retained168 >= original_raw,
               'missing full host reprice for retained 168')
        original_raw = raw_with_retained168
    raw = original_raw + paid172
    candidate136 = price['candidate136']
    actors = price['replacements']
    def evaluate(candidate, epoch):
        return budget(raw, candidate, books, epoch, charged_peers, actors,
                      price['active168_guard_floor'], price['closed_prestart_remaining'])
    required, protected, _ = evaluate(candidate136, epoch)
    zero, _, _ = evaluate(dict(remaining=0), 145)
    obligations = price['recovery_obligations']
    growth = obligations['prefix']['remaining_DATA_growth_bytes']
    total = max(required + growth, registered_floor(0, zero, candidate136, growth)) + obligations['missing_mirror_bytes']
    if price['bounded_qualification']:
        total += price['bounded_qualification']['scratch_bytes']
    worst = protected + total - required
    original_floor = price['protected_raw_floor_bytes']
    original_required = price['complete_required_HOME_bytes']
    headroom = price['available_HOME_bytes'] - original_required
    exposure = worst - original_floor
    candidate = books[str(epoch)]
    s.need(total == worst + candidate['remaining_bytes'] and exposure == total - original_required
           and exposure >= 0, 'peer fallback did not preserve the complete candidate booking')
    details = dict(schema=f'horizon-{epoch}-nonexact-peer-prestart-v1', ordinary_protected_raw_floor_bytes=original_floor,
                   ordinary_required_HOME_bytes=original_required, protected_raw_floor_bytes=worst,
                   complete_required_HOME_bytes=total, allowance_needed=exposure, initial_headroom_bytes=headroom,
                   funded=exposure <= headroom, retained167_bytes=retained[167],
                   occupied172_credit_bytes=0, full172_cap_bytes=guard172['cap'],
                   candidate_remaining_bytes=candidate['remaining_bytes'], guard172=guard172['guard'])
    if cold168_profile:
        details.update(retained_peer_bytes={str(k):v for k,v in retained.items()},
                       peer_guards={str(k):actors[str(k)]['guard'] for k in retained})
    if epoch == 166:
        details.update(retained170_bytes=retained[170], candidate_cap_bytes=candidate['cap_bytes'],
                       peer_167_guard=actors['167']['guard'], peer_170_guard=actors['170']['guard'])
    price.update(protected_raw_floor_bytes=worst, complete_required_HOME_bytes=total,
                 startup_nonexact_peer_floor=details, fits=bool(price['fits'] and details['funded']))
