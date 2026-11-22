"""Bind the cold epoch 170 producer to its stopped 384 GiB booking and read-only inputs."""
import hashlib
from pathlib import Path
import stat

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
LANE = Path('/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1')
PREVIOUS_RUN = LANE / 'replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1'
RUN = PREVIOUS_RUN / 'cold-retry11-20261122'
NAME = '170-replacement-local3retry11-20261122'
DIRECTORY = 'epoch170-retry11-rebook-20261122-v1'
NEW = R / DIRECTORY
OLD = R / 'epoch170-retry10-recovery-20261121-v1'
CLEAN = R / 'epoch170-closed-accounts-20261122-v1'
GUARD = R / 'epoch170-retry11-guard-20261122-v1'
PRIOR_IID = 'a456b826ce1c4634a2df66d66c5cc07f'
PRIOR_UNIT = 'horizon-qualify-170-replacement-local3retry10-20261121-v1.service'
STOP_SHA = 'd670ce226f7ee5e24660dbd99b2d8174d72cd38f39487d10b17bcc4c0a85d50a'
ROOT_SHA = '8420a1b00afa2d643a24e36c5b12c82fdd0b43d5238c9045c0c0c53097021728'
RETURN_SHA = 'c9cf86c9b00d3403e715c14e7af22ea8162e105a222c1d8b9b79be190e97865d'
SCOPES_SHA = '989f450ba2bea735593b0278ff996ff877d7984439da48522198421dd5249025'
OLD_PROFILE_SHA = '1596f281f699b48f4e4c7e65adf1070e4961d604d38997a7747ffe60dc536782'
CAP = 384 << 30


def stable(s):
    root, source = s.read(NEW / 'SUCCESSOR_ROOT.json', ROOT_SHA)
    returned, proof = s.read(CLEAN / 'TWO_SCOPES_RETIRED.json', RETURN_SHA)
    profiles, _ = s.read(CLEAN / 'tools/profiles170.json', SCOPES_SHA)
    st = RUN.lstat()
    s.need(RUN.resolve(strict=True) == RUN and root['root'] == str(RUN) and root['parent'] == str(PREVIOUS_RUN)
           and (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode) ==
           (root['device'], root['inode'], root['uid'], root['gid'], root['mode']) ==
           (64512, 113704962, 1001, 1003, 0o40700)
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
    return dict(stable_root=source, cleanup=proof, original_cap=CAP, resource_credit_bytes=0)


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
           and intent['stable_root'] == b['root'] == {'path':str(RUN),'device':64512,'inode':113704962},
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
    qualified, _ = s.read(GUARD / 'GUARD_QUALIFIED.json', '36d057cd24d412190ca41f2d910969a1b37fd175cab51ab8c00bd61f6826416d')
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
    stable(s)
    stopped, ref = s.read(OLD / 'guard-receipts/stop-completion.json', STOP_SHA)
    s.need(stopped['producer_invocation_id'] == PRIOR_IID and stopped['terminal']['active'] == 'inactive'
           and stopped['terminal']['pid'] == 0 and s.show(PRIOR_UNIT)['ActiveState'] == 'inactive'
           and not fit.members(PRIOR_UNIT), 'prior 170 owner returned')
    predecessor = {'original': {'producer_invocation_id': PRIOR_IID}, 'stop_completion': ref}
    return native_actor(170, own, LANE, RUN, predecessor, generation=(DIRECTORY, NAME))
