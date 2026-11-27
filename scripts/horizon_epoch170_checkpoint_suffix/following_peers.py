"""Reprice the fourth 170 window with the split actors enrolled by the same writer."""

from hashlib import sha256
import os
from pathlib import Path
import runpy
import stat
import time

G = 1 << 30
M = 1 << 20
RT = Path('/var/lib/jetstreamer/horizon_runtime_data')
PARENT = RT / 'epoch169-hourly-admission-20261123-v1'
ISSUED = PARENT / 'issued-split-v1'
SEAL169 = 'dd9873bf96f7ad3eddc20c52540f5d72087fd3287e1fadfbe62f6183f68c3796'
GRANT169 = 'be995ac49dab5db580957c3a45a659c7399db404b6bfa2f8453bd72b7ea5e5cd'
V48 = '9ca6211354be131c738c83edb2aaf4d0439423455d7dffca7950f76e84c32eb6'


def package_home():
    new_170 = RT/'epoch170-from-73766969-20261127-v1'
    price = RT/'epoch162-first-hourly-completion-20261127-v2'
    dirs = [price/'issued-price-v1', price/'issued-price-v2',
            new_170/'operator-v4', new_170/'closed-reader-v3', new_170/'progress-v4',
            RT/'survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v49-entry146',
            RT/'epoch143-first-hourly-20261127-v1/booking-price-v49']
    total = 0
    for directory in dirs:
        if not directory.exists():
            continue
        st = directory.lstat()
        if directory.resolve() != directory or not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('untrusted package directory ' + str(directory))
        total += st.st_blocks * 512
        for p in directory.iterdir():
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode) or p.resolve() != p or st.st_uid != 0 or st.st_mode & 0o222:
                raise ValueError('untrusted package member ' + str(p))
            total += max(st.st_blocks*512, (st.st_size+4095)//4096*4096)
    return total


def current_writer(core, provider):
    directory = RT/'survivor172-cadence-20261122-v1'
    original, reference = core.read(directory/'FAILED166_CADENCE_V48_ACTIVE.json', V48)
    owner = original['new']
    next_file = directory/'FAILED166_CADENCE_V49_ACTIVE.json'
    active = original
    if next_file.exists():
        active, next_ref = core.read(next_file)
        ready = core.bound(active['ready'])
        core.need(ready['old_owner'] == reference and active['old'] == owner and
                  all(active['new']['lock'][k] == owner['lock'][k] for k in ('path','device','inode'))
                  and active['new']['unit'] == owner['unit'], 'V49 did not inherit V48')
        owner, reference = active['new'], next_ref
    ready = core.bound(active['ready'])
    program = Path(owner['program'])
    pkg = core.bound(ready['package'])
    member, = [m for m in pkg['members'] if m['name'] == 'status_cycle.py']
    st = program.lstat()
    core.need(program.name == member['name'] and program.parent.parent == directory
              and ready['package']['path'] == str(program.parent/'deployment-seal-receipt.json')
              and pkg['destination'] == str(program.parent) and program.resolve() == program
              and stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o222
              and sha256(program.read_bytes()).hexdigest() == member['sha256']
              and ready['split169_provider'] == provider
              and ready['split162_provider']['sha256'] == 'ca5ac887bdb0ca18b607966df05e890dbbc0ba3f73fb1112c4717ab97dc9415e'
              and not active['producer_mutations'], 'writer changed its split interfaces')
    state = core.state(owner['unit'])
    process = Path('/proc')/str(owner['pid'])
    lock = (process/'fd'/str(owner['lock']['fd'])).stat()
    core.need(state['ActiveState']=='active' and not state['Job'] and state['MainPID']==str(owner['pid'])
              and state['InvocationID']==owner['invocation_id'] and os.fsencode(program) in (process/'cmdline').read_bytes().split(b'\0')
              and int((process/'stat').read_text().rsplit(') ',1)[1].split()[19]) == owner['start_ticks']
              and (lock.st_dev,lock.st_ino) == (owner['lock']['device'],owner['lock']['inode']),
              'different writer process or cadence lock')
    return reference


def snapshot(core):
    seal, sr = core.read(ISSUED/'deployment-seal-receipt.json', SEAL169)
    core.need(seal['destination'] == str(ISSUED), '169 provider moved')
    for member in seal['members']:
        p = ISSUED / member['name']
        s = p.lstat()
        core.need(p.parent == ISSUED and p.resolve() == p and stat.S_ISREG(s.st_mode) and
                  not s.st_mode & 0o222 and s.st_nlink == 1 and s.st_uid == 0 and s.st_size == member['bytes'],
                  'unsealed 169 member')
        core.need(sha256(p.read_bytes()).hexdigest() == member['sha256'], '169 code changed')
    other = runpy.run_path(str(ISSUED/'split_operator.py'))
    price = other['capacity']
    peer169 = price['actor']
    peer162 = runpy.run_path(str(ISSUED/'peer162.py'))
    fleet, fref = core.current_fleet()
    writer = current_writer(core,sr)
    core.need(price['seal']() == sr, '169 enrollment changed')
    a = peer169['current'](fleet)
    b = peer162['current'](fleet)
    core.need(a is not None, 'issued 169 actor lost its terminal or live identity')
    grant, gr = core.read(PARENT/'GRANT.json', GRANT169)
    post, pr = core.read(PARENT/'POST_GUARD_CAPACITY.json', grant['native_post_guard_price_sha256'])
    lineage = post['accounting']['old_six_owner_lineage']
    start = a['hourly169_start_intent']
    iid = a['invocation_id'] if a['phase']=='terminal' else a['unit']['InvocationID']
    core.need(grant['invocation_id'] == iid == post['actor']['unit']['InvocationID']
              and post['actor']['phase'] == 'held' and post['actor']['hourly169_start_intent'] == start
              and not grant['canonical_publication_authorized'] and post['fits'] and post['provider'] == sr
              and lineage['same_169_compute'] and lineage['static_169_memory'] == 69*G
              and lineage['static_169_cpu'] == 4_000_000 and not post['resource_credit_bytes'],
              'unfunded new 169')
    return dict(fleet=fref, paid169=price['resident'](a), row169=a, row162=b, writer=writer,
                provider=sr, grant=gr, post=pr, observed=time.time()), (other, peer169, peer162)


def peer_disk(row, absent_maximum):
    if not row or row['phase'] == 'terminal':
        return 0, absent_maximum, 64*M if row or absent_maximum else 0
    plan = row['disk']
    if not (0 <= plan['remaining'] <= 8*G and plan['fixed_control'] == 64*M):
        raise ValueError('invalid guarded split output')
    return plan['floor'], plan['remaining'], plan['fixed_control']


def amounts(quote, disks, booked_home, booked_ram, paid_ram):
    """The fixed guard floors remain in force while either peer can grow its private output."""
    if 'split_peers' in quote:
        raise ValueError('duplicate split-peer charge')
    floor = max(quote['guard_floor'] + booked_home + sum(d[2] for d in disks),
                *(d[0] for d in disks)) + sum(d[1] for d in disks)
    extra = floor - quote['guard_floor']
    required = quote['required_home'] + extra
    historical = quote['historical_home_margin'] - extra
    home = min(quote['available_home'] - required, historical)
    ram = quote['ram_margin'] - booked_ram + paid_ram
    tree_ok = quote['phase'] == 'read' or quote['terminal_tree_bounds'][1] + quote['candidate_170_growth_bytes'] <= 384*G
    return dict(guard_floor=floor, required_home=required, home_margin=home, historical_home_margin=historical,
                required_ram=quote['available_ram'] - ram, ram_margin=ram, fits=home >= 0 and ram >= 0 and tree_ok)


def finish(core, quote, first, providers):
    other, peer169, peer162 = providers
    fleet, fref = core.current_fleet()
    core.need(first['fleet'] == fref == quote['fleet'], 'fleet changed during fourth-window price')
    post = core.bound(first['post'])
    reference = post['native']['raw']['joint']
    joint = quote['joint']
    paid = post['accounting']
    core.need(all(joint[k] == reference[k] for k in ('interface','charged_167','return140','booking140','loan140',
                                                      'producer_allowance','guard_sibling_allowance','producer_quota_micros'))
              and joint['required_ram'] + joint['resident_lower_bytes'] >= paid['old_six_owner_lineage']['bounded_167_base']
              and not quote['resource_credit_bytes'] and not joint['resource_credit_bytes']
              and quote['private_verification168']['armed'] == paid['verification168_listener']['armed']
              and quote['private_verification168']['additional_home'] == paid['verification168_listener']['additional_home']
              and quote['shared_slot']['repeated_serial_bytes'] == 2*G
              and quote['compiler_recovery']['maximum_memory'] == paid['recovery']['maximum_memory'],
              'fourth 170 no longer inherits the funded six-owner price')
    a, b = first['row169'], first['row162']
    peer169['recheck'](fleet, a)
    a2 = peer169['current'](fleet)
    b2 = peer162['recheck'](fleet, b)
    live_ram = min(first['paid169'], other['capacity']['resident'](a2))
    if b and b['phase'] != 'terminal':
        live_ram += min(b['realized_ram'], b2['realized_ram'])
    disks = []
    for earlier, later, idle_output in ((a,a2,8*G), (b,b2,8*G if b else 0)):
        pair = zip(peer_disk(earlier, idle_output), peer_disk(later, idle_output))
        disks.append(tuple(max(x,y) for x,y in pair))
    # Keep the 168 verification outside bytes already present in quote. Pay V47
    # and V48 packages, the retained 170 input and capture once on this route.
    writer = core.bound(paid['funding_V47'])
    expected_fixed = writer['bookings']['extra_output_bytes'] + writer['additional_home_bytes']
    expected_fixed += paid['writer_overhead'] + quote['private_verification168']['additional_home']
    current_custody = quote['following_custody']
    if quote['phase'] != 'read':
        current_custody = core.bound(current_custody)['custody']
    core.need(writer['fits'] and paid['fixed_HOME'] == expected_fixed
              and paid['input170']['custody'] == current_custody == paid['terminal_ram']['issued_input']
              and paid['input170']['additional_home'] == paid['terminal_ram']['retained_input_home'],
              'different V47/V48 package or issued input budget')
    booked_home = paid['fixed_HOME'] - paid['verification168_listener']['additional_home']
    booked_home += paid['recorder170']['retained_evidence'] + paid['input170']['additional_home']
    # The 4 GiB image and 16 MiB of 168 evidence are already in the base. The
    # issued 170 copier has drained. Its source and packages remain occupied.
    booked_ram = writer['additional_RAM_bytes'] + paid['recorder170']['witness_ram']
    core.need(0 <= quote['input_allocation_after_fleet'] <= paid['input170']['additional_home']
              and paid['terminal_ram']['concluded_copier_ram'] == G and not paid['input170']['active']
              and booked_home > 0 and booked_ram == 256*M, 'different recorder, compact writer, or input funding')
    newer_home = package_home()
    booked_home += newer_home
    change = amounts(quote, disks, booked_home, booked_ram, live_ram)
    peer169['recheck'](fleet, a)
    peer162['recheck'](fleet, b)
    core.need(current_writer(core,first['provider']) == first['writer'] and core.current_fleet()[1] == fref, 'writer or fleet changed')
    return quote | change | dict(split_peers=dict(before=first, after169=a2, after162=b2,
                reserved_disks=disks, additional_fixed_home=booked_home, additional_fixed_ram=booked_ram,
                newer_packages_HOME=newer_home, realized_split_RAM=live_ram))
