"""Price the private 162 interval under the fleet lock already held by its issuer."""

from hashlib import sha256
import os
from pathlib import Path
import runpy
import stat
import subprocess
import time


RT = Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT = RT / 'epoch162-first-hourly-completion-20261127-v2'
DIRECTORY169 = RT / 'epoch169-hourly-admission-20261123-v1/issued-split-v1'
SELF = ROOT / 'issued-price-v1/capacity.py'
PEER_DIGEST = 'cf69f9a999c4b5ae81ca6d32bd215578164751291e6cde66261ee0b5b18547d0'
OPERATOR_DIGEST = 'ca5ac887bdb0ca18b607966df05e890dbbc0ba3f73fb1112c4717ab97dc9415e'
G = 1 << 30
M = 1 << 20
BOOT = Path('/proc/sys/kernel/random/boot_id')
CONTROLLERS199 = ('horizon-199200-joint-cached-controller-20261121-v1.service',
                  'horizon-qualify-199200-reservation-20261121-v1.service')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def immutable(path, digest):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_nlink == 1 and not st.st_mode & 0o222, 'unsealed program ' + str(path))
    need(sha256(path.read_bytes()).hexdigest() == digest, 'different program ' + str(path))


def software(peer, enrollment):
    spec = peer['bound'](enrollment)
    need(enrollment['path'] == str(peer['ENROLL']) and spec['donor'] == peer['DONOR']
         and spec['operator'] == dict(path=str(peer['PACKAGE']/'deployment-seal-receipt.json'), sha256=OPERATOR_DIGEST)
         and spec['capacity']['path'] == str(SELF), 'different 162 enrollment')
    immutable(SELF, spec['capacity']['sha256'])
    status, _ = peer['package'](spec)
    ready = peer['bound'](peer['bound'](spec['writer_active'])['ready'])
    other = ready['split169_provider']
    need(other['path'] == str(DIRECTORY169/'deployment-seal-receipt.json'), 'different 169 directory')
    seal = peer['bound'](other)
    immutable(Path(other['path']), other['sha256'])
    entries = {m['name']: m for m in seal['members']}
    need(seal['destination'] == str(DIRECTORY169) and len(entries) == len(seal['members'])
         and entries['peer162.py']['sha256'] == PEER_DIGEST, 'different 169 or 162 peer pricing')
    for name, member in entries.items():
        path = DIRECTORY169/name
        need(path.parent == DIRECTORY169 and path.lstat().st_size == member['bytes'], 'invalid member ' + name)
        immutable(path, member['sha256'])
    return status['api'](), other, spec['writer_active']


def unit_states(names):
    keys = ('Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID,Job,'
            'MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TriggeredBy,Triggers,Paths')
    result = subprocess.run(['/usr/bin/systemctl', 'show', '--all', '-p', keys, '--', *names],
                            capture_output=True, text=True, timeout=15)
    states = {}
    for block in result.stdout.strip().split('\n\n'):
        row = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if row:
            states[row['Id']] = row
    need(result.returncode in (0, 4) and set(states) == set(names)
         and all(not row['Job'] for row in states.values()), '166 donor census incomplete or changing')
    return states


def drained(row):
    return (row['ActiveState'] in ('inactive', 'failed') and not row.get('ControlGroup')
            and row.get('ControlPID', '0') == row.get('MainPID', '0') == '0')


def donor_observation(peer, proof):
    funding = proof['donor']
    need(funding == dict(original_actor_bytes=68*G, original_cpu_micros=9_000_000,
                         both_handlers_and_receivers_ram=2*(2*G+256*M), both_handlers_and_receivers_cpu=3_000_000,
                         passive_199_control_ram=512*M, passive_199_control_cpu=250_000,
                         usable_166_ram=63*G, usable_166_cpu_micros=5_750_000)
         and proof['retained_166_disk_bytes'] == 288*G, 'different 166 budget')
    # 162 itself and the independent 168 verification listener are observed by the full price.
    old = {k:v for k,v in proof['native'].items() if k not in (peer['UNIT'], 'horizon-168-private-verification-listener.service')}
    states = unit_states([*old, *CONTROLLERS199])
    for name, row in states.items():
        if name.endswith('.path'):
            expected = old[name]
            need(row['ActiveState'] == 'active' and row['SubState'] == 'waiting'
                 and all(row[k] == expected[k] for k in ('InvocationID', 'Paths', 'Triggers'))
                 and not Path(row['Paths'].removesuffix(' (PathExists)')).exists(), '166 publication path changed ' + name)
        else:
            need(drained(row), 'the donor already has a receiver or successor ' + name)
            if name in old:
                need(all(row.get(k) == old[name].get(k) for k in ('MemoryMax','CPUQuotaPerSecUSec')),
                     '166 controller allowance changed ' + name)
    references = proof['references']
    launchers = [p for p in references if p.endswith('/run-committed.sh')]
    need(len(launchers) == 2, '166 publication launchers changed')
    for path in launchers:
        raw, _ = peer['frozen'](path, dict(path=path, sha256=references[path]))
        need(b'MemoryMax=2G' in raw and b'CPUQuota=100%' in raw, '166 receiver budget changed')
    return states


def report169(row):
    if row is None:
        return dict(phase='precharged')
    if row['phase'] == 'terminal':
        return dict(phase='terminal', invocation_id=row['invocation_id'])
    need(row['phase'] in ('held','bootstrap','worker'), 'unknown 169 phase')
    disk = row['disk']
    return dict(phase=row['phase'], invocation_id=row['unit']['InvocationID'],
                start_intent=row['hourly169_start_intent'], guard_floor=disk['floor'],
                remaining_home_and_control=disk['remaining']+disk['fixed_control'])


def calculate(peer, base, row, phase, held, min_floor, fleet):
    need(base['schema'] == 'horizon-169-split-current-native-price-v1' and 'split162' not in base
         and base['accounting']['old_six_owner_lineage']['same_169_compute'] is True
         and base['accounting']['old_six_owner_lineage']['static_169_memory'] == 69*G,
         '169 compute missing or 162 already charged')
    resident = 0
    if phase == 'prestart':
        need(row is None and held is None, '162 is already issued')
        remaining, floor = peer['IMAGE'], min_floor
    else:
        need(phase == 'postguard' and row and row['phase'] == 'held' and row['invocation_id'] == held
             and row['donor'] == peer['DONOR'] and row['lease'], 'different held 162')
        later = peer['recheck'](fleet, row)
        remaining = max(row['disk']['remaining'], later['disk']['remaining'])
        floor = max(min_floor, row['disk']['floor'], later['disk']['floor'])
        if row['sampled_at'] <= base['started_unix_seconds']:
            resident = min(row['realized_ram'], later['realized_ram'])
    price = peer['geometry'](base, remaining, peer['CONTROL'], floor)
    ram = base['ram_margin'] + resident
    return dict(**price, ram_margin=ram, fits=price['home_margin'] >= 0 and ram >= 0,
                realized_162_ram=resident, remaining_162_home=remaining,
                peers={'169':report169(base['actor'])})


def quote(*, phase, held_invocation, profile, enrollment):
    need(Path(__file__).resolve() == SELF and os.geteuid() == 0 and __debug__, 'use the issued 162 price')
    module = DIRECTORY169/'peer162.py'
    immutable(module, PEER_DIGEST)
    peer = runpy.run_path(str(module))
    layout, provider, writer_ref = software(peer, enrollment)
    need(profile == layout.profile(36) and profile['combined_ram'] == 63*G
         and profile['producer_cpu_micros'] + profile['guard_cpu_micros'] == 3_000_000, 'different 162 profile')
    proof = peer['bound'](peer['DONOR'])
    before = donor_observation(peer, proof)
    # This provider checks all actual producers, the V48 writer and its package, the
    # 168 verification reservation, and 169's issued bootstrap or precharged envelope.
    other = runpy.run_path(str(DIRECTORY169/'split_operator.py'))
    need(other['writer']()['active'] == writer_ref, '169 and 162 have different cadence owners')
    base, row = other['price'](separate_162=True)
    need(base['provider'] == provider and not base['resource_credit_bytes'], 'foreign base price')
    fleet = peer['bound'](base['fleet'])
    need(fleet['owner'] == '/root' and not fleet['resource_credit_bytes']
         and not {166,173,199,200}.intersection(r['epoch'] for r in base['observed_actors']), 'competing compute loan')
    amounts = calculate(peer, base, row, phase, held_invocation, layout.MIN_FLOOR, fleet)
    need(before == donor_observation(peer, proof), '166 loan changed during price')
    peer['recheck'](fleet,row)
    return dict(schema='horizon-162-split-fleet-price-v1', phase=phase, unit=peer['UNIT'], profile=profile,
                scratch_gib=36, held_invocation=held_invocation, donor=peer['DONOR'], enrollment=enrollment,
                boot_id=BOOT.read_text().strip(), fleet=base['fleet'], exclusive_166_lease=True,
                donor_compute=proof['donor'], native_donor=before, base_169=base, existing_162=row,
                credited_166_disk_bytes=0, recorded_unix_seconds=time.time(), **amounts)
