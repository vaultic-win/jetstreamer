"""Inspect or retire precisely the 30 selected duplicate staged QA executables."""
import argparse
import hashlib
import os
import re
import runpy
import signal
import sys
import time
from pathlib import Path

BASE = Path('/home/sol/.jetstreamer-private')
RUNTIME = Path('/var/lib/jetstreamer/horizon_runtime_data')
PHASE = 'stage30-sealed-qa-retirement-20261123-v1'
PACK = RUNTIME / PHASE / 'tools'
STATE = BASE / 'horizon-root-runtime-data' / PHASE / 'state'
CARGO = RUNTIME / 'epoch166-exact-cargo-retirement-20261123-v1/tools'
CARGO_SEAL = '1dbc7045db4dde7bdf31d8ea4d098b094346368c2ce8c3bce9659ee0034ef1a8'
CARGO_HOST = '47fdd08d729005893e183ece467a756bcba25b5adccfe3060c1c24829e0c4ece'
MANIFEST = BASE / 'fifth168-fit-20261122-v1/unbooked-home-audit/QUALIFIED_SOURCE_SELECTION.json'
SCOPE = '1e48cb9f59a62e44d43479cca522a989113ab045b2478ecb78ec7be8c126d988'
SERIAL = Path('/run/lock/horizon-epoch140-suffix-compiler.lock')
MUTEX = BASE / 'r2-receipts/local-mutation.lock'

def require(ok, why):
    if not ok:
        raise RuntimeError(str(why))

def check_runtime(action):
    cgroup = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().split(':')[-1].lstrip('/')
    require(re.fullmatch(r'horizon-fit-stage30-'+action+r'-[0-9]+\.service',cgroup.name),'dedicated stage30 service required')
    quota, period = map(int, (cgroup / 'cpu.max').read_text().split())
    require(quota > 0 and quota * 2 <= period and int((cgroup/'memory.max').read_text()) <= 768<<20
            and int((cgroup/'memory.swap.max').read_text()) == 0, 'unfunded CPU, RAM or swap limit')
    require(os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino,'private network required')
    return cgroup.name

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect','execute'])
    parser.add_argument('seal')
    parser.add_argument('--inspection-sha256')
    cfg = parser.parse_args()
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__, 'run as root with python3 -IB')
    require(Path(__file__).absolute() == PACK/'host.py', 'use sealed deployment')
    unit = check_runtime(cfg.action)
    require(hashlib.sha256((CARGO/'host.py').read_bytes()).hexdigest()==CARGO_HOST, 'previous pricing provider changed')
    provider = runpy.run_path(str(CARGO/'host.py'))
    provider['sealed'](CARGO,CARGO_SEAL)
    require(set(provider['sealed'](PACK,cfg.seal)) == {'host.py','pairs.py','owners.py','retirement.py','test_pairs.py','invoke.py'},
            'unreviewed operator package')
    engine = runpy.run_path(str(PACK/'retirement.py'))
    controls = runpy.run_path(str(PACK/'owners.py'))
    kernel = runpy.run_path(str(CARGO/'consumers.py'))['kernel']
    pair_cls = runpy.run_path(str(PACK/'pairs.py'))['PairedFiles']
    for sig in (signal.SIGIO,signal.SIGTERM):
        signal.signal(sig,engine['interrupted'])
    engine['secure_state'](STATE)
    manifest = provider['bound'](MANIFEST,SCOPE)
    rows = manifest['proposed_files']
    require(len(rows)==30 and set(rows).isdisjoint(manifest['excluded_source_paths'])
            and len(manifest['excluded_source_paths'])==5 and manifest['physical_allocated_bytes']==12639535104
            and manifest['logical_source_bytes']==12641076584 and manifest['final_pair_read_bound']==25282153168,
            'unrecognized exact selection')
    initial = provider['bound'](Path(manifest['owner_snapshot']['path']), manifest['owner_snapshot']['sha256'])
    previous = {k:provider['bound'](Path(manifest[k]['path']),manifest[k]['sha256']) for k in
                ('pair_exclusion','control_parent_classification','outside_booking_basis')}
    require(set(rows).isdisjoint(previous['pair_exclusion']['files']), 'overlap with Cargo proposal')
    stamps = {name:item['source_stat'] for name,item in rows.items()}
    eligible = sorted(rows)
    local_locks = []
    for p,dev,ino,uid in [(SERIAL,29,1048,0),(MUTEX,64512,101135013,1001)]:
        stamp = engine['identity'](p)
        require(stamp[:2]==[dev,ino] and stamp[3]==uid and not stamp[2]&0o002, f'changed physical mutex {p}')
        local_locks.append((p,stamp))
    def keepers():
        for name in eligible:
            r = rows[name]
            path = Path(r['keeper_path'])
            require(path.is_relative_to('/usr/local/lib/jetstreamer') and path.parent.stat().st_uid==0
                    and not path.parent.stat().st_mode&0o222 and path.resolve(strict=True)==path
                    and not r['keeper_stat'][2]&0o222 and engine['identity'](path)==r['keeper_stat'],
                    f'changed keeper {path}')
            for key in ('deployment_seal','SHA256SUMS','source_seal_plan'):
                x = r[key]
                file = Path(x['path'])
                require(file.resolve(strict=True)==file and engine['fingerprint'](file)==x['sha256'],file)
            seal=engine['read'](Path(r['deployment_seal']['path']))
            require(seal['destination']==str(path.parent) and seal['plan_sha256']==r['source_seal_plan']['sha256']
                    and any(m['source']==name and m['name']==path.name and m['sha256']==r['whole_sha256_at_seal']
                            and m['bytes']==r['source_stat'][6] for m in seal['members']), 'keeper seal changed')
    with engine['locks'](local_locks):
        pair = pair_cls(STATE,rows,engine)
        proof = None
        def closure():
            frame = provider['price']()
            roots = set(manifest['priced_roots']) | {x['root'] for x in frame['bookings'].values()}
            require(all(not any(Path(s).is_relative_to(root) for root in roots) for s in rows),'overlap with booking')
            keepers()
            current = Path(frame['fleet']['path'])
            observed = controls['check'](rows,manifest,initial,current,engine,kernel)
            require(provider['fleet']()==current and engine['fingerprint'](current)==frame['fleet']['sha256'], 'fleet changed during closure')
            return dict(observed=observed, fleet=frame['fleet'], body_proof=proof,
                        status_writer=frame['status_registration']['invocation_id'], unit=unit, time=time.time(),
                        available_HOME=frame['available_HOME_bytes'], committed_HOME=frame['complete_required_HOME_bytes'],
                        exact_mutex_inodes=[s[1] for _,s in local_locks])
        scope = {'selection':SCOPE,'seal':cfg.seal}
        op = engine['Retirement'](STATE,stamps,scope,closure,batch_size=30,open_lease=pair.retained_source_lease)
        if cfg.action=='inspect':
            require(not cfg.inspection_sha256,'unexpected inspection argument')
            result = op.inspect()
            output = STATE/f'inspection-{time.time_ns()}.json'
            engine['publish'](output,result)
            print(output,engine['fingerprint'](output),flush=True)
            return
        require(cfg.inspection_sha256 and re.fullmatch('[0-9a-f]{64}',cfg.inspection_sha256),'bind inspected scope')
        matching = [p for p in STATE.glob('inspection-*.json') if engine['fingerprint'](p)==cfg.inspection_sha256]
        require(len(matching)==1,'inspection not found')
        inspection = engine['read'](matching[0])
        require(inspection['parents']==op.parents() and inspection['scope']==scope,'inspection identity differs')
        # Read the pair bodies once per execution, while all originals/captured
        # files remain write-leased. A later bad pair prevents every first mutation.
        closure()
        with pair.leases():
            path=STATE/f'paired-{time.time_ns()}.json'
            engine['publish'](path,{'scope':SCOPE,'pairs':pair.pairs,'time':time.time(),'unit':unit})
            proof={'path':str(path),'sha256':engine['fingerprint'](path)}
            print(op.run(inspection),flush=True)
        keepers()

if __name__=='__main__':
    main()
