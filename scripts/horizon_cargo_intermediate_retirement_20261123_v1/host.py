"""Inspect or complete the existing 13,754-file historical Cargo cleanup proposal."""
import argparse
import hashlib
import json
import os
import runpy
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

BASE = Path('/home/sol/.jetstreamer-private')
BUNDLE = BASE / 'peer166-closed-cargo-review-20261122-v1'
RUNTIME = Path('/var/lib/jetstreamer/horizon_runtime_data')
PHASE = 'epoch166-exact-cargo-retirement-20261123-v1'
STATE = BASE / 'horizon-root-runtime-data' / PHASE / 'state'
PACKAGE = RUNTIME / PHASE / 'tools'
PROPOSAL = '9c00b6eab801478310e5bc2ea315ef98f2b4393f9b865dd127994551c0c859b1'
REFRESH = RUNTIME / 'epoch166-retry11-rebook-20261122-v1/CARGO_13754_REFRESH_021757_20261123.json'
REFRESH_SHA = '283d0a3ccd9af8d8a3533831de9f6637ee520b710a0b54c3de1f630a3f8deaaf'
PROVIDER = RUNTIME / 'incident-replay-fit-20261121-v1/tools-homefloor-cold168-retry4-v1'
PROVIDER_SHA = '7c7dc6f92cca7fc94388b22261e3b0b15fbfe27587fd56fb61e1951aaf4250e9'
SERIAL = Path('/run/lock/horizon-epoch140-suffix-compiler.lock')
MUTEX = BASE / 'r2-receipts/local-mutation.lock'
PROFILE_LOCKS = [93852968, 93853559, 93924609, 97851660, 97912191, 108462339, 108475799,
                 111487577, 94309782, 94322104, 94835744]


def require(ok, why):
    if not ok:
        raise RuntimeError(str(why))


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def bound(path, hashed):
    require(path.resolve(strict=True) == path and sha(path) == hashed, f'changed binding: {path}')
    return read(path)


def sealed(package, expected):
    seal = package / 'deployment-seal-receipt.json'
    value = bound(seal, expected)
    require(package.stat().st_uid == 0 and not package.stat().st_mode & 0o222 and value['destination'] == str(package)
            and value['sealer_sha256'] == 'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3', package)
    members = {item['name']: item for item in value['members']}
    require(len(members) == len(value['members']) and {p.name for p in package.iterdir()} == set(members) | {seal.name, 'SHA256SUMS'}, package)
    sums = sorted((package / 'SHA256SUMS').read_text().splitlines())
    require(sums == sorted([f"{x['sha256']}  {n}" for n, x in members.items()] + [f"{expected}  {seal.name}"]), 'unexpected member checksum listing')
    for name, member in members.items():
        p = package / name
        require(p.resolve(strict=True) == p and Path(name).name == name and p.stat().st_uid == 0
                and stat.S_ISREG(p.stat().st_mode) and not p.stat().st_mode & 0o222 and sha(p) == member['sha256'], p)
    return members


def fleet():
    return max(RUNTIME.glob('root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json'), key=lambda p: p.stat().st_mtime_ns)


def price():
    sealed(PROVIDER, PROVIDER_SHA)
    head = fleet()
    checksum = sha(head)
    child = subprocess.run(['/usr/bin/python3', '-IB', PROVIDER / 'post-stop-fit', '145', head, checksum],
                           check=True, capture_output=True, timeout=220)
    p = json.loads(child.stdout)
    require(p['schema'] == 'horizon-incident-replay-fit-v1' and p['epoch'] == 145 and p['fits'] is True
            and p['fleet'] == dict(path=str(head), sha256=checksum) and head == fleet()
            and time.time()-120 < p['recorded_unix_seconds'] <= time.time()+1
            and p['available_HOME_bytes'] >= p['complete_required_HOME_bytes'] + (48 << 20)
            and p['available_memory_bytes'] >= p['required_available_memory_bytes'] + (768 << 20)
            and not p['resource_credit_bytes'] and set(p['replacements']) == {'167', '168', '170'}
            and set(p['survivors']) == {'172'}, 'unfunded or unrecognized existing four-peer 145 donor')
    return p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'execute'])
    parser.add_argument('seal', help='qualified deployment-seal SHA-256')
    parser.add_argument('--inspection-sha256', help='inspection selected by execution owner')
    opts = parser.parse_args()
    require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__, 'run as root with python3 -IB')
    require(Path(__file__).absolute() == PACKAGE / 'host.py', 'use sealed deployment')
    members = sealed(PACKAGE, opts.seal)
    require(set(members) == {'retirement.py', 'consumers.py', 'host.py', 'test_retirement.py'}, 'unexpected executable package')
    impl = runpy.run_path(str(PACKAGE / 'retirement.py'))
    controls = runpy.run_path(str(PACKAGE / 'consumers.py'))
    for sig in (signal.SIGIO, signal.SIGTERM):
        signal.signal(sig, impl['interrupted'])
    impl['secure_state'](STATE)
    proposal = bound(BUNDLE / 'ELIGIBLE.json', PROPOSAL)
    refresh = bound(REFRESH, REFRESH_SHA)
    require(proposal['schema'] == 'historical-cargo-exclusive-intermediate-proposal-v1'
            and proposal['bytes'] == refresh['allocated_bytes'] == 15776354304
            and len(proposal['files']) == refresh['unaffected_files'] == 13754, 'proposal mismatch')
    rows = proposal['files']
    for name, wanted in proposal['basis_sha256'].items():
        require(sha(BUNDLE / name) == wanted, f'changed original evidence: {name}')
    profiles = read(BUNDLE / 'proposed-cargo.json')['profiles']
    actual = read(BUNDLE / 'actual-controls.json')
    linkage = read(BUNDLE / 'linkage-and-sources.json')
    locked = [(SERIAL, 29, 1048, 0), (MUTEX, 64512, 101135013, 1001)]
    locked += [(BASE / path / '.cargo-lock', 64512, n, 1001) for path, n in zip(sorted(profiles), PROFILE_LOCKS, strict=True)]
    bindings = []
    for path, dev, ino, uid in locked:
        st = impl['identity'](path)
        require(st[:2] == [dev, ino] and st[3] == uid and not st[2] & 0o002, f'unexpected mutex: {path}')
        bindings.append((path, st))
    with impl['locks'](bindings):
        def closure():
            frame = price()
            roots = {x['root'] for x in frame['bookings'].values()} | {proposal['priced_booking_roots']['172']}
            require(roots == set(refresh['current_booked_roots']) and all(not any(p.startswith(r + '/') for r in roots) for p in rows),
                    'selection overlaps booking')
            for p, item in actual['freeze'].items():
                require(sha(Path(p)) == item['sha256'], f'compiler freeze changed: {p}')
            for p, h in linkage['receipts_and_sources_sha256'].items():
                require(sha(Path(p)) == h, f'retained compiler dependency changed: {p}')
            protected = set(proposal['omitted_runtime_libraries'] + proposal['retained_dependencies']) | linkage['needed'].keys()
            require(all(Path(p).is_file() and p not in rows for p in protected), 'retained executable absent or selected')
            linkage_count = controls['verify_linkage'](BASE, profiles, rows, linkage['needed'], proposal['omitted_runtime_libraries'])
            units = controls['check_units'](actual['units'])
            sched = controls['controls'](BASE, BUNDLE, profiles, rows, Path(frame['fleet']['path']), STATE)
            kernel = controls['kernel'](rows, [BASE / p for p in profiles])
            after = price()
            require(after['fleet'] == frame['fleet'] and after['status_registration'] == frame['status_registration']
                    and controls['check_units'](actual['units']) == units, 'owners changed during census')
            frame = after
            return dict(time=time.time(), fleet=frame['fleet'], writer=frame['status_registration']['invocation_id'],
                        fit_epoch=frame['epoch'], free_HOME=frame['available_HOME_bytes'],
                        required_HOME=frame['complete_required_HOME_bytes'], original_lock_count=len(bindings),
                        native_units=units, scheduler=sched, kernel=kernel, retained_files=len(protected), verified_dynamic_ELFs=linkage_count)
        operator = impl['Retirement'](STATE, rows, dict(proposal=PROPOSAL, seal=opts.seal), closure)
        if opts.action == 'inspect':
            require(not opts.inspection_sha256, 'inspection digest is for execute')
            inspection = operator.inspect()
            output = STATE / ('inspection-' + str(time.time_ns()) + '.json')
            impl['publish'](output, inspection)
            print(json.dumps(dict(receipt=str(output), sha256=sha(output), physical_bytes_released=0)))
        else:
            require(opts.inspection_sha256 and len(opts.inspection_sha256) == 64, 'exact checked inspection required')
            matches = [p for p in STATE.glob('inspection-*.json') if sha(p) == opts.inspection_sha256]
            require(len(matches) == 1, 'unknown inspection')
            print(json.dumps(operator.run(read(matches[0])), sort_keys=True))


if __name__ == '__main__':
    main()
