"""Qualify and seal the epoch 143 compute return with the next shared price."""
import argparse
import ast
import fcntl
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time

from derive_serial157_v23 import f, once, read_package
from idle143_compute_return import FULL, READER, RETURN, RETURNED, ROOT, RT, UNIT, observation

SCRIPT = Path(__file__).resolve().parent
PRICES = RT/'epoch162-first-hourly-completion-20261127-v2'
OLD = PRICES/'issued-price-v40'
NEW = PRICES/'issued-price-v41'
LOCK = Path('/run/horizon-epoch171-to136-g1.operation.lock')
PLAN = RETURN.parent/'PLAN.json'


def verify_source():
    repo = SCRIPT.parents[1]
    revision = f.git(repo,'rev-parse','HEAD').decode().strip()
    f.git(repo,'merge-base','--is-ancestor',revision,'origin/account-updates')
    for name in ('stage_idle143_compute_return.py','idle143_compute_return.py'):
        p = SCRIPT/name
        f.need(f.git(repo,'show',f'{revision}:{p.relative_to(repo)}') == p.read_bytes(), 'unpublished '+name)
    return revision


def prepare(old_seal):
    directory = Path(old_seal['path']).parent
    f.need(directory in (OLD, OLD.with_name('issued-price-v39')), 'different native quote reference')
    files = read_package(directory,old_seal['sha256'])
    core = runpy.run_path(str(directory/'continuation_price.py'))['prior']
    fleet, head = core.current_fleet()
    closed = runpy.run_path(str(directory/'shared_hourly143.py'))['owner'](vars(core),fleet)[0]
    admission = observation(vars(core),fleet,closed,masked=RETURN.exists())
    return files, vars(core), fleet, head, closed, admission


def create_authority(core, fleet, head, closed, admission):
    if RETURN.exists():
        present = f.reference(RETURN)
        original = core['bound'](present)
        f.need(original['native'] == admission and original['returned_ram'] == RETURNED, 'different previous compute return')
        return present
    RETURN.parent.mkdir(mode=0o700,exist_ok=True)
    subprocess.run(['/usr/bin/systemctl','mask','--runtime',UNIT],check=True,timeout=30)
    try:
        native = observation(core,fleet,closed,masked=True)
        f.need(core['current_fleet']()[1] == head and native['terminal'] == admission['terminal'],
               'host owner changed during the return')
        return f.save(RETURN,dict(schema='horizon-143-idle-compute-return-v1',native=native,
            fleet=head,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            original_ram=FULL,returned_ram=RETURNED,retained_ram=READER,retained_cpu_quota_micros=3_000_000,
            separate_reader_admission_required=True,physical_disk_release_bytes=0,
            archive_publication_authorized=False,recorded_unix_seconds=time.time()))
    except Exception:
        if not RETURN.exists():
            subprocess.run(['/usr/bin/systemctl','unmask','--runtime',UNIT],check=True,timeout=30)
        raise


def derive(files, revision, old_seal, authority, directory):
    for name,(body,mode) in list(files.items()):
        if name.endswith('.py'):
            files[name] = body.replace(bytes(OLD),bytes(NEW)),mode

    def edit(name, old, new):
        raw, mode = files[name]
        files[name] = once(raw.decode(),old,new).encode(),mode

    edit('continuation_price.py', '    ram_required = joint["required_ram"]', '''    loan = runpy.run_path(str(Path(__file__).with_name('idle143_compute_return.py')))
    compute_return = loan['charge'](vars(prior),prior.bound(joint['fleet']),closed143,replacement)
    ram_required = -compute_return['returned_ram'] + joint["required_ram"]''')
    edit('continuation_price.py','                replacement143=replacement,closed143=closed143,auxiliary=aux,',
         '                replacement143=replacement,closed143=closed143,auxiliary=aux,closed143_compute_return=compute_return,')
    edit('capacity.py', "'next_hourly170_roster.py',", "'next_hourly170_roster.py','idle143_compute_return.py',")
    edit('capacity.py','    return complete_roster(True)',
         '    raise ValueError("epoch 143 production requires compute return withdrawal and new admission")')
    edit('capacity.py','    registered["original_172_accounting"] =',
         '    registered["closed143_compute_return"] = base["native"]["raw"]["closed143_compute_return"]\n    registered["original_172_accounting"] =')
    code = once((SCRIPT/'idle143_compute_return.py').read_text(),'AUTHORITY = None','AUTHORITY = '+repr(authority))
    files['idle143_compute_return.py'] = code.encode(),0o444
    history = json.loads(files['SOURCE.json'][0])
    history.update(revision=revision,prior_shared_price=old_seal,closed143_compute_return=authority)
    files['SOURCE.json'] = (json.dumps(history,indent=2)+'\n').encode(),0o444
    directory.mkdir(mode=0o700)
    for name,(body,_) in files.items():
        if name.endswith('.py'):
            ast.parse(body,filename=name)
        (directory/name).write_bytes(body)
    return {name:(directory/name,mode) for name,(_,mode) in files.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('check','issue'))
    parser.add_argument('provider_version',type=int,choices=(39,40))
    parser.add_argument('provider_sha256')
    args = parser.parse_args()
    revision = verify_source()
    old_seal = dict(path=str(PRICES/f'issued-price-v{args.provider_version}'/'deployment-seal-receipt.json'),
                    sha256=args.provider_sha256)
    os.umask(0o077)
    with LOCK.open('rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        files, core, fleet, head, closed, current = prepare(old_seal)
        if args.phase == 'check':
            print(json.dumps(dict(native=current,fleet=head,returned_ram=RETURNED,retained_ram=READER)))
            return
        f.need(args.provider_version == 40 and not NEW.exists(), 'V40 has yet to issue or V41 already exists')
        authority = create_authority(core, fleet, head, closed, current)
        stage = Path(tempfile.mkdtemp(prefix='provider-members-',dir=RETURN.parent))
        members = derive(files,revision,old_seal,authority,stage/'members')
        ref = f.seal(NEW,members,PLAN)
        print(json.dumps(dict(authority=authority,provider=ref),sort_keys=True))


if __name__ == '__main__':
    main()
