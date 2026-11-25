#!/usr/bin/env python3
"""Verify the epoch 226 extraction-to-suffix handoff without issuing admission."""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

V = Path('/var/lib/jetstreamer')
REPO = Path('/home/ubuntu/workspace/jetstreamer')
PRIVATE = Path('/home/ubuntu/.jetstreamer-private')
SUFFIX = PRIVATE / 'checkpoint-continuation-226-suffix-v1'
SUFFIX_UNIT = 'horizon-qualify-226-checkpoint-continuation-suffix-v1.service'
SEALED = V / 'horizon226-suffix-stage-evidence-v1'
HANDOFF = V / 'horizon226-suffix-v1/source-handoff.json'
PLAN_SCHEMA = 'jetstreamer-private-epoch226-scoped-repair-plan-v1'
ADMISSION_SCHEMA = 'jetstreamer-epoch226-scoped-repair-admission-v1'
SUCCESS = '7ad2d189f7e94e70a38c781354912448'
LAUNCHES = {
    'v2': {
        'path': str(V / 'horizon226-extract-v2/fleet-launch.json'),
        'sha256': '4826797399fcd448e82bddb975cf31101d958df17126dc29013a9282e3bcf66c',
    },
    'v3': {
        'path': str(V / 'horizon226-extract-v3/fleet-launch.json'),
        'sha256': '30f1fd1a0009ff63c22f1aac39438caf570acaddfaf90bd656331e2895294df8',
    },
}
PREPARATION = {
    'path': str(V / 'horizon226-suffix-inputs-v1/preparation.json'),
    'sha256': '02d79bdc19c28d58c00c75d37e3ce870a68bd10bb89577d7e6db840434825af8',
}
STAGE_INPUTS = {
    'extract': ('original_archive', 'original_manifest', 'native_review', 'restore_proof', 'verified225', 'held_broker'),
    'replay': ('prefix_archive', 'prefix_manifest', 'extraction', 'snapshot', 'worker', 'genesis'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pin(ref):
    path = Path(ref['path'])
    sha = ref['sha256']
    require(path.is_absolute() and re.fullmatch(r'[0-9a-f]{64}', sha) and sha != '0' * 64,
            'missing absolute path or SHA-256')
    return {'path': str(path), 'sha256': sha}


def stage_digest(stage):
    # Match Rust serde for the tagged Stage enum and its nested Evidence structs.
    fields = STAGE_INPUTS[stage['operation']]
    require(set(stage) == {'operation', *fields}, 'unexpected exact-stage fields')
    ordered = {'operation': stage['operation'], **{key: pin(stage[key]) for key in fields}}
    return digest(json.dumps(ordered, ensure_ascii=False, separators=(',', ':')).encode())


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_nlink, info.st_ctime_ns, info.st_mtime_ns)


@contextlib.contextmanager
def opened(path, *, uid=0, writable=0o222):
    require(path.resolve(strict=True) == path, f'noncanonical path: {path}')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid
                and not info.st_mode & writable, f'unsafe input metadata: {path}')
        require(stamp(path.lstat()) == stamp(info), f'metadata raced at open: {path}')
        yield stream, info
        require(stamp(os.fstat(stream.fileno())) == stamp(info) == stamp(path.lstat()),
                f'input changed while reading: {path}')


def metadata(path, *, uid=0, writable=0o222):
    with opened(path, uid=uid, writable=writable) as (_, info):
        return stamp(info)


def read_bytes(path, *, uid=0, writable=0o222):
    with opened(path, uid=uid, writable=writable) as (stream, info):
        limit = 1 << 20
        require(info.st_size <= limit, f'oversized receipt: {path}')
        data = stream.read(limit + 1)
        require(len(data) == info.st_size, f'incomplete receipt: {path}')
    return data


def document(ref, *, uid=0, writable=0o222):
    ref = pin(ref)
    data = read_bytes(Path(ref['path']), uid=uid, writable=writable)
    require(digest(data) == ref['sha256'], f'receipt digest differs: {ref["path"]}')
    return json.loads(data)


def verified_file(ref, *, executable=False, full=True):
    exact = pin(ref)
    path = Path(exact['path'])
    with opened(path) as (stream, info):
        if 'bytes' in ref:
            require(ref['bytes'] == info.st_size, f'file size differs: {path}')
        if executable:
            require(info.st_mode & stat.S_IXOTH, f'private node cannot execute: {path}')
        if full:
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == exact['sha256'],
                    f'file SHA-256 differs: {path}')
        return stamp(info)


def git(*args):
    return subprocess.check_output(['git', '-c', f'safe.directory={REPO}', '-C', str(REPO), *args],
                                   text=True, timeout=20).strip()


def static_inputs(full, extraction='v2'):
    prep = document(PREPARATION)
    require(prep['schema'] == 'foundation-epoch226-pending-suffix-inputs-v1'
            and prep['epoch'] == 226 and prep['slot_range'] == [98063465, 98063999]
            and not prep['admission_issued'] and not prep['replay_launched'], 'wrong suffix preparation')
    release = document(prep['release'])
    node = prep['node']
    require(release['release_linked'] and release['scope'] == 'private epoch 226 continuation'
            and not release['replay_started'] and not release['canonical_publication_authorized']
            and [x['sha256'] for x in release['artifacts'] if x['source'] == 'jetstreamer-node/src/main.rs']
            == [node['sha256']], 'wrong dedicated private feature release')
    verified_file(node, executable=True)
    equivalence = document(prep['compiled_source_equivalence'], uid=1000, writable=0o022)
    origin = git('rev-parse', 'origin/account-updates')
    source = equivalence['source']
    require(equivalence['release_source_sha256'] == release['source_tree_sha256']
            and git('merge-base', source, origin) == source, 'pinned suffix source absent from account-updates')
    roots = {Path(entry['path']).parts[0] for entry in equivalence['checked']}
    tree = {line.split('\t')[1]: line.split('\t')[0].split()[2]
            for line in git('ls-tree', '-r', source, '--', *sorted(roots)).splitlines()}
    permitted_exceptions = {
        'jetstreamer-node/src/bin/jetstreamer-qualification-verify.rs',
        'jetstreamer-node/src/bin/qualification_verify/prefix223.rs',
        'jetstreamer-node/src/bin/qualification_verify/tail223.rs',
    }
    differences = {entry['path'] for entry in equivalence['checked'] if tree.get(entry['path']) != entry['blob']}
    require(set(equivalence['other_binary_only_differences']) == permitted_exceptions
            and differences == permitted_exceptions, 'pinned compiled-source equivalence differs')
    source_probe = document(prep['suffix_source_qualification'], uid=1000, writable=0o022)
    require(source_probe['schema'] == 'foundation-epoch226-suffix-source-qualified-v1'
            and source_probe['complete_source_slot_coverage'] == 535
            and (source_probe['rooted_blocks'], source_probe['skipped_slots']) == (505, 30)
            and source_probe['cids_verified'] > 0 and not source_probe['bank_replay_completed']
            and not source_probe['canonical_publication_authorized'], 'wrong source span qualification')
    restore = document(prep['previous_native_worker_proof'])
    native_plan = document(prep['previous_native_worker_plan'])
    native_worker = native_plan['full_worker']
    require(restore['native_input_qualified'] and not restore['entry_replay']
            and restore['native_marker']['slot'] == '98063464'
            and native_worker['sha256'] == prep['inputs']['worker']['sha256']
            and native_worker['executable'] == prep['inputs']['worker']['path'], 'wrong cold input or worker proof')
    images = {}
    for name, ref in prep['inputs'].items():
        seal = document(ref['seal'])
        path = Path(ref['path'])
        require(seal['destination'] == str(path.parent) and any(
            row['name'] == path.name and row['sha256'] == ref['sha256'] and row['bytes'] == ref['bytes']
            for row in seal['members']), f'{name} lacks its deployment seal')
        images[name] = verified_file(ref, executable=name == 'worker', full=full or name != 'snapshot')
    launch_ref = LAUNCHES[extraction]
    extract = PRIVATE / f'checkpoint-continuation-226-extract-{extraction}'
    launch = document(launch_ref)
    extract_plan = document(launch['node_plan'])
    extract_admission = document(extract_plan['admission'])
    require(launch['epoch'] == extract_plan['epoch'] == 226 and launch['operation'] == 'extract'
            and launch['launched'] is True and launch['unit'] == extract_plan['producer_unit']
            and launch['run_root'] == extract_plan['run_root'] == str(extract)
            and launch['node_sha256'] == extract_plan['node_sha256']
            and extract_plan['stage']['held_broker'] == launch['broker_pin']
            and stage_digest(extract_plan['stage']) == extract_admission['stage_sha256'],
            'extraction launch or original Rust stage digest differs')
    return prep, launch, extract_plan, {'node': pin(node), 'source_commit': source,
        'account_updates': origin, 'compiled_scope_paths': len(equivalence['checked']),
        'native_probe_envelope': native_plan['envelope'], 'input_metadata': images,
        'snapshot_body_rehashed': full, 'extraction_stage_digest_matches_native_admission': True}


def systemd(unit, fields):
    result = subprocess.check_output(['systemctl', 'show', unit, *('-p' + key for key in fields)],
                                     text=True, timeout=10)
    return dict(line.split('=', 1) for line in result.splitlines())


def terminal_matches(live, journal, launch):
    require(live.get('ActiveState') == 'inactive' and live.get('SubState') == 'dead'
            and live.get('MainPID') == live.get('ControlPID') == live.get('NRestarts') == '0'
            and live.get('ControlGroup') == live.get('Job') == '' and live.get('Result') == 'success'
            and live.get('ExecMainStatus') == '0'
            and live.get('InvocationID') in ('', launch['invocation_id']),
            'extraction producer has not drained successfully')
    exact = [row for row in journal if row.get('UNIT') == launch['unit']
             and row.get('INVOCATION_ID') == launch['invocation_id'] and row.get('_PID') == '1'
             and row.get('_UID') == '0' and row.get('MESSAGE_ID') == SUCCESS
             and row.get('UNIT_RESULT', 'success') == 'success']
    require(len(exact) == 1 and len(journal) == 1, 'PID 1 exact invocation has no unique successful terminal event')
    return exact[0]


def capture_terminal(launch):
    unit = launch['unit']
    live = systemd(unit, ('ActiveState', 'SubState', 'MainPID', 'ControlPID', 'NRestarts', 'InvocationID',
                          'ControlGroup', 'Job', 'Result', 'ExecMainStatus'))
    require(live.get('ActiveState') == 'inactive', 'extraction producer is still running or has failed')
    lines = subprocess.check_output([
        'journalctl', '-b', '--no-pager', '-o', 'json',
        f'UNIT={unit}', f'INVOCATION_ID={launch["invocation_id"]}',
        f'MESSAGE_ID={SUCCESS}', '_PID=1', '_UID=0',
    ], text=True, timeout=10).splitlines()
    journal = terminal_matches(live, [json.loads(line) for line in lines], launch)
    group = Path('/sys/fs/cgroup/system.slice') / unit
    require(not group.exists(), 'extraction producer still has a cgroup')
    return {'manager': live, 'pid1_cursor': journal['__CURSOR'],
            'terminal_unix_microseconds': journal['__REALTIME_TIMESTAMP']}


def validate_outputs(owner, extraction, manifest, launch, extract_plan, receipt_sha, manifest_sha, prefix):
    require(owner['producer_unit'] == launch['unit'] and owner['invocation_id'] == launch['invocation_id']
            and owner['operation'] == 'extract' and owner['plan'] == launch['node_plan']
            and owner['receipt'] == str(Path(launch['run_root']) / 'receipts/extract.json')
            and owner['receipt_sha256'] == receipt_sha
            and owner['source_must_be_retained'] and not owner['publication_authorized'] and not owner['r2_mutations'],
            'output owner does not bind this invocation, plan and extraction receipt')
    require(extraction['schema'] == 'jetstreamer-private-epoch226-interior-extraction-v1'
            and extraction['epoch'] == 226 and extraction['selected_slots'] == 431465
            and extraction['missing_suffix_slots'] == 535 and extraction['independent_output_reread_passed'] is True
            and extraction['source_must_be_retained'] is True and extraction['publication_authorized'] is False
            and extraction['canonical_sidecar_authorized'] is False
            and extraction['authenticated_held_broker'] == launch['broker_pin']
            and extraction['original_archive_sha256'] == extract_plan['stage']['original_archive']['sha256']
            and extraction['original_manifest_sha256'] == extract_plan['stage']['original_manifest']['sha256']
            and extraction['prefix_archive'] == str(prefix)
            and extraction['prefix_manifest'] == str(prefix.with_suffix('.jet.segment.json'))
            and extraction['prefix_manifest_sha256'] == manifest_sha, 'extraction receipt does not bind the selected prefix')
    require(manifest['epoch'] == 226 and manifest['output_slot_start'] == 97632000
            and manifest['output_slot_count'] == 431465 and manifest['terminal']['slot'] == 98063464
            and manifest['terminal']['bank_hash'] == '2qWtzMF3aJBSujYSm3U1jXfkvRMFsYd9JSj3FVT2cQmN'
            and manifest['terminal']['accounts_hash'] == '4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR'
            and manifest['archive_sha256'] == extraction['prefix_archive_sha256'], 'selected prefix manifest differs')


def durable_seal(path, payload):
    # Publish one immutable file atomically, without replacing prior custody.
    require((path.parent == SEALED or path == HANDOFF) and path.parent.resolve(strict=True) == path.parent,
            'sealed destination is not the exact stage custody path')
    parent = path.parent.stat()
    require(parent.st_uid == 0 and stat.S_IMODE(parent.st_mode) == 0o755, 'unsafe custody directory')
    mode = 0o400 if path == HANDOFF else 0o444
    if not path.exists():
        fd, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'wb') as out:
                os.fchmod(out.fileno(), mode)
                out.write(payload)
                out.flush()
                os.fsync(out.fileno())
            os.link(temporary, path)
        finally:
            temporary.unlink()
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    require(stat.S_IMODE(path.lstat().st_mode) == mode and read_bytes(path) == payload,
            f'existing sealed bytes or mode differ: {path}')
    return {'path': str(path), 'sha256': digest(payload)}


def bind_static_to_output(prep, launch, extract_plan, static, launch_ref):
    terminal = capture_terminal(launch)
    extract = Path(launch['run_root'])
    prefix = extract / 'output/epoch-226-prefix.jet'
    manifest = prefix.with_suffix('.jet.segment.json')
    receipt = extract / 'receipts/extract.json'
    owner = extract / 'receipts/owner.json'
    prefix_identity = metadata(prefix, uid=1000, writable=0o022)
    require(prefix_identity[2] > 0 and not os.path.lexists(str(prefix) + '.sha256'),
            'prefix absent or has a canonical sidecar')
    pieces = {path.name: read_bytes(path, uid=1000, writable=0o022) for path in (manifest, receipt, owner)}
    validate_outputs(*(json.loads(pieces[path.name]) for path in (owner, receipt, manifest)),
                     launch, extract_plan, digest(pieces[receipt.name]), digest(pieces[manifest.name]), prefix)
    # The dedicated node independently rehashes and decodes the retained prefix before spawning a worker.
    extracted = json.loads(pieces[receipt.name])
    if not SEALED.exists():
        SEALED.mkdir(mode=0o755)
        SEALED.chmod(0o755)
    stage = {'operation': 'replay', 'prefix_archive': pin({'path': str(prefix), 'sha256': extracted['prefix_archive_sha256']}),
             'prefix_manifest': durable_seal(SEALED / manifest.name, pieces[manifest.name]),
             'extraction': durable_seal(SEALED / receipt.name, pieces[receipt.name]),
             **{name: pin(prep['inputs'][name]) for name in ('snapshot', 'worker', 'genesis')}}
    owner_pin = durable_seal(SEALED / owner.name, pieces[owner.name])
    require(metadata(prefix, uid=1000, writable=0o022) == prefix_identity, 'prefix identity changed during custody seal')
    return {'schema': 'foundation-epoch226-suffix-handoff-v1', 'epoch': 226, 'terminal': terminal,
            'launch': launch_ref, 'inputs': PREPARATION, 'static': static, 'original_output_owner': owner_pin,
            'prefix_identity': prefix_identity, 'stage': stage, 'stage_sha256': stage_digest(stage),
            'producer_unit': SUFFIX_UNIT, 'run_root': str(SUFFIX), 'admission_issued': False,
            'guard_and_cadence_integration_required': True, 'work_started': False}


def plan_from_admission(handoff, admission_ref, admission):
    stage = handoff['stage']
    node = handoff['static']['node']
    yes = ('admitted', 'complete_fleet_and_century_floor_bound', 'actual_guard_and_owner_qualified',
           'exact_stage_scope_qualified', 'original_native_source_evidence_accepted',
           'exact_worker_artifact_and_feature_scope_qualified')
    no = ('ordinary_replay_authorized', 'canonical_sidecar_authorized', 'publication_authorized',
          'retirement_authorized', 'runtime_promotion_authorized', 'remote_mutations', 'r2_mutations')
    deadline = int(time.time())
    issued = admission['recorded_unix_seconds']
    floor = admission['protected_existing_floor_bytes']
    peak = admission['candidate_incremental_peak_bytes']
    require(admission['schema'] == ADMISSION_SCHEMA and admission['epoch'] == 226
            and admission['operation'] == 'replay' and admission['stage_sha256'] == stage_digest(stage)
            and admission['node_sha256'] == node['sha256'] and admission['producer_unit'] == SUFFIX_UNIT
            and admission['run_root'] == str(SUFFIX) and all(admission[key] is True for key in yes)
            and all(admission[key] is False for key in no) and type(issued) is int and 0 <= deadline-issued <= 900
            and type(floor) is type(peak) is int and floor > 0 and peak > 0 and floor + peak < 2**64,
            'foreign, stale or incomplete exact-stage admission')
    info = SUFFIX.stat()
    require(SUFFIX.resolve(strict=True) == SUFFIX and stat.S_ISDIR(info.st_mode) and info.st_uid == 1000
            and stat.S_IMODE(info.st_mode) == 0o700 and not any(SUFFIX.iterdir()), 'suffix root is not fresh and private')
    current = os.statvfs(SUFFIX)
    require(current.f_bavail * current.f_frsize >= floor + peak, 'live free bytes fell below the issued admission')
    return {'schema': PLAN_SCHEMA, 'epoch': 226, 'producer_unit': SUFFIX_UNIT, 'node_sha256': node['sha256'],
            'admission': pin(admission_ref), 'run_root': str(SUFFIX), 'minimum_free_bytes': floor + peak, 'stage': stage}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('verify-static', 'bind', 'emit-plan'))
    parser.add_argument('--extraction', choices=LAUNCHES, default='v2')
    parser.add_argument('--admission', nargs=2, metavar=('PATH', 'SHA256'))
    parser.add_argument('--seal-handoff', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'run with root read and sealed-custody permissions')
    require((args.operation == 'emit-plan') == bool(args.admission), 'only emit-plan accepts external admission evidence')
    require(not args.seal_handoff or args.operation == 'bind', 'only bind can seal the successful handoff')
    prep, launch, extract_plan, static = static_inputs(
        full=args.operation == 'verify-static', extraction=args.extraction)
    result = static
    if args.operation != 'verify-static':
        result = bind_static_to_output(prep, launch, extract_plan, static, LAUNCHES[args.extraction])
    if args.seal_handoff:
        # Outside the native node's writable generation; consumed by the scoped Rust drain.
        payload = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
        result = durable_seal(HANDOFF, payload)
    if args.operation == 'emit-plan':
        path, sha = args.admission
        ref = {'path': path, 'sha256': sha}
        result = plan_from_admission(result, ref, document(ref))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(f'epoch 226 handoff: {error}') from error
