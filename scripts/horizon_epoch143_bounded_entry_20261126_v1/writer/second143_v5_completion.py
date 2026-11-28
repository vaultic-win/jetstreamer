"""Reconcile the exact closed V5 epoch 143 interval in the shared price."""
from hashlib import sha256
import json
from pathlib import Path
import stat

ROOT = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch143-second-hourly-20261128-v5')
IID = '004593b7e31f4568b153befabbd4e0c9'
UNIT = 'horizon-qualify-143-second-hourly-20261128-v2.service'
GUARD = 'horizon-guard-143-second-hourly-20261128-v5'
ARCHIVE = Path('/home/sol/.jetstreamer-private/epoch143-second-hourly-20261128-v1/epoch-143-through-61794627.jet')
FIELD = 'current_private143_second_hourly_ram_retry'
TERMINAL = dict(path=str(ROOT/f'terminal-{IID}/NATIVE_TERMINAL.json'),
                sha256='067d00412a8ab2e8d6e88a5f72e1d7c9ec826e18705f5d3d16581ee6681455e9')


def closed(core, fleet):
    need, state, read, bound = (core[key] for key in ('need', 'state', 'read', 'bound'))
    result = bound(TERMINAL)
    actor, actor_ref = read(ROOT/'HELD_OWNER.json')
    row = fleet[FIELD]
    native_exit = bound(result['pid1_exit'])
    properties = native_exit['properties']
    progress = bound(result['first_progress'])
    manifest_path = ARCHIVE.with_suffix('.jet.segment.json')
    need(str(ARCHIVE) == result['archive']['path'] and ARCHIVE.resolve(strict=True) == ARCHIVE
         and str(manifest_path) == result['segment_manifest']['path']
         and manifest_path.resolve(strict=True) == manifest_path, 'different closed epoch 143 paths')
    native_archive = ARCHIVE.lstat()
    try:
        with manifest_path.open('rb') as source:
            body = source.read(1 << 20)
    except OSError as error:
        raise ValueError('cannot read the closed epoch 143 manifest') from error
    need(sha256(body).hexdigest() == result['segment_manifest']['sha256'], 'different closed epoch 143 manifest')
    manifest = json.loads(body)
    need(result['schema'] == 'horizon-epoch143-v5-native-terminal-capture-v1'
         and result['disposition'] == 'native-complete-private-interval'
         and result['unit'] == actor['unit'] == row['unit']['Id'] == UNIT
         and result['invocation_id'] == actor['producer_invocation_id'] == properties['InvocationID'] == IID
         and result['producer'] == row['held_owner'] == actor_ref and row['actor'] == native_exit['actor'] == actor
         and result['guard_plan'] == actor['guard_plan']
         and progress['producer_invocation_id'] == IID and progress['producer_pid'] == actor['producer_pid']
         and row['phase'] in ('worker', 'terminal')
         and result['terminal_slot'] == manifest['terminal']['slot'] == 61794627
         and manifest['output_slot_start'] == 61787632 and manifest['output_slot_count'] == 6996
         and manifest['archive_sha256'] == result['archive']['sha256']
         and stat.S_ISREG(native_archive.st_mode) and native_archive.st_nlink == 1
         and native_archive.st_size == result['archive_bytes'] == 1759789770
         and not ARCHIVE.with_suffix('.jet.sha256').exists()
         and result['stop_intent'] is result['stop_completion'] is None
         and not result['archive_publication_authorized'] and not result['resource_credit_bytes']
         and (properties['Result'], properties['ExecMainCode'], properties['ExecMainStatus']) == ('success','1','0')
         and properties['MainPID'] == properties['ControlPID'] == '0'
         and properties['ExecMainPID'] == str(actor['producer_pid']),
         'different private epoch 143 completed owner')
    if row['phase'] == 'worker':
        need(row['first_progress'] == result['first_progress'], 'accepted epoch 143 progress changed')
    else:
        need(row['native_terminal']['invocation_id'] == IID
             and row['native_terminal']['cursor'] == result['terminal_cursor'],
             'accepted epoch 143 terminal differs from the native exit')
    for unit in (UNIT, GUARD+'.service', GUARD+'.timer'):
        fields = 'Id,ActiveState,Job'
        if unit.endswith('.service'):
            fields += ',MainPID,ControlPID,ControlGroup'
        current = state(unit, fields)
        need(current['Id'] == unit and current['ActiveState'] == 'inactive' and not current['Job']
             and not current.get('ControlGroup') and current.get('MainPID','0') == current.get('ControlPID','0') == '0'
             and not (Path('/sys/fs/cgroup/system.slice')/unit).exists(), 'epoch 143 owner has not drained')
    return TERMINAL
