"""Return only idle compute from the exact closed second epoch 143 interval."""
from pathlib import Path
import re
import subprocess

RT = Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT = RT/'epoch143-second-hourly-20261128-v5'
IID = '004593b7e31f4568b153befabbd4e0c9'
TERMINAL = dict(path=str(ROOT/f'terminal-{IID}/NATIVE_TERMINAL.json'),
                sha256='067d00412a8ab2e8d6e88a5f72e1d7c9ec826e18705f5d3d16581ee6681455e9')
UNIT = 'horizon-qualify-143-second-hourly-20261128-v2.service'
MASK = Path('/run/systemd/system')/UNIT
RETURN = ROOT/'compute-return-v1/COMPUTE_RETURN.json'
AUTHORITY = None
GIB = 1 << 30
FULL = 41 * GIB
READER = 5 * GIB
RETURNED = FULL - READER


def observation(core, fleet, closed, *, masked):
    need, bound, state = (core[k] for k in ('need','bound','state'))
    terminal = bound(TERMINAL)
    row = fleet['current_private143_second_hourly_ram_retry']
    actor = bound(terminal['producer'])
    booking = bound(actor['booking'])
    need(closed['original_second_success'] == TERMINAL and closed['retained_ram'] == FULL
         and closed['retained_home'] == 64 * GIB + (64 << 20)
         and closed['cpu_quota_micros'] == 3_000_000 and not closed['resource_credit_bytes']
         and row['phase'] == 'terminal' and row['held_owner'] == terminal['producer']
         and row['native_terminal']['cursor'] == terminal['terminal_cursor']
         and actor == row['actor'] and actor['producer_invocation_id'] == terminal['invocation_id'] == IID
         and actor['unit'] == terminal['unit'] == UNIT and booking['RAM_bytes'] == FULL
         and booking['HOME_bytes'] == closed['retained_home'] and booking['cpu_quota_micros'] == 3_000_000,
         'different closed epoch 143 compute booking')
    for key in ('actual_executing_replays','actual_active_bootstraps','actual_active_private_diagnostics'):
        need(not any(item['epoch'] == 143 for item in fleet[key]), 'active epoch 143 fleet claim')
    configured = bound(fleet['sole_next_observer'])
    for item in configured['diagnostic_replays']:
        numbers = [int(value) for value in re.findall(r'\d+', item['range'])]
        need(numbers and not min(numbers) <= 143 <= max(numbers)
             and not re.search(r'(?:^|-)143(?:-|\.)', item['producer_unit']), 'scheduled epoch 143 successor')
    executions = subprocess.check_output(['/usr/bin/systemctl','list-units','--all','--plain','--no-legend',
        '--type=service,timer,path','--state=running,activating,deactivating,waiting','horizon*143*'],text=True,timeout=15)
    jobs = subprocess.check_output(['/usr/bin/systemctl','list-jobs','--plain','--no-legend'],text=True,timeout=15)
    epoch_unit = re.compile(r'^horizon-(?:.*-)?143(?:-|\.)')
    live = [line.split()[0] for line in executions.splitlines() if line.split() and epoch_unit.match(line.split()[0])]
    pending = [line.split()[1] for line in jobs.splitlines() if len(line.split()) > 1 and epoch_unit.match(line.split()[1])]
    need(not live and not pending, 'a native epoch 143 job still owns compute')
    properties = state(UNIT, 'Id,LoadState,ActiveState,MainPID,ControlPID,ControlGroup,Job,FragmentPath')
    need(properties['Id'] == UNIT and properties['ActiveState'] == 'inactive' and not properties['Job']
         and not properties['ControlGroup'] and properties['MainPID'] == properties['ControlPID'] == '0',
         'legacy epoch 143 unit is still occupied')
    if masked:
        need(MASK.is_symlink() and MASK.readlink() == Path('/dev/null') and MASK.lstat().st_uid == 0
             and properties['LoadState'] == 'masked' and properties['FragmentPath'] == str(MASK),
             'legacy epoch 143 execution exclusion changed')
    else:
        need(not MASK.exists() and not MASK.is_symlink() and properties['LoadState'] == 'not-found',
             'existing native unit exclusion or definition')
    return dict(producer=terminal['producer'], booking=actor['booking'], terminal=TERMINAL,
                unit=properties, physical_disk_release_bytes=0)


def charge(core, fleet, closed, replacement):
    need, bound = core['need'],core['bound']
    need(replacement is None and AUTHORITY and AUTHORITY['path'] == str(RETURN),
         'epoch 143 replay needs an explicit compute return withdrawal and new admission')
    authority = bound(AUTHORITY)
    actual = observation(core, fleet, closed, masked=True)
    need(authority['schema'] == 'horizon-143-idle-compute-return-v1'
         and authority['native'] == actual and authority['returned_ram'] == RETURNED
         and authority['retained_ram'] == READER and authority['retained_cpu_quota_micros'] == 3_000_000
         and authority['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
         and authority['separate_reader_admission_required'] and not authority['archive_publication_authorized'],
         'different epoch 143 compute return or boot')
    return dict(authority=AUTHORITY, returned_ram=RETURNED, retained_ram=READER, physical_disk_release_bytes=0)
