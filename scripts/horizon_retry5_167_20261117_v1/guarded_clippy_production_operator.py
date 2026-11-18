"""One-shot operator for the already admitted, Rust-gated retry5 guard graph."""

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

BASE = pathlib.Path('/var/lib/jetstreamer/epoch167-retry5-live166-20261117-v1/build-preparation-v2/clippy-production-v1')
DEFS = BASE / 'definitions-sealed/STATIC_DEFINITIONS.json'
DEFS_SHA = 'f743cf9f6d549746468f751f124dfa06a41f5b5a857f15200bf24094df78c5de'
PLAN = BASE / 'plan-sealed/plan.json'
PLAN_SHA = '61c00896cf158702c4d280a1216d9741b5ed07cfe1b3a25ef3648d1ad6567891'
SEALER = pathlib.Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')
SEALER_SHA = 'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
GATES = pathlib.Path('/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/gates')
UNIT = 'horizon-qualify-private183-holding-build-clippy-production-20261115-v7.service'
GUARD = 'horizon-guard-private183-holding-build-clippy-production-20261115-v7.service'
TIMER = 'horizon-guard-private183-holding-build-clippy-production-20261115-v7.timer'
IID = re.compile(r'^[0-9a-f]{32}$')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def binding(path):
    return {'path': str(path), 'sha256': sha(path.read_bytes())}


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return sha(raw)


def call(args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=20)


def props(unit, fields):
    result = call(['/usr/bin/systemctl', 'show', unit, '-p' + ','.join(fields), '--no-pager'])
    return dict(row.split('=', 1) for row in result.stdout.splitlines() if '=' in row)


NATIVE = ('Id', 'LoadState', 'ActiveState', 'SubState', 'InvocationID', 'MainPID',
          'ControlPID', 'NRestarts', 'Result', 'ExecMainStatus', 'Environment',
          'TimeoutStartUSec', 'MemoryMax', 'TasksMax', 'TriggeredBy', 'Job',
          'InactiveExitTimestampMonotonic', 'ExecStart', 'ExecStartPre')


def timer_clock():
    result = call(['/usr/bin/busctl', 'call', 'org.freedesktop.systemd1',
                   '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager',
                   'GetUnit', 's', TIMER]).stdout
    match = re.fullmatch(r'o "([^"]+)"\n', result)
    assert match and match.group(1).startswith('/org/freedesktop/systemd1/unit/')
    raw = call(['/usr/bin/busctl', 'get-property', 'org.freedesktop.systemd1',
                match.group(1), 'org.freedesktop.systemd1.Timer',
                'LastTriggerUSecMonotonic']).stdout
    match = re.fullmatch(r't ([0-9]+)\n', raw)
    assert match and int(match.group(1)) > 0
    return raw, match.group(1)


def timer_native():
    result = props(TIMER, ('Id', 'LoadState', 'ActiveState', 'SubState', 'InvocationID',
                           'Job', 'Result', 'TriggeredBy', 'Unit',
                           'InactiveExitTimestampMonotonic', 'LastTriggerUSecMonotonic'))
    result['LastTriggerUSecMonotonicDisplay'] = result['LastTriggerUSecMonotonic']
    raw, monotonic = timer_clock()
    result['LastTriggerUSecMonotonic'] = monotonic
    result['RawTimerClockReply'] = raw
    return result


def seal(source, name, destination, plan_path):
    plan = {'schema': 'jetstreamer-sealed-deployment-plan-v1',
            'destination': str(destination),
            'members': [{'source': str(source), 'name': name,
                         'sha256': sha(source.read_bytes()), 'mode': 292}]}
    plan_sha = save(plan_path, plan)
    assert sha(SEALER.read_bytes()) == SEALER_SHA
    env = dict(os.environ)
    env.pop('INVOCATION_ID', None)
    old_umask = os.umask(0o022)
    try:
        run = subprocess.run([str(SEALER), str(plan_path), '--plan-sha256', plan_sha,
                              '--self-sha256', SEALER_SHA], text=True, capture_output=True,
                             timeout=20, env=env)
    finally:
        os.umask(old_umask)
    assert run.returncode == 0, run.stderr
    assert destination.is_dir() and sha((destination / name).read_bytes()) == plan['members'][0]['sha256']
    return binding(destination / name)


def pid1_rows(start):
    result = call(['/usr/bin/journalctl', '--since', start, '-u', UNIT, '-u', GUARD,
                   '-o', 'json', '--no-pager'], check=False)
    rows = []
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append(row)
    assert rows, 'missing original PID1 journal rows'
    return rows


def run():
    assert os.geteuid() == 0 and sys.argv[1:] == []
    assert sha(DEFS.read_bytes()) == DEFS_SHA and sha(PLAN.read_bytes()) == PLAN_SHA
    static = json.loads(DEFS.read_bytes())
    plan = json.loads(PLAN.read_bytes())
    assert static['actor_argv'][0] == '/usr/bin/systemd-run'
    assert static['guard_timer_argv_unstarted'][0] == '/usr/bin/systemd-run'
    assert plan['actor_unit'] == UNIT and plan['guard_unit'] == GUARD and plan['guard_timer'] == TIMER
    assert not (GATES / 'ACTUAL_IID_REQUIRED').exists()
    assert props(UNIT, ('LoadState', 'ActiveState'))['LoadState'] == 'not-found'
    assert props(TIMER, ('LoadState', 'ActiveState'))['LoadState'] == 'not-found'
    assert props(GUARD, ('LoadState', 'ActiveState'))['LoadState'] == 'not-found'
    assert sha(pathlib.Path(static['compiler_recipe']['path']).read_bytes()) == static['compiler_recipe']['sha256']
    output = pathlib.Path(static['actor_argv'][static['actor_argv'].index('-o') + 1])
    assert not output.exists()
    start = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    before = props(TIMER, ('Id', 'LoadState', 'ActiveState', 'SubState', 'InvocationID',
                           'Job', 'Result', 'TriggeredBy', 'Unit',
                           'InactiveExitTimestampMonotonic', 'LastTriggerUSecMonotonic'))
    before['LastTriggerUSecMonotonic'] = '0'
    save(BASE / 'TIMER-BEFORE.json', before)

    actor_launched = False
    token_sealed = False
    try:
        launched = call(static['actor_argv'])
        assert launched.returncode == 0, launched.stderr
        actor_launched = True
        save(BASE / 'ACTOR-LAUNCH.json', {'code': launched.returncode,
                                          'stdout': launched.stdout, 'stderr': launched.stderr})
        deadline = time.monotonic() + 170
        while True:
            actor = props(UNIT, NATIVE)
            iid = actor.get('InvocationID', '')
            if IID.fullmatch(iid) and actor['ActiveState'] == 'activating' and actor['SubState'] == 'start-pre':
                break
            assert time.monotonic() < deadline, 'actor did not enter start-pre'
            time.sleep(.1)
        assert actor['MainPID'] == '0' and actor['NRestarts'] == '0' and int(actor['ControlPID']) > 1
        timer_argv = [iid if v == 'ACTUAL_IID_REQUIRED' else v
                      for v in static['guard_timer_argv_unstarted']]
        assert timer_argv.count(iid) == 1 and 'ACTUAL_IID_REQUIRED' not in timer_argv
        save(BASE / 'GUARD-TIMER-ACTUAL-ARGV.json', timer_argv)
        armed = call(timer_argv)
        assert armed.returncode == 0, armed.stderr
        save(BASE / 'GUARD-TIMER-LAUNCH.json', {'code': armed.returncode,
                                                'stdout': armed.stdout, 'stderr': armed.stderr})
        receipt_dir = BASE / 'guard-receipts'
        while True:
            paths = list(receipt_dir.glob('sample-*.json'))
            assert len(paths) <= 1, 'more than one first guard sample'
            if paths:
                try:
                    receipt = json.loads(paths[0].read_bytes())
                except json.JSONDecodeError:
                    receipt = None
                if receipt is not None:
                    break
            assert time.monotonic() < deadline, 'first timer guard did not finish before deadline'
            time.sleep(.1)
        assert receipt['schema'] == 'jetstreamer-horizon-build-guard-sample-v1'
        assert receipt['actor_invocation_id'] == iid and receipt['unit'] == UNIT
        assert receipt['trip'] is False and receipt['native_owner_stable'] is True
        assert receipt['minimum_free_bytes'] == plan['minimum_free_bytes']
        assert receipt['maximum_root_bytes'] == plan['maximum_root_bytes']
        assert paths[0].name == 'sample-' + receipt['guard_invocation_id'] + '.json'
        while True:
            first_guard = props(GUARD, NATIVE)
            if (first_guard['InvocationID'] == receipt['guard_invocation_id']
                    and first_guard['Result'] == 'success'
                    and first_guard['ExecMainStatus'] == '0'
                    and first_guard['ActiveState'] == 'inactive'):
                break
            assert time.monotonic() < deadline, 'first timer guard did not exit successfully'
            time.sleep(.1)
        first_actor = props(UNIT, NATIVE)
        first_timer = timer_native()
        assert first_actor['InvocationID'] == iid and first_actor['SubState'] == 'start-pre'
        assert first_actor['MainPID'] == '0' and first_actor['NRestarts'] == '0'
        assert first_guard['InvocationID'] == receipt['guard_invocation_id']
        assert first_guard['Result'] == 'success' and first_guard['ExecMainStatus'] == '0'
        assert first_timer['ActiveState'] == 'active' and first_timer['Unit'] == GUARD
        assert int(first_timer['LastTriggerUSecMonotonic']) > 0
        first = {'actor': first_actor, 'guard': first_guard, 'timer': first_timer,
                 'receipt': binding(paths[0]), 'no_manual_guard_execution': True}
        save(BASE / 'FIRST_TIMER_GUARD_NATIVE.json', first)
        journal = {'native': first, 'PID1': pid1_rows(start),
                   'original_timer_baseline': binding(BASE / 'TIMER-BEFORE.json'),
                   'exact_timer_launch': binding(BASE / 'GUARD-TIMER-LAUNCH.json')}
        journal_path = BASE / 'journal.json'
        save(journal_path, journal)
        sealed_journal = seal(journal_path, 'journal.json', BASE / 'journal-sealed',
                              BASE / 'JOURNAL-SEAL-PLAN.json')
        token = {'schema': 'private183-holding-build-prestart-token-v1',
                 'owner': '/root', 'actor_unit': UNIT, 'actor_invocation_id': iid,
                 'actor_control_pid': int(first_actor['ControlPID']),
                 'plan_sha256': PLAN_SHA, 'metadata_control': False,
                 'phase': 'clippy-production', 'admission': plan['admission'],
                 'first_timer_driven_guard': True, 'journal_evidence': sealed_journal,
                 'replay_admission_authorized': False, 'publication_authorized': False,
                 'guard_receipt': binding(paths[0]),
                 'guard_invocation_id': first_guard['InvocationID'],
                 'guard_timer_invocation_id': first_timer['InvocationID'],
                 'timer_last_trigger_usec': int(first_timer['LastTriggerUSecMonotonic']),
                 'timer_baseline_last_trigger_usec': 0,
                 'actor_activation_monotonic_usec': int(first_actor['InactiveExitTimestampMonotonic'])}
        token_path = BASE / 'token.json'
        save(token_path, token)
        sealed_token = seal(token_path, 'token.json', GATES / iid, BASE / 'TOKEN-SEAL-PLAN.json')
        token_sealed = True
        save(BASE / 'SEQUENCE-COMPLETED.json', {'actor_invocation_id': iid,
                                                'first_timer_guard': binding(BASE / 'FIRST_TIMER_GUARD_NATIVE.json'),
                                                'token': sealed_token, 'compiler_output': str(output),
                                                'replay_launch_authorized': False})
        print(json.dumps({'actor_invocation_id': iid, 'timer_guard': 'passed',
                          'token_sealed': True, 'compiler_output': str(output)}))
    except BaseException as exc:
        try:
            save(BASE / 'SEQUENCE-FAILURE.json', {'error': repr(exc),
                                                   'actor_launched': actor_launched,
                                                   'token_sealed': token_sealed,
                                                   'actor': props(UNIT, ('LoadState', 'ActiveState', 'SubState', 'InvocationID')),
                                                   'guard': props(GUARD, ('LoadState', 'ActiveState', 'SubState', 'InvocationID'))})
        except BaseException:
            pass
        if actor_launched and not token_sealed:
            subprocess.run(['/usr/bin/systemctl', 'stop', TIMER, UNIT], capture_output=True, timeout=20)
        raise


if __name__ == '__main__':
    run()
