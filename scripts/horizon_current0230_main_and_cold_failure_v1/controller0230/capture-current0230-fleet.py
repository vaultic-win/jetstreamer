from pathlib import Path
import json, os, hashlib, subprocess, re
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0230-20261109-v1'
o = Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T023022Z-postcompletion154-v1.json')
v = json.loads(o.read_text())
assert v['recorded_at_utc'] == '2026-11-09T02:30:22Z' and v['cadence']['observed_interval_seconds'] == 1800
for end in ['before', 'after']:
    assert v['host_resident_memory'][end]['status'] == 'observed' and v['host_resident_memory'][end]['rss']['census_stable'], ('Original current endpoint unavailable', end)
p.mkdir(mode=448, exist_ok=True)
sha = lambda b: hashlib.sha256(b).hexdigest()

def b(f):
    f = Path(f)
    return dict(path=str(f), sha256=sha(f.read_bytes()))

def save(n, v):
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
old = Path('/usr/local/lib/jetstreamer/horizon-first-lane-current0100-fleet-plan-20261109-v1/fleet-plan.json')
fp = json.loads(old.read_text())
prev = Path(fp['output'])
assert prev.stat().st_mode & 146 == 0
fp.update(observer=b(o), previous_fleet=b(prev), output='/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261109T023022Z-witness-terminal145-v1.json')
save('fleet-plan.json', fp)
dest = '/usr/local/lib/jetstreamer/horizon-first-lane-current0230-fleet-plan-20261109-v1'
save('FLEET-SEAL-PLAN.json', dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=dest, members=[dict(source=str(p / 'fleet-plan.json'), name='fleet-plan.json', sha256=sha((p / 'fleet-plan.json').read_bytes()), mode=292)]))
s = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
h = re.search("h='([a-f0-9]{64})'", Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1)
assert sha(Path(s).read_bytes()) == h
os.umask(18)
z = subprocess.run([s, str(p / 'FLEET-SEAL-PLAN.json'), '--plan-sha256', sha((p / 'FLEET-SEAL-PLAN.json').read_bytes()), '--self-sha256', h], capture_output=True, text=True)
save('FLEET-SEAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
assert z.returncode == 0, z.stderr
file = Path(dest) / 'fleet-plan.json'
a = json.loads((q / 'current1930-r2/FLEET-ORIGINAL-ARGV.json').read_text())
a = [x for x in a if x not in ['--wait', '--pipe']]
a = [x.replace('horizon-first-lane-current1930-r2-fleet-20261107-v1.service', 'horizon-first-lane-current0230-fleet-20261109-v1.service').replace('/usr/local/lib/jetstreamer/horizon-first-lane-current1930-r2-fleet-plan-20261107-v1/fleet-plan.json', str(file)).replace('CPUQuota=100%', 'CPUQuota=200%') for x in a]
i = next((i for i, x in enumerate(a) if x.endswith('/jetstreamer-r2')))
a[i:i] = ['-p', 'StandardOutput=file:' + str(p / 'fleet.stdout'), '-p', 'StandardError=file:' + str(p / 'fleet.stderr')]
a[a.index('--plan-sha256') + 1] = b(file)['sha256']
save('FLEET-ORIGINAL-ARGV.json', a)
z = subprocess.run(a, capture_output=True, text=True, timeout=330)
save('FLEET-ORIGINAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print(z.returncode, (p / 'fleet.stderr').read_text()[-4000:], z.stderr[-800:], flush=True)
assert z.returncode == 0
unit = 'horizon-first-lane-current0230-fleet-20261109-v1.service'
n = dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', unit, '-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup'], text=True).splitlines()))
assert n['Result'] == 'success' and n['ExecMainStatus'] == n['MainPID'] == n['ControlPID'] == n['NRestarts'] == '0' and (n['SubState'] == 'exited')
rows = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '-u', unit], text=True).splitlines()]
assert any((x.get('_PID') == '1' and x.get('_UID') == '0' and (x.get('INVOCATION_ID') == n['InvocationID']) and (x.get('JOB_RESULT') == 'done') for x in rows))
save('ROOT_CURRENT0230_FLEET_ORIGINAL_SUCCESS.json', dict(native=n, fleet=b(Path(fp['output'])), fleet_plan=b(file), observer=b(o), original_PID1=rows, original_outer_reaped=True, original_cgroup_empty=n['ControlGroup'] == '', replay_launch_authorized=False))
print('GENUINE0230FLEET', n['InvocationID'], flush=True)
