from pathlib import Path
import json, os, hashlib, subprocess, re
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0430-20261109-v1'
o = Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T043022Z-postcompletion154-v1.json')
v = json.loads(o.read_text())
assert v['recorded_at_utc'] == '2026-11-09T04:30:22Z' and v['cadence']['observed_interval_seconds'] == 1800
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
old = Path('/usr/local/lib/jetstreamer/horizon-first-lane-current0230-fleet-plan-20261109-v1/fleet-plan.json')
fp = json.loads(old.read_text())
prev = Path(fp['output'])
assert prev.stat().st_mode & 146 == 0
fp.update(observer=b(o), previous_fleet=b(prev), output='/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261109T043022Z-witness-terminal145-v1.json')
# Add exact observed0230 terminal history and actual new repair qualifications,
# preserving every older gate, raw promise and tracked service.
for unit in ['horizon-qualify-185-capped-cold-positive-positive-0230-20261109-next.service','horizon-guard-185-capped-cold-positive-positive-0230-20261109-next.service','horizon-positive185-original-actual0230-r3-20261109-next.service']:
    if unit not in fp['tracked_units']:fp['tracked_units'].insert(len(fp['tracked_units'])-3,unit)
old185=dict(fp['gates']['185']);evidence=list(old185['evidence'])
for path in ['/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2/da9b57fed9f04c9fa1b0c5dba1932488/terminal.json','/home/sol/.jetstreamer-private/epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_ACTUAL_QUALIFIED_OPERATION38_BINDINGS.json','/home/sol/.jetstreamer-private/epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_ACTUAL_EXACT0230_SUCCESSFUL_READER_RETIRED.json','/home/sol/.jetstreamer-private/current0430-guard-window-booking-20261109-v1/ROOT_NORMAL6_CURRENT0430_GUARD_DATA512_BOOKING.json']:
    binding=b(Path(path));assert binding['path'] not in {r['path']for r in evidence};evidence.append(binding)
fp['gates']['185']=dict(old185,evidence=evidence,next_action=old185['next_action']+' Latest0230actor reached Main then failed cold initialization with its own resource census ENOENT; actual drained terminal and zeroOOM evidence retained. Driver12 storage race repair, Helper35, Planner6, Final6 and Operation38 are now qualified/sealed; exact0230successfulreader aliases retired without payload/resourcecredit. Continue fresh current Frame/reader/accounting/guard/admission through actual worker execution. Full185route remains unqualified; no oldclock renewal or archive/publication authority.')
assert fp['gates']['185']['state']==old185['state']=='failed-needs-repair'
save('fleet-plan-r2.json', fp)
dest = '/usr/local/lib/jetstreamer/horizon-first-lane-current0430-fleet-plan-20261109-v1-r2'
save('FLEET-R2-SEAL-PLAN.json', dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=dest, members=[dict(source=str(p / 'fleet-plan-r2.json'), name='fleet-plan.json', sha256=sha((p / 'fleet-plan-r2.json').read_bytes()), mode=292)]))
s = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
h = re.search("h='([a-f0-9]{64})'", Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1)
assert sha(Path(s).read_bytes()) == h
os.umask(18)
z = subprocess.run([s, str(p / 'FLEET-R2-SEAL-PLAN.json'), '--plan-sha256', sha((p / 'FLEET-R2-SEAL-PLAN.json').read_bytes()), '--self-sha256', h], capture_output=True, text=True)
save('FLEET-R2-SEAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
assert z.returncode == 0, z.stderr
file = Path(dest) / 'fleet-plan.json'
a = json.loads((q / 'current1930-r2/FLEET-R2-ORIGINAL-ARGV.json').read_text())
a = [x for x in a if x not in ['--wait', '--pipe']]
a = [x.replace('horizon-first-lane-current1930-r2-fleet-20261107-v1.service', 'horizon-first-lane-current0430-fleet-20261109-v1-r2.service').replace('/usr/local/lib/jetstreamer/horizon-first-lane-current1930-r2-fleet-plan-20261107-v1/fleet-plan.json', str(file)).replace('CPUQuota=100%', 'CPUQuota=200%') for x in a]
i = next((i for i, x in enumerate(a) if x.endswith('/jetstreamer-r2')))
a[i:i] = ['-p', 'StandardOutput=file:' + str(p / 'fleet-r2.stdout'), '-p', 'StandardError=file:' + str(p / 'fleet-r2.stderr')]
a[a.index('--plan-sha256') + 1] = b(file)['sha256']
save('FLEET-R2-ORIGINAL-ARGV.json', a)
z = subprocess.run(a, capture_output=True, text=True, timeout=330)
save('FLEET-R2-ORIGINAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print(z.returncode, (p / 'fleet-r2.stderr').read_text()[-4000:], z.stderr[-800:], flush=True)
assert z.returncode == 0
unit = 'horizon-first-lane-current0430-fleet-20261109-v1-r2.service'
n = dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', unit, '-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup'], text=True).splitlines()))
assert n['Result'] == 'success' and n['ExecMainStatus'] == n['MainPID'] == n['ControlPID'] == n['NRestarts'] == '0' and (n['SubState'] == 'exited')
rows = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '-u', unit], text=True).splitlines()]
assert any((x.get('_PID') == '1' and x.get('_UID') == '0' and (x.get('INVOCATION_ID') == n['InvocationID']) and (x.get('JOB_RESULT') == 'done') for x in rows))
save('ROOT_CURRENT0430_FLEET_R2_ORIGINAL_SUCCESS.json', dict(native=n, fleet=b(Path(fp['output'])), fleet_plan=b(file), observer=b(o), original_PID1=rows, original_outer_reaped=True, original_cgroup_empty=n['ControlGroup'] == '', replay_launch_authorized=False))
print('GENUINE0430FLEET', n['InvocationID'], flush=True)
