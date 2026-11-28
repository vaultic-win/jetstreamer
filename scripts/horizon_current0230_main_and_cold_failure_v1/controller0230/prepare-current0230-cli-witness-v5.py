from pathlib import Path
import os, json, hashlib, subprocess, re
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0230-20261109-v1'
sha = lambda b: hashlib.sha256(b).hexdigest()

def b(f):
    f = Path(f)
    return dict(path=str(f), sha256=sha(f.read_bytes()))

def save(n, v):
    if n=='ROOT_GENUINE_FLEET_SUCCESS_FOR_CLI.json' and (p/n).exists():
        assert json.loads((p/n).read_text())==v, 'Original prepared fleet metadata differs; no overwrite'
        return
    fd = os.open(p / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def native(u):
    return dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', u, '-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,ControlGroup,NRestarts,Result,ExecMainStatus,ExecMainPID'], text=True).splitlines()))
fu = 'horizon-first-lane-current0230-fleet-20261109-v1.service'
fn = native(fu)
assert fn['InvocationID'] == json.loads((p / 'ROOT_CURRENT0230_FLEET_ORIGINAL_SUCCESS.json').read_text())['native']['InvocationID'] and fn['Result'] == 'success' and (fn['ExecMainStatus'] == fn['MainPID'] == fn['ControlPID'] == fn['NRestarts'] == '0') and (fn['ActiveState'] == 'active') and (fn['SubState'] == 'exited')
fp = Path('/usr/local/lib/jetstreamer/horizon-first-lane-current0230-fleet-plan-20261109-v1/fleet-plan.json')
fleetplan = json.loads(fp.read_text())
fleet = Path(fleetplan['output'])
fv = json.loads(fleet.read_text())
assert fv['plan_sha256'] == b(fp)['sha256']
save('ROOT_GENUINE_FLEET_SUCCESS_FOR_CLI.json', dict(native=fn, fleet=b(fleet), plan=b(fp), no_replay_or_credit=True))
old = Path('/usr/local/lib/jetstreamer/horizon-first-lane-current0100-chain128-frame-plan-20261109-v5/plan.json')
v = json.loads(old.read_text())
prior = Path('/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261109T010022-witness-terminal145-chain128-v5.json')
pv = json.loads(prior.read_text())
assert b(prior)['sha256'] == '4a9b82ae94e16fac25d394ab79a9f3aaf20a76b624da532ce9d836e9611b559c', 'Actual0100 Frame predecessor crossed'
priorplan = Path('/usr/local/lib/jetstreamer/horizon-first-lane-current0100-fleet-plan-20261109-v1/fleet-plan.json')
o = Path(fleetplan['observer']['path'])
on = native('horizon-visible-primary-observer023022-20261109-v1.service')
assert on['Result'] == 'success' and on['ExecMainStatus'] == on['MainPID'] == on['ControlPID'] == on['NRestarts'] == '0'
assert fv['previous_fleet'] == pv['bindings']['fleet'] and fleetplan['previous_fleet'] == pv['bindings']['fleet'] and (b(priorplan) == pv['bindings']['fleet_plan'])
t = json.loads(Path(v['cohort183_transition']['path']).read_text())
bridge_chain = [{'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T013022Z-postcompletion154-v1.json', 'sha256': 'fa22ccada8e92460fa52cdbf7fd9ef7184db3e6a1eaef2a8da10706999976ab6'}}, {'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T020022Z-postcompletion154-v1.json', 'sha256': 'e3fc848255d438d473e059cff501b7c62ff7b256ddb3a81645129fe747ff6b1a'}}]
previous_observer = pv['bindings']['observer']
for bridge_row in bridge_chain:
    binding = bridge_row['observer']
    value = json.loads(Path(binding['path']).read_text())
    assert b(Path(binding['path'])) == binding
    assert value['cadence']['previous_sample'] == previous_observer['path'] and value['cadence']['previous_sample_sha256'] == previous_observer['sha256']
    assert value['cadence']['observed_interval_seconds'] == 1800
    assert Path(binding['path']).stat().st_mode & 0o222 == 0, 'Root exact closed observer readonly finalization required for both0130 and0200 bridges'
    previous_observer = binding
assert json.loads(o.read_text())['cadence']['previous_sample'] == previous_observer['path'] and json.loads(o.read_text())['cadence']['previous_sample_sha256'] == previous_observer['sha256']
t.update(previous_recovery=b(prior), previous_cohort183_transition=pv['bindings']['cohort183_transition'], prior_fleet_plan=b(priorplan), fleet_plan=b(fp))
t['observation_bridge'] = bridge_chain
save('transition-v4.json', t)
dest = '/usr/local/lib/jetstreamer/horizon-first-lane-current0230-chain128-frame-plan-20261109-v5'
v.update(observer=b(o), fleet=b(fleet), fleet_plan=b(fp), prior_recovery=b(prior), prior_fleet_plan=b(priorplan), observer_owner=dict(unit=on['Id'], invocation_id=on['InvocationID']), fleet_owner=dict(unit=fn['Id'], invocation_id=fn['InvocationID']), cohort183_transition=dict(path=dest + '/transition.json', sha256=sha((p / 'transition-v4.json').read_bytes())), output='/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261109T023022-witness-terminal145-chain128-v5.json')
save('frame-plan-v4.json', v)
plan = dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=dest, members=[dict(source=str(p / a), name=n, sha256=sha((p / a).read_bytes()), mode=292) for a, n in [('frame-plan-v4.json', 'plan.json'), ('transition-v4.json', 'transition.json')]])
save('FRAME5-SEAL-PLAN.json', plan)
sealer = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
h = re.search("h='([a-f0-9]{64})'", Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1)
assert sha(Path(sealer).read_bytes()) == h
os.umask(18)
z = subprocess.run([sealer, str(p / 'FRAME5-SEAL-PLAN.json'), '--plan-sha256', sha((p / 'FRAME5-SEAL-PLAN.json').read_bytes()), '--self-sha256', h], capture_output=True, text=True)
save('FRAME5-SEAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
assert z.returncode == 0, z.stderr
cli = '/usr/local/lib/jetstreamer/horizon-first-lane-chain128-witness-frame-cli-tools-20261107-v5/jetstreamer-horizon-frame'
ch = '70b82a16f8c5d71257305a0873440deccf8746f78b09fc33ee23f5c691e29fe4'
assert b(Path(cli))['sha256'] == ch
f = Path(dest) / 'plan.json'
cmd = [cli, str(f), '--plan-sha256', b(f)['sha256'], '--self-sha256', ch]
