from pathlib import Path
import json, os, subprocess, re, hashlib
base = Path('/home/sol/.jetstreamer-private')
prev = base / 'visible-primary-next-observer-000022-20261109-v1'
nxt = base / 'visible-primary-next-observer-003022-20261109-v1'
nxt.mkdir(mode=448, exist_ok=True)
assert not list(nxt.iterdir()), 'Original preparation directory must still be empty; no runtime arm or sealed plan may be retried'
sample = Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T000022Z-postcompletion154-v1.json')
v = json.loads(sample.read_text())
assert v['recorded_at_utc'] == '2026-11-09T00:00:22Z' and v['cadence']['observed_interval_seconds'] == 1800

def save(n, v):
    fd = os.open(nxt / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as f:
        json.dump(v, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
sha = lambda f: hashlib.sha256(Path(f).read_bytes()).hexdigest()
cfg = json.loads((prev / 'observer.json').read_text())
cfg.update(not_before_utc='2026-11-09T00:30:22Z', previous_sample=str(sample), output='/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T003022Z-postcompletion154-v1.json')
save('observer.json', cfg)
dest = '/usr/local/lib/jetstreamer/horizon-visible-primary-observer-003022-plan-20261109-v1'
save('SEAL-PLAN.json', dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=dest, members=[dict(source=str(nxt / 'observer.json'), name='observer.json', sha256=sha(nxt / 'observer.json'), mode=292)]))
s = '/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment'
h = re.search("h='([a-f0-9]{64})'", Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1)
assert sha(s) == h
os.umask(18)
z = subprocess.run([s, str(nxt / 'SEAL-PLAN.json'), '--plan-sha256', sha(nxt / 'SEAL-PLAN.json'), '--self-sha256', h], capture_output=True, text=True)
save('SEAL-EXECUTION.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
assert z.returncode == 0, z.stderr
argv_updates = {'--unit=horizon-visible-primary-observer000022-20261109-v1': '--unit=horizon-visible-primary-observer003022-20261109-v1', '--on-calendar=2026-11-09 00:00:22 UTC': '--on-calendar=2026-11-09 00:30:22 UTC', '/usr/local/lib/jetstreamer/horizon-visible-primary-observer-000022-plan-20261109-v1/observer.json': '/usr/local/lib/jetstreamer/horizon-visible-primary-observer-003022-plan-20261109-v1/observer.json'}
original_argv = json.loads((prev / 'ORIGINAL_PREWRITTEN_ARGV.json').read_text())
assert all(original_argv.count(k) == 1 for k in argv_updates)
a = [argv_updates.get(x, x) for x in original_argv]
assert '--on-calendar=2026-11-09 00:30:22 UTC' in a
assert '--unit=horizon-visible-primary-observer003022-20261109-v1' in a
save('ORIGINAL_PREWRITTEN_ARGV.json', a)
z = subprocess.run(a, capture_output=True, text=True)
save('ORIGINAL_LAUNCH.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
assert z.returncode == 0, z.stderr
print('Next sole normal observer armed for Nov9 00:30:22 UTC; Nov9 00:00 predecessor retained.', flush=True)
