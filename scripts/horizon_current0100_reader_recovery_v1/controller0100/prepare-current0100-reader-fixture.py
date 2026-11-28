from pathlib import Path
import json, hashlib, os
q = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1')
p = q / 'current0100-20261109-v1'
old = q / 'current0000-20261109-v1'
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
a = json.loads((old / 'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json').read_text())
current = json.loads((p / 'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json').read_text())
keys = ['observer', 'fleet', 'fleet_plan', 'frame']
counts = {k: 0 for k in keys}

def replace(v):
    if isinstance(v, dict):
        for k in keys:
            if v == a[k]:
                counts[k] += 1
                return current[k]
        return {k: replace(x) for k, x in v.items()}
    if isinstance(v, list):
        return [replace(x) for x in v]
    return v
fixture = replace(json.loads((old / 'GENUINE0000_ACCOUNTING_ADAPTER_SOURCE_BUNDLE.json').read_text()))
assert all((counts[k] > 0 for k in keys)), counts
assert fixture['resource_accounting']['live145_prefix_export']['terminal_retained'] is True
save('GENUINE0100_ACCOUNTING_ADAPTER_SOURCE_BUNDLE.json', fixture)
manifest = dict(reader_spec=b(p / 'GENUINE0100_ACCOUNTING_ADAPTER_SOURCE_BUNDLE.json'), frame=current['frame'], reader_spec_role='Static accounting Sources fixture only; production adapter at original capture clock; no operational full-reader activation')
save('GENUINE0100_OUTER_ADAPTER_FIXTURE_MANIFEST.json', manifest)
save('ROOT_GENUINE0100_EXACT_FIXTURE_REBINDING.json', dict(prior_acceptance=b(old / 'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json'), current_acceptance=b(p / 'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json'), counts=counts, fixture=b(p / 'GENUINE0100_ACCOUNTING_ADAPTER_SOURCE_BUNDLE.json'), manifest=b(p / 'GENUINE0100_OUTER_ADAPTER_FIXTURE_MANIFEST.json'), native_reader_clock_started=False, replay_launch_authorized=False))
print(manifest, flush=True)
