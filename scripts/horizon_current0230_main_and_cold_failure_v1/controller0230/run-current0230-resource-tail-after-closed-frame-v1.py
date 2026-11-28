from actual0100_predecessors import actual0100_predecessors
actual0100_predecessors()
from successful0100_reader_dependency import require_qualified0100_reader_retirement
require_qualified0100_reader_retirement()
from pathlib import Path
import json, os, subprocess, time
packet = Path(__file__).resolve().parent
sample = Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T023022Z-postcompletion154-v1.json')
v = json.loads(sample.read_text())
assert v['recorded_at_utc'] == '2026-11-09T02:30:22Z' and v['cadence']['observed_interval_seconds'] == 1800
assert int(time.time()) + 900 < 1794191422 + 1800, 'Original startup budget cannot fund600s hold plus margin'
from next_operation_bindings import next_operation_bindings
next_operation_bindings()
from qualified_bindings import current_guard
current_guard()
root = packet / 'RESOURCE_TAIL_OPERATOR_ORIGINALS'
root.mkdir(mode=448)

def save(n, v):
    fd = os.open(root / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as h:
        json.dump(v, h, indent=2)
        h.flush()
        os.fsync(h.fileno())
steps = ['capture-current0230-fleet.py', 'prepare-current0230-cli-witness-v5.py', 'execute-current0230-cli-witness-v5-observer-bridges-r5.py', 'finalize-current0230-exact-metadata-observer-bridges-r5.py', 'prepare-current0230-reader-fixture.py', 'check-current0230-helper27-genuine-outer-v1.py', 'revalidate-helper27-current0230-normal-pool-v1.py', 'bind-actual0230-qualified-metadata-v1.py', 'prepare-current0230-continuations-v1.py', 'run-current0230-reader13-parent-v4.py', 'prepare-positive185-current0230-reviewed-metadata-v1.py', 'invoke-positive185-current0230-next-operation-v1.py']
accepted = Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0230-20261109-v1/ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json')
assert accepted.exists(), 'Complete genuine0230 Frame prefix required before resource tail'
steps = steps[4:]
for i, name in enumerate(steps):
    argv = ['/usr/bin/python3', str(packet / name)]
    save(f'{i:02}-ARGV.json', argv)
    print('BEGIN', name, flush=True)
    z = subprocess.run(argv, text=True, capture_output=True, timeout=2400)
    save(f'{i:02}-EXECUTION.json', dict(argv=argv, code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    print(name, z.returncode, z.stdout, z.stderr, flush=True)
    assert z.returncode == 0, (name, z.returncode)
