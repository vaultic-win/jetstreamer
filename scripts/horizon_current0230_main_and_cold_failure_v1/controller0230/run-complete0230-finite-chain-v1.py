import time as _time
assert _time.time() < 1794192322, 'Original0230 startup cutoff expired'
from pathlib import Path as _Path
import hashlib as _hashlib
_bridges = [{'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T013022Z-postcompletion154-v1.json', 'sha256': 'fa22ccada8e92460fa52cdbf7fd9ef7184db3e6a1eaef2a8da10706999976ab6'}}, {'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T020022Z-postcompletion154-v1.json', 'sha256': 'e3fc848255d438d473e059cff501b7c62ff7b256ddb3a81645129fe747ff6b1a'}}]
for _row in _bridges:
    _binding = _row['observer']; _path = _Path(_binding['path'])
    assert _path.stat().st_mode & 0o222 == 0, 'Root readonly finalization required for both actual bridge observers'
    assert _hashlib.sha256(_path.read_bytes()).hexdigest() == _binding['sha256']
from prelaunch_phase199_binding import qualified_prelaunch_phase
qualified_prelaunch_phase()
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
root = packet / 'OPERATOR_ORIGINALS'
root.mkdir(mode=448)

def save(n, v):
    fd = os.open(root / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    with os.fdopen(fd, 'w') as h:
        json.dump(v, h, indent=2)
        h.flush()
        os.fsync(h.fileno())
steps = ['capture-current0230-fleet.py', 'prepare-current0230-cli-witness-v5.py', 'execute-current0230-cli-witness-v5-observer-bridges-r5.py', 'finalize-current0230-exact-metadata-observer-bridges-r5.py', 'prepare-current0230-reader-fixture.py', 'check-current0230-helper27-genuine-outer-v1.py', 'revalidate-helper27-current0230-normal-pool-v1.py', 'bind-actual0230-qualified-metadata-v1.py', 'prepare-current0230-continuations-v1.py', 'run-current0230-reader13-parent-v4.py', 'prepare-positive185-current0230-reviewed-metadata-v1.py', 'invoke-positive185-current0230-next-operation-v1.py']
for i, name in enumerate(steps):
    argv = ['/usr/bin/python3', str(packet / name)]
    save(f'{i:02}-ARGV.json', argv)
    print('BEGIN', name, flush=True)
    z = subprocess.run(argv, text=True, capture_output=True, timeout=2400)
    save(f'{i:02}-EXECUTION.json', dict(argv=argv, code=z.returncode, stdout=z.stdout, stderr=z.stderr))
    print(name, z.returncode, z.stdout, z.stderr, flush=True)
    assert z.returncode == 0, (name, z.returncode)
