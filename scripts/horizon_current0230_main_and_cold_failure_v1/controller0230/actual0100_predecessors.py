"""Actual complete0100 immediate predecessors; JSON metadata only."""
from pathlib import Path
import hashlib, json
from qualified_bindings import _raw
PIN = '34bcb930256dba9c627a47e86fb9f123278b7fd940ef2e022741239d1c4d957e'
def actual0100_predecessors():
    raw = _raw(Path(__file__).resolve().parent / 'ACTUAL0100_COMPLETE_PREDECESSORS.json', immutable=False)
    assert hashlib.sha256(raw).hexdigest() == PIN
    v = json.loads(raw)
    def document(binding):
        raw = _raw(binding['path'], immutable=False)
        assert hashlib.sha256(raw).hexdigest() == binding['sha256']
        return json.loads(raw)
    docs = {k: document(b) for k, b in v.items()}
    current = {k: v[k] for k in ['observer', 'fleet', 'fleet_plan', 'frame']}
    assert docs['selector'] == current
    assert docs['memory']['selection']['request']['current'] == current
    assert docs['DATA']['data_selection']['current'] == current
    assert docs['memory']['selection']['request']['current_reader'] == v['full_prelaunch_reader']
    frame = docs['frame']
    assert all(frame['bindings'][k] == current[k] for k in ['observer','fleet','fleet_plan'])
    assert 'observation_bridge' not in document(frame['bindings']['cohort183_transition'])
    c = docs['actual_components_acceptance']
    assert c['actual_memory_selection'] == v['memory'] and c['actual_DATA_selection'] == v['DATA']
    assert c['physical_credit_bytes'] == 0
    return v
