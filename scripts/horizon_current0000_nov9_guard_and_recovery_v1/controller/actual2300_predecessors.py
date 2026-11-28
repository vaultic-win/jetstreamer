"""Metadata-only exact prior lineage. No resource observation or operational action."""
from pathlib import Path
import json, hashlib
from qualified_bindings import _raw
PIN = 'fe7795ed31866dd445a58e9e1ff4823094d1e0f876672dd47bad5d240a33b8b6'
MANIFEST = Path(__file__).resolve().parent / 'ACTUAL2300_PREDECESSORS.json'
def actual2300_predecessors():
    raw = MANIFEST.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PIN
    v = json.loads(raw)
    docs = {}
    for k, binding in v.items():
        raw = _raw(binding['path'], immutable=False)
        assert hashlib.sha256(raw).hexdigest() == binding['sha256'], ('actual2300 predecessor crossed', k)
        docs[k] = json.loads(raw)
    current = {k: v[k] for k in ['observer', 'fleet', 'fleet_plan', 'frame']}
    assert docs['selector'] == current
    assert docs['memory']['selection']['request']['current'] == current
    assert docs['DATA']['data_selection']['current'] == current
    assert docs['frame']['bindings']['fleet'] == v['fleet']
    return v
