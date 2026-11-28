"""Metadata-only exact prior lineage. No resource observation or operational action."""
from pathlib import Path
import json, hashlib
from qualified_bindings import _raw
PIN = 'e26345a06a42e0149afdb6c5aaabc2e7a8d715c8c11b8903f90ec0a4f7705e4c'
MANIFEST = Path(__file__).resolve().parent / 'ACTUAL0000_PREDECESSORS.json'
def actual0000_predecessors():
    raw = MANIFEST.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PIN
    v = json.loads(raw)
    docs = {}
    for k, binding in v.items():
        raw = _raw(binding['path'], immutable=False)
        assert hashlib.sha256(raw).hexdigest() == binding['sha256'], ('actual0000 predecessor crossed', k)
        docs[k] = json.loads(raw)
    current = {k: v[k] for k in ['observer', 'fleet', 'fleet_plan', 'frame']}
    assert docs['selector'] == current
    assert docs['memory']['selection']['request']['current'] == current
    assert docs['DATA']['data_selection']['current'] == current
    assert docs['frame']['bindings']['fleet'] == v['fleet']
    return v
