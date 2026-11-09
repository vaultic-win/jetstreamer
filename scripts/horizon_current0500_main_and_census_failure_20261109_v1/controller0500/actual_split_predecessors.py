"""Metadata-only split lineage: Frame0030 and last complete resources0000 remain distinct."""
from pathlib import Path
import json,hashlib
from qualified_bindings import _raw
from actual0000_predecessors import actual0000_predecessors
PIN = '19d261543635f7209262c6a37f1fc1d3a3a8ae4f7cd6af65560d1ec81323185b'
def actual_split_predecessors():
    path=Path(__file__).resolve().parent/'ACTUAL0030_FRAME_AND0000_RESOURCES_SPLIT.json'
    raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==PIN
    v=json.loads(raw)
    def doc(binding):
        raw=_raw(binding['path'],immutable=False);assert hashlib.sha256(raw).hexdigest()==binding['sha256']
        return json.loads(raw)
    resource=actual0000_predecessors()
    current=v['Frame0030']
    accepted=doc(v['actual0030_Frame_acceptance'])
    assert doc(v['actual0030_selector'])==current
    assert {k:accepted[k] for k in current}==current and accepted['complete_reader_pending'] is True
    assert accepted['replay_launch_authorized'] is False
    frame=doc(current['frame']);plan=doc(v['actual0030_Frame_plan'])
    assert frame['bindings']['observer']==current['observer'] and frame['bindings']['fleet']==current['fleet']
    assert plan['observer']==current['observer'] and plan['fleet']==current['fleet']
    assert 'observation_bridge' not in doc(plan['cohort183_transition'])
    for binding in current.values():doc(binding)
    assert resource['observer']!=current['observer']
    assert v['no0030_complete_resource_tuple_exists_or_is_claimed'] is True
    return {'Frame_predecessor0030':current,'complete_resource_predecessor0000':resource}
