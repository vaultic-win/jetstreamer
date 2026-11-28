"""Genuine complete0230 resources, kept separate from the later0430Frame."""
from pathlib import Path
import json,hashlib
from qualified_bindings import _raw
PIN='1894b2b15196de1dfff635d426d1ccb59799030260c2816fa1d5b81b812407c9'
def actual0230_predecessors():
 f=Path(__file__).resolve().parent/'ACTUAL0230_COMPLETE_RESOURCE_PREDECESSORS.json';raw=_raw(f,immutable=False);assert hashlib.sha256(raw).hexdigest()==PIN;v=json.loads(raw)
 def doc(b):
  raw=_raw(b['path'],immutable=False);assert hashlib.sha256(raw).hexdigest()==b['sha256'];return json.loads(raw)
 docs={k:doc(x)for k,x in v.items()};current={k:v[k]for k in ['observer','fleet','fleet_plan','frame']}
 assert docs['selector']==current and docs['memory']['selection']['request']['current']==docs['DATA']['data_selection']['current']==current
 assert docs['memory']['selection']['request']['current_reader']==v['full_prelaunch_reader']
 assert all(docs['frame']['bindings'][k]==current[k]for k in ['observer','fleet','fleet_plan'])
 c=docs['actual_components_acceptance'];assert c['actual_memory_selection']==v['memory']and c['actual_DATA_selection']==v['DATA']and c['physical_credit_bytes']==0
 from actual0100_predecessors import actual0100_predecessors
 old=actual0100_predecessors();transition=doc(docs['frame']['bindings']['cohort183_transition']);assert transition['previous_recovery']==old['frame']
 chain=transition['observation_bridge'];assert len(chain)==2;previous=old['observer']
 for row in chain:
  observer=row['observer'];value=doc(observer);assert value['cadence']['previous_sample']==previous['path']and value['cadence']['previous_sample_sha256']==previous['sha256']and value['cadence']['observed_interval_seconds']==1800
  assert Path(observer['path']).stat().st_mode&0o222==0;previous=observer
 assert docs['observer']['cadence']['previous_sample']==previous['path']and docs['observer']['cadence']['previous_sample_sha256']==previous['sha256']
 return v
