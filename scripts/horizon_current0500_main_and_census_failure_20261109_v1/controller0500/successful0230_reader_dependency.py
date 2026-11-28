"""Exact successful0230alias retirement, no new retirement or actor action."""
import json
from qualified_bindings import _raw,metadata_bound
BINDING={'path': '/home/sol/.jetstreamer-private/epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_ACTUAL_EXACT0230_SUCCESSFUL_READER_RETIRED.json', 'sha256': '96b5f24a466f9432b50a66d23136b90cd9c5c17aabf8ded2dc9381b03e969f64'}
def document(b):
 assert metadata_bound(b['path'],immutable=False)==b;return json.loads(_raw(b['path'],immutable=False))
def require_qualified0230_reader_retirement():
 v=document(BINDING);assert v['memory_credit_bytes']==v['DATA_credit_bytes']==0 and v['original_reader_payloads_and_packages_retained']and v['no_replay_or_publication_authority']
 assert document(v['execution'])['code']==0
 q=document(v['actual_qualified_operation']);result=v['result'];assert result['exact0230_original']and result['no_replay_or_archive_authority']
 done=document(result['actual_successful_reader_retirement']);assert done['resource_credit_bytes']==0 and done['program']['sha256']==q['program']['sha256']and done['reset_failed_called']is False
 from next_operation_bindings import next_operation_bindings
 a=next_operation_bindings();assert a['operation']==q['program']and a['actual_successful0230_reader_retirement']==BINDING
 return BINDING
