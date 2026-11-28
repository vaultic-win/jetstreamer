"""Pass the bounded 136 diagnostic through the real status, registration and audit readers."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

parent, current, scratch = map(Path, sys.argv[1:4])
base = Path('/var/lib/jetstreamer/horizon_runtime_data')
package = base/'epoch168-terminal-status-20261121-v1/publisher-v1'
active = package
if sys.argv[4:]==['--combined']:
    package=base/'epoch166-post168-cadence-20261121-v1/publisher-v1'
elif sys.argv[4:]:
    raise ValueError("unknown qualification mode")
legacy = base/'public-audit73-observer-20261121-v1/observer-package'
following = base/'public-audit73-observer-20261121-v1/following-package-v2'
sys.path.insert(0, str(package))
import private136
import status
from cycle import Cycle, load_fleet
from evidence import bound, checked, durable
from reconcile import assemble

def process(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=45)

actual_ref=bound(current)
original=checked(actual_ref)
prior=original['previous_Root_operational_review']
cycle=Cycle(prior['path'],prior['sha256'],original['observer']['sha256'])
assert cycle.private136 is None and cycle.terminal166 is None
completed=checked(original['authenticated_status_audit'])
real={int(k):checked(v) for k,v in completed['receipts'].items()}
assert len(real)==19 and completed['authenticated_readback']
directory=scratch/'status'
directory.mkdir(mode=0o700)
class LocalStatus:
    def __init__(self):
        self.objects={e:(r['before_etag'],status.body(r['before_status'])) for e,r in real.items()}
        self.writes=[]
    def get(self,epoch):
        return self.objects[epoch]
    def put(self,epoch,tag,payload):
        assert tag==self.objects[epoch][0]
        result='"fixture-'+status.digest(payload)+'"'
        self.objects[epoch]=(result,payload)
        self.writes.append(epoch)
        return result
store=LocalStatus()
spec=importlib.util.spec_from_file_location('following',following/'follow_boundary.py')
watch=importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)
assert bound(package/'public_witness.py')['sha256']==bound(following/'public_witness.py')['sha256']
existing=watch.publisher()
assert Path(existing['package']['path']).parent in (active,package)
assert watch.current_fleet(existing)[0]==actual_ref
peers=watch.peers(original)
assert {r["epoch"] for r in original["actual_active_private_diagnostics"]}=={169}
assert len(peers)==5 and original["terminal168_trace_mismatch"]["sha256"]=="29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"
# Use the real disjoint fixture unit for the prospective additional PID1 identity.
# The five original producers and their proof chain come from the accepted fleet.
unit=Path('/proc/self/cgroup').read_text().strip().split('/')[-1]
row_unit=watch.unit(unit,('Id','MainPID','InvocationID','ActiveState','NRestarts'))
assert row_unit['InvocationID']==os.environ['INVOCATION_ID'] and int(row_unit['MainPID'])>0
fixture_ref=bound(parent)
row=dict(epoch=136,phase='private-worker-authorized',positive_worker=True,canonical_replay_claimed=False,
         entry=fixture_ref,children={'worker':{'pid':int(row_unit['MainPID'])}},admission=fixture_ref,post_prefire_capacity=fixture_ref,
         native_start_ticks=watch.ticks(int(row_unit['MainPID'])),unit=row_unit,transaction_replay_claimed=False)
capture=scratch/'capture.json'
durable(capture,dict(sample=cycle.sample_ref,fleet=prior,row=row))
cycle.private136=dict(row,receipt=bound(capture))
with patch.object(cycle,'unchanged'),patch.object(cycle,'public_fresh'),patch.object(status,'observed_archive',side_effect=lambda _,e:real[e]['archive_sample']):
    completed_ref=status._publish(cycle,store,directory,completed['ready_epochs'])
    assert status._publish(cycle,store,directory,completed['ready_epochs'])==completed_ref
new_status=checked(completed_ref)
assert len(store.writes)==19 and new_status['authenticated_readback'] and new_status['active_producer_count']==6
for epoch,binding in new_status['receipts'].items():
    captured=checked(binding); old=real[int(epoch)]
    assert captured['authenticated_readback'] and captured['after_sha256']==status.digest(store.get(int(epoch))[1])
    assert captured['after_status']==old['after_status']
cap=scratch/'capacity.json'
durable(cap,dict(checked(original['current_home_cycle_capacity']),private136_observation=bound(capture)))
projected=assemble(cycle,completed_ref,original['continuing_audit_obligation']['current_observation'],
                   bound(cap),original['sole_next_observer'])
assert len(projected['actual_active_private_diagnostics'])==projected['active_private_diagnostic_count']==2
assert projected['active_producer_count']==6 and projected['canonical_producer_count']==original['canonical_producer_count']
assert len(watch.peers(projected))==6 and watch.peers(projected)[:5]==peers
wrong=copy.deepcopy(projected); wrong['actual_active_private_diagnostics'][-1]['unit']['InvocationID']='0'*32
try:watch.peers(wrong)
except (ValueError,RuntimeError):pass
else:raise AssertionError('audit handoff accepted wrong additional native invocation')
# Local file overlay in a private mount namespace. The two ordinary readers receive the
# canonical path and the fingerprint of a fully reconstructed prospective fleet.
baseline=process([sys.executable,'-B',legacy/'describe.py',current,actual_ref['sha256']])
assert baseline.returncode!=0 and 'changed producer counts' in baseline.stderr,baseline.stderr
candidate=scratch/'complete.json'
durable(candidate,projected)
subprocess.run(['mount','--bind',candidate,current],check=True)
try:
    simulated=bound(current)
    assert load_fleet(simulated)[0]['active_producer_count']==6
    old_probe=process([sys.executable,'-B',legacy/'describe.py',current,simulated['sha256']])
    # The historical six-only reader accepts this count collision; the current
    # reader also requires the correct 136 observation and terminal 168 proof.
    assert old_probe.returncode==0,old_probe.stderr
    native=process([parent,'inspect-status',current,simulated['sha256']])
    assert native.returncode==0,native.stderr
    new_head=json.loads(native.stdout)
    assert new_head['fleet']==simulated and new_head['timer']==original['sole_next_timer']
finally:
    subprocess.run(['umount',current],check=True)
assert bound(current)==actual_ref
foreign=copy.deepcopy(projected)
foreign['actual_active_private_diagnostics'][-1]=original['historical168_before_trace_mismatch']
wrong_file=scratch/'foreign.json'
durable(wrong_file,foreign)
subprocess.run(['mount','--bind',wrong_file,current],check=True)
try:
    bad=process([parent,'inspect-status',current,bound(current)['sha256']])
    assert bad.returncode!=0 and ('136 observation/count mismatch' in bad.stderr or 'foreign 168 closure' in bad.stderr),bad.stderr
finally:
    subprocess.run(['umount',current],check=True)
assert bound(current)==actual_ref
print(json.dumps(dict(source_fleet=actual_ref,writer_controller_sha256='498c639d1c37a1cd47de6dea3b31b821cb399ce71d49eb040a6d14a7d829a8ac',
    real_publisher=existing,actual_five=peers,additional_fixture_unit=row_unit,authenticated_local_statuses=19,
    payload_equivalence=19,retry_additional_puts=0,old_bridge_rejected_five=True,old_bridge_count_collision=True,native_head_six_verified=True,
    actual_audit_reader_accepted_six=True,wrong_native_invocation_rejected=True,stale_168_substitution_rejected=True,canonical_producers=projected['canonical_producer_count'],
    protected_memory_and_disk=[projected[k] for k in ('complete_projected_memory_bytes','complete_DATA_bytes')],
    admission=False,remote_writes=0)))
