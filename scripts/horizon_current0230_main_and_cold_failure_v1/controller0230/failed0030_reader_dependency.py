from pathlib import Path
import json, hashlib, subprocess
from qualified_bindings import _raw, metadata_bound
def require_qualified0030_reader_retirement():
    root=Path('/home/sol/.jetstreamer-private/current0030-failed-reader-retirement-qa-20261109-v1')
    manifest=json.loads(_raw(root/'ROOT_ACTUAL_QUALIFIED_TRANSIENT0030_READER_RETIREMENT.json',immutable=False))
    for key in ['program','normal_seal','artifact','actual_retirement','booking']:
        b=manifest[key]
        if key=='program':
            assert hashlib.sha256(Path(b['path']).read_bytes()).hexdigest()==b['sha256']=='09028027573f13bd18caa585d52330a66024037c53ed63ab9ce95ffcd01ce55a'
        else: assert metadata_bound(b['path'],immutable=False)==b
    seal=json.loads(_raw(manifest['normal_seal']['path']))
    assert seal['schema']=='jetstreamer-sealed-deployment-receipt-v1' and seal['sealer_sha256']=='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
    for key,name in [('program','retirement'),('artifact','artifact-proof.json')]:
        assert sum(x['name']==name and x['sha256']==manifest[key]['sha256'] for x in seal['members'])==1
    assert json.loads(_raw(manifest['artifact']['path']))['all_required_tests_passed'] is True
    done=json.loads(_raw(manifest['actual_retirement']['path']))
    assert done['schema']=='horizon-exact0030-failed-transient-reader-retirement-v1' and done['original_iid']=='0e271726da824c2bbbad552fc21598ae'
    assert done['original_failure_and_payloads_preserved'] and done['only_failed_transient_reset'] and done['resource_credit_bytes']==0
    assert done['original_native']['ExecMainPID']=='3798489' and done['final_native']['ActiveState']=='inactive'
    phase_path=Path('/home/sol/.jetstreamer-private/current-reader-phase199-recovery-qa-20261109-v2/ROOT_ACTUAL_QUALIFIED_ADVISORY_PHASE199_BINDINGS.json')
    phase=json.loads(_raw(phase_path,immutable=False))
    for key in ['qualification','normal_seal','booking']:
        assert metadata_bound(phase[key]['path'],immutable=False)==phase[key]
    pq=json.loads(_raw(phase['qualification']['path']))
    assert pq['all_required_tests_passed'] and pq['ordinary_tests_passed']==64 and pq['no_snapshot_equality_relaxed'] and pq['no_guard_or_timer_mutation']
    ps=json.loads(_raw(phase['normal_seal']['path']))
    assert ps['schema']=='jetstreamer-sealed-deployment-receipt-v1' and sum(x['name']=='operation' and x['sha256']==phase['program']['sha256'] for x in ps['members'])==1
    assert hashlib.sha256(Path(phase['program']['path']).read_bytes()).hexdigest()==phase['program']['sha256']
    n=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show','horizon-failed4-current-accounting-reader-20261104-v1.service','-pActiveState,MainPID,ControlPID,NRestarts,Job,ControlGroup'],text=True).splitlines())
    assert n['ActiveState']=='inactive' and n['MainPID']==n['ControlPID']==n['NRestarts']=='0' and n['Job']==n['ControlGroup']==''
    return {'retirement':manifest['actual_retirement'],'phase':phase}
