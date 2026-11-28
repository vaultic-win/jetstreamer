"""Narrow authenticated status-only maintenance; no archive or sidecar mutation."""
import datetime, hashlib, json, os, re, subprocess, stat
from pathlib import Path
from urllib.parse import urlsplit
import boto3
from botocore.config import Config
ROOT = Path('/home/sol/.jetstreamer-private/r2-status-receipts')
D = Path('/home/sol/.jetstreamer-private/actual0023-refresh-admission-20261200-v1')
OBSERVER = Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T053022Z-postcompletion154-v1.json')
sha = lambda b: hashlib.sha256(b).hexdigest()
import sys
sys.path.insert(0, str(Path(__file__).parent))
from audit_contract_r1 import observer as checked_observer, read_bound, completed_tuple
_observer = json.loads(OBSERVER.read_text())
assert _observer['recorded_at_utc'] == '2026-11-09T05:30:22Z'
HANDOFF = Path('/home/sol/.jetstreamer-private/cached145-postreplay-handoff-20261105-v1/ROOT_ACTUAL145_POSTREPLAY_SEGMENT_VERIFICATION_HANDOFF.json')
_handoff = read_bound({'path': str(HANDOFF), 'sha256': sha(HANDOFF.read_bytes())})
assert _handoff['postreplay_pipeline_live'] and _observer['cadence']['previous_sample'] == json.loads((Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1') / 'PREDECESSOR_BINDINGS.json').read_text())['observer']['path'] and (_observer['cadence']['previous_sample_sha256'] == json.loads((Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1') / 'PREDECESSOR_BINDINGS.json').read_text())['observer']['sha256'])
_row = next((x for x in _observer['diagnostic_replays'] if x['range'] == '145'))
assert _row['status'] == 'unavailable' and _row['observation'] is None and (_row['expected_producer_invocation_id'] == _handoff['original_IID'])
_current = {'accepted_selector': {'path': '/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0500-20261109-v1/accepted-frame-selector.json', 'sha256': '02e0b10a1865a6e327a19293b42f9d41957cfaf2729fe6a189e6f84d006547b1'}, 'observer': {'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T050022Z-postcompletion154-v1.json', 'sha256': 'ea34a52eef04e6038d7c0862b6ec17503efaaa8594f48a262ffc69c3a5206079'}}
_memory0230 = read_bound({'path': '/var/lib/jetstreamer/horizon-original199-parent-memory-selection-v1/ea34a52eef04e6038d7c0862b6ec17503efaaa8594f48a262ffc69c3a5206079/select-1/selection.json', 'sha256': 'c3592d090473020369d5058c39a91f811b559358ee8494e6fab5117a7a3281f6'})
_DATA0230 = read_bound({'path': '/var/lib/jetstreamer/horizon-ended183-DATA-selection-v1/ea34a52eef04e6038d7c0862b6ec17503efaaa8594f48a262ffc69c3a5206079/selection.json', 'sha256': '9edb94c846b292aa258821b6de9f88dedefc75dac210f1393eb9be4ed0d32873'})
_selector0230 = read_bound({'path': '/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0500-20261109-v1/accepted-frame-selector.json', 'sha256': '02e0b10a1865a6e327a19293b42f9d41957cfaf2729fe6a189e6f84d006547b1'})
assert _memory0230['selection']['request']['current'] == _selector0230 and _DATA0230['data_selection']['current'] == _selector0230
assert _selector0230['observer'] == _current['observer']
_selector = read_bound(_current['accepted_selector'])
FLEET = Path(_selector['fleet']['path'])
assert _selector['fleet'] == {'path': str(FLEET), 'sha256': sha(FLEET.read_bytes())} and _observer['recorded_at_utc'] == '2026-11-09T05:30:22Z'
assert read_bound(_selector['frame'])['bindings']['observer'] == _current['observer']
EP = urlsplit(os.environ['HORIZON_S3_ENDPOINT'])
BUCKET = EP.path.strip('/')
assert EP.scheme == 'https' and BUCKET and ('/' not in BUCKET)
C = boto3.client('s3', endpoint_url=f'{EP.scheme}://{EP.netloc}', region_name='auto', aws_access_key_id=os.environ['HORIZON_ACCESS_KEY_ID'], aws_secret_access_key=os.environ['HORIZON_SECRET_ACCESS_KEY'], config=Config(signature_version='s3v4', s3={'addressing_style': 'path'}, retries={'max_attempts': 0}))
NOW = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
STAMP = NOW.strftime('%Y%m%d%H%M%S')
SAMPLED = NOW.strftime('%Y-%m-%dT%H:%M:%SZ')
EPOCHS = [136, 137, 141, 145, 159, 161, 163, 185, 186, 199, 200]
WRITE_EPOCHS = EPOCHS
ACTIVE = {}

def hook(request, **unused):
    assert request.method == 'PUT' and ACTIVE['key'] in {f'epoch-{e}.epoch-status.json' for e in EPOCHS}
    assert urlsplit(request.url).path.endswith('/' + ACTIVE['key'])
    request.headers['If-Match'] = ACTIVE['etag']
C.meta.events.register_first('before-sign.s3.PutObject', hook)

def durable(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 384)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)

def bound(path):
    path = Path(path)
    return {'path': str(path), 'sha256': sha(path.read_bytes())}

def native(unit):
    keys = ['Id', 'InvocationID', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlPID', 'NRestarts', 'ControlGroup', 'Result', 'ExecMainStatus', 'Job']
    return dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', unit] + ['-p' + k for k in keys], text=True).splitlines()))
EXPORTER_UNIT = 'horizon-extract145-prefix-real1328-20261106-v1.service'
EXPORTER = native(EXPORTER_UNIT)
assert EXPORTER['InvocationID'] == '914b442c5f61432f8ba3243eb7c0f20d' and EXPORTER['NRestarts'] == '0'
EXPORTER_TERMINAL = EXPORTER['MainPID'] == EXPORTER['ControlPID'] == '0' and (EXPORTER['ActiveState'], EXPORTER['SubState']) in [('failed', 'failed'), ('inactive', 'dead'), ('active', 'exited')]
assert NOW >= datetime.datetime(2026, 11, 7, 1, 56, 28, tzinfo=datetime.timezone.utc) and EXPORTER_TERMINAL, 'Original exporter must have a genuine terminal event after its fixed deadline; do not stop or extend it'
EXPORTER_PID1 = [json.loads(x) for x in subprocess.check_output(['journalctl', '--all', '--no-pager', '-ojson', '-u', EXPORTER_UNIT], text=True).splitlines()]
assert any((x.get('_PID') == '1' and x.get('INVOCATION_ID') == EXPORTER['InvocationID'] and (x.get('UNIT') == EXPORTER_UNIT) and (x.get('UNIT_RESULT') or x.get('MESSAGE_ID') == '7ad2d189f7e94e70a38c781354912448') for x in EXPORTER_PID1)), 'Original terminal PID1 proof required'
START_NATIVE = dict((x.split('=', 1) for x in subprocess.check_output(['systemctl', 'show', EXPORTER_UNIT, '--property=ExecMainStartTimestamp,ExecMainStartTimestampMonotonic'], text=True).splitlines()))
assert START_NATIVE == {'ExecMainStartTimestamp': 'Fri 2026-11-06 13:53:09 UTC', 'ExecMainStartTimestampMonotonic': '2319850564070'}
EXPORTER_START = datetime.datetime(2026, 11, 6, 13, 53, 9, tzinfo=datetime.timezone.utc)
CANONICAL_OUTPUT = Path('/home/sol/.jetstreamer-private/epoch145-prefix-extract-real1328-20261106-v1/epoch-145.jet')
CANONICAL_COMPLETE_PRESENT = CANONICAL_OUTPUT.is_file()
if CANONICAL_COMPLETE_PRESENT:
    cm = CANONICAL_OUTPUT.lstat()
    assert stat.S_ISREG(cm.st_mode) and cm.st_uid == 0 and (cm.st_nlink == 1)
EXPORTER_TERMINAL_RECEIPT = Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1/ROOT053022_RETRY3_ORIGINAL_EXPORTER145_TERMINAL_AND_NO_CREDIT.json')
durable(EXPORTER_TERMINAL_RECEIPT, {'native': EXPORTER, 'original_PID1': EXPORTER_PID1, 'original_IID': EXPORTER['InvocationID'], 'recorded_at_utc': SAMPLED, 'canonical_complete_path_present': CANONICAL_COMPLETE_PRESENT, 'no_archive_integrity_or_publication_claim': True, 'memory_credit_bytes': 0, 'DATA_credit_bytes': 0, 'source_and_output_preserved': True, 'repair_owner': '/root'})
from live145_metadata import inspect as inspect_live145, native as live145_native, timer_same_as
LIVE145 = inspect_live145(int(NOW.timestamp()))
frame = Path(_selector['frame']['path'])
assert sha(frame.read_bytes()) == _selector['frame']['sha256']
fleet = json.loads(FLEET.read_bytes())
observer = json.loads(OBSERVER.read_bytes())
assert observer['cadence']['routine_minimum_interval_enforced'] and observer['cadence']['observed_interval_seconds'] >= 1800
inv = json.loads(Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1/inventory053022.json').read_bytes())
assert inv['requested_epochs'] == 100 and inv['ready_pairs'] == 70 and (inv['missing'] == 30) and (inv['anomalies'] == inv['archive_only'] == 0)
found = {}
for page in C.get_paginator('list_objects_v2').paginate(Bucket=BUCKET, Prefix='epoch-'):
    for row in page.get('Contents', []):
        m = re.fullmatch('epoch-(\\d+)\\.epoch-status\\.json', row['Key'])
        if m and 101 <= int(m[1]) <= 200:
            found[int(m[1])] = row['Key']
assert sorted(found) == EPOCHS
ready = {x['epoch'] for x in inv['entries'] if x['state'] == 'ready-pair'}
assert ready.isdisjoint(found)
watcher = native('horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service')
assert watcher['InvocationID'] == '7ac4617f73ab4f979a8527cce461c6a4' and watcher['ActiveState'] == 'active' and (watcher['SubState'] == 'running') and (int(watcher['MainPID']) > 0) and (watcher['NRestarts'] == '0')
terminal145 = native('horizon-qualify-145-cached-b2a09f57de39c384.service')
terminal159 = native('horizon-epoch159-finalized-gap-metadata-20261031-v2.service')
assert terminal145['InvocationID'] == '' and terminal145['MainPID'] == terminal145['ControlPID'] == terminal145['NRestarts'] == '0' and (terminal145['ControlGroup'] == '') and (terminal145['ActiveState'] == 'inactive') and (terminal145['SubState'] == 'dead')
_terminal = read_bound(bound(Path('/home/sol/.jetstreamer-private/cached145-postreplay-handoff-20261105-v1/ROOT_ACTUAL145_CLEAN_TERMINAL_AND_VERIFIED_SEGMENT.json')))
assert _terminal['parent_completed_cleanly'] and _terminal['original_IID'] == '15ddd220e2144aaa8d7418f73f60768f'
read_bound(_terminal['producer_segment_manifest'])
assert not Path('/proc/965009').exists()
assert terminal159['InvocationID'] == '5249fe78e56a44d68a51c98030d9d39b' and terminal159['ActiveState'] == 'active' and (terminal159['SubState'] == 'exited') and (terminal159['MainPID'] == '0') and (terminal159['ControlPID'] == terminal159['NRestarts'] == '0')
incident = Path('/home/sol/.jetstreamer-private/actual1518-control-20261101-v1/metadata159-terminal-repair-incident.json')
incident_value = json.loads(incident.read_bytes())
assert incident_value['current_repair_owner'] == '/root' and incident_value['repair_open'] and (incident_value['exit_status'] == 1)
source = Path('/home/sol/.jetstreamer-private/retry0005-effective-memory-final-consumers-20261102-v1/shared-qualification-v11/SOURCE_FREEZE.json')
source_binding = bound(source)
review = json.loads(Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1/status-estimate-review053022.json').read_text())
assert review['coordinated_observer'] == bound(OBSERVER) and review['owner_review_approved_by_main'] is True
assert set(review['owner_updates_by_epoch']) == {str(e) for e in EPOCHS}
assert all((isinstance(x.get('current_task'), str) and x['current_task'] and isinstance(x.get('current_phase'), str) and x['current_phase'] for x in review['owner_updates_by_epoch'].values()))
EN_PATH = Path('/home/sol/.jetstreamer-private/epoch199-backfill-current-preparation-20261102-v1/ACTUAL2258_R2_ENROLLMENT.json')
EN = json.loads(EN_PATH.read_text())
FAILURE_PATH = Path('/home/sol/.jetstreamer-private/actual1658-control-20261104-v1/EPOCH199_200_UPSTREAM500_ORIGINAL_FAILURE_EVENT.json')
FAILURE = read_bound(bound(FAILURE_PATH))
assert FAILURE['repair_open'] and FAILURE['active_repair_owner'] == '/root' and (FAILURE['original_failed_producer_invocation_id'] == EN['producer']['invocation_id']) and FAILURE['DATA_and_historical_memory_obligations_retained']
NEW_CN = native(EN['controller']['unit'])
NEW_PN = native(EN['producer']['unit'])
assert NEW_CN['InvocationID'] == EN['controller']['invocation_id'] and NEW_CN['ActiveState'] == 'active' and (NEW_CN['SubState'] == 'running') and (NEW_CN['NRestarts'] == '0') and (int(NEW_CN['MainPID']) > 0)
assert NEW_PN['MainPID'] == NEW_PN['ControlPID'] == '0' and NEW_PN['ActiveState'] == 'inactive' and (NEW_PN['SubState'] == 'dead') and (NEW_PN['LoadState'] == 'not-found') and (NEW_PN['InvocationID'] == '')
STATE_PATH = Path(FAILURE['controller_state_binding']['path'])
STATE_BINDING = FAILURE['controller_state_binding']
WITNESS = Path('/usr/local/lib/jetstreamer/horizon-original199-input-witness-actual-second-accepted-20261107-v3/witness.json')
assert sha(WITNESS.read_bytes()) == '97faf3d988eb549dc77ce564869f0d36a5ba7a3717073449a2f443330cd086aa'
_witness = json.loads(WITNESS.read_bytes())
def original_state_identity():
    m = STATE_PATH.stat(follow_symlinks=False)
    return dict(device=m.st_dev,inode=m.st_ino,bytes=m.st_size,uid=m.st_uid,gid=m.st_gid,mode=m.st_mode,links=m.st_nlink,mtime=m.st_mtime_ns//1000000000,mtime_nsec=m.st_mtime_ns%1000000000,ctime=m.st_ctime_ns//1000000000,ctime_nsec=m.st_ctime_ns%1000000000)
# Witness shape is qualified by its exact pinned bytes.
_members = _witness['verified_inputs']
_state_member = next(x for x in _members if x['binding']['path'] == str(STATE_PATH))
assert _state_member['binding'] == STATE_BINDING
assert original_state_identity() == _state_member['identity']
STATE_COPY = Path('/usr/local/lib/jetstreamer/horizon-original199-quarantined-state-capture-20261107-v1/state.json')
STATE = read_bound(dict(path=str(STATE_COPY), sha256=STATE_BINDING['sha256']))
assert original_state_identity() == _state_member['identity']
assert STATE['assignments']['lane-a'] == FAILURE['quarantined_assignment'] and STATE['assignments']['lane-a']['phase'] == 'failed' and (STATE['attempts'] == {'199-200': 1})
assert observer['replays'] == []
FAILED_ROWS = [r for r in observer['diagnostic_replays'] if r['range'] == '199-200']
assert len(FAILED_ROWS) == 1 and FAILED_ROWS[0]['status'] == 'unavailable' and (FAILED_ROWS[0]['observation'] is None) and (FAILED_ROWS[0]['expected_producer_invocation_id'] == EN['producer']['invocation_id'])
NEW_SIZES = {199: 0, 200: 0}
NEW_SIZE_EVIDENCE = []
ARCHIVE = Path('/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private/destination-4c0590bffe094dbdf1849652545292a68fbd64b07cb64c6927a0d43c6dda8453/work/root-cohort-199-200/run-2467217-1793661348112182346/archives/epoch-199.jet')
archive_meta = ARCHIVE.stat(follow_symlinks=False)
assert stat.S_ISREG(archive_meta.st_mode) and archive_meta.st_nlink == 1 and (archive_meta.st_size == FAILURE['preserved_epoch199_archive_bytes'])
NEW_SIZES[199] = archive_meta.st_size
NEW_SIZE_EVIDENCE.append({'epoch': 199, 'path': str(ARCHIVE), 'bytes': archive_meta.st_size, 'device': archive_meta.st_dev, 'inode': archive_meta.st_ino, 'metadata_only_no_verification_or_publication_credit': True})

def new_phase(e):
    return 'verification'
prep163 = Path('/home/sol/.jetstreamer-private/epoch163-shortest-second-lane-admission-source-20261104-v1')
initial163_owner = read_bound(json.loads((Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1') / 'INITIAL163_SOURCE_BINDINGS.json').read_text())['root_current_owner_acceptance'])
assert initial163_owner['current_operator'] == '/root' and initial163_owner['epoch'] == 163 and (initial163_owner['repair_or_preparation_open'] is True) and (initial163_owner['no_replay_admission_claimed'] is True)
assert bound(prep163 / 'SOURCE_FREEZE.json') == initial163_owner['source_freeze']
assert bound(prep163 / 'ROOT_163_PACKAGE_AND_BOTH_NEGATIVE_CAPABILITIES_ACCEPTED.json') == initial163_owner['package_and_negative_probes']
current = {}
for e in EPOCHS:
    r = C.get_object(Bucket=BUCKET, Key=found[e])
    raw = r['Body'].read(65537)
    assert len(raw) <= 65536
    wire = json.loads(raw)
    assert set(wire) == {'epoch', 'jet_size_bytes', 'elapsed_execution_millis', 'estimated_remaining_millis', 'sampled_at_utc', 'phase'} and wire['epoch'] == e
    assert wire['phase'] in ['replay', 'verification', 'upload', 'readback'] and all((type(wire[k]) is int and 0 <= wire[k] < 2 ** 64 for k in ['epoch', 'jet_size_bytes', 'elapsed_execution_millis', 'estimated_remaining_millis']))
    stamp = datetime.datetime.strptime(wire['sampled_at_utc'], '%Y-%m-%dT%H:%M:%SZ').strftime('%Y%m%d%H%M%S')
    prior = ROOT / f'epoch-{e}.status-correction-{stamp}.json'
    pr = prior.read_bytes()
    p = json.loads(pr)
    assert p['authenticated_readback'] is True and p['after_status'] == wire and (p['after_sha256'] == sha(raw)) and (p['after_etag'] == r['ETag']) and (p['owner_evidence']['current_operator'] == '/root')
    assert (e in [145, 199, 200] or wire['jet_size_bytes'] == 0) and SAMPLED > wire['sampled_at_utc']
    current[e] = (wire, raw, r['ETag'], prior, p)

def fixed185_eta_parts(binding, now):
    model = read_bound(binding)
    assert model['schema'] == 'horizon-epoch185-fixed-unexecuted-replay-planning-model-v1' and model['owner'] == '/root'
    basis = read_bound(model['authenticated_full_work_basis'])
    assert basis['authenticated_readback'] and basis['estimate_parts_millis']['full_epoch_replay_using_same_century_peer_rate_with25percent_contingency_millis'] == model['full_replay_fixed_millis']
    parse = lambda s: datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    full_left = model['qualification_original_total_millis'] - int((now-parse(model['qualification_anchor_utc'])).total_seconds())*1000
    spent_control = int((now-parse(model['control_model_issued_at_utc'])).total_seconds())*1000
    control_left = model['control_integration_allocation_millis'] - spent_control
    assert 0 <= spent_control and 0 < control_left <= full_left, 'Explicit new estimate review required; no expired allowance clamp/reset'
    fresh = min(3600000, control_left)
    parts = {'current_fleet_order_repair_and_launch_controls_millis':control_left-fresh, 'fresh_full_reader_memory_DATA_and_replay_admission_millis':fresh, 'full_boundary_runtime_native_Frame_successor_qualification_millis':full_left-control_left, 'bootstrap_load_and_warmup_millis':model['bootstrap_millis'], 'full_epoch_replay_using_same_century_peer_rate_with25percent_contingency_millis':model['full_replay_fixed_millis'], 'archive_close_full_plugin_boundary_verification_millis':model['verification_millis'], 'upload_whole_object_readback_and_sidecar_commit_millis':model['delivery_millis']}
    assert all(type(x) is int and x >= 0 for x in parts.values()) and sum(parts.values()) > 0
    return parts, model

out = []
for e in WRITE_EPOCHS:
    wire, raw, etag, prior, p = current[e]
    clock = datetime.datetime.strptime(wire['sampled_at_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    parts = dict(json.loads(Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1/status-estimate-review053022.json').read_bytes())['parts_by_epoch'][str(e)])
    newer_event = bound(prior) != review['latest_authenticated_status_by_epoch'][str(e)]
    if newer_event:
        parts = dict(p['estimate_parts_millis'])
    if e != 145:
        parts = dict(p['estimate_parts_millis'])
        elapsed_millis = max(0,int((NOW-clock).total_seconds())*1000)
        margins=[k for k,v in parts.items() if ('contingency' in k or 'uncertainty' in k) and v>=elapsed_millis]
        if margins:
            parts[margins[0]]-=elapsed_millis
        else:
            # Carry the authenticated absolute planning arrival forward when
            # the legacy breakdown has no separate contingency component.
            carried=wire['estimated_remaining_millis']-elapsed_millis
            assert carried>0,('Prior planning arrival passed; explicit new review required',e)
            parts={'remaining_until_prior_authenticated_planning_arrival':carried}
    if e == 185:
        fixed_binding = review['owner_updates_by_epoch']['185']['fixed_work_eta_model']
        parts, fixed_model = fixed185_eta_parts(fixed_binding, NOW)
    remaining = sum(parts.values())
    assert remaining > 0 and all((type(v) is int and v >= 0 for v in parts.values()))
    owner = {'estimate_review': bound(Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1/status-estimate-review053022.json')), 'current_operator': '/root', 'previous_owner_evidence': bound(prior), 'coordinated_observer': bound(OBSERVER), 'accepted_fleet': bound(FLEET), 'current_accepted_resource_frame': bound(frame)}
    owner.update({k: v for k, v in review['owner_updates_by_epoch'][str(e)].items() if k not in ['estimate_review', 'previous_owner_evidence', 'coordinated_observer', 'accepted_fleet', 'current_accepted_resource_frame']})
    if newer_event:
        owner.update(p['owner_evidence'])
        owner.update(estimate_review=bound(Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1/status-estimate-review053022.json')), previous_owner_evidence=bound(prior), coordinated_observer=bound(OBSERVER), current_fresh_observer=bound(OBSERVER), accepted_fleet=bound(FLEET), current_accepted_resource_frame=bound(frame), authenticated_event_correction_preserved_after_review=True)
    if e in [199, 200]:
        owner.update(enrollment=bound(EN_PATH), actual_controller=NEW_CN, actual_producer=NEW_PN, archive_size_evidence=NEW_SIZE_EVIDENCE, no_postlaunch_full_observer_yet=False, no_live_producer_claimed=True, original_failure=bound(FAILURE_PATH), quarantined_controller_state=STATE_BINDING)
    owner.update(last_complete_resource_selector={'path': '/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0500-20261109-v1/accepted-frame-selector.json', 'sha256': '02e0b10a1865a6e327a19293b42f9d41957cfaf2729fe6a189e6f84d006547b1'}, immediate_Frame_predecessor={'path': '/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261109T050022-witness-terminal145-chain128-v5.json', 'sha256': '94916c3997a2d733563acf2b4ea41b8af4c77186a55ef32473c0333d22e135b8'}, current_complete_resources_pending=True, current_primary_thread='01a1af2a-9ce8-76a2-8939-b2112bd38f53', complete_current_DATA_bytes=review['owner_updates_by_epoch'][str(e)]['complete_current_DATA_bytes'], current_complete_DATA_authority=review['owner_updates_by_epoch'][str(e)]['current_complete_DATA_authority'])
    if e == 185:
        owner.update(fixed_work_eta_model=fixed_binding, no_full_epoch_replay_started=True)
    status = dict(wire, sampled_at_utc=SAMPLED, elapsed_execution_millis=max(0, int((NOW - datetime.datetime.strptime('Mon 2026-11-02 04:40:49 UTC', '%a %Y-%m-%d %H:%M:%S UTC').replace(tzinfo=datetime.timezone.utc)).total_seconds()) * 1000) if e == 159 else wire['elapsed_execution_millis'] + int((NOW - clock).total_seconds()) * 1000, estimated_remaining_millis=remaining, phase='verification' if e == 145 else new_phase(e) if e in [199, 200] else 'verification', jet_size_bytes=os.stat('/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet', follow_symlinks=False).st_size if e == 145 else NEW_SIZES[e] if e in [199, 200] else 0)
    if e == 145:
        assert live145_native(LIVE145['actor']['Id']) == LIVE145['actor'] and timer_same_as(LIVE145['timer'])
        owner.update(LIVE145['owner'])
        parts = LIVE145['parts']
        remaining = sum(parts.values())
        status.update(jet_size_bytes=LIVE145['jet_size_bytes'], elapsed_execution_millis=LIVE145['elapsed_execution_millis'], estimated_remaining_millis=remaining, phase='verification')
        owner.update(live_exporter_rate_evidence=LIVE145['rate_evidence'], live_exporter_log_capture=LIVE145['phase2_source_log_prefix'])
    after = (json.dumps(status, sort_keys=True, separators=(',', ':')) + '\n').encode()
    proof = {'schema': 'horizon-status-only-correction-v1', 'epoch': e, 'key': found[e], 'sampled_at_utc': SAMPLED, 'before_body': raw.decode(), 'before_status': wire, 'before_etag': etag, 'before_sha256': sha(raw), 'after_status': status, 'after_sha256': sha(after), 'previous_receipt': bound(prior), 'conditional_header': 'If-Match', 'owner_evidence': owner, 'estimate_parts_millis': parts, 'estimated_remaining_millis': remaining, 'assumption': p.get('assumption', 'Definite uncertain full-sidecar engineering/replay/verification/delivery planning estimate.'), 'observer': bound(OBSERVER), 'fleet': bound(FLEET), 'resource_sample_claimed': False, 'archive_publication_authorized': False, 'replay_launch_authorized': False}
    if e == 185:
        proof['assumption'] = fixed_model['assumption']
    if e == 145:
        proof['assumption'] = 'Original145 failed74 exporter is retained debt; active Root repair uses uncertain engineering/export/verification/delivery allowances and a definite numeric full-sidecar planning arrival. Elapsed time is deducted across components with no resource release or live-exporter-rate claim.'
    durable(ROOT / f'epoch-{e}.status-correction-intent-{STAMP}.json', proof)
    assert native(watcher['Id']) == watcher and native(terminal145['Id']) == terminal145 and (native(terminal159['Id']) == terminal159)
    assert native(NEW_CN['Id']) == NEW_CN and native(NEW_PN['Id']) == NEW_PN and (original_state_identity() == _state_member['identity'])
    ACTIVE.update(key=found[e], etag=etag)
    assert native(EXPORTER_UNIT) == EXPORTER and CANONICAL_OUTPUT.is_file() == CANONICAL_COMPLETE_PRESENT
    if e == 145:
        assert live145_native(LIVE145['actor']['Id']) == LIVE145['actor'] and timer_same_as(LIVE145['timer'])
    put = C.put_object(Bucket=BUCKET, Key=found[e], Body=after, ContentType='application/json')
    rb = C.get_object(Bucket=BUCKET, Key=found[e])
    assert rb['Body'].read(65537) == after and rb['ETag'] == put['ETag']
    proof.update(authenticated_readback=True, after_etag=rb['ETag'], verified_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    rp = ROOT / f'epoch-{e}.status-correction-{STAMP}.json'
    durable(rp, proof)
    out.append({'epoch': e, 'outcome': 'refreshed-authenticated-readback', 'receipt': bound(rp)})
audit = {'schema': 'horizon-range-status-event-correction-v1', 'interruption_recovery': True, 'fresh_resource_audit_pending': True, 'first_epoch': 101, 'last_epoch': 200, 'sampled_at_utc': SAMPLED, 'observer': bound(OBSERVER), 'fleet': bound(FLEET), 'frame': bound(frame), 'authenticated_inventory_complete': True, 'status_keys': found, 'outcomes': out, 'archive_mutations': False, 'sidecar_mutations': False, 'unresolved_status_incidents': [], 'current_resource_control_incident': review['current_cycle_reassessment'], 'fresh_fleet_reconciliation_pending': True, 'current_frame_acceptance_pending': True, 'last_accepted_fleet_resource_clock': fleet['sampled_at_utc']}
rp = ROOT / f'range-101-200-status-audit-{STAMP}.json'
durable(rp, audit)
durable(Path('/home/sol/.jetstreamer-private/actual053022-visible-root-acceptance-20261109-v1/status-audit053022-result.json'), {'audit': bound(rp), 'count': len(out), 'authenticated_readback': True})
print(json.dumps({'audit': str(rp), 'count': len(out), 'authenticated_readback': True}))
