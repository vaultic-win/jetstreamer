"""Quote one metadata-only retry of the sealed 168 preparation during the known writer gap."""
from pathlib import Path
import os
import sys
import runpy
import hashlib
import fcntl
import json
import time
from datetime import datetime

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
D = R/'epoch168-retry4-rebook-20261123-v1'
PKG = R/'incident-replay-fit-20261121-v1/tools-homefloor-closed168-retry3-v1'
FLEET = R/'root011757-live166167170-20261123-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'
GAP = R/'root014757-live166167170-20261123-v1'
STATUS = R/'survivor172-cadence-20261122-v1'
OLD = 'c66cbea9e6d847b6aadd08b320fe6602'
ROOT = '713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4'
GUARD = '685ccacf23985e9f4453a80b5dd71bcf793b94eb18a4d32009c748e8f06fe16d'
LAUNCHER = '561eb14310bba8e97f2f6224021ea72e1d4d61c0741c18c7091dfa8a11542199'


def quote(operation='prepare'):
    if operation not in ('prepare','projection'):
        raise ValueError('unknown offline operation')
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode and os.geteuid()==0
    seal = PKG/'deployment-seal-receipt.json'
    assert hashlib.sha256(seal.read_bytes()).hexdigest()=='36a65a191047b3a76bf9903f97c6305619d1e745e861df3520bcaabd78133da1'
    for member in json.loads(seal.read_bytes())['members']:
        p = PKG/member['name']
        assert hashlib.sha256(p.read_bytes()).hexdigest()==member['sha256']
    provider = runpy.run_path(str(PKG/'post-stop-fit'))
    s, fit = provider['s'], provider['fit']
    fleet, fr = s.read(FLEET,'dd2f7b09412309188daaa33d35979f8489cac51c29b57f273a8fcffcc95bcb26')
    prior = s.read(STATUS/'COLD168_RETRY3_V1_STATUS_ACTIVE.json','b63b2e1b0f681e458a141a857db6b4b66137596f5387f9efb4edac31ab8d1bb7')[0]['new']
    reg = s.read(fit.READY,'02027e3e35364f64913b34162fde295bfb96b3123a9d9794545ce4e0b1a4e8ba')[1]
    def stopped_writer():
        m = s.show(fit.PUBLISHER)
        s.need(m['Id']==fit.PUBLISHER==prior['unit'] and m['InvocationID']==prior['invocation_id']==OLD
               and m['ActiveState']==m['SubState']=='failed' and m['Job']==''
               and m['Result']=='exit-code' and m['ExecMainStatus']=='1' and m['NRestarts']=='0'
               and m['MainPID']==m['ControlPID']=='0' and not fit.members(fit.PUBLISHER),
               'expected failed original status controller')
        p = fit.LOCK
        with p.open('rb') as f:
            st = os.fstat(f.fileno())
            s.need(p==Path(prior['lock']['path']) and (st.st_dev,st.st_ino)==(prior['lock']['device'],prior['lock']['inode']),
                   'different cadence lock')
            fcntl.flock(f,fcntl.LOCK_SH|fcntl.LOCK_NB)
        s.need(not (STATUS/'COLD168_RETRY4_V1_STATUS_INTENT.json').exists()
               and not (STATUS/'COLD168_RETRY4_V1_STATUS_ACTIVE.json').exists()
               and {f.name for f in GAP.iterdir()}=={'FULL172_OBSERVATION.json'},
               'status recovery or partial fleet already changed')
        _, partial = s.read(GAP/'FULL172_OBSERVATION.json','083a44c4c2fb2df4f965c3f56dc378f2ccf4ab013baffbb3cd6a3f7b23e6e2ea')
        witness, wr = s.read(STATUS/'RETRY3_STATUS_EXIT_014757_REMOTE_READBACK.json','799563bf01e179ae33d4e85188f87813c82736563b0d056f5fa6bd82d0e95a25')
        s.need(witness['last_complete']==fr and witness['terminal_writer']['InvocationID']==OLD and
               witness['full172']==partial and len(witness['authenticated_unchanged_rows'])==20 and
               not Path(witness['after_cycle_absent']).exists(),'different failed status cycle')
        s.bound(witness['native_sample'],R/'sample-root014757-live166167170-20261123-v1.json')
        return dict(registration=reg,authenticated_gap=wr,unit=m['Id'],invocation_id=OLD,pid=0,resident_credit_bytes=0,
                    failed=True,unconsumed_observation=partial)
    def reviewed_head(asked):
        # Anchor obligations to the last complete and successfully priced fleet. Its
        # scheduled successor actually sampled the same actors; use that sample's
        # own clock here. Preserve both receipts, timestamps and their distinct roles.
        previous_price = R/'incident-replay-fit-20261121-v1/homefloor-qualification/cold168-r4draft-01/screen-20261123T013950620430Z.json'
        proven, _ = s.read(previous_price,'8fea18f9001d307fa7079c2c6a2c26034d49dc0961625855a78354215d78816b')
        current, current_ref = s.read(FLEET,fr['sha256'])
        stopped = stopped_writer()
        witness = s.bound(stopped['authenticated_gap'],STATUS/'RETRY3_STATUS_EXIT_014757_REMOTE_READBACK.json')
        sample = s.bound(witness['native_sample'],R/'sample-root014757-live166167170-20261123-v1.json')
        timestamp = datetime.fromisoformat(sample['completed_at_utc']).timestamp()
        s.need(asked==current_ref==fr==proven['fleet']==witness['last_complete'] and proven['fits'] and
               current['sole_next_timer']=='horizon-observer-'+GAP.name+'.timer' and
               current['recorded_unix_seconds']<datetime.fromisoformat(sample['recorded_at_utc']).timestamp()<=timestamp and
               0<=time.time()-timestamp<=2400 and not current['actual_active_bootstraps'] and
               not current['actual_active_private_diagnostics'] and
               all(v['status']=='unavailable' and not v['ordinary_replay_claim'] and not v['publication_authorized']
                   for v in sample['diagnostic_replays']) and
               not (GAP/'ROOT_COMPLETE_OPERATIONAL_FLEET.json').exists(),'different or expired preparation observations')
        actors={v['epoch']:v for v in current['actual_executing_replays']}
        s.need(set(actors)=={167,170,172} and len(sample['replays'])==3 and
               {int(v['range']) for v in sample['replays']}==set(actors),'new or missing sampled replay owner')
        for row in sample['replays']:
            original=actors[int(row['range'])]
            unit=original['unit']
            s.need(row['invocation_binding_stable'] and row['scratch_path']==original['scratch_path'] and
                   row['worker_before']['pid']==row['worker_after']['pid'] and row['worker_after']['pid']>1 and all(
                       (row[k]['unit'],row[k]['invocation_id'],row[k]['main_pid'])==
                       (unit['Id'],unit['InvocationID'],int(unit['MainPID'])) for k in ('producer_before','producer_after')),
                   'different 168 preparation observation actor')
        return current,actors

    def preparation():
        _, rr = s.read(D/'SUCCESSOR_ROOT.json',ROOT)
        _, gr = s.read(R/'epoch168-cold-guard-20261123-v4/GUARD_QUALIFIED.json',GUARD)
        _, lr = s.read(D/'tools/deployment-seal-receipt.json',LAUNCHER)
        _, repaired = s.read(D/'QA_ALIAS_PLACEHOLDERS_20261123.json','d159ef8131ccc0d97e7198a3335cee73db9d14717e59475b4d20eb323f4263c1')
        unit = 'horizon-qualify-168-full-metered-cold-v4-20261123.service'
        native = s.show(unit)
        s.need(native['ActiveState']=='inactive' and native['MainPID']=='0' and not native['Job'] and not fit.members(unit)
               and not any((D/name).exists() for name in ('START_INTENT.json','barrier/allow','ACTUAL_ADMISSION_AND_PROTECTION.json')),
               '168 successor already started')
        inputs = dict(root=rr,guard=gr,launcher=lr,alias_repair=repaired)
        if operation=='projection':
            prepared, pr = s.read(D/'PREPARED.json')
            log, logref = s.read(D/'OBSERVER_LOG_PREPARED.json')
            s.need(prepared['epoch']==168 and prepared['baseline']['stable_roots']==rr and
                   prepared['profile']['producer_unit']==unit and log['prepared']==pr and
                   log['inode']==103481750 and log['size']==0 and log['uid']==log['gid']==0,
                   'different live projection enrollment')
            inputs.update(prepared=pr,observer_log=logref)
        return inputs
    # The production provider keeps its mandatory live writer check. Only this local
    # calculation uses the observed dead controller and retains its entire reservation.
    inputs = preparation()
    provider['capture_once'].__globals__.update(registered_status=stopped_writer,fleet_head=reviewed_head)
    result = provider['capture'](166, fr)
    reserved = fleet['retry9_auxiliary_commitments']
    s.need(preparation()==inputs and result['status_registration']==stopped_writer() and result['candidate'] is None
           and result['closed_retry3_bootstrap']['bootstrap_admission'] and result['closed_retry3_bootstrap']['executing'] is False
           and result['resource_credit_bytes']==result['stopped_generation_resident_credit_bytes']==0
           and reserved['build_and_native_qualification_serial'] and reserved['build_memory_bytes']>=1<<30
           and reserved['build_cpu_quota_micros']>=1_000_000
           and result['complete_memory_plus_reserve_bytes']==810658050048 and result['complete_cpu_quota_micros']==64000000,
           'different funding obligations')
    projection = operation=='projection'
    return dict(schema='horizon-offline-168-'+('projection' if projection else 'preparation')+'-price-v1',fits=result['fits'],epoch=168,preparation=inputs,
                authorized_action=('inspect prepared 168 namespace through a private, nonlaunch projection'
                                   if projection else 'idempotent standard prepare and observer-log preparation for epoch 168'),
                maximum_procs_cpu_quota_micros=250_000 if projection else 1_000_000,
                maximum_memory_bytes=(256<<20) if projection else (1<<30),maximum_swap_bytes=0,
                required_serial_lock='/run/lock/horizon-native-serial-compiler.lock',
                resource_credit_bytes=0,whole_host=res(result),
                full_cost=result, recorded_unix_seconds=result['recorded_unix_seconds'],
                fleet=fr, source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                replay_launch_authorized=False,status_writes_authorized=False)


def res(result):
    return {k:result[k] for k in ('available_HOME_bytes','complete_required_HOME_bytes','available_memory_bytes',
                                  'required_available_memory_bytes','complete_cpu_quota_micros','complete_memory_plus_reserve_bytes')}


if __name__=='__main__':
    if sys.argv[1:] not in ([],['--projection']):
        raise SystemExit('usage: closed_writer_prepare168.py [--projection]')
    value=quote('projection' if sys.argv[1:] else 'prepare')
    print(json.dumps(value,sort_keys=True))
    sys.exit(0 if value['fits'] else 1)
