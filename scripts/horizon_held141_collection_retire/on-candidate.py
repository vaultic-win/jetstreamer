"""Carry the owner's terminal-event instruction through the existing native gates."""
import ctypes
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

BASE=Path('/var/lib/jetstreamer/horizon_runtime_data')
OUT=BASE/'held141-collection-retirement-20261120-v1'
STATE=OUT/'state'
HOOK=OUT/'approved-terminal-handoff'
OBS=BASE/'replay167-wall-rate-20261120-v1/observer-package'
sys.path.insert(0,str(OBS))
from evidence import bound,checked,content,digest,durable,need,raw,syncdir,utc
from owners import show

def verify_approval_candidate():
    auth=raw(HOOK/'authority.txt')
    need(digest(auth)=='54a7a466442bc65d68bcf919d7e279cf87df8a87a37f9e56c48e18baec55e87a','parent authorization differs')
    p=OUT/'CANDIDATE_ROOT_RELEASE.json'
    # The path unit may dispatch between exclusive creation and the writer's close.
    for i in range(20):
        try:
            if p.is_file() and json.loads(raw(p)).get("operation")=="retire-local-held141-collection":
                break
        except (ValueError,FileNotFoundError):
            pass
        time.sleep(.1)
    else:
        raise ValueError("no complete root-owned terminal release candidate")
    # The inotify watcher produced this file only after full terminal proof. Re-run the same immutable preflight.
    result=subprocess.check_output(['/usr/bin/python3','-IB',OUT/'local-qualification/preflight-release.py'],text=True,timeout=120)
    review=json.loads(result)
    need(review['candidate']==bound(p) and review['files']==6094 and review['sizes']==[189943475031,539418911425] and review['retirement_authorized'] is False,
         'terminal review differs')
    return p,review

def install_approved(p,release_sha):
    dest=STATE/'ROOT_RELEASE.json'
    data=raw(p)
    need(digest(data)==release_sha,'candidate changed')
    if not dest.exists():
        fd,tmp=tempfile.mkstemp(dir=STATE,prefix='.pending-release-')
        try:
            with os.fdopen(fd,'wb') as f:
                os.fchmod(f.fileno(),0o400);f.write(data);f.flush();os.fsync(f.fileno())
            rc=ctypes.CDLL(None,use_errno=True).renameat2(-100,os.fsencode(tmp),-100,os.fsencode(dest),1)
            if rc:
                n=ctypes.get_errno()
                raise OSError(n,os.strerror(n))

        finally:
            Path(tmp).unlink(missing_ok=True)
        syncdir(STATE)
    need(raw(dest)==data and dest.lstat().st_mode==stat.S_IFREG|0o400 and dest.lstat().st_nlink==1,'foreign approval')
    return bound(dest)

def latest_fleet():
    paths=BASE.glob('root*-live166167170-*-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json')
    p=max(paths,key=lambda path:path.lstat().st_mtime_ns)
    ref=bound(p);f=checked(ref);s=checked(f['observer'])
    age=(dt.datetime.now(dt.timezone.utc)-utc(s['recorded_at_utc'])).total_seconds()
    need(0<=age<2100 and f['all_reservation_ending_bytes']==0 and f['all_existing_memory_DATA_OS_native_transport_promises_retained'],
         'fleet or reservations changed')
    rows=f['actual_executing_replays']+f['actual_active_private_diagnostics']
    need({int(r['epoch']) for r in rows}=={166,167,168,169,170},'handoff fleet changed')
    for row in rows:
        n=row['unit'];v=show(n['Id'],('ActiveState','MainPID','InvocationID'))
        need(v['ActiveState']=='active' and v['MainPID']==n['MainPID'] and v['InvocationID']==n['InvocationID'],'fleet native owner changed')
    return ref

def run():
    need(os.geteuid()==0 and len(sys.argv)==1,'root terminal handoff only')
    p,review=verify_approval_candidate()
    fleet=latest_fleet()
    spec=importlib.util.spec_from_file_location('held141_capacity',HOOK/'capacity-on-release.py')
    cap=importlib.util.module_from_spec(spec);spec.loader.exec_module(cap)
    phase=cap.capture()
    need(phase['projected_141_member_retirement_bytes']==539456057344 and phase['restore_tree_lower_bound']==539458154496
         and phase['actual_credited']==0 and phase['compressed_staging_bytes']==0 and not phase['raw_overlap_reserved'],
         'foreign capacity disposition')
    need((OUT/'STATIC_FUTURE_READER.json').is_file() and
         phase['slack_against_169_after_projected_retirement_and_172_growth']>phase['projected_172_guard_margin_bytes'],
         'prospective phase budget requires reconciliation')
    token=review['candidate']['sha256']
    proof=OUT/('TERMINAL_DISPOSITION_'+token+'.json')
    if not proof.exists():durable(proof,dict(owner='/root',authority=bound(HOOK/'authority.txt'),review=review,current_fleet=fleet,phase_fit=phase,
        scope='local retired collection only; no epoch172 admission or remote mutation',restore_order='Retain validated derivative and exact held authenticated raw object. Whole-raw restore requires a fresh expanded-tree allocation; sequence after the next lane drains if overlap cannot fit.'))
    previous=content(proof)
    need(previous['review']==review and previous['authority']==bound(HOOK/'authority.txt'),'terminal disposition changed')
    approval=install_approved(p,token)
    finished=subprocess.check_output(['/usr/bin/python3','-IB',OUT/'local-qualification/launch-approved.py',token],text=True,timeout=900)
    c=bound(STATE/'complete.json');v=checked(c)
    need(v['removed_members']==6094 and v['member_allocation_unlinked_bytes']==539456057344 and not v['r2_mutations'],'terminal retirement differs')
    done=OUT/'ACTUAL_LOCAL_RETIREMENT.json'
    if not done.exists():durable(done,dict(authorization=approval,disposition=bound(proof),actual_native_completion=c,
        allocated_member_bytes=v['member_allocation_unlinked_bytes'],observed_free_before=v['available_bytes_before'],
        observed_free_after=v['available_bytes_after'],net_HOME_delta=v['available_bytes_after']-v['available_bytes_before'],
        current_fleet=latest_fleet(),source=str(p),wall_clock_utc=dt.datetime.now(dt.timezone.utc).isoformat(),epoch172_admission=False))
    print(json.dumps(dict(completion=bound(done),native_result=finished.strip())))
if __name__=='__main__':run()
