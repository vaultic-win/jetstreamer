"""Refresh phase arithmetic using the existing native guards and HOME statvfs."""
import datetime as dt
import os
from pathlib import Path
import sys
import time
B=Path('/var/lib/jetstreamer/horizon_runtime_data')
O=B/'held141-collection-retirement-20261120-v1'
sys.path.insert(0,str(B/'replay167-wall-rate-20261120-v1/observer-package'))
from evidence import bound,checked,need,durable,utc
from owners import show
def ref(p,h):
    expected=dict(path=str(p),sha256=h);return checked(expected)
def available():
    m=os.statvfs('/home/sol');return m.f_bavail*m.f_frsize
def capture():
    started=time.time()
    vf=available()
    old=ref(O/'PHASE_FIT_BEFORE_RETIREMENT.json','c160f5f93fb1a847d76cc234b96e7695542fd0aa6166f62f80aa6602851491d3')
    guardroot=B/'epoch169-focused-admission-20261120-v4'
    g=ref(guardroot/'ACTUAL_GUARD_PLAN.json','3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58')
    plan=ref(guardroot/'POST_GUARD_CAPACITY.json','803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc')
    native=show(g['unit'],('InvocationID','MainPID','ActiveState'))
    need(native['InvocationID']==g['invocation_id'] and native['ActiveState']=='active','focused169 owner changed')
    guard_dir=Path(g['receipt_directory'])
    candidates=sorted(guard_dir.glob('sample-*.json'),key=lambda p:p.lstat().st_mtime_ns,reverse=True)
    accepted=[]
    for p in candidates[:12]:
        r=bound(p); doc=checked(r)
        need(doc['producer_invocation_id']==g['invocation_id'] and doc['producer']['pid']==int(native['MainPID']) and
             doc['plan_sha256']=='3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58' and
             doc['guard_sha256']=='b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016' and
             doc['minimum_free_bytes']==g['minimum_free_bytes'] and doc['maximum_root_physical_bytes']==g['maximum_root_physical_bytes'] and
             not doc['trip_reason'] and not doc['root_physical_observation_error'] and not doc['remote_mutations'],'invalid current native guard')
        phys=doc['root_physical_observation']
        if 0<=started-doc['recorded_unix_seconds']<120 and all(phys[k]['vanished_entries']==0 and phys[k]['symlinks']==0 for k in ('first','second')):
            accepted.append(dict(ref=r,recorded=doc['recorded_unix_seconds'],free=doc['available_bytes'],
                realized=min(phys[k]['physical_bytes'] for k in ('first','second'))))
        if len(accepted)==2:break
    if accepted:
        realized=min(v['realized'] for v in accepted)
    else:
        # Native 169 rotates accounts files. For incomplete tree scans, use only the still-present prequalified stable members.
        records=checked(bound(O/'PHASE_FIT_RESIDUAL_169_STABLE_SUBSET.json'))
        realized=0
        for row in records['selected']:
            p=Path(row['path']);m=p.lstat()
            need(p.resolve(strict=True)==p and m.st_dev==os.stat('/home/sol').st_dev and m.st_ino==row['inode'] and m.st_nlink==1,'stable member changed')
            realized+=min(m.st_blocks*512,row['allocated_lower_bound'])
    floor=max(g['minimum_free_bytes'],plan['protected_raw_floor_bytes'])
    need(floor==8515329790544 and g['maximum_root_physical_bytes']==103079215104 and 0<=realized<=g['maximum_root_physical_bytes'],'169 guard envelope changed')
    remaining=g['maximum_root_physical_bytes']-realized
    free=min(vf,available(),*[s['free'] for s in accepted])
    release=old['corpus_member_allocated']
    restore=old['restore_data_lower_bound']
    candidate=old['prospective_172_growth']
    need(release==539456057344 and candidate==283818000384 and restore==539458154496,'phase constants differ')
    return dict(measured_utc=dt.datetime.now(dt.timezone.utc).isoformat(),guard_samples=accepted,native169=native,
        conservative_HOME_available_bytes=free,focused169_armed_floor_bytes=floor,focused169_realized_lower_bound=realized,
        focused169_unspent_root_upper_bound=remaining,total_protected_bytes_against_focused169=floor+remaining,
        projected_141_member_retirement_bytes=release,actual_credited=0,restore_tree_lower_bound=restore,
        compressed_staging_bytes=0,prospective172_remaining_growth_bytes=candidate,
        slack_against_169_after_projected_retirement_and_raw_restore=free+release-restore-floor-remaining,
        slack_against_169_after_projected_retirement_and_172_growth=free+release-candidate-floor-remaining,
        slack_against_169_after_projected_retirement_and_172_and_raw_restore=free+release-candidate-restore-floor-remaining,
        projected_172_guard_margin_bytes=16<<30,derivative_retained=True,raw_overlap_reserved=False,
        actual_epoch172_admission=False,assumptions='Phase estimates are relative to the existing 169 guard/root. Actual 172 requires its independent full CPU, memory and disk admission. Raw restore requires a fresh final-size tree plus metadata and must be sequenced if it cannot overlap.')
if __name__=='__main__':
    q=capture()
    if len(sys.argv)==2:
        name=sys.argv[1];need(name in ('PHASE_FIT_2059','PHASE_FIT_AT_TERMINAL'),'unexpected output');durable(O/(name+'.json'),q)
    import json
    print(json.dumps(q))
