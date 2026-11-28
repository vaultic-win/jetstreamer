"""Join separate original native results durably. Retirement assessment never mutates a payload."""
import argparse
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
# Load the explicitly sealed sibling by file.
import importlib.util
spec=importlib.util.spec_from_file_location('cid268_booked_operator',Path(__file__).with_name('booked268.py'))
op=importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
D=Path('/home/ubuntu/.codex/diagnostics')
PRE={'path':str(D/'horizon268-range-compare-v176-a1/completion.json'),
     'sha256':'62ea945604d7da5fef03be5e16489712c9acc2c00e85a0c54ef3db97da14c91a'}
STATE=Path('/var/lib/jetstreamer/horizon268-cid-holding-custody-v1')
C267={'path':str(D/'horizon267-cid-validate-v174-a1/completion.json'),
      'sha256':'b260b65cd84557bfc41954b9987237df61b855723beb9ac65c7e6c5f28be3daa'}
END='7ad2d189f7e94e70a38c781354912448'
def select_epoch267():
    global PRE, STATE
    op.select_epoch267()
    PRE={'path':str(D/'horizon267-range-comparison-v174-a1/completion.json'),
         'sha256':'51dc5186a36eb511e1d530051144660a7f357a6a74636c27d95a0562d1e76a9e'}
    STATE=Path('/var/lib/jetstreamer/horizon267-cid-holding-custody-v1')

def gate(result,phase):
    op.need(result['operation']==phase and result['kind']=='cid-to-offset-and-size' and result['epoch']==op.EPOCH
            and result['bytes']==op.SIZE and result['sha256']==op.SHA and result['parts']==(op.SIZE+32*op.M-1)//(32*op.M) and
            re.fullmatch('[0-9a-f]{64}',result['manifest_sha256']) and
            result['capacity_credit']==0 and result['canonical_publication'] is False,'wrong native artifact or operation')

def receipt(ref):
    # On reboot RAM control paths disappear. The anchor preserves their byte-exact contents.
    try:
        return op.binding(ref)
    except FileNotFoundError:
        h=ref['sha256']
        op.need(re.fullmatch('[a-f0-9]{64}',h), 'invalid archived receipt digest')
        return op.binding(dict(path=str(STATE/(h+'.json')),sha256=h))

def packed_refs(ref):
    c=op.binding(ref);actor=op.binding(c['actor']);booking=op.binding(actor['booking'])
    return ([ref,c['actor'],c['manager'],actor['booking']]
            +([c['token']] if 'token' in c else [])
            +[booking[k] for k in ('complete_basis','retained_review','serial_basis','serial_assignment','closed_source_review') if k in booking])

def native_completion(ref,phase):
    c=receipt(ref); actor=receipt(c['actor']); b=receipt(actor['booking']); term=receipt(c['manager'])
    op.need(c['process_exit']==0 and c['controller']==b['controller']==op.MAIN and b['operation']==phase and
            actor['schema']==f'horizon{op.EPOCH}-cid-holding-actor-v1' and actor['worker']==b['image'] and
            re.fullmatch('[a-f0-9]{32}',c['invocation']), 'wrong native booking/process')
    if isinstance(term,list):
        rows=[e for e in term if e.get('MESSAGE_ID')==END]
        op.need(len(rows)==1 and rows[0].get('INVOCATION_ID')==c['invocation'] and
                rows[0].get('UNIT')==c['unit'] and rows[0].get('_PID')=='1' and rows[0].get('_UID')=='0' and
                rows[0].get('UNIT_RESULT','success')=='success' and b['cgroup']=='/system.slice/'+c['unit'], 'PID 1 termination')
    else:
        token=receipt(c['token'])
        op.need(term['success'] and term['process_drained'] and
                term['invocation']==token['invocation']==c['invocation'] and term['phase']==token['phase']==phase and
                term['booking_sha']==token['booking_sha']==actor['booking']['sha256'] and
                term['token_sha']==c['token']['sha256'] and term['result_sha']==c['actor']['sha256'] and
                token['first_cgroup_guard'] and token['pidfd_owner'] and token['boot']==op.BOOT, 'native pidfd closure')
    op.need(not (op.CG/b['cgroup'].lstrip('/')).exists(), 'spent actor cgroup still exists')
    gate(actor['result'],phase)
    return c,actor,b

def pair(park_ref,verify_ref):
    p,a,bp=native_completion(park_ref,'park');v,c,bv=native_completion(verify_ref,'verify')
    op.need(p['invocation']!=v['invocation'] and a['booking']!=c['booking'] and
            a['worker']==c['worker'] and a['result']['manifest_sha256']==c['result']['manifest_sha256'] and
            bp['authenticated_endpoint_sha256']==bv['authenticated_endpoint_sha256'],'independent custody bind')
    return dict(schema=f'horizon{op.EPOCH}-cid-holding-custody-v1',epoch=op.EPOCH,source=str(op.SRC),original_identity=list(op.STAMP),
                bytes=op.SIZE,sha256=op.SHA,manifest_sha256=a['result']['manifest_sha256'],
                selector=f'foundation_node_01/closed-private-v1/epoch{op.EPOCH}-cid-index-v1/index-{op.SHA[:8]}-v1.manifest',
                park=park_ref,verify=verify_ref,capacity_credit=0,original_removal_authorized=False)

def save_bytes(path,data):
    # Atomic no-replace rename leaves any interrupted staging file unattached to the final inode.
    import ctypes
    import errno
    import tempfile
    if not path.exists():
        fd,name=tempfile.mkstemp(dir=path.parent,prefix='.custody-')
        try:
            with os.fdopen(fd,'wb') as f:
                os.fchmod(fd,0o400);f.write(data);f.flush();os.fsync(fd)
            rename=ctypes.CDLL(None,use_errno=True).renameat2
            if rename(-100,os.fsencode(name),-100,os.fsencode(path),1)!=0 and ctypes.get_errno()!=errno.EEXIST:
                raise OSError(ctypes.get_errno(),'custody publication')
        finally:
            Path(name).unlink(missing_ok=True)
    op.need(path.resolve()==path and path.read_bytes()==data and path.stat().st_nlink==1 and
            path.stat().st_uid==os.geteuid() and stat.S_IMODE(path.stat().st_mode)==0o400,'existing custody conflict')
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def save(path,value):
    save_bytes(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())

def durable(park,verify):
    op.need(os.geteuid()==0 and os.environ.get('CODEX_THREAD_ID')==op.MAIN and
            STATE.resolve()==STATE and STATE.stat().st_uid==0 and stat.S_IMODE(STATE.stat().st_mode)==0o700 and
            STATE.stat().st_dev==op.DEV, 'Main in a separately funded durable state directory')
    result=pair(park,verify)
    op.need(op.stamp(op.SRC)==op.STAMP,'original CID index changed before custody anchor')
    refs=packed_refs(park)+packed_refs(verify)
    op.need(sum(Path(r['path']).stat().st_size for r in refs)<=2*op.M, 'reserve larger durable receipt archive before anchoring')
    for ref in refs:
        op.binding(ref);raw=Path(ref['path']).read_bytes();h=ref['sha256']
        op.need(hashlib.sha256(raw).hexdigest()==h,'source receipt changed during archive')
        save_bytes(STATE/(h+'.json'),raw)
    target=STATE/'custody.json';save(target,result)
    return dict(path=str(target),sha256=op.digest(target))

def compare_close(review):
    pre=op.binding(PRE)
    validated267=op.binding(C267)
    seal=op.binding(op.SEAL267)
    op.need(seal['native']['sha256']=='2eff392db0da6e2744a811db71b1a9e91078de3da92bca3bb0060c317d558e2e' and
            (validated267['identity']==list(op.STAMP) if op.EPOCH==267 else list(op.stamp(op.ORIGINAL_267))==validated267['identity']),'267 predecessor custody changed')
    op.need(pre['identities'][2]==list(op.STAMP) and pre['input_sha256'][2]==op.SHA and
            pre['result']['slots']==432000 and pre['result']['disagreements']==(60 if op.EPOCH==267 else 38) and
            pre['result']['missing_block_sections']==0,'wrong initial full comparison')
    q=op.binding(review)
    op.need(q['controller']==op.MAIN and q['pre']==PRE and q['seal267']==op.SEAL267 and q['complete'] and
            q['pending_consumers']==[] and q[f'staged_{op.EPOCH}_references']==[] and q['future_writers']==[] and
            q['original_identity']==list(op.STAMP) and 0<=time.time()-q['recorded_unix_seconds']<=120,'consumer closure still pending')
    for field in ('staged_review','postcomparison','resolution','compare_manager','compare_process'):
        op.binding(q[field])
    staged=op.binding(q['staged_review'])
    op.need(staged['controller']==op.MAIN and staged['source_identity']==list(op.STAMP) and
            staged['pending_consumers']==[] and staged['unresolved_references']==[] and
            staged['recorded_unix_seconds']>=q['recorded_unix_seconds']-120,'staged closure missing')
    post=op.binding(q['postcomparison']);result=post['result']
    proof=op.binding(q['resolution'])
    if op.EPOCH==267:
        # The earlier rooted repair produced a native window report and the original
        # direct CAR reads. Bind those to the repeat full comparison and sealed map.
        native=op.binding(seal['native'])
        lookup=op.binding({'path':str(D/'horizon267-disputed-car-sections-v175-a1/completion.json'),
                           'sha256':'42f2ebeb0c2b2e531897a0a78ea01d070db6ec46f491e9a62d01f3c883d1ee12'})
        samples=op.binding(lookup['lookup_results'])
        hits={v['slot']:v for v in samples['samples']}
        foreign=sorted(k for k,v in hits.items() if k!=v['embedded_slot'])
        changes={v['slot']:v for v in proof['changes']}
        op.need(native['report']==q['resolution'] and proof['epoch']==267 and
                proof['windows']['failures']==[] and proof['windows']['canonical_block_cids']==result['raw_present'] and
                native['repaired']['sha256']==proof['corrected_sha256']==post['input_sha256'][0] and
                samples['slot_index_sha']==post['input_sha256'][1] and
                len(hits)==60 and len(foreign)==len(changes)==30 and changes.keys()==hits.keys()-set(foreign) and
                all(changes[k]['rooted_witness'][3]==hits[k]['block_cid_hex'] for k in changes) and
                sorted(x[0] for x in result['examples'])==foreign and
                all((o,n,h,b,z,over)==(0,0,True,hits[k]['section_offset'],hits[k]['section_length'],False)
                    for k,o,n,h,b,z,over in result['examples']), '267 rooted and direct CAR evidence disagree')
    else:
        op.need(proof['epoch']==268 and proof['raw_sha256']==post['input_sha256'][0] and
                proof['slot_sha256']==post['input_sha256'][1] and
                sorted(proof['false_positive_slots'])==sorted(x[0] for x in result['examples']), '268 rooted comparison')
    op.need(post['identities'][2]==list(op.STAMP) and post['input_sha256'][2]==op.SHA and
            result['slots']==432000 and result['missing_block_sections']==result['raw_overlaps']==0 and
            len(result['examples'])==result['disagreements'] and
            post['manager']==q['compare_manager'] and post['process']==q['compare_process'] and
            op.binding(post['process'])['exit']==0,'corrected comparison or native resolution missing')
    pr=op.binding(post['process']);events=op.binding(post['manager'])
    ends=[r for r in events if r.get('MESSAGE_ID')==END and r.get('_PID')=='1' and r.get('_UID')=='0']
    op.need(len(ends)==1 and ends[0].get('UNIT_RESULT','success')=='success' and json.loads(pr['stdout'])==result,
            'corrected comparator native closure')
    return q

def review_retirement(anchor,review):
    proof=op.binding(anchor)
    op.need(Path(anchor['path'])==STATE/'custody.json' and pair(proof['park'],proof['verify'])==proof,
            'different durable custody')
    q=compare_close(review)
    op.need(op.stamp(op.SRC)==op.STAMP and not op.census(op.DEV,op.INO),'original changed or referenced')
    return dict(epoch=op.EPOCH,original=str(op.SRC),source_identity=list(op.STAMP),sha256=op.SHA,
                durable_custody=anchor,closed_comparison=review,postcomparison=q['postcomparison'],
                physical_ceiling=op.SRC.stat().st_blocks*512,observed_release=0,capacity_credit=0,
                subsequent_action='Main exact-inode retirement under the existing lock and fresh staged/FD/mmap checks')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--epoch',type=int,choices=(267,268),default=268)
    p.add_argument('action',choices=('anchor','retire-review'))
    for v in ('first','second'):
        p.add_argument(v,type=Path);p.add_argument(v+'_sha')
    a=p.parse_args()
    if a.epoch==267:
        select_epoch267()
    args=[dict(path=str(getattr(a,n)),sha256=getattr(a,n+'_sha')) for n in ('first','second')]
    action=durable if a.action=='anchor' else review_retirement
    print(json.dumps(action(*args),sort_keys=True))
if __name__=='__main__':
    main()
