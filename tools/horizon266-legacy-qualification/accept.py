"""Read the original PID1 terminal and sample or compiler outputs after natural drain."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
import runpy

HERE=Path(__file__).resolve().parent
recipe=runpy.run_path(str(HERE/'render.py'))
def require(ok,msg):
    if not ok:
        raise ValueError(msg)
def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()
def trusted(path):
    s=path.lstat()
    require(path.resolve()==path and path.is_file() and s.st_uid==0 and not s.st_mode&0o022,str(path))
def journal(*filters):
    raw=subprocess.check_output(['/usr/bin/journalctl','-b','--no-pager','--output=json',*filters])
    return [json.loads(row) for row in raw.splitlines()]
def accept(phase,launch_path):
    trusted(launch_path)
    launch=json.loads(launch_path.read_bytes())
    booking_path=Path(launch['booking']['path'])
    trusted(booking_path)
    require(sha(booking_path)==launch['booking']['sha256'],'launch/booking binding')
    booking=json.loads(booking_path.read_bytes())
    specification=recipe['render'](phase,booking['cpu'])
    unit=specification['unit']
    require(all(booking[k]==v for k,v in specification.items()),'original booking and argv')
    iid=launch['unit']['InvocationID']
    require(re.fullmatch('[a-f0-9]{32}',iid) and launch['unit']['Id']==unit and launch['unit']['NRestarts']=='0',
            'original manager identity')
    events=journal('_PID=1','UNIT='+unit)
    own=[r for r in events if r.get('INVOCATION_ID')==iid]
    require({r['INVOCATION_ID'] for r in events if r.get('INVOCATION_ID')}=={iid},'multiple PID1 invocations')
    ids=[r.get('MESSAGE_ID') for r in own]
    require(ids.count('39f53479d3a045ac8e11786248231fbf')==1 and ids.count('7ad2d189f7e94e70a38c781354912448')==1 and
            'd9b373ed55a64feb8242e02dbe79a49c' not in ids and 'de5b426a63be47a7b6ac3eaac82e2f6f' not in ids and
            ids.index('39f53479d3a045ac8e11786248231fbf')<ids.index('7ad2d189f7e94e70a38c781354912448'),'original natural success')
    require(not (Path('/sys/fs/cgroup/system.slice')/unit).exists(),'cgroup undrained')
    result=dict(unit=unit,invocation=iid,launch_sha256=sha(launch_path),booking_sha256=sha(booking_path),
                manager_events=own,cgroup_drained=True)
    if phase=='build':
        out=recipe['OUT']
        built=json.loads((out/'build.json').read_bytes())
        plan=json.loads((recipe['BUILD_STAGE']/'plan.json').read_bytes())
        require(built['compiler_argv']==plan['argv'] and built['compiler_cwd']==plan['cwd']
                and plan['cwd']=='/tmp/horizon266-legacy-rustc-v2' and built['compiler_tmpdir']==plan['cwd']
                and built['compiler_tmpfs_bytes']==specification['private_tmpfs_bytes'],
                'actual compiler invocation or tmpfs differs')
        require(built['invocation']==iid and built['plan_sha256']==sha(recipe['BUILD_STAGE']/'plan.json') and
                built['provenance_sha256']==sha(recipe['BUILD_STAGE']/'provenance.json') and
                set(built['output_sha256'])=={'legacy-source','inputs.d','link.map'} and
                all(sha(out/k)==v for k,v in built['output_sha256'].items()),'original build products')
        result['build']=built
    else:
        image=recipe['IMAGE']
        trusted(image)
        require(sha(image)==booking['image_sha256'],'sealed sample executable changed')
        messages=journal('_SYSTEMD_UNIT='+unit,'_SYSTEMD_INVOCATION_ID='+iid,'_TRANSPORT=stdout','_UID=1000')
        samples=[(r,json.loads(r['MESSAGE'])) for r in messages if r.get('MESSAGE','').startswith('{')]
        require(len(samples)==1,'original diagnostic stdout count')
        record,sample=samples[0]
        require(record.get('_EXE')==str(image) and int(record['_PID'])==int(launch['unit']['MainPID']),'wrong sample process')
        expected_path=recipe['SERVICE']/'expected.json'
        trusted(expected_path)
        require(sha(expected_path)=='00dedd690ae9ed8e6f193dedfd17fb4c25d7fbc67ba8c9900ce32ac6b16c1196','expected digest')
        expected=json.loads(expected_path.read_bytes())
        require(sample['schema']=='horizon266-legacy-source-sample-v2' and sample['invocation']==iid and
                sample['argv']==[str(image)] and sample['cwd']==str(recipe['SERVICE']) and
                sample['epoch']==266 and sample['car_root']==expected['car_root'] and sample['expected']==expected and
                sample['native_presence_start']==114910769 and sample['native_presence_end']==115343999 and
                sample['present_count']>=3 and sample['entry_replay'] is False and sample['full_car_verified'] is False,
                'sample contents')
        require(len(sample['samples'])==3 and all(all(o[k]==r[k] for k in ('slot','cid','offset','length')) and
                o['nodes']>0 and re.fullmatch('[0-9a-f]{64}',o['sha256'])
                for o,r in zip(sample['samples'],expected['slots'])),'CAR verification records')
        result['record']=record
        result['sample']=sample
    return result
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['build','sample'])
    parser.add_argument('launch',type=Path)
    a=parser.parse_args()
    print(json.dumps(accept(a.phase,a.launch),indent=2))
