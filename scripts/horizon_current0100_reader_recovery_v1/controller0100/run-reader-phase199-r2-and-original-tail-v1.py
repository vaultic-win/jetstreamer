from failed0030_reader_dependency import require_qualified0030_reader_retirement
require_qualified0030_reader_retirement()
from next_operation_bindings import next_operation_bindings
operation_authority=next_operation_bindings()
from pathlib import Path
import json,os,time,datetime,hashlib,subprocess,re
p=Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0100-20261109-v1')
sha=lambda b:hashlib.sha256(b).hexdigest()
def b(f):return {'path':str(f),'sha256':sha(Path(f).read_bytes())}
def save(n,v):
    f=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(f,'w') as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
    f=os.open(p,os.O_DIRECTORY);os.fsync(f);os.close(f)
assert time.time()<1794186922, 'Original0100startup cutoff expired'
prior=json.loads((p/'ROOT_PHASE_GATED_READER_ORIGINAL_OUTER.json').read_text());assert prior['code']==1 and 'retained199 advisory quiet phase differs' in prior['stderr']
old_request=json.loads((p/'ROOT_PHASE_GATED_READER_REQUEST.json').read_text());spec=json.loads(Path(old_request['reader_spec']['path']).read_text());assert not Path(spec['output_directory']).exists(), 'No original reader output namespace reuse'
phase=json.loads(Path('/home/sol/.jetstreamer-private/current-reader-phase199-recovery-qa-20261109-v2/ROOT_ACTUAL_QUALIFIED_ADVISORY_PHASE199_BINDINGS.json').read_text())
root=Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-current0100-reader-phase-r2-20261109-v1');root.mkdir(mode=0o700)
request=dict(old_request,operation_root=str(root),generation='positive-reader-0100-phase199-r2');save('ROOT_PHASE199_R2_READER_REQUEST.json',request)
avg=json.loads((p/'ROOT_PHASE_GATED_READER_ORIGINAL_ARGV.json').read_text());image_i=next(i for i,x in enumerate(avg) if x.endswith('/operation'))
avg[image_i]=phase['program']['path'];avg[avg.index('--request-sha256')-1]=str(p/'ROOT_PHASE199_R2_READER_REQUEST.json');avg[avg.index('--request-sha256')+1]=b(p/'ROOT_PHASE199_R2_READER_REQUEST.json')['sha256'];avg[avg.index('--self-sha256')+1]=phase['program']['sha256'];avg=['--unit=horizon-current0100-reader-phase199-r2-20261109-v1' if x.startswith('--unit=') else x for x in avg]
save('ROOT_PHASE199_R2_READER_ARGV.json',avg)
z=subprocess.run(avg,capture_output=True,text=True,timeout=725);save('ROOT_PHASE199_R2_READER_ORIGINAL_OUTER.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print('PHASE199_R2_READER',z.returncode,z.stdout[-3000:],z.stderr[-3000:],flush=True);assert z.returncode==0,z.stderr
phase_result=json.loads(z.stdout);original_binding=phase_result['original_reader_outer'];assert b(original_binding['path'])==original_binding
original=json.loads(Path(original_binding['path']).read_text());assert original['exit_code']==0 and original['exit_signal'] is None and original['stdout_read_error'] is None and original['stderr_read_error'] is None and not original['stdout_overflow'] and not original['stderr_overflow']
original_stdout=bytes(original['stdout_bytes']).decode();original_stderr=bytes(original['stderr_bytes']).decode();assert json.loads(original_stdout)==phase_result['actual_reader_result']
save('ROOT_FAILED4_READER0100_ORIGINAL_OUTER.json',dict(code=0,stdout=original_stdout,stderr=original_stderr,actual_owned_reader_child=original_binding,actual_phase_gated_outer=b(p/'ROOT_PHASE199_R2_READER_ORIGINAL_OUTER.json'),actual_phase=phase_result['actual_native_start_phase'],original_stdout_and_stderr_preserved=True))
parent = p / 'parent/complete_parent_capture0100_witness_v1.py'
parent_env = dict(os.environ, HORIZON_CURRENT_NATIVE_CONTINUATION_BINDINGS_SHA256=sha((p / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json').read_bytes()))
parent_argv = ['/usr/bin/python3', str(parent)]
save('ROOT_PARENT_CAPTURE0100_PREWRITTEN_ARGV.json', dict(argv=parent_argv, bindings=b(p / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json'), metadata_source=b(parent), normal_pool_bytes=6 << 30, native_actor_bytes=2 << 30, no_replay_authority=True))
z = subprocess.run(parent_argv, capture_output=True, text=True, timeout=2200, env=parent_env)
save('ROOT_PARENT_CAPTURE0100_ORIGINAL_OUTER.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print('PARENT', z.returncode, z.stdout[-6000:], z.stderr[-4000:], flush=True)
assert z.returncode == 0, z.stderr
data = p / 'parent/run_data_after0100_witness_memory_v1.py'
save('ROOT_DATA0100_PREWRITTEN_CONTINUATION_ARGV.json', dict(argv=['/usr/bin/python3', str(data)], bindings=b(p / 'ROOT_CURRENT_NATIVE_CONTINUATION_BINDINGS.json'), metadata_source=b(data)))
z = subprocess.run(['/usr/bin/python3', str(data)], capture_output=True, text=True, timeout=900, env=parent_env)
save('ROOT_DATA0100_CONTINUATION_ORIGINAL_OUTER.json', dict(code=z.returncode, stdout=z.stdout, stderr=z.stderr))
print('DATA', z.returncode, z.stdout[-6000:], z.stderr[-4000:], flush=True)
assert z.returncode == 0, z.stderr

packet=Path('/tmp/continuations0100-helper34-operation36-20261109-v1')
for index,name in enumerate(['prepare-positive185-current0100-reviewed-metadata-v1.py','invoke-positive185-current0100-next-operation-v1.py']):
    print('BEGIN',name,flush=True);argv=['/usr/bin/python3',str(packet/name)];z=subprocess.run(argv,capture_output=True,text=True,timeout=2400);save('ROOT_PHASE199_R2_TAIL_'+str(index)+'_ORIGINAL.json',dict(argv=argv,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(name,z.returncode,z.stdout,z.stderr,flush=True);assert z.returncode==0
