import sys
from pathlib import Path
root=Path('/tmp/horizon247-current-fadfe2d4-v2')
sys.path.insert(0,str(root))
from owner_seal import *
need(os.geteuid()==0 and os.environ.get('CODEX_THREAD_ID')==MAIN,'owner')
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import funding as live_fit
reservation_lock=live_fit.partition.take()
price=live_fit.price(352*live_fit.M,2*live_fit.M,2*live_fit.M,closed_disk=(live_fit.V/'horizon266-closed-residual-delivery265-v215/assignment.json').exists())
import funds
ledger=D/("horizon-bounded265-residual-seal-consumers265-v215-"+sys.argv[1]);ledger.mkdir(mode=0o700);funds.put(ledger/"assignment.json",price)
tag='horizon265-delivery-consumers-v215-'+sys.argv[1]
stage=Path('/run')/tag;out=stage/'result';diag=D/tag;unit=tag+'.service'
dest=Path('/var/lib/jetstreamer')/(tag+'-qualified')
commit=git('rev-parse',sys.argv[2]+'^{commit}').strip()
git('merge-base','--is-ancestor',commit,'origin/account-updates')
q=load(out/'qualification.json');iid=q['invocation_id'];recipe=load(stage/'offline-qualification.json')
commands=load(stage/'commands.json');booking=load(stage/'booking.json')
need(q['unit']==unit and booking['source']==recipe['commit']==commit and booking['unit']==unit and not q['archive_io'] and not q['authority'] and load(diag/'booking.json')==load(stage/'booking.json'),'booking')
need(set(p.name for p in out.iterdir())==OUTPUTS|{'library-tests','wrapper-tests'},'expected outputs')
for p in out.iterdir():regular(p,1000)
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-','')
pid1=journal('_PID=1','_UID=0','UNIT='+unit,'INVOCATION_ID='+iid)
ids=['7d4958e842da4a758f6c1cdc7b36dcc5','39f53479d3a045ac8e11786248231fbf','7ad2d189f7e94e70a38c781354912448']
need(not (Path('/sys/fs/cgroup/system.slice')/unit).exists() and all(e['_BOOT_ID']==boot and e.get('UNIT_RESULT','success')=='success' for e in pid1) and [e['MESSAGE_ID'] for e in pid1 if e.get('MESSAGE_ID') in ids]==ids,'incomplete terminal')
pairs=diag/'bounded-test.json'
need(load(pairs)['code']==0 and 'bounded_writer_reopens_its_runtime_and_issued_booking ... ok' in load(pairs)['stdout'] and '1 passed; 0 failed' in load(pairs)['stdout'], 'bounded original handoff')
stage_files=('build.py','booking.json','source.sha256','inputs.sha256','commands.json','externs.sha256','tools.sha256','offline-qualification.json')
for n in stage_files:regular(stage/n,0)
old=Path('/var/lib/jetstreamer/horizon191-193-fleet-consumers-a1-qualified')
for n in ('commands.json','externs.sha256','tools.sha256'):
 need(ref(old/n)['sha256']==ref(stage/n)['sha256'],'predecessor '+n)
paths=sorted(manifest(stage/'source.sha256'))
head=git('rev-parse','origin/account-updates').strip()
graph0=load(out/'compiler-inputs.json')
used=sorted(set().union(*(set(v) for k,v in graph0.items() if k not in ('jetstreamer-r2.d','r2-tests.d'))))
need(not git('diff','--name-only',commit,head,'--',*used).strip(),'observer/wrapper transitive compiled inputs moved')
need(not git('diff','--name-only',commit,head,'--','Cargo.lock','Cargo.toml','.cargo','rust-toolchain.toml','vendor','jetstreamer-horizon-observe/Cargo.toml').strip(),'observer Cargo build inputs moved')
scope=dict(fetched_head=head,build_commit=commit,eligible_images=['terminal-aware-observe','jetstreamer-horizon-observe'],compiled_inputs=used,changed_paths=git('diff','--name-only',commit,head).splitlines(),observation_only=True)
src=(root/'owner_seal.py').read_text()
import textwrap
validation=textwrap.dedent(src[src.index('    for key, name in'):src.index('    return diag, dest')])
validation=validation.replace("tree[n]==['100755' if path.stat().st_mode&0o111 else '100644','blob',oid]", "stat.S_IMODE(path.stat().st_mode)==0o444 and tree[n][0] in ('100644','100755') and tree[n][1:]==['blob',oid]")
exec(validation)
os.umask(0o022)
same(diag/'pid1.json',bundle(pid1))
files=[*(stage/n for n in stage_files),*(out/n for n in sorted(OUTPUTS)),pairs,diag/'pid1.json']
for a in q['artifacts']:
 n=Path(a['path']).name;p=diag/(n+'-provenance.json')
 same(p,bundle(dict(provenance,artifact=dict(path=str(dest/n),sha256=a['sha256']))));files.append(p)
members=[dict(name=p.name,source=str(p),sha256=ref(p)['sha256'],mode=0o555 if p.name in IMAGES else 0o444) for p in files]
planfile=diag/'owner-seal.json'
same(planfile,bundle(dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(dest),members=members)))
seal=apply(planfile)
completion=dict(unit=unit,invocation=iid,source=commit,pid1=ref(diag/'pid1.json'),original_pairs=ref(pairs),seal=seal,compiler=ref(dest/'qualification.json'),binaries={n:ref(dest/n) for n in IMAGES},wrapper_observer=q["wrapper_observer"],canonical_247_publication=False,branch_scope=scope)
same(diag/'deployment.json',bundle(completion));print(ref(diag/'deployment.json'))
