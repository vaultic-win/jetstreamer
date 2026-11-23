"""Re-observe the sealed old loop before reusing its existing disk allowance."""
import sys,subprocess as sp,json,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from funding import D,V,M,CG,partition,price,ref,bound
import funds
with partition.take():
 name='horizon266-bounded-closure-fit-v215-'+sys.argv[1];d=D/name;fit=price(224*M,2*M,2*M);d.mkdir(mode=0o700)
 rr=D/('horizon-bounded265-residual-'+name);rr.mkdir(mode=0o700);allocation=funds.put(rr/'assignment.json',fit)
 closure=ref(D/'horizon266-stopped-close-v215-a1/completion.json');assert closure['sha256']=='5b232f4cbe088b8dda43b0173397c3120a0afabffb1c935c2a46dd7f10546892'
 retirement=ref(D/'horizon266-stopped-retire-v215-a1/completion.json');assert retirement['sha256']=='5091876032723b07a8dfdde25e88a620d8e7895f257a6099abbff61300d661a4'
 inv=ref(D/'horizon266-bounded-stopped-inventory-v215-a1/completion.json');assert inv['sha256']=='cf0b9ea9a89f287b8259d86222415e6c613222db4f224e9350acf50e0eba8d38'
 k=bound(inv);stop=bound(k['original_stop']);assert fit['closed266']==k['original_stop'] and fit['issued']==stop['original_reservation']
 ctl=V/'horizon266-stopped-bounded-v215-state'
 for phase,receipt in [('retire',retirement),('close',closure)]:
  q=bound(receipt);b=bound(q['booking']);a=bound(q['authorization']);assert b['authorization']==q['authorization'] and a['original_stop']==k['original_stop'] and a['qualification']['sha256']=='a2bb189c4fd04c4198be02ef4b04e5a41a4c17bb4f6c4c391365ae535bb10347'
  iid=b['invocation'];unit=b['manager']['Id'];assert not (CG/unit).exists()
  assert any(r.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and r['INVOCATION_ID']==iid and r.get('UNIT_RESULT','success')=='success' for r in bound(q['manager']))
  fp=ctl/('retired' if phase=='retire' else 'closed');cf=ctl/f'{phase}-confirmed-{iid}'
  assert ref(cf)==q['exact_state'] and cf.read_text()==fp.read_text()+f"confirming_invocation={iid}\nconfirming_booking={q['booking']['sha256']}\ncapacity_credit=0\n"
 census_plan=bound(k['evidence']['census']['plan']);src=Path(census_plan['cmd'][-1])
 assert ref(src) in bound(k['booking'])['source']
 unit=name+'.service'
 proc=sp.run(['systemd-run','--quiet','--pipe','--wait','--unit='+unit,*['--property='+x for x in census_plan['props']],*census_plan['cmd']],capture_output=True,timeout=320)
 assert proc.returncode==0,proc.stderr[-900:]
 c=json.loads(proc.stdout);assert c['geometry']==[804,1810,2,66305,13850126,344997011456] and not c['references'] and all('ro' in r.split(' - ')[1].split()[2].split(',') for rows in c['namespaces'].values() for r in rows)
 ev=[json.loads(l) for l in sp.check_output(['journalctl','--no-pager','-b','-o','json','_PID=1','_UID=0','UNIT='+unit,'INVOCATION_ID='+c['invocation']]).splitlines()]
 assert any(e.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' and e.get('UNIT_RESULT','success')=='success' for e in ev) and not (CG/unit).exists()
 p=fit['extent'];before=bound(bound(closure)['authorization'])['fit']['extent'];assert before['identity']==p['identity']
 fields=dict(l.split('=',1) for l in fp.read_text().splitlines()[1:]);orig=int(fields['image_allocated_before_retirement']);final=int(fields['final'])
 assert None not in [orig,final] and p['first']['blocks']==p['second']['blocks']==final and before['first']['blocks']==before['second']['blocks']==orig
 assert fields['archive']==k['members'][0]['sha256'] and fields['state']==k['members'][1]['sha256']
 assert Path('/sys/block/loop18/ro').read_text().strip()=='1' and sp.check_output(['blockdev','--getro','/dev/loop18'],text=True).strip()=='1'
 cap=p['identity']['cap'];old=bound(fit['issued']);assert old['loop']==cap and old['producer']==192000000000
 floor=fit['protected_floor']-p['remaining']+fit['disk'];margin=p['free']-floor-cap-2*(256*M)
 assert floor>=old['protected_floor']
 plan=bound(fit['planning'])
 assert plan['terminal']==k['original_stop'] and plan['partial_archive']['size']==k['members'][0]['identity'][2]
 required=sum(plan['terms'].values())
 available=p['free']-floor-2*(256*M)
 deficit=max(0,required-available)
 rel=V/'horizon266-v210-closed-growth-v215';rel.mkdir(mode=0o700)
 print(funds.put(rel/'release.json',dict(original=fit['issued'],terminal=fit['closed266'],inventory=inv,retirement=retirement,closure=closure,closed=ref(fp),proof=funds.put(d/'census.json',c),manager=funds.put(d/'pid1.json',ev),assessment=allocation,previous=before,current=p,retained_backing_bytes=final,backing_bytes_reclaimed=orig-final,conservative_physical_reclaim=min(orig-final,before['credit']-p['credit']),replaced_future_growth_bytes=p['remaining'],remaining_original_growth=0,same_reservation_only=True,producer=old['producer'],guard=old['guard'],root=cap,cpu=old['cpu'],floor=floor,qa_bytes=2*256*M,margin_for_one_successor=margin,full_planning=fit['planning'],full_workspace_required=required,available_for_full_workspace=available,full_workspace_deficit=deficit,new_replay_admitted=False,other_reservations_retained=True)),flush=True)
