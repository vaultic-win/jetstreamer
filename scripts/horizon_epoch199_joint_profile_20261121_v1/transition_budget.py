"""Reprice the original 169/172 nested HOME equation for exclusive 199/200 transfers."""
from itertools import combinations

G = 1 << 30
BOOK = 16 << 20
STATIC = 8297502499408
CAP = {166:288*G, 167:512*G, 168:288*G, 170:384*G}
ALL_CAP = {**CAP,172:288*G}
PRESTART = {166:169028829184, 167:177601941504, 170:230591926272}
GENERATIONS = {166:'3c220efd0d0740f59572a96447e83762', 167:'0876e9944c784b41afeff1b666539ead',
               168:'9cebb1d022124fb08588e93e055d5446', 170:'a456b826ce1c4634a2df66d66c5cc07f',172:'0e17b745938546608b0bdc52815151d0'}
MEM = 810658050048

def need(test, explanation):
    if not test:
        raise ValueError(explanation)

def calculate(fit, ledger, fleet, prior169, transfers, closed, host_ram, cpus):
    """Amounts for future repair/restore stay in each immutable original envelope."""
    books=fit['bookings']
    x=ledger['native_inputs']
    audit=fleet['continuing_audit_obligation']
    resident=fit['joined_resident_lower_bounds']
    remaining={e:books[str(e)]['remaining_bytes'] for e in CAP}
    is_closed=172 in closed
    present=set(CAP)|({172} if is_closed else set())
    diag=fit.get('closed_focused169')
    if diag:
        focused=books['169']
        need(diag['terminal']==fleet.get('focused169_terminal') and diag['guard_retirement']==fleet.get('focused169_guard_retirement') and
             diag['resource_credit_bytes']==0 and 0<=focused['remaining_bytes']<=96*G and
             focused['cap_bytes']==96*G==focused['remaining_bytes']+focused['physical_bytes'] and
             fit['registered_host_equation']['retained_169_remaining']==focused['remaining_bytes'] and
             fit['registered_host_equation']['retained_169_plan']==focused['plan']==diag['actual_guard_plan'],'unfunded closed focused diagnostic')
    else:need(fleet.get('focused169_terminal') is None and fleet.get('focused169_guard_retirement') is None,'missing diagnostic closure')
    if is_closed:
        remaining[172]=books['172']['remaining_bytes']
    need(set(map(int,books))==present|({169} if diag else set()) and all(books[str(e)]['physical_bytes']+remaining[e]==ALL_CAP[e]==books[str(e)]['cap_bytes'] and 0<=remaining[e]<=ALL_CAP[e] for e in present),'different producer bookings')
    need(set(transfers)<=set(closed)<=set(ALL_CAP) and set(map(int,resident))==set(CAP)-set(closed),'different original population')
    need(fit['epoch']==145 and fit['resource_credit_bytes']==fit['stopped_generation_resident_credit_bytes']==0 and fit['replay_launch_authorized'] is False and fit['complete_memory_plus_reserve_bytes']==MEM and fit['complete_cpu_quota_micros']==64000000 and cpus==64,'different base funding authority')
    need(host_ram>=MEM and set(fit['survivors'])==((set() if diag else {'169'}) | (set() if is_closed else {'172'})) and fit['candidate136']['remaining']>=0,'changed survivor provider')
    retained={e:t['retained_growth_bytes'] for e,t in transfers.items()}
    for e,t in transfers.items():
        need(type(retained[e]) is int and retained[e]>=BOOK and type(t['maximum_transfer_bytes']) is int and 0<=t['maximum_transfer_bytes']<=ALL_CAP[e],'invalid transfer envelope')
    cash={e:min(t['maximum_transfer_bytes'],max(0,remaining[e]-retained[e])) for e,t in transfers.items()}
    # Charge delivery even if a committed producer has not transferred its allowance.
    pub_growth=(set(closed)-set(transfers))
    charges=len(pub_growth)*BOOK
    # Retaining a floor larger than the current residual may not be funded by the old cap.
    charges+=sum(max(0,retained[e]-remaining[e]) for e in transfers)
    ext=fit['epoch170_extension']['extra_bytes']
    need(ext==96*G,'foreign extended original allowance')
    # The extension was added outside the nested 169/172 floor. Older standard
    # peer/independent balances are inside its original pre-169 aggregate.
    extension_transfer=min(ext,cash.get(170,0))
    shared=max(x['historical_floor_bytes'],audit['configured_free_floor_bytes'])+x['roots']['peer_remaining_growth_bytes']+10*G+x['auxiliary']['remaining_growth_bytes']+(64<<20)+x['independent166_whole_cap_bytes']+18*G
    a=dict(floor=0,remaining=focused['remaining_bytes']) if diag else fit['survivors']['169']['guard']
    if is_closed:
        b=dict(floor=0,remaining=remaining[172])
        need(fit['registered_host_equation']['retained_172_remaining']==b['remaining'] and fit.get('closed_full172'),'absent full172 retained booking')
    else:
        b=fit['survivors']['172']['guard']
    def pre136(raw_shared,remaining168,extension,guard172,remaining172):
        base=max(raw_shared+remaining168,prior169,STATIC+remaining168)
        raw=max(max(base,a['floor'])+a['remaining']+16*G,guard172)+remaining172+(128<<20)+extension
        return base,raw
    base,raw=pre136(shared,remaining[168],ext,b['floor'],b['remaining'])
    need(base==fit['registered_host_equation']['rebased_floor'] and raw==fit['original_aggregate_HOME_bytes'],'original inner HOME equation failed')
    shared-=sum(cash.get(e,0) for e in (166,167,170))-extension_transfer
    _,adjusted=pre136(shared,remaining[168]-cash.get(168,0),ext-extension_transfer,0 if 172 in transfers else b['floor'],b['remaining']-cash.get(172,0))
    c=fit['candidate136']
    spent=sum(prior-remaining[e] for e,prior in PRESTART.items())
    deficit=sum(max(0,bk['historical_realized_bytes']-bk['physical_bytes']) for bk in books.values())
    need(deficit==fit['historical_baseline_deficit_bytes'],'historical occupancy deficit differs')
    floors=[STATIC,a['floor'],0 if is_closed else b['floor'],c.get('guard_floor',0),fit['active168_guard_floor'],*[v['floor'] for v in fit['replacements'].values()]]
    absolute=max(floors)
    def disk(raw):
        return max(max(raw+deficit-spent,c.get('guard_floor',0))+c['remaining'],absolute)
    need(disk(raw)==fit['complete_required_HOME_bytes'],'native outer HOME equation failed')
    hard=MEM-len(transfers)*66*G
    live=fit['required_available_memory_bytes']-len(transfers)*66*G
    cpu=fit['complete_cpu_quota_micros']-len(set(transfers)&set(CAP))*8000000
    floor=disk(adjusted)+charges
    need(floor>=absolute and 0<live<=hard and 0<cpu<=64000000,'invalid projected totals')
    effective=dict(fit,complete_required_HOME_bytes=floor,complete_memory_plus_reserve_bytes=hard,required_available_memory_bytes=live,complete_cpu_quota_micros=cpu)
    gaps=dict(disk=max(0,floor+448*G-fit['available_HOME_bytes']),committed_memory=max(0,hard+153*G-host_ram),available_memory=max(0,live+153*G-fit['available_memory_bytes']),cpu_quota_micros=max(0,cpu+8000000-cpus*1000000))
    return effective,dict(closed=sorted(closed),transferred=sorted(transfers),actual_unspent_transferred_bytes=cash,retained_growth_bytes=retained,absolute_surviving_floor_bytes=absolute,complete_protected_HOME_bytes=floor,candidate_HOME_bytes=448*G,committed_memory_before_candidate=hard,required_available_memory_before_candidate=live,committed_cpu_micros_before_candidate=cpu,gaps=gaps)

def scenarios(fit,ledger,fleet,prior169,ram,cpus,current_closed):
    """Sensitivity only. Preserve each surviving guard and all future growth at each max."""
    rows=[]
    for size in range(6):
        for seq in combinations(ALL_CAP,size):
            hypothetical=set(seq)|set(current_closed)
            candidate=dict(fit,replacements={k:v for k,v in fit['replacements'].items() if int(k) not in hypothetical},joined_resident_lower_bounds={k:v for k,v in fit['joined_resident_lower_bounds'].items() if int(k) not in hypothetical},active168_guard_floor=0 if 168 in hypothetical else fit['active168_guard_floor'])
            # Retired resident pages are no longer prepaid in a complete future sample.
            candidate['required_available_memory_bytes']=fit['required_available_memory_bytes']+sum(v for k,v in fit['joined_resident_lower_bounds'].items() if int(k) in hypothetical)
            if 172 in hypothetical and '172' in candidate['survivors']:
                live=candidate['survivors']['172']
                b=live['guard']
                newbook=dict(remaining_bytes=b['remaining'],cap_bytes=b['cap'],physical_bytes=b['cap']-b['remaining'],historical_realized_bytes=0,retired_guard_floor=b['floor'])
                candidate=dict(candidate,bookings={**candidate['bookings'],'172':newbook},survivors={'169':candidate['survivors']['169']},closed_full172={'arithmetic_only':True},registered_host_equation={**candidate['registered_host_equation'],'retained_172_remaining':b['remaining']},required_available_memory_bytes=candidate['required_available_memory_bytes']+live['resident'])
                # The ordinary five-source fit retires the absolute 172 threshold only
                # after its native guard has drained. Its unspent balance still survives.
                guard169=candidate['survivors']['169']['guard']
                before172=max(candidate['registered_host_equation']['rebased_floor'],guard169['floor'])+guard169['remaining']+16*G
                candidate['original_aggregate_HOME_bytes']-=max(0,b['floor']-before172)
            spent=sum(n-candidate['bookings'][str(e)]['remaining_bytes'] for e,n in PRESTART.items())
            c=candidate['candidate136']
            protected=max(candidate['original_aggregate_HOME_bytes']+candidate['historical_baseline_deficit_bytes']-spent,c.get('guard_floor',0))+c['remaining']
            candidate['complete_required_HOME_bytes']=max(protected,STATIC,c.get('guard_floor',0),candidate['active168_guard_floor'],*[v['floor'] for v in candidate['replacements'].values()],*[v['guard']['floor'] for v in candidate['survivors'].values()])
            allowed={e:dict(retained_growth_bytes=BOOK,maximum_transfer_bytes=ALL_CAP[e]) for e in seq}
            _,row=calculate(candidate,ledger,fleet,prior169,allowed,hypothetical,ram,cpus)
            rows.append(row)
    return rows
