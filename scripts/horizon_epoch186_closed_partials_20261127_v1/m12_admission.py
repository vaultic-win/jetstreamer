"""Reuse the charged Anza serial holding slot for the closed epoch 186 M12 partial."""
import ctypes
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time

import rotation as op

ROOT = op.OUT/'m12'
PINS = (101713325, 43292107574, '3cc39b3562d257f266d5c430fd7b115dfac5450ad1bd0785a61c5039ec6724ac')
EVIDENCE = {
    'SOURCE_AND_CONSUMERS_1795818418795113448.json':'d4f5dca40fe85cf8b1ab749b40bcc353a3040eeaa0e47a24255bbbef7332c091',
    'DIGEST_COMPLETE.json':'a4872b780ce000a9db796721e5b5109de7421409fe116418f80adbf9245554d2',
    'eligibility.json':'97cc874302d7fea3e63059fc9978c7267b666a440572fe497d222e95ceaac7cb',
    'expected.json':'ea1623bdbf4a9b54fc5e7d167152877288976642f2baa55bf240fb8ecdfa0b06',
    'plan.json':'09aa45d71a85a212bc29c8830f1600579015dbe30df854ec5d63dc97df3a497b',
}
PREVIOUS = 'horizon-qualify-170-from-73746882-20261127-v1.service'
NEXT = 'horizon-qualify-170-from-73766969-20261127-v1.service'
PREVIOUS_IID = 'c3ab30cfeb05428bb8f5c48a5a44822c'
SCOPE = op.RT/'epoch162-first-hourly-completion-20261127-v2/issued-price-v3'
FOURTH = op.RT/'epoch170-from-73766969-20261127-v1/operator-v5'
PRICE = {
    SCOPE:('f431f64b7b51dc24d6427fbf2e42e98f749d27e2fc382bb9fb743376042e5f56','capacity.py'),
    FOURTH:('45011b4930da3a9b88c239441881905ae040790bae3297b2de85bccdefd921f9','continuation_price.py'),
}
M12_EXP = 'ea1623bdbf4a9b54fc5e7d167152877288976642f2baa55bf240fb8ecdfa0b06'
PHASES = {'park':(2*op.G,'2s'), 'retire':(op.G,'1s'), 'restore':(2*op.G,'1s')}
SERIAL_PATS=('horizon-*park*','horizon-*holding*','horizon-*retire*','horizon-*restore*','horizon-closed186-*')


def inputs():
    refs = {k:op.fixed(ROOT/k,h) for k,h in EVIDENCE.items()}
    old = op.bound(refs['SOURCE_AND_CONSUMERS_1795818418795113448.json'])
    digest = op.bound(refs['DIGEST_COMPLETE.json'])
    plan = op.bound(refs['plan.json'])
    eligible = op.bound(refs['eligibility.json'])
    expected = op.bound(refs['expected.json'])
    ident = old['identity']
    op.need(old['lane']=='m' and old['producer']['unit'].endswith('e186-186-lane-m-12.service')
            and not old['live_references'] and not old['staged']['rows'][0]['unresolved_units']
            and digest['source']==refs['SOURCE_AND_CONSUMERS_1795818418795113448.json']
            and digest['identity']==ident and digest['allocated']==old['allocated']==ident[7]*512
            and (ident[1],ident[6],digest['digest'])==PINS and digest['native']['Result']=='success'
            and digest['native']['ExecMainStatus']=='0' and not digest['resource_credit_bytes']
            and plan['source']==eligible['source']==expected['source']==old['source']
            and plan['sha256']==eligible['sha256']==expected['sha256']==digest['digest']
            and eligible['producer_attempt']==12 and eligible['closed'] and not eligible['canonical_publication_authorized']
            and plan['eligibility']==refs['eligibility.json'] and expected['object_key']=='node_02/objects/'+digest['digest']+'.blob'
            and expected['manifest_key']=='node_02/manifests/'+expected['manifest_sha256']+'.json'
            and expected['single_copy_peak']==PINS[1]+op.META and expected['retained_shared_serial_slot']==op.SLOT,
            'unexpected M12 partial or custody plan')
    profile = {k:old[k] for k in ('source','lane','producer','cohort','identity','allocated','epoch_lock','lock_identity')}
    profile.update(rotation_lane='m12',sha256=digest['digest'],source_bindings=refs)
    return profile


def profile():
    row = inputs()
    op.need(op.bound(op.ref(ROOT/'profile.json'))==row,'different sealed M12 profile')
    return row


def serial_handoff():
    receipt = op.fixed(op.OUT/'N_SERIAL_HANDBACK.json','46bdfc158b25a04d70f5eda8157cad325f29315260b36394cf3597da360fe7dd')
    previous = op.bound(receipt)
    native = op.bound(previous['native_custody'])
    retired = op.bound(previous['retirement'])
    op.need(previous['return_to']=='campaign controller' and previous['remote_sha256_readback']
            and native['remote_sha256_readback'] and native['local_source_revalidated']
            and retired['allocated_bytes_removed']==previous['allocated_bytes_removed']==28562640896
            and previous['native_custody']==op.bound(previous['park'])['native_custody']
            and not Path(retired['source']).exists()
            and previous['retained_serial_restore']==op.SLOT and not previous['canonical_publication'],
            'N serial custody or handback has changed')
    return [receipt]


def list_units(*patterns):
    data=op.consumers.system('list-units','--no-legend','--plain','--type=service',
                             '--state=running,activating,deactivating,reloading',*patterns)
    return {r.split()[0] for r in data.splitlines() if r.strip()}


def manager(unit):
    data=op.consumers.system('show','--all','-p','Id,ActiveState,InvocationID,MainPID,ControlGroup,Job,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec',unit)
    return dict(s.split('=',1) for s in data.splitlines() if '=' in s)


def sealed_module(directory):
    digest, name = PRICE[directory]
    seal = op.fixed(directory/'deployment-seal-receipt.json',digest)
    pkg = op.bound(seal)
    op.need(pkg['destination']==str(directory) and len(pkg['members'])==len({r['name'] for r in pkg['members']}),'foreign native price')
    for obj in pkg['members']:
        path=directory/obj['name']
        st=path.lstat()
        op.need(path.parent==directory and path.resolve()==path and st.st_uid==0
                and not st.st_mode & 0o222 and st.st_size==obj['bytes'],'different native price member')
        op.fixed(path,obj['sha256'])
    return seal,directory/name


def external_price(directory,phase=None):
    # Its accounting imports an older, sealed copy of rotation and n_admission.
    # Keep those module names independent from the active M12 service.
    seal,path = sealed_module(directory)
    code=("import json,runpy,sys; s=runpy.run_path(sys.argv[1]); "
          "q=s['whole_roster']() if len(sys.argv)==2 else s['price'](sys.argv[2]); print(json.dumps(q))")
    args=['/usr/bin/python3','-IB','-c',code,str(path)]
    if phase:args.append(phase)
    return json.loads(subprocess.check_output(args,text=True,timeout=120)),seal


def funding(live, disk, ram):
    # The common price already includes both independent 2 GiB slots. Use only
    # the holding slot here. Retain its full restoration reservation throughout.
    op.need(isinstance(disk,int) and isinstance(ram,int) and live['restore_overlap']==op.SLOT
            and live['serial_ram']==2*op.G and live['scanner_ram']==2*op.G
            and not live['credit'] and disk==live['available']-live['floor']
            and live['following_growth']==36*op.G, 'different shared serial or 170 funding')
    return dict(remaining_home=disk,remaining_ram=(0 if ram<0 else 2*op.G+ram),
                floor=live['floor'],available_home=live['available'],post_reservation_ram_margin=ram,
                serial_slot=op.SLOT,holding_ram_available_from_serial=2*op.G,resource_credit_bytes=0)


def owners(q):
    fleet=op.bound(q['fleet'])
    latest=max(op.RT.glob('root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),key=lambda p:p.stat().st_mtime_ns)
    op.need(q['fleet']['path']==str(latest) and fleet['all_active_status_reports_authenticated_readback']
            and not fleet['resource_credit_bytes'],'different accepted full fleet')
    ids=q['owners']
    op.need(list_units('horizon-qualify-*')==set(ids),'M12 price lost an active producer')
    for name,iid in ids.items():
        s=manager(name)
        op.need(s['Id']==name and s['ActiveState']=='active' and s['InvocationID']==iid
                and not s['Job'] and int(s['MainPID'])>0 and s['ControlGroup']=='/system.slice/'+name
                and Path('/proc',s['MainPID'],'cgroup').read_text().strip()=='0::'+s['ControlGroup'],
                'changed funded producer '+name)


def price():
    current=list_units('horizon-qualify-*')
    op.need(not {PREVIOUS,NEXT}<=current,'overlapping 170 producers')
    if PREVIOUS in current:
        q,seal=external_price(SCOPE)
        base=q['base_169']; raw=base['native']['raw']
        op.need(q['schema']=='horizon-168-post-assembly-six-owner-price-v1' and q['resource_credit_bytes']==0
                and base['resource_credit_bytes']==0 and raw['priced_170_invocation']==PREVIOUS_IID
                and raw['assembly168']['state']=='queued-or-drained'
                and not raw['resource_credit_bytes'] and q['fleet']==base['fleet']
                and q['package']==seal,'foreign five-owner price')
        # An unissued 162 file is the outcome of reclamation. Once issued, use
        # its actual additional space, guard floor and remaining reservations.
        selected=base if q['prospective_162'] else q
        owners_by_unit={r['unit']:r['invocation_id'] for r in base['observed_actors']}
        proof=dict(available=q['available_home'],restore_overlap=raw['auxiliary']['serial_restore_overlap_already_reserved'],
                   following_growth=raw['candidate_170_growth_bytes'],serial_ram=base['accounting']['rooms']['holding_ram_available_from_serial'],
                   scanner_ram=base['accounting']['verification168_listener']['scanner_ram_from_serial'],credit=base['resource_credit_bytes'])
        # The native minimum includes historical protections as well as hard
        # floors. Reconstruct that exact effective floor for resumed restoration.
        proof['floor']=q['available_home']-selected['home_margin']
        amounts=funding(proof,selected['home_margin'],selected['ram_margin'])
        holding=base['accounting']['holding']
        native_time=q['recorded_unix_seconds']
    else:
        q,seal=external_price(FOURTH,'held' if NEXT in current else 'start')
        peers=q['split_peers'];before=peers['before']
        op.need(q['phase'] in ('held','start') and q['resource_credit_bytes']==0 and
                q['fleet']==before['fleet'] and q['shared_slot']['repeated_serial_bytes']==2*op.G
                and q['assembly168']['state']=='queued-or-drained','foreign fourth-interval price')
        fleet=op.bound(q['fleet'])
        rows=fleet['actual_executing_replays']+fleet['actual_active_private_diagnostics']+fleet['actual_active_bootstraps']
        owners_by_unit={r['unit']['Id']:r['unit']['InvocationID'] for r in rows if r['epoch'] not in (162,169,170)}
        for peer in (peers['after169'],peers['after162']):
            if peer and peer['phase']!='terminal':
                owners_by_unit[peer['unit']['Id']]=peer['unit']['InvocationID']
        if q['priced_170_invocation']:
            owners_by_unit[NEXT]=q['priced_170_invocation']
        if q['replacement143']:
            owners_by_unit[q['replacement143']['unit']]=q['replacement143']['iid']
        proof=dict(available=q['available_home'],floor=q['available_home']-q['home_margin'],
                   restore_overlap=q['auxiliary']['serial_restore_overlap_already_reserved'],
                   following_growth=q['candidate_170_growth_bytes'],serial_ram=q['shared_slot']['repeated_serial_bytes'],
                   scanner_ram=q['private_verification168']['scanner_ram_from_serial'],credit=q['resource_credit_bytes'])
        amounts=funding(proof,q['home_margin'],q['ram_margin'])
        holding=q['holding']
        native_time=time.time()
    op.need(0<=time.time()-native_time<30,'stale M12 provider response')
    scope=Path('/proc/self/cgroup').read_text().strip().removeprefix('0::')
    escrow=list_units(*SERIAL_PATS)
    if re.fullmatch(r'/system.slice/horizon-closed186-(park|retire|restore)-m12-[0-9]+\.service',scope):
        op.need(escrow=={Path(scope).name} and holding and holding.get('native',{}).get('Id')==Path(scope).name,
                'unrecognized current holding invocation')
    else:
        op.need(not escrow,'another serial holding operator is active')
        # The storage client's flock is exclusive even outside a named service.
        import n_admission
        n_admission.serial_owner()
    result=dict(basis=q,provider=seal,utc=time.time(),fleet=q['fleet'],owners=owners_by_unit,
                verification_and_turnover=proof,serial_owner=holding,**amounts)
    owners(result)
    return result


def arm(directory,phase,token,unit,iid,start,ram):
    st=manager(unit)
    cap,quota=PHASES[phase]
    expected=op.fixed(directory/'expected.json',M12_EXP)
    e=op.bound(expected)
    record=op.bound(start)
    op.need(directory==ROOT and unit==f'horizon-closed186-{phase}-m12-{token}.service' and token.isdecimal()
            and re.fullmatch('[0-9a-f]{32}',iid) and st['Id']==unit and st['InvocationID']==iid
            and st['ActiveState']=='active' and not st['Job'] and int(st['MainPID'])>0
            and st['ControlGroup']=='/system.slice/'+unit and st['MemoryMax']==str(cap) and ram==cap
            and st['MemorySwapMax']=='0' and st['CPUQuotaPerSecUSec']==quota and record['phase']==phase
            and record['unit']==unit and record['source']==e['source'] and record['extra_memory']==cap,
            'different provisional M12 service')
    return op.save(directory/f'ADMISSION_{phase}_{token}.json',dict(unit=unit,invocation=iid,phase=phase,
          start=start,expected=expected,ram=cap,swap=0,restore_slot=e['retained_shared_serial_slot'],
          restore_peak=e['single_copy_peak'],canonical_publication=False,
          scope='Only reserves the serial holding slot for this invocation; the native entry must reprice before any payload action.'))


def wait_arm(path, timeout=30):
    """The service can be scheduled before systemd returns its ID to the dispatcher."""
    fd=op.libc.inotify_init1(os.O_CLOEXEC)
    if fd<0:raise OSError(ctypes.get_errno(),'inotify_init1')
    try:
        watch=op.libc.inotify_add_watch(fd,os.fsencode(path.parent),0x80|0x100|0x400|0x800)
        if watch<0:raise OSError(ctypes.get_errno(),'inotify_add_watch')
        deadline=time.monotonic()+timeout
        while not path.exists():
            remaining=deadline-time.monotonic()
            op.need(remaining>0,'timed out awaiting serial dispatch admission')
            if select.select([fd],[],[],remaining)[0]:
                os.read(fd,65536)
    finally:
        os.close(fd)


def validate_arm(directory,phase,token,unit,iid,ram):
    a=op.bound(op.ref(directory/f'ADMISSION_{phase}_{token}.json'))
    e=op.fixed(directory/'expected.json',M12_EXP)
    st=manager(unit)
    op.need(a['unit']==unit and a['invocation']==iid==st['InvocationID'] and a['phase']==phase
            and a['expected']==e and a['ram']==ram and not a['canonical_publication'] and
            a['restore_slot']==op.SLOT and st['MainPID']==str(os.getpid()),'changed M12 phase admission')
    s=op.bound(a['start'])
    op.need(s['source']==op.bound(e)['source'] and s['unit']==unit and s['phase']==phase and s['extra_memory']==ram,
            'M12 dispatch changed after admission')
