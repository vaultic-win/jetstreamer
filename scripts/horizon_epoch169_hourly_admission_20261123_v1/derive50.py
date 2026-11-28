"""Continue V49 on its partial original sample with an idempotent status preflight."""
import ast
import hashlib
import json
from pathlib import Path

from derive49 import one

HERE = Path(__file__).resolve().parent
OLD='tools-cold168-retry5-failed166-v49-entry146'
NEW=OLD.replace('v49','v50')
WRITER='4dd7b81551d7c2e556a3a7bafa6d2d2b6603db9abdbcf360a7cf4f22ea416307'
BOOKER='43cc72255fbeaec6e0810f9090139adc1a05b27d72bfe56450a956298d0c9007'
ACTIVE='06c15b1b1e3994506f95b38ff404f04972053337f51d222c866395090e77719d'
W48='e6c2609a84e2d5eb8029ebf91332a49b6f1db7dbb2b11047d4ba228c2b2a3f90'
A48='9ca6211354be131c738c83edb2aaf4d0439423455d7dffca7950f76e84c32eb6'
R48='bc74fb72fbcc58d0b8c5855ade3b097d2d340c07a96f87d83927f04cd34fc69c'
R49='94641b9b2dc501c0a6bcf3f8d117e94a6ef873087fd565bae6677c6432d19c96'
INITIAL='9d288f485ebd128a7f0784a73c4085f14de97b0188ebfd205be2104c6d480411'


def next_tags(s):
    for p in ('cutover', 'v', 'V'):
        s=s.replace(p+'49',p+'50').replace(p+'48',p+'49')
    return s


def cycle(s):
    s=s.replace(', 49)',', 49, 50)').replace('if FAILED166_VERSION == 49:', 'if FAILED166_VERSION in (49, 50):')
    s=s.replace('if FAILED166_VERSION == 49 and', 'if FAILED166_VERSION in (49, 50) and')
    s=s.replace('if FAILED166_VERSION == 49 else', 'if FAILED166_VERSION in (49, 50) else')
    s=one(s,'                import transition_v49','                import transition_v49\n                if FAILED166_VERSION == 50:\n                    import transition_v50')
    s=one(s,'                    modules += [split_wire, initial162, transition_v49]',
            '                    modules += [split_wire, initial162, transition_v49]\n                    if FAILED166_VERSION == 50:\n                        modules.append(transition_v50)')
    s=one(s,'    elif FAILED166_VERSION in (49, 50):\n        transition_v49',
            '    elif FAILED166_VERSION == 50:\n        transition_v50.validate(globals(), ready, receipt)\n    elif FAILED166_VERSION == 49:\n        transition_v49')
    k='                49: (transition_v49.V48_SHA, transition_v49.V48_SEAL),'
    s=one(s,k,k+'\n                50: (transition_v50.V49_SHA, transition_v50.V49_SEAL),')
    k="                    49: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    s=one(s,k,k+'\n'+k.replace('49:', '50:'))
    k="    if FAILED166_VERSION in (49, 50) and len(sys.argv) == 4:"
    pos=s.index(k);end=s.index('    if FAILED166_VERSION == 48 and len(sys.argv)',pos)
    chunk=s[pos:end]
    s=s[:pos]+chunk.replace('in (49, 50)', '== 50').replace('v49','v50').replace('V49','V50')+chunk.replace('in (49, 50)','== 49')+s[end:]
    # Inventory must see the already published receipt. The ordinary batch still
    # needs its original predecessor when it revisits the exact immutable intent.
    for epoch in (146,162):
        a=f'publish(c,store,refs,target,{epoch})\n            c.status{epoch}=refs[\'{epoch}\']'
        b=f'publish(c,store,refs,target,{epoch})\n            c.status{epoch} = refs[\'{epoch}\']'
        match=a if a in s else b
        s=one(s,match,f"preflight = dict(refs)\n            publish(c,store,preflight,target,{epoch})\n            c.status{epoch} = preflight['{epoch}']")
    s=s.replace("extra['split162_enrollment'] = old['split162_enrollment']", "extra['private162_split_enrollment'] = old['private162_split_enrollment']")
    s=s.replace("if 'split162_grant' in old:", "if 'private162_split_grant' in old:").replace("extra['split162_grant'] = old['split162_grant']", "extra['private162_split_grant'] = old['private162_split_grant']")
    return s


def watcher(s):
    s=one(s,'LISTENER = dict(',f'V50 = original.WRITER / "{NEW}"\nLISTENER = dict(')
    s=one(s,'        HERE == V49','        HERE == V50')
    s=one(s,'    if active49.exists():', '''    active50 = original.WRITER / 'FAILED166_CADENCE_V50_ACTIVE.json'
    if active50.exists():
        ref = bound(active50)
        version, directory, booker = 50, V50, original.TARGET / 'booking-price-v50'
    elif active49.exists():''')
    k=s.index('    if version == 49:');end=s.index('    if version == 48:',k);clause=s[k:end]
    s=s[:k]+clause.replace('version == 49','version == 50').replace('active48','active49').replace('ready48','ready49').replace(A48,ACTIVE).replace('v48_rebound','v49_rebound').replace('V49 lost','V50 lost')+s[k:]
    s=one(s,'route[4] not in (47, 48, 49)','route[4] not in (47, 48, 49, 50)')
    k='    if sys.argv[1:] == ["--check-entry"]:'
    s=one(s,k,'''    if sys.argv[1:] == ["--check-failed-predecessor"]:
        import status_cycle
        import recover50
        import cutover50
        ref=bound(cutover50.OLD_ACTIVE)
        need(ref['sha256'] == cutover50.OLD_OWNER and not cutover50.ACTIVE.exists()
             and resolve() is None,'different failed 143 predecessor')
        recover50.failed_owner(cutover50,checked(ref)['new'])
        print(json.dumps(dict(writer=ref)))
        return
''' +k)
    return s


def cutover(s):
    s=next_tags(s).replace(W48,WRITER).replace(A48,ACTIVE).replace(R48,R49)
    s=one(s,'    owner(active["new"], OLD)','    import recover50\n    recover50.failed_owner(sys.modules[__name__],active["new"])')
    s=one(s,'PROGRAM, "--check-entry"', 'PROGRAM, "--check-failed-predecessor"')
    s=one(s,'def endpoints(fleet):','def endpoints(fleet, listener=None):')
    s=one(s,'hourly143=preserve143()', 'hourly143=preserve143() if listener is None else listener')
    s=one(s,'    import transition_v50','    import status_cycle  # establish the sealed parent evidence import path\n    import transition_v50')
    return s


def stage(old,work):
    book=old.name=='booking-price-v49'
    raw=(old/'deployment-seal-receipt.json').read_bytes()
    if (not book and old.name!=OLD) or hashlib.sha256(raw).hexdigest()!=(BOOKER if book else WRITER):
        raise ValueError('unrecognized V49 seal')
    work.mkdir(mode=0o700)
    members={}
    def add(name,value):
        data=value.encode() if isinstance(value,str) else value
        ast.parse(data,filename=name)
        p=work/name;p.write_bytes(data);p.chmod(0o444)
        members[name]=dict(name=name,source=str(p),sha256=hashlib.sha256(data).hexdigest(),mode=0o444)
    for r in json.loads(raw)['members']:
        name=r['name'];p=old/name
        if p.resolve()!=p or p.parent!=old or hashlib.sha256(p.read_bytes()).hexdigest()!=r['sha256']:
            raise ValueError('different V49 module '+name)
        if name!='SHA256SUMS':
            members[name]=dict(name=name,source=str(p),sha256=r['sha256'],mode=int(r['mode'],8))
    if book:
        for name in ('book141.py','prepare143.py'):
            s=(old/name).read_text().replace('v49','v50').replace('V49','V50').replace('version = 49','version = 50').replace(A48,ACTIVE)
            if name=='book141.py':
                short='checked(checked(ready["old_owner"])["ready"])["old_owner"]'
                s=one(s,short,'checked(checked('+short+')["ready"])["old_owner"]')
            add(name,s)
    else:
        add('status_cycle.py',cycle((old/'status_cycle.py').read_text()))
        for name in ('full170_status.py','cold170_status.py','joint168_status.py'):
            s=(old/name).read_text()
            if f"'{OLD}')" not in s:raise ValueError(name+' missing V49')
            add(name,s.replace(f"'{OLD}')",f"'{OLD}', '{NEW}')"))
        add('cutover50.py',cutover((old/'cutover49.py').read_text()))
        add('watch143_versions.py',watcher((old/'watch143_versions.py').read_text()))
        tr=(old/'transition_v49.py').read_text()
        add('transition_v50.py',next_tags(tr).replace(A48,ACTIVE).replace(W48,WRITER).replace(R48,R49).replace("failed166_package'](48)", "failed166_package'](49)"))
        initial=Path('/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2/initial-status-tools-v1/initial162.py').read_bytes()
        if hashlib.sha256(initial).hexdigest()!=INITIAL: raise ValueError('changed real 162 first-status reader')
        add('initial162.py',initial)
        s=(old/'split_wire.py').read_text()
        s=s.replace('split162_enrollment','private162_split_enrollment').replace('split162_grant','private162_split_grant')
        add('split_wire.py',s)
        add('recover50.py',(HERE/'recover50.py').read_bytes())
    return dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(old.with_name('booking-price-v50' if book else NEW)),members=list(members.values()))
