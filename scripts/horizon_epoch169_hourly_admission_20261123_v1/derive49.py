"""Derive a successor for the V48 cadence and matching 143 entry from their native seals."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = 'tools-cold168-retry5-failed166-v48-entry146'
NEW = OLD.replace('v48','v49')
WRITER = 'e6c2609a84e2d5eb8029ebf91332a49b6f1db7dbb2b11047d4ba228c2b2a3f90'
BOOKER = '644097943f7e55b0b097331dea35ac4a61df51bb30029978c62374a8e9344972'
ACTIVE = '9ca6211354be131c738c83edb2aaf4d0439423455d7dffca7950f76e84c32eb6'
OLD_ACTIVE = 'def64d8842984dee1835c05aefa8b5f344c52f9b97e8691db123b1cce2daca86'
OLD_SEAL = 'cdeef56bc6fddb7189be65ace5a72468514ed97d08b470be5248d79da8177f55'
REBOUND = 'bc74fb72fbcc58d0b8c5855ade3b097d2d340c07a96f87d83927f04cd34fc69c'


def one(s,old,new):
    if s.count(old) != 1:
        raise ValueError('changed V48 source: '+old)
    return s.replace(old,new)


def cycle(s):
    s=s.replace(', 48)',', 48, 49)').replace('== 48 and split_status169', 'in (48, 49) and split_status169')
    s=s.replace('if FAILED166_VERSION == 48:', 'if FAILED166_VERSION in (48, 49):')
    s=s.replace('if FAILED166_VERSION == 48 and c.split', 'if FAILED166_VERSION in (48, 49) and c.split')
    s=s.replace('if FAILED166_VERSION == 48 and epoch', 'if FAILED166_VERSION in (48, 49) and epoch')
    s=one(s,'            import transition_v48','''            import transition_v48
            if FAILED166_VERSION == 49:
                import initial162
                import split_wire
                import transition_v49''')
    s=one(s,'                modules += [transition_v48, split_status169, status162]','''                modules += [transition_v48, split_status169, status162]
                if FAILED166_VERSION == 49:
                    modules += [split_wire, initial162, transition_v49]''')
    s=one(s,'    elif FAILED166_VERSION in (48, 49):\n        transition_v48','''    elif FAILED166_VERSION == 49:
        transition_v49.validate(globals(), ready, receipt)
    elif FAILED166_VERSION == 48:
        transition_v48''')
    s=one(s,'                48: (transition_v48.V47_SHA, transition_v48.V47_SEAL),','''                48: (transition_v48.V47_SHA, transition_v48.V47_SEAL),
                49: (transition_v49.V48_SHA, transition_v49.V48_SEAL),''')
    slot="                    48: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    s=one(s,slot,slot+'\n'+slot.replace('48:', '49:'))
    anchor="    if FAILED166_VERSION == 48 and len(sys.argv) == 4:"
    s=one(s,anchor,'''    if FAILED166_VERSION == 49 and len(sys.argv) == 4:
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        if sys.argv[1] == '--check-v49-handoff':
            print(json.dumps(transition_v49.ready(globals(), head, receipt)))
            return
        if sys.argv[1] == '--enroll-next-bounded-170':
            os.umask(0o077)
            print(json.dumps(successor170_status.enroll(globals(), head, bound(ROOT/'FAILED166_CADENCE_V49_ACTIVE.json'))))
            return
''' +anchor)
    s=one(s, '        c.split162 = status162.observe(c, cycle.observed_lane)', '''        from functools import partial
        callback162 = partial(cycle.observed_lane, private_journal=True) if FAILED166_VERSION == 49 else cycle.observed_lane
        c.split162 = status162.observe(c, callback162)''')
    anchor="        elif epoch in getattr(c,'new_rows',{}):"
    s=one(s,anchor,'''        elif FAILED166_VERSION == 49 and epoch in (162,169) and (row := getattr(c,f'split{epoch}',None)) and (
                row['phase'] != 'terminal' or old.get('producer_invocation_id') is not None):
            after,extra=split_wire.forecast(c,row,prior,old,original,delivery_eta.estimate)
''' +anchor)
    anchor="    previous_completions = set(map(int, c.fleet.get('retained_publication_completions', {})))"
    s=one(s,anchor,'''    if FAILED166_VERSION == 49:
        c.status162 = initial162.baseline(c, refs.pop('162', None))
''' +anchor)
    anchor='    if FULL146_CADENCE and c.status146:'
    s=one(s,anchor,'''    if FAILED166_VERSION == 49 and c.status162:
        extra162 = {'162':c.status162}
        read_statuses(store,extra162,target)
        refs.update(extra162)
        c.status162=refs['162']
        if (target/'epoch-162.intent.json').exists():
            publish(c,store,refs,target,162)
            c.status162=refs['162']
''' +anchor)
    anchor='    original = checked(c.prior[\'inventory\'], root=False)'
    s=one(s,anchor,'''    if FAILED166_VERSION == 49:
        ref162 = c.status162
        need((162 in statuses) == bool(ref162), 'unexpected or missing split 162 status')
        if ref162:
            need(162 not in ready and 162 not in archives,'split 162 status conflicts with canonical object')
            authenticated(store,162,ref162)
            statuses = statuses - {162}
''' +anchor)
    s=one(s,"        c.status146 = refs.get('146')","        c.status146 = refs.get('146')\n    if FAILED166_VERSION == 49:\n        c.status162 = refs.get('162')")
    s=one(s,"if k not in ('140','146')","if k not in ('140','146','162')")
    anchor="            extra.update(status162.status_fields(c.split162))"
    s=one(s,anchor,anchor+"""
            if FAILED166_VERSION == 49:
                extra['split162_enrollment'] = old['split162_enrollment']
                if 'split162_grant' in old:
                    extra['split162_grant'] = old['split162_grant']""")
    anchor="        status162.install(fleet, c.split162)"
    s=one(s,anchor,anchor+"""
        if FAILED166_VERSION == 49:
            for epoch, row in ((162,c.split162),(169,c.split169)):
                if row and row['phase'] != 'terminal':
                    lookup[epoch].update(no_live_producer_claimed=False,current_repair_owner='/root',
                        state='executing' if row['phase']=='worker' else 'verification')""")
    return s


def watcher(s):
    s=one(s,'LISTENER = dict(',f'V49 = original.WRITER / "{NEW}"\nLISTENER = dict(')
    s=one(s,'        HERE == V48','        HERE == V49')
    s=one(s,'    if active48.exists():','''    active49 = original.WRITER / 'FAILED166_CADENCE_V49_ACTIVE.json'
    if active49.exists():
        ref = bound(active49)
        version, directory, booker = 49, V49, original.TARGET / 'booking-price-v49'
    elif active48.exists():''')
    s=one(s,'    if version == 48:','''    if version == 49:
        predecessor = dict(path=str(active48), sha256='''+repr(ACTIVE)+''')
        ready48 = checked(checked(predecessor)['ready'])
        need(active['old'] == checked(predecessor)['new'] and ready['old_owner'] == predecessor
             and ready['retained_143_phase'] == report['phase'] == ready48['retained_143_phase']
             and ready['retained_143_listener'] == ready48['retained_143_listener'] == LISTENER
             and checked(ready['retained_143_v48_rebound'])['phase'] == report['phase'],
             'V49 lost the original 143 authority')
    if version == 48:''')
    return one(s,'route[4] not in (47, 48)','route[4] not in (47, 48, 49)')


def cutover(s):
    for prefix in ('cutover','v','V'):
        s=s.replace(prefix+'48',prefix+'49').replace(prefix+'47',prefix+'48')
    s=s.replace(OLD_SEAL,WRITER).replace(OLD_ACTIVE,ACTIVE)
    s=one(s,'61883f8f6fd84c70a145042944ef602369d6b798decd34ade652d26e8cbf565e',REBOUND)
    s=one(s,'inherited["writer"] == phase["writer"] and inherited["phase"] == scope["phase"]',
        'inherited["writer"] == doc(Path(active["ready"]["path"]),active["ready"]["sha256"])["old_owner"] and inherited["phase"] == scope["phase"]')
    anchor='    need(\n        actual == set(expected) and "horizon-qualify-169-focused-hourly-20261123-v1.service" not in actual,'
    s=one(s,anchor,'''    import transition_v49
    for unit, assignment in transition_v49.assignments(fleet).items():
        basic = dict(Id=unit,InvocationID=assignment['iid'],MainPID=assignment['pid'],ActiveState='active')
        if unit in expected:
            need(all(expected[unit][k] == v for k,v in basic.items()),'changed private actor')
        else:
            expected[unit]=basic
    need(
        actual == set(expected),''')
    return s


def booker(s):
    s=s.replace('v48','v49').replace('V48','V49').replace('version = 48','version = 49')
    s=s.replace(OLD_ACTIVE,ACTIVE)
    s=s.replace('checked(checked(ready["old_owner"])["ready"])["old_owner"]',
                'checked(checked(checked(checked(ready["old_owner"])["ready"])["old_owner"])["ready"])["old_owner"]')
    return s


def stage(old,work,initial):
    book=old.name=='booking-price-v48'
    expected=BOOKER if book else WRITER
    if not book and old.name!=OLD:
        raise ValueError('unexpected predecessor location')
    raw=(old/'deployment-seal-receipt.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('unexpected predecessor seal')
    work.mkdir(mode=0o700)
    members={}
    def add(name,data):
        ast.parse(data,filename=name)
        p=work/name
        p.write_bytes(data);p.chmod(0o444)
        members[name]=dict(name=name,source=str(p),sha256=hashlib.sha256(data).hexdigest(),mode=0o444)
    for r in json.loads(raw)['members']:
        name=r['name'];p=old/name
        if p.resolve()!=p or p.parent!=old or hashlib.sha256(p.read_bytes()).hexdigest()!=r['sha256']:
            raise ValueError('unsealed old member '+name)
        if name!='SHA256SUMS':
            members[name]=dict(name=name,source=str(p),sha256=r['sha256'],mode=int(r['mode'],8))
    if book:
        for name in ('book141.py','prepare143.py'):
            add(name,booker((old/name).read_text()).encode())
    else:
        add('status_cycle.py',cycle((old/'status_cycle.py').read_text()).encode())
        for name in ('full170_status.py','cold170_status.py','joint168_status.py'):
            text=(old/name).read_text()
            if f"'{OLD}')" not in text:
                raise ValueError(name+' missing V48')
            add(name,text.replace(f"'{OLD}')",f"'{OLD}', '{NEW}')").encode())
        for name in ('split_wire.py','transition_v49.py'):
            add(name,(HERE/name).read_bytes())
        add('initial162.py',initial.read_bytes())
        add('cutover49.py',cutover((old/'cutover48.py').read_text()).encode())
        add('watch143_versions.py',watcher((old/'watch143_versions.py').read_text()).encode())
    return dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(old.with_name('booking-price-v49' if book else NEW)),members=list(members.values()))
