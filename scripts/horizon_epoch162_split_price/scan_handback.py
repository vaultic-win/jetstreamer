"""Reconcile every issued private 168 scanner before granting borrowed 166 compute to epoch 162."""
from pathlib import Path
import re
import runpy
import time

ROOT = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch168-exact-private-verification-20261127-v1')
ORIGINAL = ROOT / 'tools-v1/dispatch.py'
ORIGINAL_SHA = '4e5c88e4b1b173a71a88934dd811bf0582d81b7459c5ff8b5f46db6b20407795'
BINARY_SHA = '0be59c4f7b98188894b8fa9f69fbcda70b0a517f4ca98665e370c00e7a53c5a7'
SCOPE_SHA = 'b914d8570f3fe8fd2cc2bc91cc5285a9598b11515ab8763f17eeb28f13373a9c'
PHASE_FIELD = 'unissued_162_donor_loan'
SUCCESS = '7ad2d189f7e94e70a38c781354912448'
FAIL = '98e322203f7a4ed290d09fe03c09fe15'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def disposition(unit, ad_ref, native, scanner, start, terminal, expired, now, valid_until):
    """Only a matched active scanner, a native drain or a dated no-start can clear an issued intent."""
    if native['ActiveState'] == 'active':
        need(scanner and scanner['native']['Id'] == unit and scanner['native']['InvocationID'] == native['InvocationID']
             and scanner['admission'] == ad_ref and start and start[1] == scanner['started']
             and start[0]['invocation'] == native['InvocationID'] and not native['Job'],
             '168 borrowed phase has not entered its fully funded scanner')
        return 'funded-active-scanner'
    need(native['ActiveState'] in ('inactive','failed') and not native['Job'] and not native['ControlGroup']
         and native['MainPID'] == native['ControlPID'] == '0', '168 borrowed phase is starting or draining')
    if start or terminal:
        need(terminal and (not start or terminal['invocation'] == start[0]['invocation']),
             '168 borrowed phase lacks its exact drained invocation')
        return 'native-terminal-drained'
    need(expired and now > valid_until and expired['admission'] == ad_ref and expired['unit'] == unit,
         '168 borrowed phase has a durable intent without a terminal or confirmed expired no-start')
    return 'expired-and-never-started'


def check(core, immutable, base):
    binding = dict(path=str(ROOT/'scope.json'),sha256=SCOPE_SHA)
    inspector = base['accounting']['verification168_listener']
    scan = inspector['audits']['scanner']
    receipts = []
    immutable(ORIGINAL, ORIGINAL_SHA)
    dispatcher = runpy.run_path(str(ORIGINAL))
    for path in sorted(ROOT.glob('attempt-*/INTENT.json')):
        attempt = path.parent
        m = re.fullmatch(r'attempt-([0-9]+)',attempt.name)
        need(m and path.resolve() == path, 'foreign 168 scanner attempt')
        unit = 'horizon-168-private-archive-verify-'+m[1]+'.service'
        intent, ir = core.read(path)
        ad, ar = core.read(attempt/'ADMISSION.json')
        fit, fr = core.read(attempt/'FIT.json')
        need(ad['scope'] == binding == intent['scope'] and ad['fit'] == fr and intent['admission'] == ar
             and ad['scan_unit'] == unit == intent['unit'] and ad['output'] == str(attempt/'output')
             and ad['fits'] and not ad['canonical_writes'] and intent['binary'] ==
                 dict(path=str(ROOT/'tools-v1/private-archive-verify'),sha256=BINARY_SHA)
             and intent['command'] == dispatcher['managed_argv'](Path(intent['binary']['path']), binding, ar,attempt/'output',unit),
             'different private scanner intent')
        if PHASE_FIELD in fit:
            need(type(fit[PHASE_FIELD]) is bool, 'invalid 168 donor phase')
        if not fit.get(PHASE_FIELD):
            continue
        loan = fit['phase']
        need(type(loan['temporary_166_ram']) is int and 0 <= loan['temporary_166_ram'] <= 63*(1<<30)
             and type(loan['prospective_162_home_deferred']) is int and loan['prospective_162_home_deferred'] >= 0
             and (loan['temporary_166_ram'] or loan['prospective_162_home_deferred']),
             '168 phase has no registered donor obligation')
        native = core.state(unit)
        entered = attempt/'output/STARTED.json'
        start = core.read(entered) if entered.exists() else None
        if start:
            need(start[0]['scope']==binding and start[0]['admission']==ar and start[0]['scan_unit']==unit,
                 'different private scanner start')
        history = None
        expired = None
        if native['ActiveState'] in ('inactive','failed') and not native['Job']:
            need(not (Path('/sys/fs/cgroup/horizonaudit.slice')/unit/'cgroup.procs').exists(),
                 '168 scanner still has a native cgroup')
            events = dispatcher['recognized_boot'](unit)
            ids = {x.get('INVOCATION_ID') for x in events if x.get('INVOCATION_ID')}
            terminal = [r for r in events if r.get('MESSAGE_ID') in (SUCCESS,FAIL)]
            if terminal:
                need(len(ids)==1 and re.fullmatch('[0-9a-f]{32}',next(iter(ids))) and
                     all(r.get('INVOCATION_ID') in ids and r.get('UNIT') == unit and
                         int(r['__REALTIME_TIMESTAMP']) >= ad['issued_at']*1_000_000 for r in terminal),
                     'ambiguous 168 scanner terminal')
                history = dict(invocation=ids.pop(),events=[r['__CURSOR'] for r in terminal])
            elif not events and (attempt/'UNSTARTED.json').is_file():
                expired = core.read(attempt/'UNSTARTED.json')[0]
        mode = disposition(unit,ar,native,scan,start,history,expired,time.time(),ad['valid_until'])
        receipts.append(dict(intent=ir,admission=ar,phase_fit=fr,disposition=mode,unit=unit,
                             started=start[1] if start else None,terminal=history))
    return receipts
