"""Add the second RAM gap to the V57 writer after its normal version lift."""
import ast
from hashlib import sha256
from pathlib import Path

from derive_ram170_writer import once

HERE = Path(__file__).resolve().parent
OLD = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-ram-20261128-v1/observer-modules-v1')
SEAL = 'e94b0211cfa973e0ca708259c3ec7e611b5cfd6b831d27c9530167d96b3c8bee'
READY_KEY = 'second_ram_gap170_interface'
ENROLL_OPTION = '--enroll-second-ram-gap-170'


def members(scope_ref):
    import json
    seal = (OLD/'deployment-seal-receipt.json').read_bytes()
    if sha256(seal).hexdigest()!=SEAL:
        raise ValueError('different first RAM observer')
    old={}
    for m in json.loads(seal)['members']:
        name=m['name']; content=(OLD/name).read_bytes()
        if sha256(content).hexdigest()!=m['sha256']:
            raise ValueError('changed first RAM observer')
        old[name]=content.decode()
    native=old['ram170_native.py'].replace('from ram170_contract import','from ram170_second_contract import').replace(
        'import ram170_workspace as workspace','import ram170_second_workspace as workspace').replace(
        'from-73760367-ram-20261128-v1','from-73760367-ram-20261128-v2').replace(
        'current_private170_ram_gap','current_private170_second_ram_gap').replace(
        'ram_gap170_interface',READY_KEY).replace('retained_170_ram_gap_checkpoint','retained_170_second_ram_gap_checkpoint')
    status=old['ram170_status.py'].replace('import ram170_contract as contract','import ram170_second_contract as contract').replace(
        'import ram170_native as gap','import ram170_second_native as gap').replace('ram_gap170_interface',READY_KEY).replace(
        'private170_ram_gap_','private170_second_ram_gap_').replace('RAM-backed checkpoint gap ', 'second RAM-backed checkpoint gap ')
    contract=(HERE/'ram170_second_contract.py').read_text()
    contract=once(contract,"INTERFACE_DIGEST = None",'INTERFACE_DIGEST = '+repr(scope_ref['sha256']))
    if scope_ref['path']!='/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-ram-20261128-v2/RAM_GAP170_WRITER_INTERFACE.json':
        raise ValueError('different second RAM scope')
    files={'ram170_second_native.py':native,'ram170_second_status.py':status,'ram170_second_contract.py':contract,
           'ram170_second_workspace.py':old['ram170_workspace.py']}
    for name,text in files.items(): ast.parse(text,filename=name)
    return {k:v.encode() for k,v in files.items()}


def cycle(source):
    def insert(anchor, line):
        nonlocal source
        source = once(source, anchor, anchor+'\n'+line)
    def replace(a,b):
        nonlocal source
        source=once(source,a,b)
    insert('                import ram170_status','                if FAILED166_VERSION == 57:\n                    import ram170_second_status')
    replace('    ram_prior = None\n    bridge_prior', '    second_ram_prior = None\n    ram_prior = None\n    bridge_prior')
    replace('            ram_prior = ram170_status.retained_population(c.fleet,c.cfg)\n            ram_cfg = ram170_status.history_config(c.fleet,c.cfg)',
            '''            if FAILED166_VERSION == 57:
                second_ram_prior = ram170_second_status.retained_population(c.fleet,ram_cfg)
                ram_cfg = ram170_second_status.history_config(c.fleet,ram_cfg)
            ram_prior = ram170_status.retained_population(c.fleet,ram_cfg)
            ram_cfg = ram170_status.history_config(c.fleet,ram_cfg)''')
    replace('private_successor=ram_prior or gap_prior','private_successor=second_ram_prior or ram_prior or gap_prior')
    replace('c.bridge170_prior = ram_prior or gap_prior','c.bridge170_prior = second_ram_prior or ram_prior or gap_prior')
    insert('        ram170_status.project(c,c.ram_gap170)', '''    if FAILED166_VERSION == 57:
        c.second_ram_gap170 = ram170_second_status.observe(c,second_ram_prior,cycle.observed_lane)
        if ram170_second_status.active(c.second_ram_gap170):
            need(c.ram_gap170 and c.ram_gap170['phase']=='terminal' and c.gap170 and c.gap170['phase']=='terminal'
                 and not bridge170_status.active(c.bridge170) and not successor170_status.active(c.successor170)
                 and '170' not in native_owners and 170 not in c.new_rows and c.stopped170,'second RAM gap overlaps a 170 replay')
            if c.second_ram_gap170['phase']!='held':
                native_owners = dict(native_owners, second_ram_gap170=c.second_ram_gap170)
        ram170_second_status.project(c,c.second_ram_gap170)''')
    for anchor, extra in [('ram170_status.recheck(c.ram_gap170)','ram170_second_status.recheck(c.second_ram_gap170)'),
                          ('if c.ram_gap170: cap[ram170_status.FIELD] = c.ram_gap170','if c.second_ram_gap170: cap[ram170_second_status.FIELD] = c.second_ram_gap170'),
                          ('diagnostic_count += int(ram170_status.active(c.ram_gap170))','diagnostic_count += int(ram170_second_status.active(c.second_ram_gap170))'),
                          ('ram170_status.install(fleet,c.ram_gap170)','ram170_second_status.install(fleet,c.second_ram_gap170)')]:
        insert('        '+anchor,'    if FAILED166_VERSION == 57:\n        '+extra)
    insert('            extra.update(ram170_status.status_fields(c.ram_gap170))',
           '        if FAILED166_VERSION == 57 and epoch == 170 and c.second_ram_gap170:\n            extra.update(ram170_second_status.status_fields(c.second_ram_gap170))')
    insert('            modules += [ram170_status, ram170_status.contract, ram170_status.gap, ram170_status.gap.workspace]',
           '            if FAILED166_VERSION == 57:\n                modules += [ram170_second_status,ram170_second_status.contract,ram170_second_status.gap,ram170_second_status.gap.workspace]')
    replace('            ram_prior = None\n', '''            second_ram_prior = None
            ram_prior = None
            if FAILED166_VERSION == 57:
                need(ready['second_ram_gap170_interface']==ram170_second_status.INTERFACE,'unregistered second RAM gap')
                second_ram_prior=ram170_second_status.retained_population(fleet,previous_cfg)
                previous_cfg=ram170_second_status.history_config(fleet,previous_cfg)
''')
    replace('            prior = ram_prior or gap_prior or older or prior','            prior = second_ram_prior or ram_prior or gap_prior or older or prior')
    import re
    match, = re.finditer(r"^    if [^\n]+ and sys.argv\[1\] == '--enroll-ram-gap-170':$", source,re.M)
    source=source[:match.start()]+'''    if FAILED166_VERSION == 57 and len(sys.argv) == 4 and sys.argv[1] == '--enroll-second-ram-gap-170':
        head = dict(path=str(Path(sys.argv[2])),sha256=sys.argv[3])
        os.umask(0o077)
        print(json.dumps(ram170_second_status.enroll(globals(),head,bound(ROOT/'FAILED166_CADENCE_V57_ACTIVE.json'))))
        return
'''+source[match.start():]
    ast.parse(source)
    return source
