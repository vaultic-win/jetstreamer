"""Extend the existing cadence with one disjoint private 170 receiver."""
import ast
from hashlib import sha256
from pathlib import Path

HERE=Path(__file__).resolve().parent
SCOPE=dict(path="/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-ram-20261128-v1/RAM_GAP170_WRITER_INTERFACE.json",
           sha256="cf7836a48efd71f886924a07657101691d27d24f6ccf05cbe7938b4be1daedaf")


def once(source,old,new):
    if source.count(old)!=1:
        raise ValueError("accepted receiver changed near "+old)
    return source.replace(old,new)


def members(previous):
    native=(previous/"gap170_native.py").read_bytes()
    status=(previous/"gap170_status.py").read_bytes()
    if (sha256(native).hexdigest(), sha256(status).hexdigest())!=(
            "60263022c4af858ebe6331237a98ff98bd787d4d35e38cc3d4a993cfc4fe3ad7",
            "64b3295996e6ef65c58ced2ab67b360771dc825068abe1a11389ac53c67c5f1d"):
        raise ValueError("different first gap receiver")
    code=native.decode().replace("gap170_contract","ram170_contract").replace(
        "from-73760367-20261128","from-73760367-ram-20261128").replace(
        "current_private170_checkpoint_gap","current_private170_ram_gap").replace(
        '"gap170_interface"','"ram_gap170_interface"').replace('"retained_170_gap_checkpoint"','"retained_170_ram_gap_checkpoint"')
    code=once(code,"from evidence import","import ram170_workspace as workspace\nfrom evidence import")
    code=once(code,'str(48 << 30)','str(56 << 30)')
    code=once(code,'    pids = {int(value)', '''    scratch = Path(scope["run"])/"scratch"
    workspace.mount(pid,scratch)
    need((CGROUP/"memory.max").read_text().strip()==str(56<<30) and (CGROUP/"memory.swap.max").read_text().strip()=="0"
         and (CGROUP/"cpu.max").read_text().split()==["600000","100000"],"RAM retry kernel limits changed")
    pids = {int(value)''')
    left=code.index('        child_exe = Path(f"/proc/{child_pid}/exe")')
    right=code.index('    return [process(value)',left)
    code=code[:left]+'''        child = workspace.worker(child_pid,pid,scratch,scope["profile"]["worker"],GROUP)
'''+code[right:]
    status=status.decode().replace("gap170_contract","ram170_contract").replace("gap170_native","ram170_native").replace(
        "private170_gap_","private170_ram_gap_").replace('"gap170_interface"','"ram_gap170_interface"').replace(
        "Private epoch 170 checkpoint gap ","Private epoch 170 RAM-backed checkpoint gap ")
    files={"ram170_native.py":code.encode(),"ram170_status.py":status.encode(),
           "ram170_workspace.py":(HERE/"ram170_workspace.py").read_bytes(),
           "ram170_contract.py":(HERE/"ram170_contract.py").read_bytes()}
    for name,content in files.items():
        ast.parse(content,filename=name)
    return files


def cycle(source):
    """Call after the normal V55→V56 version lift. Preserve the first gap's terminal field."""
    def replace(a,b):
        nonlocal source
        source=once(source,a,b)
    def after(a,b):
        replace(a,a+"\n"+b)
    after("            import gap170_status","            if FAILED166_VERSION == 56:\n                import ram170_status")
    replace("    bridge_prior = bridge170_status.retained_population(c.fleet, c.cfg)",
            "    ram_prior = None\n    bridge_prior = bridge170_status.retained_population(c.fleet, c.cfg)")
    replace("        gap_prior = gap170_status.retained_population(c.fleet, c.cfg)\n        previous_cfg = gap170_status.history_config(c.fleet, c.cfg)",
            """        ram_cfg = c.cfg
        if FAILED166_VERSION == 56:
            ram_prior = ram170_status.retained_population(c.fleet,c.cfg)
            ram_cfg = ram170_status.history_config(c.fleet,c.cfg)
        gap_prior = gap170_status.retained_population(c.fleet,ram_cfg)
        previous_cfg = gap170_status.history_config(c.fleet,ram_cfg)""")
    replace("private_successor=gap_prior or successor_prior or bridge_prior","private_successor=ram_prior or gap_prior or successor_prior or bridge_prior")
    replace("c.bridge170_prior = gap_prior or successor_prior or bridge_prior","c.bridge170_prior = ram_prior or gap_prior or successor_prior or bridge_prior")
    after("        gap170_status.project(c, c.gap170)", """    if FAILED166_VERSION == 56:
        c.ram_gap170 = ram170_status.observe(c, ram_prior, cycle.observed_lane)
        if ram170_status.active(c.ram_gap170):
            need(c.gap170 and c.gap170['phase']=='terminal' and not bridge170_status.active(c.bridge170)
                 and not successor170_status.active(c.successor170) and '170' not in native_owners
                 and 170 not in c.new_rows and c.stopped170,'RAM retry overlaps an earlier 170 owner')
            if c.ram_gap170['phase']!='held':
                native_owners = dict(native_owners, ram_gap170=c.ram_gap170)
        ram170_status.project(c,c.ram_gap170)""")
    for anchor,line in (
        ("        gap170_status.recheck(c.gap170)","ram170_status.recheck(c.ram_gap170)"),
        ("        cap[gap170_status.FIELD] = c.gap170","if c.ram_gap170: cap[ram170_status.FIELD] = c.ram_gap170"),
        ("        diagnostic_count += int(gap170_status.active(c.gap170))","diagnostic_count += int(ram170_status.active(c.ram_gap170))"),
        ("        gap170_status.install(fleet, c.gap170)","ram170_status.install(fleet,c.ram_gap170)")):
        after(anchor,"    if FAILED166_VERSION == 56:\n        "+line)
    after("            extra.update(gap170_status.status_fields(c.gap170))",
          "        if FAILED166_VERSION == 56 and epoch == 170 and c.ram_gap170:\n            extra.update(ram170_status.status_fields(c.ram_gap170))")
    after("            modules += [gap170_status, gap170_status.contract, gap170_status.gap]",
          "        if FAILED166_VERSION == 56:\n            modules += [ram170_status, ram170_status.contract, ram170_status.gap, ram170_status.gap.workspace]")
    replace("            gap_prior = None\n", """            gap_prior = None
            ram_prior = None
            if FAILED166_VERSION == 56:
                need(ready['ram_gap170_interface']==ram170_status.INTERFACE,'unregistered RAM retry scope')
                ram_prior = ram170_status.retained_population(fleet,previous_cfg)
                previous_cfg = ram170_status.history_config(fleet,previous_cfg)
""")
    replace("            prior = gap_prior or older or prior","            prior = ram_prior or gap_prior or older or prior")
    insert="    if FAILED166_VERSION == 54 and len(sys.argv) == 4 and sys.argv[1] == '--enroll-gap-170':"
    replace(insert,"""    if FAILED166_VERSION == 56 and len(sys.argv) == 4 and sys.argv[1] == '--enroll-ram-gap-170':
        head = dict(path=str(Path(sys.argv[2])),sha256=sys.argv[3])
        os.umask(0o077)
        print(json.dumps(ram170_status.enroll(globals(),head,bound(ROOT/'FAILED166_CADENCE_V56_ACTIVE.json'))))
        return
"""+insert)
    ast.parse(source)
    return source
