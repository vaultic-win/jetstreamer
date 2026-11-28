"""Reuse the sealed RAM observer for the hourly range following the floor-stopped disk run."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import re

from derive_ram170_writer import once

HERE = Path(__file__).resolve().parent
BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = BASE / "epoch170-from-73766969-ram-20261128-v1"
RAM_RECEIVER = BASE / "epoch170-from-73760367-ram-20261128-v3/observer-modules-v1"
RAM_SEAL = "1eac71ad427b6f67421199403e8f6782823d0052e98aec9793b7a7497f3ae0e3"
READY_KEY = "after_floor170_interface"
ENROLL_OPTION = "--enroll-after-floor-170"


def members(scope):
    if scope["path"] != str(ROOT/"AFTER_FLOOR_WRITER_INTERFACE.json") or not re.fullmatch("[a-f0-9]{64}",scope["sha256"]):
        raise ValueError("unknown hourly receiver interface")
    manifest = (RAM_RECEIVER/"deployment-seal-receipt.json").read_bytes()
    if sha256(manifest).hexdigest() != RAM_SEAL:
        raise ValueError("different sealed RAM receiver")
    seal = json.loads(manifest)
    rows = {row["name"]:row["sha256"] for row in seal["members"]}
    if seal["destination"] != str(RAM_RECEIVER) or set(rows) != {
            "ram170_third_" + name + ".py" for name in ("contract", "native", "status", "workspace")}:
        raise ValueError("unknown sealed observer members")
    result = {}
    for name, digest in rows.items():
        body = (RAM_RECEIVER/name).read_bytes()
        if sha256(body).hexdigest() != digest:
            raise ValueError("observer changed " + name)
        target = name.replace("ram170_third_","after_floor170_")
        if "contract" in name:
            code = once((HERE/target).read_text(),"INTERFACE_DIGEST = None","INTERFACE_DIGEST = " + repr(scope["sha256"]))
        else:
            code = body.decode().replace("ram170_third_","after_floor170_").replace("third_ram_gap","after_floor")
            code = code.replace("from-73760367-ram-20261128-v3","from-73766969-ram-20261128-v1")
            code = code.replace("/run/horizon-170-from-73760367-v1","/run/horizon-170-from-73766969-v1")
            code = code.replace("independent_checkpoint","closed_comparison")
            code = code.replace("third RAM-backed checkpoint gap","interval 73,766,970–73,773,645")
            if "status" in name:
                code = once(code, 'ready["after_floor170_interface"] == INTERFACE,',
                            'ready["after_floor170_interface"] == INTERFACE and ready["after_ram170_interface"] == contract.previous.INTERFACE,')
        ast.parse(code,filename=target)
        result[target] = code.encode()
    return result


def cycle(code, version):
    """Enroll and sample this invocation on the existing cadence after its normal version lift."""
    if not isinstance(version,int) or version < 67:
        raise ValueError("the disk stop needs its accepted predecessor writer")
    enable = f"FAILED166_VERSION >= {version}"
    existing_hourly = code.count("c.hourly170")
    if not existing_hourly or "c.after_floor170" in code:
        raise ValueError("existing 170 context changed or recovery receiver already registered")


    def change(old,new):
        nonlocal code
        code = once(code,old,new)

    def append(old,new):
        change(old,old + "\n" + new)

    append("                import after_ram170_status",f"                if {enable}:\n                    import after_floor170_status")
    change("    after_ram_prior = None\n    third_ram_prior = None","    after_floor_prior = None\n    after_ram_prior = None\n    third_ram_prior = None")
    begin = "        ram_cfg = c.cfg\n"
    change(begin,begin + f"""        if {enable}:
            after_floor_prior = after_floor170_status.retained_population(c.fleet,ram_cfg)
            ram_cfg = after_floor170_status.history_config(c.fleet,ram_cfg)
""")
    change("private_successor=after_ram_prior or ", "private_successor=after_floor_prior or after_ram_prior or ")
    change("c.bridge170_prior = after_ram_prior or ", "c.bridge170_prior = after_floor_prior or after_ram_prior or ")
    append("        after_ram170_status.project(c, c.after_ram170)",f"""    if {enable}:
        c.after_floor170 = after_floor170_status.observe(c, after_floor_prior, cycle.observed_lane)
        if after_floor170_status.active(c.after_floor170):
            need(c.after_ram170 and c.after_ram170["phase"] == "terminal"
                 and not any(v.get("epoch", key) in (170, "170") for key, v in native_owners.items() if isinstance(v, dict))
                 and 170 not in c.new_rows and c.stopped170, "duplicate active 170 on the hourly replacement")
            if c.after_floor170["phase"] != "held":
                native_owners = dict(native_owners, after_floor170=c.after_floor170)
        after_floor170_status.project(c, c.after_floor170)""")
    for older, newer in (
        ("after_ram170_status.recheck(c.after_ram170)", "after_floor170_status.recheck(c.after_floor170)"),
        ("if c.after_ram170: cap[after_ram170_status.FIELD] = c.after_ram170", "if c.after_floor170: cap[after_floor170_status.FIELD] = c.after_floor170"),
        ("diagnostic_count += int(after_ram170_status.active(c.after_ram170))", "diagnostic_count += int(after_floor170_status.active(c.after_floor170))"),
        ("after_ram170_status.install(fleet,c.after_ram170)", "after_floor170_status.install(fleet,c.after_floor170)"),
    ):
        append("        "+older, f"    if {enable}:\n        "+newer)
    append("            extra.update(after_ram170_status.status_fields(c.after_ram170))",
           f"        if {enable} and epoch == 170 and c.after_floor170:\n            extra.update(after_floor170_status.status_fields(c.after_floor170))")
    modules = "modules += [after_ram170_status, after_ram170_status.contract, after_ram170_status.following]"
    match, = re.finditer(r"^( *)"+re.escape(modules)+"$",code,re.M)
    indent = match[1]
    append(indent+modules,indent+f"if {enable}:\n"+indent+"    modules += [after_floor170_status, after_floor170_status.contract, after_floor170_status.gap, after_floor170_status.gap.workspace]")
    change("            after_ram_prior = None\n", f"""            after_floor_prior = None
            if {enable}:
                need(ready['after_floor170_interface'] == after_floor170_status.INTERFACE, 'unregistered hourly 170 receiver')
                after_floor_prior = after_floor170_status.retained_population(fleet,previous_cfg)
                previous_cfg = after_floor170_status.history_config(fleet,previous_cfg)
            after_ram_prior = None
""")
    change("            prior = after_ram_prior or ", "            prior = after_floor_prior or after_ram_prior or ")
    enrollment, = re.finditer(r"^    if [^\n]+sys.argv\[1\] == '--enroll-after-ram-170':$",code,re.M)
    new = f"""    if {enable} and len(sys.argv) == 4 and sys.argv[1] == '{ENROLL_OPTION}':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        os.umask(0o077)
        writer = bound(ROOT / f'FAILED166_CADENCE_V{{FAILED166_VERSION}}_ACTIVE.json')
        print(json.dumps(after_floor170_status.enroll(globals(), head, writer)))
        return
"""
    code = code[:enrollment.start()] + new + code[enrollment.start():]
    if code.count("c.hourly170") != existing_hourly:
        raise ValueError("the existing hourly observation was changed")
    ast.parse(code)
    return code
