"""Enroll the next epoch 170 interval on an existing, versioned cadence writer."""
import ast
from hashlib import sha256
from pathlib import Path
import re

from derive_ram170_writer import once
from following_prepare import need, read, reference
from next_hourly170 import PREVIOUS, ROOT

HERE = Path(__file__).resolve().parent
OLD_RECEIVER = PREVIOUS/"observer-modules-v1"
OLD_SEAL = dict(path=str(OLD_RECEIVER/"deployment-seal-receipt.json"),
                sha256="d02806af0dd82e76ad140b6436b3ab2f78b5a551005a42f7c728ee56fcc6685c")
READY_KEY = "next_hourly170_interface"
ENROLL_OPTION = "--enroll-next-hourly-170"


def members(scope):
    interface = read(scope)
    need(scope["path"] == str(ROOT/"NEXT_HOURLY_WRITER_INTERFACE.json") and
         re.fullmatch("[a-f0-9]{64}",scope["sha256"]), "foreign next-hourly interface")
    seal = read(OLD_SEAL)
    rows = {row["name"]:row["sha256"] for row in seal["members"]}
    need(seal["destination"] == str(OLD_RECEIVER) and set(rows) ==
         {f"after_floor170_{name}.py" for name in ("contract","native","status","workspace")},
         "unknown predecessor receiver")
    result = {}
    for name,digest in rows.items():
        path = OLD_RECEIVER/name
        body = path.read_bytes()
        need(sha256(body).hexdigest() == digest, "changed receiver source " + name)
        target = name.replace("after_floor170_", "next_hourly170_")
        if name.endswith("_contract.py"):
            code = once((HERE/target).read_text(),"INTERFACE_DIGEST = None",
                        "INTERFACE_DIGEST = " + repr(scope["sha256"]))
        else:
            code = body.decode().replace("after_floor170_", "next_hourly170_")
            code = code.replace("after_floor","next_hourly")
            code = code.replace("from-73766969-ram-20261128-v1","from-73773645-ram-20261128-v1")
            code = code.replace("/run/horizon-170-from-73766969-v1","/run/horizon-170-from-73773645-v1")
            code = code.replace("interval 73,766,970–73,773,645","interval 73,773,646–73,780,397")
            if name.endswith("_native.py"):
                code = once(code,'GUARD_ROOT = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1"',
                            "GUARD_ROOT = " + repr(interface["run"]))
                code = once(code,"<= 384 << 30","<= 8 << 30")
            if name.endswith("_status.py"):
                code = once(code,'ready["after_ram170_interface"] == contract.previous.INTERFACE',
                            'ready["after_floor170_interface"] == contract.previous.INTERFACE')
        ast.parse(code,filename=target)
        result[target] = code.encode()
    return result


def cycle(code, version):
    """Derive an unactivated successor while retaining the predecessor row."""
    need(isinstance(version,int) and version >= 75 and "c.next_hourly170" not in code,
         "unqualified cadence version or duplicate receiver")
    enable = f"FAILED166_VERSION >= {version}"
    prior_count = code.count("c.after_floor170")

    def change(old,new):
        nonlocal code
        code = once(code,old,new)

    def append(old,new):
        change(old,old + "\n" + new)

    append("                    import after_floor170_status",
           f"                    if {enable}:\n                        import next_hourly170_status")
    change("    after_floor_prior = None\n    after_ram_prior",
           "    next_hourly_prior = None\n    after_floor_prior = None\n    after_ram_prior")
    change("        ram_cfg = c.cfg\n", f"""        ram_cfg = c.cfg
        if {enable}:
            next_hourly_prior = next_hourly170_status.retained_population(c.fleet,ram_cfg)
            ram_cfg = next_hourly170_status.history_config(c.fleet,ram_cfg)
""")
    change("private_successor=after_floor_prior or ","private_successor=next_hourly_prior or after_floor_prior or ")
    change("c.bridge170_prior = after_floor_prior or ","c.bridge170_prior = next_hourly_prior or after_floor_prior or ")
    append("        after_floor170_status.project(c, c.after_floor170)", f"""    if {enable}:
        c.next_hourly170 = next_hourly170_status.observe(c, next_hourly_prior, cycle.observed_lane)
        if next_hourly170_status.active(c.next_hourly170):
            need(c.after_floor170 and c.after_floor170["phase"] == "terminal"
                 and not any(v.get("epoch", key) in (170, "170") for key, v in native_owners.items() if isinstance(v, dict))
                 and 170 not in c.new_rows and c.stopped170, "duplicate live next-hourly 170 owner")
            if c.next_hourly170["phase"] != "held":
                native_owners = dict(native_owners, next_hourly170=c.next_hourly170)
        next_hourly170_status.project(c, c.next_hourly170)""")
    for old,new in (
        ("after_floor170_status.recheck(c.after_floor170)", "next_hourly170_status.recheck(c.next_hourly170)"),
        ("if c.after_floor170: cap[after_floor170_status.FIELD] = c.after_floor170", "if c.next_hourly170: cap[next_hourly170_status.FIELD] = c.next_hourly170"),
        ("diagnostic_count += int(after_floor170_status.active(c.after_floor170))", "diagnostic_count += int(next_hourly170_status.active(c.next_hourly170))"),
        ("after_floor170_status.install(fleet,c.after_floor170)", "next_hourly170_status.install(fleet,c.next_hourly170)"),
    ):
        append("        "+old, f"    if {enable}:\n        "+new)
    append("            extra.update(after_floor170_status.status_fields(c.after_floor170))",
           f"        if {enable} and epoch == 170 and c.next_hourly170:\n"
           "            extra.update(next_hourly170_status.status_fields(c.next_hourly170))")
    modules = "modules += [after_floor170_status, after_floor170_status.contract, after_floor170_status.gap, after_floor170_status.gap.workspace]"
    match, = re.finditer(r"^( *)"+re.escape(modules)+"$",code,re.M)
    indent = match[1]
    append(indent+modules,indent+f"if {enable}:\n"+indent+
           "    modules += [next_hourly170_status,next_hourly170_status.contract,next_hourly170_status.gap,next_hourly170_status.gap.workspace]")
    change("            after_floor_prior = None\n",f"""            next_hourly_prior = None
            if {enable}:
                need(ready['{READY_KEY}'] == next_hourly170_status.INTERFACE, 'unregistered next hourly 170 receiver')
                next_hourly_prior = next_hourly170_status.retained_population(fleet,previous_cfg)
                previous_cfg = next_hourly170_status.history_config(fleet,previous_cfg)
            after_floor_prior = None
""")
    change("            prior = after_floor_prior or ","            prior = next_hourly_prior or after_floor_prior or ")
    enrollment, = re.finditer(r"^    if [^\n]+sys.argv\[1\] == '--enroll-after-floor-170':$",code,re.M)
    body = f"""    if {enable} and len(sys.argv) == 4 and sys.argv[1] == '{ENROLL_OPTION}':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        os.umask(0o077)
        writer = bound(ROOT / f'FAILED166_CADENCE_V{{FAILED166_VERSION}}_ACTIVE.json')
        print(json.dumps(next_hourly170_status.enroll(globals(), head, writer)))
        return
"""
    code = code[:enrollment.start()] + body + code[enrollment.start():]
    need(code.count("c.after_floor170") == prior_count + 2, "predecessor observation changed")
    ast.parse(code)
    return code
