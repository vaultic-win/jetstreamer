"""Add the already-staged 73,766,970 successor to the existing writer and enrollment command."""
import ast
from hashlib import sha256
from pathlib import Path
import re

from derive_ram170_writer import once

HERE = Path(__file__).resolve().parent
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-gap-20261128-v1")
READY_KEY = "after_ram170_interface"
ENROLL_OPTION = "--enroll-after-ram-170"


def received(directory, name, expected):
    content = (directory / name).read_bytes()
    if sha256(content).hexdigest() != expected:
        raise ValueError("different staged fourth receiver " + name)
    return content.decode()


def members(writer_directory, scope):
    if scope["path"] != str(ROOT / "AFTER_RAM_WRITER_INTERFACE.json") or not re.fullmatch("[0-9a-f]{64}",scope["sha256"]):
        raise ValueError("unregistered after-RAM scope")
    native = received(writer_directory, "fourth170_native.py",
                      "0d3552abf6180eaf15f0abce075984b74102672721adc063cd5a2be3e61f77df")
    native = once(native, "from fourth170_contract import", "from after_ram170_contract import")
    native = once(native, '"current_private170_bounded_successor"', '"current_private170_after_ram"')
    native = once(native, '"successor170_interface"', '"' + READY_KEY + '"')
    native = once(native, '"retained_170_bounded_predecessor_comparison"', '"retained_170_third_ram_comparison"')
    native = once(native, '    pids = {int(value)', '''    need((CGROUP / "memory.max").read_text().strip() == str(48 << 30)
         and (CGROUP / "memory.swap.max").read_text().strip() == "0"
         and (CGROUP / "cpu.max").read_text().split() == ["600000", "100000"],
         "disk-backed successor kernel caps changed")
    pids = {int(value)''')
    historical = received(writer_directory, "rolling170_fourth_status.py",
                          "3a1f93a304153bff41f87a1ffc0c7c04b5ea0d6a6a696ffcd7f7c1a61f55e7b4")
    historical = once(historical, "import fourth170_contract as contract",
                      "import after_ram170_status\nimport fourth170_contract as contract")
    if historical.count("following.native.idle(following.UNIT)") != 2:
        raise ValueError("staged successor history changed")
    historical = historical.replace("following.native.idle(following.UNIT)", "after_ram170_status.legacy_idle()")
    contract = once((HERE / "after_ram170_contract.py").read_text(), "INTERFACE_DIGEST = None",
                    "INTERFACE_DIGEST = " + repr(scope["sha256"]))
    files = {"after_ram170_native.py": native, "after_ram170_contract.py": contract,
             "after_ram170_history.py": historical, "after_ram170_status.py": (HERE / "after_ram170_status.py").read_text()}
    for name, content in files.items():
        ast.parse(content, filename=name)
    return {name: content.encode() for name, content in files.items()}


def cycle(source, version):
    """Apply after the ordinary version lift. All pre-existing receiver images are preserved."""
    if not isinstance(version, int) or version <= 62:
        raise ValueError("expected a new writer revision")
    enabled = f"FAILED166_VERSION >= {version}"

    def replace(anchor, content):
        nonlocal source
        source = once(source, anchor, content)

    def after(anchor, content):
        replace(anchor, anchor + "\n" + content)

    anchor = "            import rolling170_fourth_status as successor170_status"
    after(anchor, f"            if {enabled}:\n                import after_ram170_status\n                import after_ram170_history as successor170_status")
    replace("    third_ram_prior = None\n    second_ram_prior",
            "    after_ram_prior = None\n    third_ram_prior = None\n    second_ram_prior")
    replace("        ram_cfg = c.cfg\n", f"""        ram_cfg = c.cfg
        if {enabled}:
            after_ram_prior = after_ram170_status.retained_population(c.fleet,ram_cfg)
            ram_cfg = after_ram170_status.history_config(c.fleet,ram_cfg)
""")
    replace("private_successor=third_ram_prior or ", "private_successor=after_ram_prior or third_ram_prior or ")
    replace("c.bridge170_prior = third_ram_prior or ", "c.bridge170_prior = after_ram_prior or third_ram_prior or ")
    after("        ram170_third_status.project(c,c.third_ram_gap170)", f"""    if {enabled}:
        c.after_ram170 = after_ram170_status.observe(c, after_ram_prior, cycle.observed_lane)
        if after_ram170_status.active(c.after_ram170):
            need(c.third_ram_gap170 and c.third_ram_gap170['phase'] == 'terminal'
                 and c.second_ram_gap170 and c.second_ram_gap170['phase'] == 'terminal'
                 and c.ram_gap170 and c.ram_gap170['phase'] == 'terminal' and c.gap170 and c.gap170['phase'] == 'terminal'
                 and not bridge170_status.active(c.bridge170) and not successor170_status.active(c.successor170)
                 and '170' not in native_owners and 170 not in c.new_rows and c.stopped170,
                 'following epoch 170 overlaps another producer')
            if c.after_ram170['phase'] != 'held':
                native_owners = dict(native_owners, after_ram170=c.after_ram170)
        after_ram170_status.project(c, c.after_ram170)""")
    for original, extension in (
        ("ram170_third_status.recheck(c.third_ram_gap170)", "after_ram170_status.recheck(c.after_ram170)"),
        ("if c.third_ram_gap170: cap[ram170_third_status.FIELD] = c.third_ram_gap170",
         "if c.after_ram170: cap[after_ram170_status.FIELD] = c.after_ram170"),
        ("diagnostic_count += int(ram170_third_status.active(c.third_ram_gap170))",
         "diagnostic_count += int(after_ram170_status.active(c.after_ram170))"),
        ("ram170_third_status.install(fleet,c.third_ram_gap170)", "after_ram170_status.install(fleet,c.after_ram170)"),
    ):
        after("        " + original, f"    if {enabled}:\n        " + extension)
    after("            extra.update(ram170_third_status.status_fields(c.third_ram_gap170))",
          f"        if {enabled} and epoch == 170 and c.after_ram170:\n            extra.update(after_ram170_status.status_fields(c.after_ram170))")
    module_anchor = "modules += [transition_v61, ram170_third_status, ram170_third_status.contract, ram170_third_status.gap, ram170_third_status.gap.workspace]"
    match, = re.finditer(r"^( *)" + re.escape(module_anchor) + "$", source, re.M)
    indent = match.group(1)
    after(indent + module_anchor, indent + "if " + enabled + ":\n" + indent
          + "    modules += [after_ram170_status, after_ram170_status.contract, after_ram170_status.following]")
    replace("            third_ram_prior = None\n", f"""            after_ram_prior = None
            if {enabled}:
                need(ready['after_ram170_interface'] == after_ram170_status.INTERFACE, 'unregistered after-RAM scope')
                after_ram_prior = after_ram170_status.retained_population(fleet, previous_cfg)
                previous_cfg = after_ram170_status.history_config(fleet, previous_cfg)
            third_ram_prior = None
""")
    replace("            prior = third_ram_prior or ", "            prior = after_ram_prior or third_ram_prior or ")
    enroll, *_ = re.finditer(r"^    if [^\n]+sys.argv\[1\] == '--enroll-third-ram-gap-170':$",source,re.M)
    new_enrollment = f"""    if {enabled} and len(sys.argv) == 4 and sys.argv[1] == '{ENROLL_OPTION}':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        os.umask(0o077)
        writer = bound(ROOT / f'FAILED166_CADENCE_V{{FAILED166_VERSION}}_ACTIVE.json')
        print(json.dumps(after_ram170_status.enroll(globals(), head, writer)))
        return
"""
    source = source[:enroll.start()] + new_enrollment + source[enroll.start():]
    ast.parse(source)
    return source
