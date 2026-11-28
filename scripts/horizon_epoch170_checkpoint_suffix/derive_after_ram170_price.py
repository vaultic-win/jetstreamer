"""Register the after-RAM producer in the two native censuses and in the complete roster."""
import ast
from pathlib import Path

from derive_ram170_writer import once

HERE = Path(__file__).resolve().parent
MODULE = "after_ram170_admission.py"


def extend(files):
    """Apply to a validated new provider after its usual self-path and provenance lift."""
    if MODULE in files:
        raise ValueError("after-RAM provider already registered")
    files = dict(files)
    def edit(name, substitutions):
        source, mode = files[name]
        code = source.decode()
        for anchor, replacement in substitutions:
            code = once(code,anchor,replacement)
        ast.parse(code,filename=name)
        files[name] = (code.encode(),mode)

    edit("capacity.py", [
        ("'second162_peer.py','frozen169_output.py'}", "'second162_peer.py','frozen169_output.py','after_ram170_admission.py'}"),
        ("    return merged\n", '''    after_ram = runpy.run_path(str(STOPPED.parent / 'after_ram170_admission.py'))
    return after_ram['account'](merged, core, STOPPED.parent)
''')
    ])
    edit("after_stop.py", [
        ("def stopped(core, current, fleet):","def stopped(core, current, fleet, successor):"),
        ("    for name in (PREV, NEXT, *(x['service']['Id'] for x in handlers['armed'])):",
         """    # The original failed dispatch stays closed. A separate signed successor may reuse its unit and barrier.
    inactive_next = (NEXT,) if not successor or successor["phase"] == "terminal" else ()
    for name in (PREV, *inactive_next, *(x['service']['Id'] for x in handlers['armed'])):"""),
        ("        core.need(not os.path.lexists(next_dir/name), 'the blocked fourth window changed '+name)",
         """        if name == 'barrier/allow' and successor and successor['release']:
            core.need((next_dir/name).read_bytes() == successor['invocation'].encode(), 'foreign successor barrier')
        else:
            core.need(not os.path.lexists(next_dir/name), 'the blocked fourth window changed '+name)"""),
        ("    stopped_ref = stopped(core,current,fleet)", """    after_ram = runpy.run_path(str(directory/'after_ram170_admission.py'))
    successor = after_ram['owner'](core,fleet,directory)
    live_successor = successor if successor and successor['phase'] != 'terminal' else None
    stopped_ref = stopped(core,current,fleet,successor)"""),
        ("    gap170 = live['owner'](core,fleet)",
         "    gap170 = live['owner'](core,fleet)\n    core.need(not (gap170 and successor), 'two 170 owners claim the reservation')"),
        ("gap170=gap170,retry169=retry169)", "gap170=gap170 or live_successor,retry169=retry169)"),
        ("    owners = observations(core,fleet,raw,first,gap170,retry169)",
         "    owners = observations(core,fleet,raw,first,gap170 or live_successor,retry169)"),
        ("    native['ram_gap170'] = gap170", "    native['ram_gap170'] = gap170\n    native['after_ram170'] = successor"),
        ("and stopped(core,current,fleet)==stopped_ref and observations(core,fleet,raw,first,gap170,retry169)==owners",
         """and after_ram['owner'](core,fleet,directory)==successor
              and stopped(core,current,fleet,successor)==stopped_ref
              and observations(core,fleet,raw,first,gap170 or live_successor,retry169)==owners""")
    ])
    edit("successor_price.py", [
        ('''    if gap170 is not None:
        unit = "horizon-qualify-170-from-73760367-ram-20261128-v3.service"''',
         '''    if gap170 is not None:
        following_unit = "horizon-qualify-170-from-73766969-20261127-v1.service"
        is_following = gap170["unit"] == following_unit
        unit = following_unit if is_following else "horizon-qualify-170-from-73760367-ram-20261128-v3.service"'''),
        ('and actual["MemoryMax"] == str(56*G) and actual["CPUQuotaPerSecUSec"] == "6s"',
         'and actual["MemoryMax"] == str((48 if is_following else 56)*G) and actual["CPUQuotaPerSecUSec"] == "6s"')
    ])
    files[MODULE] = ((HERE / MODULE).read_bytes(),0o444)
    return files
