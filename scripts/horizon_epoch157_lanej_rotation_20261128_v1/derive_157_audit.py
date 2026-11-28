"""Extend a V27-or-later price with native recognition of its already funded 157 audit owner."""
from hashlib import sha256
from pathlib import Path

ORIGINAL = "47a710c7e3256b1fc300826cba872d06261d8d965a36e1a420156457e4d29b14"
SPLIT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-admission-20261123-v1/issued-split-v1")
CORE = "a315dc743160c91bdbc6c480e9ea314597fd176f03033a9c1a2d41c44b81a7dd"


def replace_once(blob, old, new):
    if blob.count(old) != 1:
        raise ValueError("different 157 audit integration point")
    return blob.replace(old, new)


def audit_source():
    path = Path(__file__).resolve().parent.parent/"horizon_epoch170_checkpoint_suffix/verification_reservation.py"
    original = path.read_bytes()
    if sha256(original).hexdigest() != ORIGINAL:
        raise ValueError("different native 168 audit implementation")
    old = b"        else:\n            match = AUDIT.fullmatch(name)"
    new = b'''        elif rotation["AUX"].fullmatch(name):
            core.need(reclamation is None, "multiple owners of the 157 metadata sublease")
            rotation["registered"](core)
            reclamation = rotation["confirm"](core, name, rotation["AUX"])
        else:
            match = AUDIT.fullmatch(name)'''
    data = replace_once(original, b"    scan = None\n    for name in sorted(groups):",
                        b'''    rotation = runpy.run_path(str(Path(__file__).with_name("serial157_operator.py")))
    reclamation = None
    scan = None
    for name in sorted(groups):''')
    data = replace_once(data, old, new)
    data = replace_once(data, b"scanner=scan, groups=sorted(groups),",
                        b"scanner=scan, groups=sorted(groups), reclamation157=reclamation,")
    data += f'''
import runpy
from hashlib import sha256
from types import SimpleNamespace

def verification168(funds):
    program = Path("{SPLIT}")/"successor_price.py"
    if sha256(program.read_bytes()).hexdigest() != "{CORE}":
        raise ValueError("different split reservation core")
    core = SimpleNamespace(**runpy.run_path(str(program)))
    return reservation(core, funds)
'''.encode()
    compile(data, "verification157.py", "exec")
    return data


def integrate(files):
    """Patch a mutable name -> (source bytes, mode) map before the complete provider is sealed."""
    if "verification157.py" in files or "serial157_operator.py" not in files:
        raise ValueError("157 audit integration requires a V27-derived provider")
    files["verification157.py"] = audit_source(), 0o444
    data, mode = files["after_stop.py"]
    old = b"    cap = operations[0]['capacity']"
    new = b'''    verified = runpy.run_path(str(directory/'verification157.py'))['verification168']
    cap = dict(operations[0]['capacity'], verification168=verified)
    operations = (dict(operations[0], capacity=cap), *operations[1:])'''
    files["after_stop.py"] = replace_once(data, old, new), mode
    data, mode = files["capacity.py"]
    marker = b"'serial157_operator.py',"
    files["capacity.py"] = replace_once(data, marker, marker + b"'verification157.py',"), mode
