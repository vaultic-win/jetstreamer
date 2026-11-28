"""Reuse the qualified native 170 observer for a separate writer field and checkpoint."""
import ast
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
NATIVE_SHA = "0d3552abf6180eaf15f0abce075984b74102672721adc063cd5a2be3e61f77df"


def native(source):
    if hashlib.sha256(source).hexdigest() != NATIVE_SHA:
        raise ValueError("different accepted fourth-window observer")
    text = source.decode().replace("fourth170_contract", "gap170_contract")
    text = text.replace("from gap170_contract import INTERFACE, ROOT, interface, closed_comparison",
                        "from gap170_contract import INTERFACE, ROOT, interface, checkpoint")
    text = text.replace('from-73766969-20261127', 'from-73760367-20261128').replace('from-73766969-v1','from-73760367-v1')
    text = text.replace("current_private170_bounded_successor", "current_private170_checkpoint_gap")
    text = text.replace('"successor170_interface"', '"gap170_interface"')
    text = text.replace('"closed_comparison"', '"independent_checkpoint"')
    text = text.replace("closed_comparison=", "independent_checkpoint=")
    text = text.replace("closed_comparison(", "checkpoint(")
    text = text.replace('"retained_170_bounded_predecessor_comparison"', '"retained_170_gap_checkpoint"')
    ast.parse(text)
    return text.encode()


def members(previous):
    return {"gap170_native.py": native((previous / "fourth170_native.py").read_bytes()),
            **{name:(HERE/name).read_bytes() for name in ("gap170_contract.py", "gap170_status.py")}}
