"""Run the existing 162 landing forecast and journal reader with the second interval's scope."""
from pathlib import Path
import types

UNIT="horizon-qualify-162-second-replay-20261128-v1.service"
RUN=Path("/home/sol/.jetstreamer-private/epoch162-second-replay-20261128-v1")
FIRST=69991077
LAST=69998119
OLD_UNIT="horizon-qualify-162-first-hourly-completion-20261127-v2.service"


def forecast(module, c, row, previous, old, original, delivery):
    if row["unit"]["Id"]!=UNIT:
        raise ValueError("other 162 producer")
    # The existing function calls archive() via its globals. Give both
    # functions their own binding so other epochs keep their original tables.
    scope=dict(module.__dict__,PATHS={**module.PATHS,162:RUN/"ledger/epoch-162.diagnostic.jet"},
               BOUNDS={**module.BOUNDS,162:(FIRST,LAST)},IDENTITIES={**module.IDENTITIES,162:"private162_second_held"})
    scope["archive"]=types.FunctionType(module.archive.__code__,scope)
    return types.FunctionType(module.forecast.__code__,scope)(c,row,previous,old,original,delivery)


def progress(module):
    code=Path(module.__file__).read_text()
    if code.count(OLD_UNIT)!=1 or code.count("69_984_000")>1:
        raise ValueError("different private 162 progress protocol")
    code=code.replace(OLD_UNIT,UNIT).replace("epoch162-first-hourly-completion-20261127-v2/scratch",str(RUN/"scratch"))
    code=code.replace("69_984_000","69_991_077").replace("69_991_076","69_998_119").replace("69_983_761","69_991_077")
    receiver=types.ModuleType("second162_progress");exec(compile(code,str(module.__file__),"exec"),receiver.__dict__)
    return receiver
