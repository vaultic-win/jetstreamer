"""Original guard and writer of the metered epoch 168 archive."""
from pathlib import Path
import runpy

shared = runpy.run_path(str(Path(__file__).resolve().with_name("closure.py")))
R = shared["R"]
T = R / "epoch168-current-delivery-20261121-v1"
D = R / "epoch168-full-metered-20261121-v1"
FIELD = "metered168_local_commit"
UNIT = "horizon-qualify-168-full-metered-20261121-v1.service"
IID = "9cebb1d022124fb08588e93e055d5446"
guard = shared["GuardClosure"](
    epoch=168,
    terminal_root=T,
    admission_root=D,
    producer_unit=UNIT,
    producer_id=IID,
    guard_timer="horizon-guard-168-full-metered-20261121-v1.timer",
    guard_timer_id="1e57eddd76674ff89dcaaf4d9160e84b",
    witness_hash="11c7cbb269258849d637259fad7a005f3e1255fbeaac99e3239f089495164ac7",
    admission_hash="d2553d0008fa8e43500633e1f916daf4f9609f51eba0be60475c1e3293c9db56",
    admission_mode=0o400,
    worker_hash="f0881354a940f74fff699c5de9d205c427a3d0414672ce41133e28a2bd0428c6",
    terminal_program_hash="bb1980365fddf57bcd245299d543cb589949661997dfad973e45307f5c6fe770",
)
DONE = guard.completion_path
committed = guard.committed
retire = guard.retire
inspect = guard.inspect
