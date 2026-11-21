"""Load the original guard and local archive verifier for recovered epochs 167 and 170."""
from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import NamedTuple

shared = runpy.run_path(str(Path(__file__).resolve().with_name("closure.py")))


class Producer(NamedTuple):
    field: str
    witness_sha256: str
    verifier_sha256: str
    receipt_mode: int


PRODUCERS = {
    167: Producer("indexed167_local_commit",
                  "f9b3e1fbdddfd983f1589ead46439a5bde07762cfc6151a8cfbb6f5580e818be",
                  "e19166571e5e23338d6db68a14ed354d38c2b9f34317ac8cd1836da23812606a",
                  0o444),
    170: Producer("recovered170_local_commit",
                  "8221f8f31df8bd360b7ef95a82b6cbf04c27fff2a0dc53508f6c79d1731dff7b",
                  "fca4c122b08d414dfdb4765680bfef7ecf5a7e5b15fb993578e8f1cdd91b62ed",
                  0o400),
}


def authority(epoch):
    profile = PRODUCERS[epoch]
    root = shared["R"] / f"epoch{epoch}-current-delivery-20261121-v1"
    live, _ = shared["document"](root / "LIVE.json", 0o600, profile.witness_sha256)
    native = live["native"]
    node, timer = native["manager"], native["timer"]
    admitted = Path(live["admission"]["path"])
    worker = Path(live["first_protected_worker"]["path"])
    shared["need"](live["schema"] == "horizon-singleton-live-to-terminal-witness-v1"
                   and live["epoch"] == epoch
                   and admitted.name == "ACTUAL_ADMISSION_AND_PROTECTION.json"
                   and worker == admitted.with_name("FIRST_PROTECTED_WORKER.json"),
                   "unexpected original producer witness")
    guard = shared["GuardClosure"](
        epoch=epoch, terminal_root=root, admission_root=admitted.parent,
        producer_unit=node["Id"], producer_id=node["InvocationID"],
        guard_timer=timer["Id"], guard_timer_id=timer["InvocationID"],
        witness_hash=profile.witness_sha256, admission_hash=live["admission"]["sha256"],
        admission_mode=profile.receipt_mode, worker_hash=live["first_protected_worker"]["sha256"],
        worker_mode=profile.receipt_mode, terminal_program_hash=profile.verifier_sha256,
    )
    return SimpleNamespace(T=root, DONE=guard.completion_path, FIELD=profile.field,
                           UNIT=guard.producer_unit, IID=guard.producer_id, guard=guard,
                           committed=guard.committed, inspect=guard.inspect, retire=guard.retire)
