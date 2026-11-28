"""Nondestructive classification fixtures for the replacement ordinary producer."""
from copy import deepcopy
from pathlib import Path
import importlib.util


def run(module):
    intent = dict(prior_trace_terminal=module.ref(module.TRACE, module.CLOSED),
                  prepared=module.ref(module.D/"PREPARED.json", module.PREPARED),
                  token="f"*32, producer_unit=module.U, timer_unit=module.T)
    actor = dict(producer_invocation_id="a"*32, producer_pid=12345, start_ticks=102, producer_unit=module.U)
    ad = dict(epoch=168, **actor, bootstrap_only=True, transaction_replay_claimed=False,
              prior_trace_terminal=intent["prior_trace_terminal"])
    row = dict(range="168", controller_unit=module.U, producer_unit=module.U,
               expected_controller_invocation_id="a"*32, expected_producer_invocation_id="a"*32)
    worker = dict(**actor, observer_row=row, worker_sha256=module.WORKER, worker_pid=12346, worker_start_ticks=103)
    positive = []
    for a, b, w, stage in [(None,None,None,"intent"), (actor,None,None,"gated"),
                            (actor,ad,None,"protected-bootstrap"), (actor,ad,worker,"protected-worker")]:
        result = module.classify(intent,a,b,w)
        assert result["stage"] == stage and result["ordinary_canonical"] == bool(b)
        assert not result["private_diagnostic"] and not result["transaction_replay_claimed"]
        assert bool(result["observer_row"]) == bool(w)
        positive.append(stage)
    controls = [(dict(intent, prior_trace_terminal={}),actor,ad,worker),
                (intent,dict(actor,producer_invocation_id=module.OLD),ad,None),
                (intent,actor,dict(ad,start_ticks=1),None),(intent,actor,None,worker),
                (intent,actor,ad,dict(worker,worker_sha256="0"*64)),
                (intent,actor,ad,dict(worker,observer_row=dict(row,expected_producer_invocation_id="b"*32))),
                (intent,actor,dict(ad,transaction_replay_claimed=True),None)]
    for args in controls:
        try:
            module.classify(*deepcopy(args))
        except ValueError:
            continue
        raise AssertionError("accepted crossed generation or worker")
    return dict(fixture_only=True, positive=positive, rejected=len(controls))


if __name__ == "__main__":
    spec=importlib.util.spec_from_file_location("status168",Path(__file__).with_name("status168.py"))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    print(run(module))
