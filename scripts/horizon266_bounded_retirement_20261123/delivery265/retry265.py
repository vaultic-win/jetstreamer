"""Retry ordinary 265 publication within the original reservation, preserving its first invocation."""
import importlib.util
import os
from functools import partial
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, "/var/lib/jetstreamer/horizon265-delivery-v215-tools")
import lane265 as first

shared = first.shared
D, V, CG, ref, bound = first.D, first.V, first.CG, first.ref, first.bound
CPU, EPOCH, KEY, PRIVATE, LENGTH, SHA, ORIGIN_IID = (
    first.CPU, first.EPOCH, first.KEY, first.PRIVATE, first.LENGTH, first.SHA, first.ORIGIN_IID)
ROOT = D / "horizon-upload-265-ordinary-retry-v216"
UNIT = ROOT.name + ".service"
CLAIM = ROOT / "pipeline-claim.json"
BOOK = V / (ROOT.name + "-control") / "assignment.json"
DEPLOY = D / "horizon265-delivery-consumers-v215-retry216/deployment.json"
TOOLS = V / "horizon265-retry-tools-v216"
owner = sys.modules[__name__]
process = partial(shared.process, owner=owner)
registered = partial(shared.registered, owner=owner)
prefix = partial(shared.prefix, owner=owner)
select_schedule = partial(shared.select_schedule, owner=owner)
census = partial(shared.census, owner=owner)


def live_binding():
    return dict(shared.live_binding(owner), retry_unit=UNIT)


def retired_binding():
    claim, value, _, launch = first.registered()
    end = bound(ref(first.ROOT / "terminal.json"))
    assert end["claim"] == claim and not end["ready"] and not end["reservation_released"]
    assert end["issuer"] == ref(first.BOOK) and not (CG / first.UNIT).exists()
    return dict(invocation_id=value["invocation_id"], pid=int(launch["unit"]["MainPID"]), claim_sha256=claim["sha256"])


def finite_owner():
    if not BOOK.exists():
        assert not CLAIM.exists() and not (CG / UNIT).exists()
        return {}
    _, value, book, launch = registered()
    assert book["original_reservation"] == ref(first.BOOK)
    retired_binding()
    if not (CG / UNIT).exists():
        state = shared.props(UNIT, ["ActiveState", "MainPID", "Job"])
        assert state["ActiveState"] in ("inactive","failed") and state["MainPID"] == "0" and not state["Job"]
        return {}
    live_binding()
    return {UNIT:(value["invocation_id"], int(launch["unit"]["MainPID"]), shared.LIMIT, {CPU,CPU+1})}


def predecessor():
    incident = D / "horizon-resumed-campaign-status-v216-a1/265/terminal-outcome.json"
    assert bound(ref(incident))["terminal"] == ref(first.ROOT / "terminal.json")
    result = ref(first.ROOT / "origin-clock-status/completion.json")
    assert bound(result)["readback"]["sha256"] == ref(incident.parent / "before.json")["sha256"]
    return result


def status():
    spec = importlib.util.spec_from_file_location("ordinary249.retry_clock", TOOLS / "status248.py")
    clock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(clock)
    clock.start(owner, predecessor())


def issue():
    import retry_fit
    with shared.partition.take():
        if CLAIM.exists():
            return live_binding()
        shared.unfunded(owner)
        retired_binding()
        _, _, old, _ = first.registered()
        repair = shared.pin(D/"horizon265-sealed-rpc-repair-v216/completion.json",
                            "7fb0a3f3bc35e15290011939bebfb2e80719d9f719ba5f5c9c80be45f00ad415")
        evidence = bound(repair)
        assert evidence["plan"] == old["plan"] and evidence["expectation"] == bound(old["plan"])["epoch_expectations"]["265"]
        _, prior, _, _, _, _ = first.delivery249.inputs()
        branch, paths, fixture, _ = shared.qualify(owner, prior, bound(ref(DEPLOY)), old["plan"], old["handoff"], old["drain"])
        assert fixture == old["fixture"]
        for file in ("retry265.py", "register_retry265.py"):
            assert (TOOLS / file).read_text().strip() == shared.git("show", branch+":scripts/horizon266_bounded_retirement_20261123/delivery265/"+file)
        q = retry_fit.price(0,0,0,assessment_only=True)
        assert q["closed265_delivery"] == ref(first.BOOK) and q["total_hard"] == old["hard"]
        release = bound(old["donor"])
        extent = q["extent"]
        assert release["terminal"] == q["closed266"] and release["current"]["identity"] == extent["identity"]
        assert Path("/sys/block/loop18/ro").read_text().strip() == "1"
        assert extent["first"]["blocks"] == extent["second"]["blocks"] == release["retained_backing_bytes"]
        floor = q["protected_floor"] - extent["remaining"] + release["qa_bytes"] + old["disk"]
        assert extent["free"] >= floor >= bound(old["plan"])["minimum_free_bytes"]
        assert q["growth_margin"] + bound(q["issued"])["producer"] >= 0
        for unit in q["after"]:
            if (CG / unit).exists():
                assert {CPU, CPU+1}.isdisjoint(os.sched_getaffinity(int(shared.props(unit, ["MainPID"])["MainPID"])))
        current = prefix()
        assert set(current) == {KEY} and current[KEY]["ETag"] == bound(predecessor())["etag"]
        props = [v.replace(str(first.ROOT / "operation.log"), str(ROOT / "operation.log")) for v in old["properties"]]
        props.append(evidence["bind_property"])
        subprocess.run(["sudo","-n","--preserve-env=SSH_AUTH_SOCK","-u","ubuntu","ssh-add","-l"], stdout=subprocess.DEVNULL, check=True)
        ROOT.mkdir(mode=0o700)
        BOOK.parent.mkdir(mode=0o700)
        booking = shared.funds.put(BOOK, dict(old, service=UNIT, properties=props, fit=q, observer=ref(DEPLOY),
                                  source=branch, original_reservation=ref(first.BOOK), evidence_repair=repair,
                                  terminal=ref(first.ROOT / "terminal.json"), issue_time=time.time(),
                                  ordinary_reader_paths=paths, protected_floor=floor, prefix=current))
        env = ["--setenv="+k for k in ("HORIZON_S3_ENDPOINT","HORIZON_ACCESS_KEY_ID","HORIZON_SECRET_ACCESS_KEY","SSH_AUTH_SOCK")]
        subprocess.run(["systemd-run","--quiet","--unit="+UNIT,*["--property="+p for p in props],*env,
                        "--setenv=HOME=/home/ubuntu","--setenv=GIT_TERMINAL_PROMPT=0","--setenv=TMPDIR="+str(PRIVATE/"tmp"),
                        *old["argv"]],check=True)
        manager = process(bound(booking))
        launch = shared.funds.put(ROOT / "launch.json",dict(booking=booking, unit=manager, time=time.time()))
        claim = shared.funds.put(CLAIM,dict(epoch=EPOCH, phase="upload-readback", unit=UNIT, invocation_id=manager["InvocationID"],
                                 expected_exec_start=manager["ExecStart"], evidence=[booking, launch]))
        assert live_binding()["claim_sha256"] == claim["sha256"]
        return claim


if __name__ == "__main__":
    import retry265
    action, = sys.argv[1:]
    if action == "terminal":
        first.terminal.capture(retry265)
    elif action == "status":
        retry265.status()
    else:
        assert action == "issue"
        print(retry265.issue(), flush=True)
