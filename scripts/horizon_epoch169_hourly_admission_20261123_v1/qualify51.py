"""Exercise the actual V51 entry, saved observation and status replay in private storage."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
import derive51
import recover51 as bindings

SEALER = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
BOOKER_SHA = "d1801ac0ac8e47cdc4cb39271d3c7ec3588181428c0db8f2c06f820bafbcf534"


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def command(*args):
    process = subprocess.run(list(map(str,args)), capture_output=True, text=True)
    if process.returncode:
        raise RuntimeError(process.stderr[-2400:] + process.stdout[-400:])
    return process.stdout


def stage(destination):
    plan = derive51.stage(bindings.ROOT/derive51.OLD, destination/"writer-input")
    planfile = destination/"writer-plan.json"
    planfile.write_text(json.dumps(plan,sort_keys=True,indent=2)+"\n")
    planfile.chmod(0o400)
    if sha(SEALER) != SEALER_SHA:
        raise ValueError("different deployment sealer")
    command(SEALER, planfile,"--plan-sha256",sha(planfile),"--self-sha256",SEALER_SHA)
    return sha(bindings.NEW/"deployment-seal-receipt.json")


class SimulatedPuts:
    def __init__(self, signed):
        self.signed = signed
        self.originals = {}
        self.writes = {}

    def inventory(self):
        return self.signed.inventory()

    def get(self, epoch):
        if epoch in self.writes:
            return self.writes[epoch]
        if epoch not in self.originals:
            self.originals[epoch] = self.signed.get(epoch)
        return self.originals[epoch]

    def put(self, epoch, etag, body):
        if self.get(epoch)[0] != etag or epoch in self.writes:
            raise ValueError("conditional write mismatch")
        self.writes[epoch] = ('"'+hashlib.md5(body).hexdigest()+'"',body)
        return self.writes[epoch][0]


def exercise(destination):
    w = bindings.ROOT
    if (Path("/proc/self/ns/mnt").stat().st_ino == Path("/proc/1/ns/mnt").stat().st_ino):
        raise ValueError("rehearsal requires an isolated mount namespace")
    upper, work = destination/"upper", destination/"work"
    upper.mkdir()
    work.mkdir()
    command("mount","-t","overlay","overlay","-o",f"lowerdir={w},upperdir={upper},workdir={work}",w)
    statuses = Path("/home/sol/.jetstreamer-private/r2-status-receipts/cycle011808-live166167170-19-20261128-v1")
    out = bindings.CENSUS.parent
    for target, copy in ((statuses,destination/"receipts"),(out,destination/"output")):
        command("cp","-a","--",target,copy)
        command("mount","--bind",copy,target)
    seal = stage(destination)
    recovery = deployed()
    c,h = recovery.load(seal)
    c.validate_package()
    assert c.entry()["sha256"] == seal and sha(h.BOOKER/"deployment-seal-receipt.json") == BOOKER_SHA
    listener = json.loads(command("/usr/bin/python3","-IB",h.PROGRAM,"--check-failed-predecessor"))
    assert listener["writer"] == h.ref(h.OLD_ACTIVE)
    ready,record = recovery.check(c,h)
    recovery.save(h,h.READY,ready)
    lock = c.lock(c.BASE/'stable-cadence-controller-20261120-v1/consumer.lock')
    try:
        simulated_state = dict(Id=c.CONTROLLER,ActiveState="active",Job="",InvocationID="0"*31+"1")
        assert c.rejoin_failed166_cadence(simulated_state,c.entry(),lock) == ready
    finally:
        os.close(lock)
    head = record["fleet"]
    fleet = c.checked(head)
    sample = record["observer"]
    ctx = c.make_context(head, fleet, sample, c.sealed(ready["config"]), out)
    bridge = c.handoff()
    observed = c.census(ctx, bridge)
    assert sha(bindings.CENSUS) == bindings.CENSUS_SHA and ctx.split162 == observed["capacity"][c.status162.FIELD]
    transport = SimulatedPuts(c.status.Storage())
    prev, allref = c.publish_all(ctx,bridge,transport,observed)
    after = c.checked(allref)
    assert len(after["receipts"]) == 20 and after["receipts"]["162"] == record["initial_162"]
    assert 162 not in transport.writes and set(transport.originals) == set(after["status_epochs"])
    due = c.stamp(c.utc(ctx.stamp)+dt.timedelta(seconds=1800))
    nextref = c.config(out, c.project(ctx.next_cfg,due,sample))
    cfg = c.sealed(nextref)
    assert [r["range"] for r in cfg["diagnostic_replays"]].count("162") == 1
    result = c.fleet_successor(ctx,bridge,observed,prev,allref,nextref,c.names(due)["timer"])
    workers = {r["epoch"]:r["unit"]["InvocationID"] for r in result["actual_executing_replays"]+result["actual_active_private_diagnostics"]}
    assert set(workers)=={146,162,167,172} and workers[162]==bindings.INITIAL_ACTOR
    report = dict(package=seal, booker=BOOKER_SHA, sample=sample, saved_census=record["saved_census"],
                  predecessor=head, later_status_162=record["initial_162"], status_epochs=after["status_epochs"],
                  simulated_conditional_puts=sorted(transport.writes), protected_workers=workers, next_config=nextref,
                  authenticated_reads_only=True, protected_endpoints=record["protected_endpoints"])
    (destination/"QUALIFICATION.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(dict(fixture=str(destination), workers=workers, statuses=after["status_epochs"], next_due=due)), flush=True)


def deployed():
    import importlib.util
    spec = importlib.util.spec_from_file_location("deployed_recovery",bindings.NEW/"recover51.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Ensure the watcher's "import recover51" resolves to the deployed file as well.
    sys.modules["recover51"] = module
    return module


if __name__ == "__main__":
    dest = Path(sys.argv[2]).resolve(strict=True)
    os.umask(0o077)
    if sys.argv[1] == "--fixture":
        exercise(dest)
    elif sys.argv[1] == "--stage" and dest == bindings.EVIDENCE:
        print(stage(dest))
    else:
        raise SystemExit("use --fixture in a mount namespace or --stage in the V51 deployment directory")
