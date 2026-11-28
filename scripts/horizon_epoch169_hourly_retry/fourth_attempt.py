"""Derive the fourth private 169 gate and qualify its HOME floor against both measured failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
PARENT = runpy.run_path(str(HERE / "fourth_parent.py"))
THIRD = PARENT["ROOT"]
FOURTH = THIRD.with_name("epoch169-hourly-retry-20261128-v4")
OLD = THIRD / "operator-v1"
NEW = FOURTH / "operator-v1"
SEAL = "9203f263c94be2d6ae9cacbcda15b72cfed8662146b940af1704cd617e582196"
CONTRACT = "bdb679419333a1a1aa0c0d744306aef44e76f18008ceae6dc10ffe26ced1db16"
SEALER = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"


def paths(text):
    for identifier in ("169-hourly-retry-20261128", "169-hourly-retry-terminal-20261128",
                       "/run/horizon-169-hourly-retry"):
        text = text.replace(identifier + "-v3", identifier + "-v4")
    return text


def single(text, old, new):
    if text.count(old) != 1:
        raise ValueError("changed third operator: " + old)
    return text.replace(old, new)


def derive(name, data):
    text = paths(data.decode())
    if name == "issuer.py":
        text = single(text, 'max(0,price["home_margin"]) * 3 // 4', 'max(0,price["home_margin"]) // 3')
    elif name == "observe.py":
        text = single(text, 'FIELD="current_private169_retry3"', 'FIELD="current_private169_retry4"')
        marker = '    actor_path=c.CONTROL/"START_INTENT.json"'
        text = single(text, marker, '    closed_parent(fleet)\n' + marker)
        marker = 'def current(fleet):'
        text = single(text, marker, '''def closed_parent(fleet):
    parent = runpy.run_path(str(HERE / "fourth_parent.py"))
    return parent["terminal"](c, quote.state, fleet)


''' + marker)
    return text.encode()


def plan(commit, observed):
    if hashlib.sha256((OLD / "contract.py").read_bytes()).hexdigest() != CONTRACT:
        raise ValueError("different third operator reader")
    c = runpy.run_path(str(OLD / "contract.py"))
    need, read = c["need"], c["read"]
    deployment, parent = read(OLD / "deployment-seal-receipt.json", SEAL)
    prior, scope = read(THIRD / "SCOPE.json", PARENT["SCOPE"])
    closed, closure = read(THIRD / "UNRELEASED_OUTPUT_MARGIN.json", PARENT["CLOSURE"])
    need(deployment["destination"] == str(OLD) and prior["operator"] == parent and closed["scope"] == scope
         and closed["proof"] == prior["guard_projection_qualification"] and not os.path.lexists(NEW),
         "different third gate or fourth destination")
    sources = {}
    for filename in ("fourth_attempt.py", "fourth_parent.py", "unreleased_third.py"):
        file = HERE / filename
        key = "scripts/horizon_epoch169_hourly_retry/" + filename
        raw = file.read_bytes()
        for revision in (observed, commit):
            need(subprocess.check_output(["git", "show", revision + ":" + key], cwd=HERE) == raw,
                 "source differs from merged revision: " + filename)
        sources[filename] = hashlib.sha256(raw).hexdigest()
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, observed], cwd=HERE, check=True)
    FOURTH.mkdir(mode=0o755, exist_ok=True)
    st = FOURTH.lstat()
    need(FOURTH.resolve(strict=True) == FOURTH and st.st_uid == 0 and not st.st_mode & 0o022
         and st.st_dev == c["HOME"].stat().st_dev, "wrong fourth control tree")
    stage = Path(tempfile.mkdtemp(prefix="operator-source.", dir=FOURTH))
    for item in deployment["members"]:
        name = item["name"]
        file = OLD / name
        meta, raw = c["stable"](file, expected=item["sha256"], sealed=True, keep_bytes=True)
        need(file.parent == OLD and meta["size"] == item["bytes"], "third package member changed")
        if name == "ORIGIN.json":
            continue
        code = derive(name, raw)
        if name.endswith(".py"):
            compile(code, name, "exec")
        (stage / paths(name)).write_bytes(code)
    (stage / "fourth_parent.py").write_bytes((HERE / "fourth_parent.py").read_bytes())
    c["recorded"](stage / "ORIGIN.json", dict(branch="origin/account-updates", commit=commit, remote_observed=observed,
                  remote_contains_commit=True, sources=sources, parent=parent, parent_scope=scope, closure=closure,
                  guard_fixture=closed["proof"]))
    members = [dict(name=p.name, source=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest(), mode=0o444)
               for p in sorted(stage.iterdir())]
    ref = c["recorded"](FOURTH / f"OPERATOR_PLAN_{time.time_ns()}.json",
                        dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=members))
    c["stable"](SEALER, expected=SEALER_SHA, sealed=True)
    subprocess.run([str(SEALER), ref["path"], "--plan-sha256", ref["sha256"], "--self-sha256", SEALER_SHA], check=True)
    seal, result = read(NEW / "deployment-seal-receipt.json")
    need(seal["destination"] == str(NEW) and seal["plan_sha256"] == ref["sha256"], "different fourth operator")
    return result


def floors(c, issuer, prior, closed):
    first = issuer.quote.bound(prior["first_gate_closure"])
    receipts = {}
    for label, refs in (("protected_floor_rose", (first["prestart"], first["postguard_reproduction"])),
                        ("available_home_fell", (closed["prestart"], closed["postguard"]))):
        before, after = (issuer.quote.bound(ref) for ref in refs)
        floor = issuer.startup_floor(before)
        margin = issuer.guarded_margin(after, floor, c.HOME_OUTPUT)
        c.need(before["fits"] and after["fits"] and before["home_margin"] >= 0
               and after["guard_floor"] <= floor <= before["whole_roster"]["available_home"] - c.HOME_OUTPUT
               and margin >= 0, "fourth startup would refuse the measured " + label)
        receipts[label] = dict(prestart=refs[0], postguard=refs[1], armed_floor=floor,
                               measured_protected=after["guard_floor"], remaining_after_full_output=margin)
    return c.recorded(FOURTH / "STARTUP_FLOOR_FIXTURE.json", receipts)


def scope():
    sys.path.insert(0, str(NEW))
    import contract as c
    import issuer
    import prepare
    import observe
    prior, parent = c.read(THIRD / "SCOPE.json", PARENT["SCOPE"])
    closed, closure = c.read(THIRD / "UNRELEASED_OUTPUT_MARGIN.json", PARENT["CLOSURE"])
    row, previous = observe.closed_parent({})
    c.need(previous == closure and row["terminal"] == closed["terminal"], "third missed-tick recovery failed")
    seal, package = c.read(NEW / "deployment-seal-receipt.json")
    origin, source = c.read(NEW / "ORIGIN.json")
    c.need(origin["parent_scope"] == parent and origin["closure"] == closure
           and origin["guard_fixture"] == prior["guard_projection_qualification"], "fourth source binding")
    floor_fixture = floors(c, issuer, prior, closed)
    namespace = prepare.fixture(NEW)
    sample = issuer.quote.bound(namespace)
    c.need(sample["host"]["mounts"] == sample["readback"]["mounts"] and sample["current_inputs"] == prior["inputs"]
           and sample["readback"]["limits"]["memory.max"] == str(c.RAM) and not sample["admission"],
           "different fourth namespace")
    predecessor = issuer.quote.bound(prior["guard_static"])
    old_plan = issuer.quote.bound(predecessor["plan"])
    plan = c.recorded(FOURTH / "GUARD_STATIC_FIXTURE.json", json.loads(paths(json.dumps(old_plan))))
    result = json.loads(subprocess.check_output([str(issuer.GUARD), plan["path"], "--plan-sha256", plan["sha256"],
                        "--self-sha256", issuer.GUARD_SHA, "--validate-plan-only"], text=True))
    c.need(result["validated"] and result["unit"] == c.UNIT and not result["protective_guard_proven"]
           and result["resource_samples_taken"] == 0 and not result["replay_launch_authorized"], "fourth guard validation")
    guard = c.recorded(FOURTH / "GUARD_STATIC_ACCEPTED.json", dict(plan=plan, result=result, unit_started=False,
                       projection_fixture=prior["guard_projection_qualification"]))
    cadence_sha, = (r["sha256"] for r in seal["members"] if r["name"] == "cadence.py")
    current = dict(prior, schema="horizon-169-fourth-attempt-scope-v1", parent_scope=parent, third_unreleased=closure,
                   startup_floor_fixture=floor_fixture, guard_readonly_source=str(c.RETRY), producer_unit=c.UNIT,
                   guard_timer=observe.TIMER, watcher=prepare.TERMINAL, operator=package, namespace_fixture=namespace,
                   guard_static=guard, merged_source=source, output=str(c.RETRY / "v158" / c.BASE_NAME), log=str(observe.LOG),
                   cadence_source=dict(path=str(NEW / "cadence.py"), sha256=cadence_sha))
    issuer.checked_inputs(current)
    return c.recorded(FOURTH / "SCOPE.json", current)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "scope"))
    parser.add_argument("--commit")
    parser.add_argument("--observed")
    args = parser.parse_args()
    print(json.dumps(plan(args.commit, args.observed) if args.action == "plan" else scope()))
