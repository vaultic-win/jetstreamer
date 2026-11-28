"""Reuse the tested epoch 170 hold, protection and release controls for the new interval."""
import argparse
import ast
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from derive_ram170_writer import once
from following_prepare import ROOT as RT, git, need, read, reference, save, seal
from next_hourly170 import PREVIOUS, ROOT
from closed_successor import persist

OLD = PREVIOUS/"operator-v1"
OLD_SEAL = dict(path=str(OLD/"deployment-seal-receipt.json"),
                sha256="18c12ba44fffba984d64b9310e94fbc24f838b32c28c713a30a06a2c2edf70f3")


def source_members(destination):
    deployed = read(OLD_SEAL)
    pins = {m["name"]:m["sha256"] for m in deployed["members"]}
    def text(name):
        path = OLD/name
        need(reference(path)["sha256"] == pins[name],"different inherited "+name)
        return path.read_text()

    operator = text("bounded_successor.py")
    operator = once(operator,"epoch170-from-73766969-ram-20261128-v1/operator-v1",
                    "epoch170-from-73773645-ram-20261128-v1/operator-v1")
    operator = once(operator,'    q = load("after_ram170_issuer")','    q = load("next_hourly170_issuer")')
    old = '''    layout=q.bound(i["layout"])
'''
    operator = once(operator,old,'    layout=q.bound(i["staged_layout"])\n')
    begin = operator.index('    spec=Path(layout["service"]["path"])')
    end = operator.index("    # Verify complete preflight",begin)
    operator = operator[:begin]+'''    spec=package/UNIT
    need(ns["service"]["path"]==str(spec) and digest(spec)==ns["service"]["sha256"]
         and ns["source"]==i["source_packet"] and ns["seal"]==profile["sealed_package"]
         and layout["directories"][2]["path"]==i["run"],"namespace differs")
'''+operator[end:]
    operator = once(operator,'    unit=Path(q.bound(i["layout"])["service"]["path"])',
                    '    unit=Path(i["profile"]["sealed_package"]["path"]).with_name(UNIT)')
    begin = operator.index("def funded_guard(")
    end = operator.index("def arm(",begin)
    operator = operator[:begin]+'''def funded_guard(fit, floor, cap):
    if floor < fit["guard_floor"] or cap != fit["guard_cap"]:
        return False
    raised = floor - fit["guard_floor"]
    return (fit["home_margin"] >= raised
            and fit["available_home"] >= fit["required_home"] + raised + fit["drawdown_allowance"])


'''+operator[end:]
    issuer = (HERE/"next_hourly170_issuer.py").read_text()
    recovery = text("after_ram170_issuer.py")
    issuer += "\n\n" + recovery[recovery.index("def recover_start("):]
    issuer = once(issuer,"import sys\n","import sys\nimport time\n")
    progress = once(text("continuation_progress.py"),"epoch170-from-73766969-ram-20261128-v1",
                    "epoch170-from-73773645-ram-20261128-v1")
    if destination.name == "operator-v2":
        operator = once(operator, f'{ROOT.name}/operator-v1', f'{ROOT.name}/operator-v2')
        progress = once(progress, 'HOURLY_RAM_ROOT/"operator-v1"', 'HOURLY_RAM_ROOT/"operator-v2"')
        progress = once(progress, 'if Path(__file__).resolve().parent == AFTER_RAM_ROOT/"operator-v1":',
                        'if Path(__file__).resolve().parent in (AFTER_RAM_ROOT/"operator-v1", HOURLY_RAM_ROOT/"operator-v2"):')
        progress = once(progress, 'OPERATOR = ROOT/OPERATOR_NAME',
                        'OPERATOR = ROOT/("operator-v2" if ROOT == HOURLY_RAM_ROOT else OPERATOR_NAME)')
        progress = once(progress, '    directory = ROOT/"operator-v1" if ROOT in (RAM_ROOT,AFTER_RAM_ROOT) else OPERATOR',
                        '    directory = ROOT/"operator-v1" if ROOT in (RAM_ROOT,AFTER_RAM_ROOT) and ROOT != HOURLY_RAM_ROOT else OPERATOR')
    return {"bounded_successor.py":operator.encode(),"next_hourly170_issuer.py":issuer.encode(),
            "continuation_dispatch.py":text("continuation_dispatch.py").encode(),
            "continuation_progress.py":progress.encode(),
            "ram170_workspace.py":text("ram170_workspace.py").encode(),
            "closed_successor.py":text("closed_successor.py").encode()}


def stage(provider,writer):
    repo = HERE.parents[1]
    revision = git(repo,"rev-parse","HEAD").decode().strip()
    git(repo,"merge-base","--is-ancestor",revision,"origin/account-updates")
    names = ("stage_next_hourly170_operator.py","next_hourly170_issuer.py","next_hourly170_price.py",
             "next_hourly170.py","following_prepare.py")
    for name in names:
        member = HERE/name
        need(git(repo,"show",f"{revision}:{member.relative_to(repo)}")==member.read_bytes(),"unpublished operator source "+name)
    price = read(provider)
    active = read(writer)
    version = int(Path(price["destination"]).name.removeprefix("issued-price-v"))
    need(version == 37 or version >= 39, "different next-hourly shared provider")
    need(Path(price["destination"]) == Path(provider["path"]).parent
         and writer["path"].endswith("/FAILED166_CADENCE_V75_ACTIVE.json")
         and active["new"]["program"].endswith("/tools-cold168-retry5-failed166-v75-entry146/status_cycle.py"),
         "different V37 and V75 lineage")
    generation = 1 if version == 37 else 2
    destination = ROOT/f"operator-v{generation}"
    stage = ROOT/f"operator-source-v{generation}"
    stage.mkdir(mode=0o700,exist_ok=True)
    need(stage.resolve(strict=True)==stage and stage.stat().st_uid==0
         and not stage.stat().st_mode & 0o077,"unsafe operator staging path")
    bindings = save(stage/"binding.json",dict(provider=provider,preceding_writer=writer,source_revision=revision,
        interface=reference(ROOT/"NEXT_HOURLY_WRITER_INTERFACE.json"),
        receiver=reference(ROOT/"observer-modules-v1/deployment-seal-receipt.json")))
    files = {name:(HERE/name,0o444) for name in ("next_hourly170_price.py","next_hourly170.py","following_prepare.py")}
    for name,raw in source_members(destination).items():
        ast.parse(raw,filename=name)
        path = stage/name
        persist(path,raw)
        files[name] = path,0o444
    files["binding.json"] = Path(bindings["path"]),0o444
    plan = "OPERATOR_PLAN.json" if generation == 1 else "REBOUND_OPERATOR_PLAN.json"
    return seal(destination,files,ROOT/plan)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider_sha256")
    parser.add_argument("v75_owner_sha256")
    parser.add_argument("--price-version", type=int, default=37)
    args = parser.parse_args()
    base = RT/f"epoch162-first-hourly-completion-20261127-v2/issued-price-v{args.price_version}"
    writer = RT/"survivor172-cadence-20261122-v1/FAILED166_CADENCE_V75_ACTIVE.json"
    print(json.dumps(stage(dict(path=str(base/"deployment-seal-receipt.json"),sha256=args.provider_sha256),
        dict(path=str(writer),sha256=args.v75_owner_sha256)),sort_keys=True))
