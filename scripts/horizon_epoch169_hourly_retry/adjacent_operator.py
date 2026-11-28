"""Issue the existing private split-scratch operator for epoch 169's next NY5 checkpoint."""
import argparse
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import adjacent_inputs as a

one = a.shared.exact
OLD_BASE = a.TEMPLATE.parent.name
BASE = a.BASE
DONOR_SHA = "d1837511edc09d506d6ba851d94b53ba5d5c67df6390bd0df36c8624443f35fa"


def between(source, start, end, value):
    a.need(source.count(start) == source.count(end) == 1, "unexpected template section: " + start)
    left, tail = source.split(start)
    _, right = tail.split(end)
    return left + value + end + right


def route(text):
    return (text.replace(OLD_BASE, BASE.name).replace("162-third-replay-20261128-v1","169-from-73245218-20261128-v1")
            .replace("third162_", "adjacent169_").replace("status162.py", "status169.py")
            .replace("epoch 162", "epoch 169").replace("epoch-162", "epoch-169")
            .replace("162-split-readback","169-adjacent-readback").replace("SPLIT162_ENROLLMENT","ADJACENT169_ENROLLMENT"))


def layout(text, scope_hash):
    text = one(text,"1ded1d0f3bdf930a1e07c8d83f6bddf4cb648cf18d344bb3a80c525f6f5bda77",scope_hash)
    text = one(text,"a954d3035ecc6c450c97212ec4a27f6676440c6c23a6bf579d0cc07a949c0ff9",a.GUARD_SHA)
    text = one(text,'DONOR = RT / "epoch162-first-hourly-completion-20261127-v2" / "SPLIT_AND_166_WATCHERS_1795819276953592886.json"',
               'DONOR = RT / "' + a.PRIOR.name + '" / "START_INTENT.json"')
    text = one(text,"64aa76de4fb179a650488d3d53c05050aff7b4fa97ef60c61d3726e42545133c",DONOR_SHA)
    text = one(text,'SUPPORT = PRIVATE / "epoch162-local-capped-20261127.6qaa2Qgr"\n',"")
    text = one(text,"9_470_567_509_909","9_605_558_988_436")
    text = one(text,"HOME_IMAGE = 3 * G","HOME_IMAGE = 4 * G")
    text = one(text,"scratch_gib in (32, 36)", "scratch_gib == 44")
    text = text.replace("26 * G", "12 * G").replace("scratch_gib + 26", "scratch_gib + 12").replace("scratch_gib + 27", "scratch_gib + 13")
    return one(text,'plan["scratch_bytes"] + 24696061952','plan["producer_memory_max"] - 3 * G')


def launch(text):
    text = text.replace("l.profile(36)", "l.profile(44)").replace("l.producer_argv(36,", "l.producer_argv(44,")
    text = text.replace("l.verify_mounts(pid, 36,", "l.verify_mounts(pid, 44,")
    text = between(text,"def check_169(spec, q):","def price(phase, held):","")
    text = one(text,'q["third_162_predecessor"] == l.scope()["previous"], "different second interval custody"',
               'q["adjacent_169_predecessor"] == l.scope()["previous"], "different private 169 predecessor"')
    text = one(text,'"horizon-162-split-fleet-price-v1"','"horizon-169-adjacent-fleet-price-v1"')
    text = one(text,'q["scratch_gib"] == 36','q["scratch_gib"] == 44')
    text = one(text,'q["exclusive_166_lease"] is True\n        and "169" in q["peers"]\n        and q["peers"]["169"]["phase"] in ("precharged", "held", "bootstrap", "worker", "terminal")',
               'q["exclusive_169_lease"] is True\n        and q["whole_roster"]["adjacent_169_accounting"]["predecessor"] == l.scope()["previous"]')
    return text.replace("166 donor","169 predecessor booking").replace("162 ", "169 ")


def status(text):
    text = one(text,'FIELD = "current_private162_third_hourly"',f'FIELD = "{a.FIELD}"')
    text = between(text, '    historical = fleet.get("current_private162_first_hourly")','    registered = [r for r in fleet',
                   '''    predecessor = fleet.get("current_private169_retry4")
    model = l.scope()
    end = l.bound(model["previous"])
    l.need(predecessor and predecessor["unit"]["Id"] == end["unit"]
           and predecessor["phase"] == "terminal"
           and predecessor["invocation_id"] == end["invocation_id"] == "89f12725fa804408958878cb5cb8ca55"
           and predecessor["terminal"] == model["previous"] and predecessor["held"] == model["previous_held"]
           and end["disposition"] == "completed-private-span" and not end["resource_credit_bytes"],
           "missing accepted preceding epoch 169 interval")
''')
    return text.replace('== 162','== 169').replace('epoch=162','epoch=169').replace('"162"','"169"').replace('private162_','private169_').replace("162 ", "169 ")


def terminal(text):
    text = one(text,"/home/sol/.jetstreamer-private/epoch162-next-input-20261128.j9SpisbY/TERMINAL_BANK_WITNESS.json",str(a.WITNESSES[1]))
    text = one(text,"7af0483755d00617ea91328de4b0f160311261427423f63f37c4a5a8c74fe377",a.BANK_SHAS[1])
    return text.replace("70004937","73252243")


def close(text):
    text = text.replace('manifest["epoch"] == 162','manifest["epoch"] == 169').replace("(69998120,6818)","(73245219,7025)")
    text = text.replace("69998119","73245218").replace("70004937","73252243")
    text = one(text,'previous=l.bound(l.scope()["previous"])["archive"]["typed_manifest"]','previous=l.scope()["previous_bank"]')
    text = one(text,'previous["terminal"][key]','previous[key]')
    text = one(text,'and all(typed["bootstrap"]','and typed["runtime"]["runtime_profile"] == "solana-v1.5.6"\n               and typed["runtime"]["runtime_revision"] == "01e4d0a1e9917701d1a148e1043b0ccf545c27f1"\n               and all(typed["bootstrap"]')
    return text.replace("third interval","adjacent 169 interval").replace("third manifest","adjacent 169 manifest").replace("62-GiB","56-GiB")


def members(scope_hash):
    seal = a.load(a.TEMPLATE/"deployment-seal-receipt.json",a.TEMPLATE_SEAL)
    result = {}
    for f in seal["members"]:
        name = f["name"]
        if name.endswith(".py"):
            path = a.TEMPLATE/name
            a.need(path.parent == a.TEMPLATE and a.digest(path) == f["sha256"],"different source member " + name)
            source = route(path.read_text())
            name = name.replace("status162","status169")
            transform = {"launch.py":launch,"status169.py":status,"close.py":close,"terminal_bank.py":terminal}
            text = layout(source,scope_hash) if name == "layout.py" else transform[name](source)
            compile(text,name,"exec")
            result[name] = text
    a.need(len(result) == 5,"incomplete operator")
    return result


def fixture():
    model = a.scope("fixture")
    files = members("0"*64)
    ns = {"__name__":"fixture"}
    exec(compile(files["layout.py"],"layout.py","exec"),ns)
    terminal_ns = {"__name__":"fixture"}
    exec(compile(files["terminal_bank.py"],"terminal_bank.py","exec"),terminal_ns)
    fit = ns["profile"](44)
    g = model["quota"]
    a.need(ns["UNIT"] == a.UNIT and ns["RUN"] == a.RUN and ns["GATE"] == BASE/"static-v1/hold"
           and ns["GUARD"] == BASE/"static-v1/guard" and ns["GUARD_SHA"] == a.GUARD_SHA
           and ns["DONOR"] == a.PRIOR/"START_INTENT.json" and a.digest(ns["DONOR"]) == ns["DONOR_SHA"]
           and fit["home_image"] == g["home_output"] and fit["control"] == g["home_control"]
           and fit["scratch_bytes"] == g["scratch"] and fit["producer_memory_max"] == g["producer_ram"]
           and fit["guard_memory_max"] == g["guard_ram"] and fit["producer_cpu_micros"] == g["producer_cpu"]
           and fit["guard_cpu_micros"] == g["guard_cpu"],"split profile differs from predecessor reservation")
    argv = ns["producer_argv"](44,model,model["profile"]["readonly_projections"])
    a.need(argv[-1] == a.ALIAS+"/hold" and "--property=MemoryMax="+str(56*a.G) in argv
           and "--property=MemorySwapMax=0" in argv and "169" == model["profile"]["actual_node_argv"][1],
           "different launch entry")
    return dict(positions=model["position_count"],previous=model["previous"],terminal_bank=terminal_ns["fixture"](),
                scope_checkpoints=[w.name for w in a.WITNESSES],profile=fit)


def prepare(revision):
    checkout = HERE.parents[1]
    git = ["git","-c","safe.directory="+str(checkout),"-C",str(checkout)]
    for commit in (revision,a.SOURCE_NATIVE):
        subprocess.run([*git,"merge-base","--is-ancestor",commit,"origin/account-updates"],check=True)
    inputs = {}
    for path in (HERE/"adjacent_inputs.py",HERE/"adjacent_operator.py",HERE.parent/"horizon_epoch162_split_scratch/second_interval.py"):
        relative = str(path.relative_to(checkout))
        a.need(subprocess.check_output([*git,"show",revision+":"+relative]) == path.read_bytes(),"unpublished "+relative)
        inputs[relative] = a.digest(path)
    a.need(os.geteuid() == 0 and BASE.resolve() == BASE and BASE.stat().st_uid == 0 and not BASE.stat().st_mode & 0o077
           and BASE.stat().st_dev == a.PRIVATE.stat().st_dev,"unsafe control root")
    model = a.scope(revision)
    code = a.load(a.TEMPLATE/"deployment-seal-receipt.json",a.TEMPLATE_SEAL)["members"]
    original = a.TEMPLATE/"layout.py"
    a.need(a.digest(original) == next(v["sha256"] for v in code if v["name"] == original.name),"changed metadata writer")
    save = runpy.run_path(str(original))["save"]
    sr = save(BASE/"SCOPE.json",model,0o400)
    src = BASE/"operator-source-v1"
    src.mkdir(mode=0o700,exist_ok=True)
    a.need(src.resolve() == src and src.stat().st_uid == 0 and not src.stat().st_mode & 0o077,"unsafe staging")
    files = {}
    for name, text in members(sr["sha256"]).items():
        save(src/name,text.encode(),0o444)
        files[name] = (src/name,0o444)
    origin = src/"ORIGIN.json"
    save(origin,dict(revision=revision,native=a.SOURCE_NATIVE,inputs=inputs,scope=sr,qualified_operator=a.reference(a.TEMPLATE/"deployment-seal-receipt.json"),
                     guard=model["guard_deployment"],predecessor=model["previous"],predecessor_validation=model["previous_validation"]))
    files[origin.name] = origin,0o444
    a.shared.BASE = BASE
    operator = a.shared.seal(files,BASE/"operator-v1",save)
    return save(BASE/"INTERFACE.json",dict(unit=a.UNIT,field=a.FIELD,provider=operator,
                reader=a.reference(BASE/"operator-v1/status169.py"),scope=sr,first_slot=a.SLOTS[0]+1,last_slot=a.SLOTS[1],
                previous=model["previous"],previous_held=model["previous_held"],guard=model["first_hourly_guard"],
                gate=model["first_hourly_gate"],guard_validation=model["native_guard_validation"]),0o400)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--prepare",metavar="SOURCE_COMMIT")
    args = cli.parse_args()
    out = fixture()
    if args.prepare:
        out["interface"] = prepare(args.prepare)
    print(json.dumps(out,sort_keys=True))
