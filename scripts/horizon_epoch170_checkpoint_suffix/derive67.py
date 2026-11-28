"""Recover the existing 09:48 sample and enroll the 170 hourly receiver."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import derive_after_floor170_writer as hourly

ROOT = hourly.BASE / "survivor172-cadence-20261122-v1"
OLD = ROOT / "tools-cold168-retry5-failed166-v66-entry146"
NEW = OLD.with_name(OLD.name.replace("v66", "v67"))
SEAL = "05a0b11ac5eb14c53aa0bd0773479b9c4d76e616d9e6c03d8508f2b3311171cb"
SCOPE = dict(path=str(hourly.ROOT/"AFTER_FLOOR_WRITER_INTERFACE.json"), sha256="a4ca94b87bb1a301d76eacab1b3421dd52f96b5a4e5d0074b73dd6a3d3a63078")


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("different predecessor near " + old[:100])
    return source.replace(old, new)


def cycle(source):
    model, commands = source.split("def main():", 1)
    model = model.replace(", 66)", ", 66, 67)")
    model = re.sub(r"^( +)if FAILED166_VERSION == 66:$", r"\1if FAILED166_VERSION >= 66:", model, flags=re.M)
    for anchor, addition in (("import transition_v66", "import transition_v67\nimport forecast166"),
                             ("modules += [floor_retry143, floor_retry143_scope, transition_v66]", "modules += [transition_v67, forecast166]")):
        line, = [line for line in model.splitlines() if line.strip() == anchor]
        indent = line[:len(line)-len(line.lstrip())]
        model = once(model, line, line+"\n"+indent+"if FAILED166_VERSION >= 67:\n"+"\n".join(indent+"    "+v for v in addition.splitlines()))
    anchor = "    elif FAILED166_VERSION == 66:\n        transition_v66.validate(globals(), ready, receipt)"
    model = once(model, anchor, anchor.replace("== 66", "== 67").replace("v66.validate", "v67.validate")+"\n"+anchor)
    for line in model.splitlines():
        if line.strip().startswith(("66: (transition_v66.", "66: 'fb9db4e77")):
            model = once(model, line, line+"\n"+line.replace("66:", "67:", 1).replace("transition_v66.V65", "transition_v67.V66"))
    # The first 143 check proves any earlier write at this sample. Keep its
    # predecessor in refs until the ordinary loop processes the same intent.
    block = """        if (target/'epoch-143.intent.json').exists():
            publish(c, store, one143, target, 143)
        refs.update(one143)
        c.status143 = refs['143']"""
    model = once(model, block, """        refs.update(one143)
        if (target/'epoch-143.intent.json').exists():
            publish(c, store, one143, target, 143)
        c.status143 = one143['143']""")
    anchor = "        else:\n            need(prior['phase']=='verification','new replay owner requires adoption before publication')"
    model = once(model, anchor, """        elif epoch == 166 and FAILED166_VERSION >= 67 and (
                c.now - utc(prior['sampled_at_utc'])).total_seconds()*1000 >= prior['estimated_remaining_millis']:
            after, extra = forecast166.forecast(c, prior, original, refs['162'])
""" + anchor)
    command_blocks = list(re.finditer(r"^    if FAILED166_VERSION == 66 and len\(sys.argv\) == 4[^\n]*:\n(?:        [^\n]*\n)+", commands, re.M))
    if len(command_blocks) != 5:
        raise ValueError("unexpected V66 handoff commands")
    for m in reversed(command_blocks):
        nxt = m[0].replace("== 66", "== 67").replace("v66", "v67").replace("V66", "V67")
        commands = commands[:m.start()]+nxt+commands[m.start():]
    result = hourly.cycle(model + "def main():" + commands, 67)
    # The legacy checkpoint receiver already owns c.hourly170. Both receivers
    # must be able to present their independent evidence in the same sample.
    if result.count("c.hourly170 = after_floor170_status.observe("):
        raise ValueError("hourly receiver uses the legacy receiver's state")
    return result


def stage(folder):
    raw = (OLD/"deployment-seal-receipt.json").read_bytes()
    if sha256(raw).hexdigest() != SEAL or json.loads(raw)["destination"] != str(OLD):
        raise ValueError("unrecognized V66 package")
    folder.mkdir(mode=0o700)
    rows = {}
    for item in json.loads(raw)["members"]:
        name = item["name"]
        p = OLD/name
        if p.parent != OLD or name in rows or p.resolve() != p or sha256(p.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("different V66 member "+name)
        if name != "SHA256SUMS":
            rows[name] = dict(name=name, source=str(p), sha256=item["sha256"], mode=int(item["mode"], 8))

    def add(name, raw):
        ast.parse(raw, filename=name)
        p = folder / name
        p.write_bytes(raw)
        p.chmod(0o444)
        rows[name] = dict(name=name, source=str(p), sha256=sha256(raw).hexdigest(), mode=0o444)

    add("status_cycle.py", cycle((OLD/"status_cycle.py").read_text()).encode())
    scope_ref = hourly.ROOT/"observer-modules-v1/deployment-seal-receipt.json"
    if sha256(scope_ref.read_bytes()).hexdigest() != "d02806af0dd82e76ad140b6436b3ab2f78b5a551005a42f7c728ee56fcc6685c":
        raise ValueError("unexpected hourly observer deployment")
    source = hourly.members(SCOPE)
    for name, raw in source.items():
        if raw != (scope_ref.parent/name).read_bytes():
            raise ValueError("observer source differs from the accepted receiver")
        add(name, raw)
    cutover = (OLD/"cutover66.py").read_text()
    cutover = re.sub(r"(cutover|[vV])(65|66)", lambda m: m[1] + str(int(m[2]) + 1), cutover)
    cutover = cutover.replace("53f0d5e2181341b51779c2e91672b61f1b06bfd0c4d493708e2524ab54f2e1c3", SEAL)
    cutover = cutover.replace("53397543058f6c75319bd7e68bf587cf991bf4c984ea155096c34d90a4bb74ac", "b4d26a441e41758d31cb797d746d608b27ecda582126cf58fb5cceac67815dd7")
    add("cutover67.py", cutover.encode())
    for name in ("forecast166.py", "transition_v67.py", "recover67.py"):
        add(name, (HERE/name).read_bytes())
    for name, count in (("full170_status.py",1), ("cold170_status.py",5), ("joint168_status.py",3)):
        source = (OLD/name).read_text()
        marker = repr(OLD.name)+")"
        if source.count(marker) != count:
            raise ValueError("different installed roster in "+name)
        add(name,source.replace(marker,repr(OLD.name)+", "+repr(NEW.name)+")").encode())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(NEW),members=list(rows.values()))


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]).resolve()), indent=2))
