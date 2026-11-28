"""Carry the V50 status pipeline and its existing appointments into V51."""
import ast
import hashlib
import json
from pathlib import Path

from derive49 import one

HERE = Path(__file__).resolve().parent
OLD = "tools-cold168-retry5-failed166-v50-entry146"
NEW = OLD.replace("v50", "v51")
SEAL = "dd12e26e1050e42797c117c62a3b34c4f84f45e05dc47aa5060b4807421b45d2"
ACTIVE = "1a97e2971f8222d98412392054d540fda66efa609721b1d7caa28f402125eb22"
REBOUND = "76e9bad312e85015599a9fd6025284677e0b713718f424d30140adb504190d2d"
V49_SEAL = "4dd7b81551d7c2e556a3a7bafa6d2d2b6603db9abdbcf360a7cf4f22ea416307"
V49_ACTIVE = "06c15b1b1e3994506f95b38ff404f04972053337f51d222c866395090e77719d"
V49_REBOUND = "94641b9b2dc501c0a6bcf3f8d117e94a6ef873087fd565bae6677c6432d19c96"


def next_pair(source):
    for tag in ("cutover", "recover", "v", "V"):
        source = source.replace(tag + "50", tag + "51").replace(tag + "49", tag + "50")
    return source.replace(V49_SEAL, SEAL).replace(V49_ACTIVE, ACTIVE).replace(V49_REBOUND, REBOUND)


def cycle(source):
    source = source.replace(", 50)", ", 50, 51)")
    for line in source.splitlines():
        if line.strip() in ("import transition_v50", "modules.append(transition_v50)"):
            wrapper = line[:line.index(line.strip()) - 4]
            source = one(source, line, line + "\n" + wrapper + "elif FAILED166_VERSION == 51:\n" + line.replace("v50","v51"))
        elif "50: (transition_v50." in line or "50: 'fb9db4" in line:
            source = one(source, line, line + "\n" + next_pair(line).replace("50:", "51:"))
    # The predecessor authority table evaluates both module references.
    source = one(source, "                elif FAILED166_VERSION == 51:\n                    import transition_v51",
                 "                elif FAILED166_VERSION == 51:\n                    import transition_v50\n                    import transition_v51")
    anchor = "    elif FAILED166_VERSION == 50:\n        transition_v50.validate(globals(), ready, receipt)"
    source = one(source, anchor, anchor + "\n" + anchor.replace("50","51"))
    start = source.index("    if FAILED166_VERSION == 50 and len(sys.argv)")
    end = source.index("    if FAILED166_VERSION == 49 and len(sys.argv)", start)
    source = source[:start] + source[start:end].replace("50", "51") + source[start:]
    # Use the frozen 162 actor for a resumed sample. Its PID and guard are still
    # checked normally and the initial wire receipt retains its own event time.
    anchor = "        c.split162 = status162.observe(c, callback162)"
    return one(source, anchor, """        saved_census = out/'CYCLE_OBSERVATION.json'
        if FAILED166_VERSION == 51 and saved_census.exists():
            frozen = checked(bound(saved_census))
            need(frozen['observer'] == sample_ref and frozen['fleet_predecessor'] == head,
                 'saved 162 census belongs to another observation')
            c.split162 = frozen['capacity'].get(status162.FIELD)
        else:
            c.split162 = status162.observe(c, callback162)""")


def watcher(source):
    declaration = 'V50 = original.WRITER / "' + OLD + '"'
    source = one(source, declaration, declaration + "\n" + declaration.replace("50", "51"))
    source = one(source, "        HERE == V50", "        HERE == V51")
    start = source.index("    if active50.exists():")
    end = source.index("    elif active49.exists():", start)
    branch = source[start:end]
    source = source[:start] + "    active51 = original.WRITER / 'FAILED166_CADENCE_V51_ACTIVE.json'\n" + branch.replace("50","51") + branch.replace("    if ", "    elif ", 1) + source[end:]
    start = source.index("    if version == 50:")
    end = source.index("    if version == 49:", start)
    clause = next_pair(source[start:end]).replace("version == 50", "version == 51")
    clause = clause.replace("active49","active50").replace("ready49","ready50")
    clause += """        fleet_path = original.WRITER.parent/'root011808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'
        if not fleet_path.exists():
            return None
        need(checked(bound(fleet_path))['previous_Root_operational_review'] == ready['fleet'],
             '143 reentry requires the accepted 01:18 predecessor')
"""
    source = source[:start] + clause + source[start:]
    source = one(source, "route[4] not in (47, 48, 49, 50)", "route[4] not in (47, 48, 49, 50, 51)")
    start = source.index('    if sys.argv[1:] == ["--check-failed-predecessor"]:')
    end = source.index('    if sys.argv[1:] == ["--check-entry"]:',start)
    return source[:start] + next_pair(source[start:end]) + source[end:]


def stage(old, work):
    seal = old / "deployment-seal-receipt.json"
    raw = seal.read_bytes()
    if old.name != OLD or hashlib.sha256(raw).hexdigest() != SEAL:
        raise ValueError("different predecessor package")
    work.mkdir(mode=0o700)
    members = {}
    for item in json.loads(raw)["members"]:
        name = item["name"]
        path = old / name
        if path.resolve() != path or path.parent != old or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("changed member " + name)
        if name != "SHA256SUMS":
            members[name] = dict(name=name, source=str(path), sha256=item["sha256"], mode=int(item["mode"],8))

    def add(name, data):
        ast.parse(data, filename=name)
        path = work / name
        path.write_text(data)
        path.chmod(0o444)
        members[name] = dict(name=name, source=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), mode=0o444)

    add("status_cycle.py", cycle((old/"status_cycle.py").read_text()))
    for name in ("full170_status.py", "cold170_status.py", "joint168_status.py"):
        data = (old/name).read_text()
        end = "'" + OLD + "')"
        if end not in data:
            raise ValueError("missing parent receiver " + name)
        add(name, data.replace(end, "'" + OLD + "', '" + NEW + "')"))
    add("watch143_versions.py", watcher((old/"watch143_versions.py").read_text()))
    transition = next_pair((old/"transition_v50.py").read_text()).replace("failed166_package'](49)", "failed166_package'](50)")
    add("transition_v51.py", transition)
    add("cutover51.py", next_pair((old/"cutover50.py").read_text()))
    add("recover51.py", (HERE/"recover51.py").read_text())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(old.with_name(NEW)), members=list(members.values()))
