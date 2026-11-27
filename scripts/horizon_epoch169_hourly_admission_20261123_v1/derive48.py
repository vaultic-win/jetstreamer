"""Stage V48 from the exact V47 writer, including its existing 143 and 170 actors."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
V47 = "cdeef56bc6fddb7189be65ace5a72468514ed97d08b470be5248d79da8177f55"
BOOKER = "f127e596ee005a8d2a1adc72561fb288bb98df03ff10a5439dc4e06bac66aa79"
ACTIVE = "def64d8842984dee1835c05aefa8b5f344c52f9b97e8691db123b1cce2daca86"
OLD = "tools-cold168-retry5-failed166-v47-entry146"
NEW = OLD.replace("v47","v48")
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
OPERATOR = RT / "epoch169-hourly-admission-20261123-v1/issued-split-v1"
PEER = RT / "epoch162-first-hourly-completion-20261127-v2/issued-split-v1"
PEER_SHA = "ca5ac887bdb0ca18b607966df05e890dbbc0ba3f73fb1112c4717ab97dc9415e"
PEER_READER = "9abbb1b8451e84e99b8b6dc81e14a78390430bfb3242f3f876a963b9fb8a62b9"


def one(source, old, new):
    if source.count(old) != 1:
        raise ValueError("predecessor changed: " + old)
    return source.replace(old, new)


def cycle(s):
    s = s.replace(", 47)",", 47, 48)")
    s = one(s, "        if FAILED166_VERSION == 47:\n            import transition_v47", """        if FAILED166_VERSION == 48:
            import transition_v48
            import split_status169
            import status162
        if FAILED166_VERSION in (47, 48):
            import transition_v47""")
    s = one(s, "            if FAILED166_VERSION == 47:\n                modules +=", """            if FAILED166_VERSION == 48:
                modules += [transition_v48, split_status169, status162]
            if FAILED166_VERSION in (47, 48):
                modules +=""")
    s = one(s, "    elif FAILED166_VERSION == 47:\n        transition_v47", """    elif FAILED166_VERSION == 48:
        transition_v48.validate(globals(), ready, receipt)
    elif FAILED166_VERSION == 47:
        transition_v47""")
    needle = "                47: (transition_v47.V46_SHA, transition_v47.V46_SEAL),"
    s = one(s,needle,needle+"\n                48: (transition_v48.V47_SHA, transition_v48.V47_SEAL),")
    needle = "                    47: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    s = one(s,needle,needle+"\n"+needle.replace("47:", "48:"))
    old = "    if FAILED166_VERSION == 47 and len(sys.argv) == 4:"
    s = one(s,old,"""    if FAILED166_VERSION == 48 and len(sys.argv) == 4:
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        if sys.argv[1] == '--check-v48-handoff':
            print(json.dumps(transition_v48.ready(globals(), head, receipt)))
            return
        if sys.argv[1] == '--enroll-next-bounded-170':
            os.umask(0o077)
            writer_ref = bound(ROOT/'FAILED166_CADENCE_V48_ACTIVE.json')
            print(json.dumps(successor170_status.enroll(globals(), head, writer_ref)))
            return
""" + old)
    needle = "    if FAILED166_VERSION == 47:\n        print(json.dumps(dict(epoch143_writer_active=bound(ROOT/'FAILED166_CADENCE_V47_ACTIVE.json'))), flush=True)"
    s = one(s,needle,needle.replace("== 47", "in (47, 48)").replace("ROOT/'FAILED166_CADENCE_V47_ACTIVE.json'", "ROOT/f'FAILED166_CADENCE_V{FAILED166_VERSION}_ACTIVE.json'"))
    needle = "                diagnostic_replays=[r for r in original['diagnostic_replays'] if r['range']!='169'],"
    s = one(s,needle,"""                diagnostic_replays=[r for r in original['diagnostic_replays'] if r['range']!='169'
                                    or FAILED166_VERSION == 48 and split_status169.accept_assignment(r)],""")
    needle = "        hourly_population.project_all(c, c.first_hourly)"
    s = one(s,needle,needle+"""
    if FAILED166_VERSION == 48:
        c.split169 = split_status169.observe(c, cycle.observed_lane)
        if split_status169.active(c.split169) and c.split169['phase'] != 'held':
            need('169' not in native_owners and 169 not in c.new_rows, 'private and canonical epoch 169 overlap')
            native_owners = dict(native_owners, hourly169=c.split169)
        split_status169.project(c, c.split169)
        c.split162 = status162.observe(c, cycle.observed_lane)
        if status162.active(c.split162) and c.split162['phase'] != 'held':
            need('162' not in native_owners and 'first162' not in native_owners and 162 not in c.new_rows, 'concurrent 162 owners')
            native_owners = dict(native_owners, split162=c.split162)
        status162.project(c, c.split162)""")
    needle = "        hourly_population.recheck_all(c.first_hourly)"
    s = one(s,needle,needle+"""
    if FAILED166_VERSION == 48:
        split_status169.reader()['recheck'](c.fleet, c.split169)
        status162.recheck(c.fleet, c.split162)""")
    needle = "        cap[hourly_population.CAPACITY_FIELD] = hourly_population.capacity(c.first_hourly)"
    s = one(s,needle,needle+"""
    if FAILED166_VERSION == 48 and c.split169:
        cap[split_status169.FIELD] = c.split169
    if FAILED166_VERSION == 48 and c.split162:
        cap[status162.FIELD] = c.split162""")
    needle = "        if PRIVATE136:\n            extra.update(private136.status_fields(c,epoch))"
    s = one(s,needle,"""        if FAILED166_VERSION == 48 and epoch == 169 and c.split169:
            extra.update(split_status169.status_fields(c.split169))
        if FAILED166_VERSION == 48 and epoch == 162 and c.split162:
            extra.update(status162.status_fields(c.split162))
""" + needle)
    needle = "        diagnostic_count += sum(hourly_population.active(row) for _, row in c.first_hourly)"
    s = one(s,needle,needle+"""
    if FAILED166_VERSION == 48:
        diagnostic_count += int(split_status169.active(c.split169)) + int(status162.active(c.split162))""")
    needle = "        hourly_population.install(fleet, c.first_hourly)"
    return one(s,needle,needle+"""
    if FAILED166_VERSION == 48:
        split_status169.install(fleet, c.split169)
        status162.install(fleet, c.split162)""")


def watcher(s):
    s = one(s, '    if active47.exists():', '''    active48 = original.WRITER / "FAILED166_CADENCE_V48_ACTIVE.json"
    if active48.exists():
        ref = bound(active48)
        version, directory, booker = 48, V48, original.TARGET / "booking-price-v48"
    elif active47.exists():''')
    s = one(s, 'LISTENER = dict(', 'V48 = original.WRITER / "'+NEW+'"\nLISTENER = dict(')
    s = one(s, "        HERE == V47", "        HERE == V48")
    old = "    if version == 47:"
    s = one(s,old,'''    if version == 48:
        predecessor = dict(path=str(active47), sha256='''+ repr(ACTIVE)+''')
        ready47 = checked(checked(predecessor)["ready"])
        need(active["old"] == checked(predecessor)["new"] and ready["old_owner"] == predecessor
             and ready["retained_143_phase"] == report["phase"] == ready47["retained_143_phase"]
             and ready["retained_143_listener"] == ready47["retained_143_listener"] == LISTENER
             and checked(ready["retained_143_v47_rebound"])["phase"] == report["phase"],
             "V48 lacks the original 143 scheduling authority")
''' +old)
    return one(s, "        route[4] != 47", "        route[4] not in (47, 48)")


def cutover(s):
    s=s.replace("cutover47","cutover48").replace("v47","v48").replace("V47","V48")
    s=s.replace("cutover46","cutover47").replace("v46","v47").replace("V46","V47")
    s=s.replace(OLD+"-r2",OLD)
    s=one(s,"4bb23953781c66d9d221d36525f0daae6243d8d667b41bc4388b36be17bc9ea4",V47)
    s=one(s,"657c9965f71dbff5478308c1c6a703bb4732855c6ac3d4b6daaa4dfa67907f4f",ACTIVE)
    s=one(s,'ORIGINAL_LISTENER = TARGET / "reentry-tools-v1/watch143_reentry.py"','ORIGINAL_LISTENER = OLD / "watch143_versions.py"')
    s=one(s,'    phase = doc(Path(scope["phase"]["path"]), scope["phase"]["sha256"])\n    need(\n        phase["writer"] == ref(OLD_ACTIVE) and not ACTIVE.exists(),',
              '''    phase = doc(Path(scope["phase"]["path"]), scope["phase"]["sha256"])
    inherited = doc(TARGET / "REENTRY_V47_REBOUND.json", "61883f8f6fd84c70a145042944ef602369d6b798decd34ade652d26e8cbf565e")
    need(
        inherited["writer"] == phase["writer"] and inherited["phase"] == scope["phase"]
        and inherited["writer_package"] == doc(Path(active["ready"]["path"]), active["ready"]["sha256"])["package"]
        and not ACTIVE.exists(),''')
    s=s.replace('scope["listener"]','inherited["new"]').replace('scope["package"]','inherited["writer_package"]')
    # Matched native actors, including the fourth 170 if already enrolled.
    s=one(s,'actual == set(expected) and NEXT not in actual','actual == set(expected) and "horizon-qualify-169-focused-hourly-20261123-v1.service" not in actual')
    s=one(s,'    return dict(\n        producers=owners, assembly=assembly, guards=guards, hourly143=preserve143()','''    import split_status169
    native = split_status169.verification(fleet)
    return dict(
        producers=owners, assembly=assembly, verification168=native, guards=guards, hourly143=preserve143()''')
    return s


def booker(name,s):
    # V48 has its own sealed directory and consumes only the V48 CLI option.
    s=s.replace("v47","v48").replace("V47","V48").replace("version = 47","version = 48")
    if name == "book141.py":
        s=one(s, "657c9965f71dbff5478308c1c6a703bb4732855c6ac3d4b6daaa4dfa67907f4f", ACTIVE)
        s=one(s,'and checked(ready["retained_143_phase"])["writer"] == ready["old_owner"]',
              'and checked(ready["retained_143_phase"])["writer"] == checked(checked(ready["old_owner"])["ready"])["old_owner"]')
    return s


def stage(old, staging, operator):
    book = old.name == "booking-price-v47"
    if not book and old.name != OLD:
        raise ValueError("expected deployed V47 package")
    raw=(old/"deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != (BOOKER if book else V47):
        raise ValueError("different V47 package")
    prior=json.loads(raw)
    members={}
    staging.mkdir(mode=0o700)
    def add(name,data,mode=0o444):
        if name.endswith(".py"):
            ast.parse(data,filename=name)
        path=staging/name
        path.write_bytes(data)
        path.chmod(mode)
        members[name]=dict(name=name,source=str(path),sha256=hashlib.sha256(data).hexdigest(),mode=mode)
    for r in prior["members"]:
        name=r["name"]
        path=old/name
        if path.parent != old or path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest()!=r["sha256"]:
            raise ValueError("changed V47 member " + name)
        if name != "SHA256SUMS":
            members[name]=dict(name=name,source=str(path),sha256=r["sha256"],mode=int(r["mode"],8))
    if operator["path"] != str(OPERATOR/"deployment-seal-receipt.json") or hashlib.sha256(Path(operator["path"]).read_bytes()).hexdigest() != operator["sha256"]:
        raise ValueError("different 169 provider")
    if book:
        for name in ("book141.py", "prepare143.py"):
            add(name,booker(name,(old/name).read_text()).encode())
        add("price_hourly143.py",hourly_price((old/"price_hourly143.py").read_text()).encode())
        add("successor_price.py",(HERE.parent/"horizon_epoch170_checkpoint_suffix/successor_price.py").read_bytes())
        add("split169_provider.json",json.dumps(operator,sort_keys=True).encode())
        add("split_status169.py",(HERE/"split_status169.py").read_bytes())
    else:
        add("status_cycle.py",cycle((old/"status_cycle.py").read_text()).encode())
        for name in ("full170_status.py", "cold170_status.py", "joint168_status.py"):
            value=(old/name).read_text()
            if f"'{OLD}')" not in value:
                raise ValueError("missing V47 receiver "+name)
            add(name,value.replace(f"'{OLD}')",f"'{OLD}', '{NEW}')").encode())
        add("split169_provider.json",json.dumps(operator,sort_keys=True).encode())
        peer_file = PEER / "deployment-seal-receipt.json"
        peer_reader = PEER / "status162.py"
        if hashlib.sha256(peer_file.read_bytes()).hexdigest() != PEER_SHA or hashlib.sha256(peer_reader.read_bytes()).hexdigest() != PEER_READER:
            raise ValueError("changed 162 operator")
        add("status162.py", peer_reader.read_bytes())
        add("split162_provider.json", json.dumps(dict(path=str(peer_file),sha256=PEER_SHA),sort_keys=True).encode())
        for name in ("split_status169.py","transition_v48.py"):
            add(name,(HERE/name).read_bytes())
        add("cutover48.py",cutover((old/"cutover47.py").read_text()).encode())
        add("watch143_versions.py",watcher((old/"watch143_versions.py").read_text()).encode())
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",
                destination=str(old.with_name("booking-price-v48" if book else NEW)),members=list(members.values()))


def hourly_price(s):
    needle='    j=core.price("start" if peer is None else "held",attempt=second.OLD,'
    s=one(s,needle,'''    import split_status169
    native = split_status169.reader()
    population = core.bound(dict(path=fleet,sha256=sha))
    admitted169 = native["current"](population)
    peer162 = split_status169.peer162()
    admitted162 = peer162["current"](population)
''' +needle)
    s=one(s,'hourly_replacement=held)','hourly_replacement=held, native169=admitted169, native162=admitted162)')
    needle='    if projection:\n'
    s=one(s,needle,'''    native["recheck"](population, admitted169)
    peer162["recheck"](population, admitted162)
    protected = [r["disk"] for r in (admitted169, admitted162) if r and r["phase"] != "terminal"]
    if admitted162 and admitted162["phase"] == "terminal":
        protected.append(dict(remaining=peer162["IMAGE"], fixed_control=peer162["CONTROL"], floor=0))
    if protected:
        controls = sum(d["fixed_control"] for d in protected)
        growth = sum(d["remaining"] for d in protected)
        floor = max(quote["retained_required_home_bytes"] + controls, *(d["floor"] for d in protected))
        required = floor + growth
        quote["retained_required_home_bytes"] = required
        quote["live_home_margin"] = quote["live_available_home_bytes"] - required - TREE - EVIDENCE
        quote["historical_home_margin"] -= growth + controls
        quote["home_margin_bytes"] = min(quote["live_home_margin"], quote["historical_home_margin"])
        quote["available_home_bytes"] = required + TREE + EVIDENCE + quote["home_margin_bytes"]
        quote["disk_fits"] = quote["disk_fits"] and quote["home_margin_bytes"] >= 0 and (not own or own["floor"] >= required)
        quote["private169"] = admitted169
        quote["private162"] = admitted162
''' +needle)
    return s


if __name__ == "__main__":
    cli=argparse.ArgumentParser(__doc__)
    cli.add_argument("previous",type=Path)
    cli.add_argument("staging",type=Path)
    cli.add_argument("operator_sha256")
    args=cli.parse_args()
    print(json.dumps(stage(args.previous,args.staging,dict(path=str(OPERATOR/"deployment-seal-receipt.json"),sha256=args.operator_sha256)),indent=2))
