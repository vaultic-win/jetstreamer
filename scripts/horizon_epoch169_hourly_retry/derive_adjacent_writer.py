"""Derive fixed, generation-bound 169 members for the common writer's next normal transition."""
import ast
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adjacent_inputs as a

INTERFACE = dict(path=str(a.BASE/"INTERFACE.json"),sha256="9bd834876a560f4e90dc9623d019acfbf49d1cdaf3edba09fb6da69784152226")
TEMPLATE = a.RT/"survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v68-entry146/third162_progress.py"
one = a.shared.exact


def members(interface=INTERFACE):
    a.need(interface == INTERFACE,"different 169 interface")
    packet = a.bind(interface)
    seal = a.bind(packet["provider"])
    refs = dict(INTERFACE=interface,SCOPE=packet["scope"],OPERATOR=packet["provider"],READER=packet["reader"],
                PREVIOUS=packet["previous"],PREVIOUS_HELD=packet["previous_held"])
    a.need(packet["reader"]["path"] == str(a.BASE/"operator-v1/status169.py") and packet["unit"] == a.UNIT
           and packet["field"] == a.FIELD and packet["previous"] == dict(path=str(a.PREVIOUS),sha256=a.OLD_SHA)
           and packet["previous_held"] == a.OLD_HELD and a.bind(packet["scope"])["unit"] == a.UNIT
           and seal["destination"] == str(a.BASE/"operator-v1") and any(v["name"] == "status169.py"
             and v["sha256"] == packet["reader"]["sha256"] for v in seal["members"]),"different operator or reader")
    reader = Path(packet["reader"]["path"]).read_bytes()
    a.need(hashlib.sha256(reader).hexdigest() == packet["reader"]["sha256"],"different reader bytes")
    text = TEMPLATE.read_text()
    a.need(hashlib.sha256(text.encode()).hexdigest() == "44ddccee5cd6c6efafc7596d8518d94da142f430a2bcffdb772cc1e17604e782","different progress provider")
    text = text.replace("horizon-qualify-162-third-replay-20261128-v1.service",a.UNIT)
    text = text.replace("epoch162-third-replay-20261128-v1",a.BASE.name)
    text = one(text,"69_998_120 <= slot <= 70_004_937","73_245_219 <= slot <= 73_252_243")
    text = one(text,"a954d3035ecc6c450c97212ec4a27f6676440c6c23a6bf579d0cc07a949c0ff9",a.GUARD_SHA)
    # initial162 is the accepted common evidence reader. Retain that import.
    text = text.replace("private162_journal","private169_journal").replace('== 162','== 169').replace('"162"','"169"').replace(" 162 ", " 169 ")
    result = {"adjacent169_progress.py":text.encode(),"adjacent169_bindings.py":"".join(f"{k} = {v!r}\n" for k,v in refs.items()).encode(),
              "adjacent169_route.py":(HERE/"adjacent_writer.py").read_bytes(),"adjacent169_status.py":reader,
              "adjacent169_provider.json":(json.dumps(packet["provider"],sort_keys=True)+"\n").encode()}
    for name,body in result.items():
        if name.endswith(".py"):
            compile(body,name,"exec")
    return result


def cycle(source,version):
    """The common publisher owns version selection, packaging, lock transfer and activation."""
    a.need(type(version) is int and version >= 70,"unexpected writer registration version")
    line, = [v for v in source.splitlines() if v.strip() == "import fourth169_status as retry169_status"]
    indent = line[:len(line)-len(line.lstrip())]
    source = one(source,line,line+"\n"+indent+"fourth169_prior = retry169_status\n"+indent+f"if FAILED166_VERSION >= {version}:\n"
                 +indent+"    import adjacent169_route as retry169_status")
    guard = f"FAILED166_VERSION >= {version}"
    source = one(source,"c.retry169['phase'] != 'terminal' or old.get('private169_retry_terminal') != c.retry169['terminal']",
                 f"retry169_status.needs_forecast(c.retry169,old) if {guard} else c.retry169['phase'] != 'terminal' or old.get('private169_retry_terminal') != c.retry169['terminal']")
    source = one(source,"extra.update(retry169_status.receiver()['status_fields'](c.retry169))",
                 f"extra.update(retry169_status.fields(c.fleet,c.retry169) if {guard} else retry169_status.receiver()['status_fields'](c.retry169))")
    for before, after in (("retry169_status.receiver()['project'](c, c.retry169)","retry169_status.project(c,c.retry169)"),
                          ("cap[retry169_status.FIELD] = c.retry169","retry169_status.save(cap,c.fleet,c.retry169)"),
                          ("retry169_status.install(fleet, c.retry169)","retry169_status.install(fleet,c.fleet,c.retry169)")):
        line, = [v for v in source.splitlines() if v.strip() == before]
        pad = line[:len(line)-len(line.lstrip())]
        source = one(source,line,pad+f"if {guard}:\n"+pad+"    "+after+"\n"+pad+"else:\n"+pad+"    "+before)
    line, = [v for v in source.splitlines() if "modules += [transition_v55, retry169_status]" in v]
    pad = line[:len(line)-len(line.lstrip())]
    source = one(source,line,line.replace("retry169_status]","fourth169_prior if "+guard+" else retry169_status]")+"\n"
                 +pad+f"if {guard}:\n"+pad+"    modules += [retry169_status,retry169_status.live,retry169_status.progress,retry169_status.refs]")
    ast.parse(source)
    return source


def wire(source):
    # Our status provider's terminal is a PID1 journal object, as for split 162. Carry
    # the same invocation's most recent measured bytes until event-driven custody.
    return one(source,"elif closed and epoch == 169:","elif closed and epoch == 169 and row['unit']['Id'] != "+repr(a.UNIT)+":")
