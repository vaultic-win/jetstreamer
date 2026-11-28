"""Carry the 169 V55 forecast interface to the separately scoped second attempt."""
import hashlib
from pathlib import Path

SCOPE_SHA="322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e"
CLOSURE_SHA="24d2fc5ecf736827e0b06af6194f85ad1dae055f33065d6e9e20606eb17ee9dc"
FLEET_SHA="fce265c2b9b3911784089b2cb076a06e0c66a3127cf6ea899c3ddaa0b408a206"


def status(source):
    if hashlib.sha256(source.encode()).hexdigest()!="52f89f0bd9d82af514eb202b0e02ec41725421efb7a37e9076527b095766f6a2":
        raise ValueError("different first-attempt status interface")
    result=(source.replace("169-hourly-retry-20261128-v1","169-hourly-retry-20261128-v2")
            .replace("eb589f4c2c51dcf75314d50d7074a9411d034e6bd3f6a8bd826705ca4a1feb3a",SCOPE_SHA)
            .replace('FIELD = "current_private169_retry"', 'FIELD = "current_private169_retry2"')
            .replace('KEY = "private169_retry_start"', 'KEY = "private169_retry2_start"'))
    anchor='    receiver()["install"](fleet, row)'
    if result.count(anchor)!=1:
        raise ValueError("different fleet installation point")
    return result.replace(anchor, f'''    closed = checked({{"path":str(CONTROL.parent/"epoch169-hourly-retry-20261128-v1/UNRELEASED_HELD_CLOSURE.json"),"sha256":"{CLOSURE_SHA}"}})
    old = checked(closed["fleet"])["current_private169_retry"]
    need(closed["fleet"]["sha256"]=="{FLEET_SHA}" and old["phase"]=="terminal" and old["terminal"]==closed["terminal"]
         and old["invocation_id"]==closed["invocation_id"], "invalid first-attempt custody")
    fleet["current_private169_retry"] = old
'''+anchor)


def wire(source):
    old="row.get('unit', {}).get('Id') == 'horizon-qualify-169-hourly-retry-20261128-v1.service'"
    if source.count(old)!=1:
        raise ValueError("different private start binding")
    return source.replace(old,"row.get('unit', {}).get('Id') in ('horizon-qualify-169-hourly-retry-20261128-v1.service', 'horizon-qualify-169-hourly-retry-20261128-v2.service')")
