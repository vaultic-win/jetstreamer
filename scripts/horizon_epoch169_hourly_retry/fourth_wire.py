"""Extend the V58 writer's epoch 169 receiver to the fourth disjoint private gate."""
import hashlib


SCOPE = "f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5"
PARENT = "7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf"
CLOSURE = "438f68aca277600ec8ecbf9eea5c651a02f8962b4d0b5cde94db00743f358b4b"


def status(source):
    if hashlib.sha256(source.encode()).hexdigest() != "f0534898b9e656db5178d84e42825b273c2a1e29f19ac29627db36cd5b896c36":
        raise ValueError("unexpected V58 third 169 receiver")
    text = source.replace("169-hourly-retry-20261128-v3", "169-hourly-retry-20261128-v4")
    text = text.replace(PARENT, SCOPE).replace("private169_retry3", "private169_retry4")
    marker = '    receiver()["install"](fleet, row)'
    if text.count(marker) != 1:
        raise ValueError("third receiver install changed")
    return text.replace(marker, f'''    third, closure = receiver()["observe"].closed_parent(fleet)
    need(closure == checked(SCOPE)["third_unreleased"] and closure["sha256"] == "{CLOSURE}",
         "changed third 169 custody at fourth install")
    fleet["current_private169_retry3"] = third
''' + marker)


def wire(source):
    if hashlib.sha256(source.encode()).hexdigest() != "f2fb29c4db75829c3a885482522896dba6a68dff9988aed517d31926670a7892":
        raise ValueError("unexpected V58 split wire")
    old = "'horizon-qualify-169-hourly-retry-20261128-v3.service')"
    if source.count(old) != 1:
        raise ValueError("third split wire census changed")
    return source.replace(old, old[:-1] + ", 'horizon-qualify-169-hourly-retry-20261128-v4.service')")
