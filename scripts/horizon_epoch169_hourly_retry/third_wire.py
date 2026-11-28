"""Extend the existing second-attempt forecast to its guarded successor."""
import hashlib

SCOPE="7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf"
STOP="c09b0bf82efe4c970a0810219bdccb03a1869333a30cd1fef39e9034dfc40e02"


def status(source):
    if hashlib.sha256(source.encode()).hexdigest()!="4aa7334ae809518bd6819e42f44d4cf7a5c9080117e333b2ab4a5498c30ff32b":
        raise ValueError("different second-attempt status interface")
    code=(source.replace("169-hourly-retry-20261128-v2","169-hourly-retry-20261128-v3")
          .replace("322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e",SCOPE)
          .replace('FIELD = "current_private169_retry2"', 'FIELD = "current_private169_retry3"')
          .replace('KEY = "private169_retry2_start"', 'KEY = "private169_retry3_start"'))
    anchor='    receiver()["install"](fleet, row)'
    if code.count(anchor)!=1:
        raise ValueError("different fleet install")
    return code.replace(anchor,f'''    ref = {{"path":str(CONTROL.parent/"epoch169-hourly-retry-20261128-v2/WORKER_ALIAS_STOP.json"),"sha256":"{STOP}"}}
    prior = checked(ref)
    end = checked(prior["terminal"])
    need(end["invocation_id"] == prior["invocation_id"] == "1446633fdd224bab9297255a7ad66330"
         and end["grant_sha256"] == prior["grant"]["sha256"] and end["archive"] is None
         and not end["private_span"] and not end["canonical_publication_authorized"], "different second 169 result")
    stopped = fleet.get("current_private169_retry2")
    if stopped is None:
        stopped = dict(epoch=169, phase="terminal", unit=prior["states"][end["unit"]], invocation_id=prior["invocation_id"],
                       held=prior["held"], terminal=prior["terminal"], canonical_replay_claimed=False,
                       archive_publication_authorized=False, resource_credit_bytes=0)
    need(stopped["phase"]=="terminal" and stopped["invocation_id"]==prior["invocation_id"]
         and stopped["held"]==prior["held"] and stopped["terminal"]==prior["terminal"],"different second fleet row")
    fleet["current_private169_retry2"] = stopped
'''+anchor)


def wire(source):
    if hashlib.sha256(source.encode()).hexdigest()!="f6198b443f1665de768b1e3f3087eb325658f13ecd72823ead3aa9d4d1e9d1ae":
        raise ValueError("different V56 split wire")
    old="'horizon-qualify-169-hourly-retry-20261128-v2.service')"
    if source.count(old)!=1:
        raise ValueError("different split wire start")
    return source.replace(old,"'horizon-qualify-169-hourly-retry-20261128-v2.service', 'horizon-qualify-169-hourly-retry-20261128-v3.service')")
