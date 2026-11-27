"""Project one bounded epoch 170 owner onto the single existing observer."""
from evidence import checked, need
import continuation170_native as following
import successor170_status as previous

FIELD = previous.FIELD
INTERFACE = following.INTERFACE
active = previous.active
project = previous.project
interface = following.interface


def retained_population(fleet, config):
    prior = fleet.get(FIELD)
    receiver = following if prior and prior["interface"] == following.INTERFACE else previous
    return receiver.retained_population(fleet, config)


def observe(c, prior, observed_lane):
    if prior and prior["interface"] == following.INTERFACE:
        previous.native.idle(previous.UNIT)
        return following.observe(c, prior, observed_lane)
    incumbent = previous.observe(c, prior, observed_lane)
    if not following.ACTOR.exists():
        following.native.idle(following.UNIT)
        need(not following.RELEASE.exists(),"second 170 release exists without an actor")
        return incumbent
    scope = interface()
    need(incumbent and incumbent["phase"] == "terminal" and incumbent["actor_ref"] == scope["old_actor"]
         and incumbent["release"] == scope["old_release"], "two bounded epoch 170 owners would overlap")
    result = following.observe(c, None, observed_lane)
    result["preceding_terminal_owner"] = incumbent
    return result


def recheck(row):
    if row and row["interface"] == following.INTERFACE:
        previous.native.idle(previous.UNIT)
        following.recheck(row)
    else:
        previous.recheck(row)
        following.native.idle(following.UNIT)


def install(fleet, row):
    if not row or row["interface"] == previous.INTERFACE:
        return previous.install(fleet,row)
    old = row.get("preceding_terminal_owner")
    # The fleet builder retains earlier receipts. Archive the old terminal view once.
    if old is not None:
        fleet["retained_170_first_bounded_terminal"] = old
    following.install(fleet,row)


def enroll(api, head, writer_ref):
    ready = checked(checked(writer_ref)["ready"])
    need(ready["successor170_interface"] == following.INTERFACE
         and ready["prior_successor170_interface"] == previous.INTERFACE,
         "writer has not adopted both bounded 170 routes")
    return following.enroll(api,head,writer_ref)
