"""Migrate the current Foundation consumers from epoch 250 park to verify."""
from pathlib import Path

PACKAGE = Path("/var/lib/jetstreamer/horizon250-holding-readback-v219")
ORIGINAL = Path("/run/horizon250-private-holding-v203-a1")
IMPORT = f"sys.path.insert(0,{str(PACKAGE)!r})\nimport holding250"


def once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def pricing(text):
    text = once(text, " import restore257", " import restore257\n " + IMPORT.replace("\n", "\n "))
    text = once(text, "old=partition.holding();others=", "holding,holding_workers=holding250.state();others=")
    text = once(text, "partition.park:('179e129e82aa4f4db14b97c80ac5bd63',3375961,512*M,{56}),", "")
    text = once(text, "  fixed.update(delivery.finite_owner())", "  fixed.update(holding_workers)\n  fixed.update(delivery.finite_owner())")
    # Bind the observed custody receipt to the fit, across all three samples.
    text = once(text, " anon_samples=[]", " holding_samples=[]\n anon_samples=[]")
    text = once(text, "  anon_samples.append(anonymous)", "  holding_samples.append(holding)\n  anon_samples.append(anonymous)")
    return once(text, " return dict(reservation257=", " assert all(s==holding_samples[0] for s in holding_samples)\n return dict(holding250=holding_samples[0],reservation257=")


def issuer(text):
    text = once(text, "from current_fit import issue", IMPORT + "\nfrom holding250 import issue, partition")
    text = once(text, "here=Path(__file__).parent;phase=sys.argv[1];assert phase in ('park','verify')",
                f"here=Path({str(ORIGINAL)!r});phase=sys.argv[1];assert phase=='verify'")
    text = once(text, " cap=issue(", " admission_lock=partition.take()\n cap=issue(")
    text = once(text, "set(x['epoch'] for x in fleet['active'])=={247}",
                "set(x['epoch'] for x in fleet['active'])=={247,248,249,265}")
    # The booking now claims the serial slot. Competing fits reject a booked
    # verify until its native worker is visible. funds.LOCK remains held to exit.
    return once(text, " args=['systemd-run'", " admission_lock.close()\n args=['systemd-run'")


def status(text):
    text = once(text, "import runpy", "import runpy\n" + IMPORT)
    return once(text, "  else:\n   queue+=20*3600", """  elif n==250:
   custody,workers=holding250.state()
   evidence.extend(r for r in custody.values() if r)
   queue+=20*3600
   step=('Independent private readback completed.' if custody['complete'] else
         'Independent private readback is running.' if workers else 'Independent private readback is pending.')
   basis='Private transfer completed and the original archive is retained. '+step+' The serial delivery forecast allows twenty hours after the preceding sidecar.'
  else:
   queue+=20*3600""")


def fleet(text):
    end = "for ep in range(292,296):\n for phase in ('plan','sections','capture'):"
    return once(text, end, IMPORT + """
custody250,workers250=holding250.state()
for item in custody250.values():
 if item:b.include(p['gates']['250'],Path(item['path']))
if custody250['complete']:
 p['gates']['250']['next_action']='Independent private readback completed. Check local consumers and the restore deadline before any local retirement.'
elif workers250:
 p['gates']['250']['next_action']='Independent private readback is running. Retain the original archive and reservation until it completes.'
""" + end)
