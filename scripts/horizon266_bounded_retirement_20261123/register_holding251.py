"""Bind the peer's actual completed transfer while preserving both holding reservations."""
from pathlib import Path
from register_holding250 import once

PACKAGE = Path("/var/lib/jetstreamer/horizon251-holding-readback-v219")
ORIGINAL = Path("/run/horizon251-private-holding-v205-a1")
IMPORT = f"sys.path.insert(0,{str(PACKAGE)!r})\nimport holding251"


def pricing(text):
    text = once(text, " import holding250\n", " import holding250\n " + IMPORT.replace("\n", "\n ") + "\n")
    text = once(text, "others=peer251.active();assert len(others)==1", "custody251,workers251=holding251.state()")
    text = once(text, ",next(iter(others)):('93fcaa47db5f4c7aba270738f598dc42',3391444,512*M,{41})", "")
    text = once(text, "  fixed.update(holding_workers)", "  fixed.update(workers251)\n  fixed.update(holding_workers)")
    text = once(text, "holding_samples.append(holding)", "holding_samples.append((holding,custody251))")
    return once(text, "holding250=holding_samples[0],", "holding250=holding_samples[0][0],holding251=holding_samples[0][1],")


def issuer(text):
    text = once(text, "from rotation_fit import issue", IMPORT + "\nfrom holding251 import issue")
    text = once(text, "here=Path(__file__).parent;phase=sys.argv[1];assert phase in ('park','verify')",
                f"here=Path({str(ORIGINAL)!r});phase=sys.argv[1];assert phase=='verify'")
    text = once(text, "all(41 not in os.sched_getaffinity(pid) for pid in (2774321,3375961))",
                "41 not in os.sched_getaffinity(2774321) and all(41 not in mask for _,_,_,mask in holding251.holding250.state()[1].values())")
    # Both park receipts and the original inodes were checked in the current fit.
    text = once(text, "cohort['park_with_part_readback']+cohort['independent_readback']", "cohort['independent_readback']")
    return once(text, "4*sum(sec.values())", "4*(sec['verify']+sec['refill'])")


def status(text):
    text = once(text, "import runpy\n", "import runpy\n" + IMPORT + "\n")
    return once(text, "elif n==250:\n   custody,workers=holding250.state()",
                "elif n in (250,251):\n   custody,workers=(holding250 if n==250 else holding251).state()")


def fleet(text):
    key = "custody250,workers250=holding250.state()"
    return once(text, key, IMPORT + """
custody251,workers251=holding251.state()
for item in custody251.values():
 if item:b.include(p['gates']['251'],Path(item['path']))
p['gates']['251']['next_action']=('Independent private readback completed; check local consumers and restore budget.' if custody251['complete'] else
 'Independent private readback is running; retain the local source.' if workers251 else 'Private transfer completed; run independent private readback.')
""" + key)
