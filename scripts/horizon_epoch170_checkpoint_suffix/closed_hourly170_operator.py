"""Use the established closed reader with its retained, exclusive funding."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import runpy
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import closed_hourly170_funding as funding
from following_prepare import git, need, reference

DRIVER = Path("/home/sol/.jetstreamer-private/epoch170-guarded-gap-20261128.cx1SXtA5/build/after170-hourly-closed.py")
DRIVER_SHA = "14112c30d8dcfb1289c78beeb35627646ef196090a85d2418bbad7bbb2adbaa5"
LOCK = "/run/horizon-epoch171-to136-g1.operation.lock"


def one(raw, old, new):
    need(raw.count(old) == 1, "different existing closed reader")
    return raw.replace(old, new, 1)


def driver(allow_exchange):
    source = reference(DRIVER)
    need(source["sha256"] == DRIVER_SHA and DRIVER.resolve(strict=True) == DRIVER,
         "different existing closed reader source")
    raw = DRIVER.read_text()
    need(reference(DRIVER) == source, "existing closed reader changed during read")
    repo = HERE.parents[1]
    version = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "merge-base", "--is-ancestor", version, "origin/account-updates")
    tracked = {}
    for path in (Path(__file__).resolve(), HERE / "closed_hourly170_funding.py", HERE / "following_prepare.py"):
        need(git(repo, "show", f"{version}:{path.relative_to(repo)}") == path.read_bytes(),
             "unpublished closed reader source " + path.name)
        tracked[path.name] = reference(path)

    def bound_quote(full, package, terminal):
        return dict(funding.quote(full, package, terminal), revision=version, driver=source, sources=tracked)

    raw = one(raw, '    need(full["fits"] and min(full["home_margin"],full["ram_margin"])>=0 and full["package"]==provider',
              '    private=bound_quote(full,provider,end)\n'
              '    need(private["fits"] and (private["nominal"] or allow_exchange) and full["package"]==provider')
    raw = one(raw, 'dict(whole=full,provider=provider,terminal=end,reader=package,',
              'dict(whole=full,provider=provider,terminal=end,reader=package,private_funding=private,')
    module = dict(__name__="independent_hourly170_close", __file__=str(DRIVER),
                  bound_quote=bound_quote, allow_exchange=allow_exchange)
    exec(compile(raw, str(DRIVER), "exec"), module)
    return module


def check(module):
    with open(LOCK, "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        terminal = module["terminal"]()
        issuer = runpy.run_path(str(module["c"]["OP"] / "after_ram170_issuer.py"))
        latest, provider = issuer["latest_hourly_provider"]()
        full = runpy.run_path(str(latest / "capacity.py"))["whole_roster"]()
        result = module["bound_quote"](full, provider, terminal)
        receipt = module["save"](module["root"] / f"HOURLY_CLOSED_READER_QUOTE_{time.time_ns()}.json",
                                 dict(whole=full, private_funding=result, terminal=terminal))
        return dict(receipt=receipt, **result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("quote", "nominal-close", "funded-close"))
    args = parser.parse_args()
    os.umask(0o077)
    operator = driver(allow_exchange=args.phase == "funded-close")
    if args.phase == "quote":
        print(json.dumps(check(operator)), flush=True)
    else:
        print(json.dumps(dict(closed=operator["close"]())), flush=True)
        print(json.dumps(dict(drained=operator["drain"]())), flush=True)
