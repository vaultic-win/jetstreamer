"""Compare the next private 162 native checkpoint record with its independent historical Bank."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

WITNESS = Path(
    "/home/sol/.jetstreamer-private/epoch162-v156-capped-shrink-20261127.v1/checkpoint-v1/TERMINAL_BANK_WITNESS.json"
)
UNIT = "horizon-qualify-162-first-hourly-completion-20261127-v2.service"
H = r"([1-9A-HJ-NP-Za-km-z]{32,44})"
BODY = re.compile(
    r"jetstreamer_node::historical_replay\] historical checkpoint slot=(\d+) bank_hash="
    + H
    + " accounts_hash="
    + H
    + " last_blockhash="
    + H
    + r" capitalization=(\d+) transactions=(\d+) tick_height=(\d+) complete=(true|false) writes=(\d+) next_write_version=(\d+)$"
)
TARGET = 69991076


def reference():
    b = WITNESS.read_bytes()
    if hashlib.sha256(b).hexdigest() != "6089633fc4f78a962c89a28fd738c076e1aa8621ec81f766c22a09b2c8a3d792":
        raise ValueError("different terminal witness")
    j = json.loads(b)
    bank = j["bank"]
    if bank["slot"] != TARGET or not bank["slot_complete"] or not bank["tick_height"] == bank["max_tick_height"]:
        raise ValueError("different frozen/complete Bank")
    return [
        str(TARGET),
        bank["bank_hash"],
        j["canonical_accounts_hash_from_snapshot_identity"],
        bank["last_blockhash"],
        str(bank["capitalization"]),
        str(bank["transaction_count"]),
        str(bank["tick_height"]),
        "true",
    ]


def compare(rows, iid, pid):
    if not (re.fullmatch("[0-9a-f]{32}", iid) and int(iid, 16) and str(pid).isdecimal() and int(pid) > 1):
        raise ValueError("invalid native identity")
    want = reference()
    observed = []
    extra = set()
    for row in rows:
        if (row.get("_SYSTEMD_INVOCATION_ID"), row.get("_SYSTEMD_UNIT"), row.get("_PID")) != (iid, UNIT, str(pid)):
            continue
        text = row.get("MESSAGE", "")
        if f"historical checkpoint slot={TARGET} " not in text:
            continue
        match = BODY.search(text)
        if not match or list(match.groups()[:8]) != want:
            raise ValueError("terminal Bank fields differ from historical snapshot")
        writes, nxt = map(int, match.groups()[8:])
        if nxt < writes:
            raise ValueError("invalid worker write cursor")
        extra.add((writes, nxt))
        observed.append([row["__CURSOR"], row["__REALTIME_TIMESTAMP"]])
    if not observed or len(extra) != 1:
        raise ValueError("missing or conflicting invocation-bound terminal checkpoint")
    writes, nxt = extra.pop()
    return dict(
        checkpoint=want,
        observed_writes=writes,
        observed_next_write_version=nxt,
        journal_positions=observed,
        source=str(WITNESS),
        ordered_full_stock_reference=False,
    )


def fixture():
    fields = reference()
    iid = "1" * 32
    pid = "10001"
    labels = [
        "slot",
        "bank_hash",
        "accounts_hash",
        "last_blockhash",
        "capitalization",
        "transactions",
        "tick_height",
        "complete",
        "writes",
        "next_write_version",
    ]
    message = "[fixture INFO jetstreamer_node::historical_replay] historical checkpoint " + " ".join(
        a + "=" + v for a, v in zip(labels, fields + ["1", "2"])
    )
    r = {
        "_SYSTEMD_INVOCATION_ID": iid,
        "_SYSTEMD_UNIT": UNIT,
        "_PID": pid,
        "__CURSOR": "fixture",
        "__REALTIME_TIMESTAMP": "1",
        "MESSAGE": message,
    }
    assert compare([r], iid, pid)["observed_next_write_version"] == 2
    wrong = [
        [],
        [dict(r, _SYSTEMD_INVOCATION_ID="2" * 32)],
        [dict(r, _PID="9")],
        [dict(r, _SYSTEMD_UNIT="other.service")],
        [dict(r, MESSAGE=message.replace(fields[1], fields[2]))],
        [dict(r, MESSAGE=message.replace("complete=true", "complete=false"))],
        [r, dict(r, MESSAGE=message.replace("next_write_version=2", "next_write_version=3"))],
    ]
    for trial in wrong:
        try:
            compare(trial, iid, pid)
        except ValueError:
            continue
        raise ValueError("negative fixture accepted")
    return dict(positive=1, negative=len(wrong), snapshot_hash=WITNESS.name, production_journal=False)


if __name__ == "__main__":
    if sys.argv[1:] == ["--fixture"]:
        print(json.dumps(fixture()))
        sys.exit()
    if len(sys.argv) != 3:
        sys.exit("usage: check-terminal.py EXPECTED_INVOCATION_ID SEALED_NODE_PID")
    iid, pid = sys.argv[1:]
    reference()
    if not re.fullmatch("[0-9a-f]{32}", iid) or not pid.isdecimal():
        sys.exit("invalid invocation/PID")
    data = subprocess.check_output(
        [
            "/usr/bin/journalctl",
            "--boot",
            "--quiet",
            "--no-pager",
            "-o",
            "json",
            "_SYSTEMD_INVOCATION_ID=" + iid,
            "_SYSTEMD_UNIT=" + UNIT,
            "_PID=" + pid,
            "--grep=historical checkpoint slot=69991076 ",
        ],
        text=True,
    )
    print(json.dumps(compare([json.loads(line) for line in data.splitlines()], iid, pid), indent=2))
