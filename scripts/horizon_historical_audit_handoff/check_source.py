"""Exercise the offline acceptance and completion predicates using existing native receipts."""
import copy
import json
from pathlib import Path
import tempfile
import history
from unittest import mock


def rejected(fn):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("invalid evidence accepted")


a = history.tools()
scope, rows = history.identities(a)
assert set(rows) == set(range(101)) and not history.FINAL.exists()
d = a.read(history.OLD / "evidence/reader.json")
args = d["reader_argv"]
native = a.native(rows, 0, 100, args, history.OLD/"reports", history.OLD/"playback.log", 256)
history.compare(native)
for key in ("transactions", "account_data_bytes", "entries", "transaction_updates"):
    candidate = copy.deepcopy(native)
    candidate[100]["counters"][key] += 1
    rejected(lambda: history.compare(candidate))
candidate = copy.deepcopy(native)
candidate[0]["counters"]["stream_digest"][0] ^= 1
rejected(lambda: history.compare(candidate))
rejected(lambda: history.compare(native[:-1]))
assert history.outstanding(a) and not history.ready(a)
first = a.read(history.DATA/"scope.json")["eligible_ranges"]
with tempfile.TemporaryDirectory(dir="/home/sol/.jetstreamer-private") as name:
    folder=Path(name)
    (folder/"accepted").mkdir()
    (folder/"scope.json").write_bytes((history.DATA/"scope.json").read_bytes())
    for lo, hi in first:
        receipt = dict(schema="horizon-ready-range-verified-v1", range=[lo,hi], scope=a.ref(folder/"scope.json"),
                       exit=dict(success=True), method="strict-public-slot-ranges", epochs=[dict(epoch=i) for i in range(lo,hi+1)])
        (folder/"accepted"/f"{lo}-{hi}.json").write_text(json.dumps(receipt))
    with mock.patch.object(history, "DATA", folder), mock.patch.object(history, "FINAL", folder/"done.json"):
        assert history.ready(a)
        (folder/"done.json").write_text("{}")
        assert not history.ready(a)
        q=folder/"accepted"/"101-135.json"
        j=json.loads(q.read_text()); j["epochs"].pop(); q.write_text(json.dumps(j))
        rejected(lambda: history.outstanding(a))
print("101 native digests and counters, six invalid transcripts, genuine pending handoff, complete/incomplete/duplicate receipt controls passed.")
