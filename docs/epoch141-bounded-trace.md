# Epoch 141 bounded trace on dev-samjohnson

The distinct trace generation ran from 2026-10-23 11:39:51 to 11:49:57 UTC,
invocation `59a11599b72644f1a6098974a7301c2e`. It reproduced the original
execution mismatch at slot 60912005, entry 388, transaction 378, with vote
instruction `Custom(2)` / `SlotHashMismatch`.

The trace provides the missing concrete Bank evidence: at slot 60912005 the
parent Bank and SlotHashes entry for 60912004 contain
`5TAhovjU9KPhDWsb7Aqugeh2RaACSNkwp7aPMxxe4AGf`, while the vote expects
`GtE6AijvzVgK1UKQ5HyVEZMGisDddVWRQkBnM74sjABf`. The original-entry adapter
had already validated slot 60912004's 188 transactions, 507 original entries,
five PoH boundaries and four million PoH hashes. The vote's Bank hash and the
source's final PoH hash are different concepts. Recovering the original source
entries alone has not corrected the Bank state across this epoch boundary.
Next diagnosis should compare the freeze/epoch-transition Bank inputs and
derived state; another identical replay without a new diagnostic or repair
would add no evidence.

The trace used the existing sealed parent and v1.4.25 worker, adding only
`JETSTREAMER_HISTORICAL_TRACE=1`. Its separate root is
`/home/sol/.jetstreamer-private/epoch141-original-entry-trace-20261023-v1`.
The failed original root was preserved. Admission protected all five production
owners and their remaining-growth claims, the authenticated century floor,
128 GiB scheduling memory plus 64 GiB host reserve, and a 256 GiB whole-root
physical stop. Hard limits remained CPU 200%, MemoryHigh 128 GiB,
MemoryMax 192 GiB, no swap, 512 tasks, and a 1,800-second runtime bound.
The physical budget covers scratch and output; it is an experimental stop,
not an adopted full-epoch resource estimate. No archive publication or runtime
promotion was authorized.

The sealed guard passed a manual observation and an actual timer-generated
one-worker observation. The launch capture pinned the exact timer invocation,
typed D-Bus clocks, producer identity, environment and guard bytes. On the
updated systemd, `systemctl show` omits empty `EnvironmentFiles`; the capture
now requires the actual D-Bus `a(sb) 0` result rather than treating absence as
proof. Guard samples are durably written with mode 0600; the selected completed
sample was made read-only before its no-clobber private pin. After confirmed
producer failure the trace guard timer was stopped, with all evidence retained.

The normal 11:43 cycle was cancelled during reader qualification. Exactly one
replacement coordinated observation ran at 11:56, retaining the original
11:13:57 predecessor. The trace's admission and launch clocks were preserved.
The qualified coordinator permits a 30–60 minute successor interval only for
this first coordinated trace adoption bound to its exact prelaunch predecessor;
later routine cycles return to 1,800 seconds. Its retained 144 diagnostic
validators now allow the separately authenticated 141 owner without dropping
or weakening the 144 claim. The 11:56 fleet records the trace as terminal and
keeps epoch 141 in `failed-needs-repair`; 59 ready pairs, 41 missing epochs,
zero anomalies and all 11 production status publications were retained.

Key private evidence:

- Admission: `/var/lib/jetstreamer/horizon-original141-trace-admission-20261023-v1/admission.json`, SHA-256 `64a105e4d02b64fd547d8c945c2446b7f607f938e9432ec19e0d8bcdabcbcf95`.
- Launch: the trace root's `receipts/launch.json`, SHA-256 `4dc804fb9836d25f3465b8b75dfe83fbbbfa4d48900c7d722ad02cb53eff10fc`.
- Fleet: `/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261023T115600Z.json`, SHA-256 `cfecd738cb1bca18cc8e14123408e4889cc192bb8fdc2918ec512d1326c43ccc`.
- Retained complete journal source: `.ops-horizon-trace141-20261023-v1/trace-journal.jsonl`, SHA-256 `44eaf42bfb7469bf9e78fd7365b045182da516b188f76dce97160f80d4b992a1`.

The 11:56 capacity receipt correctly records five production lanes and zero
private lanes, but its next-action text incorrectly treats the retained 141
profile as expanded live work. The subsequent fix selects that gate from actual
live invocations, including live fleet owners whose optional RSS observation
is unavailable. The original receipt is preserved; its text is not evidence of
a sixth live lane or a proven expanded operating point.
