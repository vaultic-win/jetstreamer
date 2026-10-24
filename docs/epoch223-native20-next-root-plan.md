# Epoch223 after successful native20 warmup

The actual bounded invocation `58ab3d9221a6452685b8eab3ceabdb49` completed with
manager success/0 and cooperative target96335554. Its immutable terminal proof
is `/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/proof.json`,
SHA256 `6790592b9188e7c4a3d32171a326b743f84fc6c5b5ad07f94182c104876b7028`.
The saved resource result SHA256 is
`4040a077d90eca93e0208485a86131b1541564527acc4ab9de746292e32504d3`.
This proves the original native25 fee/load failure can be passed using the exact
native20 warmup. It does not qualify the remaining prefix or a completed epoch.

## Smallest next execution

Reuse the existing sealed parent99f643ff and **long prefix** worker a651b7a6
from `/var/lib/jetstreamer/horizon-223-v1620-long-prefix-80202938-v1`.
Do not reuse the first16 worker52d6c86a for the full prefix or widen that binary.
The long worker already uses the reviewed capped-shrink policy. No runtime,
transaction loading, fee, checkpoint or Bank algorithm change is needed.

Source `1eb580cc` strengthens the separate
`jetstreamer-epoch223-v1620-root-prefix-resource` supervisor. Its no-worker
planning and actual execution now require both the exact successful warmup
proof and independently qualified native cold-input proof. It uses an isolated
`qualification-223-v1620-prefix-full-root-*` namespace. The actual run must
finish naturally; it never receives the bounded warmup's target SIGINT.

The work scope remains cold bootstrap96335538, entries96335539..96767522,
recorded slots96336000..96767522 inclusive: **431,523 slots**, leaving477 tail
slots uncovered. Both independently known canonical roots remain mandatory:

| Point | Slot | Accounts hash | Bank hash |
|---|---:|---|---|
| Cold bootstrap | 96335538 | `Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE` | `8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F` |
| Known terminal | 96767522 | `3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7` | `EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB` |

Prepare a new immutable actual plan and separate capability plan for that exact
supervisor. The plan keeps node99f643ff, full workera651b7a6, snapshot SHA256
`301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665`, and
epoch-hashes SHA256
`9ce886d556f70e84386dbf1b2c4abc4b4fb7ea57064b903e50ff6b34479a0c15`.
Create root/scratch/output/receipts/**ledger**, uid1000, mode0700, in both new
namespaces before a capability invocation. The no-worker invocation uses
`--storage-capability`; it must traverse the actual parent's pre-worker barrier
and emit the new prerequisite bindings without restoring a Bank or replaying an
entry. Compilation is not that capability proof.

The proposed production envelope is225,000,000,000-byte MemoryMax,
150,000,000,000-byte MemoryHigh, swap0, CPU800%, two Rayon threads, Tasks512,
and a72-hour hard execution bound. Kernel limits must equal host-page-floor
values while systemd requested strings remain exactly the sealed requested
values. Preserve those layers separately. The supervisor enforces a2-TB
filesystem floor and480-GiB available-memory reserve every15seconds as a safety
guard, not a new routine campaign observer. Starting memory must also cover the
candidate's entire225-GB cap.

Scratch300 GB is planning evidence, not a measured full-prefix peak. Reserve an
additional160 GiB for output and overhead: whole-root471,798,691,840 bytes.
Starting free disk therefore must be at least2,471,798,691,840 bytes even before
fresh complete-fleet arithmetic raises that requirement. The supervisor checks
that conservative start threshold; a favorable target-only warmup capture is
not permission to lower it. Root owns fresh admission, including any newly live
full209 owner, both bracketing censuses, existing producer guards and century
floor. Seal an invocation-bound whole-root/VMA guard before accepting the new
owner into fleet/status publication. **The existing native25 prefix223 fleet
adapter does not accept this new owner. A separate exact native20
admission/capture/observer/status adapter remains a required next gate.**

## Qualification and delivery gates

1. After natural success/0, preserve `receipts/root-prefix.json`, the private
   `.jet`, producer `.segment.json`, original launch, exact journal and guard
   evidence. That producer receipt remains non-authorizing.
2. Run the existing independent `jetstreamer-qualification-verify` native20
   known-root prefix rereader against the new private root. Bind full
   workera651b7a6, runtime `solana-v1.6.20`, revision
   `77bdb45d4af61fc687161ec06cc0178ff79726d5`, the431,523-slot span, both known
   accounts/Bank hashes and source archive digest. Its namespace-specific
   validation deliberately rejects the first16 worker and native25 substitutes.
3. Independently qualify the native restart at96767522. Its canonical account
   equality, required hard-fork markers, exact write cursor and runtime handoff
   cannot be inferred from a prefix's terminal hash or from a successful tail
   comparison. Keep the separately sealed native25 suffix comparison isolated;
   its earlier success cannot qualify the native20 prefix retroactively.
   First capture the existing native25 input evidence as described in
   `epoch223-tail-exact-evidence.md`; do not restore another Bank merely to
   format that historical receipt. The raw producer journal and sealed segment
   preserve the exact initialized/bootstrap cursor and full consensus tuple;
   the older terminal summary rounded both capitalization integers and is
   explicitly nonauthoritative for those values. Require the future native20
   independently reread terminal consensus tuple to equal this native25 input
   tuple before qualifying a handoff. Raw write cursors are local to separately
   restored validators, so prefix and suffix cursor equality is not a handoff
   condition; prove their separate contiguous emitted ranges and checked
   normalization instead. The dormant native25 restart-test candidate remains
   a contingency for a genuinely missing obligation, not required extra replay.
4. Qualify the477-slot suffix96767523..96767999 and an explicit cursor/event
   mapping. Assemble only with proven ordered, non-overlapping coverage of all
   432,000 epoch slots and all existing cross-runtime boundary requirements.
   Until this exists, prefix and suffix stay private segments without canonical
   sidecars. No unimplemented assembler or unsupported resume path is implied.
5. Independently full-verify the assembled archive, run the current plugin
   checks, and retain both adjacent boundary receipts for eventual local
   retirement. Only then pass the archive through the normal Rust uploader:
   full upload, whole-object readback, source revalidation, sidecar creation,
   sidecar readback and durable pair receipt. Delete its status only after that
   readiness marker commits. Keep the223 repair open until this verified pair.

## Terminal warmup scratch: eligibility and conservative reclaim estimate

The saved target capture records32,879,235,072 physical scratch bytes
(32.88 GB,30.62 GiB), of which30,313,709,568 bytes are accounts-state. These
are target-time measurements, **not current reclaimable bytes**. The parent and
worker use `TempDir` state and may already have removed much of it during their
clean drain. Current reclaim can therefore be zero. No fresh resource poll was
used to make this estimate.

The16 executed slots end before epoch223 recording begins at96336000. No
canonical prefix, native checkpoint or supported resumable worker state was
qualified. Full prefix execution uses a fresh namespace and independently
sealed cold snapshot; it cannot resume from the warmup's private Bank files.
Preserve every output file, receipt, journal, source snapshot and long worker.

Source `2a52215c` provides a narrowly scoped Rust path:

```
jetstreamer-r2 retire-warmup223-scratch SPEC \
  --spec-sha256 SPEC_SHA --self-sha256 HELPER_SHA
```

The sealed spec schema is
`jetstreamer-warmup223-58ab-scratch-retirement-spec-v1`, with `mode` set to
`check-only` or `retire`, exact `scratch` beneath the58ab v2 root, and fixed
receipt directory
`/var/lib/jetstreamer/horizon-warmup223-58ab-scratch-retirement-v1`.
It binds the actual terminal proof/resource, checks current terminal owner and
unchanged PID1 history, rejects pending jobs, requires its guard and timer
inactive, rehashes the retained cold source, and rejects any archive, sidecar,
snapshot or checkpoint anywhere in scratch. It reuses the reviewed no-mount,
same-device, uid1000, no-hardlink/special-file tree census and complete streaming
command/maps/cwd/root/exe/fd reference scan. Incomplete reads or references fail
closed. Check-only returns actual eligible tree bytes with a private receipt.

Retirement requires a separate sealed `retire` spec. It persists a no-clobber
intent, repeats gates and tree identity, removes only scratch contents and
fsyncs the retained empty directory before writing completion. Interrupted
retirement can resume only under its exact original intent and unchanged root
identity; a completed retry must still prove absence and matching completion.
The root directory, output, receipts and ledger are never deletion targets.
The helper neither contacts R2 nor offloads to any host prefix. Neither the
check nor retirement has been executed by this repair agent.
