# Separately pinned capped 228 candidate

The existing v1.6.20 consensus path now has an exclusive
`epoch228-capped-qualification` feature. It requires the exact 98495291 snapshot,
accepts entries 98495292–98928278 and rejects foreign batches before decoding or
Bank mutation. It adds only the previously reviewed storage shrink-debt cap;
transaction execution, fees, native programs, PoH and account writes keep the
original runtime path. Combining it with 227,223 or singleton diagnostics is a
compile error. Existing deployed workers and their digests are untouched.

The rustc 1.51.0 release build passed 58 tests; three cold-snapshot tests remained
ignored. The new native test was compiled, not run. Its exact invocation is:

```text
epoch228_profile::tests::native_epoch228_cold_input_matches_canonical_accounts_commitment --exact --ignored --test-threads=1 --nocapture
```

The candidate worker is sealed at
`/var/lib/jetstreamer/horizon-228-capped-candidate-1bfa8d51-v1/jetstreamer-historical-worker-v1-6-20`,
SHA-256 `1bfa8d51d44729c75db7ffe5d466cec9d902216d9362a6efb129bf927ca85673`.
The optimized native test is sealed at
`/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test`,
SHA-256 `d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827`.
It reads the existing 98495291 cached snapshot and the existing mainnet genesis
from the 227 input package. It requires an empty, isolated
`native-input228-v1620-*` scratch root, rehashes the 10.5 GB snapshot, restores no
entries, freezes the bootstrap and requires the canonical accounts commitment,
zero writes, unchanged write cursor and unchanged last blockhash. It prints
raw consensus integers and hashes. No snapshot was downloaded or copied.

The dormant `epoch228-native-input-service.service` template proposes the same
112/128 GiB cold-input envelope, eight CPUs, no swap/restarts/network and45-minute
ceiling as the qualified neighboring native attempts. Before it can be used,
the coordinator must add the exact 228 native profile to its registry/status/
observer/admission accounting and deploy a separately pinned MainPID/executable/
VMA guard. Fresh complete-fleet admission and a first real successful guard fire
remain required. Neither file sealing nor synthetic tests establish native
input qualification or authorize starting a service.

`epoch228_extract` is a correctness core for the resulting432279-slot focused
artifact. It pins the new worker digest, original runtime revision/genesis,
exact bootstrap and canonical terminal account commitments, authenticates the
source segment manifest and uses the existing complete source SHA/deep decode
validator. It preserves an immutable source handle across extraction.

Its private-prefix transform reuses `reencode_archive_prefix`, checks strict
stored PoH-parent links, preserves event order/raw write versions/bootstrap/
worker provenance, and narrows only requested output/epoch metadata to 432000
slots. A separately admitted controller supplies a required live budget guard;
the sink additionally enforces at most 160 GiB. The output is independently
decoded and matched against the re-encoder's expected semantic digest before
no-clobber publication into a private 228 extraction directory.

The core is not an armed executor. The coordinator still needs a reviewed
wrapper binding the actual completed producer, fresh allocation admission,
source/manifest hashes, budget guard and durable returned evidence. It must
retain the complete279-slot checkpoint-bearing source. No terminal segment
manifest is fabricated at 98927999: that cut's Bank summary was not observed.
The extraction evidence instead binds the real canonical checkpoint 98928278
in the retained source. It writes no checksum and grants no plugin, publication,
runtime-promotion or retirement authority. Independent final full/current-plugin
checks and an accepted publication adapter remain required before a sidecar.

This makes native input qualification the next actionable stage without
replaying all of 229. Full 228 execution stays gated until that native result,
resource admission, guard/status registration and the extraction executor/
publication adapters are qualified. Epoch 301 is unrelated and remains private.

The dormant service and profile are sealed for review at
`/var/lib/jetstreamer/horizon-228-native-service-review-v1/`. The service member is
`horizon-native-input-228-capped-1bfa8d51-v1.service`; its SHA-256 is
`fc3b66018c738add46654264e1ecd6d297d3bcee0a16e79e3defe0f185458b92`.
The proposed guard tuple is that unit, the exact native executable/digest above,
`/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1`,300000000000
maximum physical bytes and 3500000VMAs, plus the actual admitted IID/MainPID.
There is no installed or started 228unit.

The extraction core additionally supports an interrupted-receipt retry: an
existing frozen candidate is never replaced. It derives expected output
semantics into a null sink, then verifies the existing file's complete coverage,
exact narrowed provenance, strict links, semantic digest and unchanged identity
before returning evidence. A conflict fails closed. The future controller must
still provide a single-owner lease and persist its intent/completion records.
Its distinct admission must account for the output copy while retaining the
complete checkpoint-bearing source; completed replay scratch may be retired
only through its separately qualified lifecycle.

Validation:58 historical-worker tests passed, 3 cold tests ignored; 3 extraction
core tests passed, including the real432279→432000-slot width; 4 existing shared
prefix-codec tests passed, covering cut-inside-bucket events, raw write versions,
metadata, strict anchors and provenance rejection. Node-library clippy passed
with warnings denied. Native 228has not been restored, entries have not run, no
real focused artifact has been extracted, and no public sidecar is authorized.
