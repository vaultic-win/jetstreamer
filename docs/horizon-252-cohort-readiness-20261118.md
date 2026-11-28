# Epoch 252–256 cohort readiness

The source manifest requires one contiguous 252–256 replay, using bootstrap
slot 108863259 and the canonical final root in epoch 256. The failed singleton
preflight must not be retried as a replacement for this cohort.

The repaired production node is
`/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node`,
SHA-256 `2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32`.
Its source `1ae137f752f605463e52dad3055ab8cb161b64e2` is contained in
`origin/account-updates`. Existing native evidence covers all six repaired
253–255 CAR ranges and rejection of an incorrect override-manifest digest.

On 2026-11-18, the actual node rejected an incorrect cohort fingerprint in
`horizon-252-production-node-fingerprint-20261118-v1.service`, invocation
`390633c3a6634c01bab2e96ab3c4ca70`. An initial filename probe mistakenly requested
only epoch 252 and correctly failed the whole-cohort gate; that failure is
preserved. The corrected `252-256` invocation
`625a248d941d4a83ab84e484e885c80d` in
`horizon-252-production-node-cohort-filename-20261118-v2.service` acquired all
five epoch leases, accepted manifest fingerprint
`sha256:469f487447916aec81e8bb9ccac45ba886e297855a699e64fc9859f08c01ca3f`,
then rejected the deliberately incorrect snapshot filename before worker
initialization. These network-isolated probes each had a 1 GB memory cap,
100% CPU quota and 60-second bound. The corrected output contains only five
empty lease files; no replay or archive was produced.

The retained bootstrap is already present at
`/var/lib/jetstreamer/horizon-contiguous-252-256-current-46b4b4a-v1/`
`snapshot-108863259-7h1Ynk3rFxcF7GuUQ3vjxzSvXe8sykWqCkYYHLXFJ6nz.tar.zst`.
Its 14,208,032,327 bytes need no duplicate download. A fresh bounded hash in
`horizon-252-retained-bootstrap-hash-20261118-v1.service`, invocation
`549b924372864db4b56fa64d531cbbd2`, completed normally and matched the retained
custody digest `dc8095ef66ee9d5dea9b65a20923a2248bd56cf62759602180376978099cb390`.
The hash is local integrity evidence; it is not a new authenticated GCS readback.

All journals are retained under
`/home/ubuntu/.codex/diagnostics/horizon252-production-node-input-probes-20261118-v1`.
Worker bootstrap initialization, complete replay and fresh guarded admission
remain unproven. At the accepted 23:23:03 sample, the memory target was nine
lanes against five executing. Existing hard obligations leave only 9.64 GB
before the 7 GB epoch-205 audit, so a sixth 128 GB lane cannot use the existing
non-oversubscribed admission policy. Preserve healthy workers and their hard
limits; qualify pressure relief and candidate admission before launch. The
cohort's complete retained working set and inherited guard floors must also fit.

The alternative singleton epoch 265 also passed offline manifest preparation on
2026-11-19. Its sealed manifest is
`/var/lib/jetstreamer/horizon265-singleton-manifest-20261119-v1/preflight-265-singleton.json`,
fingerprint `sha256:a126bce31196effaf656230c7185e92f73db9574e13a45e3976aae1859461e28`.
The same actual production node accepted it and then rejected the deliberately
incorrect snapshot filename before initialization, in
`horizon-265-production-node-filename-20261119-v1.service`, invocation
`424280351c41494286db281771e6ce00`. The expected exit was 1; the 256 MB probe
terminated normally at that rejection with 102.9 MB peak memory. Evidence is
under `/home/ubuntu/.jetstreamer-private/qualification-265-source-20261119-v1`.

Its retained 16,483,458,670-byte bootstrap already exists at
`/var/lib/jetstreamer/horizon-contiguous-265-265-current-46b4b4a-v1/`
`snapshot-114479281-Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW.tar.zst`.
Recorded GCS generation is `1641500477962489`, CRC32C `+0CPhA==` and MD5
`Q0FEYKFkXAJiwZNXZtq6rQ==`. On November 19, the 256 MB bounded hash service
`horizon-265-retained-bootstrap-hash-20261119-v1.service`, invocation
`006af45b3f9847748103fdf6da73218e`, completed normally. The root-owned 0444
file's fresh SHA-256 matches sealed custody:
`04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641`.
The journal is `bootstrap-hash.jsonl` in the source evidence directory,
SHA-256 `d11bc8125e5d41d2fd33e37959a872f15bde05cd786bbd27958fccedf6098e59`.
This is local integrity evidence, not a new authenticated GCS metadata read.
The canonical final root is slot 114910768, hash
`HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK`, generation
`1641767242524970`. No duplicate download or epoch-265 replay was launched.
This shorter candidate remains subject to the same recovery and admission gates.
