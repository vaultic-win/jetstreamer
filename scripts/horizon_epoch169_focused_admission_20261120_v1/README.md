# Epoch 169 focused admission

Generation four uses `epoch169-focused-admission-20261120-v4` and `attempt-g4`.
Generation three restored slot 73,007,829 and exited on the CID index transfer.
The controller checks its admission, final guard sample, terminal receipt and
drained units. It binds the upstream comparison to the retained 4,322,853,290-byte
CID index by inode, size, mtime and ctime, checks the slot index files, and
projects the standard lane’s epoch 169 cache read-only at the node’s normal
path. The existing reservation includes that source tree. The held gate checks
the actual mount, and the payload rechecks the index before spawning the node.
A live 171 or 172 actor excludes this retry. Wait for the epoch 172 G3 closure
and a reconciled fleet before admission. Earlier generations and their receipts
are retained. The G3 floor contract is described in [FLOOR_RETRY.md](FLOOR_RETRY.md).

Build from a commit already in account-updates with Rust 1.98.0 inside the authorized serial slot. The standalone crate reuses the checked-in 168 physical allocation census, 172 native replay peer census, 166 resource accounting, exact-byte R2 audit and the existing 170 root guard. The node and v1.5.8 worker are separate sealed inputs.

    cargo test --locked --offline -j 1 --manifest-path scripts/horizon_epoch169_focused_admission_20261120_v1/Cargo.toml
    cargo clippy --locked --offline -j 1 --all-targets --manifest-path scripts/horizon_epoch169_focused_admission_20261120_v1/Cargo.toml -- -D warnings
    cargo build --locked --offline -j 1 --release --manifest-path scripts/horizon_epoch169_focused_admission_20261120_v1/Cargo.toml --message-format=json

Seal the compiled admit169, gate169, focused169 and artifact-proof.json in /var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-admission-20261120-v2/admission-v1. Create the outer runtime directory mode 0700 root:root on the existing home-backed mount. The controller supplies the guard plan, timer, host fits, private release barrier and immutable result records. The proof uses the existing 172 shape with source_commit, source_tree, observed_origin, source_contained_in_origin_account_updates, tests_passed, tests_failed and artifacts keyed by binary basename. Include node_seal_sha256=1f8f198a0fd613379281cb12c867d4de64ab7b4659522ff3947351bf0e9c04b7 and worker_seal_sha256=2fe7d2fb8ca707b4b122662622587a1d00bf6981781609a2989a7ac7f6f42e69. Bind each hash to its actual file and native Cargo build evidence. Fetch origin/account-updates as the repository owner immediately before the operation. The controller checks artifact hashes, Git commit ancestry, source tree, input seals and the continuing fleet sources.

Use the fully qualified installed admit169 with --preflight FLEET FLEET_SHA CONTROLLER_SEAL_SHA SOURCE_COMMIT. FLEET is the fresh complete reconciled fleet receipt. Once the current 172 producer/timer/guard have closed and the fresh host fit succeeds, the controlling operator can invoke the same arguments with --launch. The candidate's allocation caps are 68 GiB actor memory, 1 GiB guard, 3+1 CPUs, 96 GiB focused source tree and 3,500,000 worker VMAs. These reuse the existing 172/168 diagnostic concurrency model. The original 169 allocation retains its 288 GiB and 8 GiB guard commitments. Actual standard-root allocation plus the full focused cap must fit inside 288 GiB. The disk-fit model independently preserves the original admitted floors and budgets focused growth against actual available HOME. CPU fit includes the additive 13 CPU bound above the original 50.25, covering 168 and the candidate and guard. The shared admission lock and live native census refuse a concurrent 136 admission. A changed 166/167 owner requires its own identity review, and a stopped 170 requires the bound terminal evidence already understood by the native census.

The sealed node requires the exact destination /home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1/v158, its checkpoint, focused output name and scratch directory. The original 12:36 UTC attempt reached its guarded release and failed when the node found its archive batch receipts below this destination. Generation two uses the sibling attempt-g2/private for leases, work and receipts. Its stdout, staging receipt and temporary directory also reside below attempt-g2. The controller creates this generation exclusively, after verifying the SHA-bound first failure, drained units and original destination contents. The old private tree, log, inputs receipt, temporary directory, 142-byte checkpoint, existing staged snapshot and genesis have individual read-only service mounts. Staging verifies the 2,109,034,648-byte snapshot and 20,144-byte genesis in place. The exact original scratch directory must be empty and the focused archive absent. The old runtime, input files and records stay in place. Whole-lane protection includes both generations.

A held gate must be running with the correct PID and cgroup, zero capabilities, NoNewPrivs and exact immutable mount identities. The payload remains held until a genuine first timer-driven protective sample and second complete capacity fit succeed. The controller binds the current node identity and append log, requires the lease, runtime-selection and worker-selection records from its node, and records their bounded prefix hash before accepting the guarded admission. Actual terminal output, independent checkpoint verification and any translation into a full canonical epoch are later operations. No R2 publication is authorized. Classify only verified progress at the operator's normal observer cadence.

The controller intentionally uses one attempt per generation. A failed partially staged invocation retains its evidence. Inspect its actual owner, files and terminal receipts before a supervised recovery. Keep genuine source material such as the original checkpoint.


## Offline native path test

Build the focused169 Rust test harness in the serial test build. Pass its absolute path to native-path-test.sh. The test runs the sealed node with the payload’s actual argument and environment constructor in disposable mount and network namespaces. It replays the old receipt-location rejection, checks the corrected layout with a missing snapshot, then uses the retained real snapshot, genesis and checkpoint through read-only binds and stops at the deliberately missing worker executable. The command prints each genuine node exit. Actual bank initialization and replay require a separate guarded run.
