# Shared R2 source integration (not operational authority)

This carrier starts at the frozen epoch233 adapter source 4b44bf93 (which includes
069bdebf as its exact cherry-pick) and adds real capped admission brackets from
fa4785ee. Capped admission recomputes full before/after/worst-growth disk floors
and full before/after/worst-auxiliary memory policies, reserves all maxima and
requires minima across accepted observation, both brackets and post-mirror reads.
Exact raw owner/cap equality, protected floor, native223/canary accounting,
complete path, immutable source and freshness gates remain. Positive receipts
bind every bracket and policy; late and post-mirror rejection has private durable
negative diagnostics. Legacy monotonicity is recorded without governing admission.

Reviewed R2-only functionality is imported from 49435645: capped204_v4_admission,
maintenance_capacity/capped204_native223, the closed Capped204V4 mode, strict
terminal-manager/empty-cgroup wrappers and admit-capped204-v4-delivery dispatch.
No historical node, worker, Cargo/lock/vendor changes or reversions to thread
profiles, new-admission checks or the known singleton209 const assertion are
imported from that older carrier. Existing209/210 dispatch and policies stay intact.

The shared terminal API is
maintenance_capacity::capped204_native223::prove_terminal(f) -> Result<Value>.
Its visibility is exposed to the maintenance subtree; its original manager,
empty-cgroup, process-reference, pending-job/trigger, no-replacement and repair
ledger protections are unchanged. No terminal implementation was duplicated.
The separately owned233 memory-policy successor can consume it and add a strict
pure saved-proof validator here; it must keep the live480GiB floor, and release
that floor only under the full positive proof. This integration must receive that
reviewed successor before a233 policy is represented as supporting terminal223.
The204 delivery stage whitelist remains16/64GiB;233's225GB+2GiB profile is separate.

Source-only so far. No Cargo/target access, runtime retries, resource observations,
canonical publication or R2 mutations were performed for this integration. Run
all focused tests (capped204205_admission, maintenance_capacity, first_root233,
private_prefix, capped204_v4_admission), both complete R2 feature suites and strict
all-target/all-feature Clippy once the final combined source is frozen and parent
transfers the exclusive target lease. The root-only isolated negative-audit writer
fixture additionally needs the parent's reviewed sealed test-harness execution.

After QA, build/capture ONE all-features production R2 with actual compiler,
source, extern/native/config/ELF/QA evidence before target reuse. Parent independent
review/sealing remains separate. Update the admission self binding and every new
ETA model/publisher pin to its actual NEW SHA. Do not use 5746ac2a's6d7d hash.
Node/control/probe, historical worker, actual disposable capability and observer
78dc remain unchanged. The old source capture expired02:24: preserve it and take
an independent unique fresh capture/plan/proposal/attempt only after all durable
preparation is complete. Capture the actual live launch and publish immediate
status at the original1792749926759 clock; no retrospective receipt is permitted.
