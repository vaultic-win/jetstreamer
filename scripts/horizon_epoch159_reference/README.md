# Epoch 159 bounded vote reference

The original epoch 159 producer failed at slot 68,688,001, entry 56, transaction 78, with VoteError::SlotHashMismatch. The private reference uses the same v1.5.6 worker executable and restored checkpoint. It supplies complete original Old Faithful entries through the existing protocol-v5 request path. All 16 real boundary hashes in the five warmup gaps must match the independently recovered RecentBlockhashes writes. Eleven intermediates were independently recomputed from the finalized parent and the transaction-free tick prefixes. The five endpoints also match finalized RPC. Validator votes signed the Bank-hash witnesses used for the separate SlotHashes comparisons.

The exact snapshot is 1,769,283,828 bytes at slot 68,687,833. The bounded source spans 157 produced blocks, 69,491 entries and 97,502 transactions through 68,688,001. Both small index slices and all seven CAR windows have pinned SHA-256 digests. The reader streams 66,786,830 CAR bytes and verifies each CBOR content identifier. Each entry's original transaction grouping and hash travel unchanged to the v1.5.6 worker, which verifies PoH as it processes the entries. The procedure produces private diagnostic evidence.

Install the cbor2 dependency from the sibling epoch 157 reference requirements or expose the existing sealed Anza package. Run these commands from the repository checkout.

```sh
/usr/bin/python3 -IB scripts/horizon_epoch159_reference/test_trace.py
/usr/bin/python3 -IB scripts/horizon_epoch159_reference/trace.py check-source
```

The replay command within the controller's reviewed physical allocation is

```sh
/usr/bin/python3 -IB scripts/horizon_epoch159_reference/trace.py replay /absolute/private/scratch /absolute/private/receipts
```

Provide an empty private ext4 scratch mount backed by a fully allocated 24 GiB HOME loop image and an empty private HOME receipt directory. The service uses two CPUs, 48 GiB of RAM, zero swap and at least 500,000 free scratch inodes. The snapshot tar contains 360,002 members and 7,750,623,232 bytes of file payload rounded to 4 KiB blocks. The prior incident's measured peak was 38.4 GiB. Read the snapshot, genesis, worker and deployed reader through read-only mounts, keep scratch and receipts writable for the unprivileged worker, and bound service output. Bind the script, inputs, sibling car and native modules and their CBOR dependencies to the deployed package. The controller retains admission, cgroup and mount ownership. Check the complete fleet, leases and host-wide process guards before launch.

The bounded run compares the original restored Bank tuple, three subsequent native Bank checkpoints, original target transaction wire and result, and the actual published SlotHashes writes with signed parent-Bank evidence. A discrepancy is preserved in outcome.json and returns failure. Completed receipts describe this bounded interval. Epoch-wide verification and publication continue to require their own evidence.

## Physical reference service

The campaign owner installs the flat package, including the shared feature profile module, under
`/var/lib/jetstreamer/horizon_runtime_data/epoch159-bounded-reference-20261123-v1/package-v1`.
The package includes the two protocol modules and original block index correction
from the epoch 157 reference. The optional [epoch 159 feature differential](FEATURE-REFERENCE.md) uses its own package and invocation. Use the deployment sealer to bind every member.
The existing v1.5.6 executable, CBOR extension/modules, genesis and snapshot are
opened in the actual privilege-dropped read-only mount view by
`service.py check-mounted-inputs`. This reads the complete snapshot and verifies
all ten dependency hashes without running a historical worker. Use
`service.py recipe` to display the exact systemd and sandbox argument vectors.

Only the physical campaign owner can mint the root-owned mode 0400
`ADMISSION.json` in the service parent. The fields are
`schema=horizon-epoch159-bounded-grant-v1`, `actual_grant=true`, the exact
`unit`, `limits` from the recipe, current deployment `package_sha256`,
`priced_at_utc`, `fleet` and full `price` evidence references (path, sha256),
`donor_lock` (path, dev, ino), and the complete `donor_idle_units` from the
approved focused-169/136/171 transition. Both checks run under the original
admission lock. The service holds it until its native worker exits and its
mounts have been torn down. Recheck the full fleet and actual donor ownership
when pricing the grant.

From that directory the owner runs:

```sh
sudo -n /usr/bin/python3 -IB package-v1/service.py dispatch "$admission_sha256"
```

The sole fixed unit runs for at most 7,800 seconds with 2 CPUs, 48 GiB and
zero swap. It creates one fully allocated 24 GiB ext4 scratch image with
524,288 inodes and one 8 MiB ext4 evidence image on HOME. External program
output drains continuously, retaining at most 8 MiB of logs. Extracted JSON
also has an 8 MiB allocated-block bound. All overhead is charged within the
separate 32 MiB HOME booking. The directly executed historical binary retains
its original filename. Its HELLO receipt records kernel comm, parent, start
ticks, executable inode and cgroup before any snapshot is restored.

After the fixed unit exits, inspect the native receipts, especially
`attempt-v1/retained/{hello,bootstrap,outcome}.json`, and open its log if
the worker failed. Native failure retains diagnostic evidence. After accepting
the copies, the owner can run `service.py retire-scratch`. It verifies the
original terminal invocation, empty service cgroup, recorded image inode,
detached loop and retained outcome before unlinking only scratch. On a
supervisor interruption both images persist for reconciliation. The exclusive
dispatch intent and attempt directory prevent a duplicate run.
