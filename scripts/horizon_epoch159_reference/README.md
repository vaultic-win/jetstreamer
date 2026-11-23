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
