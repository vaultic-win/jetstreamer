# Consume the terminal epoch 168 private diagnostic

Apply `status.patch` to the 42-member status publisher sealed by `005603ab7a0e18a15433b008180f13cbb8a568f45aa88e90c8722d243c15c4db` and install `closed168.py`. The first transition binds the original 08:19:59 sample, its 07:49:59 predecessor, and the terminal receipt for the admitted diagnostic. The consumer checks that the original PID and cgroup have drained and the original guard has stopped. Subsequent observers omit the retired diagnostic. The private allocation, repair owner, 19 authenticated status records, and original half-hour cadence carry forward.

Run `qualify.py PACKAGE PRIVATE_OUTPUT` as the receipt owner. It exercises the genuine five-owner census, sample, conditional publication against a private store, assembled fleet, following configuration and rejection controls. The production consumer retains its authenticated inventory, conditional R2 writes and readback.
