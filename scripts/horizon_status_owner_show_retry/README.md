# Retry a timed-out status owner query

Apply `owners.patch` with `patch -p1 --fuzz=0` to the status publisher sealed by `d7bb6adb2390bcc534915cb4e78b0e3743ca5de62f481302dac226207bb44e33`. The patch changes the shared `owners.show` function. A `TimeoutExpired` on a read-only `systemctl show` retries the identical command once with the existing 15-second timeout. A second timeout, command failure, changed owner, or expired status sample propagates through the existing publication checks.

Run `qualify.py PACKAGE ACCEPTED_FLEET PRIVATE_OUTPUT` offline as the receipt owner. It uses the fleet's 19 authenticated status pairs and corresponding intents, the real epoch 172 guard identity check, and a private conditional store. It covers a changed invocation, both timeout outcomes, a different command failure, freshness after the retry, three completed writes, and a fourth write whose successful response was lost.
