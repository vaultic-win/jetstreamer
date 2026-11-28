# Epoch 234 transaction fixture

These are the original responses to two read-only, finalized JSON-RPC requests
to `https://api.mainnet-beta.solana.com`, acquired on 2026-11-06. Each request
was bounded to one MiB, a ten-second connection timeout and thirty-second total
timeout, without retries. The request bodies, original HTTP headers and response
bytes are also retained in the immutable same-host acquisition package
`/var/lib/jetstreamer/horizon234-fixture918-acquisition-v1`.

`epoch234-getTransaction.json` names slot 101249927 and signature
`5vsu4HtoCUafoiHmeJSPPEBnXCtCs3Saff9hSsbTGQCQ6DS3teP4i3PWQpcs5MyytginSBAttfmVLtSG1fJKvpNb`.
`epoch234-getBlock-signatures.json` is the separate response for that slot and
places the signature uniquely at zero-based transaction index 298, among 547
signatures. Its blockhash is
`5V2zQPVzufyRg8GCiQBy5hHkX7gKqwcYWxGaWs9TfBtX`.

The binary fixture is the response's exact base64 transaction payload. The
regression checks both original JSON hashes and the payload hash, independently
decodes the packet with the native bincode and Firehose codecs, reserializes it
byte for byte, sanitizes it and verifies its Ed25519 signature. It retains the
actual successful status and RPC metadata through Horizon conversion and archive
encoding. Changing an instruction invalidates the signature; trailing packet
bytes are rejected.

The signed packet is 1203 bytes and contains **67** instructions, each with three
account indexes and nine data bytes: 804 arena bytes in total. The old failure
reported the first overflowing append, instruction 65, rather than the message's
total count. The separate synthetic 65-instruction regression remains useful for
the first overflow and failed-status behavior.

| File | SHA-256 |
| --- | --- |
| `epoch234-slot101249927-tx298.bin` | `056658fd4f6f8172bae030599afa0335f0a05ab49ea5236b1d98d5fac0809d05` |
| `epoch234-getTransaction.json` | `7f5cbd7a11dbe22ad0a7f3ca799f35f0d23fef29aa76ed732f288c0379243c28` |
| `epoch234-getBlock-signatures.json` | `f7c29a0ee8811128afe103b9f0e67f1b668b76d9103ae51ef868767e89ef6a54` |

Signature verification authenticates the message. The finalized RPC responses
provide slot/order provenance; they do not establish a Bank checkpoint, CAR DAG
root, full replay result or publication eligibility.
