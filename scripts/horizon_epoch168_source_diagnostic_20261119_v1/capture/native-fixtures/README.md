These certificates and the private key are public, disposable TLS test fixtures.
They identify only a loopback test server and protect no real service or data.
The test CA is added only by the cfg(test) native transport harness. Production
has no CA or endpoint override. The certificates were generated November 19,
2026 with OpenSSL, using P-256 keys, localhost/127.0.0.1 SANs, and serial 168.

The CA signing key is not needed by the tests and is not included here.
