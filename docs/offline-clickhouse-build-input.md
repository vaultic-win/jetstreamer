# Offline ClickHouse build input

`jetstreamer-utils` embeds ClickHouse, including for the ordinary `horizon_pipeline`
that starts a local server. For an offline production build, supply both:

```text
JETSTREAMER_CLICKHOUSE_BINARY=/absolute/canonical/sealed/input/clickhouse
JETSTREAMER_CLICKHOUSE_SHA256=<64 lowercase hexadecimal digits>
```

The build script requires a nonempty, root-owned, singly linked regular file, at
most 1 GiB, without any write bits. Every ancestor must be a root-owned directory
without group or other write access. It rejects symlinks/noncanonical paths,
hash mismatches and changes to file identity, metadata or length during hashing.
The verified immutable file is embedded directly, avoiding another build-cache
copy. Cargo tracks both variables, the selected file and `DOCS_RS` for rebuilds.
An incomplete or invalid explicit input fails without attempting the installer,
including when `DOCS_RS` is set. Without an explicit input the existing online
installer and docs.rs behavior remain available.

Seal the binary and retained provenance with `jetstreamer-seal-deployment` before
using this option. A retained download log and independently observed local hash
do not establish a vendor signature or version. Qualify the exact executable's
version/functionality and the resulting ordinary pipeline separately; a successful
build is not replay, archive-verification or publication authority. Do not use an
empty docs.rs embedding for production.

The regression module is shared by the real build script and
`cargo test -p jetstreamer-utils --test clickhouse_build_input`. Its ignored native
positive/mismatched-hash case requires a separately sealed input:

```text
HORIZON_TEST_CLICKHOUSE_INPUT=/absolute/canonical/sealed/input/clickhouse
HORIZON_TEST_CLICKHOUSE_SHA256=<independently observed input digest>
```

Run that case with `-- --include-ignored` inside the separately admitted test
scope. Keep the build's `JETSTREAMER_*` bindings and native test bindings explicit.
The second ignored native case extracts the exact bytes into a private writable
temporary directory, runs bounded version and SQL probes, and revalidates the
sealed original. The retained compressed distribution needs to decompress beside
its executable, just as the embedded runtime permits after temporary extraction.
