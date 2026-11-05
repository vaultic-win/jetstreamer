#!/bin/sh
set -eu

# Embedding ClickHouse makes this library too large for sccache's ZIP writer.
# Compile it directly while retaining the cache for all other crates.
previous=
for argument do
    if [ "$previous" = "--crate-name" ] && [ "$argument" = "jetstreamer_utils" ]; then
        exec "$@"
    fi
    if [ "$argument" = "--crate-name=jetstreamer_utils" ]; then
        exec "$@"
    fi
    previous=$argument
done

exec sccache "$@"
