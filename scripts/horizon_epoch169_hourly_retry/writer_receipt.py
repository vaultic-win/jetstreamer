"""Read the active cadence receipt returned by the native writer census."""
import json
from pathlib import Path


def read_active_writer(contract, reference):
    # The cadence process records ACTIVE with mode 0600. Its native census
    # binds the digest, live systemd invocation, process start and lock inode.
    metadata, content = contract.stable(
        Path(reference["path"]), expected=reference["sha256"], keep_bytes=True
    )
    contract.need(metadata["owner"] == 0 and
                  (metadata["mode"] == 0o600 or not metadata["mode"] & 0o222),
                  "invalid owner or mode for active cadence receipt")
    return json.loads(content)
