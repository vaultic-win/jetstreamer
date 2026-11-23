"""Epoch 163 restore actor's systemd TemporaryFileSystem value."""
import argparse
from pathlib import PurePosixPath


def scratch_tmpfs(scratch: str) -> str:
    path = PurePosixPath(scratch)
    if (path.anchor != "/" or len(path.parts) < 2 or ".." in path.parts
            or str(path) != scratch or any(ch.isspace() or ch in ":,\\'\"%"
                                           or ord(ch) < 32 for ch in scratch)):
        raise ValueError("expected an absolute scratch directory usable as one systemd mount target")
    return f"/tmp:ro /var/tmp:ro {scratch}:rw,nosuid,nodev,exec,size=40G,nr_inodes=524288,mode=0700"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scratch")
    print("TemporaryFileSystem=" + scratch_tmpfs(parser.parse_args().scratch))
