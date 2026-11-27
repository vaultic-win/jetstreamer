import unittest
from pathlib import Path

from scratch_mount import parse_record

TARGET = Path("/home/sol/fixture")
RECORD = ("112 55 0:44 / /home/sol/fixture rw,nosuid,nodev shared:17 - tmpfs tmpfs "
          "rw,size=46137344k,nr_inodes=600000,mode=700,uid=1001,gid=1003,inode64,noswap")


class ScratchMount(unittest.TestCase):
    def test_genuine_with_shared_optional_field(self):
        self.assertEqual(parse_record(RECORD, TARGET), ("112", "0:44"))

    def test_foreign_or_unbounded_mount(self):
        for old, new in [("noswap", "swappiness=0"), ("rw,nosuid,nodev", "rw,noexec,nosuid,nodev"),
                         ("rw,nosuid,nodev", "ro,nosuid,nodev"), (" - tmpfs ", " - ext4 "),
                         ("size=46137344k", "size=46137345k"), ("mode=700", "mode=777"),
                         ("nr_inodes=600000", "nr_inodes=0"), ("gid=1003", "gid=0"),
                         ("0:44 / ", "0:44 /child "), ("/home/sol/fixture", "/home/sol/elsewhere")]:
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                parse_record(RECORD.replace(old, new), TARGET)

    def test_stacked_mount_rejected(self):
        with self.assertRaises(ValueError):
            parse_record(RECORD + "\n" + RECORD, TARGET)
