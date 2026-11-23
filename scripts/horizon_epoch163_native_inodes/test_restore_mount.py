import unittest

from restore_mount import scratch_tmpfs


class RestoreMountTest(unittest.TestCase):
    def test_epoch_163_restore_mount(self):
        path = "/home/sol/epoch163/scratch"
        self.assertEqual(
            scratch_tmpfs(path).split(),
            ["/tmp:ro", "/var/tmp:ro",
             path + ":rw,nosuid,nodev,exec,size=40G,nr_inodes=524288,mode=0700"],
        )

    def test_reject_paths_that_change_the_mount_or_its_systemd_parsing(self):
        for path in ["/", "relative", "/home/sol/../root", "/a//b", "//a",
                     "/a:b", "/a,b", "/a b", "/a\nb", "/a\\b", "/a%t", '/a"b', "/a'b"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                scratch_tmpfs(path)


if __name__ == "__main__":
    unittest.main()
