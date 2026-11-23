import json
from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

M = runpy.run_path(str(Path(__file__).with_name("v5n_feature_cover.py")))
IID = "e"*32


class CorrectedDonor(unittest.TestCase):
    def test_unclaimed_granted_pending_and_completed(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            attempt=root/"attempt-v1"
            group=root/"cgroup"
            props={"Id":M["UNIT"],"ActiveState":"inactive","SubState":"dead","InvocationID":"","MainPID":"0",
                   "ControlPID":"0","Job":"","NRestarts":"0","LoadState":"not-found"}
            def command(name,*args):
                if name.endswith("systemctl"):
                    return "\n".join(k+"="+v for k,v in props.items())
                if name.endswith("journalctl"):
                    return json.dumps({"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","__CURSOR":"original"})
                self.assertTrue(name.endswith("losetup"))
                return ""
            def bound(path,expected=None):
                import hashlib
                raw=path.read_bytes()
                h=hashlib.sha256(raw).hexdigest()
                self.assertIn(expected,(None,h))
                return json.loads(raw),h
            def write(path,data):
                path.write_text(json.dumps(data))
                return bound(path)[1]
            def need(valid,reason):
                if not valid:raise ValueError(reason)
            snapshot=M["snapshot"];donor=dict(command=command,bound=bound,need=need)
            with patch.dict(snapshot.__globals__,R=root,GROUP=group):
                self.assertEqual(snapshot(donor)["stage"],"unclaimed")
                gh=write(root/"ADMISSION.json",dict(unit=M["UNIT"],actual_grant=True))
                with self.assertRaises(FileNotFoundError):snapshot(donor)
                write(root/"DISPATCH_INTENT.json",dict(unit=M["UNIT"],grant=gh))
                attempt.mkdir()
                write(attempt/"start.json",dict(iid=IID,grant=gh,unit=M["UNIT"]))
                with self.assertRaises(FileNotFoundError):snapshot(donor)
                (attempt/"retained").mkdir()
                oh=write(attempt/"retained"/"outcome.json",{"passed":True})
                write(attempt/"driver-exit.json",dict(code=0,iid=IID,retained={"outcome.json":oh},utc="2026-11-23T15:00:00Z"))
                write(attempt/"success.json",dict(iid=IID,outcome=oh,utc="2026-11-23T15:00:01Z"))
                for n in ("scratch","evidence"):
                    im=attempt/(n+".ext4")
                    im.write_bytes(b"1"*4096)
                    st=im.stat()
                    write(attempt/(n+"-identity.json"),dict(ino=st.st_ino,dev=st.st_dev,size=st.st_size))
                self.assertEqual(snapshot(donor)["stage"],"drained")
                props["Job"]="2"
                with self.assertRaises(ValueError):snapshot(donor)
                props["Job"]=""
                write(root/"DISPATCH_INTENT.json",dict(unit=M["UNIT"],grant="0"*64))
                with self.assertRaises(ValueError):snapshot(donor)

if __name__ == "__main__":
    unittest.main()
