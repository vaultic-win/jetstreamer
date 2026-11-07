#!/usr/bin/env python3
"""Root-only SOURCE dispatcher; not executed by helper. No retries/restarts."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from prepare_native128 import metadata, require


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('prepared_directory')
    args=parser.parse_args()
    require(os.geteuid()==0,'Root is sole operator')
    directory=Path(args.prepared_directory)
    prepared=json.loads((directory/'prepared-bindings.json').read_bytes())
    plan=metadata(prepared['native_plan'])
    actor=json.loads((directory/'actor-argv.json').read_bytes())
    issuer=json.loads((directory/'issuer-argv.json').read_bytes())
    ready=Path(plan['state'])/'ready.json'
    require(not ready.exists() and not Path(plan['admission']).exists(), 'fresh original native state required')
    began=time.monotonic()
    subprocess.run(actor['argv'],check=True,timeout=15)
    while not ready.exists():
        require(time.monotonic()-began<30,'native ready absent inside dispatch budget; no retry or restart')
        time.sleep(.1)
    value=json.loads(ready.read_bytes())
    require(value['schema']=='epoch163-native-input-held-v1' and value['plan']==prepared['native_plan']
        and value['snapshot_body_opened'] is False,'actual held ready original plan')
    require(time.monotonic()-began<35,'insufficient true original actor margin; no issuer dispatch')
    subprocess.run(issuer['argv'],check=True,timeout=15)
    print('Original actor and one issuer dispatched. Issuer authenticates actual PID/IID/<105s. No replay authorized.')


if __name__=='__main__':
    main()
