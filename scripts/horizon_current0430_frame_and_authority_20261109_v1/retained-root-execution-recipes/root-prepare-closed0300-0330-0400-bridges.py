from pathlib import Path
import json,hashlib,ast
base=Path('/home/sol/workspace/jetstreamer/scripts/horizon_reader_phase145_busy_v3/operator-source/root-finalize-closed0200-bridge-metadata-v1.py');s=base.read_text();old="chain = [{'path': '/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T020022Z-postcompletion154-v1.json', 'sha256': 'e3fc848255d438d473e059cff501b7c62ff7b256ddb3a81645129fe747ff6b1a'}]";assert s.count(old)==1
for stamp in ['0300','0330','0400']:
 f=Path('/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1')/('sample-20261109T'+stamp+'22Z-postcompletion154-v1.json');binding=dict(path=str(f),sha256=hashlib.sha256(f.read_bytes()).hexdigest());x=s.replace(old,'chain = '+repr([binding])).replace('observer0200-closed-metadata','observer'+stamp+'-closed-metadata').replace('ROOT_GENUINE0200_OBSERVER','ROOT_GENUINE'+stamp+'_OBSERVER');ast.parse(x);Path('/tmp/root-finalize-closed'+stamp+'-bridge-metadata-v1.py').write_text(x)
