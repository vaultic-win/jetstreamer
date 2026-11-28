"""Authenticate the recovery that starts while the original epoch 166 is still running."""
from pathlib import Path

import status168 as s

OLD = '5dfb817906f74b73a27f61a386751d75'
STATE = s.ROOT / 'epoch145-guarded-export-20261121-v1/state' / OLD
START = s.ref(STATE / 'recovery-started.json', 'abfd9eca8c8249e4f1f6b69aaa7ba05c6b970a3d0a932d0087b8cea51e0ff0c2')
FAILURE = s.ref(STATE / 'failed.json', '5d4c65a72c123351ba1f0a7dffd4a753ce2c8627efa74220e1568337375a685a')
HERE = Path(__file__).resolve().parent
IMAGE = s.ROOT / 'epoch145-semantic-continuity-20261121-v1/tools-v4/export145'


def profile(executable):
    if executable!=str(IMAGE):
        return None
    settings,reference=s.read(HERE/'same-five-image.json')
    seal,_=s.read(HERE/'deployment-seal-receipt.json')
    s.need(seal['destination']==str(HERE) and any(
        r['name']=='same-five-image.json' and r['sha256']==reference['sha256'] for r in seal['members']),
        'unbound five-owner verifier configuration')
    image=Path(settings['image']['path'])
    s.need(image==IMAGE, 'incorrectly staged five-owner verifier')
    return image,settings['image']['sha256'],settings['seal']['sha256'],settings['build']['sha256']


def predecessor(prior,fit,unit):
    failed=prior['verified_predecessor_failure']
    s.need(failed['failure']==FAILURE and s.bound(FAILURE,STATE/'failed.json')['iid']==OLD,
           'different original 145 failure')
    event=failed['native']
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-','')
    s.need(event['_BOOT_ID']==boot and event['UNIT']==unit and event['INVOCATION_ID']==OLD and
           event['MESSAGE_ID']=='98e322203f7a4ed290d09fe03c09fe15' and
           event['EXIT_CODE']=='exited' and event['EXIT_STATUS']=='1','different original manager failure')
    for pid,ticks in ((3738161,359708608),(3751536,359803826)):
        try: current=s.process(pid)[1]
        except (FileNotFoundError,ProcessLookupError): continue
        s.need(current!=ticks,'original frozen verifier still present')
    old=s.bound(START,STATE/'recovery-started.json')['fresh_fit']['remaining_native_owners']
    s.need(set(old)=={'166','167','169','170','172'} and fit['remaining_native_owners']==old and
           fit['joint_closed166'] is None and fit['metered168'] is None and fit['joint136_enabled'] is True and
           fit['charged_cpu_micros']==64_000_000, 'different paid initial five-owner census')
    return FAILURE
