"""Render the fixed inactive guard/producer and passive file-activation units."""
from pathlib import Path
import runpy

HERE=Path(__file__).resolve().parent
C=runpy.run_path(str(HERE/'contract.py'))
B=C['B']
STATE=B/'transition-state'
REG=B/'phase-handoffs'
ENTRY=B/'phase-transition-v4/transition_event.py'
CHECK='horizon-199200-phase-checkpoint.service'
PATH=CHECK.replace('.service','.path')
DELIVERY={e:B.parent/(f'epoch{e}-current-delivery-20261121-v1' if e!=166 else 'epoch166-retry10-delivery-20261121-v1') for e in (166,167,168,170,172)}

def units():
    common='Type=exec\nRestart=no\nUMask=0077\nMemorySwapMax=0\nNoNewPrivileges=yes\nPrivateNetwork=yes\n'
    check='[Unit]\nDescription=Price epochs 199 and 200 after a recorded original phase transition\n[Service]\n'+common+'MemoryMax=512M\nCPUQuota=100%\nNice=15\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths='+str(STATE)+' /run/horizon-epoch171-to136-g1.operation.lock\nExecStart=/usr/bin/python3 -IB '+str(ENTRY)+' checkpoint\n'
    paths='[Unit]\nDescription=Watch accepted original producer and capacity transfers\n[Path]\n'+''.join('PathChanged='+str(d/'event-state/INTENT.json')+'\n' for d in DELIVERY.values())+'PathChanged='+str(REG)+'\nPathChanged='+str(B.parent/'epoch169-focused-terminal-20261121-v1/TERMINAL_GUARD_DRAINED.json')+'\nPathChanged='+str(STATE/'physical-events')+'\nUnit='+CHECK+'\n[Install]\nWantedBy=multi-user.target\n'
    result={CHECK:check,PATH:paths}
    for e,d in DELIVERY.items():
        name=f'horizon-199200-after-publication-{e}'
        # A successful one-shot stays active after the permanent marker appears.
        result[name+'.path']='[Unit]\nDescription=Observe authenticated epoch '+str(e)+' publication\n[Path]\nPathExistsGlob='+str(d/f'run-*/receipts/epoch-{e}.r2.json')+'\n[Install]\nWantedBy=multi-user.target\n'
        result[name+'.service']='[Unit]\nDescription=Price 199 and 200 after epoch '+str(e)+' publication\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/systemctl start --no-block '+CHECK+'\n'
    result[C['HOLD']]='[Unit]\nDescription=Own the funded 199 and 200 aggregate reservation\n[Service]\n'+common+'Slice=horizon199200-aux.slice\nMemoryMax=512M\nCPUQuota=100%\nExecStart=/usr/bin/python3 -IB '+str(ENTRY)+' guard\n'
    result[C['CTRL']]='[Unit]\nDescription=Run the admitted 199 and 200 ordinary cohort controller\n[Service]\nType=exec\nRestart=no\nUMask=0077\nNoNewPrivileges=yes\nExecStart=/usr/bin/python3 -IB '+str(ENTRY)+' controller\n'
    result.update(C['slices']())
    result.update({str(Path(name)/'90-measured-199200.conf'):body for name,body in C['service_dropins']().items()})
    return result
