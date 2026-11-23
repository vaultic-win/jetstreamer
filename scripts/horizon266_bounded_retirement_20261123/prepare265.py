"""Prepare the closed epoch 265 archive for ordinary delivery using the qualified reader and uploader pair."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).parent))
from successor_fit import pin
from funding import CG, D, M, V, bound, partition, price, ref
import funds
sys.path.insert(0,'/var/lib/jetstreamer/horizon249-delivery-v214-tools')
from ordinary249 import delivery248, delivery249

PRIVATE = Path('/home/ubuntu/.jetstreamer-private/current-reader-delivery-265-v215')
SEALED = V/'horizon265-ordinary-reader-v215'


def prepare(attempt):
    folder = D/('horizon265-ordinary-delivery-preflight-v215-'+attempt)
    with partition.take():
        fit = price(256*M,8*M,4*M)
        release = pin(V/'horizon266-v210-closed-growth-v215/release.json','c2112c2cf4d97797dbf9d1d2c347c2e00c954c14eedba5572b621aa22e7588af')
        closed = bound(release)
        assert fit['extent']['identity']==closed['current']['identity'] and closed['terminal']==fit['closed266']
        assert fit['extent']['second']['blocks']==closed['retained_backing_bytes'] and Path('/sys/block/loop18/ro').read_text().strip()=='1'
        prior, pre, observer, reader, _, _ = delivery249.inputs()
        source = ref(V/'horizon-singleton-delivery265-20261120-v1/terminal-handoff.json')
        drain = pin(V/'horizon-singleton-delivery265-20261120-v1/terminal-drain.json','8ce7206e139b9dcd3fc1312619f9125147404925ebe275027581a0dced5624ca')
        assert bound(drain)['terminal_handoff']==source and bound(drain)['producer_cgroup_drained']
        plan = bound(reader)
        expectation = ref(V/'horizon265-boundary-expectation-20261120-v1/epoch-265.json')
        assert bound(expectation)['epoch']==265
        archive = bound(source)['source']['archive']
        candidate = SimpleNamespace(EPOCH=265,LENGTH=189538254413,SHA='4fa8bae107eca8d6405774afa81976b4443a72e2d318aa12d17c54d3cfe9ef62')
        plan['epoch_expectations']={'265':expectation}
        plan['scratch_directory']=str(PRIVATE/'playback')
        folder.mkdir(mode=0o700)
        ledger = D/('horizon-bounded265-residual-'+folder.name)
        ledger.mkdir(mode=0o700)
        assignment = funds.put(ledger/'assignment.json',fit)
        proposed = funds.put(folder/'epoch-265-plan.json',plan)
        head, paths, fixture, local = delivery248.qualify(candidate,pre,bound(observer),proposed,source,drain)
        assert str(local)==archive['path'] and archive['identity']['length']==candidate.LENGTH
        listing=delivery248.prefix(candidate)
        assert set(listing)=={'epoch-265.epoch-status.json'}
        sealer=pin(V/'horizon251-published-sealer-20261118-v1/horizon251-sealer','faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a')
        if not SEALED.exists():
            sealing=funds.put(folder/'seal-plan.json',dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(SEALED),
                members=[dict(name='epoch-265-plan.json',source=proposed['path'],sha256=proposed['sha256'],mode=0o444)]))
            subprocess.run([sealer['path'],sealing['path'],'--plan-sha256',sealing['sha256'],'--self-sha256',sealer['sha256']],check=True)
        sealed=pin(SEALED/'epoch-265-plan.json',proposed['sha256'])
        for p in (PRIVATE,PRIVATE/'playback',PRIVATE/'receipts',PRIVATE/'tmp'):
            p.mkdir(mode=0o700,exist_ok=True)
            assert p.resolve()==p and p.stat().st_uid==0 and p.stat().st_mode & 0o777 == 0o700
            if p!=PRIVATE:assert not list(p.iterdir())
        floor = fit['protected_floor']-fit['extent']['remaining']+closed['qa_bytes']+fit['disk']
        assert fit['extent']['free']-floor>delivery248.DISK and fit['serialized_phase_margin']>delivery248.GROSS
        print(funds.put(folder/'assessment.json',dict(resources=assignment,prior=prior,current_observer=observer,branch=head,
            ordinary_reader_paths=paths,qualified_pair=fixture,epoch_expectation=expectation,plan=sealed,
            seal=ref(SEALED/'deployment-seal-receipt.json'),handoff=source,drain=drain,release=release,
            listing=listing,gross=delivery248.GROSS,disk=delivery248.DISK,
            disk_margin=fit['extent']['free']-floor-delivery248.DISK,memory_margin=fit['serialized_phase_margin']-delivery248.GROSS,
            publication_started=False,capacity_reassigned=False)),flush=True)


if __name__=='__main__':
    prepare(sys.argv[1])
