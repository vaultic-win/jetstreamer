"""Fund one serialized custody operation inside the drained 266 producer reservation."""
import os
import sys
from pathlib import Path
sys.path.insert(0,'/run/horizon266-bounded-tools-v208')
import retry_fit
from retry_fit import M,D,V,CG,partition,ref,bound

def price(serial,retained,disk,*,consumer_build=False,prepare257=False,closed_disk=False):
    assert __debug__ and os.geteuid()==0 and partition.locked(partition.LOCK,os.getpid())
    if consumer_build:
        assert (serial, retained, disk) == (6400*M, 256*M, 112*M)
        previous = bound(ref(D/'horizon249-delivery-consumers-v214-a1/booking.json'))
        allowance = bound(previous['assignment'])
        assert tuple(allowance[k] for k in ('serial','retained','disk')) == (serial,retained,disk)
    elif prepare257:
        previous = bound(ref(D/'horizon257-inert-prepare-cold-v156-v1/booking.json'))
        assert (serial, retained, disk) == (512*M, 256*M, 256*M)
        assert (previous['memory'], previous['disk_reserve']) == (serial, disk)
    else:
        assert 0<serial<=2<<30 and 0<disk<=retained<=64*M
    fit=retry_fit.price(0,0,0,assessment_only=True)
    terminal=bound(fit['closed266'])
    planning=ref(D/'horizon266-full-workspace-after-target-v214/assessment.json')
    assert planning['sha256']=='a7ce74b5e9580302b9f54cf99df3dcbd29f11cc383e1bbcf4327d017737aaae6'
    assert bound(planning)['terminal']==fit['closed266'] and terminal['original_reservation']==fit['issued']
    book=bound(fit['issued']);original=bound(terminal['handoff'])
    assert book['producer']==192000000000 and book['cpu']==list(range(8)) and original['unit']==terminal['unit']
    assert terminal['producer_drained'] and terminal['bounded_target_met'] and terminal['iid']==original['iid']
    assert not (CG/original['unit']).exists() and fit['before'][original['unit']]==fit['middle'][original['unit']]==fit['after'][original['unit']]==0
    # A launch cannot enter this phase: all issuers use the same exclusive lock, the original
    # retry is consumed, and its guard and worker have drained. Keep the complete hard ledger.
    assert bound(ref(V/'horizon266-capped-bounded-v210-control/pilot/handoff.json'))==original
    disk_margin = fit['disk_margin']
    if closed_disk:
        booking = bound(fit['closed265_delivery'])
        assert booking['donor']['sha256'] == 'c2112c2cf4d97797dbf9d1d2c347c2e00c954c14eedba5572b621aa22e7588af'
        release = bound(booking['donor'])
        extent = fit['extent']
        assert release['original'] == fit['issued'] and release['terminal'] == fit['closed266']
        assert extent['identity'] == release['current']['identity'] and Path('/sys/block/loop18/ro').read_text().strip() == '1'
        assert extent['first']['blocks'] == extent['second']['blocks'] == release['retained_backing_bytes']
        assert extent['remaining'] == release['replaced_future_growth_bytes']
        disk_margin += extent['remaining'] - release['qa_bytes'] - booking['disk']
    assert fit['remaining_265']>=retained and disk_margin>=disk
    margin=fit['growth_margin']+book['producer']-serial-retained
    assert margin>=0 and serial+retained<=book['producer']
    return dict(fit,planning=planning,serial=serial,retained=retained,disk=disk,
                serialized_phase_margin=margin,donor=fit['issued'],serialized_in_place_of_drained_producer=True,
                remaining_265=fit['remaining_265']-retained,disk_margin_after_phase=disk_margin-disk,
                owner_lock=str(partition.LOCK),general_capacity_credit=0,replay_admitted=False)
