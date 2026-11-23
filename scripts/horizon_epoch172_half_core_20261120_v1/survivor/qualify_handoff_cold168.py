"""Rehearse the 168 handoff with the real completed forecast and a private simulated service."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def denied(expected, operation):
    try:
        operation()
    except ValueError as exc:
        if expected not in str(exc):
            raise
    else:
        raise AssertionError('expected rejection: '+expected)


def qualify(root, h):
    # Load the installed evidence readers and shared switch, then replace each manager boundary.
    assert hashlib.sha256(h['COMMON'].read_bytes()).hexdigest()==h['COMMON_SHA']
    assert hashlib.sha256(h['OLD'].read_bytes()).hexdigest()==h['OLD_SHA']
    common=runpy.run_path(str(h['COMMON']))
    evidence=runpy.run_path(str(h['OLD']))
    final,head=h['finished_forecast'](evidence)
    original=evidence['checked'](h['PREVIOUS'])['new']
    attempt=h['ATTEMPT']
    number=f'retry{attempt}'
    predecessor_key=f'failed_retry{attempt-1}'
    target=root/f'tools-cold168-{number}-v1'
    target.mkdir()
    session=root/'session'
    session.mkdir()
    new=target/'status_cycle.py'
    new.write_text('fixture reader')
    generation=target/(number+'-168-generation.json')
    evidence['durable'](generation,h['generation_record']())
    members=[]
    for member in [new,generation]:
        member.chmod(0o444)
        members.append(dict(name=member.name,mode='0444',sha256=evidence['bound'](member)['sha256']))
    seal=target/'deployment-seal-receipt.json'
    evidence['durable'](seal,dict(schema='jetstreamer-sealed-deployment-receipt-v1',sealer_sha256=h['SEALER_SHA'],
                                 remote_mutations=False,destination=str(target),members=members))
    qualified_path=root/(h['TAG']+'QUALIFIED.json')
    active=root/(h['TAG']+'ACTIVE.json')
    intent=root/(h['TAG']+'INTENT.json')
    rollback=root/(h['TAG']+'ROLLBACK.json')
    reg=dict(schema=f'horizon-168-{number}-v1-status-qualified-v1',epoch=168,guard=h['GUARD'],successor_root=h['ANCHOR'],
             prepared=h['PREPARED'],generation=evidence['bound'](generation),source_commit='1'*40,
             suites={'fixture':True},entry=evidence['bound'](new),package=evidence['bound'](seal))
    if attempt>2:
        reg[predecessor_key]=h['FAILURE']
    future=root/'future'
    future.mkdir()
    def names(stamp):
        paths=evidence['names'](stamp)
        return paths if stamp==h['DUE'] else dict(paths,statuses=future)
    live=dict(owner=original,stops=0,starts=0,failures=2,elapsed=False)
    schedule=dict(fleet=head,timer={'Id':'fixture.timer'})
    def timer(c,ref,minimum_seconds=110):
        assert ref==head and not live['elapsed'], 'expired timer was reused'
        return schedule
    def show(unit,fields):
        assert unit==common['UNIT']
        owner=live['owner']
        return dict(Id=unit,MainPID=str(owner['pid']) if owner else '0',InvocationID=owner['invocation_id'] if owner else '',
                    ActiveState='active' if owner else 'inactive',Job='',ExecStart=str(new)+' ;')
    def publisher(c,path,require_sleep=False):
        owner=live['owner']
        assert owner and owner['program']==str(path)
        return owner
    def command(*args,**kwargs):
        assert args[0]=='systemctl'
        if args[1]=='stop':
            assert len(args)==3 and args[2]==common['UNIT'] and live['owner']
            live.update(owner=None,stops=live['stops']+1)
        else:
            assert args==('systemctl','daemon-reload')
    def start(c,program):
        assert live['owner'] is None and program in (new,h['OLD'])
        if program==new and live['failures']:
            live['failures']-=1
            raise ValueError('injected receiver startup failure')
        live['starts']+=1
        owner=dict(original,program=str(program),pid=1000+live['starts'],start_ticks=1200+live['starts'],
                   invocation_id=format(live['starts'],'032x'))
        live['owner']=owner
        return owner
    c=dict(evidence,names=names,owners=SimpleNamespace(show=show))
    common_globals=common['switch'].__globals__
    overrides=dict(ROOT=root,DROP=root/'switch.conf',LOCK=root/'fixture.lock',publisher=publisher,output=command,
                   start_and_wait=start,timer_evidence=timer)
    operator=h['switch'].__globals__
    with patch.dict(common_globals,overrides),patch.dict(operator,ROOT=root,TARGET=target,QUALIFIED=qualified_path,
                                                        ACTIVE=active,SESSION=session):
        # run_path returns a namespace copy. Use the patched function globals for delegated callbacks.
        def activate():
            return h['switch'](c,common_globals,head)
        c['durable'](qualified_path,dict(reg,generation=h['GUARD']))
        denied('different qualified epoch 168 generation',activate)
        qualified_path.unlink()
        c['durable'](qualified_path,reg)
        def incomplete(ref):
            result=c['checked'](ref)
            if ref==final:
                result=copy.deepcopy(result)
                result['receipts' if attempt==3 else 'statuses'].pop('136')
            return result
        denied('incomplete first retry2 readback' if attempt==3 else 'wrong issuer, forecast handoff',lambda:h['switch'](dict(c,checked=incomplete),common_globals,head))
        denied('outside the completed 00:17 forecast chain',
               lambda:h['current_cycle'](c,c['checked'](h['FORECAST_PREP'])['head'],head))
        pending=future/'epoch-136.intent.json'
        pending.touch()
        denied('next status cycle has pending work',activate)
        pending.unlink()
        started=session/'START_INTENT.json'
        started.touch()
        denied('epoch 168 changed',activate)
        started.unlink()
        live['owner']=dict(original,start_ticks=original['start_ticks']+1)
        denied('different original publisher',activate)
        live['owner']=original
        assert live['stops']==live['starts']==0 and not intent.exists()
        for _ in range(2):
            denied('injected receiver startup failure',activate)
            assert live['owner']['program']==str(h['OLD']) and not active.exists()
            h['restored_owner'](c,live['owner'],original)
            denied('unregistered restored writer',lambda:h['restored_owner'](c,dict(live['owner'],pid=22),original))
            denied('different replacement service',lambda:h['restored_owner'](c,dict(live['owner'],lock={**original['lock'],'inode':1}),original))
        second,=root.glob(h['TAG']+'ROLLBACK_*.json')
        assert c['read_ref'](second)['original_rollback']==c['bound'](rollback)
        readback=activate()
        record=c['checked'](readback)
        prepared=h['PREPARED']
        assert record['new']==live['owner'] and record['old']==original and record['intent']==c['bound'](intent)
        for value in [record,c['read_ref'](intent)]:
            assert value['generation']==c['bound'](generation) and value['completed_forecast']==final
            assert value['admission']==value['prepared']==prepared
            if attempt>2:
                assert value['previous_active']==h['PREVIOUS'] and value[predecessor_key]==h['FAILURE']
        if attempt>2:
            assert record['schema']==f'horizon-168-retry{attempt}-v1-status-active-v1'
        live['elapsed']=True
        started.touch()
        pending.touch()
        assert activate()==readback and live['stops']==live['starts']==3
    return dict(fleet=head,original_writer=original,completed_forecast=final,authenticated_status_count=20,
                conditional_corrections=14,registered_rollbacks=2,same_lock=True,accepted_after_two_rollbacks=True,
                idempotent_after_timer_and_epoch_start=True,foreign_registration_rejected=True,
                incomplete_forecast_rejected=True,unresolved_future_intent_rejected=True,
                original_writer_and_rollback_identities_checked=True,physical_service_changes=0,remote_writes=0)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture_parent',type=Path)
    flags=parser.add_mutually_exclusive_group()
    flags.add_argument('--retry3',dest='attempt',action='store_const',const=3)
    flags.add_argument('--retry4',dest='attempt',action='store_const',const=4)
    parser.set_defaults(attempt=2)
    args=parser.parse_args()
    assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__
    assert args.fixture_parent.resolve(strict=True).is_relative_to('/home/sol')
    with tempfile.TemporaryDirectory(dir=args.fixture_parent) as tmp:
        h=runpy.run_path(str(Path(__file__).with_name('handoff_cold168.py')))
        if args.attempt>2:
            h['configure_successor'](args.attempt)
            h=h['switch'].__globals__
        report=qualify(Path(tmp),h)
        print(json.dumps(report,sort_keys=True))
