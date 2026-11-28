"""Authenticate the complete status range then conditionally refresh each status only."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import urlsplit
from cycle import Cycle,status_predecessor
from evidence import EPOCHS, STATUS_ROOT, bound, checked, content, digest, durable, ensure_dir, lock, need, utc
from owners import IDS, DIAG_REF, show
import replay167_rate
import replay167_event

BUCKET="solana-archive-with-accounts-data"
FIELDS={"epoch","jet_size_bytes","elapsed_execution_millis","estimated_remaining_millis","sampled_at_utc","phase"}
def body(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def key(epoch):return f"epoch-{epoch}.epoch-status.json"
class Storage:
    def __init__(self):
        import boto3
        from botocore.config import Config
        endpoint=urlsplit(os.environ["HORIZON_S3_ENDPOINT"])
        need(endpoint.scheme=="https" and endpoint.path.strip("/")==BUCKET and not endpoint.query and not endpoint.fragment,"incorrect campaign bucket")
        self.s3=boto3.client("s3",endpoint_url=f"https://{endpoint.netloc}",region_name="auto",
            aws_access_key_id=os.environ["HORIZON_ACCESS_KEY_ID"],aws_secret_access_key=os.environ["HORIZON_SECRET_ACCESS_KEY"],
            config=Config(signature_version="s3v4",s3={"addressing_style":"path"},retries={"max_attempts":0}))
        self.pending=None
        def if_match(request,**kw):
            need(request.method=="PUT" and self.pending is not None and urlsplit(request.url).path.endswith("/"+self.pending[0]),"outside conditional status target")
            request.headers["If-Match"]=self.pending[1]
        self.s3.meta.events.register_first("before-sign.s3.PutObject",if_match)
    def inventory(self):
        statuses=set();sidecars=set();archives={}
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET,Prefix="epoch-"):
            for r in page.get("Contents",[]):
                m=re.fullmatch(r"epoch-([0-9]+)\.(epoch-status\.json|jet\.sha256|jet)",r["Key"])
                if not m:continue
                epoch=int(m[1])
                if not 101<=epoch<=200:continue
                need(m[1]==str(epoch),"noncanonical inventory key "+r["Key"])
                if m[2]=="jet":archives[epoch]=(r["ETag"].strip('"'),r["Size"])
                elif m[2]=="epoch-status.json":statuses.add(epoch)
                else:sidecars.add(epoch)
        return statuses,sidecars,archives
    def get(self,e):
        r=self.s3.get_object(Bucket=BUCKET,Key=key(e))
        try:raw=r["Body"].read(65537)
        finally:r["Body"].close()
        need(len(raw)<=65536,"oversize status object");return r["ETag"],raw
    def put(self,e,etag,data):
        from botocore.exceptions import ClientError

        self.pending=(key(e),etag)
        try:
            for delay in (0.5, 1, 2, None):
                try:
                    return self.s3.put_object(Bucket=BUCKET,Key=key(e),ContentType="application/json",Body=data)["ETag"]
                except ClientError as error:
                    if error.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 503:
                        raise
                    if delay is not None:
                        time.sleep(delay)
                    current_etag, current_body = self.get(e)
                    if current_etag != etag:
                        need(current_body == data, "status changed during conditional R2 retry")
                        return current_etag
                    if delay is None:
                        raise
        finally:
            self.pending=None
def inventory(c,storage):
    statuses,ready,archives=storage.inventory()
    ref=c.prior["inventory"];v=checked(ref,root=False)
    need(v["schema"]=="jetstreamer-horizon-r2-inventory-v1" and v["anomalies"]==0 and v["first_epoch"]==101 and v["last_epoch"]==200,"frozen R2 inventory invalid")
    wanted={r["epoch"]:r for r in v["entries"] if r["state"] in ("ready-pair","archive-only")}
    need(statuses==set(EPOCHS) and ready==set(c.prior["ready_epochs"])=={n for n,r in wanted.items() if r["state"]=="ready-pair"}
         and ready.isdisjoint(statuses) and archives.keys()==wanted.keys() and len(ready)==v["ready_pairs"],"R2 inventory changed; reconcile canonical readiness before refreshing statuses")
    for n,(etag,size) in archives.items():
        need((etag,size)==(wanted[n]["archive_etag"].strip('"'),wanted[n]["archive_length"]),"archive identity changed for "+str(n))
    return sorted(ready)
def observed_archive(c,epoch):
    p=Path(c.rows[epoch]["scratch_path"]).parent/"archives"/f"epoch-{epoch}.jet"
    pid=IDS[epoch][1]
    try:m=p.lstat()
    except FileNotFoundError:
        need(not c.advancing[epoch],"progressing canonical producer has no archive")
        return None
    need(p.resolve(strict=True)==p and stat.S_ISREG(m.st_mode) and m.st_uid==1001,"unexpected archive source")
    matches=[]
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if fd.readlink()==p and fd.samefile(p):matches.append(str(fd))
        except FileNotFoundError:continue
    need(matches,"archive not open by admitted producer "+str(epoch))
    return dict(path=str(p),device=m.st_dev,inode=m.st_ino,size=m.st_size,bound_producer_fds=matches)
def forecast(c,e,old):
    need(set(old)==FIELDS and old["epoch"]==e and old["phase"] in ("verification","replay"),"previous status shape invalid")
    age=round((c.now-utc(old["sampled_at_utc"])).total_seconds()*1000)
    need(age>=0,"newer report must be retained separately")
    after=dict(old,sampled_at_utc=c.stamp,estimated_remaining_millis=old["estimated_remaining_millis"]-age)
    archive=None
    if e in c.lanes:
        w=c.lanes[e]["useful_work"]
        need(old["phase"]=="replay","ordinary owner's predecessor must be replay")
        if c.advancing[e]:
            n=show(c.rows[e]["unit"]["Id"],("ExecMainStartTimestamp","InvocationID","MainPID"))
            need(n["InvocationID"]==IDS[e][0] and n["MainPID"]==str(IDS[e][1]),"live native start differs")
            started=dt.datetime.strptime(n["ExecMainStartTimestamp"],"%a %Y-%m-%d %H:%M:%S UTC").replace(tzinfo=dt.timezone.utc)
            duration=round((c.now-started).total_seconds()*1000)
            need(duration>=old["elapsed_execution_millis"],"elapsed time regressed")
            after["elapsed_execution_millis"]=duration
            if w["counter_resets"]==0 and w["elapsed_seconds"]>=60:
                left=w["last"]["terminal_slot"]-w["last"]["slot"]
                need(left>0,"terminal slot reached; reconcile verification ownership")
                after["estimated_remaining_millis"]=round(left*w["elapsed_seconds"]/w["slot_delta"]*1100)+12*3600000
        if e == replay167_rate.EPOCH:
            c.rolling167 = replay167_rate.forecast(c.sample_ref,old["estimated_remaining_millis"])
            if not c.advancing[e]:
                need(c.rolling167["state"] == "stalled-or-recovery-unproven", "inconsistent 167 native progress")
                after["elapsed_execution_millis"] = old["elapsed_execution_millis"] + age
            after["estimated_remaining_millis"] = c.rolling167["estimated_remaining_millis"]
        archive=observed_archive(c,e)
        if archive:
            need(archive["size"]>=old["jet_size_bytes"],"archive shrank under same producer")
            after["jet_size_bytes"]=archive["size"]
    else:
        need(old["phase"]=="verification","unexpected unowned public replay")
        # Elapsed here is the existing repair/review clock, independent of private diagnostic execution.
        after["elapsed_execution_millis"]=old["elapsed_execution_millis"]+age
    need(after["estimated_remaining_millis"]>0,f"epoch {e} forecast expired; publish a corrected evidence-backed event")
    return after,archive
def follow_event(e,ref,etag,raw):
    prior=checked(ref)
    if prior["after_etag"]==etag and prior["after_sha256"]==digest(raw) and prior["after_status"]==json.loads(raw):return ref,prior
    if e == replay167_rate.EPOCH:
        return replay167_event.follow(ref,etag,raw)
    need(e not in IDS,"canonical remote status changed; reconcile current owner's event")
    # Follow a finite, hash-and-ETag-linked chain of root-owned corrections.
    events=[]
    for p in STATUS_ROOT.glob("event-*/RECEIPT.json"):
        if p.lstat().st_uid!=0:continue
        v=content(p)
        if v.get("epoch")==e and v.get("authenticated_readback") and v.get("current_repair_owner")=="/root":events.append((p,v))
    seen=set()
    while ref["sha256"] not in seen:
        seen.add(ref["sha256"])
        matches=[(p,v) for p,v in events if v.get("previous_receipt")==ref and v.get("before_etag")==prior["after_etag"] and v.get("before_sha256")==prior["after_sha256"] and v.get("before_status")==prior["after_status"] and v.get("after_status",{}).get("phase")=="verification"]
        need(len(matches)==1,f"unbound R2 change for epoch {e}; reconcile the exact status event")
        p,prior=matches[0];ref=bound(p)
        if prior["after_etag"]==etag and prior["after_sha256"]==digest(raw) and prior["after_status"]==json.loads(raw):return ref,prior
    raise ValueError("cyclic status event chain")
def proof(c,e,ref,prior,etag,raw):
    old=prior["after_status"];after,archive=forecast(c,e,old)
    result = dict(schema="horizon-status-only-range-refresh-v1",epoch=e,key=key(e),sampled_at_utc=c.stamp,
        before_status=old,before_etag=etag,before_sha256=digest(raw),after_status=after,after_sha256=digest(body(after)),
        previous_receipt=ref,conditional_header="If-Match",current_repair_owner=None if e in IDS else "/root",
        current_replay_lanes=sum(c.advancing.values()),canonical_producer_count=3,active_bootstraps=0,
        producer_invocation_id=IDS[e][0] if e in IDS else None,epoch_useful_work=c.lanes[e]["useful_work"] if e in IDS else None,
        native_identity=c.native.get(str(e)),archive_sample=archive,observer=c.sample_ref,fleet_predecessor=status_predecessor(c),terminal172_closure=c.fleet["terminal172_closure"],metered172_closure=c.fleet["metered172_closure"],terminal169_transfer=c.fleet["terminal169_transfer"],
        current_retry9_replay_event=c.fleet["current_retry9_replay_event"],historical_epoch170_closures=c.closures,
        latest_terminal_retry8_170=c.fleet["latest_terminal_retry8_170"],private_diagnostic_admission=DIAG_REF,
        coordinated_private_diagnostic_168=c.diagnostic if e==168 else None,coordinated_private_diagnostic_169=c.diagnostic169 if e==169 else None,measured_canonical_progress=c.advancing.get(e,False),
        estimate_model="Clean positive slot growth over at least 60 seconds plus 10 percent and 12 hours. Otherwise retain the authenticated absolute forecast.",
        archive_publication_authorized=False,replay_launch_authorized=False)
    if e == replay167_rate.EPOCH:
        result.update(estimate_model=replay167_rate.MODEL, rolling_rate_evidence=c.rolling167)
    return result
def receipt_identity(v,c,e):
    need(v["epoch"]==e and v["key"]==key(e) and v["observer"]==c.sample_ref and v["fleet_predecessor"]==status_predecessor(c) and v["after_sha256"]==digest(body(v["after_status"])) and v["conditional_header"]=="If-Match","existing cycle evidence is foreign")
    p=checked(v["previous_receipt"]);need(p["authenticated_readback"] and p["after_etag"]==v["before_etag"] and p["after_sha256"]==v["before_sha256"] and p["after_status"]==v["before_status"],"broken intent predecessor")
def publish(c,storage):
    ready=inventory(c,storage);out=c.paths["statuses"];ensure_dir(out);fd=lock(out/"cycle.lock")
    try:return _publish(c,storage,out,ready)
    finally:os.close(fd)
def _publish(c,storage,out,ready):
    complete=out/"COMPLETED.json"
    if complete.exists():
        v=content(complete)
        need(v["observer"]==c.sample_ref and v["fleet_predecessor"]==status_predecessor(c) and set(map(int,v["receipts"]))==set(EPOCHS),"foreign completed status set")
        for k,ref in v["receipts"].items():
            r=checked(ref); etag,data=storage.get(int(k))
            need(r["authenticated_readback"] and r["after_etag"]==etag and digest(data)==r["after_sha256"],"completed remote status superseded; reconcile owner")
        return bound(complete)
    c.public_fresh();plan=[];receipts={};newer={}
    for e in EPOCHS:
        ip=out/f"epoch-{e}.intent.json";rp=out/f"epoch-{e}.receipt.json"
        etag,data=storage.get(e)
        if rp.exists():
            r=content(rp);receipt_identity(r,c,e)
            need(ip.exists() and all(r[k]==x for k,x in content(ip).items()) and r["authenticated_readback"] and r["after_etag"]==etag and r["after_sha256"]==digest(data),"partial cycle receipt no longer matches R2")
            receipts[str(e)]=bound(rp);continue
        if ip.exists():
            r=content(ip);receipt_identity(r,c,e)
            need((etag==r["before_etag"] and digest(data)==r["before_sha256"]) or (data==body(r["after_status"]) and digest(data)==r["after_sha256"]),"partial conditional outcome changed on R2")
        else:
            ref,prior=follow_event(e,c.prior["receipts"][str(e)],etag,data)
            if utc(prior["after_status"]["sampled_at_utc"])>c.now:
                need(e not in IDS and prior["current_repair_owner"]=="/root","newer canonical status would be overwritten")
                receipts[str(e)]=newer[str(e)]=ref;continue
            r=proof(c,e,ref,prior,etag,data)
        plan.append((e,ip,rp,r))
    # Validate the complete cohort before creating the first conditional write.
    for e,ip,rp,r in plan:
        c.unchanged();c.public_fresh();durable(ip,r)
        etag,data=storage.get(e);expected=body(r["after_status"])
        if etag==r["before_etag"] and digest(data)==r["before_sha256"]:
            sent=storage.put(e,etag,expected);after_etag,after=storage.get(e)
            need(after_etag==sent and after==expected,"R2 conditional PUT readback differs");recovery=False
        else:
            need(data==expected and digest(data)==r["after_sha256"],"R2 changed after intent; inspect partial cycle")
            after_etag=etag;recovery=True
        durable(rp,dict(r,authenticated_readback=True,after_etag=after_etag,verified_at_utc=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),already_published_intent_read_back=recovery))
        receipts[str(e)]=bound(rp)
    need(set(map(int,receipts))==set(EPOCHS),"incomplete writes")
    c.unchanged()
    durable(complete,dict(schema="horizon-status-full-range-audit-v1",owner="/root",primary_thread=c.fleet["primary_thread"],
        observer=c.sample_ref,fleet_predecessor=status_predecessor(c),terminal172_closure=c.fleet["terminal172_closure"],metered172_closure=c.fleet["metered172_closure"],terminal169_transfer=c.fleet["terminal169_transfer"],inventory=c.prior["inventory"],sampled_at_utc=c.stamp,
        authenticated_status_count=19,all_nineteen_existing_statuses_authenticated=True,active_report_keys=list(EPOCHS),status_epochs=list(EPOCHS),
        authenticated_ready_pairs=len(ready),ready_epochs=ready,remaining_epochs=sorted(set(range(101,201))-set(ready)),authenticated_readback=True,
        receipts=receipts,newer_events_read_back_without_overwrite=newer,replay_lanes=sum(c.advancing.values()),active_bootstraps=0,
        active_producer_count=5,canonical_producer_count=3,active_private_diagnostic_count=2,archive_or_sidecar_mutations=False,
        current_retry9_replay_event=c.fleet["current_retry9_replay_event"],latest_terminal_retry8_170=c.fleet["latest_terminal_retry8_170"],
        coordinated_private_diagnostic_168=c.diagnostic,coordinated_private_diagnostic_169=c.diagnostic169,effective_status_predecessor=c.fleet["authenticated_status_audit"]))
    return bound(complete)
if __name__=="__main__":
    need(len(sys.argv)==4,"usage: status.py PREVIOUS_FLEET FLEET_SHA SAMPLE_SHA")
    os.umask(0o077);print(json.dumps(publish(Cycle(*sys.argv[1:]),Storage())))
