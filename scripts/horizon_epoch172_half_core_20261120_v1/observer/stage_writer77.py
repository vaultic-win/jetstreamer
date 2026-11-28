"""Install post-replay support in an immutable successor of the original V76 package."""
import ast
import os
from pathlib import Path
import sys
import re

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path[:0] = [str(REPO/"scripts/horizon_epoch170_checkpoint_suffix"),
                str(REPO/"scripts/horizon_epoch143_bounded_entry_20261126_v1/writer")]
import stage_next_hourly170_cadence as v76
from following_prepare import git, need, reference, save, seal
from closed_successor import persist
from derive_ram170_writer import once

OLD = v76.NEW
NEW = OLD.with_name("tools-cold168-retry5-failed166-v77-entry146")
CONTROL = v76.RUNTIME/"epoch172-current-delivery-20261121-v1"
OLD_SEAL = "dbd4f4fd773442371e2043ba58293b01338bc6d068b27bc8ef253d6e987e5dc4"
ACTIVE = "50c63b7091977e256d3184b59b7ebfad6a61cc98a5db6e2658d19b33fa36d3d1"


def cycle(raw):
    code = v76.lift(raw,76,77)
    code = once(code,"import cold167_status\n","import cold167_status\nimport finalizing172\n")
    code = once(code,"    owners_by_epoch={","    original=finalizing172.effective(original)\n    owners_by_epoch={")
    code = once(code,"    need(owners_by_epoch['172']['producer_unit']==full172.UNIT,'changed survivor')",
                "    need('172' not in owners_by_epoch,'finished epoch 172 returned to replay')")
    code = once(code,"def check_sample(fleet, sample, cfg):","SURVIVOR_CONFIGS += ((),)\n\ndef check_sample(fleet, sample, cfg):\n    cfg = finalizing172.effective(cfg)")
    code = once(code,"    sample=checked(sample_ref);when=check_sample(fleet,sample,cfg)",
               "    cfg=finalizing172.effective(cfg)\n    sample=checked(sample_ref);when=check_sample(fleet,sample,cfg)")
    start=code.index("    old=full172.owned(fleet);")
    end=code.index("    if FAILED166_VERSION >= 34:",start)
    need("full172.reconcile_sample(c,cycle.observed_lane)" in code[start:end],"different live 172 read")
    code=code[:start]+"""    c.original172=finalizing172.observe(fleet)
    ident=c.original172["identity"]
    c.full172=None
    c.full172_row=None
"""+code[end:]
    start=code.index("        if epoch==172:\n")
    end=code.index("        elif epoch in (168, 170) and commit:",start)
    code=code[:start]+"""        if epoch==172:
            after,extra=finalizing172.publish(c,old,prior)
"""+code[end:]
    for before,after in (
        ("surviving_epoch172_protection=c.full172","current_full172_finalization=c.original172"),
        ("arc=status.observed_archive(c,172) if c.full172_row['scratch_path'] else None","arc=c.original172['archive_result']"),
        ("lookup[172].update(current_replay=c.full172_row,current_repair_owner=None,no_live_producer_claimed=False,state='executing')",
         "finalizing172.install(fleet,c,lookup[172])"),
        ("actual_executing_replays=[c.full172_row]","actual_executing_replays=[]"),
        ("useful_replay_count=int(c.advancing[172]),live_replay_count=1,active_producer_count=1,canonical_producer_count=1",
         "useful_replay_count=0,live_replay_count=0,active_producer_count=0,canonical_producer_count=0"),
        ("Single surviving canonical replay 172. Four HOME guard closures and terminal 169. All twenty status keys are authenticated.",
         "Original epoch 172 replay reached its terminal Bank. Its verification and delivery remain tracked."),
    ):
        code=once(code,before,after)
    need(code.count("sorted([172,*c.new_rows])")==2,"different survivor count")
    code=code.replace("sorted([172,*c.new_rows])","sorted(c.new_rows)")
    return code


def stage():
    source=v76.read_package(OLD,OLD_SEAL)
    files={name:(OLD/name,mode) for name,(_,mode) in source.items() if name!="SHA256SUMS"}
    def text(name): return source[name][0].decode()
    updates={name:(HERE/name).read_text() for name in ("transition_v77.py","finalizing172.py","recover77.py")}
    updates["status_cycle.py"]=cycle(text("status_cycle.py"))
    updates["cold167_status.py"]=once(text("cold167_status.py"),"canonical_producer_count=1+len(rows)","canonical_producer_count=len(rows)")
    for name in ("full170_status.py","cold170_status.py","joint168_status.py"):
        anchor=repr(OLD.name)+")"
        need(anchor in text(name),"different V76 program allowlist "+name)
        updates[name]=text(name).replace(anchor,repr(OLD.name)+", "+repr(NEW.name)+")")
    cut=re.sub(r"(cutover|[vV])(75|76)",lambda m:m[1]+str(int(m[2])+1),text("cutover76.py"))
    cut=re.sub(r"^OLD = BASE / .*$","OLD = BASE / "+repr(OLD.name),cut,flags=re.M)
    cut=re.sub(r"^NEW = BASE / .*$","NEW = BASE / "+repr(NEW.name),cut,flags=re.M)
    cut=re.sub(r'^ORIGINAL_SEAL = ".*"$','ORIGINAL_SEAL = '+repr(OLD_SEAL),cut,flags=re.M)
    cut=re.sub(r'^OLD_OWNER = ".*"$','OLD_OWNER = '+repr(ACTIVE),cut,flags=re.M)
    updates["cutover77.py"]=cut
    revision=git(REPO,"rev-parse","HEAD").decode().strip()
    tracked=[Path(__file__).resolve(),*(HERE/n for n in ("transition_v77.py","finalizing172.py","recover77.py"))]
    git(REPO,"merge-base","--is-ancestor",revision,"origin/account-updates")
    for f in tracked:
        need(git(REPO,"show",f"{revision}:{f.relative_to(REPO)}")==f.read_bytes(),"unpublished writer input "+f.name)
    staging=CONTROL/"writer-v77-source"
    staging.mkdir(mode=0o700,exist_ok=True)
    need(staging.stat().st_uid==0 and staging.resolve(strict=True)==staging and not staging.stat().st_mode&0o077,"unsafe stage")
    for name,body in updates.items():
        ast.parse(body,filename=name)
        persist(staging/name,body.encode())
        files[name]=staging/name,source.get(name,(None,0o444))[1]
    src=save(staging/"SOURCE.json",dict(revision=revision,previous=reference(OLD/"deployment-seal-receipt.json"),
        active_owner=ACTIVE,source_sha256={str(f.relative_to(REPO)):reference(f)["sha256"] for f in tracked},
        updates=sorted(updates)))
    files["SOURCE.json"]=Path(src["path"]),0o444
    return seal(NEW,files,staging/"SEAL_PLAN.json")


if __name__=="__main__":
    import json
    need(os.geteuid()==0 and __debug__, "requires privileged sealer")
    print(json.dumps(stage(),sort_keys=True))
