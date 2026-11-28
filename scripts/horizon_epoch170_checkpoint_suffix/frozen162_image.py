"""Price the frozen first interval's future materialization and keep its source in place."""
import json
import os
from pathlib import Path
import stat
import subprocess

G = 1 << 30
M = 1 << 20
IMAGE = Path('/home/sol/.jetstreamer-private/epoch162-first-hourly-completion-20261127-v2/mutable.ext4')
UNIT = 'horizon-qualify-162-first-hourly-completion-20261127-v2.service'
INVOCATION = 'e08ac6700a714ea0bf2d08a40516fc7e'
TERMINAL = '445b05009592b381506701162673494fe3d6deb3851a33adade0f4e44d6a64ad'
CUSTODY = dict(path='/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2/FIRST162_CLOSED_IMAGE_GROWTH_CUSTODY.json',sha256='cc70ce6ea6370abcace4135716c985176a05f4e3bfea19bf718eb4f0e5275f1e')
MATERIALIZED_SIZE = 1_787_236_876


def detached_image(need):
    # losetup --associated passes the backing inode/device to the kernel. An
    # attachment called by an alias of this file counts as the same backing.
    raw=subprocess.check_output(['/usr/sbin/losetup','--list','--json','--output','NAME,BACK-INO,BACK-MAJ:MIN,RO',
                                 '--associated',str(IMAGE)],timeout=10)
    need(json.loads(raw)=={'loopdevices':[]},'first 162 output image has an active loop attachment')


def reconcile(peer, base, first, final):
    need=peer['need']; reserved=final['prospective_162_interval_two']; image=reserved['retained_image']
    evidence=peer['bound'](CUSTODY);verification=peer['bound'](reserved['verification'])
    need('frozen_first_162_image' not in final and first['phase']=='terminal' and first['invocation_id']==INVOCATION
         and first['unit']['Id']==UNIT and first['unit']['ActiveState']=='inactive' and not first['unit']['ControlGroup']
         and first['terminal']['MESSAGE_ID']=='7ad2d189f7e94e70a38c781354912448'
         and not (Path('/sys/fs/cgroup/system.slice')/UNIT/'cgroup.procs').exists()
         and reserved['first_producer']==INVOCATION and reserved['verification']['sha256']==TERMINAL
         and image==verification['read_only_source_image'] and Path(image['path'])==IMAGE
         and verification['validated_derived_segment']['derived_size']==MATERIALIZED_SIZE
         and not verification['validated_derived_segment']['materialized']
         and verification['source_files_preserved'] and not verification['canonical_or_r2_writes']
         and reserved['retained_first_image_allowance']==peer['IMAGE']==8*G
         and reserved['additional_home']==3*G+64*M and first['profile']['control']==64*M and final['realized_162_ram']==0,
         'different 162 terminal, source or outstanding reservation')
    need(evidence['schema']=='anza-162-closed-image-custody-v1' and evidence['verified']==reserved['verification']
         and evidence['custody']['retained_image']==image and evidence['custody']['retained_stock']==reserved['retained_stock']
         and evidence['producer_invocation']==INVOCATION and evidence['held']==first['held_owner']
         and evidence['holders']==evidence['loop_attachments']==[] and evidence['future_image_growth_bytes']==0
         and not evidence['live_guard_floor_changed'] and evidence['previous_image_allowance']==peer['IMAGE']
         and evidence['protected_second_interval_home']==reserved['additional_home']
         and evidence['remaining_first_interval_home']==1_854_349_312 and evidence['obsolete_future_growth_bytes']==6_735_585_280,
         'different first interval custody or future materialization')
    for name, prior in evidence['unit_states'].items():
        current=peer['idle'](name)
        need(current['Id']==name and current['ActiveState']==prior['ActiveState']=='inactive' and not current['Job']
             and not current.get('ControlGroup'), 'original 162 owner or guard returned')
    st=IMAGE.lstat()
    need(IMAGE.resolve(strict=True)==IMAGE and stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink)==(0,0,1)
         and stat.S_IMODE(st.st_mode)==0o400 and [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]==image['identity']
         and st.st_dev==Path('/home/sol').stat().st_dev and st.st_blocks*512==1_791_680_512 and st.st_size==8*G,
         'first 162 retained inode or HOME allocation changed')
    detached_image(need)
    # Every armed floor in this geometry remains. The former image supplied
    # the only 8 GiB future-growth term outside the protected joint floor.
    change = reprice(need,base,final,os.statvfs(IMAGE).f_frsize)
    final['frozen_first_162_image']=dict(custody=CUSTODY,verification=reserved['verification'],source=image,
                                        occupied_home_bytes=st.st_blocks*512,**change)


def reprice(need, base, final, block):
    reserved=final['prospective_162_interval_two']
    need(reserved['retained_first_image_allowance']==8*G and reserved['additional_home']==3*G+64*M,'changed 162 charges')
    old=final['required_home']; horizon=base['available_home']; floor=final['guard_floor']
    need(old==floor+base['remaining_output']+8*G+reserved['additional_home'] and final['home_margin']==horizon-old
         and floor>=base['guard_floor'], 'different 162 HOME equation')
    need(block==4096,'different HOME allocation size')
    output=((MATERIALIZED_SIZE+block-1)//block)*block
    working=output+64*M
    final['required_home']=old-8*G+working
    final['home_margin']=horizon-final['required_home']
    final['fits']=bool(base['fits'] and min(final['home_margin'],final['ram_margin'])>=0)
    reserved['first_image_predecessor_reservation']=reserved['retained_first_image_allowance']
    reserved['retained_first_image_allowance']=0
    return dict(removed_future_growth=8*G,derived_output_bytes=MATERIALIZED_SIZE,rounded_output=output,
                separate_staging_cap=64*M,prospective_materialization_bytes=working,net_reduction=8*G-working,
                guard_floor_unchanged=floor,resource_credit_bytes=0)
