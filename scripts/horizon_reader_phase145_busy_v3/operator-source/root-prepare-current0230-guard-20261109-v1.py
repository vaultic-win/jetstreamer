from pathlib import Path
import os,json,hashlib,shutil
old=Path('/tmp/root-current0200-window-source-20261109-v2');packet=Path('/tmp/root-current0230-window-source-20261109-v1');packet.mkdir(mode=0o700)
base=Path('/home/sol/.jetstreamer-private');p=base/'first-lane-full-reader-witness-qualification-20261107-v1/combined-runtime/current0230-window-20261109-v1';p.mkdir(mode=0o700);(p/'source').mkdir(mode=0o700);(p/'work/tmp').mkdir(parents=True,mode=0o700)
sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(f,v):
 raw=(json.dumps(v,indent=2)+'\n').encode() if not isinstance(v,str) else v.encode();fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as h:h.write(raw);h.flush();os.fsync(h.fileno())
 fd=os.open(f.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def adapt(s):return s.replace('current0200','current0230').replace('1794189622','1794191422').replace('1_794_189_622','1_794_191_422').replace('2026-11-09T02:00:22Z','2026-11-09T02:30:22Z').replace('20261109-v1-root-r2','20261109-v1')
for f in old.rglob('*'):
 if not f.is_file():continue
 dest=packet/f.relative_to(old);dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);save(dest,adapt(f.read_text()))
source=packet/'source/main.rs';assert '1_794_191_422' in source.read_text();save(p/'source/main.rs',source.read_text())
bookingroot=base/'current0230-guard-window-booking-20261109-v1';bookingroot.mkdir(mode=0o700)
prev=base/'current-reader-phase145-busy-recovery-qa-20261109-v3/ROOT_NORMAL6_PHASE145_BUSY_DATA512_BOOKING.json';assert json.loads(prev.read_text())['complete_DATA_bytes']==5165115454100
book=dict(schema='horizon-normal6-current0230-guard-booking-v1',owner='/root',previous=b(prev),previous_retained_DATA_lower_bound_bytes=5165115454100,new_retained_DATA_bytes=536870912,complete_DATA_bytes=5165652325012,normal_pool_bytes=6<<30,extra_QA_bytes=0,one_serial_compiler_bytes=512<<20,all_failed_original_actor_and_DATA_promises_retained=True,no_replay_or_resource_credit=True)
save(bookingroot/'ROOT_NORMAL6_CURRENT0230_GUARD_DATA512_BOOKING.json',book);save(p/'ROOT_QA_EXACT_BOOKING.json',dict(book,actual_original_booking=b(bookingroot/'ROOT_NORMAL6_CURRENT0230_GUARD_DATA512_BOOKING.json')))
v=json.loads((packet/'SOURCE_ONLY_MANIFEST.json').read_text());v.update(source_sha256=sha(source),root_QA_directory=str(p),canonical_DATA_before_guard_booking_bytes=5165115454100,minimum_complete_DATA_after_guard_booking_bytes=5165652325012,root_actual_guard_booking=b(bookingroot/'ROOT_NORMAL6_CURRENT0230_GUARD_DATA512_BOOKING.json'),booking_not_created=False,source_base='Actual accepted0200R2source. Exact timestamp+currentdirectory advanced to0230, all65testnames preserved.')
(packet/'SOURCE_ONLY_MANIFEST.json').write_text(json.dumps(v,indent=2)+'\n')
print(p)
