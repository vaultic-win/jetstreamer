"""Derive the single existing sealed pricing function with an explicit idle CPU profile."""
import hashlib
from pathlib import Path
import sys

EXPECTED='36d946d97f5c1f9575965d80a2aa0da245097cd82da677f911fe5082522ec852'
OLD='''    audit_group=Path("/sys/fs/cgroup/horizonaudit.slice")
    s.need((audit_group/"cpu.max").read_text().split()==["400000","100000"]
           and int((audit_group/"memory.max").read_text())==24*G and int((audit_group/"memory.swap.max").read_text())==0,
           "changed native audit allocation")'''
HEADER='''"""Existing epoch 168 host allocation equation with the sealed shared audit CPU policy."""
from pathlib import Path
import runpy
from fit import ANCHOR, BASELINE, CAP, G, MEM, F169, P169, BOOK
import status168 as s
observe_cpu=runpy.run_path(str(Path(__file__).with_name('idle_audit_cpu.py')))['profile']
'''

def derive(predecessor,output):
    data=predecessor.read_bytes()
    if hashlib.sha256(data).hexdigest()!=EXPECTED:
        raise ValueError('unexpected predecessor pricing source')
    text=data.decode();start=text.index('def floor(');end=text.index('\ndef ',start+1)
    original=text[start:end]
    if original.count(OLD)!=1:
        raise ValueError('unexpected audit envelope in pricing function')
    code=HEADER+'\n'+original.replace(OLD,'    observe_cpu()')+'\n'
    compile(code,'idle_floor.py','exec')
    output.write_text(code)

if __name__=='__main__':
    derive(Path(sys.argv[1]),Path(sys.argv[2]))
