"""Exact current0000 field bindings; historical dates, hashes and ETA anchors stay intact."""
import ast,json
from pathlib import Path
SAMPLE_UTC='2026-11-09T05:30:22Z'
SAMPLE_UNIX=1794202222
MAPPING=json.loads((Path(__file__).resolve().parent/'CURRENT0530_EXACT_LITERAL_MAP.json').read_text())
def literal(value):return MAPPING.get(value,value)
def adapt(source):
    tree=ast.parse(source);offsets=[0]
    for line in source.splitlines(keepends=True):offsets.append(offsets[-1]+len(line))
    joined={id(n) for j in ast.walk(tree) if isinstance(j,ast.JoinedStr) for n in ast.walk(j) if isinstance(n,ast.Constant)}
    edits=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Constant) and isinstance(n.value,str):
            v=literal(n.value)
            if v!=n.value:
                assert id(n) not in joined,'dynamic f-string requires explicit review'
                edits.append((offsets[n.lineno-1]+n.col_offset,offsets[n.end_lineno-1]+n.end_col_offset,repr(v)))
    previous=len(source)+1
    for start,end,v in sorted(edits,reverse=True):
        assert end<=previous
        source=source[:start]+v+source[end:];previous=start
    ast.parse(source);return source
