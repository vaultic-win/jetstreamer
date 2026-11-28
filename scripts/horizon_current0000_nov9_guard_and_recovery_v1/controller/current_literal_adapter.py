import ast, re
SAMPLE_UTC = '2026-11-09T00:00:22Z'
SAMPLE_UNIX = 1794182422
MAPPING = {'230022': '000022', '23:00:22': '00:00:22', '2300': '0000', '223022': '230022', '22:30:22': '23:00:22', '2230': '2300'}
PATTERN = re.compile('|'.join((re.escape(k) for k in MAPPING)))
HASH = re.compile('([a-f0-9]{64}|(?<!\\d)20\\d{6}(?!\\d))')

def literal(value):
    parts = HASH.split(value)
    result = ''.join((part if i % 2 else PATTERN.sub(lambda m: MAPPING[m[0]], part) for i, part in enumerate(parts)))
    assert HASH.findall(result) == HASH.findall(value)
    return result

def adapt(source):
    tree = ast.parse(source)
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    joined = {id(n) for j in ast.walk(tree) if isinstance(j, ast.JoinedStr) for n in ast.walk(j) if isinstance(n, ast.Constant)}
    edits = []
    for node in ast.walk(tree):
        value = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            changed = literal(node.value)
            if changed != node.value:
                assert id(node) not in joined, 'dynamic f-string requires explicit review'
                value = repr(changed)
        elif isinstance(node, ast.Constant) and node.value == 1794178822:
            value = str(SAMPLE_UNIX)
        if value is not None:
            edits.append((offsets[node.lineno - 1] + node.col_offset, offsets[node.end_lineno - 1] + node.end_col_offset, value))
    previous = len(source) + 1
    for start, end, value in sorted(edits, reverse=True):
        assert end <= previous, 'overlapping AST edit'
        source = source[:start] + value + source[end:]
        previous = start
    ast.parse(source)
    return source
