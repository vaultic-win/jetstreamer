from pathlib import Path
import ast, json, hashlib
p = Path(__file__).resolve().parent
for f in p.rglob('*.py'):
    ast.parse(f.read_text())
for row in json.loads((p / 'PARENT_SOURCE_BINDINGS.json').read_text()):
    assert hashlib.sha256(Path(row['prepared_source']).read_bytes()).hexdigest() == row['prepared_source_sha256']
from next_operation_bindings import next_operation_bindings
v = next_operation_bindings()
print(json.dumps({'static_operation31_authority': 'passed', 'operation': v['operation'], 'DATA_lower_bound': v['current_complete_DATA_lower_bound_bytes'], 'current_guard_qualification_separate': True}))
