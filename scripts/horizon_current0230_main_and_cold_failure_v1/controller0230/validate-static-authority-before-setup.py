from pathlib import Path
import ast,json
p=Path(__file__).resolve().parent
for f in p.rglob('*.py'):ast.parse(f.read_text())
from actual0100_predecessors import actual0100_predecessors
actual0100_predecessors()
from prelaunch_phase199_binding import qualified_prelaunch_phase
phase=qualified_prelaunch_phase()
from next_operation_bindings import next_operation_bindings
authority=next_operation_bindings()
from qualified_bindings import current_guard
guard=current_guard()
assert authority['current_complete_DATA_lower_bound_bytes']>=5164578583188
print(json.dumps(dict(actual_qualified0230_authority='passed',operation=authority['operation'],phase=phase['program'],DATA_lower_bound=authority['current_complete_DATA_lower_bound_bytes'],guard=guard,source_is_not_replay=True)))
