"""Carry the clean V5 terminal without releasing the prior epoch 143 booking."""
import json
from pathlib import Path

from derive143_bootstrap_retry import change
from derive143_held_retry import edit
from second143_v5_completion import TERMINAL


def apply_completion(files):
    def owner(source):
        return change(source, '    if native["ActiveState"] == "inactive":\n', '''    if native["ActiveState"] == "inactive" and (SECOND / "HELD_OWNER.json").exists():
        completed = runpy.run_path(str(Path(__file__).with_name("second143_v5_completion.py")))["closed"]
        return dict(closure, second_v5_complete_terminal=completed(core, fleet)), None
    if native["ActiveState"] == "inactive":
''')

    edit(files, 'shared_hourly143.py', owner)
    edit(files, 'capacity.py', lambda source: change(source,
        "'second143_floor_terminal.py','price143_floor_retry.py'",
        "'second143_floor_terminal.py','second143_v5_completion.py','price143_floor_retry.py'"))
    files['second143_v5_completion.py'] = (Path(__file__).with_name('second143_v5_completion.py').read_bytes(), 0o444)
    source = json.loads(files['SOURCE.json'][0])
    source['second_v5_complete_terminal'] = TERMINAL
    files['SOURCE.json'] = ((json.dumps(source, indent=2)+'\n').encode(), 0o444)
