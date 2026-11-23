"""Stage the exact cadence changes needed to register epoch 257."""
import argparse
import hashlib
from pathlib import Path

BASELINE = {
    "cycle.py": "c9600fad0e56549171257afec8ab08627351e937f94656618cef538124b02a2f",
    "replay261.py": "c6c2de124bfb03fa846db22251d76660e421cce360edf9811eec220b378ac5f1",
    "native_binding_handoff.py": "1d27f40e0d6e3e150a385897322e5a572dc843099f4f951c1b9da8c00f9dc942",
}
CONTROLLER = Path("/var/lib/jetstreamer/horizon-seven-publication-controller-v222")


def replace_once(body, old, new):
    assert body.count(old) == 1, old
    return body.replace(old, new)


def load(name):
    raw = (CONTROLLER / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BASELINE[name], name
    return raw.decode()


def epoch_257():
    body = load("replay261.py").replace("261", "257")
    for old, new in (
        ("horizon257-full-admission-v227-a2", "horizon257-full-admission-after248-v1"),
        ("horizon257-full-profile-v226-a1", "horizon257-full-profile-v230-a1"),
        (
            "6b27a27ff1596fe6688f207d460566c51d5c9552cef47817358d2008b484f281",
            "0f94cde65866edcf0ff777e557da2b8d61aea907673b5f82a9a6cd3486129bdc",
        ),
        ("112751208<=last<=113183999", "111022755<=last<=111455999"),
        ("(113183999-last)", "(111455999-last)"),
        (
            "assert a['controller']==os.environ['CODEX_THREAD_ID'] and a['profile_sha256']==PROFILE_SHA",
            "assert a['controller']==os.environ['CODEX_THREAD_ID'] and a['profile_sha256']==PROFILE_SHA\n"
            "    assert a['schema']=='horizon257-full-admission-v1' and a['epoch']==257\n"
            "    assert token['schema']=='horizon257-full-first-guard-v1'",
        ),
    ):
        body = replace_once(body, old, new)
    return body


def cycle():
    body = load("cycle.py")
    for old, new in (
        ("import replay261\n", "import guarded_replays\n"),
        ("cfg['replays']=replay261.config()", "cfg['replays']=guarded_replays.config()"),
        (
            "    saved = bound(ref(out/'config.json'))",
            "    saved = bound(ref(out/'config.json'))\n    cfg['replays'] = saved['replays']",
        ),
        ("replay261.verify_replays(sample['replays'],cfg['replays'])",
         "guarded_replays.validate_observation(sample['replays'],cfg['replays'])"),
        ("replay261.gate(plan,cfg['replays'])", "guarded_replays.gate(plan,cfg['replays'])"),
        (
            "    assert sorted(r['epoch'] for r in f['active'])==sorted([*roster,*([261] if cfg['replays'] else [])])",
            "    assert sorted(r['epoch'] for r in f['active']) == sorted([*roster,*guarded_replays.by_epoch(cfg['replays'])])\n"
            "    guarded_replays.validate_fleet([r for r in f['active'] if r['epoch'] not in roster], "
            "bound(ref(obs))['replays'])",
        ),
        (
            "    from seven_status import refresh\n    for e,previous",
            "    from seven_status import refresh\n    replays = guarded_replays.by_epoch(cfg['replays'])\n    for e,previous",
        ),
        (
            "if e==261 and cfg['replays']:replay261.refresh(previous,sample,globals())",
            "if e in replays: guarded_replays.refresh(e,previous,sample,globals())",
        ),
        ("T/'native_binding_handoff.py', str(n)", "T/'native_binding_replays.py', str(n)"),
    ):
        body = replace_once(body, old, new)
    return body


def native_binding():
    return replace_once(
        load("native_binding_handoff.py"),
        "assert all(r['epoch']==261 and r['phase']=='replay' for r in f['active'] if r not in sample_publishers)",
        "import guarded_replays\n"
        "guarded_replays.validate_fleet([r for r in f['active'] if r not in sample_publishers], bound(obs)['replays'])",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    for name, body in {
        "cycle.py": cycle(),
        "native_binding_replays.py": native_binding(),
        "replay257.py": epoch_257(),
        "guarded_replays.py": Path(__file__).with_name("guarded_replays.py").read_text(),
    }.items():
        compile(body, name, "exec")
        with (args.output / name).open("x") as stream:
            stream.write(body)


if __name__ == "__main__":
    main()
