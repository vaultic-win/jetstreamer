"""Join the two admitted singleton replays with the existing cadence."""
import replay257
import replay261

SINGLETONS = {257: replay257, 261: replay261}


def epoch(replay):
    first, last = replay["range"].split("-")
    assert first == last and int(first) in SINGLETONS
    return int(first)


def by_epoch(rows):
    result = {epoch(row): row for row in rows}
    assert len(result) == len(rows)
    return result


def config():
    return [row for lane in SINGLETONS.values() for row in lane.config()]


def validate_observation(observed, configured):
    actual, expected = by_epoch(observed), by_epoch(configured)
    assert set(actual) == set(expected)
    for number, lane in SINGLETONS.items():
        lane.verify_replays(
            [actual[number]] if number in actual else [],
            [expected[number]] if number in expected else [],
        )


def gate(plan, configured):
    expected = by_epoch(configured)
    for number, lane in SINGLETONS.items():
        lane.gate(plan, [expected[number]] if number in expected else [])


def refresh(number, previous, sample, cycle):
    row = by_epoch(sample["replays"])[number]
    SINGLETONS[number].refresh(previous, dict(sample, replays=[row]), cycle)


def validate_fleet(active, observed):
    replays = by_epoch(observed)
    rows = {row["epoch"]: row for row in active}
    assert len(rows) == len(active) and set(rows) == set(replays)
    for number, row in rows.items():
        sample = replays[number]
        assert row["phase"] == "replay" and sample["invocation_binding_stable"]
        assert row["scratch_path"] == sample["scratch_path"]
        for role in ("controller", "producer"):
            identity = sample[f"{role}_after"]
            assert identity["unit"] == SINGLETONS[number].UNIT == row[role]["Id"]
            assert identity["invocation_id"] == row[role]["InvocationID"]
