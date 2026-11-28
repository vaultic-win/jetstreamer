"""Exercise both sides of the epoch-136/172 admission's scheduled observation overlap."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock, patch


def main():
    p = argparse.ArgumentParser()
    p.add_argument("fleet", type=Path)
    p.add_argument("digest")
    args = p.parse_args()
    path = Path(__file__).resolve().parent.parent / "horizon_epoch136_donor171_20261120_v1/public_audit.py"
    spec = importlib.util.spec_from_file_location("admission", path)
    admission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(admission)
    observer = admission.load_observer()
    import evidence
    ref = evidence.pair(args.fleet, args.digest)
    fleet = evidence.checked(ref)
    obligation = fleet["continuing_audit_obligation"]
    incumbent = admission.capture(observer, obligation)
    old_ref = incumbent["launch"]
    live, storage, owner = observer.observe_public(Path("/home/sol").stat().st_dev, obligation)
    old = evidence.checked(old_ref)
    native = dict(owner["native"], InvocationID="a"*32, MainPID="4000000")
    next_owner = dict(old, pid=int(native["MainPID"]), InvocationID=native["InvocationID"],
                      native=native, start_ticks=old["start_ticks"]+1)
    new_ref = evidence.pair(admission.V14 / "PUBLIC_OWNER.json", "a"*64)
    bound = evidence.pair(admission.V14 / "BOUNDARY.json", "b"*64)
    before = obligation["current_observation"]
    boundary = dict(prior_fleet=ref, prior_audit_observation=before)
    staged = dict(owner, native=native, launch=new_ref, previous_owner=old_ref,
                  natural_epoch73_boundary=bound)
    new_live = copy.deepcopy(live)
    new_live["progress"]["pid"] = next_owner["pid"]
    fake = Mock(deployment_sha256=observer.deployment_sha256)
    fake.native = Mock(spec=observer.native)
    fake.native.MAX_ARCHIVE = observer.native.MAX_ARCHIVE
    fake.native.RESERVE = observer.native.RESERVE
    fake.native.ticks.return_value = next_owner["start_ticks"]
    fake.native.native.return_value = native
    fake.observe_public.return_value = (new_live, storage, staged)
    real_checked = evidence.checked
    new_observation = evidence.pair(admission.V14/"NEW_TEST_OBSERVATION", "c"*64)
    def checked(r):
        if r == new_ref: return next_owner
        if r == bound: return boundary
        if r == new_observation: return new_live
        return real_checked(r)

    with patch.object(evidence, "checked", side_effect=checked):
        assert admission.capture(fake, obligation)["launch"] == new_ref
        assert admission.capture(fake, dict(obligation, current_observation=new_observation))["launch"] == new_ref
        rejected = 0
        for obj, key, bad in [
            (boundary, "prior_audit_observation", new_observation),
            (boundary, "prior_fleet", before),
            (staged, "previous_owner", new_ref),
            (new_live["progress"], "pid", old["pid"]),
            (new_live["progress"], "remote_mutations", True),
        ]:
            previous = obj[key]
            obj[key] = bad
            try:
                admission.capture(fake, obligation)
            except (KeyError, ValueError):
                rejected += 1
            else:
                raise AssertionError("accepted incorrect "+key)
            finally:
                obj[key] = previous
    print(json.dumps(dict(fleet=ref, sealed_adapter=observer.deployment_sha256,
                          incumbent_checked=incumbent["native"]["InvocationID"],
                          simulated_transition_before_and_after_cadence=True, negative_cases=rejected)))


if __name__ == "__main__":
    main()
