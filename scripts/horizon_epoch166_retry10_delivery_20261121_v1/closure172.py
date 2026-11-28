"""Native archive and timer closure for the original full epoch 172 producer."""
import json
from pathlib import Path
import runpy
import subprocess

shared = runpy.run_path(str(Path(__file__).resolve().with_name("closure.py")))
R = shared["R"]
T = R / "epoch172-current-delivery-20261121-v1"
D = R / "epoch172-full-half-core-20261120-v1"
FIELD = "full172_local_commit"
UNIT = "horizon-qualify-172-full-half-core-20261120-v1.service"
IID = "0e17b745938546608b0bdc52815151d0"
TIMER = "horizon-guard-172-full-half-core-20261120-v1.timer"
TIMER_IID = "6259c4f5ba654513a1903fc693e4f6a9"
FIRST_WORKER = D / "FIRST_PROTECTED_HISTORICAL_WORKER_20261121.json"
document, need = shared["document"], shared["need"]


class FullGuard(shared["GuardClosure"]):
    def original(self):
        live, lr = document(T / "LIVE.json", 0o600, self.witness_hash)
        admission, ar = document(D / "ACTUAL_ADMISSION_AND_PROTECTION.json", 0o444, self.admission_hash)
        worker, wr = document(FIRST_WORKER, 0o400, self.worker_hash)
        first, fr = document(D / "FIRST_GUARD.json", 0o444, "622ec96e45f536527412f118c7ea8896958347fef6a13b8b7f91911f695f763d")
        plan, pr = document(D / "ACTUAL_GUARD_PLAN.json", 0o444, "3b9b6fd4c2c713065749c1ce8bda7aed00e30ed19df341b09b3cff92bb1f9472")
        need(live["admission"] == ar and live["first_protected_worker"] == wr and live["first_guard"] == admission["first_guard"] == fr
             and live["actual_guard_plan"] == admission["actual_guard_plan"] == pr
             and plan["unit"] == admission["producer_unit"] == UNIT and plan["invocation_id"] == admission["producer_invocation_id"] == IID
             and plan["maximum_root_physical_bytes"] == live["reserved_disk_bytes"] == 288 << 30
             and plan["worker_root"] == live["booked_tree"]["path"] and plan["filesystem"] == "/home/sol"
             and worker["worker_pid"] == live["native"]["worker"]["pid"] and worker["worker_start_ticks"] == live["native"]["worker"]["start_ticks"]
             and worker["observer_row"]["expected_producer_invocation_id"] == IID and first["genuine_first_timer_driven_success"],
             "different full 172 admission, worker, guard or tree")
        for timer in (first["timer"], worker["worker_guard"]["timer"], live["native"]["timer"]):
            need(timer["Id"] == TIMER and timer["InvocationID"] == TIMER_IID and timer["ActiveState"] == "active"
                 and timer["Triggers"] == self.guard_service and not timer["Job"], "different original 172 timer")
        return live, lr, ar, wr

    def committed(self):
        terminal, tr = document(T / "TERMINAL_SUCCESS.json", 0o400)
        live, lr, ar, wr = self.original()
        self.validate_terminal(terminal, live, lr, ar, wr)
        tool = T / "terminal-tools/terminal172"
        shared["member"](tool, 0o555, self.terminal_program_hash, 8 << 20)
        need(json.loads(subprocess.check_output([tool, "inspect"], timeout=45)) == terminal
             and not any((D / "guard-receipts").glob("stop-*.json")), "original 172 terminal changed or guard stopped producer")
        return dict(terminal=tr, admission=ar, first_worker=wr, live=lr, producer_invocation_id=IID,
                    timer_unit=TIMER, timer_invocation_id=TIMER_IID, guard_unit=self.guard_service, resource_credit_bytes=0)


guard = FullGuard(172, T, D, UNIT, IID, TIMER, TIMER_IID,
                  "4d4e760ba2d4cb53368cfc7c616044f789f82f66934499ad91e5797f41cf6dc2",
                  "c1dc591288eca1a2f6e2ab37888c57f108d2d25e6639d292d612def83ff2f2df", 0o444,
                  "165d1600fb91aebef3903532ed997db46658f8901d765c49e3550fb548c39148",
                  "fa1330215d2d6238f432fc32e3352a9332e729d75aa49c34b39852131973bb0b", 0o400)
DONE = guard.completion_path
committed = guard.committed
retire = guard.retire
inspect = guard.inspect
