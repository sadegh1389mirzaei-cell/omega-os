import os
import sys
import time

sys.path.insert(0, os.path.expanduser("~/omega"))

# Use isolated directory
TEST_DIR = os.path.expanduser("~/omega/test_correct_tmp")
os.makedirs(TEST_DIR, exist_ok=True)
os.environ["OMEGA_DIR"] = TEST_DIR

import importlib
import feedback_loop
importlib.reload(feedback_loop)

fb = feedback_loop.FeedbackLoop()

print()
print("=" * 60)
print("  Test: Realistic Data (not fake)")
print("=" * 60)
print()

# --- Scenario 1: battery slightly drops on battery ---
print("[1] Battery drops 75 -> 74, on battery")
old = {
    "cpu": 30, "ram": 55, "temp_soc": 38.0,
    "battery": 75, "power_source": 0, "workload": 2,
}
dec = {
    "state": 1, "tier": 0, "thermal": 0,
    "cpu_cap": 100, "gpu_cap": 100, "reason": "test1",
}
r1 = fb.log_decision(old, dec, {})
r1.ts = int((time.time() - 120) * 1000)

new = {
    "cpu": 25, "ram": 55, "temp_soc": 36.0,
    "battery": 74, "power_source": 0, "workload": 2,
}
fb.evaluate_pending(new)
print(f"    score={r1.score}  outcome={r1.outcome}")
print()

# --- Scenario 2: on charger, battery grows ---
print("[2] On charger, battery grows 60 -> 65")
old2 = {
    "cpu": 20, "ram": 50, "temp_soc": 35.0,
    "battery": 60, "power_source": 1, "workload": 0,
}
dec2 = {
    "state": 0, "tier": 0, "thermal": 0,
    "cpu_cap": 100, "gpu_cap": 100, "reason": "test2",
}
r2 = fb.log_decision(old2, dec2, {})
r2.ts = int((time.time() - 120) * 1000)

new2 = {
    "cpu": 15, "ram": 50, "temp_soc": 34.0,
    "battery": 65, "power_source": 1, "workload": 0,
}
fb.evaluate_pending(new2)
print(f"    score={r2.score}  outcome={r2.outcome}")
print()

# --- Scenario 3: heavy load, temp rises ---
print("[3] Heavy load, temp rises 40 -> 47")
old3 = {
    "cpu": 80, "ram": 70, "temp_soc": 40.0,
    "battery": 50, "power_source": 0, "workload": 5,
}
dec3 = {
    "state": 2, "tier": 0, "thermal": 1,
    "cpu_cap": 100, "gpu_cap": 100, "reason": "test3",
}
r3 = fb.log_decision(old3, dec3, {})
r3.ts = int((time.time() - 120) * 1000)

new3 = {
    "cpu": 85, "ram": 72, "temp_soc": 47.0,
    "battery": 47, "power_source": 0, "workload": 5,
}
fb.evaluate_pending(new3)
print(f"    score={r3.score}  outcome={r3.outcome}")
print()

# --- Final summary ---
print("=" * 60)
print("  Summary")
print("=" * 60)
print()
print(f"  Total decisions : {len(fb.records)}")
print(f"  Evaluated       : {len(fb.evaluated)}")
print(f"  Average score   : {fb.stats()['avg_score']}")
print()
print("  Expected outcomes:")
print("    [1] efficient      (battery drops 1%, on battery)")
print("    [2] on_charger     (charger connected)")
print("    [3] overheating    (temp jumped 7C)")
print()
