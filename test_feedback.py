# ==============================================================
# Test Feedback Loop with simulated time
# ==============================================================

import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from omega import Config, InputVector, WorkloadClass, PerformanceState
from feedback_loop import FeedbackLoop, input_to_snapshot, decision_to_dict

# Use a fresh directory for this test
TEST_DIR = os.path.expanduser("~/omega/test_feedback_tmp")
os.makedirs(TEST_DIR, exist_ok=True)

os.environ["OMEGA_DIR"] = TEST_DIR

# Reload module with new OMEGA_DIR
import importlib
import feedback_loop
importlib.reload(feedback_loop)

print()
print("=" * 60)
print("  Feedback Loop Test (simulated time)")
print("=" * 60)
print()

fb = feedback_loop.FeedbackLoop()

# Simulate 3 decisions with fake timestamps
print("[1] Logging 3 decisions...")

for i, (cpu, temp, batt) in enumerate([
    (10, 35, 80),
    (25, 38, 78),
    (60, 42, 75),
]):
    snap = {
        "cpu": cpu,
        "ram": 50,
        "temp_soc": temp,
        "battery": batt,
        "power_source": 0,
        "workload": int(WorkloadClass.LIGHT),
    }
    dec = {
        "state": int(PerformanceState.BALANCED),
        "tier": 0,
        "thermal": 0,
        "cpu_cap": 100,
        "gpu_cap": 100,
        "reason": f"test #{i+1}",
    }
    r = fb.log_decision(snap, dec, {})
    # Manually backdate to make it "old"
    r.ts = int((time.time() - 120) * 1000)
    print(f"    logged id={r.record_id} cpu={cpu}% temp={temp}C")

print()
print("[2] Current stats:")
for k, v in fb.stats().items():
    print(f"    {k}: {v}")

# Now simulate "current" state — 2 minutes later
print()
print("[3] Evaluating pending decisions...")
current_snap = {
    "cpu": 5,          # CPU dropped
    "ram": 45,
    "temp_soc": 32.0,  # Cooled down
    "battery": 79,     # Slight drain
    "power_source": 0,
    "workload": 0,
}
fb.evaluate_pending(current_snap)

print()
print("[4] After evaluation:")
for k, v in fb.stats().items():
    print(f"    {k}: {v}")

# Print each decision's outcome
print()
print("[5] Decision outcomes:")
for r in fb.evaluated:
    print(f"    id={r.record_id} score={r.score} outcome={r.outcome}")

# Now tune
print()
print("[6] Attempting tune (need 20 samples):")
result = fb.tune()
print(f"    {result}")
print()

