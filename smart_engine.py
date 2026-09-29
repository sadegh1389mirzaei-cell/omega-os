# ==============================================================
# OMEGA OS - Smart Engine
# ==============================================================
# Wraps DecisionEngine with FeedbackLoop.
# Every decision is logged, evaluated, and tuned over time.
# ==============================================================

import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from omega import Config, DecisionEngine
from feedback_loop import (
    FeedbackLoop, input_to_snapshot, decision_to_dict,
)


class SmartEngine:
    """
    Decision Engine + Feedback Loop.
    Every decision gets logged and evaluated.
    """

    def __init__(self, cfg: Config = None):
        self.cfg = cfg or Config()
        self.engine = DecisionEngine(self.cfg)
        self.feedback = FeedbackLoop()
        self.last_decision_time = 0
        self.decisions_since_tune = 0
        self.tune_every_n = 20

    def evaluate(self, iv):
        # Evaluate pending feedback first
        snap_now = input_to_snapshot(iv)
        self.feedback.evaluate_pending(snap_now)

        # Run normal decision
        cmd = self.engine.evaluate(iv)

        # Log the decision
        decision = decision_to_dict(cmd)
        self.feedback.log_decision(snap_now, decision,
                                   {"cycle": self.decisions_since_tune})

        self.decisions_since_tune += 1
        self.last_decision_time = time.time()

        # Periodic tuning
        if self.decisions_since_tune >= self.tune_every_n:
            result = self.feedback.tune()
            self.decisions_since_tune = 0
            if result.get("status") == "tuned":
                print(f"[smart] tuned! avg_score="
                      f"{result['avg_score']} changes={result['changes']}")

        return cmd

    def stats(self):
        s = self.feedback.stats()
        s["engine_state"] = self.engine.state
        return s


if __name__ == "__main__":
    print()
    print("=" * 60)
    print("  OMEGA Smart Engine - Feedback Integration")
    print("=" * 60)
    print()

    from omega import InputVector, WorkloadClass, PerformanceState

    sm = SmartEngine()

    # Simulate a sequence of inputs
    print("[1] Simulating decisions...")
    for i in range(5):
        iv = InputVector()
        iv.cpu_util_percent = [10 + i * 15] * 8
        iv.ram_pressure_percent = 40 + i * 5
        iv.temp_soc_c = 350 + i * 15
        iv.battery_percent = 80 - i * 3
        iv.power_source = 0
        iv.foreground_workload = int(WorkloadClass.LIGHT)

        cmd = sm.evaluate(iv)
        state = PerformanceState(cmd.performance_state).name
        print(f"  [{i+1}] cpu={10+i*15}% temp={35+i*1.5:.1f}C → {state}")

    print()
    print("[2] Stats:")
    for k, v in sm.stats().items():
        print(f"    {k}: {v}")
    print()
