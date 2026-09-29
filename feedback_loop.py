# ==============================================================
# OMEGA OS - Feedback Loop for Decision Engine
# ==============================================================
# Logs every decision, evaluates the outcome after 60s,
# and gradually tunes parameters based on results.
# ==============================================================

import os
import json
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional

HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
DECISIONS_LOG = os.path.join(OMEGA_DIR, "decisions.jsonl")
OUTCOMES_LOG = os.path.join(OMEGA_DIR, "outcomes.jsonl")
PARAMS_FILE = os.path.join(OMEGA_DIR, "tuned_params.json")

# How long to wait before evaluating a decision
EVAL_DELAY_S = 60

# How many samples before we can tune
MIN_SAMPLES_FOR_TUNE = 20


class DecisionRecord:
    def __init__(self, record_id, ts, input_snapshot, decision, context):
        self.record_id = record_id
        self.ts = ts
        self.input_snapshot = input_snapshot
        self.decision = decision
        self.context = context
        self.evaluated = False
        self.score = None
        self.outcome = None

    def to_dict(self):
        return {
            "id": self.record_id,
            "ts": self.ts,
            "input": self.input_snapshot,
            "decision": self.decision,
            "context": self.context,
            "evaluated": self.evaluated,
            "score": self.score,
            "outcome": self.outcome,
        }

    @classmethod
    def from_dict(cls, d):
        r = cls(d["id"], d["ts"], d["input"], d["decision"], d["context"])
        r.evaluated = d.get("evaluated", False)
        r.score = d.get("score")
        r.outcome = d.get("outcome")
        return r


class FeedbackLoop:

    def __init__(self):
        self.records: List[DecisionRecord] = []
        self.pending: List[DecisionRecord] = []
        self.evaluated: List[DecisionRecord] = []
        self.next_id = 1
        self.params = self._load_params()
        self._load_history()

    def _load_params(self) -> Dict:
        try:
            with open(PARAMS_FILE) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "thermal_hysteresis_bonus": 0.0,
                "battery_threshold_adj": 0.0,
                "perf_cap_adj": 0.0,
                "tunes_applied": 0,
            }

    def _save_params(self):
        with open(PARAMS_FILE, "w") as f:
            json.dump(self.params, f, indent=2)

    def _load_history(self):
        if not os.path.exists(DECISIONS_LOG):
            return
        try:
            with open(DECISIONS_LOG) as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        r = DecisionRecord.from_dict(d)
                        self.records.append(r)
                        if r.evaluated:
                            self.evaluated.append(r)
                        else:
                            self.pending.append(r)
                        if r.record_id >= self.next_id:
                            self.next_id = r.record_id + 1
                    except (json.JSONDecodeError, KeyError):
                        continue
        except OSError:
            pass

    def log_decision(self, input_snapshot: Dict,
                     decision: Dict, context: Dict = None) -> DecisionRecord:
        r = DecisionRecord(
            record_id=self.next_id,
            ts=int(time.time() * 1000),
            input_snapshot=input_snapshot,
            decision=decision,
            context=context or {},
        )
        self.next_id += 1
        self.records.append(r)
        self.pending.append(r)

        # Append to log file
        with open(DECISIONS_LOG, "a") as f:
            f.write(json.dumps(r.to_dict()) + "\n")

        return r

    def evaluate_pending(self, current_input: Dict):
        """
        Evaluate pending decisions that are old enough.
        current_input = snapshot of the system NOW.
        """
        now = time.time() * 1000
        still_pending = []

        for r in self.pending:
            age_s = (now - r.ts) / 1000.0
            if age_s < EVAL_DELAY_S:
                still_pending.append(r)
                continue

            score, outcome = self._evaluate(r, current_input)
            r.evaluated = True
            r.score = score
            r.outcome = outcome
            self.evaluated.append(r)

            # Log outcome
            with open(OUTCOMES_LOG, "a") as f:
                f.write(json.dumps(r.to_dict()) + "\n")

        self.pending = still_pending

    def _evaluate(self, record: DecisionRecord,
                  now_input: Dict) -> tuple:
        """
        Score a past decision based on what happened.
        Returns (score 0-100, outcome_str).
        """
        old_input = record.input_snapshot
        old_state = record.decision.get("state", "?")
        old_temp = old_input.get("temp_soc", 0)
        new_temp = now_input.get("temp_soc", 0)
        old_batt = old_input.get("battery", 100)
        new_batt = now_input.get("battery", 100)

        score = 50
        notes = []

        # 1. Temperature stability
        temp_change = new_temp - old_temp
        if temp_change <= -2:
            score += 15
            notes.append("cooled_down")
        elif temp_change >= 5:
            score -= 20
            notes.append("overheating")
        elif temp_change >= 2:
            score -= 5
            notes.append("warming")

        # 2. Battery reasonable — check power source first
        old_ps = old_input.get("power_source", 0)
        new_ps = now_input.get("power_source", 0)
        # power_source: 0=BATTERY, 1=USB, 2=WIRELESS, 3=DOCK
        now_charging = new_ps != 0
        was_charging = old_ps != 0

        batt_drain = old_batt - new_batt

        if now_charging:
            # On charger — no concerns about drain
            score += 5
            notes.append("on_charger")
        else:
            # On battery — drain matters
            if batt_drain < 0:
                # Battery increased while on battery? Impossible
                # (bug in data or read error)
                notes.append("batt_anomaly")
            elif batt_drain > 5:
                score -= 15
                notes.append("fast_drain")
            elif batt_drain <= 2:
                score += 10
                notes.append("efficient")
            else:
                notes.append("normal_drain")

        # 3. State appropriateness
        # state codes: 0=IDLE, 1=BALANCED, 2=PERFORMANCE, 3=CREATIVE, 4=COMPUTE
        now_cpu = now_input.get("cpu", 0)
        now_temp = now_input.get("temp_soc", 0)
        if old_state == 0 and now_cpu > 30:
            score -= 10
            notes.append("idle_but_busy")
        if old_state == 2 and now_temp > 45:
            score -= 15
            notes.append("perf_but_hot")
        if old_state == 3 and now_temp > 45:
            score -= 10
            notes.append("creative_but_hot")

        score = max(0, min(100, score))
        outcome = "+".join(notes) if notes else "neutral"
        return score, outcome

    def tune(self):
        """
        Adjust parameters based on recent outcomes.
        Only tunes if we have enough samples.
        """
        if len(self.evaluated) < MIN_SAMPLES_FOR_TUNE:
            return {"status": "not_enough_data",
                    "have": len(self.evaluated),
                    "need": MIN_SAMPLES_FOR_TUNE}

        # Look at the last 50 decisions
        recent = self.evaluated[-50:]
        avg_score = sum(r.score for r in recent) / len(recent)

        # Count specific failure modes
        hot_count = sum(1 for r in recent
                       if r.outcome and "overheating" in r.outcome)
        drain_count = sum(1 for r in recent
                         if r.outcome and "fast_drain" in r.outcome)

        changes = {}

        # If too many overheatings, be more conservative
        if hot_count > len(recent) * 0.20:
            self.params["thermal_hysteresis_bonus"] += 0.5
            self.params["perf_cap_adj"] -= 2.0
            changes["thermal_conservative"] = True

        # If too many drains, save power earlier
        if drain_count > len(recent) * 0.20:
            self.params["battery_threshold_adj"] += 1.0
            changes["battery_conservative"] = True

        # If score is good, we can relax slightly
        if avg_score >= 75 and hot_count == 0:
            if self.params["perf_cap_adj"] < 0:
                self.params["perf_cap_adj"] += 1.0
                changes["relax_perf"] = True

        self.params["tunes_applied"] += 1
        self._save_params()

        return {
            "status": "tuned",
            "samples": len(recent),
            "avg_score": round(avg_score, 1),
            "hot_count": hot_count,
            "drain_count": drain_count,
            "changes": changes,
            "params": self.params,
        }

    def stats(self) -> Dict:
        total = len(self.records)
        evaluated = len(self.evaluated)
        pending = len(self.pending)

        avg_score = 0
        if evaluated:
            avg_score = sum(r.score for r in self.evaluated) / evaluated

        return {
            "total_decisions": total,
            "evaluated": evaluated,
            "pending": pending,
            "avg_score": round(avg_score, 1),
            "tunes_applied": self.params.get("tunes_applied", 0),
        }


# ==============================================================
# Integration helper
# ==============================================================

def input_to_snapshot(iv) -> Dict:
    """Convert an InputVector to a simple dict for logging."""
    return {
        "cpu": sum(iv.cpu_util_percent) // max(1, iv.cpu_core_count),
        "ram": iv.ram_pressure_percent,
        "temp_soc": iv.temp_soc_c / 10.0,
        "battery": iv.battery_percent,
        "power_source": iv.power_source,
        "workload": iv.foreground_workload,
    }


def decision_to_dict(cmd) -> Dict:
    """Convert a ResourceCommands to a simple dict."""
    return {
        "state": cmd.performance_state,
        "tier": cmd.power_tier,
        "thermal": cmd.thermal_state,
        "cpu_cap": cmd.cpu_max_freq_percent,
        "gpu_cap": cmd.gpu_max_freq_percent,
        "reason": cmd.reason[:80],
    }


if __name__ == "__main__":
    fb = FeedbackLoop()
    print()
    print("=" * 60)
    print("  OMEGA Feedback Loop - Status")
    print("=" * 60)
    print()
    stats = fb.stats()
    for k, v in stats.items():
        print(f"  {k:<20} {v}")
    print()
    print(f"  params: {json.dumps(fb.params, indent=4)}")
    print()
