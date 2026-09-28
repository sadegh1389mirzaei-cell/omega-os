# ==============================================================
# OMEGA OS - Personal AI (v2 — with BOOT filter + charge gate)
# ==============================================================

import os
import json
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Tuple

try:
    from bus import Event, Topic
    from bus_hooks import _safe_emit
    _BUS = True
except Exception:
    _BUS = False
    def _safe_emit(*a, **k): pass


HOME = os.path.expanduser("~")
DEFAULT_LOG = os.path.join(HOME, "omega", "bus_log.jsonl")
DEFAULT_MODEL = os.path.join(HOME, "omega", "personal_model.json")

WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def bucket_hour(h: int) -> str:
    if 0 <= h < 6:   return "night"
    if 6 <= h < 12:  return "morning"
    if 12 <= h < 17: return "midday"
    if 17 <= h < 21: return "afternoon"
    return "evening"


def time_key(ts_ms: int) -> Tuple[str, str, str]:
    dt = datetime.fromtimestamp(ts_ms / 1000)
    return (WEEKDAYS[dt.weekday()],
            bucket_hour(dt.hour),
            f"{dt.hour:02d}")


@dataclass
class HabitModel:
    workload_by_hour:    Dict[str, Dict[str, int]] = field(default_factory=dict)
    workload_by_bucket:  Dict[str, Dict[str, int]] = field(default_factory=dict)
    workload_by_weekday: Dict[str, Dict[str, int]] = field(default_factory=dict)
    charge_hours:        Dict[str, int] = field(default_factory=dict)
    battery_at_charge:   List[int] = field(default_factory=list)
    avg_battery_by_hour: Dict[str, float] = field(default_factory=dict)
    total_samples:       int = 0

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "HabitModel":
        return cls(**{k: v for k, v in d.items()
                      if k in cls.__dataclass_fields__})


class HabitLearner:

    def __init__(self, model: HabitModel):
        self.model = model
        self._battery_sum: Dict[str, List[int]] = defaultdict(list)

    def ingest_event(self, evt: Event) -> None:
        topic = evt.topic
        payload = evt.payload or {}
        wd, bucket, hour = time_key(evt.ts)

        if topic == Topic.TELEMETRY_SAMPLE:
            wl = str(payload.get("workload", "?")).upper()
            if wl == "?":
                return
            # Ignore boot noise
            if wl in ("BOOT",):
                return

            self._bump(self.model.workload_by_hour, hour, wl)
            self._bump(self.model.workload_by_bucket, bucket, wl)
            self._bump(self.model.workload_by_weekday, wd, wl)

            battery = payload.get("battery")
            if isinstance(battery, (int, float)):
                self._battery_sum[hour].append(int(battery))

            self.model.total_samples += 1

        elif topic == Topic.DECISION_STATE_CHG:
            new = payload.get("new", "?")
            self._bump(self.model.workload_by_hour, hour, f"STATE:{new}")

        # NOTE: SYSTEM_BOOT ignored — it's not a workload

    @staticmethod
    def _bump(d: Dict[str, Dict[str, int]], key: str, sub: str):
        if key not in d:
            d[key] = {}
        d[key][sub] = d[key].get(sub, 0) + 1

    def ingest_charging(self, ts_ms: int, battery: int):
        _, _, hour = time_key(ts_ms)
        self.model.charge_hours[hour] = self.model.charge_hours.get(hour, 0) + 1
        self.model.battery_at_charge.append(int(battery))

    def finalize(self):
        for hour, vals in self._battery_sum.items():
            if vals:
                self.model.avg_battery_by_hour[hour] = sum(vals) / len(vals)


class Predictor:

    def __init__(self, model: HabitModel):
        self.model = model

    def predict_workload(self, ts_ms: Optional[int] = None) -> Tuple[str, float]:
        if ts_ms is None:
            ts_ms = int(time.time() * 1000)
        wd, bucket, hour = time_key(ts_ms)
        scores: Counter = Counter()

        for counts, weight in (
            (self.model.workload_by_hour.get(hour, {}),   3.0),
            (self.model.workload_by_bucket.get(bucket, {}), 2.0),
            (self.model.workload_by_weekday.get(wd, {}),  1.0),
        ):
            for wl, c in counts.items():
                if wl.startswith("STATE:") or wl == "BOOT":
                    continue
                scores[wl] += c * weight

        if not scores:
            return "?", 0.0

        top_wl, top_c = scores.most_common(1)[0]
        total = sum(scores.values()) or 1
        return top_wl, top_c / total

    def top_n_workloads(self, n: int = 3,
                        ts_ms: Optional[int] = None) -> List[Tuple[str, float]]:
        if ts_ms is None:
            ts_ms = int(time.time() * 1000)
        _, bucket, hour = time_key(ts_ms)
        counts = self.model.workload_by_hour.get(hour, {})
        if not counts:
            counts = self.model.workload_by_bucket.get(bucket, {})
        total = sum(counts.values()) or 1
        return [(wl, c / total)
                for wl, c in Counter(counts).most_common(n)
                if not wl.startswith("STATE:") and wl != "BOOT"]


@dataclass
class Suggestion:
    kind: str
    text: str
    confidence: float
    priority: int = 0


class SuggestionEngine:

    def __init__(self, model: HabitModel, predictor: Predictor):
        self.model = model
        self.predictor = predictor

    def evaluate(self, battery: int, on_battery: bool,
                 workload: str,
                 ts_ms: Optional[int] = None) -> List[Suggestion]:
        out = []

        # ── Charging: only if we have real charging history ──
        if on_battery and battery < 25 and self.model.charge_hours:
            _, _, hour = time_key(ts_ms or int(time.time() * 1000))
            hour_int = int(hour)
            nearby = sum(self.model.charge_hours.get(f"{h:02d}", 0)
                         for h in range(max(0, hour_int - 1),
                                        min(24, hour_int + 2)))
            if nearby > 0:
                conf = min(0.9, 0.4 + nearby * 0.15)
                out.append(Suggestion(
                    kind="charge",
                    text=f"Battery at {battery}%. You usually charge around now.",
                    confidence=conf, priority=5,
                ))

        # ── Workload mismatch ──
        predicted, conf = self.predictor.predict_workload(ts_ms)
        if predicted not in ("?", workload) and conf > 0.5:
            out.append(Suggestion(
                kind="info",
                text=f"Usually you'd be doing {predicted} now "
                     f"(currently {workload}).",
                confidence=conf, priority=2,
            ))

        # ── Rest ──
        if workload in ("GAMING_HEAVY", "COMPUTE", "CREATIVE"):
            out.append(Suggestion(
                kind="rest",
                text="Sustained heavy workload — consider a short break.",
                confidence=0.5, priority=1,
            ))

        return out


class PersonalAI:

    def __init__(self,
                 log_path: str = DEFAULT_LOG,
                 model_path: str = DEFAULT_MODEL):
        self.log_path = log_path
        self.model_path = model_path
        self.model = self._load_model()
        self.learner = HabitLearner(self.model)
        self.predictor = Predictor(self.model)
        self.suggestions = SuggestionEngine(self.model, self.predictor)
        self.last_ingest_ts = 0
        self.ingested_events = 0

    def _load_model(self) -> HabitModel:
        try:
            with open(self.model_path) as f:
                return HabitModel.from_dict(json.load(f))
        except (FileNotFoundError, json.JSONDecodeError):
            return HabitModel()

    def save_model(self) -> None:
        with open(self.model_path, "w") as f:
            json.dump(self.model.to_dict(), f, indent=2)

    def reset(self) -> None:
        self.model = HabitModel()
        self.learner = HabitLearner(self.model)
        self.predictor = Predictor(self.model)
        self.suggestions = SuggestionEngine(self.model, self.predictor)
        self.last_ingest_ts = 0
        self.save_model()

    def ingest_log(self, incremental: bool = True) -> int:
        if not os.path.exists(self.log_path):
            return 0
        processed = 0
        with open(self.log_path, "r") as f:
            for line in f:
                evt = Event.from_jsonl(line)
                if evt is None:
                    continue
                if incremental and evt.ts <= self.last_ingest_ts:
                    continue
                self.learner.ingest_event(evt)
                processed += 1
                if evt.ts > self.last_ingest_ts:
                    self.last_ingest_ts = evt.ts
        if processed:
            self.learner.finalize()
            self.ingested_events += processed
            self.save_model()
        return processed

    def predict(self, ts_ms: Optional[int] = None) -> Tuple[str, float]:
        return self.predictor.predict_workload(ts_ms)

    def top_workloads(self, n: int = 3,
                      ts_ms: Optional[int] = None) -> List[Tuple[str, float]]:
        return self.predictor.top_n_workloads(n, ts_ms)

    def suggest(self, battery: int, on_battery: bool, workload: str,
                ts_ms: Optional[int] = None) -> List[Suggestion]:
        return self.suggestions.evaluate(battery, on_battery, workload, ts_ms)

    def report(self) -> str:
        lines = []
        m = self.model
        lines.append(f"  total samples : {m.total_samples}")
        lines.append(f"  events seen   : {self.ingested_events}")

        if m.workload_by_hour:
            busiest = max(
                m.workload_by_hour.items(),
                key=lambda kv: sum(v for k, v in kv[1].items()
                                   if not k.startswith("STATE:") and k != "BOOT"),
                default=None,
            )
            if busiest:
                hour, counts = busiest
                total = sum(c for k, c in counts.items()
                            if not k.startswith("STATE:") and k != "BOOT")
                top = max(
                    ((k, v) for k, v in counts.items()
                     if not k.startswith("STATE:") and k != "BOOT"),
                    key=lambda kv: kv[1],
                    default=("?", 0),
                )
                lines.append(f"  busiest hour  : {hour}:00 ({total} samples, "
                             f"top: {top[0]} {top[1]})")

        if m.charge_hours:
            top_charge = max(m.charge_hours.items(), key=lambda kv: kv[1])
            avg_bat = (sum(m.battery_at_charge) / len(m.battery_at_charge)
                       if m.battery_at_charge else 0)
            lines.append(f"  charge hour   : {top_charge[0]}:00 "
                         f"({top_charge[1]}x, avg batt {avg_bat:.0f}%)")
        else:
            lines.append(f"  charge hour   : (no data yet)")

        wl, conf = self.predict()
        lines.append(f"  prediction    : {wl} ({conf*100:.0f}%)")
        return "\n".join(lines)


def demo():
    print("=" * 60)
    print("  OMEGA Personal AI — Demo")
    print("=" * 60)

    ai = PersonalAI()

    print("\n[1] Ingesting event log...")
    n = ai.ingest_log(incremental=False)
    print(f"    processed {n} events")

    print("\n[2] Model summary:")
    print(ai.report())

    print("\n[3] Top workloads for current hour:")
    for wl, p in ai.top_workloads(5):
        bar = "█" * int(p * 30)
        print(f"    {wl:<15} {p*100:>5.1f}%  {bar}")

    print("\n[4] Predictions by hour of day:")
    now = datetime.now()
    for delta_h in range(0, 12, 2):
        h = (now.hour + delta_h) % 24
        ts = int((now.replace(hour=h, minute=0, second=0).timestamp()) * 1000)
        wl, conf = ai.predict(ts)
        if wl == "?":
            continue
        print(f"    +{delta_h:>2}h ({h:02d}:00) → {wl:<15} "
              f"conf {conf*100:>4.1f}%")

    print("\n[5] Current suggestions (battery=20%, on_battery=True):")
    sugs = ai.suggest(battery=20, on_battery=True, workload="LIGHT")
    if not sugs:
        print("    (none — need more data)")
    for s in sugs:
        star = "★" * max(1, s.priority)
        print(f"    [{s.kind:<6}] {star:<6} {s.text}")
        print(f"             conf {s.confidence*100:.0f}%")


if __name__ == "__main__":
    demo()
