import os, json, time
from collections import defaultdict
from datetime import datetime

HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
LOG = os.path.join(OMEGA_DIR, "bus_log.jsonl")
MODEL = os.path.join(OMEGA_DIR, "personal_v2_model.json")
WEEKDAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

def hour_bucket(h):
    if h < 6: return "night"
    if h < 12: return "morning"
    if h < 17: return "midday"
    if h < 21: return "evening"
    return "late"

def battery_bucket(p):
    if p < 15: return "critical"
    if p < 30: return "low"
    if p < 70: return "medium"
    return "high"

class Markov:
    def __init__(self, halflife_h=24.0):
        self.tr = defaultdict(lambda: defaultdict(float))
        self.state = defaultdict(float)
        self.halflife = halflife_h
        self.n_seq = 0
        self.n_tr = 0

    def _decay(self, base, ev):
        dt = (base - ev) / 3600000.0
        if dt < 0: dt = 0
        return 0.5 ** (dt / self.halflife)

    def add(self, states, ts, now=None):
        if len(states) < 1: return
        if now is None: now = int(time.time()*1000)
        self.state[states[0]] += self._decay(now, ts[0])
        for i in range(len(states)-1):
            w = self._decay(now, ts[i+1])
            self.tr[states[i]][states[i+1]] += w
            self.state[states[i+1]] += w
            self.n_tr += 1
        self.n_seq += 1

    def predict(self, s, n=3):
        if s not in self.tr: return []
        row = self.tr[s]
        total = sum(row.values())
        if total <= 0: return []
        items = sorted(row.items(), key=lambda kv: -kv[1])[:n]
        return [(k, v/total) for k, v in items]

    def to_dict(self):
        return {"tr": {k: dict(v) for k, v in self.tr.items()},
                "state": dict(self.state), "n_seq": self.n_seq,
                "n_tr": self.n_tr, "halflife": self.halflife}

    @classmethod
    def from_dict(cls, d):
        m = cls(d.get("halflife", 24.0))
        for src, dsts in d.get("tr", {}).items():
            for dst, v in dsts.items():
                m.tr[src][dst] = float(v)
        m.state = defaultdict(float, d.get("state", {}))
        m.n_seq = d.get("n_seq", 0)
        m.n_tr = d.get("n_tr", 0)
        return m

class ContextPredictor:
    def __init__(self):
        self.global_chain = Markov()
        self.by_bucket = {}
        self.by_weekday = {}

    def add(self, states, ts, contexts):
        if not states: return
        self.global_chain.add(states, ts)
        for i in range(len(states)-1):
            pair = [states[i], states[i+1]]
            pair_ts = [ts[i], ts[i+1]]
            b = contexts[i].get("bucket", "?")
            wd = contexts[i].get("weekday", "?")
            if b not in self.by_bucket:
                self.by_bucket[b] = Markov()
            self.by_bucket[b].add(pair, pair_ts)
            if wd not in self.by_weekday:
                self.by_weekday[wd] = Markov()
            self.by_weekday[wd].add(pair, pair_ts)

    def predict(self, state, hour, weekday):
        b = hour_bucket(hour)
        for chain, label in [
            (self.by_bucket.get(b), "bucket:"+b),
            (self.by_weekday.get(weekday), "wd:"+weekday),
            (self.global_chain, "global")]:
            if chain is None: continue
            preds = chain.predict(state)
            if preds:
                return [(s, p, label) for s, p in preds]
        return []

    def to_dict(self):
        return {
            "global": self.global_chain.to_dict(),
            "by_bucket": {k: v.to_dict() for k, v in self.by_bucket.items()},
            "by_weekday": {k: v.to_dict() for k, v in self.by_weekday.items()}}

    @classmethod
    def from_dict(cls, d):
        cp = cls()
        if "global" in d: cp.global_chain = Markov.from_dict(d["global"])
        for k, v in d.get("by_bucket", {}).items():
            cp.by_bucket[k] = Markov.from_dict(v)
        for k, v in d.get("by_weekday", {}).items():
            cp.by_weekday[k] = Markov.from_dict(v)
        return cp

class PersonalAIv2:
    def __init__(self):
        self.predictor = ContextPredictor()
        self.last_ts = 0
        self.n_ingested = 0
        self.current = None
        self._load()

    def _load(self):
        try:
            with open(MODEL) as f: d = json.load(f)
            self.predictor = ContextPredictor.from_dict(d.get("predictor", {}))
            self.last_ts = d.get("last_ts", 0)
            self.n_ingested = d.get("n_ingested", 0)
        except: pass

    def save(self):
        with open(MODEL, "w") as f:
            json.dump({"predictor": self.predictor.to_dict(),
                       "last_ts": self.last_ts,
                       "n_ingested": self.n_ingested}, f, indent=2)

    def ingest(self, rebuild=False):
        if not os.path.exists(LOG): return 0
        if rebuild:
            self.predictor = ContextPredictor()
            self.last_ts = 0
            self.n_ingested = 0
        events = []
        with open(LOG) as f:
            for line in f:
                try: evt = json.loads(line)
                except: continue
                if evt.get("ts", 0) <= self.last_ts and not rebuild: continue
                if evt.get("topic") != "telemetry.sample": continue
                p = evt.get("payload", {})
                wl = str(p.get("workload", "?")).upper()
                if wl in ("?", "BOOT", ""): continue
                events.append({"ts": evt["ts"], "state": wl})
        if not events: return 0
        sequences = []
        cur = []
        prev = None
        for e in events:
            if prev is not None and (e["ts"] - prev) > 1800000:
                if len(cur) >= 2: sequences.append(cur)
                cur = []
            cur.append(e)
            prev = e["ts"]
        if len(cur) >= 2: sequences.append(cur)
        for seq in sequences:
            states = [e["state"] for e in seq]
            ts = [e["ts"] for e in seq]
            ctxs = []
            for e in seq:
                dt = datetime.fromtimestamp(e["ts"]/1000)
                ctxs.append({"bucket": hour_bucket(dt.hour),
                             "weekday": WEEKDAYS[dt.weekday()]})
            self.predictor.add(states, ts, ctxs)
        self.n_ingested += len(events)
        if events: self.last_ts = max(e["ts"] for e in events)
        self.save()
        return len(events)

    def predict_next(self, state=None):
        if state is None: state = self.current
        if state is None: return []
        now = datetime.now()
        return self.predictor.predict(state, now.hour, WEEKDAYS[now.weekday()])

    def all_states(self):
        """Return all states that ever appeared (source or target)."""
        gc = self.predictor.global_chain
        states = set(gc.state.keys())
        for src, dsts in gc.tr.items():
            states.add(src)
            for dst in dsts.keys():
                states.add(dst)
        return states

    def summary(self):
        gc = self.predictor.global_chain
        return {"sequences": gc.n_seq, "transitions": gc.n_tr,
                "states": len(gc.state), "ingested": self.n_ingested,
                "buckets": len(self.predictor.by_bucket),
                "weekdays": len(self.predictor.by_weekday)}

def demo():
    print()
    print("=" * 66)
    print("  OMEGA Personal AI v2 - Markov Chain")
    print("=" * 66)
    print()
    pai = PersonalAIv2()
    print("[1] Ingesting...")
    n = pai.ingest(rebuild=True)
    print(f"    {n} events processed")
    print()
    print("[2] Summary:")
    for k, v in pai.summary().items():
        print(f"    {k}: {v}")
    print()
    print("[3] Transitions:")
    gc = pai.predictor.global_chain
    all_states = pai.all_states()
    top = sorted(((s, gc.state.get(s, 0)) for s in all_states),
                 key=lambda kv: -kv[1])[:5]
    for state, cnt in top:
        preds = gc.predict(state)
        if not preds: continue
        print(f"    {state} ({int(cnt)}x):")
        for ns, p in preds:
            bar = "#" * int(p*20)
            print(f"      -> {ns:<12} {p*100:>5.1f}%  {bar}")
    print()
    print("[4] Live predictions:")
    for s in ["LIGHT","WEB","COMPUTE","IDLE"]:
        preds = pai.predict_next(s)
        if not preds: continue
        print(f"    after {s}:")
        for ns, p, src in preds:
            print(f"      -> {ns:<12} {p*100:>5.1f}%  ({src})")
    print()

if __name__ == "__main__":
    demo()
