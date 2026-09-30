# ==============================================================
# OMEGA OS - Security AI v2
# ==============================================================
# Section 6.3 of the OMEGA spec, with real behavioral learning.
#
# What's new vs v1:
#   - Markov chain on process behavior sequences
#   - Time-decay: recent behavior weighs more
#   - Baseline per process, per hour
#   - Anomaly scoring (not just pattern matching)
#   - Dynamic trust that adapts to observed behavior
# ==============================================================

import os
import json
import time
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

try:
    from quarantine import QuarantineManager
    _QUARANTINE_ENABLED = True
except ImportError:
    _QUARANTINE_ENABLED = False
    QuarantineManager = None


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
DEFAULT_MODEL = os.path.join(OMEGA_DIR, "security_v2_model.json")
DEFAULT_LOG = os.path.join(OMEGA_DIR, "security_v2_events.jsonl")
FILE_MONITOR_LOG = os.path.join(OMEGA_DIR, "file_monitor.jsonl")

# Decay: behavior from 48 hours ago weighs half
HALFLIFE_HOURS = 48.0

# Anomaly threshold: below this probability is suspicious
ANOMALY_THRESHOLD = 0.15

# Known suspicious patterns — severity escalates
# (pattern, severity, reason)
THREAT_PATTERNS = [
    ("nc -l",           "HIGH",     "netcat listener (potential backdoor)"),
    ("ncat -l",         "HIGH",     "ncat listener"),
    ("nc -e",           "CRITICAL", "netcat with command execution"),
    ("nc -c",           "CRITICAL", "netcat with shell"),
    ("/dev/tcp",        "HIGH",     "bash tcp redirection"),
    ("curl | sh",       "CRITICAL", "pipe remote script to shell"),
    ("wget | sh",       "CRITICAL", "pipe remote script to shell"),
    ("base64 -d",       "MEDIUM",   "base64 decode (obfuscation)"),
    ("chmod 777",       "MEDIUM",   "weak permissions"),
    ("rm -rf /",        "CRITICAL", "destructive delete"),
    ("sudo ",           "MEDIUM",   "privilege escalation attempt"),
    ("su -",            "MEDIUM",   "privilege escalation attempt"),
    ("nmap",            "HIGH",     "port scanner"),
    ("masscan",         "HIGH",     "port scanner"),
]


def classify_threat(name: str, args: str = "") -> tuple:
    """
    Returns (severity, reason) if matches a threat pattern,
    else ("INFO", "unknown process").
    """
    text = (name + " " + args).lower()
    for pattern, severity, reason in THREAT_PATTERNS:
        if pattern.lower() in text:
            return severity, reason
    return "INFO", "new process observed"


# ==============================================================
# Process signature
# ==============================================================

@dataclass
class ProcessSig:
    """A compact signature of what a process is doing."""
    name: str
    pid: int
    cpu_pct: int          # 0-100
    mem_pct: int          # 0-100
    state: str            # R, S, D, Z, T
    category: str         # LIBRARY, DAEMON, SERVICE, UNKNOWN

    def to_key(self) -> str:
        """Compact key for Markov state."""
        return f"{self.name}::{self.state}::{self.category}"

    def to_dict(self):
        return asdict(self)


# ==============================================================
# Behavior state (what we learn per process name)
# ==============================================================

@dataclass
class ProcessBaseline:
    name: str
    count: int = 0
    total_cpu: float = 0.0
    total_mem: float = 0.0
    max_cpu: float = 0.0
    states_seen: Set[str] = field(default_factory=set)
    hours_seen: Set[int] = field(default_factory=set)
    first_seen: int = 0
    last_seen: int = 0
    trust: int = 50

    def to_dict(self):
        d = asdict(self)
        d["states_seen"] = list(self.states_seen)
        d["hours_seen"] = list(self.hours_seen)
        return d

    @classmethod
    def from_dict(cls, d):
        b = cls(name=d["name"])
        b.count = d.get("count", 0)
        b.total_cpu = d.get("total_cpu", 0.0)
        b.total_mem = d.get("total_mem", 0.0)
        b.max_cpu = d.get("max_cpu", 0.0)
        b.states_seen = set(d.get("states_seen", []))
        b.hours_seen = set(d.get("hours_seen", []))
        b.first_seen = d.get("first_seen", 0)
        b.last_seen = d.get("last_seen", 0)
        b.trust = d.get("trust", 50)
        return b

    def avg_cpu(self) -> float:
        return self.total_cpu / self.count if self.count else 0.0

    def avg_mem(self) -> float:
        return self.total_mem / self.count if self.count else 0.0

    def is_new(self) -> bool:
        return self.count < 5

    def to_summary(self) -> str:
        return (f"count={self.count} "
                f"cpu_avg={self.avg_cpu():.1f}% "
                f"cpu_max={self.max_cpu:.1f}% "
                f"trust={self.trust}")

    def adjust_trust(self, delta: int, reason: str = "") -> int:
        """Adjust trust score, clamped to [0, 100]."""
        old_trust = self.trust
        self.trust = max(0, min(100, self.trust + delta))
        return self.trust - old_trust


# Trust deltas by severity
TRUST_DELTAS = {
    "INFO":     +1,     # benign process, slight trust gain
    "LOW":      -5,
    "MEDIUM":   -10,
    "HIGH":     -25,
    "CRITICAL": -50,
}

# Thresholds
TRUST_WARN_LEVEL = 30
TRUST_KILL_LEVEL = 15



# ==============================================================
# Markov chain for behavior sequences
# ==============================================================

class BehaviorMarkov:

    def __init__(self, halflife_h: float = HALFLIFE_HOURS):
        self.transitions = defaultdict(lambda: defaultdict(float))
        self.state_counts = defaultdict(float)
        self.halflife_h = halflife_h
        self.total_transitions = 0

    def _decay(self, base_ts: int, event_ts: int) -> float:
        dt_h = (base_ts - event_ts) / 3600000.0
        if dt_h < 0:
            dt_h = 0
        return 0.5 ** (dt_h / self.halflife_h)

    def add(self, sequence: List[str], timestamps: List[int],
            now_ms: Optional[int] = None):
        if len(sequence) < 1:
            return
        if now_ms is None:
            now_ms = int(time.time() * 1000)

        self.state_counts[sequence[0]] += self._decay(now_ms, timestamps[0])

        for i in range(len(sequence) - 1):
            w = self._decay(now_ms, timestamps[i + 1])
            self.transitions[sequence[i]][sequence[i + 1]] += w
            self.state_counts[sequence[i + 1]] += w
            self.total_transitions += 1

    def probability(self, src: str, dst: str) -> float:
        """P(dst | src)."""
        if src not in self.transitions:
            return 0.0
        row = self.transitions[src]
        total = sum(row.values())
        if total <= 0:
            return 0.0
        return row.get(dst, 0.0) / total

    def predict_next(self, src: str, top_n: int = 3) -> List[Tuple[str, float]]:
        if src not in self.transitions:
            return []
        row = self.transitions[src]
        total = sum(row.values())
        if total <= 0:
            return []
        items = sorted(row.items(), key=lambda kv: -kv[1])[:top_n]
        return [(s, v / total) for s, v in items]

    def to_dict(self):
        return {
            "transitions": {k: dict(v) for k, v in self.transitions.items()},
            "state_counts": dict(self.state_counts),
            "halflife_h": self.halflife_h,
            "total_transitions": self.total_transitions,
        }

    @classmethod
    def from_dict(cls, d):
        m = cls(halflife_h=d.get("halflife_h", HALFLIFE_HOURS))
        for src, dsts in d.get("transitions", {}).items():
            for dst, v in dsts.items():
                m.transitions[src][dst] = float(v)
        m.state_counts = defaultdict(float, d.get("state_counts", {}))
        m.total_transitions = d.get("total_transitions", 0)
        return m


# ==============================================================
# Security AI v2
# ==============================================================

class SecurityAIv2:

    def __init__(self, model_path: str = DEFAULT_MODEL,
                 log_path: str = DEFAULT_LOG):
        self.model_path = model_path
        self.log_path = log_path

        self.markov = BehaviorMarkov()
        self.baselines: Dict[str, ProcessBaseline] = {}
        self.sequences: List[List[str]] = []   # recent sequences
        self.current_sequence: List[Tuple[str, int]] = []
        self.last_sequence_ts = 0
        self.events: List[dict] = []
        self.total_samples = 0
        self.auto_quarantine = True
        self.quarantine = (QuarantineManager()
                          if _QUARANTINE_ENABLED else None)

        # File Monitor integration
        self.file_monitor_log = FILE_MONITOR_LOG
        self.file_monitor_last_ts = 0
        self.file_anomaly_count = 0

        self._load()

    def _load(self):
        try:
            with open(self.model_path) as f:
                d = json.load(f)
            self.markov = BehaviorMarkov.from_dict(d.get("markov", {}))
            for name, b in d.get("baselines", {}).items():
                self.baselines[name] = ProcessBaseline.from_dict(b)
            self.total_samples = d.get("total_samples", 0)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self):
        with open(self.model_path, "w") as f:
            json.dump({
                "markov": self.markov.to_dict(),
                "baselines": {k: v.to_dict()
                              for k, v in self.baselines.items()},
                "total_samples": self.total_samples,
            }, f, indent=2)

    def _emit(self, kind: str, severity: str, subject: str,
              detail: str, score: float = 0.0,
              pid: Optional[int] = None):
        event = {
            "ts": int(time.time() * 1000),
            "kind": kind,
            "severity": severity,
            "subject": subject,
            "detail": detail,
            "score": round(score, 3),
        }
        self.events.append(event)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except OSError:
            pass

        # Adjust trust based on severity
        if subject in self.baselines:
            delta = TRUST_DELTAS.get(severity, 0)
            if delta != 0:
                self.baselines[subject].adjust_trust(delta, kind)

        # Auto-quarantine on HIGH or CRITICAL
        if (self.auto_quarantine and self.quarantine
                and severity in ("HIGH", "CRITICAL")
                and pid is not None):
            result = self.quarantine.kill_process(
                pid=pid, name=subject,
                severity=severity, reason=detail,
            )
            event["quarantine_action"] = result.get("action")
            print(f"[security] auto-quarantine: "
                  f"{subject} (pid={pid}) -> {result['action']}")

    def ingest_file_anomalies(self) -> int:
        """
        Read new file anomalies from file_monitor.jsonl.
        Returns number of new events processed.
        """
        if not os.path.exists(self.file_monitor_log):
            return 0

        processed = 0
        try:
            with open(self.file_monitor_log) as f:
                for line in f:
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    ts = evt.get("ts", 0)
                    if ts <= self.file_monitor_last_ts:
                        continue

                    # Only process HIGH and CRITICAL file anomalies.
                    # LOW/MEDIUM are counted but NOT turned into events
                    severity = evt.get("severity", "LOW")
                    if severity in ("HIGH", "CRITICAL"):
                        self._handle_file_anomaly(evt)
                        processed += 1
                    self.file_monitor_last_ts = ts
                    self.file_anomaly_count += 1
        except OSError:
            pass

        return processed

    def _handle_file_anomaly(self, evt: dict):
        """Convert a file anomaly into a security event."""
        severity = evt.get("severity", "LOW")
        name = evt.get("name", "?")
        detail = evt.get("detail", "")
        anomaly = evt.get("anomaly", "?")

        # Emit as a security event (with subject prefixed)
        subject = f"FILE:{name}"
        self._emit(
            kind=f"file_{anomaly}",
            severity=severity,
            subject=subject,
            detail=detail,
        )

    def observe(self, sigs: List[ProcessSig]):
        """
        Record a snapshot of process signatures.
        Updates Markov chain, baselines, and triggers anomalies.
        """
        if not sigs:
            return

        now = int(time.time() * 1000)
        current_hour = datetime.now().hour

        # 1. Update baselines
        for sig in sigs:
            b = self.baselines.get(sig.name)
            if b is None:
                b = ProcessBaseline(name=sig.name,
                                    first_seen=now)
                self.baselines[sig.name] = b
                # Classify threat
                severity, reason = classify_threat(sig.name)
                self._emit("new_process", severity,
                          sig.name, reason, pid=sig.pid)

            b.count += 1
            b.total_cpu += sig.cpu_pct
            b.total_mem += sig.mem_pct
            b.max_cpu = max(b.max_cpu, sig.cpu_pct)
            b.states_seen.add(sig.state)
            b.hours_seen.add(current_hour)
            b.last_seen = now

            # Trust gain for well-behaved process
            # Only adjust after enough samples to know it's normal
            if b.count > 5 and b.count % 10 == 0:
                b.adjust_trust(1, "stable_behavior")

                # Check if trust has fallen too low
                if b.trust <= TRUST_KILL_LEVEL:
                    self._emit("low_trust", "HIGH", sig.name,
                              f"trust={b.trust} (auto-kill)",
                              pid=sig.pid)
                elif b.trust <= TRUST_WARN_LEVEL:
                    self._emit("low_trust", "MEDIUM", sig.name,
                              f"trust={b.trust}")

        # 2. Build sequence
        seq_keys = [s.to_key() for s in sigs]

        # 3. Check anomalies: for each consecutive pair, compute prob
        if len(self.current_sequence) > 0:
            last_key, last_ts = self.current_sequence[-1]
            for k in seq_keys:
                prob = self.markov.probability(last_key, k)
                if prob > 0 and prob < ANOMALY_THRESHOLD:
                    self._emit("low_prob_transition", "MEDIUM",
                              k.split("::")[0],
                              f"P({k} | {last_key}) = {prob:.3f}",
                              score=prob)
                # Novel transition (never seen)
                elif prob == 0.0 and self.markov.total_transitions > 50:
                    # Only if we have enough data to know what's normal
                    self._emit("novel_transition", "LOW",
                              k.split("::")[0],
                              f"new transition from {last_key}",
                              score=0.0)

        # 4. Add to current sequence
        for k in seq_keys:
            self.current_sequence.append((k, now))

        # 5. If sequence is long enough or time passed, finalize it
        sequence_age_s = (now - self.last_sequence_ts) / 1000.0 \
            if self.last_sequence_ts else 0

        if len(self.current_sequence) >= 10 or sequence_age_s > 60:
            keys = [k for k, _ in self.current_sequence]
            timestamps = [t for _, t in self.current_sequence]
            self.markov.add(keys, timestamps, now_ms=now)
            self.current_sequence = []
            self.last_sequence_ts = now

        self.total_samples += 1

    def stats(self) -> dict:
        s = {
            "processes_tracked": len(self.baselines),
            "total_transitions": self.markov.total_transitions,
            "events": len(self.events),
            "total_samples": self.total_samples,
            "current_seq_len": len(self.current_sequence),
            "auto_quarantine": self.auto_quarantine,
        }
        if self.quarantine:
            s["quarantined"] = self.quarantine.stats()["killed_total"]
        s["file_anomalies"] = self.file_anomaly_count
        return s


if __name__ == "__main__":
    print()
    print("=" * 60)
    print("  Security AI v2 - Status")
    print("=" * 60)
    print()
    sec = SecurityAIv2()
    for k, v in sec.stats().items():
        print(f"  {k}: {v}")
    print()



# ==============================================================
# Integration with ProcessScanner
# ==============================================================

def sigs_from_processes(procs) -> List[ProcessSig]:
    """
    Convert processes.Process objects to ProcessSig objects.
    Category classification by name pattern.
    """
    # Tools that measure their own CPU — ignore their spikes
    SELF_TOOLS = {"ps", "top", "grep", "sed", "awk", "cat", "python"}

    sigs = []
    for p in procs:
        # Use args-based name if comm is truncated or generic
        name = (p.comm or "").strip()
        args = (p.args or "").strip()

        # SKIP ZOMBIES: any process with 'defunct' in name or args
        combined = (name + " " + args).lower()
        if "defunct" in combined:
            continue
        if name.startswith("<") and name.endswith(">"):
            continue
        if name.strip("[]") == "":
            continue



        # If args has more info, use a combined identifier
        if args and len(args.split()) > 1:
            # Take first 2 words of args (e.g., "runsv postgres")
            first_words = " ".join(args.split()[:2])
            # If comm is very short or generic, use args version
            if len(name) < 5 or name in ("runsv", "sh", "bash"):
                name = first_words

        if not name:
            continue

        # Skip self-measuring tools that always show 100%
        base = name.split()[0].split("/")[-1]
        if base in SELF_TOOLS:
            cpu_val = 0.0
        else:
            cpu_val = p.cpu_percent

        # Category
        cat = "UNKNOWN"
        lower = name.lower()
        if "python" in lower or "node" in lower or "java" in lower:
            cat = "RUNTIME"
        elif "ssh" in lower or "sshd" in lower:
            cat = "NETWORK"
        elif "chrome" in lower or "firefox" in lower:
            cat = "BROWSER"
        elif lower in ("sh", "bash", "zsh", "dash"):
            cat = "SHELL"
        elif "runsv" in lower or "svlogd" in lower:
            cat = "SUPERVISOR"
        elif lower in ("ps", "top", "grep", "sed", "awk", "cat"):
            cat = "TOOL"
        elif "termux" in lower:
            cat = "TERMUX"
        elif lower.startswith("["):
            cat = "KERNEL"
        elif lower.startswith("/data/data"):
            cat = "ANDROID_APP"
        elif lower.startswith("/system/bin"):
            cat = "ANDROID_SYS"
        elif lower.startswith("/system"):
            cat = "ANDROID_SYS"

        # State: assume S for now (we don't have state from Process)
        state = "S"

        sig = ProcessSig(
            name=name,
            pid=p.pid,
            cpu_pct=int(min(100, cpu_val)),
            mem_pct=0,
            state=state,
            category=cat,
        )
        sigs.append(sig)
    return sigs


def demo_real():
    """Run with real processes from the system."""
    import sys
    sys.path.insert(0, OMEGA_DIR)
    from processes import ProcessScanner

    print()
    print("=" * 60)
    print("  Security AI v2 - Real Process Test")
    print("=" * 60)
    print()

    sec = SecurityAIv2()
    scanner = ProcessScanner()

    print("[1] Collecting process snapshots...")

    # Run 5 snapshots, 1 second apart
    for i in range(5):
        procs = scanner.scan()
        sigs = sigs_from_processes(procs)
        sec.observe(sigs)
        print(f"    snapshot #{i+1}: {len(sigs)} processes")
        time.sleep(1)

    # Force finalize any pending sequence
    if sec.current_sequence:
        keys = [k for k, _ in sec.current_sequence]
        ts = [t for _, t in sec.current_sequence]
        sec.markov.add(keys, ts)
        sec.current_sequence = []

    sec.save()

    print()
    print("[2] Stats:")
    for k, v in sec.stats().items():
        print(f"    {k}: {v}")

    print()
    print("[3] Learned process baselines:")
    top_procs = sorted(sec.baselines.values(),
                       key=lambda b: -b.count)[:10]
    print(f"    {'NAME':<20} {'COUNT':<7} {'CPU_AVG':<9} {'CPU_MAX':<9} TRUST")
    print("    " + "-" * 60)
    for b in top_procs:
        print(f"    {b.name:<20} {b.count:<7} "
              f"{b.avg_cpu():>6.1f}%  {b.max_cpu:>6.1f}%  "
              f"{b.trust}")

    print()
    print("[4] Learned transitions (top):")
    if sec.markov.transitions:
        # Top source states
        sources = sorted(sec.markov.state_counts.items(),
                        key=lambda kv: -kv[1])[:5]
        for src, cnt in sources:
            preds = sec.markov.predict_next(src, top_n=2)
            if not preds:
                continue
            print(f"    {src[:40]}")
            for dst, prob in preds:
                print(f"      -> {dst[:40]:<40} {prob*100:.1f}%")
    else:
        print("    (no transitions yet — need more snapshots)")

    print()
    if sec.events:
        print(f"[5] Events ({len(sec.events)}):")
        for e in sec.events[-5:]:
            print(f"    [{e['severity']:<8}] {e['kind']:<20} "
                  f"{e['subject']}")
    else:
        print("[5] No events yet")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "real":
        demo_real()
    else:
        print()
        print("=" * 60)
        print("  Security AI v2 - Status")
        print("=" * 60)
        print()
        sec = SecurityAIv2()
        for k, v in sec.stats().items():
            print(f"  {k}: {v}")
        print()
        print("  Run with 'real' argument to test on real processes:")
        print("    python security_v2.py real")
        print()




# ==============================================================
# Web Widget for Dashboard
# ==============================================================

def web_widget() -> dict:
    """Dashboard widget for Security AI v2."""
    from widgets import metrics_widget, metric_row

    try:
        sec = SecurityAIv2()
        s = sec.stats()

        threat_color = {
            "NORMAL": "green",
            "ELEVATED": "yellow",
            "HIGH": "orange",
            "CRITICAL": "red",
        }.get(s.get("threat_level", "NORMAL"), "white")

        rows = [
            metric_row("Threat Level",
                      s.get("threat_level", "NORMAL"),
                      threat_color),
            metric_row("Processes", s.get("processes_tracked", 0), "cyan"),
            metric_row("Events", s.get("events", 0)),
            metric_row("File Anomalies",
                      s.get("file_anomalies", 0),
                      "red" if s.get("file_anomalies", 0) > 0 else ""),
            metric_row("Quarantined",
                      s.get("quarantined", 0),
                      "red" if s.get("quarantined", 0) > 0 else ""),
        ]

        return metrics_widget(
            widget_id="security",
            title="Security AI",
            rows=rows,
            priority=20,
        )
    except Exception as e:
        return metrics_widget(
            widget_id="security",
            title="Security AI",
            rows=[metric_row("Status", "error", "red")],
            priority=20,
        )
