# ==============================================================
# OMEGA OS - Security AI
# ==============================================================
# Sections 6.3 and 11 of the OMEGA spec, adapted for Termux.
#
# Components:
#   - FileWatcher      : sensitive file access monitor
#   - ProcessWatcher   : new process detection
#   - BehaviorAnalyzer : baseline + anomaly detection
#   - TrustStore       : persistent trust scores (JSON)
#   - IncidentLogger   : append-only incident log
#   - SecurityAI       : orchestrator
#
# Now publishes events to the Message Bus (bus.py + bus_hooks.py).
# ==============================================================

import os
import re
import json
import time
import stat
import math
import hashlib
import subprocess
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict, deque

from omega import WorkloadClass
from processes import Process, ProcessScanner, WorkloadClassifier

# ── Message Bus integration ──
try:
    from bus_hooks import (
        emit_security_threat,
        emit_security_level_change,
        emit_trust_change,
    )
    _BUS_ENABLED = True
except Exception:
    _BUS_ENABLED = False
    def emit_security_threat(*a, **k): pass
    def emit_security_level_change(*a, **k): pass
    def emit_trust_change(*a, **k): pass


# ==============================================================
# Configuration
# ==============================================================

HOME = os.path.expanduser("~")
PREFIX = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")

SENSITIVE_PATHS = [
    os.path.join(HOME, ".ssh"),
    os.path.join(HOME, ".termux"),
    os.path.join(HOME, ".bashrc"),
    os.path.join(HOME, ".zshrc"),
    os.path.join(HOME, ".profile"),
    os.path.join(PREFIX, "etc"),
    "/etc/passwd",
    "/etc/hosts",
]

SAFE_PROCESSES = {
    "runsvdir", "runsv", "svlogd", "sshd", "ssh-agent", "crond",
    "httpd", "nginx", "postgres", "mysqld", "zsh", "bash",
    "python", "python3", "ps", "top", "grep", "sed", "awk",
    "cat", "head", "tail", "ls", "cd", "git", "pkg", "apt",
    "termux-battery-status", "login", "sh",
}

SUSPICIOUS_PATTERNS = [
    (r"nc\s+-l", "netcat_listener", 60),
    (r"ncat\s+-l", "ncat_listener", 60),
    (r"curl.*\|\s*(sh|bash)", "pipe_to_shell", 90),
    (r"wget.*\|\s*(sh|bash)", "pipe_to_shell", 90),
    (r"base64\s+-d.*\|.*sh", "obfuscated_shell", 95),
    (r"/tmp/\.", "hidden_in_tmp", 50),
    (r"/dev/shm/", "running_in_shm", 60),
    (r"\./\.\/\.\/", "path_obfuscation", 40),
    (r"chmod\s+777", "weak_permissions", 30),
    (r"rm\s+-rf\s+/", "destructive_rm", 100),
    (r"dd\s+if=/dev/zero", "disk_wipe_attempt", 95),
]


# ==============================================================
# Incident
# ==============================================================

@dataclass
class Incident:
    ts: int
    severity: str
    category: str
    subject: str
    detail: str
    action: str = "logged"

    def to_dict(self):
        return asdict(self)


# ==============================================================
# Trust Store
# ==============================================================

class TrustStore:

    def __init__(self, path: str = "trust.json"):
        self.path = path
        self.scores: Dict[str, int] = {}
        self.load()

    def load(self) -> None:
        try:
            with open(self.path) as f:
                data = json.load(f)
            self.scores = data.get("scores", {})
        except (FileNotFoundError, json.JSONDecodeError):
            self.scores = {}

    def save(self) -> None:
        with open(self.path, "w") as f:
            json.dump({"scores": self.scores}, f, indent=2)

    def get(self, subject: str, default: int = 50) -> int:
        return self.scores.get(subject, default)

    def set(self, subject: str, score: int) -> None:
        self.scores[subject] = max(0, min(100, score))

    def adjust(self, subject: str, delta: int) -> int:
        cur = self.get(subject)
        new = max(0, min(100, cur + delta))
        self.scores[subject] = new
        # Emit trust change
        if cur != new:
            try:
                emit_trust_change(subject, cur, new)
            except Exception:
                pass
        return new

    def mark_trusted(self, subject: str) -> None:
        self.scores[subject] = 90

    def mark_dangerous(self, subject: str) -> None:
        self.scores[subject] = 5


# ==============================================================
# Incident Logger
# ==============================================================

class IncidentLogger:

    def __init__(self, path: str = "incidents.jsonl"):
        self.path = path

    def log(self, inc: Incident) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(inc.to_dict(), ensure_ascii=False) + "\n")

    def tail(self, n: int = 20) -> List[dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            lines = f.readlines()
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def count(self) -> int:
        if not os.path.exists(self.path):
            return 0
        with open(self.path) as f:
            return sum(1 for _ in f)


# ==============================================================
# File Watcher
# ==============================================================

class FileWatcher:

    def __init__(self, paths: List[str]):
        self.paths = paths
        self.baseline: Dict[str, dict] = {}
        self.first_scan = True

    def _file_signature(self, path: str) -> Optional[dict]:
        try:
            st = os.stat(path)
            if not stat.S_ISREG(st.st_mode):
                return None
            h = hashlib.sha256()
            with open(path, "rb") as f:
                h.update(f.read(1024 * 1024))
            return {
                "mtime": int(st.st_mtime),
                "size": st.st_size,
                "sha256": h.hexdigest()[:16],
            }
        except (OSError, PermissionError):
            return None

    def _iter_files(self):
        for p in self.paths:
            if os.path.isfile(p):
                yield p
            elif os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    if root.count(os.sep) - p.count(os.sep) > 2:
                        dirs[:] = []
                        continue
                    for f in files:
                        yield os.path.join(root, f)

    def scan(self) -> List[Tuple[str, str, dict]]:
        events = []
        seen = set()

        for path in self._iter_files():
            sig = self._file_signature(path)
            if sig is None:
                continue
            seen.add(path)

            old = self.baseline.get(path)
            if old is None:
                if not self.first_scan:
                    events.append(("new", path, sig))
            else:
                if old["sha256"] != sig["sha256"]:
                    events.append(("changed", path, sig))

            self.baseline[path] = sig

        for path in list(self.baseline.keys()):
            if path not in seen:
                events.append(("deleted", path, {}))
                del self.baseline[path]

        if self.first_scan:
            self.first_scan = False
            return []
        return events


# ==============================================================
# Process Watcher
# ==============================================================

class ProcessWatcher:

    def __init__(self):
        self.known_pids: Set[int] = set()
        self.first_scan = True

    def scan(self, procs: List[Process]) -> List[Tuple[str, Process, int]]:
        events = []
        current_pids = {p.pid for p in procs}

        if not self.first_scan:
            new_pids = current_pids - self.known_pids
            for p in procs:
                if p.pid in new_pids:
                    reason = self._check_suspicious(p)
                    if reason:
                        events.append((reason, p, self._severity_for(reason)))
        else:
            self.first_scan = False

        self.known_pids = current_pids
        return events

    def _check_suspicious(self, p: Process) -> Optional[str]:
        target = f"{p.comm} {p.args}".lower()

        for pat, name, _ in SUSPICIOUS_PATTERNS:
            if re.search(pat, target, re.IGNORECASE):
                return name

        if p.args.startswith("/tmp/") or "/dev/shm/" in p.args:
            return "unusual_location"

        name = p.comm.lower()
        if name not in SAFE_PROCESSES:
            if not p.args.startswith(HOME) and \
               not p.args.startswith(PREFIX):
                if p.cpu_percent > 20:
                    return "unknown_high_cpu"
                return "unknown_binary"

        return None

    def _severity_for(self, reason: str) -> int:
        for _, name, sev in SUSPICIOUS_PATTERNS:
            if name == reason:
                return sev
        return {
            "unknown_binary": 15,
            "unknown_high_cpu": 40,
            "unusual_location": 55,
        }.get(reason, 30)


# ==============================================================
# Behavior Analyzer
# ==============================================================

class BehaviorAnalyzer:

    WINDOW = 30
    MIN_SAMPLES = 5

    def __init__(self):
        self.cpu_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.WINDOW))

    def update(self, procs: List[Process]) -> List[Tuple[str, Process, float, float]]:
        anomalies = []
        for p in procs:
            name = p.comm
            if not name:
                continue
            hist = self.cpu_history[name]
            hist.append(p.cpu_percent)

            if len(hist) < self.MIN_SAMPLES:
                continue

            mean = sum(hist) / len(hist)
            var = sum((x - mean) ** 2 for x in hist) / len(hist)
            std = math.sqrt(var)

            if std > 0.1 and p.cpu_percent > mean + 3 * std and p.cpu_percent > 25:
                anomalies.append(("cpu_spike", p, p.cpu_percent, mean))
        return anomalies


# ==============================================================
# Security AI
# ==============================================================

class SecurityAI:

    def __init__(self, state_dir: str = "."):
        self.state_dir = state_dir
        self.trust = TrustStore(os.path.join(state_dir, "trust.json"))
        self.logger = IncidentLogger(os.path.join(state_dir, "incidents.jsonl"))
        self.file_watcher = FileWatcher(SENSITIVE_PATHS)
        self.process_watcher = ProcessWatcher()
        self.behavior = BehaviorAnalyzer()
        self.scanner = ProcessScanner()

        self.recent: deque = deque(maxlen=20)
        self.total_incidents = self.logger.count()
        self.threat_level = "NORMAL"
        self._prev_threat = None

    # ──────────────────────────────────────────────────────────

    def _emit(self, severity: str, category: str, subject: str,
              detail: str, action: str = "logged"):
        inc = Incident(
            ts=int(time.time() * 1000),
            severity=severity,
            category=category,
            subject=subject,
            detail=detail,
            action=action,
        )
        self.logger.log(inc)
        self.recent.append(inc.to_dict())
        self.total_incidents += 1

        # ── Mirror to Message Bus ──
        try:
            emit_security_threat(
                severity=severity,
                subject=subject,
                detail=detail,
                category=category,
            )
        except Exception:
            pass

    def _recompute_threat_level(self):
        if not self.recent:
            self.threat_level = "NORMAL"
        else:
            sev_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            recent_list = list(self.recent)[-5:]
            max_sev = max(sev_rank.get(i["severity"], 0) for i in recent_list)
            if max_sev >= 4:
                self.threat_level = "CRITICAL"
            elif max_sev == 3:
                self.threat_level = "HIGH"
            elif max_sev == 2:
                self.threat_level = "ELEVATED"
            else:
                self.threat_level = "NORMAL"

        # ── Emit level change to bus ──
        if self._prev_threat is not None and self._prev_threat != self.threat_level:
            try:
                emit_security_level_change(self._prev_threat, self.threat_level)
            except Exception:
                pass
        self._prev_threat = self.threat_level

    # ──────────────────────────────────────────────────────────

    def scan(self) -> dict:
        # ── File events ──
        file_events = self.file_watcher.scan()
        for evt, path, info in file_events:
            if evt == "changed":
                sev = "MEDIUM" if any(s in path for s in (".ssh", ".termux")) else "LOW"
                self._emit(sev, "file", path, "sensitive file modified")
                self.trust.adjust(path, -5)
            elif evt == "new":
                self._emit("LOW", "file", path, "new file in sensitive dir")
            elif evt == "deleted":
                self._emit("MEDIUM", "file", path, "sensitive file deleted")

        # ── Process events ──
        procs = self.scanner.scan()
        proc_events = self.process_watcher.scan(procs)

        for reason, p, score in proc_events:
            if score >= 80:
                sev = "CRITICAL"
            elif score >= 60:
                sev = "HIGH"
            elif score >= 40:
                sev = "MEDIUM"
            elif score >= 20:
                sev = "LOW"
            else:
                sev = "INFO"

            delta = -max(1, score // 10)
            new_trust = self.trust.adjust(p.comm, delta)

            action = "logged"
            if new_trust < 20:
                action = "marked_dangerous"

            self._emit(sev, "process", p.comm,
                       f"{reason} (pid={p.pid}, cpu={p.cpu_percent:.1f}%)",
                       action=action)

        # ── Behavior anomalies ──
        anomalies = self.behavior.update(procs)
        for reason, p, cur, expected in anomalies:
            self._emit("MEDIUM", "behavior", p.comm,
                       f"{reason}: {cur:.1f}% (expected ~{expected:.1f}%)")
            self.trust.adjust(p.comm, -2)

        # ── Persist ──
        self.trust.save()

        self._recompute_threat_level()

        return {
            "threat_level": self.threat_level,
            "total_incidents": self.total_incidents,
            "recent": list(self.recent),
            "trusted_count": sum(1 for s in self.trust.scores.values() if s >= 70),
            "dangerous_count": sum(1 for s in self.trust.scores.values() if s < 20),
        }

    def recent_incidents(self, n: int = 5) -> List[dict]:
        return list(self.recent)[-n:]

    def trust_score(self, subject: str) -> int:
        return self.trust.get(subject)
