# ==============================================================
# OMEGA OS - Process Scanner + Workload Classifier
# ==============================================================
# Reads running processes and classifies them into workload
# categories (Section 6.2.5 of the OMEGA spec).
# ==============================================================

import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from collections import defaultdict

from omega import WorkloadClass


# ==============================================================
# Pattern tables
# ==============================================================

# Each pattern: (regex, workload, weight)
# Order matters — first match wins.
PATTERNS = [
    # GAMING
    (r"com\.miHoYo|com\.epicgames|com\.supercell|com\.riotgames|"
     r"com\.tencent\.tmgp|unity|unreal|com\.roblox|com\.mojang|"
     r"com\.mojang\.minecraft|com\.ea\.|com\.ubisoft|com\.activision",
     WorkloadClass.GAMING_HEAVY, 10),
    (r"com\.king\.|com\.zynga|com\.playrix|com\.peakgames|"
     r"com\.dreamgames|com\.ketchapp|gameloft",
     WorkloadClass.GAMING_LIGHT, 6),

    # VIDEO
    (r"org\.videolan\.vlc|com\.google\.android\.youtube|"
     r"com\.netflix|com\.spotify\.music|com\.soundcloud|"
     r"mpv|vlc|youtube|netflix|hulu|twitch",
     WorkloadClass.VIDEO, 8),

    # VIDEO / Streaming in browser
    (r"youtube\.com|twitch\.tv|netflix\.com",
     WorkloadClass.VIDEO, 6),

    # COMPUTE / DEV
    (r"gcc|clang|rustc|cargo|python|node|java|javac|gradle|"
     r"kotlin|make|cmake|docker|podman|git-|npm|yarn|pip",
     WorkloadClass.COMPUTE, 8),
    (r"code-server|vim|nvim|emacs|tmux|htop|top",
     WorkloadClass.COMPUTE, 4),

    # CREATIVE
    (r"com\.adobe\.|adobe|photoshop|premiere|aftereffects|"
     r"com\.autodesk|blender|gimp|inkscape|krita|"
     r"com\.canva|com\.picsart|com\.lightricks",
     WorkloadClass.CREATIVE, 9),

    # WEB / BROWSER
    (r"chrome|firefox|chromium|brave|opera|vivaldi|edge|"
     r"com\.android\.chrome|org\.mozilla\.firefox",
     WorkloadClass.WEB, 5),

    # LIGHT / PRODUCTIVITY
    (r"com\.google\.android\.gm|com\.microsoft\.office|"
     r"docs|gmail|com\.android\.vending|com\.whatsapp|"
     r"com\.telegram|org\.telegram|com\.discord|"
     r"com\.slack|com\.zoom|com\.microsoft\.teams|"
     r"com\.google\.android\.apps\.messaging|"
     r"com\.google\.android\.apps\.maps|com\.waze",
     WorkloadClass.LIGHT, 4),

    # MUSIC (light background)
    (r"com\.spotify|com\.google\.android\.apps\.youtube\.music|"
     r"com\.soundcloud|music|audacious|rhythmbox",
     WorkloadClass.LIGHT, 2),

    # SYSTEM (don't count as user workload)
    (r"^\[|kworker|kthread|ksoftirqd|migration|rcu_|irq/|"
     r"init|systemd|kerneld|watchdog|zygote|surfaceflinger|"
     r"servicemanager|hwservicemanager|vold|netd|logd|"
     r"runsv|sshd|termux|com\.termux",
     WorkloadClass.SYSTEM if hasattr(WorkloadClass, "SYSTEM") else WorkloadClass.LIGHT,
     0),   # weight 0 = ignore
]


# ==============================================================
# Process record
# ==============================================================

@dataclass
class Process:
    pid: int
    user: str
    comm: str
    args: str
    cpu_percent: float = 0.0

    @property
    def name(self) -> str:
        return self.comm or self.args.split()[0] if self.args else "?"

    def matches(self, pattern: str) -> bool:
        target = f"{self.comm} {self.args}".lower()
        return bool(re.search(pattern, target, re.IGNORECASE))


# ==============================================================
# Scanner
# ==============================================================

class ProcessScanner:

    def __init__(self):
        self.last_procs: List[Process] = []
        self.last_error: Optional[str] = None

    def scan(self) -> List[Process]:
        """Read processes via ps. Returns list of Process objects."""
        self.last_error = None
        procs = []

        # Try with %CPU first
        try:
            r = subprocess.run(
                ["ps", "-eo", "pid,user,pcpu,comm,args"],
                capture_output=True, timeout=4,
            )
            if r.returncode == 0:
                procs = self._parse_with_cpu(r.stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            self.last_error = str(e)

        if not procs:
            # Fallback without %CPU
            try:
                r = subprocess.run(
                    ["ps", "-eo", "pid,user,comm,args"],
                    capture_output=True, timeout=4,
                )
                if r.returncode == 0:
                    procs = self._parse_no_cpu(r.stdout.decode("utf-8", errors="ignore"))
            except Exception as e:
                self.last_error = str(e)

        self.last_procs = procs
        return procs

    def _parse_with_cpu(self, text: str) -> List[Process]:
        lines = text.splitlines()
        if not lines:
            return []
        procs = []
        for line in lines[1:]:
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            try:
                pid = int(parts[0])
                user = parts[1]
                cpu = float(parts[2])
                comm = parts[3]
                args = parts[4]
            except (ValueError, IndexError):
                continue
            procs.append(Process(pid, user, comm, args, cpu))
        return procs

    def _parse_no_cpu(self, text: str) -> List[Process]:
        lines = text.splitlines()
        if not lines:
            return []
        procs = []
        for line in lines[1:]:
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
                user = parts[1]
                comm = parts[2]
                args = parts[3]
            except (ValueError, IndexError):
                continue
            procs.append(Process(pid, user, comm, args))
        return procs


# ==============================================================
# Classifier
# ==============================================================

class WorkloadClassifier:
    """
    Classifies workload from a list of processes.
    Produces a WorkloadClass + confidence + top contributors.
    """

    def __init__(self):
        self.last_scores: Dict[WorkloadClass, int] = {}
        self.last_top_processes: List[Process] = []
        self.last_summary: str = ""

    def classify(self, procs: List[Process]) -> tuple:
        """
        Returns:
            (workload: WorkloadClass, confidence: int 0-100, summary: str)
        """
        scores: Dict[WorkloadClass, int] = defaultdict(int)
        contributors: Dict[WorkloadClass, List[Process]] = defaultdict(list)

        for p in procs:
            for pattern, wc, weight in PATTERNS:
                if weight == 0:
                    continue
                if p.matches(pattern):
                    # Weight by CPU if available
                    cpu_factor = max(0.5, p.cpu_percent / 5.0) if p.cpu_percent else 1.0
                    effective = int(weight * cpu_factor)
                    scores[wc] += effective
                    contributors[wc].append(p)
                    break   # first match wins

        if not scores:
            # No match: fall back to top CPU process
            return WorkloadClass.LIGHT, 20, "no patterns matched"

        # Pick winner
        winner = max(scores.items(), key=lambda kv: kv[1])
        wc, score = winner

        total = sum(scores.values()) or 1
        confidence = min(100, int(score * 100 / total))

        # Top contributors
        top = sorted(contributors[wc],
                     key=lambda p: p.cpu_percent,
                     reverse=True)[:3]
        names = ", ".join(p.name[:12] for p in top) if top else "?"

        self.last_scores = dict(scores)
        self.last_top_processes = top
        summary = f"{wc.name} ({confidence}%) via {names}"
        self.last_summary = summary
        return wc, confidence, summary

    def top_processes(self, procs: List[Process], n: int = 3) -> List[Process]:
        """Return top-n processes by CPU."""
        valid = [p for p in procs if p.cpu_percent > 0.1]
        return sorted(valid, key=lambda p: p.cpu_percent, reverse=True)[:n]


# ==============================================================
# Standalone test
# ==============================================================

if __name__ == "__main__":
    scanner = ProcessScanner()
    classifier = WorkloadClassifier()

    procs = scanner.scan()
    print(f"Scanned {len(procs)} processes")
    if scanner.last_error:
        print(f"Error: {scanner.last_error}")

    print("\n--- Top 10 by CPU ---")
    for p in classifier.top_processes(procs, 10):
        print(f"  {p.cpu_percent:>5.1f}%  {p.pid:>6}  {p.user:<12} {p.name[:30]}")

    wc, conf, summary = classifier.classify(procs)
    print(f"\nClassified: {summary}")

    if classifier.last_scores:
        print("\n--- Score breakdown ---")
        for wc_k, s in sorted(classifier.last_scores.items(),
                              key=lambda kv: kv[1], reverse=True):
            print(f"  {wc_k.name:<14} {s}")
