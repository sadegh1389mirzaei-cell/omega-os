# ==============================================================
# OMEGA OS - File Trust Store
# ==============================================================
# Section 6.3.3 of the OMEGA spec.
#
# Tracks files by content hash and maintains a dynamic Trust Score
# for each one. Trust evolves based on observed behavior:
#   - Repeated appearances without anomaly → trust increases
#   - Every file anomaly detected → trust decreases
#   - Trust below threshold → alert / quarantine candidate
# ==============================================================

import os
import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
TRUST_FILE = os.path.join(OMEGA_DIR, "file_trust.json")
TRUST_LOG = os.path.join(OMEGA_DIR, "file_trust.jsonl")


# ==============================================================
# Trust deltas
# ==============================================================

TRUST_INITIAL = 50

# Per event
TRUST_DELTA = {
    "seen_clean":     +1,   # seen again, no anomaly
    "seen_again":     +0,   # seen, no change
    "low_severity":   -3,
    "medium_severity":-10,
    "high_severity":  -25,
    "critical_severity": -50,
    "user_approved":  +40,  # explicit user approval
    "user_flagged":   -100, # explicit user flagged as bad
}

# Thresholds
TRUST_WARN = 30
TRUST_DANGER = 15
TRUST_TRUSTED = 80


# ==============================================================
# Data model
# ==============================================================

@dataclass
class FileTrustEntry:
    hash: str
    # The most recent path we saw this hash at
    last_path: str = ""
    last_name: str = ""
    # Counters
    seen_count: int = 0
    clean_count: int = 0
    anomaly_count: int = 0
    # Trust
    trust: int = TRUST_INITIAL
    # Timing
    first_seen: int = 0
    last_seen: int = 0
    # Anomaly history (list of (ts, anomaly, severity))
    history: List[Tuple[int, str, str]] = field(default_factory=list)

    def to_dict(self):
        return {
            "hash": self.hash,
            "last_path": self.last_path,
            "last_name": self.last_name,
            "seen_count": self.seen_count,
            "clean_count": self.clean_count,
            "anomaly_count": self.anomaly_count,
            "trust": self.trust,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "history": self.history[-20:],  # keep last 20
        }

    @classmethod
    def from_dict(cls, d):
        e = cls(hash=d["hash"])
        e.last_path = d.get("last_path", "")
        e.last_name = d.get("last_name", "")
        e.seen_count = d.get("seen_count", 0)
        e.clean_count = d.get("clean_count", 0)
        e.anomaly_count = d.get("anomaly_count", 0)
        e.trust = d.get("trust", TRUST_INITIAL)
        e.first_seen = d.get("first_seen", 0)
        e.last_seen = d.get("last_seen", 0)
        e.history = [tuple(h) for h in d.get("history", [])]
        return e

    def adjust_trust(self, delta: int):
        self.trust = max(0, min(100, self.trust + delta))

    def status(self) -> str:
        if self.trust >= TRUST_TRUSTED:
            return "TRUSTED"
        if self.trust <= TRUST_DANGER:
            return "DANGER"
        if self.trust <= TRUST_WARN:
            return "WARN"
        return "NEUTRAL"

    def age_human(self) -> str:
        if not self.first_seen:
            return "?"
        delta = (time.time() * 1000 - self.first_seen) / 1000
        if delta < 60:
            return f"{int(delta)}s"
        if delta < 3600:
            return f"{int(delta / 60)}m"
        if delta < 86400:
            return f"{int(delta / 3600)}h"
        return f"{int(delta / 86400)}d"




# ==============================================================
# File Trust Store
# ==============================================================

class FileTrustStore:

    def __init__(self, path: str = TRUST_FILE):
        self.path = path
        self.entries: Dict[str, FileTrustEntry] = {}
        self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            for h, entry in d.get("entries", {}).items():
                self.entries[h] = FileTrustEntry.from_dict(entry)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self):
        data = {
            "entries": {h: e.to_dict() for h, e in self.entries.items()},
            "updated": int(time.time() * 1000),
        }
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    # ─────────────────────────────────────────────────────
    # Recording
    # ─────────────────────────────────────────────────────

    def observe_clean(self, file_hash: str, path: str,
                      name: str) -> FileTrustEntry:
        """Record a clean observation of a file."""
        entry = self.entries.get(file_hash)
        now = int(time.time() * 1000)

        if entry is None:
            entry = FileTrustEntry(
                hash=file_hash,
                last_path=path,
                last_name=name,
                first_seen=now,
                last_seen=now,
                seen_count=1,
                clean_count=1,
                trust=TRUST_INITIAL,
            )
            self.entries[file_hash] = entry
        else:
            entry.seen_count += 1
            entry.clean_count += 1
            entry.last_path = path
            entry.last_name = name
            entry.last_seen = now
            entry.adjust_trust(TRUST_DELTA["seen_clean"])

        self._log("clean", entry)
        return entry

    def observe_anomaly(self, file_hash: str, path: str, name: str,
                        anomaly: str, severity: str) -> FileTrustEntry:
        """Record an anomaly for a file."""
        entry = self.entries.get(file_hash)
        now = int(time.time() * 1000)

        # Map severity to delta key
        delta_key = {
            "LOW":      "low_severity",
            "MEDIUM":   "medium_severity",
            "HIGH":     "high_severity",
            "CRITICAL": "critical_severity",
        }.get(severity, "low_severity")

        delta = TRUST_DELTA[delta_key]

        if entry is None:
            entry = FileTrustEntry(
                hash=file_hash,
                last_path=path,
                last_name=name,
                first_seen=now,
                last_seen=now,
                seen_count=1,
                anomaly_count=1,
                trust=max(0, TRUST_INITIAL + delta),
            )
            self.entries[file_hash] = entry
        else:
            entry.seen_count += 1
            entry.anomaly_count += 1
            entry.last_path = path
            entry.last_name = name
            entry.last_seen = now
            entry.adjust_trust(delta)

        # Add to history
        entry.history.append((now, anomaly, severity))
        if len(entry.history) > 20:
            entry.history = entry.history[-20:]

        self._log("anomaly", entry, anomaly, severity)
        return entry

    def user_approve(self, file_hash: str):
        """User explicitly approves a file."""
        entry = self.entries.get(file_hash)
        if entry:
            entry.adjust_trust(TRUST_DELTA["user_approved"])
            self._log("user_approved", entry)

    def user_flag(self, file_hash: str):
        """User explicitly flags a file as bad."""
        entry = self.entries.get(file_hash)
        if entry:
            entry.adjust_trust(TRUST_DELTA["user_flagged"])
            self._log("user_flagged", entry)

    # ─────────────────────────────────────────────────────
    # Querying
    # ─────────────────────────────────────────────────────

    def get(self, file_hash: str) -> Optional[FileTrustEntry]:
        return self.entries.get(file_hash)

    def by_status(self, status: str) -> List[FileTrustEntry]:
        return [e for e in self.entries.values()
                if e.status() == status]

    def top_risky(self, n: int = 10) -> List[FileTrustEntry]:
        return sorted(self.entries.values(),
                     key=lambda e: e.trust)[:n]

    def top_trusted(self, n: int = 10) -> List[FileTrustEntry]:
        return sorted(self.entries.values(),
                     key=lambda e: -e.trust)[:n]

    def stats(self) -> dict:
        by_status = {}
        for e in self.entries.values():
            s = e.status()
            by_status[s] = by_status.get(s, 0) + 1

        return {
            "total_files": len(self.entries),
            "by_status": by_status,
            "avg_trust": (sum(e.trust for e in self.entries.values())
                         / len(self.entries)) if self.entries else 0,
        }

    # ─────────────────────────────────────────────────────
    # Logging
    # ─────────────────────────────────────────────────────

    def _log(self, event: str, entry: FileTrustEntry,
             anomaly: str = "", severity: str = ""):
        record = {
            "ts": int(time.time() * 1000),
            "event": event,
            "hash": entry.hash,
            "name": entry.last_name,
            "trust": entry.trust,
            "status": entry.status(),
        }
        if anomaly:
            record["anomaly"] = anomaly
        if severity:
            record["severity"] = severity

        try:
            with open(TRUST_LOG, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass




# ==============================================================
# Integration helper
# ==============================================================

def integrate_with_monitor():
    """
    Read file_monitor.jsonl and update trust scores.
    Returns (clean_events, anomaly_events).
    """
    log_path = os.path.join(OMEGA_DIR, "file_monitor.jsonl")
    if not os.path.exists(log_path):
        return 0, 0

    store = FileTrustStore()

    # Track last processed timestamp
    state_file = os.path.join(OMEGA_DIR, "file_trust_state.json")
    last_ts = 0
    try:
        with open(state_file) as f:
            last_ts = json.load(f).get("last_ts", 0)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    clean = 0
    anomalies = 0
    new_last_ts = last_ts

    with open(log_path) as f:
        for line in f:
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = evt.get("ts", 0)
            if ts <= last_ts:
                continue

            file_hash = evt.get("hash", "")
            if not file_hash:
                continue

            name = evt.get("name", "?")
            path = evt.get("path", "")

            # File Monitor only logs anomalies — so each entry
            # is an anomaly. Clean files are not in this log.
            anomaly = evt.get("anomaly", "?")
            severity = evt.get("severity", "LOW")

            store.observe_anomaly(file_hash, path, name,
                                 anomaly, severity)
            anomalies += 1

            if ts > new_last_ts:
                new_last_ts = ts

    if anomalies:
        store.save()

    # Save state
    with open(state_file, "w") as f:
        json.dump({"last_ts": new_last_ts}, f)

    return clean, anomalies


# ==============================================================
# Display
# ==============================================================

def print_header(title: str):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def print_entry(e: FileTrustEntry):
    status = e.status()
    print(f"  [{status:<8}] trust={e.trust:<3} "
          f"seen={e.seen_count} anom={e.anomaly_count}")
    print(f"    name: {e.last_name}")
    print(f"    path: {e.last_path}")
    print(f"    hash: {e.hash}")
    if e.history:
        last = e.history[-1]
        print(f"    last anomaly: {last[1]} ({last[2]})")


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
OMEGA File Trust Store

Usage:
  python file_trust.py stats               show trust statistics
  python file_trust.py risky [N]           top N riskiest files
  python file_trust.py trusted [N]         top N most trusted files
  python file_trust.py status NAME         status of specific status
                                           (TRUSTED/WARN/DANGER/NEUTRAL)
  python file_trust.py integrate           read file_monitor.jsonl and
                                           update trust scores
  python file_trust.py info HASH           show entry by hash
  python file_trust.py help                this message
""")


def cli_stats():
    store = FileTrustStore()
    stats = store.stats()
    print_header("File Trust Statistics")
    print()
    print(f"  Total files: {stats['total_files']}")
    print(f"  Avg trust  : {stats['avg_trust']:.1f}")
    print()
    if stats['by_status']:
        print("  By status:")
        for st, count in sorted(stats['by_status'].items()):
            print(f"    {st:<10} {count}")


def cli_risky(n: int = 10):
    store = FileTrustStore()
    print_header(f"Top {n} Riskiest Files")
    entries = store.top_risky(n)
    if not entries:
        print("  (no files tracked yet)")
        return
    print()
    for e in entries:
        print_entry(e)
        print()


def cli_trusted(n: int = 10):
    store = FileTrustStore()
    print_header(f"Top {n} Trusted Files")
    entries = store.top_trusted(n)
    if not entries:
        print("  (no files tracked yet)")
        return
    print()
    for e in entries:
        print_entry(e)
        print()


def cli_status(status: str):
    store = FileTrustStore()
    entries = store.by_status(status.upper())
    print_header(f"Files with status: {status.upper()}")
    if not entries:
        print(f"  (no files with status {status})")
        return
    print()
    for e in entries:
        print_entry(e)
        print()


def cli_integrate():
    print_header("Integrating File Monitor → Trust Store")
    print()
    print("  Reading file_monitor.jsonl...")
    clean, anomalies = integrate_with_monitor()
    print(f"  Anomalies processed: {anomalies}")
    print()
    store = FileTrustStore()
    stats = store.stats()
    print(f"  Total tracked: {stats['total_files']}")
    print(f"  Avg trust    : {stats['avg_trust']:.1f}")
    if stats['by_status']:
        print()
        print("  By status:")
        for st, count in sorted(stats['by_status'].items()):
            print(f"    {st:<10} {count}")


def cli_info(hash_prefix: str):
    store = FileTrustStore()
    for h, e in store.entries.items():
        if h.startswith(hash_prefix):
            print_entry(e)
            return
    print(f"[!] No entry matching hash: {hash_prefix}")


def main():
    import sys
    if len(sys.argv) < 2:
        cli_help()
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd in ("help", "-h"):
        cli_help()
    elif cmd == "stats":
        cli_stats()
    elif cmd == "risky":
        n = int(args[0]) if args else 10
        cli_risky(n)
    elif cmd == "trusted":
        n = int(args[0]) if args else 10
        cli_trusted(n)
    elif cmd == "status":
        if not args:
            print("[!] usage: status NAME")
        else:
            cli_status(args[0])
    elif cmd == "integrate":
        cli_integrate()
    elif cmd == "info":
        if not args:
            print("[!] usage: info HASH")
        else:
            cli_info(args[0])
    else:
        print(f"[!] unknown command: {cmd}")
        cli_help()


if __name__ == "__main__":
    main()


# ==============================================================
# Web Widget for Dashboard
# ==============================================================

def web_widget() -> dict:
    """Dashboard widget for File Trust Store."""
    from widgets import metrics_widget, metric_row, list_widget

    try:
        store = FileTrustStore()
        stats = store.stats()

        by_status = stats.get("by_status", {})
        danger = by_status.get("DANGER", 0)
        warn = by_status.get("WARN", 0)
        trusted = by_status.get("TRUSTED", 0)

        # If there are DANGER files, show them as a list widget
        if danger > 0:
            risky = store.top_risky(5)
            items = []
            for e in risky:
                items.append({
                    "primary": e.last_name[:30],
                    "secondary": f"trust={e.trust} seen={e.seen_count}",
                    "badge": e.status(),
                })
            return list_widget(
                widget_id="file_trust",
                title=f"File Trust ({danger} DANGER)",
                items=items,
                priority=25,
                max_items=5,
            )

        # Otherwise show metrics
        return metrics_widget(
            widget_id="file_trust",
            title="File Trust",
            rows=[
                metric_row("Tracked", stats.get("total_files", 0), "cyan"),
                metric_row("Trusted", trusted, "green"),
                metric_row("WARN", warn, "yellow"),
                metric_row("DANGER", danger,
                          "red" if danger > 0 else ""),
                metric_row("Avg Trust",
                          f"{stats.get('avg_trust', 0):.1f}"),
            ],
            priority=25,
        )
    except Exception as e:
        return metrics_widget(
            widget_id="file_trust",
            title="File Trust",
            rows=[metric_row("Status", "error", "red")],
            priority=25,
        )
