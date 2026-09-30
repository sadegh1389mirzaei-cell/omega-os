
# ==============================================================
# OMEGA OS - Quarantine Manager
# ==============================================================
# Section 11.5.1 of the OMEGA spec.
# When a threat reaches HIGH or CRITICAL severity,
# we kill the process and log it to quarantine.
# ==============================================================

import os
import json
import time
import signal
from datetime import datetime
from typing import List, Dict, Optional


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
QUARANTINE_LOG = os.path.join(OMEGA_DIR, "quarantine.jsonl")
WHITELIST_FILE = os.path.join(OMEGA_DIR, "whitelist.json")


class QuarantineManager:

    def __init__(self):
        self.killed: List[dict] = []
        self.whitelist: set = set()
        self._load()

    def _load(self):
        try:
            with open(WHITELIST_FILE) as f:
                self.whitelist = set(json.load(f).get("processes", []))
        except (FileNotFoundError, json.JSONDecodeError):
            self.whitelist = set()

    def _save(self):
        with open(WHITELIST_FILE, "w") as f:
            json.dump({"processes": sorted(self.whitelist)}, f, indent=2)

    def is_whitelisted(self, name: str) -> bool:
        base = name.split()[0].split("/")[-1]
        return name in self.whitelist or base in self.whitelist

    def whitelist(self, name: str):
        self.whitelist.add(name)
        self._save()

    def unwhitelist(self, name: str):
        self.whitelist.discard(name)
        self._save()

    def kill_process(self, pid: int, name: str,
                     severity: str, reason: str,
                     dry_run: bool = False) -> dict:
        """
        Kill a process (or simulate). Returns a record.
        """
        record = {
            "ts": int(time.time() * 1000),
            "pid": pid,
            "name": name,
            "severity": severity,
            "reason": reason,
            "action": "killed" if not dry_run else "would_kill",
        }

        if dry_run:
            self.killed.append(record)
            self._log(record)
            return record

        if self.is_whitelisted(name):
            record["action"] = "whitelisted"
            self._log(record)
            return record

        # Actually try to kill
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.3)
            # Check if still alive
            try:
                os.kill(pid, 0)
                # Still alive — send SIGKILL
                os.kill(pid, signal.SIGKILL)
                record["action"] = "killed_force"
            except ProcessLookupError:
                record["action"] = "killed"
        except ProcessLookupError:
            record["action"] = "already_gone"
        except PermissionError:
            record["action"] = "permission_denied"
        except Exception as e:
            record["action"] = f"error: {e}"

        self.killed.append(record)
        self._log(record)
        return record

    def _log(self, record: dict):
        try:
            with open(QUARANTINE_LOG, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass

    def stats(self) -> dict:
        return {
            "killed_total": len(self.killed),
            "whitelisted": len(self.whitelist),
            "last_kill": (self.killed[-1]["name"]
                         if self.killed else None),
        }


if __name__ == "__main__":
    qm = QuarantineManager()
    print()
    print("=" * 60)
    print("  Quarantine Manager - Status")
    print("=" * 60)
    print()
    for k, v in qm.stats().items():
        print(f"  {k}: {v}")
    print()
    print(f"  Whitelist file: {WHITELIST_FILE}")
    print(f"  Log file: {QUARANTINE_LOG}")
    print()



# ==============================================================
# Web Widget for Dashboard
# ==============================================================

def web_widget() -> dict:
    """Dashboard widget for Quarantine Manager."""
    from widgets import metrics_widget, metric_row

    try:
        qm = QuarantineManager()
        s = qm.stats()

        killed = s.get("killed_total", 0)
        whitelisted = s.get("whitelisted", 0)
        last = s.get("last_kill")

        return metrics_widget(
            widget_id="quarantine",
            title="Quarantine",
            rows=[
                metric_row("Killed Total", killed,
                          "red" if killed > 0 else ""),
                metric_row("Whitelisted", whitelisted,
                          "green" if whitelisted > 0 else ""),
                metric_row("Last Kill", last or "—"),
            ],
            priority=35,
        )
    except Exception as e:
        return metrics_widget(
            widget_id="quarantine",
            title="Quarantine",
            rows=[metric_row("Status", "error", "red")],
            priority=35,
        )
