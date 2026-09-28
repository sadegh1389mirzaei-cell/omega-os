# ==============================================================
# OMEGA OS - Capability Store
# ==============================================================
# Section 3.7.1 of the OMEGA spec.
# Capability-based access control. No root user.
# ==============================================================

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, Set, List


class Cap:
    CAMERA            = "OM_CAP_CAMERA"
    MICROPHONE        = "OM_CAP_MICROPHONE"
    LOCATION_PRECISE  = "OM_CAP_LOCATION_PRECISE"
    CONTACTS_READ     = "OM_CAP_CONTACTS_READ"
    FILES_READ        = "OM_CAP_FILES_READ"
    FILES_WRITE       = "OM_CAP_FILES_WRITE"
    PROJECTS_READ     = "OM_CAP_PROJECTS_READ"
    PROJECTS_WRITE    = "OM_CAP_PROJECTS_WRITE"
    NETWORK           = "OM_CAP_NETWORK"
    BACKGROUND        = "OM_CAP_BACKGROUND"
    SYSTEM            = "OM_CAP_SYSTEM"


ALL_CAPS = [
    v for k, v in vars(Cap).items()
    if not k.startswith("_") and isinstance(v, str)
]


@dataclass
class ProcessCaps:
    pid: int
    name: str
    caps: Set[str] = field(default_factory=set)
    trust: int = 50


class CapabilityStore:
    def __init__(self, path: str = "capabilities.json"):
        self.path = path
        self.processes: Dict[int, ProcessCaps] = {}
        self.grants: List[dict] = []
        self.denials = 0
        self.load()

    def load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            for p in d.get("processes", []):
                pc = ProcessCaps(p["pid"], p["name"],
                                set(p.get("caps", [])),
                                p.get("trust", 50))
                self.processes[pc.pid] = pc
            self.grants = d.get("grants", [])
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self):
        with open(self.path, "w") as f:
            json.dump({
                "processes": [
                    {"pid": p.pid, "name": p.name,
                     "caps": sorted(p.caps), "trust": p.trust}
                    for p in self.processes.values()
                ],
                "grants": self.grants[-200:],
            }, f, indent=2)

    def register(self, pid: int, name: str, trust: int = 50):
        self.processes[pid] = ProcessCaps(pid, name, set(), trust)

    def grant(self, pid: int, cap: str) -> bool:
        if pid not in self.processes:
            return False
        if cap not in ALL_CAPS:
            return False
        self.processes[pid].caps.add(cap)
        self.grants.append({"pid": pid, "cap": cap, "action": "grant"})
        self.save()
        return True

    def revoke(self, pid: int, cap: str) -> bool:
        if pid not in self.processes:
            return False
        if cap in self.processes[pid].caps:
            self.processes[pid].caps.discard(cap)
            self.grants.append({"pid": pid, "cap": cap, "action": "revoke"})
            self.save()
            return True
        return False

    def check(self, pid: int, cap: str) -> bool:
        p = self.processes.get(pid)
        if p is None:
            self.denials += 1
            return False
        if cap not in p.caps:
            self.denials += 1
            return False
        return True

    def print_table(self):
        print(f"{'PID':<6} {'NAME':<20} {'TRUST':<6} CAPS")
        print("-" * 72)
        for p in self.processes.values():
            caps_str = ", ".join(
                sorted(c.replace("OM_CAP_", "") for c in p.caps)
            ) or "(none)"
            print(f"{p.pid:<6} {p.name:<20} {p.trust:<6} {caps_str}")


if __name__ == "__main__":
    store = CapabilityStore("capabilities.json")
    store.register(100, "photo_editor",    65)
    store.register(101, "browser",         80)
    store.register(102, "suspicious_app",  25)

    store.grant(100, Cap.CAMERA)
    store.grant(100, Cap.FILES_READ)
    store.grant(101, Cap.NETWORK)
    store.grant(101, Cap.FILES_READ)
    store.grant(102, Cap.CONTACTS_READ)

    print("=" * 72)
    print("  OMEGA Capability Store")
    print("=" * 72)
    store.print_table()
    print()
    print(f"check 100 CAMERA     : {store.check(100, Cap.CAMERA)}")
    print(f"check 101 CAMERA     : {store.check(101, Cap.CAMERA)}")
    print(f"check 102 CONTACTS   : {store.check(102, Cap.CONTACTS_READ)}")
    print()
    print("revoking CONTACTS from 102...")
    store.revoke(102, Cap.CONTACTS_READ)
    print(f"check 102 CONTACTS   : {store.check(102, Cap.CONTACTS_READ)}")
    print()
    print(f"total denials        : {store.denials}")
