# ==============================================================
# OMEGA OS - App Sandbox Runtime
# ==============================================================
# Section 11.2 of the OMEGA spec.
# Simulates per-app capability enforcement + resource limits.
# ==============================================================

import os
import time
import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional

from capabilities import CapabilityStore, Cap, ALL_CAPS


class SandboxViolation(Exception):
    pass


class SandboxLevel(IntEnum):
    STANDARD   = 0   # normal apps
    ELEVATED   = 1   # system services
    RESTRICTED = 2   # untrusted


@dataclass
class SandboxConfig:
    app_id: str
    name: str
    level: SandboxLevel = SandboxLevel.STANDARD
    trust: int = 50
    cpu_limit_pct: int = 100
    mem_limit_mb: int = 0            # 0 = unlimited
    background_allowed: bool = False
    network_allowed: bool = False


@dataclass
class SandboxStats:
    app_id: str
    cpu_violations: int = 0
    mem_violations: int = 0
    cap_denials: int = 0
    network_attempts_blocked: int = 0
    file_attempts_blocked: int = 0
    started_at: int = 0


class Sandbox:
    """
    Represents a single app's sandbox.
    Enforces capability, CPU, memory, and background policies.
    """

    def __init__(self, cfg: SandboxConfig, cap_store: CapabilityStore):
        self.cfg = cfg
        self.caps = cap_store
        self.stats = SandboxStats(app_id=cfg.app_id,
                                  started_at=int(time.time() * 1000))

        # register process in cap store
        cap_store.register(cfg.app_id.__hash__() & 0xFFFF,
                          cfg.name, trust=cfg.trust)

        # auto-grant based on config (mirrors manifest declarations)
        pid = cfg.app_id.__hash__() & 0xFFFF

        # Any app with network_allowed=True gets NETWORK at install time
        # (mirrors android.permission.INTERNET in the manifest).
        if cfg.network_allowed:
            cap_store.grant(pid, Cap.NETWORK)

        # Background apps implicitly get BACKGROUND (Section 10.3.3)
        if cfg.background_allowed:
            cap_store.grant(pid, Cap.BACKGROUND)

        # Elevated (system) apps get full filesystem + system
        if cfg.level == SandboxLevel.ELEVATED:
            cap_store.grant(pid, Cap.FILES_READ)
            cap_store.grant(pid, Cap.FILES_WRITE)
            cap_store.grant(pid, Cap.SYSTEM)

    @property
    def _pid(self) -> int:
        return self.cfg.app_id.__hash__() & 0xFFFF

    # ──────────────────────────────────────────────────────────
    # Permission checks
    # ──────────────────────────────────────────────────────────

    def request_capability(self, cap: str, reason: str = "") -> bool:
        """App requests a capability. Returns True if granted."""
        if self.caps.check(self._pid, cap):
            return True
        self.stats.cap_denials += 1
        return False

    def request_network(self) -> bool:
        if not self.cfg.network_allowed:
            self.stats.network_attempts_blocked += 1
            return False
        return self.request_capability(Cap.NETWORK)

    def request_file(self, write: bool = False) -> bool:
        cap = Cap.FILES_WRITE if write else Cap.FILES_READ
        if self.request_capability(cap):
            return True
        self.stats.file_attempts_blocked += 1
        return False

    def request_camera(self) -> bool:
        return self.request_capability(Cap.CAMERA)

    def request_location(self) -> bool:
        return self.request_capability(Cap.LOCATION_PRECISE)

    # ──────────────────────────────────────────────────────────
    # Resource enforcement
    # ──────────────────────────────────────────────────────────

    def enforce_cpu(self, current_pct: int) -> int:
        """Return the throttled CPU value."""
        if current_pct > self.cfg.cpu_limit_pct:
            self.stats.cpu_violations += 1
            return self.cfg.cpu_limit_pct
        return current_pct

    def enforce_memory(self, current_mb: int) -> int:
        """Return the throttled memory value."""
        if self.cfg.mem_limit_mb and current_mb > self.cfg.mem_limit_mb:
            self.stats.mem_violations += 1
            return self.cfg.mem_limit_mb
        return current_mb

    # ──────────────────────────────────────────────────────────

    def is_trusted(self) -> bool:
        return self.cfg.trust >= 70

    def is_dangerous(self) -> bool:
        return self.cfg.trust < 20

    def summary(self) -> dict:
        return {
            "app_id": self.cfg.app_id,
            "name": self.cfg.name,
            "level": self.cfg.level.name,
            "trust": self.cfg.trust,
            "denials": self.stats.cap_denials,
            "cpu_violations": self.stats.cpu_violations,
            "mem_violations": self.stats.mem_violations,
            "net_blocked": self.stats.network_attempts_blocked,
            "file_blocked": self.stats.file_attempts_blocked,
        }


# ==============================================================
# Sandbox Manager
# ==============================================================

class SandboxManager:

    def __init__(self, cap_store: Optional[CapabilityStore] = None):
        self.caps = cap_store or CapabilityStore("capabilities.json")
        self.sandboxes: Dict[str, Sandbox] = {}

    def create(self, cfg: SandboxConfig) -> Sandbox:
        sb = Sandbox(cfg, self.caps)
        self.sandboxes[cfg.app_id] = sb
        return sb

    def get(self, app_id: str) -> Optional[Sandbox]:
        return self.sandboxes.get(app_id)

    def remove(self, app_id: str):
        self.sandboxes.pop(app_id, None)

    def all_stats(self) -> List[dict]:
        return [sb.summary() for sb in self.sandboxes.values()]

    def total_denials(self) -> int:
        return sum(sb.stats.cap_denials for sb in self.sandboxes.values())

    def save(self):
        self.caps.save()


# ==============================================================
# Demo
# ==============================================================

def demo():
    print()
    print("=" * 68)
    print("  OMEGA Sandbox — capability enforcement demo")
    print("=" * 68)

    mgr = SandboxManager()

    # Three typical apps
    apps = [
        SandboxConfig("com.omega.mail", "Mail",
                     level=SandboxLevel.STANDARD,
                     trust=90, network_allowed=True,
                     background_allowed=True, mem_limit_mb=300),
        SandboxConfig("com.thirdparty.cleaner", "System Cleaner",
                     level=SandboxLevel.RESTRICTED,
                     trust=15, network_allowed=False,
                     background_allowed=False, mem_limit_mb=100),
        SandboxConfig("com.omega.settings", "Settings",
                     level=SandboxLevel.ELEVATED,
                     trust=95, network_allowed=False,
                     background_allowed=True),
    ]

    print()
    print("[1] Creating sandboxes...")
    for cfg in apps:
        sb = mgr.create(cfg)
        print(f"    ✓ {sb.cfg.name:<20} trust={sb.cfg.trust} "
              f"level={sb.cfg.level.name}")

    # Simulate various requests
    print()
    print("[2] Simulating permission requests:")
    print()
    print(f"  {'APP':<20} {'REQUEST':<25} {'RESULT':<10}")
    print("  " + "─" * 60)

    requests = [
        ("com.omega.mail", "network", lambda s: s.request_network()),
        ("com.omega.mail", "file_read", lambda s: s.request_file(False)),
        ("com.omega.mail", "camera", lambda s: s.request_camera()),
        ("com.thirdparty.cleaner", "network", lambda s: s.request_network()),
        ("com.thirdparty.cleaner", "file_write",
         lambda s: s.request_file(True)),
        ("com.thirdparty.cleaner", "location",
         lambda s: s.request_location()),
        ("com.omega.settings", "file_write",
         lambda s: s.request_file(True)),
        ("com.omega.settings", "system",
         lambda s: s.request_capability(Cap.SYSTEM)),
    ]

    for app_id, req_name, fn in requests:
        sb = mgr.get(app_id)
        if not sb:
            continue
        ok = fn(sb)
        color = "\033[92m" if ok else "\033[91m"
        status = f"{color}{'ALLOW' if ok else 'DENY'}\033[0m"
        print(f"  {sb.cfg.name:<20} {req_name:<25} {status}")

    # Resource enforcement
    print()
    print("[3] Resource limit enforcement:")
    sb = mgr.get("com.thirdparty.cleaner")
    cpu = sb.enforce_cpu(150)
    mem = sb.enforce_memory(250)
    print(f"    {sb.cfg.name}:")
    print(f"      CPU 150% → {cpu}%  (limit {sb.cfg.cpu_limit_pct}%)")
    print(f"      MEM 250MB → {mem}MB  (limit {sb.cfg.mem_limit_mb}MB)")

    # Summary
    print()
    print("[4] Sandbox summaries:")
    print()
    print(f"  {'APP':<20} {'TRUST':<6} {'DENIALS':<8} "
          f"{'CPU':<5} {'MEM':<5} {'NET':<5} {'FILE':<5}")
    print("  " + "─" * 60)
    for s in mgr.all_stats():
        print(f"  {s['name']:<20} {s['trust']:<6} {s['denials']:<8} "
              f"{s['cpu_violations']:<5} {s['mem_violations']:<5} "
              f"{s['net_blocked']:<5} {s['file_blocked']:<5}")

    print()
    print(f"  Total capability denials: {mgr.total_denials()}")


if __name__ == "__main__":
    demo()
