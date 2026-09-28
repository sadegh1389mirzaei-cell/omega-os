# ==============================================================
# OMEGA OS - Bus Hooks
# ==============================================================
# Thin wrappers around bus.emit() for common scenarios.
# Import these instead of building Event objects directly.
# ==============================================================

from typing import Optional
from bus import EventBus, Topic, Event


# Global bus used by the hooks (set by whoever runs the system)
_bus: Optional[EventBus] = None


def set_bus(bus: EventBus) -> None:
    """Register the bus that hooks should use."""
    global _bus
    _bus = bus


def get_bus() -> Optional[EventBus]:
    return _bus


def _safe_emit(topic: str, source: str, severity: str = "INFO", **payload):
    if _bus is None:
        return
    try:
        _bus.emit(topic, source, severity=severity, **payload)
    except Exception:
        pass


# ── Telemetry ──
def emit_telemetry_sample(cpu: int, ram: int, battery: int,
                          temp_c: float, workload: str) -> None:
    _safe_emit(Topic.TELEMETRY_SAMPLE, "telemetry",
               cpu=cpu, ram=ram, battery=battery,
               temp=round(temp_c, 1), workload=workload)


def emit_temp_warning(temp_c: float, threshold: float) -> None:
    _safe_emit(Topic.TELEMETRY_TEMP_WARN, "telemetry",
               severity="MEDIUM", temp=round(temp_c, 1),
               threshold=round(threshold, 1))


# ── Decision Engine ──
def emit_decision_state(state: str, tier: str, thermal: str,
                        mode: str, reason: str) -> None:
    _safe_emit(Topic.DECISION_STATE, "decision",
               state=state, tier=tier, thermal=thermal,
               mode=mode, reason=reason[:60])


def emit_decision_change(old: str, new: str, reason: str) -> None:
    _safe_emit(Topic.DECISION_STATE_CHG, "decision",
               severity="LOW", old=old, new=new, reason=reason[:60])


def emit_decision_command(cpu_max: int, gpu_max: int, refresh: int) -> None:
    _safe_emit(Topic.DECISION_COMMAND, "decision",
               cpu_max=cpu_max, gpu_max=gpu_max, refresh=refresh)


# ── Security AI ──
def emit_security_threat(severity: str, subject: str, detail: str,
                         category: str = "process") -> None:
    _safe_emit(Topic.SECURITY_THREAT, "security_ai",
               severity=severity, subject=subject[:40],
               detail=detail[:60], category=category)


def emit_security_level_change(old: str, new: str) -> None:
    _safe_emit(Topic.SECURITY_LEVEL_CHG, "security_ai",
               severity="MEDIUM" if new in ("HIGH", "CRITICAL") else "LOW",
               old=old, new=new)


def emit_trust_change(subject: str, old: int, new: int) -> None:
    direction = "up" if new > old else "down"
    _safe_emit(Topic.SECURITY_TRUST_CHG, "security_ai",
               subject=subject[:30], old=old, new=new,
               direction=direction)


# ── Storage / OMFS ──
def emit_file_added(path: str, project: str, category: str) -> None:
    _safe_emit(Topic.STORAGE_FILE_ADDED, "omfs",
               file=path.split("/")[-1], project=project,
               category=category)


def emit_project_created(name: str, description: str = "") -> None:
    _safe_emit(Topic.STORAGE_PROJECT_NEW, "omfs",
               name=name, description=description[:40])


# ── System ──
def emit_system_boot(version: str) -> None:
    _safe_emit(Topic.SYSTEM_BOOT, "system", version=version)


def emit_system_shutdown() -> None:
    _safe_emit(Topic.SYSTEM_SHUTDOWN, "system")
