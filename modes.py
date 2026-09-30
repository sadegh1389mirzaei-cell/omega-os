# ==============================================================
# OMEGA OS - System Modes
# ==============================================================
# Section 7 of the OMEGA spec.
#
# Manages the four orthogonal state dimensions:
#   1. Device Mode    (Phone / Tablet / Desktop / Docked)
#   2. Performance    (Idle / Balanced / Performance / Creative / Compute)
#   3. Power Tier     (Normal / Low Power / Emergency)
#   4. Thermal State  (Normal / Warm / Throttle / Emergency)
#
# Also implements mode transitions with:
#   - User-driven triggers
#   - Automatic context-aware triggers
#   - Hysteresis for stability
#   - Event bus emission
# ==============================================================

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable, List, Tuple

try:
    from bus import EventBus, Topic
    _BUS = True
except Exception:
    _BUS = False


# ==============================================================
# Enums
# ==============================================================

class DeviceMode(IntEnum):
    PHONE   = 0
    TABLET  = 1
    DESKTOP = 2
    DOCKED  = 3


class PerfState(IntEnum):
    IDLE        = 0
    BALANCED    = 1
    PERFORMANCE = 2
    CREATIVE    = 3
    COMPUTE     = 4


class PowerTier(IntEnum):
    NORMAL    = 0
    LOW_POWER = 1
    EMERGENCY = 2


class ThermalState(IntEnum):
    NORMAL    = 0    # < 40C
    WARM      = 1    # 40-45C
    THROTTLE  = 2    # 45-50C
    EMERGENCY = 3    # > 50C


# ==============================================================
# Triggers (Section 7.5)
# ==============================================================

class Trigger:
    """String identifiers for mode transitions."""
    # Hardware
    EXT_DISPLAY_CONNECTED = "ext_display_connected"
    EXT_DISPLAY_REMOVED   = "ext_display_removed"
    KEYBOARD_CONNECTED    = "keyboard_connected"
    MOUSE_CONNECTED       = "mouse_connected"
    DOCK_CONNECTED        = "dock_connected"
    DOCK_REMOVED          = "dock_removed"
    CHARGER_CONNECTED     = "charger_connected"
    CHARGER_REMOVED       = "charger_removed"

    # Battery / thermal
    BATTERY_LOW           = "battery_low"
    BATTERY_CRITICAL      = "battery_critical"
    TEMP_HIGH             = "temp_high"
    TEMP_CRITICAL         = "temp_critical"

    # User
    USER_FORCED_MODE      = "user_forced_mode"
    USER_FORCED_LOW_POWER = "user_forced_low_power"

    # Workload
    HEAVY_APP_LAUNCHED    = "heavy_app_launched"
    APP_CLOSED            = "app_closed"
    USER_IDLE             = "user_idle"
    USER_ACTIVE           = "user_active"


# ==============================================================
# SystemMode snapshot
# ==============================================================

@dataclass
class SystemMode:
    device: DeviceMode = DeviceMode.PHONE
    perf: PerfState = PerfState.IDLE
    power: PowerTier = PowerTier.NORMAL
    thermal: ThermalState = ThermalState.NORMAL
    changed_ts: int = 0
    reason: str = ""

    def label(self) -> str:
        return (f"{self.device.name}/{self.perf.name}/"
                f"{self.power.name}/{self.thermal.name}")

    def to_dict(self) -> dict:
        return {
            "device": self.device.name,
            "perf": self.perf.name,
            "power": self.power.name,
            "thermal": self.thermal.name,
            "reason": self.reason,
        }


# ==============================================================
# ModeManager
# ==============================================================

class ModeManager:
    """
    Owns the four orthogonal state dimensions.
    Applies triggers, hysteresis, and emits events.

    Thermal thresholds are class constants so they can be
    customized per device class (mobile / laptop / desktop).
    """

    # Minimum seconds a state must persist before changing
    MIN_STATE_DURATION = 1.0

    # Thermal thresholds (realistic mobile defaults)
    SOC_WARNING   = 45.0
    SOC_THROTTLE  = 50.0
    SOC_EMERGENCY = 60.0

    # Cooldown between thermal state decreases
    COOLDOWN_SEC = 5.0

    def __init__(self, bus: Optional[EventBus] = None):
        self.bus = bus
        self.mode = SystemMode(changed_ts=int(time.time() * 1000))
        self._last_change_ts = 0.0   # allow first change immediately
        self._history: List[dict] = []

    # ──────────────────────────────────────────────────────────
    # Emit helpers
    # ──────────────────────────────────────────────────────────

    def _emit(self, kind: str, old: str, new: str, reason: str,
              severity: str = "INFO"):
        if not self.bus:
            return
        try:
            self.bus.emit(
                topic=f"system.mode.{kind}",
                source="modes",
                severity=severity,
                old=old, new=new, reason=reason[:50],
            )
        except Exception:
            pass

    def _record(self):
        self._history.append({
            "ts": self.mode.changed_ts,
            "device": self.mode.device.name,
            "perf": self.mode.perf.name,
            "power": self.mode.power.name,
            "thermal": self.mode.thermal.name,
            "reason": self.mode.reason,
        })
        if len(self._history) > 200:
            self._history = self._history[-200:]

    # ──────────────────────────────────────────────────────────
    # Individual dimension setters (with hysteresis)
    # ──────────────────────────────────────────────────────────

    def _can_change(self) -> bool:
        return (time.time() - self._last_change_ts) >= self.MIN_STATE_DURATION

    def set_device(self, device: DeviceMode, reason: str) -> bool:
        if device == self.mode.device:
            return False
        if not self._can_change():
            return False
        old = self.mode.device.name
        self.mode.device = device
        self.mode.reason = reason
        self.mode.changed_ts = int(time.time() * 1000)
        self._last_change_ts = time.time()
        self._emit("device", old, device.name, reason)
        self._record()
        return True

    def set_perf(self, perf: PerfState, reason: str,
                 force: bool = False) -> bool:
        if perf == self.mode.perf:
            return False
        if not force and not self._can_change():
            return False
        old = self.mode.perf.name
        self.mode.perf = perf
        self.mode.reason = reason
        self.mode.changed_ts = int(time.time() * 1000)
        self._last_change_ts = time.time()
        self._emit("perf", old, perf.name, reason)
        self._record()
        return True

    def set_power(self, power: PowerTier, reason: str,
                  force: bool = False) -> bool:
        if power == self.mode.power:
            return False
        if not force and not self._can_change():
            return False
        old = self.mode.power.name
        self.mode.power = power
        self.mode.reason = reason
        self.mode.changed_ts = int(time.time() * 1000)
        self._last_change_ts = time.time()
        sev = "HIGH" if power == PowerTier.EMERGENCY else (
              "MEDIUM" if power == PowerTier.LOW_POWER else "INFO")
        self._emit("power", old, power.name, reason, severity=sev)
        self._record()
        return True

    # Cooldown: minimum seconds between thermal state DECREASES
    COOLDOWN_SEC = 5.0
    _thermal_changed_at: float = 0.0

    def set_thermal(self, thermal: ThermalState, reason: str) -> bool:
        if thermal == self.mode.thermal:
            return False

        # Heating up is immediate (safety).
        # Cooling down requires cooldown period.
        if thermal < self.mode.thermal:
            elapsed = time.time() - self._thermal_changed_at
            if elapsed < self.COOLDOWN_SEC:
                return False

        old = self.mode.thermal.name
        self.mode.thermal = thermal
        self.mode.reason = reason
        self.mode.changed_ts = int(time.time() * 1000)
        self._last_change_ts = time.time()
        self._thermal_changed_at = time.time()

        sev = "CRITICAL" if thermal == ThermalState.EMERGENCY else (
              "HIGH" if thermal == ThermalState.THROTTLE else "MEDIUM")
        self._emit("thermal", old, thermal.name, reason, severity=sev)
        self._record()
        return True

    # ──────────────────────────────────────────────────────────
    # Trigger application
    # ──────────────────────────────────────────────────────────

    def apply_trigger(self, trigger: str, **kwargs) -> bool:
        """
        Apply a named trigger and update the mode accordingly.
        Returns True if any dimension changed.
        """
        before = self.mode.label()
        t = trigger

        # ── Hardware triggers ──
        if t == Trigger.EXT_DISPLAY_CONNECTED:
            kb = kwargs.get("keyboard", False)
            mouse = kwargs.get("mouse", False)
            if kb and mouse:
                self.set_device(DeviceMode.DESKTOP, "ext display + kb + mouse")
            else:
                self.set_device(DeviceMode.TABLET, "ext display only")

        elif t == Trigger.EXT_DISPLAY_REMOVED:
            self.set_device(DeviceMode.PHONE, "ext display removed")

        elif t == Trigger.DOCK_CONNECTED:
            self.set_device(DeviceMode.DOCKED, "dock with active cooling")
            self.set_thermal(ThermalState.NORMAL, "docked, cooled")

        elif t == Trigger.DOCK_REMOVED:
            self.set_device(DeviceMode.DESKTOP, "undocked")

        elif t == Trigger.CHARGER_CONNECTED:
            # Exit low power if battery ok
            if self.mode.power == PowerTier.LOW_POWER:
                self.set_power(PowerTier.NORMAL, "charger connected",
                               force=True)

        elif t == Trigger.CHARGER_REMOVED:
            # Check if we should enter low power
            bat = kwargs.get("battery", 100)
            if bat <= 15:
                self.set_power(PowerTier.LOW_POWER, "on battery, low",
                               force=True)

        # ── Battery triggers ──
        elif t == Trigger.BATTERY_LOW:
            self.set_power(PowerTier.LOW_POWER, "battery <= 15%",
                           force=True)
            # Cap perf
            self.set_perf(PerfState.BALANCED, "low power tier caps perf",
                          force=True)

        elif t == Trigger.BATTERY_CRITICAL:
            self.set_power(PowerTier.EMERGENCY, "battery <= 5%",
                           force=True)
            self.set_perf(PerfState.IDLE, "emergency forces IDLE",
                          force=True)

        # ── Thermal triggers ──
        elif t == Trigger.TEMP_HIGH:
            self.set_thermal(ThermalState.WARM, "temp 40-45C")
        elif t == Trigger.TEMP_CRITICAL:
            self.set_thermal(ThermalState.EMERGENCY, "temp > 50C")
            self.set_perf(PerfState.IDLE, "thermal emergency",
                          force=True)

        # ── User triggers ──
        elif t == Trigger.USER_FORCED_MODE:
            dev = kwargs.get("device")
            if isinstance(dev, DeviceMode):
                self.set_device(dev, "user forced", )
        elif t == Trigger.USER_FORCED_LOW_POWER:
            self.set_power(PowerTier.LOW_POWER, "user forced", force=True)

        # ── Workload triggers ──
        elif t == Trigger.HEAVY_APP_LAUNCHED:
            wl = kwargs.get("workload", "GAMING_HEAVY")
            if wl in ("GAMING_HEAVY", "GAMING_LIGHT"):
                self.set_perf(PerfState.PERFORMANCE, f"workload={wl}")
            elif wl in ("CREATIVE", "COMPUTE"):
                self.set_perf(PerfState.CREATIVE, f"workload={wl}")

        elif t == Trigger.APP_CLOSED:
            self.set_perf(PerfState.BALANCED, "app closed")

        elif t == Trigger.USER_IDLE:
            # Idle allowed in Phone/Tablet, but Desktop never idles
            if self.mode.device in (DeviceMode.PHONE, DeviceMode.TABLET):
                self.set_perf(PerfState.IDLE, "user idle")

        elif t == Trigger.USER_ACTIVE:
            if self.mode.perf == PerfState.IDLE:
                self.set_perf(PerfState.BALANCED, "user active")

        return before != self.mode.label()

    # ──────────────────────────────────────────────────────────
    # Evaluation from live data (auto triggers)
    # ──────────────────────────────────────────────────────────

    def evaluate(self, iv) -> bool:
        """
        Evaluate the current InputVector and apply automatic triggers.
        Returns True if any state changed.
        """
        before = self.mode.label()

        # ── Device Mode from HAL-like data ──
        if iv.external_displays > 0:
            if iv.keyboard_connected and iv.mouse_connected:
                if iv.power_source == 3:   # DOCK
                    self.set_device(DeviceMode.DOCKED, "auto: docked")
                else:
                    self.set_device(DeviceMode.DESKTOP, "auto: ext+io")
            else:
                self.set_device(DeviceMode.TABLET, "auto: ext display")
        else:
            self.set_device(DeviceMode.PHONE, "auto: handheld")

        # ── Power Tier from battery ──
        on_battery = (iv.power_source == 0)
        if on_battery and iv.battery_percent <= 5:
            self.set_power(PowerTier.EMERGENCY, "auto: battery critical",
                          force=True)
        elif on_battery and iv.battery_percent <= 15:
            self.set_power(PowerTier.LOW_POWER, "auto: battery low",
                          force=True)
        elif not on_battery:
            self.set_power(PowerTier.NORMAL, "auto: on charger", force=True)

        # ── Thermal from temp (uses realistic mobile thresholds) ──
        t = iv.temp_soc_c / 10.0
        if t >= self.SOC_EMERGENCY:
            self.set_thermal(ThermalState.EMERGENCY, f"auto: {t:.1f}C")
        elif t >= self.SOC_THROTTLE:
            self.set_thermal(ThermalState.THROTTLE, f"auto: {t:.1f}C")
        elif t >= self.SOC_WARNING:
            self.set_thermal(ThermalState.WARM, f"auto: {t:.1f}C")
        else:
            self.set_thermal(ThermalState.NORMAL, f"auto: {t:.1f}C")

        return before != self.mode.label()

    # ──────────────────────────────────────────────────────────
    # Reporting
    # ──────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        return self.mode.to_dict()

    def history(self, n: int = 10) -> List[dict]:
        return self._history[-n:]

    def pretty(self) -> str:
        m = self.mode
        return (
            f"Device: {m.device.name:<8} "
            f"Perf: {m.perf.name:<12} "
            f"Power: {m.power.name:<10} "
            f"Thermal: {m.thermal.name}"
        )


# ==============================================================
# Standalone demo
# ==============================================================

def demo():
    print("=" * 72)
    print("  OMEGA System Modes — Demo")
    print("=" * 72)

    mm = ModeManager()

    def show(label):
        print(f"\n[ {label} ]")
        print(f"  {mm.pretty()}")
        if mm.mode.reason:
            print(f"  reason: {mm.mode.reason}")

    show("Initial state")

    # Simulate a day of events
    events = [
        (Trigger.HEAVY_APP_LAUNCHED, {"workload": "GAMING_HEAVY"}),
        (Trigger.TEMP_HIGH, {}),
        (Trigger.TEMP_CRITICAL, {}),
        (Trigger.APP_CLOSED, {}),
        (Trigger.EXT_DISPLAY_CONNECTED, {"keyboard": True, "mouse": True}),
        (Trigger.BATTERY_LOW, {}),
        (Trigger.CHARGER_CONNECTED, {}),
        (Trigger.DOCK_CONNECTED, {}),
        (Trigger.USER_IDLE, {}),
    ]

    for trig, kw in events:
        time.sleep(1.1)  # satisfy hysteresis
        changed = mm.apply_trigger(trig, **kw)
        show(f"{trig}" + (" (changed)" if changed else " (no change)"))

    print()
    print("=" * 72)
    print("  History (last 5 transitions):")
    print("=" * 72)
    for h in mm.history(5):
        ts = time.strftime("%H:%M:%S", time.localtime(h["ts"] / 1000))
        print(f"  {ts}  {h['device']:<8} {h['perf']:<12} "
              f"{h['power']:<10} {h['thermal']:<10} {h['reason']}")


if __name__ == "__main__":
    demo()
