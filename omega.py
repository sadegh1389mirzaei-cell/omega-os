# ==============================================================
# OMEGA OS - Decision Engine (Simulation Prototype)
# ==============================================================
# Author  : (Your Name)
# Started : 2025
# Version : 0.4  (Freeze/Thaw + run-all fix)
# ==============================================================

import os
import csv
import json
import time
import random
from enum import IntEnum
from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Optional


# ==============================================================
# SECTION 1 : ENUMS
# ==============================================================

class PerformanceState(IntEnum):
    IDLE        = 0
    BALANCED    = 1
    PERFORMANCE = 2
    CREATIVE    = 3
    COMPUTE     = 4


class DeviceMode(IntEnum):
    PHONE   = 0
    TABLET  = 1
    DESKTOP = 2
    DOCKED  = 3


class PowerTier(IntEnum):
    NORMAL    = 0
    LOW_POWER = 1
    EMERGENCY = 2


class ThermalState(IntEnum):
    NORMAL    = 0
    WARNING   = 1
    THROTTLE  = 2
    EMERGENCY = 3


class WorkloadClass(IntEnum):
    IDLE         = 0
    LIGHT        = 1
    WEB          = 2
    VIDEO        = 3
    GAMING_LIGHT = 4
    GAMING_HEAVY = 5
    CREATIVE     = 6
    COMPUTE      = 7


class PowerSource(IntEnum):
    BATTERY  = 0
    USB      = 1
    WIRELESS = 2
    DOCK     = 3


class Runtime(IntEnum):
    NATIVE       = 0
    ANDROID      = 1
    LINUX        = 2
    WINDOWS_WINE = 3
    WINDOWS_VM   = 4


class PreWarmStage(IntEnum):
    NONE     = 0
    LOADING  = 1
    WAKING   = 2
    BOOSTING = 3
    IMMINENT = 4
    ABORTED  = 5


class AppState(IntEnum):
    RUNNING   = 0   # در foreground یا visible
    STOPPED   = 1   # پس‌زمینه، هنوز در RAM
    FROZEN    = 2   # در ZRAM فشرده
    DESTROYED = 3   # کشته‌شده


# ==============================================================
# SECTION 2 : INPUT VECTOR
# ==============================================================

@dataclass
class InputVector:
    timestamp_ms: int = 0

    cpu_core_count: int = 8
    cpu_util_percent: List[int] = field(default_factory=lambda: [0] * 8)
    cpu_freq_percent: List[int] = field(default_factory=lambda: [0] * 8)
    cpu_ipc_percent:  List[int] = field(default_factory=lambda: [0] * 8)

    gpu_util_percent: int = 0
    gpu_freq_mhz: int = 0
    gpu_mem_bw_percent: int = 0

    ram_pressure_percent: int = 0
    ram_used_mb: int = 0
    ram_available_mb: int = 0
    zram_compressed_mb: int = 0

    io_read_kbps: int = 0
    io_write_kbps: int = 0
    io_latency_us: int = 0

    battery_percent: int = 100
    battery_current_ma: int = 0
    battery_health_percent: int = 100
    power_source: int = 0
    charger_power_w: int = 0
    temp_soc_c: int = 300
    temp_gpu_c: int = 300
    temp_skin_c: int = 300
    temp_battery_c: int = 300

    display_mode: int = 0
    external_displays: int = 0
    internal_display_on: int = 1
    keyboard_connected: int = 0
    mouse_connected: int = 0
    stylus_connected: int = 0

    foreground_workload: int = 0
    foreground_runtime: int = 0
    background_count: int = 0
    background_heavy_count: int = 0

    predicted_app_id: int = 0
    predicted_confidence: int = 0
    predicted_launch_seconds: int = 0
    predicted_workload: int = 0

    security_threat_level: int = 0
    foreground_trust_score: int = 100
    quarantine_count: int = 0

    user_performance_pref: int = 1
    low_power_threshold: int = 15
    thermal_sensitivity: int = 1

    event_mask: int = 0
    launched_workload: int = 0

    # NEW: app opened by user this cycle (0 = none)
    opened_app_id: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ==============================================================
# SECTION 3 : RESOURCE COMMANDS
# ==============================================================

@dataclass
class ResourceCommands:
    performance_state: int = 0
    device_mode: int = 0
    power_tier: int = 0
    thermal_state: int = 0

    cpu_max_freq_percent: int = 100
    cpu_cores_online: int = 8
    cpu_cores_parked: List[int] = field(default_factory=list)

    gpu_max_freq_percent: int = 100
    gpu_power_on: bool = True

    display_refresh_hz: int = 60
    display_brightness_percent: int = 100

    ram_pressure_target: int = 60

    freeze_list: List[int] = field(default_factory=list)
    thaw_list: List[int] = field(default_factory=list)

    # Memory
    zram_used_mb: int = 0
    ram_saved_mb: int = 0
    frozen_count: int = 0

    prewarm_stage: int = 0
    prewarm_actions: List[str] = field(default_factory=list)
    prewarm_reason: str = ""

    reason: str = ""
    actions: List[str] = field(default_factory=list)
    memory_note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ==============================================================
# SECTION 4 : APP RECORD
# ==============================================================

@dataclass
class AppRecord:
    app_id: int
    name: str
    memory_mb: int = 100
    priority: int = 5              # 1=بالا، 10=پایین
    state: int = AppState.STOPPED
    last_active_s: int = 0
    predicted_soon: bool = False

    def is_active(self) -> bool:
        return self.state in (AppState.RUNNING, AppState.STOPPED)


# ==============================================================
# SECTION 5 : CONFIG
# ==============================================================

@dataclass
class ThermalConfig:
    """Thermal thresholds in Celsius.

    Defaults are tuned for a modern passively-cooled smartphone
    (Snapdragon-class SoC). Higher-profile devices (laptops,
    desktops, docks) can override via config or by changing the
    active profile.

    Reference: Section 2.5 of the OMEGA spec acknowledges that
    thresholds must be tuned per device class (42C on a phone
    vs 85C on a desktop). The values here are calibrated to
    real-world Snapdragon behavior rather than spec minimums.
    """

    # SoC junction temperature (the actual die)
    soc_warning: float = 45.0
    soc_throttle: float = 50.0
    soc_emergency: float = 60.0

    # GPU die temperature
    gpu_warning: float = 47.0
    gpu_throttle: float = 52.0
    gpu_emergency: float = 62.0

    # Skin temperature (what the user feels)
    skin_warning: float = 40.0
    skin_throttle: float = 43.0
    skin_emergency: float = 47.0

    # Battery temperature
    battery_warning: float = 40.0
    battery_throttle: float = 45.0
    battery_emergency: float = 50.0


@dataclass
class HysteresisConfig:
    idle_to_balanced: float = 0.5
    balanced_to_performance: float = 2.0
    performance_to_balanced: float = 8.0
    creative_to_balanced: float = 5.0
    min_state_duration: float = 1.0
    low_power_exit: float = 30.0
    low_power_battery_margin: int = 5


@dataclass
class PreWarmConfig:
    min_confidence: int = 75
    max_seconds: int = 120
    temp_limit: float = 42.0
    battery_min: int = 40
    abort_grace_s: int = 30


@dataclass
class MemoryConfig:
    zram_ratio: float = 2.0        # 2:1 compression
    freeze_timeout_s: int = 600    # 10 دقیقه
    freeze_timeout_low_s: int = 180  # 3 دقیقه در باتری کم
    pressure_threshold: int = 70
    pressure_urgent: int = 85
    battery_low: int = 30
    battery_critical: int = 15


@dataclass
class Config:
    decision_cycle_ms: int = 100
    low_power_threshold: int = 15
    emergency_battery: int = 5
    thermal: ThermalConfig = field(default_factory=ThermalConfig)
    hysteresis: HysteresisConfig = field(default_factory=HysteresisConfig)
    pre_warm: PreWarmConfig = field(default_factory=PreWarmConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)

    @classmethod
    def load(cls, path: str) -> "Config":
        c = cls()
        if not os.path.exists(path):
            return c
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return c

        for key, attr in (("decision_cycle_ms", "decision_cycle_ms"),
                          ("low_power_threshold", "low_power_threshold"),
                          ("emergency_battery", "emergency_battery")):
            if key in data:
                setattr(c, key, data[key])

        for section, obj in (("thermal", c.thermal),
                             ("hysteresis", c.hysteresis),
                             ("pre_warm", c.pre_warm),
                             ("memory", c.memory)):
            for k, v in data.get(section, {}).items():
                if hasattr(obj, k):
                    setattr(obj, k, v)
        return c


# ==============================================================
# SECTION 6 : POWER TIER EVALUATOR
# ==============================================================

class PowerTierEvaluator:

    @staticmethod
    def evaluate(iv: InputVector, config: Config) -> Tuple[PowerTier, str]:
        if iv.security_threat_level >= 3:
            return PowerTier.EMERGENCY, "Security critical"
        if iv.temp_soc_c > int(config.thermal.soc_emergency * 10):
            return PowerTier.EMERGENCY, "Thermal emergency"
        if (iv.battery_percent <= config.emergency_battery
                and iv.power_source == PowerSource.BATTERY):
            return PowerTier.EMERGENCY, "Battery critical"
        if (iv.battery_percent <= iv.low_power_threshold
                and iv.power_source == PowerSource.BATTERY):
            return PowerTier.LOW_POWER, "Low battery threshold"
        if iv.event_mask & (1 << 9):
            return PowerTier.LOW_POWER, "Manual low power override"
        return PowerTier.NORMAL, ""


# ==============================================================
# SECTION 7 : DEVICE MODE EVALUATOR
# ==============================================================

class DeviceModeEvaluator:

    @staticmethod
    def evaluate(iv: InputVector, current: DeviceMode) -> Tuple[DeviceMode, str]:
        if iv.power_source == PowerSource.DOCK and iv.external_displays > 0:
            return DeviceMode.DOCKED, "Docked with external display"
        if (iv.external_displays > 0
                and iv.keyboard_connected and iv.mouse_connected):
            return DeviceMode.DESKTOP, "External display + KB + Mouse"
        if iv.external_displays > 0:
            return DeviceMode.TABLET, "External display only"
        return DeviceMode.PHONE, "Default handheld"


# ==============================================================
# SECTION 8 : PERFORMANCE STATE SELECTOR
# ==============================================================

class PerformanceSelector:

    @staticmethod
    def select(iv, tier, mode, current):
        if tier == PowerTier.EMERGENCY:
            return PerformanceState.IDLE, "Emergency tier forces IDLE"
        if tier == PowerTier.LOW_POWER:
            return PerformanceState.BALANCED, "Low power tier caps to BALANCED"

        wc = WorkloadClass(iv.foreground_workload)
        if mode in (DeviceMode.DESKTOP, DeviceMode.DOCKED):
            if wc == WorkloadClass.IDLE:
                return PerformanceState.BALANCED, "Desktop never IDLE"
        if wc == WorkloadClass.IDLE:
            return PerformanceState.IDLE, "Idle workload"
        if wc == WorkloadClass.GAMING_HEAVY:
            return PerformanceState.PERFORMANCE, "Heavy gaming"
        if wc == WorkloadClass.GAMING_LIGHT:
            return PerformanceState.PERFORMANCE, "Light gaming"
        if wc in (WorkloadClass.CREATIVE, WorkloadClass.COMPUTE):
            return PerformanceState.CREATIVE, f"Creative/Compute: {wc.name}"
        return PerformanceState.BALANCED, f"Light workload: {wc.name}"


# ==============================================================
# SECTION 9 : THERMAL MANAGER
# ==============================================================

class ThermalManager:

    @staticmethod
    def evaluate(iv, config):
        soc_c = iv.temp_soc_c / 10.0
        skin_c = iv.temp_skin_c / 10.0
        gpu_c = iv.temp_gpu_c / 10.0
        t = config.thermal

        if (soc_c >= t.soc_emergency or gpu_c >= t.gpu_emergency
                or skin_c >= t.skin_emergency):
            return ThermalState.EMERGENCY, {
                "cpu_max": 10, "gpu_max": 0, "gpu_on": False}
        if soc_c >= t.soc_throttle or gpu_c >= t.gpu_throttle:
            return ThermalState.THROTTLE, {"cpu_max": 60, "gpu_max": 50}
        if soc_c >= t.soc_warning or skin_c >= t.skin_warning:
            return ThermalState.WARNING, {
                "cpu_max": 80, "gpu_max": 80, "no_prewarm": True}
        return ThermalState.NORMAL, {}


# ==============================================================
# SECTION 10 : HYSTERESIS
# ==============================================================

class Hysteresis:

    def __init__(self, config: Config):
        self.cfg = config.hysteresis
        self.current = None
        self.pending = None
        self.pending_since = 0.0
        self.last_change = 0.0

    def force(self, state: PerformanceState) -> PerformanceState:
        self.current = state
        self.pending = state
        self.last_change = time.time()
        return state

    def filter(self, proposed: PerformanceState) -> PerformanceState:
        now = time.time()

        if self.current is None:
            self.current = proposed
            self.pending = proposed
            self.pending_since = now
            self.last_change = now
            return self.current

        if proposed == self.current:
            self.pending = proposed
            self.pending_since = now
            return self.current

        if proposed != self.pending:
            self.pending = proposed
            self.pending_since = now
            return self.current

        elapsed = now - self.pending_since
        delay = self._get_delay(self.current, proposed)
        since_change = now - self.last_change

        if elapsed >= delay and since_change >= self.cfg.min_state_duration:
            self.current = proposed
            self.last_change = now
            return self.current
        return self.current

    def _get_delay(self, src, dst):
        c = self.cfg
        if src == PerformanceState.IDLE:
            return c.idle_to_balanced
        if src == PerformanceState.BALANCED and dst == PerformanceState.PERFORMANCE:
            return c.balanced_to_performance
        if src == PerformanceState.PERFORMANCE and dst == PerformanceState.BALANCED:
            return c.performance_to_balanced
        if src == PerformanceState.CREATIVE and dst == PerformanceState.BALANCED:
            return c.creative_to_balanced
        return 1.0


# ==============================================================
# SECTION 11 : PRE-WARM MANAGER
# ==============================================================

class PreWarmManager:

    def __init__(self, config: Config):
        self.cfg = config.pre_warm
        self.active_stage = PreWarmStage.NONE
        self.active_app_id = 0
        self.last_predicted_id = 0

    def evaluate(self, iv, tier, thermal, caps):
        if iv.predicted_confidence == 0 or iv.predicted_launch_seconds == 0:
            if self.active_stage not in (PreWarmStage.NONE, PreWarmStage.ABORTED):
                self.active_stage = PreWarmStage.ABORTED
            return PreWarmStage.NONE, [], ""

        if iv.predicted_app_id != self.active_app_id:
            self.active_app_id = iv.predicted_app_id

        fails = []
        if iv.predicted_confidence < self.cfg.min_confidence:
            fails.append(f"conf<{self.cfg.min_confidence}")
        if iv.predicted_launch_seconds > self.cfg.max_seconds:
            fails.append(f"eta>{self.cfg.max_seconds}s")
        if tier != PowerTier.NORMAL:
            fails.append("tier!=NORMAL")
        if thermal != ThermalState.NORMAL:
            fails.append(f"thermal={thermal.name}")
        if caps.get("no_prewarm"):
            fails.append("thermal_no_prewarm")
        if iv.temp_soc_c >= int(self.cfg.temp_limit * 10):
            fails.append(f"temp≥{self.cfg.temp_limit}")
        if (iv.battery_percent < self.cfg.battery_min
                and iv.power_source == PowerSource.BATTERY):
            fails.append(f"battery<{self.cfg.battery_min}")

        wc = WorkloadClass(iv.predicted_workload)
        if wc not in (WorkloadClass.GAMING_LIGHT, WorkloadClass.GAMING_HEAVY,
                      WorkloadClass.CREATIVE, WorkloadClass.COMPUTE):
            fails.append(f"workload={wc.name}")

        if fails:
            self.active_stage = PreWarmStage.ABORTED
            return PreWarmStage.ABORTED, [], "abort: " + ",".join(fails)

        eta = iv.predicted_launch_seconds
        if eta > 60:
            stage, actions = PreWarmStage.LOADING, ["load_code_pages_to_cache"]
        elif eta > 30:
            stage, actions = PreWarmStage.WAKING, ["wake_big_cores_50pct"]
        elif eta > 10:
            stage, actions = PreWarmStage.BOOSTING, ["gpu_to_50pct"]
        else:
            stage, actions = PreWarmStage.IMMINENT, ["cpu_to_80pct", "gpu_to_80pct"]

        self.active_stage = stage
        reason = f"prewarm {stage.name} (eta={eta}s, conf={iv.predicted_confidence}%)"
        return stage, actions, reason


# ==============================================================
# SECTION 12 : MEMORY MANAGER  (Freeze/Thaw)
# ==============================================================

class MemoryManager:
    """
    Simulates the freeze/thaw subsystem from Section 3.3.5.
    Inactive apps are frozen, their RAM is compressed into ZRAM,
    and thawed on demand in a few milliseconds.
    """

    def __init__(self, config: Config):
        self.cfg = config.memory
        self.apps: List[AppRecord] = []
        self.zram_used_mb = 0.0
        self.total_frozen = 0
        self.total_thawed = 0
        self.last_freeze_event: Optional[str] = None
        self.last_thaw_event: Optional[str] = None

    def register(self, app: AppRecord) -> None:
        self.apps.append(app)

    def set_predicted(self, app_id: int, seconds: int) -> None:
        """Personal AI says: this app will be used soon → keep it warm."""
        for app in self.apps:
            app.predicted_soon = (app.app_id == app_id and seconds < 120)

    def on_user_opened(self, app_id: int) -> bool:
        """Called when the user opens an app explicitly."""
        for app in self.apps:
            if app.app_id == app_id:
                if app.state == AppState.FROZEN:
                    # THAW
                    app.state = AppState.STOPPED
                    app.last_active_s = 0
                    self.zram_used_mb -= app.memory_mb / self.cfg.zram_ratio
                    self.total_thawed += 1
                    self.last_thaw_event = app.name
                    return True
                elif app.state == AppState.STOPPED:
                    app.last_active_s = 0
                    return True
        return False

    def update(self, iv: InputVector,
               tier: PowerTier, thermal: ThermalState) -> Tuple[List[int], List[int], str]:
        """
        Decide which apps to freeze this cycle.
        Returns: (frozen_ids, thawed_ids, note)
        """
        # Advance idle timer for STOPPED apps
        for app in self.apps:
            if app.state == AppState.STOPPED:
                app.last_active_s += 1

        pressure = iv.ram_pressure_percent
        battery = iv.battery_percent
        on_battery = (iv.power_source == PowerSource.BATTERY)

        # Emergency tier → freeze everything except top priority
        if tier == PowerTier.EMERGENCY:
            return self._freeze_all(threshold_priority=3,
                                    note="emergency_freeze_all")

        # Thermal emergency → freeze more
        if thermal == ThermalState.EMERGENCY:
            return self._freeze_all(threshold_priority=4,
                                    note="thermal_emergency_freeze")

        # Normal case: freeze based on conditions
        frozen_now = []
        reasons = []

        for app in self.apps:
            if app.state != AppState.STOPPED:
                continue
            if app.priority <= 2:        # music, calls
                continue
            if app.predicted_soon:       # AI predicts return
                continue

            # Pressure-based
            if pressure >= self.cfg.pressure_urgent and app.last_active_s >= 10:
                self._freeze(app)
                frozen_now.append(app.app_id)
                reasons.append(f"{app.name} (urgent)")
                continue

            if pressure >= self.cfg.pressure_threshold and app.last_active_s >= 30:
                self._freeze(app)
                frozen_now.append(app.app_id)
                reasons.append(f"{app.name} (pressure)")
                continue

            # Battery-based
            if (on_battery and battery <= self.cfg.battery_critical
                    and app.last_active_s >= 10):
                self._freeze(app)
                frozen_now.append(app.app_id)
                reasons.append(f"{app.name} (battery)")
                continue

            if (on_battery and battery <= self.cfg.battery_low
                    and app.last_active_s >= 60):
                self._freeze(app)
                frozen_now.append(app.app_id)
                reasons.append(f"{app.name} (battery_low)")
                continue

            # Time-based
            if app.last_active_s >= self.cfg.freeze_timeout_s:
                self._freeze(app)
                frozen_now.append(app.app_id)
                reasons.append(f"{app.name} (timeout)")
                continue

            if (on_battery and battery <= self.cfg.battery_low
                    and app.last_active_s >= self.cfg.freeze_timeout_low_s):
                self._freeze(app)
                frozen_now.append(app.app_id)
                reasons.append(f"{app.name} (timeout_low)")
                continue

        note = ""
        if frozen_now:
            note = f"froze: {', '.join(reasons[:3])}"
            if len(reasons) > 3:
                note += f" +{len(reasons) - 3}"

        return frozen_now, [], note

    def _freeze(self, app: AppRecord) -> None:
        app.state = AppState.FROZEN
        self.zram_used_mb += app.memory_mb / self.cfg.zram_ratio
        self.total_frozen += 1
        self.last_freeze_event = app.name

    def _freeze_all(self, threshold_priority: int, note: str):
        frozen = []
        for app in self.apps:
            if app.state == AppState.STOPPED and app.priority > threshold_priority:
                self._freeze(app)
                frozen.append(app.app_id)
        return frozen, [], note if frozen else ""

    def stats(self) -> dict:
        running = sum(1 for a in self.apps if a.state == AppState.RUNNING)
        stopped = sum(1 for a in self.apps if a.state == AppState.STOPPED)
        frozen  = sum(1 for a in self.apps if a.state == AppState.FROZEN)
        ram_in_apps = sum(a.memory_mb for a in self.apps
                          if a.state == AppState.STOPPED)
        return {
            "running": running,
            "stopped": stopped,
            "frozen": frozen,
            "zram_mb": int(self.zram_used_mb),
            "ram_in_active_apps_mb": ram_in_apps,
            "total_frozen": self.total_frozen,
            "total_thawed": self.total_thawed,
        }


# ==============================================================
# SECTION 13 : DECISION ENGINE
# ==============================================================

class DecisionEngine:

    def __init__(self, config: Config):
        self.cfg = config
        self.state = PerformanceState.IDLE
        self.mode = DeviceMode.PHONE
        self.tier = PowerTier.NORMAL
        self.thermal = ThermalState.NORMAL
        self.hysteresis = Hysteresis(config)
        self.prewarm = PreWarmManager(config)
        self.memory = MemoryManager(config)
        self.history = []
        self._register_default_apps()

    def _register_default_apps(self) -> None:
        apps = [
            AppRecord(1, "Music",    120, 2),
            AppRecord(2, "Messages",  80, 3),
            AppRecord(3, "Browser",  400, 4),
            AppRecord(4, "Gallery",  200, 5),
            AppRecord(5, "Notes",     60, 6),
            AppRecord(6, "Maps",     250, 5),
            AppRecord(7, "Podcast",  150, 7),
            AppRecord(8, "Calendar",  70, 6),
            AppRecord(9, "Shopping", 180, 8),
            AppRecord(10, "News",    140, 8),
        ]
        for a in apps:
            self.memory.register(a)

    def evaluate(self, iv: InputVector) -> ResourceCommands:
        # 1. Power Tier
        tier, tier_reason = PowerTierEvaluator.evaluate(iv, self.cfg)

        # 2. Device Mode
        mode, mode_reason = DeviceModeEvaluator.evaluate(iv, self.mode)

        # 3. Performance State
        proposed, ps_reason = PerformanceSelector.select(iv, tier, mode, self.state)

        # 4. Hysteresis
        if tier in (PowerTier.LOW_POWER, PowerTier.EMERGENCY):
            final_state = self.hysteresis.force(proposed)
        else:
            final_state = self.hysteresis.filter(proposed)

        # 5. Thermal
        thermal_state, caps = ThermalManager.evaluate(iv, self.cfg)
        if thermal_state == ThermalState.EMERGENCY:
            final_state = self.hysteresis.force(PerformanceState.IDLE)

        # 6. Pre-warming
        pw_stage, pw_actions, pw_reason = self.prewarm.evaluate(
            iv, tier, thermal_state, caps)

        # 7. Memory — freeze/thaw
        # First: honor user opening an app
        thawed_now = []
        if iv.opened_app_id:
            if self.memory.on_user_opened(iv.opened_app_id):
                thawed_now.append(iv.opened_app_id)

        # Tell MemoryManager what the Personal AI predicts
        self.memory.set_predicted(iv.predicted_app_id,
                                  iv.predicted_launch_seconds)

        frozen_now, _, mem_note = self.memory.update(
            iv, tier, thermal_state)

        # 8. Build commands
        cmd = self._build_commands(
            iv, final_state, mode, tier, thermal_state, caps,
            pw_stage, pw_actions, pw_reason,
            frozen_now, thawed_now, mem_note,
            reasons={"tier": tier_reason, "mode": mode_reason,
                     "state": ps_reason}
        )

        self._record(iv, cmd)

        self.state = final_state
        self.mode = mode
        self.tier = tier
        self.thermal = thermal_state
        return cmd

    def _build_commands(self, iv, state, mode, tier, thermal, caps,
                        pw_stage, pw_actions, pw_reason,
                        frozen, thawed, mem_note, reasons):
        cmd = ResourceCommands(
            performance_state=int(state),
            device_mode=int(mode),
            power_tier=int(tier),
            thermal_state=int(thermal),
            prewarm_stage=int(pw_stage),
            prewarm_actions=pw_actions,
            prewarm_reason=pw_reason,
            freeze_list=frozen,
            thaw_list=thawed,
            memory_note=mem_note,
        )

        cmd.cpu_max_freq_percent = caps.get("cpu_max", 100)
        cmd.gpu_max_freq_percent = caps.get("gpu_max", 100)
        cmd.gpu_power_on = caps.get("gpu_on", True)

        if tier == PowerTier.LOW_POWER:
            cmd.cpu_max_freq_percent = min(cmd.cpu_max_freq_percent, 50)
            cmd.gpu_max_freq_percent = min(cmd.gpu_max_freq_percent, 30)
            cmd.display_refresh_hz = 60
        elif tier == PowerTier.EMERGENCY:
            cmd.cpu_max_freq_percent = 10
            cmd.gpu_max_freq_percent = 0
            cmd.gpu_power_on = False
            cmd.display_refresh_hz = 1

        stats = self.memory.stats()
        cmd.zram_used_mb = stats["zram_mb"]
        cmd.frozen_count = stats["frozen"]

        parts = [v for v in reasons.values() if v]
        cmd.reason = " | ".join(parts)
        cmd.actions = self._collect_actions(state, tier, thermal)
        return cmd

    def _collect_actions(self, state, tier, thermal):
        actions = []
        if state == PerformanceState.PERFORMANCE:
            actions += ["unpark_big_cores", "boost_gpu"]
        if state == PerformanceState.IDLE:
            actions += ["park_big_cores", "compress_ram"]
        if thermal == ThermalState.THROTTLE:
            actions.append("cap_cpu_60")
        if tier == PowerTier.LOW_POWER:
            actions.append("freeze_background")
        return actions

    def _record(self, iv, cmd):
        self.history.append({
            "ts": iv.timestamp_ms,
            "state":   PerformanceState(cmd.performance_state).name,
            "mode":    DeviceMode(cmd.device_mode).name,
            "tier":    PowerTier(cmd.power_tier).name,
            "thermal": ThermalState(cmd.thermal_state).name,
            "prewarm": PreWarmStage(cmd.prewarm_stage).name,
            "frozen":  len(cmd.freeze_list),
            "thawed":  len(cmd.thaw_list),
            "zram_mb": cmd.zram_used_mb,
            "memory_note": cmd.memory_note,
            "reason":  cmd.reason,
        })


# ==============================================================
# SECTION 14 : TELEMETRY SIMULATOR
# ==============================================================

class TelemetrySimulator:

    def __init__(self, scenario: str = "gaming"):
        self.scenario = scenario
        self.t = 0

    def next(self) -> InputVector:
        iv = InputVector()
        iv.timestamp_ms = int(time.time() * 1000)
        self.t += 1

        if self.scenario == "gaming":
            iv.foreground_workload = WorkloadClass.GAMING_HEAVY
            iv.gpu_util_percent = random.randint(80, 95)
            iv.gpu_freq_mhz = 900
            iv.temp_soc_c = 430 + random.randint(-5, 10)
            iv.temp_gpu_c = 445 + random.randint(-5, 10)
            iv.temp_skin_c = 360
            iv.battery_percent = 78
            iv.power_source = PowerSource.DOCK
            iv.external_displays = 1
            iv.keyboard_connected = 1
            iv.mouse_connected = 1
            iv.ram_pressure_percent = 55

        elif self.scenario == "idle":
            iv.foreground_workload = WorkloadClass.IDLE
            iv.gpu_util_percent = 2
            iv.temp_soc_c = 300
            iv.battery_percent = 50
            iv.power_source = PowerSource.BATTERY
            iv.ram_pressure_percent = 25

        elif self.scenario == "low_battery":
            iv.foreground_workload = WorkloadClass.WEB
            iv.battery_percent = 14
            iv.power_source = PowerSource.BATTERY
            iv.temp_soc_c = 330
            iv.ram_pressure_percent = 45

        elif self.scenario == "thermal":
            iv.foreground_workload = WorkloadClass.GAMING_HEAVY
            iv.gpu_util_percent = 90
            iv.temp_soc_c = 470
            iv.temp_gpu_c = 490
            iv.temp_skin_c = 420
            iv.battery_percent = 60
            iv.power_source = PowerSource.USB
            iv.ram_pressure_percent = 50

        elif self.scenario == "desktop":
            iv.foreground_workload = WorkloadClass.WEB
            iv.gpu_util_percent = 20
            iv.temp_soc_c = 340
            iv.battery_percent = 90
            iv.power_source = PowerSource.USB
            iv.external_displays = 1
            iv.keyboard_connected = 1
            iv.mouse_connected = 1
            iv.ram_pressure_percent = 40

        elif self.scenario == "prewarm":
            iv.foreground_workload = WorkloadClass.IDLE
            iv.gpu_util_percent = 3
            iv.temp_soc_c = 340
            iv.temp_skin_c = 330
            iv.battery_percent = 70
            iv.power_source = PowerSource.USB
            iv.predicted_app_id = 3
            iv.predicted_workload = WorkloadClass.GAMING_HEAVY
            iv.predicted_confidence = 85
            iv.predicted_launch_seconds = max(5, 90 - self.t * 5)
            iv.ram_pressure_percent = 35

        elif self.scenario == "memory":
            # RAM pressure rises, then a user opens an app
            t = self.t
            if t <= 8:
                # rising pressure
                iv.ram_pressure_percent = 40 + t * 7   # 47 → 96
                iv.foreground_workload = WorkloadClass.LIGHT
            elif t == 9:
                # user opens Music (app_id=1, already priority 2 → not frozen)
                iv.opened_app_id = 1
                iv.ram_pressure_percent = 88
                iv.foreground_workload = WorkloadClass.VIDEO
            elif t <= 14:
                # continuing high pressure
                iv.ram_pressure_percent = 85
                iv.foreground_workload = WorkloadClass.VIDEO
            elif t == 15:
                # user opens a frozen app (Browser, id=3)
                iv.opened_app_id = 3
                iv.ram_pressure_percent = 75
                iv.foreground_workload = WorkloadClass.WEB
            else:
                iv.ram_pressure_percent = max(40, 75 - (t - 15) * 4)
                iv.foreground_workload = WorkloadClass.WEB

            iv.battery_percent = 60
            iv.power_source = PowerSource.BATTERY
            iv.temp_soc_c = 340

        else:
            iv.foreground_workload = random.choice(list(WorkloadClass))
            iv.gpu_util_percent = random.randint(0, 100)
            iv.temp_soc_c = random.randint(280, 500)
            iv.battery_percent = random.randint(5, 100)
            iv.power_source = random.choice(list(PowerSource))
            iv.ram_pressure_percent = random.randint(20, 95)

        return iv


# ==============================================================
# SECTION 15 : JSON STORE
# ==============================================================

class JsonStore:

    def __init__(self, path: str):
        self.path = path

    def save(self, data: dict) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}


# ==============================================================
# SECTION 16 : COLORS + DISPLAY
# ==============================================================

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    ORANGE  = "\033[38;5;208m"


STATE_COLOR = {
    "IDLE":        C.GRAY,
    "BALANCED":    C.CYAN,
    "PERFORMANCE": C.GREEN,
    "CREATIVE":    C.MAGENTA,
    "COMPUTE":     C.YELLOW,
}
TIER_COLOR = {
    "NORMAL":    C.WHITE,
    "LOW_POWER": C.YELLOW,
    "EMERGENCY": C.RED,
}
THERMAL_COLOR = {
    "NORMAL":    C.WHITE,
    "WARNING":   C.YELLOW,
    "THROTTLE":  C.ORANGE,
    "EMERGENCY": C.RED,
}
PREWARM_COLOR = {
    "NONE":     C.GRAY,
    "LOADING":  C.CYAN,
    "WAKING":   C.CYAN,
    "BOOSTING": C.YELLOW,
    "IMMINENT": C.GREEN,
    "ABORTED":  C.RED,
}


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}"


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def format_cmd(idx: int, cmd: ResourceCommands) -> str:
    ps = PerformanceState(cmd.performance_state).name
    dm = DeviceMode(cmd.device_mode).name
    pt = PowerTier(cmd.power_tier).name
    ts = ThermalState(cmd.thermal_state).name
    pw = PreWarmStage(cmd.prewarm_stage).name

    ps_c = colorize(f"{ps:<11}", STATE_COLOR.get(ps, ""))
    pt_c = colorize(f"{pt:<9}",  TIER_COLOR.get(pt, ""))
    ts_c = colorize(f"{ts:<9}",  THERMAL_COLOR.get(ts, ""))
    pw_c = colorize(f"{pw:<8}",  PREWARM_COLOR.get(pw, ""))

    cpu = f"CPU:{cmd.cpu_max_freq_percent:>3}%"
    gpu = f"GPU:{cmd.gpu_max_freq_percent:>3}%"

    line = f"[{idx:03d}] {ps_c} {dm:<7} {pt_c} {ts_c} {pw_c} {cpu} {gpu}"

    if cmd.prewarm_reason and pw != "NONE":
        line += f"  {colorize(cmd.prewarm_reason, C.GRAY)}"

    # Second line if memory activity
    mem_lines = []
    if cmd.freeze_list:
        mem_lines.append(f"FROZE: {cmd.memory_note}")
    if cmd.thaw_list:
        mem_lines.append(f"THAWED: id={cmd.thaw_list}")
    if mem_lines:
        line += "\n       └─ " + colorize(" | ".join(mem_lines), C.BLUE)
        line += f"  {colorize(f'ZRAM:{cmd.zram_used_mb}MB', C.GRAY)}"

    return line


# ==============================================================
# SECTION 17 : MAIN
# ==============================================================

def run_scenario(scenario: str, steps: int, engine: DecisionEngine, cfg: Config):
    sim = TelemetrySimulator(scenario)
    print()
    print(colorize(f"  >> SCENARIO: {scenario.upper()}  ({steps} cycles)", C.BOLD))
    print("-" * 95)
    print(f"{'#':<5} {'STATE':<11} {'MODE':<7} {'TIER':<9} {'THERMAL':<9} "
          f"{'PREWARM':<8} CAPS")
    print("-" * 95)

    for i in range(1, steps + 1):
        iv = sim.next()
        cmd = engine.evaluate(iv)
        print(format_cmd(i, cmd))
        time.sleep(cfg.decision_cycle_ms / 1000.0)


def save_history(engine: DecisionEngine, path: str = "history.json"):
    store = JsonStore(path)
    store.save({"history": engine.history})

    with open("history.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts", "state", "mode", "tier", "thermal", "prewarm",
                    "frozen", "thawed", "zram_mb", "note", "reason"])
        for h in engine.history:
            w.writerow([h["ts"], h["state"], h["mode"], h["tier"],
                        h["thermal"], h.get("prewarm", "NONE"),
                        h.get("frozen", 0), h.get("thawed", 0),
                        h.get("zram_mb", 0), h.get("memory_note", ""),
                        h["reason"]])

    print()
    print(colorize(
        f"[+] Saved {len(engine.history)} decisions -> history.json + history.csv",
        C.GREEN))


def show_menu() -> None:
    print("=" * 60)
    print("         OMEGA OS - Decision Engine Simulator")
    print("=" * 60)
    print("  1. Gaming scenario (heavy 3D game, docked)")
    print("  2. Idle scenario (system idle on battery)")
    print("  3. Low battery scenario (14% on battery)")
    print("  4. Thermal scenario (hot SoC, USB power)")
    print("  5. Desktop scenario (external monitor + KB/M)")
    print("  6. Pre-warm scenario (predictive warm-up)")
    print("  7. Memory scenario (freeze/thaw + ZRAM)")
    print("  8. Random scenario (stress test)")
    print("  9. Run all scenarios")
    print("  0. Exit")
    print("-" * 60)


def main():
    cfg = Config.load("config.json")

    while True:
        clear_screen()
        show_menu()
        try:
            choice = int(input("Choice: "))
        except ValueError:
            print("Please enter a number.")
            input("Press Enter...")
            continue

        if choice == 0:
            print("Goodbye.")
            break

        # All-scenarios mode: fresh engine per scenario
        if choice == 9:
            for sc, steps in [("gaming", 15), ("idle", 15),
                              ("low_battery", 15), ("thermal", 15),
                              ("desktop", 15), ("prewarm", 15),
                              ("memory", 20)]:
                engine = DecisionEngine(cfg)
                run_scenario(sc, steps, engine, cfg)
                save_history(engine, f"history_{sc}.json")
            input("\nPress Enter to return to menu...")
            continue

        engine = DecisionEngine(cfg)
        scenario = None
        steps = 30

        if choice == 1:
            scenario, steps = "gaming", 30
        elif choice == 2:
            scenario, steps = "idle", 30
        elif choice == 3:
            scenario, steps = "low_battery", 30
        elif choice == 4:
            scenario, steps = "thermal", 30
        elif choice == 5:
            scenario, steps = "desktop", 30
        elif choice == 6:
            scenario, steps = "prewarm", 20
        elif choice == 7:
            scenario, steps = "memory", 25
        elif choice == 8:
            scenario, steps = "random", 30
        else:
            print("Invalid choice.")
            input("Press Enter...")
            continue

        run_scenario(scenario, steps, engine, cfg)
        save_history(engine)
        input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    main()
