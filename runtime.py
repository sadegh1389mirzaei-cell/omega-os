# ==============================================================
# OMEGA OS - Runtime Environments Simulator
# ==============================================================
# Section 5 of the OMEGA spec.
#
# Models the four runtime environments and their overhead:
#   - Native OMEGA    : 1.00x baseline (zero overhead)
#   - Android (ACL)   : 1.15-1.35x CPU, 1.30-1.50x RAM
#   - Linux (LCL)     : 1.05x CPU, 1.10-1.20x RAM
#   - Windows (Wine)  : 1.10-1.30x CPU, 1.20-1.40x RAM
#   - Windows (Micro-VM): 1.50-3.00x CPU, 2.00-3.00x RAM
#
# Provides:
#   - Launch time estimation
#   - Memory overhead
#   - Battery drain multiplier
#   - Runtime recommendation ("which one fits best?")
# ==============================================================

import os
import time
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

try:
    from bus import EventBus, Topic
    _BUS = True
except Exception:
    _BUS = False


HOME = os.path.expanduser("~")


# ==============================================================
# Runtime Types
# ==============================================================

class RuntimeType(IntEnum):
    NATIVE      = 0
    ANDROID     = 1
    LINUX       = 2
    WINDOWS_WINE = 3
    WINDOWS_VM  = 4


# ==============================================================
# Overhead coefficients (Section 5, table in 6.5.5)
# ==============================================================

@dataclass
class RuntimeSpec:
    name: str
    cpu_overhead: Tuple[float, float]       # (min, max) multiplier
    memory_overhead: Tuple[float, float]
    gpu_overhead: Tuple[float, float]
    launch_ms: Tuple[int, int]              # cold start range
    warm_launch_ms: Tuple[int, int]         # with pre-warm
    battery_multiplier: float               # x vs native
    description: str = ""
    can_prewarm: bool = True

    def avg_cpu(self) -> float:
        return (self.cpu_overhead[0] + self.cpu_overhead[1]) / 2

    def avg_memory(self) -> float:
        return (self.memory_overhead[0] + self.memory_overhead[1]) / 2

    def avg_launch(self) -> int:
        return (self.launch_ms[0] + self.launch_ms[1]) // 2


# ==============================================================
# The four runtimes — from Section 5
# ==============================================================

NATIVE_SPEC = RuntimeSpec(
    name="Native OMEGA",
    cpu_overhead=(1.00, 1.00),
    memory_overhead=(1.00, 1.00),
    gpu_overhead=(1.00, 1.00),
    launch_ms=(150, 250),
    warm_launch_ms=(80, 120),
    battery_multiplier=1.00,
    description="Zero translation, direct libomega access",
    can_prewarm=True,
)

ANDROID_SPEC = RuntimeSpec(
    name="Android (ACL)",
    cpu_overhead=(1.15, 1.35),
    memory_overhead=(1.30, 1.50),
    gpu_overhead=(1.05, 1.15),
    launch_ms=(600, 900),
    warm_launch_ms=(350, 500),
    battery_multiplier=1.05,
    description="ART translation + framework shims",
    can_prewarm=True,
)

LINUX_SPEC = RuntimeSpec(
    name="Linux (LCL)",
    cpu_overhead=(1.05, 1.05),
    memory_overhead=(1.10, 1.20),
    gpu_overhead=(1.05, 1.05),
    launch_ms=(400, 700),
    warm_launch_ms=(250, 350),
    battery_multiplier=1.03,
    description="Container with glibc + Wayland proxy",
    can_prewarm=True,
)

WINE_SPEC = RuntimeSpec(
    name="Windows (Wine)",
    cpu_overhead=(1.10, 1.30),
    memory_overhead=(1.20, 1.40),
    gpu_overhead=(1.10, 1.30),
    launch_ms=(800, 1500),
    warm_launch_ms=(500, 800),
    battery_multiplier=1.08,
    description="Win32 API translation layer",
    can_prewarm=True,
)

VM_SPEC = RuntimeSpec(
    name="Windows (Micro-VM)",
    cpu_overhead=(1.50, 3.00),
    memory_overhead=(2.00, 3.00),
    gpu_overhead=(1.15, 1.35),
    launch_ms=(1500, 4000),
    warm_launch_ms=(700, 900),
    battery_multiplier=1.20,
    description="Minimal Windows kernel with VirtIO-GPU",
    can_prewarm=True,
)


SPECS = {
    RuntimeType.NATIVE:       NATIVE_SPEC,
    RuntimeType.ANDROID:      ANDROID_SPEC,
    RuntimeType.LINUX:        LINUX_SPEC,
    RuntimeType.WINDOWS_WINE: WINE_SPEC,
    RuntimeType.WINDOWS_VM:   VM_SPEC,
}


# ==============================================================
# Resource profile of an app
# ==============================================================

@dataclass
class AppProfile:
    """Baseline resource demand if run native."""
    app_id: str
    name: str
    cpu_mhz: int = 500          # avg CPU MHz needed
    memory_mb: int = 200        # baseline RAM
    gpu_mhz: int = 0            # GPU if any
    battery_mw: float = 300.0   # power draw if native

    def to_dict(self):
        return asdict(self)


@dataclass
class LaunchEstimate:
    """Result of estimating a launch in a given runtime."""
    runtime: RuntimeType
    app: AppProfile
    cpu_mhz: int
    memory_mb: int
    gpu_mhz: int
    battery_mw: float
    launch_cold_ms: int
    launch_warm_ms: int
    cpu_mult: float
    mem_mult: float
    reason: str = ""

    def to_dict(self):
        return {
            "runtime": RuntimeType(self.runtime).name,
            "app": self.app.name,
            "cpu_mhz": self.cpu_mhz,
            "memory_mb": self.memory_mb,
            "gpu_mhz": self.gpu_mhz,
            "battery_mw": self.battery_mw,
            "launch_cold_ms": self.launch_cold_ms,
            "launch_warm_ms": self.launch_warm_ms,
            "cpu_mult": round(self.cpu_mult, 2),
            "mem_mult": round(self.mem_mult, 2),
        }


# ==============================================================
# Runtime Manager
# ==============================================================

class RuntimeManager:
    """
    Owns all runtime environments.
    Simulates launch cost with real overhead coefficients.
    """

    def __init__(self, bus: Optional[EventBus] = None):
        self.bus = bus
        self.specs = dict(SPECS)
        self.instances: Dict[RuntimeType, dict] = {}
        self.launch_log: List[dict] = []
        self.total_launches = 0

    # ──────────────────────────────────────────────────────────

    def register(self, rt: RuntimeType, pid: int):
        """Mark a runtime as 'running' (an instance is up)."""
        self.instances[rt] = {
            "pid": pid,
            "started_at": time.time(),
            "launches": 0,
        }

    def unregister(self, rt: RuntimeType):
        self.instances.pop(rt, None)

    def is_running(self, rt: RuntimeType) -> bool:
        return rt in self.instances

    # ──────────────────────────────────────────────────────────

    def estimate(self, app: AppProfile, rt: RuntimeType,
                 variance: float = 0.0) -> LaunchEstimate:
        """
        Estimate resource usage if `app` runs under runtime `rt`.
        `variance` ∈ [0,1] shifts the coefficients toward their max.
        """
        spec = self.specs[rt]

        def pick(rng: Tuple[float, float]) -> float:
            lo, hi = rng
            return lo + (hi - lo) * variance

        cpu_m = pick(spec.cpu_overhead)
        mem_m = pick(spec.memory_overhead)
        gpu_m = pick(spec.gpu_overhead)

        # Compute warm launch availability
        cold = spec.avg_launch()
        warm = spec.avg_launch()  # default same
        if spec.can_prewarm:
            warm = (spec.warm_launch_ms[0] + spec.warm_launch_ms[1]) // 2

        return LaunchEstimate(
            runtime=rt,
            app=app,
            cpu_mhz=int(app.cpu_mhz * cpu_m),
            memory_mb=int(app.memory_mb * mem_m),
            gpu_mhz=int(app.gpu_mhz * gpu_m),
            battery_mw=round(app.battery_mw * spec.battery_multiplier, 1),
            launch_cold_ms=cold,
            launch_warm_ms=warm,
            cpu_mult=cpu_m,
            mem_mult=mem_m,
            reason=spec.description,
        )

    def compare_all(self, app: AppProfile) -> List[LaunchEstimate]:
        """Compare the same app across all runtimes."""
        out = []
        for rt in RuntimeType:
            out.append(self.estimate(app, rt))
        return out

    # ──────────────────────────────────────────────────────────

    def launch(self, app: AppProfile, rt: RuntimeType,
               prewarmed: bool = False,
               variance: float = 0.0) -> LaunchEstimate:
        """
        Simulate a launch: emit event and record log.
        """
        est = self.estimate(app, rt, variance=variance)
        actual_ms = est.launch_warm_ms if prewarmed else est.launch_cold_ms

        self.total_launches += 1
        if rt in self.instances:
            self.instances[rt]["launches"] += 1

        record = {
            "ts": int(time.time() * 1000),
            "app": app.app_id,
            "runtime": RuntimeType(rt).name,
            "actual_ms": actual_ms,
            "prewarmed": prewarmed,
            "cpu_mhz": est.cpu_mhz,
            "memory_mb": est.memory_mb,
        }
        self.launch_log.append(record)
        if len(self.launch_log) > 500:
            self.launch_log = self.launch_log[-500:]

        # Emit to bus
        if self.bus:
            try:
                self.bus.emit(
                    topic="runtime.launch",
                    source="runtime",
                    severity="INFO",
                    app=app.app_id,
                    runtime=RuntimeType(rt).name,
                    ms=actual_ms,
                    prewarmed=prewarmed,
                )
            except Exception:
                pass

        return est

    # ──────────────────────────────────────────────────────────

    def recommend(self, app: AppProfile,
                  available: List[RuntimeType]) -> RuntimeType:
        """
        Pick the best runtime given availability.
        Prefers Native, then Linux, then Android, then Wine, then VM.
        """
        if RuntimeType.NATIVE in available:
            return RuntimeType.NATIVE
        if RuntimeType.LINUX in available:
            return RuntimeType.LINUX
        if RuntimeType.ANDROID in available:
            return RuntimeType.ANDROID
        if RuntimeType.WINDOWS_WINE in available:
            return RuntimeType.WINDOWS_WINE
        if RuntimeType.WINDOWS_VM in available:
            return RuntimeType.WINDOWS_VM
        raise ValueError("no runtime available")

    # ──────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        return {
            "total_launches": self.total_launches,
            "active_runtimes": [
                RuntimeType(rt).name for rt in self.instances.keys()
            ],
            "specs": {
                RuntimeType(rt).name: {
                    "cpu": spec.cpu_overhead,
                    "mem": spec.memory_overhead,
                    "launch_ms": spec.launch_ms,
                }
                for rt, spec in self.specs.items()
            },
        }


# ==============================================================
# Pretty printer
# ==============================================================

def print_comparison(app: AppProfile, rts: List[LaunchEstimate]):
    print()
    print("  App: " + app.name + "  (" + app.app_id + ")")
    print("  Baseline (native): "
          f"cpu={app.cpu_mhz}MHz, "
          f"mem={app.memory_mb}MB, "
          f"bat={app.battery_mw}mW")
    print()
    header = f"  {'RUNTIME':<20} {'CPU':<8} {'RAM':<8} {'BAT':<8} " \
             f"{'COLD':<8} {'WARM':<8} NOTES"
    print(header)
    print("  " + "-" * 78)

    for e in rts:
        spec = SPECS[e.runtime]
        rt_name = spec.name
        cpu_s = f"{e.cpu_mhz}MHz"
        ram_s = f"{e.memory_mb}MB"
        bat_s = f"{e.battery_mw}mW"
        cold_s = f"{e.launch_cold_ms}ms"
        warm_s = f"{e.launch_warm_ms}ms"
        note = f"x{e.cpu_mult:.2f}/{e.mem_mult:.2f}"

        print(f"  {rt_name:<20} {cpu_s:<8} {ram_s:<8} {bat_s:<8} "
              f"{cold_s:<8} {warm_s:<8} {note}")


# ==============================================================
# Standalone demo
# ==============================================================

def demo():
    print("=" * 80)
    print("  OMEGA Runtime Environments — Simulator")
    print("=" * 80)
    print()
    print("  Section 5 — overhead coefficients")

    rm = RuntimeManager()

    # ── App 1: A light text editor ──
    editor = AppProfile(
        app_id="com.omega.notes",
        name="Text Editor",
        cpu_mhz=200, memory_mb=80, gpu_mhz=0, battery_mw=120.0,
    )

    print()
    print("[ App 1 ] A light text editor")
    print_comparison(editor, rm.compare_all(editor))

    # ── App 2: A 3D game ──
    game = AppProfile(
        app_id="com.game.fps",
        name="Heavy 3D Game",
        cpu_mhz=1800, memory_mb=3500, gpu_mhz=900, battery_mw=4500.0,
    )

    print()
    print()
    print("[ App 2 ] A heavy 3D game")
    print_comparison(game, rm.compare_all(game))

    # ── App 3: A Windows legacy app ──
    legacy = AppProfile(
        app_id="accounting.exe",
        name="Legacy Accounting",
        cpu_mhz=800, memory_mb=1200, gpu_mhz=200, battery_mw=800.0,
    )

    print()
    print()
    print("[ App 3 ] A legacy Windows app")
    # Only Wine and VM can run it
    wine_est = rm.estimate(legacy, RuntimeType.WINDOWS_WINE)
    vm_est = rm.estimate(legacy, RuntimeType.WINDOWS_VM)
    print_comparison(legacy, [wine_est, vm_est])

    # ── Recommendation ──
    print()
    print("=" * 80)
    print("  Runtime Recommendation")
    print("=" * 80)
    print()

    available = [RuntimeType.NATIVE, RuntimeType.LINUX,
                 RuntimeType.ANDROID]
    best = rm.recommend(editor, available)
    print(f"  {editor.name:<25} → {SPECS[best].name}")

    best = rm.recommend(game, available)
    print(f"  {game.name:<25} → {SPECS[best].name}")

    # Windows app only fits WCL
    win_avail = [RuntimeType.WINDOWS_WINE, RuntimeType.WINDOWS_VM]
    best = rm.recommend(legacy, win_avail)
    print(f"  {legacy.name:<25} → {SPECS[best].name}  "
          f"(only WCL available)")

    # ── Prewarm impact ──
    print()
    print("=" * 80)
    print("  Pre-warm Impact")
    print("=" * 80)
    print()
    for rt in RuntimeType:
        spec = SPECS[rt]
        cold = spec.avg_launch()
        if spec.can_prewarm:
            warm = (spec.warm_launch_ms[0] + spec.warm_launch_ms[1]) // 2
            saved = cold - warm
            pct = int(saved * 100 / cold) if cold else 0
            print(f"  {spec.name:<20} "
                  f"cold={cold}ms  warm={warm}ms  "
                  f"saves={saved}ms ({pct}%)")
        else:
            print(f"  {spec.name:<20} cold={cold}ms  (no prewarm)")


if __name__ == "__main__":
    demo()
