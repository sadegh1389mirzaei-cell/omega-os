# ==============================================================
# OMEGA OS - Main Entry Point (v2)
# ==============================================================
# Section 13.5 of the OMEGA spec.
# Single command boots the whole system:
#   1. Boot sequence (silicon → kernel → AI Core)
#   2. System services (bus, HAL, scheduler, storage, ...)
#   3. AI Core (Resource, Security, Personal)
#   4. Subsystems (Runtime, ACL Bridge, Modes, Sync)
#   5. Dashboard (optional)
#
# Usage:
#   python main.py                full boot + dashboard
#   python main.py --fast         fast boot + dashboard
#   python main.py --no-boot      skip boot animation
#   python main.py --headless     run without dashboard
#   python main.py --status       show current state
#   python main.py --shutdown     graceful shutdown
#   python main.py --version      print version
#   python main.py --help         full help
#   python main.py --list         list all subsystems
# ==============================================================

import os
import sys
import time
import json
import signal
import atexit
from typing import Optional, List, Tuple

HOME = os.path.expanduser("~")
OMEGA_DIR = os.path.join(HOME, "omega")
sys.path.insert(0, OMEGA_DIR)

VERSION = "0.8"
CODENAME = "Axon"
PID_FILE = os.path.join(OMEGA_DIR, "omega.pid")
STATE_FILE = os.path.join(OMEGA_DIR, "omega.state")
BOOT_LOG = os.path.join(OMEGA_DIR, "boot_history.jsonl")


# ==============================================================
# Colors
# ==============================================================

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    ORANGE  = "\033[38;5;208m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


# ==============================================================
# Runtime state
# ==============================================================

class Runtime:
    """Holds all running subsystems."""

    def __init__(self):
        # Core
        self.bus = None
        self.hal = None
        self.scheduler = None
        self.capabilities = None
        self.packages = None
        self.network = None

        # AI Core
        self.engine = None
        self.security = None
        self.personal = None
        self.telemetry = None
        self.scanner = None
        self.classifier = None

        # Additional
        self.modes = None
        self.storage = None
        self.runtime_mgr = None
        self.acl_bridge = None
        # New modules
        self.sandbox = None
        self.emulator = None
        self.telemetry_ring = None
        self.apk_deep = None
        self.dexview = None

        self.started_at = 0
        self.loaded_subsystems = []

    def register(self, name: str):
        if name not in self.loaded_subsystems:
            self.loaded_subsystems.append(name)

    def snapshot(self) -> dict:
        return {
            "version": VERSION,
            "codename": CODENAME,
            "started_at": self.started_at,
            "uptime_s": int(time.time() - self.started_at)
                        if self.started_at else 0,
            "subsystems": list(self.loaded_subsystems),
            "subsystem_count": len(self.loaded_subsystems),
        }


RUNTIME = Runtime()


# ==============================================================
# Logging helpers
# ==============================================================

def log_ok(name: str, detail: str = ""):
    padded = name.ljust(22)
    print(f"     {c('OK', C.GREEN)}   {c(padded, C.WHITE)} "
          f"{c(detail, C.GRAY)}")


def log_fail(name: str, detail: str = ""):
    padded = name.ljust(22)
    print(f"     {c('FAIL', C.RED)} {c(padded, C.WHITE)} "
          f"{c(detail, C.RED)}")


def log_warn(name: str, detail: str = ""):
    padded = name.ljust(22)
    print(f"     {c('WARN', C.YELLOW)} {c(padded, C.WHITE)} "
          f"{c(detail, C.YELLOW)}")


def section(title: str):
    print()
    line_len = max(2, 58 - len(title))
    print(c(f"  ── {title} " + "─" * line_len, C.CYAN))


# ==============================================================
# Subsystem phases
# ==============================================================

def phase_bus():
    from bus import EventBus
    import bus_hooks
    bus = EventBus(echo=False)
    bus_hooks.set_bus(bus)
    RUNTIME.bus = bus
    RUNTIME.register("bus")
    log_ok("event-bus", "in-process pub/sub")


def phase_hal():
    from hal import HAL
    hal = HAL(bus=RUNTIME.bus)
    RUNTIME.hal = hal
    RUNTIME.register("hal")
    s = hal.snapshot()
    log_ok("hal", f"{s['core_count']} cores, "
                  f"battery {s['battery_pct']}%, "
                  f"{len(s['thermal_raw'])} thermal zones")


def phase_scheduler():
    from scheduler import Scheduler
    n = RUNTIME.hal.snapshot()["core_count"] if RUNTIME.hal else 8
    sched = Scheduler(core_count=n)
    RUNTIME.scheduler = sched
    RUNTIME.register("scheduler")
    log_ok("scheduler", f"{n} cores, 5 task classes")


def phase_capabilities():
    from capabilities import CapabilityStore
    caps = CapabilityStore(os.path.join(OMEGA_DIR, "capabilities.json"))
    RUNTIME.capabilities = caps
    RUNTIME.register("capabilities")
    log_ok("capabilities", f"{len(caps.processes)} processes tracked")


def phase_packages():
    from pkgman import PackageManager
    pm = PackageManager(bus=RUNTIME.bus)
    RUNTIME.packages = pm
    RUNTIME.register("packages")
    log_ok("pkgman", f"{len(pm.packages)} packages installed")


def phase_network():
    from network import NetworkMonitor
    net = NetworkMonitor(bus=RUNTIME.bus)
    RUNTIME.network = net
    RUNTIME.register("network")
    log_ok("network", f"source: {net.source}")


def phase_telemetry():
    from real_telemetry import RealTelemetry
    rt = RealTelemetry()
    RUNTIME.telemetry = rt
    RUNTIME.register("telemetry")
    log_ok("telemetry", f"cpu source: {rt.cpu_source}")


def phase_modes():
    from modes import ModeManager
    mm = ModeManager(bus=RUNTIME.bus)
    RUNTIME.modes = mm
    RUNTIME.register("modes")
    log_ok("modes", "4 dimensions ready")


def phase_ai_resource():
    from omega import Config, DecisionEngine
    cfg = Config.load(os.path.join(OMEGA_DIR, "config.json"))
    eng = DecisionEngine(cfg)
    RUNTIME.engine = eng
    RUNTIME.register("resource-ai")
    log_ok("resource-ai", "decision engine ready")


def phase_ai_security():
    from security_v2 import SecurityAIv2 as SecurityAI
    sec = SecurityAI(state_dir=OMEGA_DIR)
    RUNTIME.security = sec
    RUNTIME.register("security-ai")
    log_ok("security-ai",
           f"{sec.total_incidents} prior incidents, "
           f"threat={sec.threat_level}")


def phase_ai_personal():
    from personal_ai_v2 import PersonalAIv2 as PersonalAI
    pai = PersonalAI(
        log_path=os.path.join(OMEGA_DIR, "bus_log.jsonl"),
        model_path=os.path.join(OMEGA_DIR, "personal_model.json"),
    )
    n = pai.ingest_log(incremental=False)
    RUNTIME.personal = pai
    RUNTIME.register("personal-ai")
    log_ok("personal-ai", f"learned from {n} events")


def phase_classifier():
    from processes import ProcessScanner, WorkloadClassifier
    RUNTIME.scanner = ProcessScanner()
    RUNTIME.classifier = WorkloadClassifier()
    RUNTIME.register("classifier")
    log_ok("classifier", "process scanner ready")


def phase_storage():
    from omfs import OMFS
    omfs = OMFS(root=os.path.join(OMEGA_DIR, "storage"))
    RUNTIME.storage = omfs
    RUNTIME.register("storage")
    s = omfs.stats()
    log_ok("storage", f"{s['projects']} projects, "
                     f"{s['files']} files")


def phase_runtime_mgr():
    from runtime import RuntimeManager
    rm = RuntimeManager(bus=RUNTIME.bus)
    RUNTIME.runtime_mgr = rm
    RUNTIME.register("runtime-mgr")
    log_ok("runtime-mgr", "5 runtime environments")


def phase_acl_bridge():
    from acl_bridge import ACLRuntimeBridge
    bridge = ACLRuntimeBridge(bus=RUNTIME.bus)
    RUNTIME.acl_bridge = bridge
    RUNTIME.register("acl-bridge")
    log_ok("acl-bridge", "APK analysis ready")


def phase_sandbox():
    from capabilities import CapabilityStore
    from sandbox import SandboxManager
    caps = CapabilityStore(os.path.join(OMEGA_DIR, "capabilities.json"))
    mgr = SandboxManager(cap_store=caps)
    RUNTIME.sandbox = mgr
    RUNTIME.register("sandbox")
    log_ok("sandbox", "capability enforcement ready")


def phase_emulator():
    from emulator import ABIEmulator, ABI
    emu = ABIEmulator(host_abi=ABI.ARM64_V8A)
    RUNTIME.emulator = emu
    RUNTIME.register("emulator")
    log_ok("emulator", "ABI translation cost model")


def phase_telemetry_proto():
    from telemetry_proto import TelemetryRing
    ring = TelemetryRing(slots=256)
    RUNTIME.telemetry_ring = ring
    RUNTIME.register("telemetry-proto")
    log_ok("telemetry-proto", "256-slot binary ring")


def phase_apk_deep():
    from apk_deep import APKDeepInspector
    ins = APKDeepInspector()
    RUNTIME.apk_deep = ins
    RUNTIME.register("apk-deep")
    log_ok("apk-deep", "manifest + signature inspector")


def phase_dexview():
    from dexview import DexViewer
    viewer = DexViewer()
    RUNTIME.dexview = viewer
    RUNTIME.register("dexview")
    log_ok("dexview", "jadx/dex2jar decompiler")


# ==============================================================
# Service groups
# ==============================================================

CORE_SERVICES: List[Tuple[str, callable]] = [
    ("event-bus",     phase_bus),
    ("hal",           phase_hal),
    ("scheduler",     phase_scheduler),
    ("capabilities",  phase_capabilities),
    ("packages",      phase_packages),
    ("network",       phase_network),
]

AI_SERVICES: List[Tuple[str, callable]] = [
    ("resource-ai",   phase_ai_resource),
    ("security-ai",   phase_ai_security),
    ("personal-ai",   phase_ai_personal),
    ("classifier",    phase_classifier),
]

EXTRA_SERVICES: List[Tuple[str, callable]] = [
    ("telemetry",       phase_telemetry),
    ("modes",           phase_modes),
    ("storage",         phase_storage),
    ("runtime-mgr",     phase_runtime_mgr),
    ("acl-bridge",      phase_acl_bridge),
    ("sandbox",         phase_sandbox),
    ("emulator",        phase_emulator),
    ("telemetry-proto", phase_telemetry_proto),
    ("apk-deep",        phase_apk_deep),
    ("dexview",         phase_dexview),
]


# ==============================================================
# Startup
# ==============================================================

def show_banner():
    clear()
    print()
    print(c("     " + "═" * 64, C.CYAN))
    print(c(f"         OMEGA OS  v{VERSION}  \"{CODENAME}\"", C.CYAN + C.BOLD))
    print(c("         Convergent AI-Native Operating System", C.CYAN))
    print(c("     " + "═" * 64, C.CYAN))
    print()


def run_boot_sequence(fast: bool = False):
    """Run the boot animation."""
    try:
        from bus import EventBus
        import bus_hooks
        from boot import run_boot

        boot_bus = EventBus(
            log_path=os.path.join(OMEGA_DIR, "bus_log.jsonl"),
            echo=False,
        )
        bus_hooks.set_bus(boot_bus)
        RUNTIME.bus = boot_bus
        run_boot(boot_bus, fast=fast)
        return True
    except Exception as e:
        print(c(f"     [!] boot sequence failed: {e}", C.RED))
        print(c("         continuing with service startup...", C.GRAY))
        return False


def startup(do_boot: bool = True, fast_boot: bool = False) -> bool:
    show_banner()

    # Phase 0: Boot sequence
    if do_boot:
        if not run_boot_sequence(fast=fast_boot):
            phase_bus()
    else:
        phase_bus()

    # Phase 1: Core services
    section("System Services")
    for name, fn in CORE_SERVICES:
        if name == "event-bus":
            continue   # already done
        try:
            fn()
        except Exception as e:
            log_fail(name, str(e)[:60])

    # Phase 2: AI Core
    section("AI Core")
    for name, fn in AI_SERVICES:
        try:
            fn()
        except Exception as e:
            log_fail(name, str(e)[:60])

    # Phase 3: Extra subsystems
    section("Additional Subsystems")
    for name, fn in EXTRA_SERVICES:
        try:
            fn()
        except Exception as e:
            log_fail(name, str(e)[:60])

    # Complete
    RUNTIME.started_at = time.time()
    snapshot = RUNTIME.snapshot()

    print()
    print(c("     " + "─" * 64, C.GREEN))
    print(c(f"     ✅ SYSTEM READY   "
            f"({snapshot['subsystem_count']} subsystems up)",
            C.GREEN + C.BOLD))
    print(c("     " + "─" * 64, C.GREEN))

    # Persist state
    _save_state(snapshot)

    return True


def _save_state(snapshot: dict):
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        with open(STATE_FILE, "w") as f:
            json.dump(snapshot, f, indent=2)
    except OSError:
        pass


# ==============================================================
# Shutdown
# ==============================================================

_shutdown_done = False


def shutdown():
    global _shutdown_done
    if _shutdown_done:
        return
    _shutdown_done = True

    print()
    print(c("     " + "─" * 64, C.YELLOW))
    print(c("     ⏻  Shutting down OMEGA...", C.YELLOW))

    # Emit shutdown event
    if RUNTIME.bus:
        try:
            import bus_hooks
            bus_hooks.emit_system_shutdown()
        except Exception:
            pass

    # Save state of subsystems
    for name, obj, method in (
        ("security", RUNTIME.security, "trust"),
        ("personal", RUNTIME.personal, "model"),
    ):
        if obj:
            try:
                if method == "trust" and hasattr(obj, "trust"):
                    obj.trust.save()
                elif method == "model":
                    obj.save_model()
            except Exception:
                pass

    # Cleanup pid
    try:
        if os.path.exists(PID_FILE):
            os.unlink(PID_FILE)
    except OSError:
        pass

    print(c("     ✓ shutdown complete", C.GREEN))
    print()


def install_signal_handlers():
    def handler(sig, frame):
        shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


# ==============================================================
# Status & listing
# ==============================================================

def show_status():
    clear()
    print()
    print(c("     OMEGA OS — Status", C.CYAN + C.BOLD))
    print(c("     " + "─" * 60, C.CYAN))
    print()

    if not os.path.exists(STATE_FILE):
        print(c("     System not running (no state file).", C.GRAY))
        print(c("     Run: python main.py --fast", C.GRAY))
        print()
        return

    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        print(c("     State file corrupted.", C.RED))
        return

    uptime = state.get("uptime_s", 0)
    mm, ss = divmod(uptime, 60)
    hh, mm = divmod(mm, 60)

    print(f"  version    : {state.get('version', '?')} "
          f"\"{state.get('codename', '?')}\"")
    print(f"  uptime     : {hh}h {mm}m {ss}s")
    print(f"  subsystems : {state.get('subsystem_count', 0)}")
    print()

    subs = state.get("subsystems", [])
    print(c("  Loaded:", C.WHITE))
    for s in sorted(subs):
        print(f"    {c('✓', C.GREEN)} {s}")

    # Extra info from live runtime
    if RUNTIME.packages:
        print(f"\n  packages   : {len(RUNTIME.packages.packages)}")
    if RUNTIME.security:
        print(f"  incidents  : {RUNTIME.security.total_incidents}")
    if RUNTIME.storage:
        s = RUNTIME.storage.stats()
        print(f"  files      : {s['files']} in {s['projects']} projects")

    print()


# Map subsystem name → actual Python file
SUBSYSTEM_FILES = {
    "event-bus":       "bus.py",
    "hal":             "hal.py",
    "scheduler":       "scheduler.py",
    "capabilities":    "capabilities.py",
    "packages":        "pkgman.py",
    "network":         "network.py",
    "resource-ai":     "omega.py",
    "security-ai":     "security_ai.py",
    "personal-ai":     "personal_ai.py",
    "classifier":      "processes.py",
    "telemetry":       "real_telemetry.py",
    "modes":           "modes.py",
    "storage":         "omfs.py",
    "runtime-mgr":     "runtime.py",
    "acl-bridge":      "acl_bridge.py",
    "sandbox":         "sandbox.py",
    "emulator":        "emulator.py",
    "telemetry-proto": "telemetry_proto.py",
    "apk-deep":        "apk_deep.py",
    "dexview":         "dexview.py",
}


def _count_modules():
    """Count .py files in omega dir."""
    try:
        return sum(1 for f in os.listdir(OMEGA_DIR)
                   if f.endswith(".py") and not f.startswith("."))
    except OSError:
        return 0


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(os.path.join(OMEGA_DIR, path))
    except OSError:
        return 0


def list_subsystems():
    print()
    print(c("  OMEGA OS — Subsystem Map", C.CYAN + C.BOLD))
    print(c("  " + "─" * 68, C.CYAN))
    print()

    groups = [
        ("Core Services", CORE_SERVICES),
        ("AI Core", AI_SERVICES),
        ("Additional Subsystems", EXTRA_SERVICES),
    ]

    total_lines = 0
    total_bytes = 0

    for title, items in groups:
        print(f"  {c(title, C.WHITE + C.BOLD)}")
        for name, _ in items:
            file = SUBSYSTEM_FILES.get(name, "?")
            size = _file_size(file)
            total_lines += 1
            total_bytes += size
            exists = c("✓", C.GREEN) if size else c("✗", C.RED)
            size_str = f"{size // 1024}K" if size else "—"
            file_padded = c(file.ljust(22), C.GRAY)
            size_padded = c(size_str.rjust(5), C.DIM)
            print(f"    {c('•', C.CYAN)} {exists} "
                  f"{name:<20} {file_padded} {size_padded}")
        print()

    n_files = _count_modules()
    print(f"  {c('Subsystems active: ' + str(total_lines), C.GREEN)}")
    print(f"  {c('Subsystem code   : ' + str(total_bytes // 1024) + ' KB', C.GREEN)}")
    print(f"  {c('Python files     : ' + str(n_files), C.GREEN)}")
    print()


# ==============================================================
# Dashboard launcher
# ==============================================================

def launch_dashboard():
    print()
    print(c("     Launching dashboard...", C.GRAY))
    print(c("     (press Q in dashboard to quit, R to reset, S to save)",
            C.DIM))
    print()
    time.sleep(0.4)

    dash = os.path.join(OMEGA_DIR, "omega_dash.py")
    if not os.path.exists(dash):
        print(c(f"     [!] {dash} not found", C.RED))
        return wait_forever()

    try:
        # exec replaces current process with dashboard
        os.execvp("python", ["python", dash])
    except Exception as e:
        print(c(f"     Dashboard failed: {e}", C.RED))
        print(c("     Falling back to headless mode.", C.GRAY))
        return wait_forever()


def wait_forever():
    print(c("     System running in headless mode.", C.GREEN))
    print(c("     Press Ctrl+C to shut down.", C.GRAY))
    print()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()


# ==============================================================
# Help & version
# ==============================================================

def show_version():
    print(f"OMEGA OS {VERSION} \"{CODENAME}\"")


def show_help():
    print(f"""
OMEGA OS  {VERSION} \"{CODENAME}\"
Convergent AI-Native Operating System

USAGE
  python main.py [OPTIONS]

OPTIONS
  --fast          fast boot (skip animation delays)
  --no-boot       skip boot sequence entirely
  --headless      start services without dashboard
  --status        show current system state
  --list          list all subsystems
  --shutdown      graceful shutdown of running instance
  --version       print version
  --help          this message

MODES
  (default)       full boot + all services + dashboard
  --fast          recommended for daily use
  --headless      for background/server use

EXAMPLES
  python main.py --fast
      → boot quickly and launch the live dashboard

  python main.py --headless
      → start all services in foreground (Ctrl+C to stop)

  python main.py --status
      → print loaded subsystems and uptime

SUBSYSTEMS LOADED (20)
  Core Services  : event-bus, hal, scheduler, capabilities,
                   packages, network
  AI Core        : resource-ai, security-ai, personal-ai, classifier
  Additional     : telemetry, modes, storage, runtime-mgr, acl-bridge,
                   sandbox, emulator, telemetry-proto, apk-deep, dexview

SECTIONS OF OMEGA SPEC COVERED
  2.4  Message Bus      6.2-6.5  AI Core       9    Storage
  3.2  Scheduler        7        Modes         10   Packages
  3.3  Memory           8        UI            12   Sync
  3.7  Capabilities     4        HAL           13   Boot
  5    Runtime          4.8      Network

""")


# ==============================================================
# Main
# ==============================================================

def main():
    args = sys.argv[1:]

    # Meta commands
    if "--help" in args or "-h" in args:
        show_help()
        return 0

    if "--version" in args:
        show_version()
        return 0

    if "--list" in args:
        list_subsystems()
        return 0

    if "--status" in args:
        show_status()
        return 0

    if "--shutdown" in args:
        shutdown()
        return 0

    # Real startup
    install_signal_handlers()

    do_boot = "--no-boot" not in args
    fast_boot = "--fast" in args
    headless = "--headless" in args

    try:
        ok = startup(do_boot=do_boot, fast_boot=fast_boot)
    except KeyboardInterrupt:
        shutdown()
        return 130
    except Exception as e:
        print(c(f"     [!] startup error: {e}", C.RED))
        import traceback
        traceback.print_exc()
        return 1

    if not ok:
        print(c("     [!] startup failed", C.RED))
        return 1

    # Launch mode
    if headless:
        wait_forever()
    else:
        try:
            launch_dashboard()
        except KeyboardInterrupt:
            shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
