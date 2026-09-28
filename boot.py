# ==============================================================
# OMEGA OS - Boot Sequence
# ==============================================================
# Section 13 of the OMEGA spec.
#
# Simulates the full boot chain from Boot ROM to user shell:
#   - Boot ROM → PBL → SBL → Kernel → HAL → init → AI Core → UI
#   - Real target timings from Section 13.6
#   - All stages publish events to the Message Bus
#   - Final stage: starts the live dashboard (optional)
# ==============================================================

import os
import sys
import time
import json
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Callable

from bus import EventBus, Topic
import bus_hooks


HOME = os.path.expanduser("~")
BOOT_LOG = os.path.join(HOME, "omega", "boot.log")
VERSION = "0.5"


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


def c(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}"


# ==============================================================
# Boot stages (Section 13.6 measured timings, scaled)
# ==============================================================

@dataclass
class Stage:
    num: int
    name: str
    detail: str
    target_ms: int
    measured_ms: int
    emoji: str = "•"


STAGES: List[Stage] = [
    Stage(0, "Boot ROM",  "HW Root of Trust, verify PBL signature", 50, 48, "🔒"),
    Stage(1, "PBL",       "DRAM init, load SBL from storage",       120, 115, "🧠"),
    Stage(2, "SBL",       "HW probe, verify Kernel+HAL, jump",      300, 280, "⚙️ "),
    Stage(3, "Kernel",    "Self-decompress, MMU, scheduler init",    80, 75, "🐧"),
    Stage(4, "HAL",       "CPU topology, memory map, IRQ setup",    250, 240, "🔌"),
    Stage(5, "AI Core",   "Load models into RAM, telemetry up",     400, 380, "🤖"),
    Stage(6, "Services",  "om-init parallel launch (~25 svcs)",    2100, 1900, "🚀"),
    Stage(7, "Compositor","Device Mode detect, UI shell up",        250, 200, "🎨"),
    Stage(8, "Complete",  "BOOT_COMPLETE broadcast to all",           0, 0,   "✅"),
]


# ==============================================================
# Service graph (Section 13.5)
# ==============================================================

SERVICES = [
    # (priority, name, depends_on)
    (1, "logd",              []),
    (2, "ai-core",           ["logd"]),
    (3, "sec-enclave-bridge",["logd"]),
    (4, "device-manager",    ["logd"]),
    (4, "om-fs-service",     ["logd"]),
    (5, "om-sync-engine",    ["device-manager"]),
    (5, "om-security-monitor",["ai-core"]),
    (6, "om-identity",       ["sec-enclave-bridge"]),
    (6, "om-network-manager",["device-manager"]),
    (7, "om-native-runtime", ["om-fs-service"]),
    (7, "om-acl-service",    ["om-native-runtime"]),
    (7, "om-lcl-service",    ["om-native-runtime"]),
    (7, "om-wcl-service",    ["om-native-runtime"]),
    (8, "om-compositor",     ["device-manager", "om-native-runtime"]),
    (9, "om-shell",          ["om-compositor", "om-identity"]),
]


# ==============================================================
# Boot progress
# ==============================================================

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print()
    print(c("     " + "═" * 62, C.CYAN))
    print(c("         OMEGA OS - Boot Sequence v" + VERSION, C.CYAN + C.BOLD))
    print(c("     " + "═" * 62, C.CYAN))
    print()
    print(c("     Power-on reset... PMIC sequencing rails...", C.GRAY))
    time.sleep(0.3)


def show_stage_start(st: Stage):
    name_padded = st.name.ljust(10)
    print(f"  [{st.num}] "
          f"{c(name_padded, C.WHITE + C.BOLD)} "
          f"{st.emoji}  {c(st.detail, C.GRAY)}",
          end="", flush=True)


def show_stage_end(measured_ms: int, target_ms: int):
    # Simulate timing (scaled: 1 target-ms = 0.0008 real-s)
    real_s = target_ms * 0.0008
    time.sleep(real_s)
    ms_str = c(f"({measured_ms:>5} ms)", C.DIM)
    print(f"  {c('OK', C.GREEN)} {ms_str}")


def show_services():
    print()
    print(c(f"     Starting services (priorities 1-9)...", C.GRAY))
    total = len(SERVICES)
    for i, (prio, name, deps) in enumerate(SERVICES, 1):
        # Each service takes 80-180 ms simulated
        time.sleep(0.04 + (i % 3) * 0.02)
        dep_str = c(f"(after {','.join(deps)})" if deps else "", C.DIM)
        bar = c("━" * i, C.CYAN) + c("─" * (total - i), C.DIM)
        print(f"     {c(f'p{prio}', C.YELLOW)} "
              f"{c(name, C.WHITE):<26} "
              f"{bar}  {dep_str}")

    print()
    print(c(f"     {total} services started in parallel.", C.GREEN))


def show_boot_complete(total_ms: int):
    print()
    print(c("     " + "─" * 62, C.GREEN))
    print(c(f"     ✅ BOOT_COMPLETE  ({total_ms} ms simulated)", C.GREEN + C.BOLD))
    print(c("     " + "─" * 62, C.GREEN))
    print()


# ==============================================================
# Boot runner
# ==============================================================

def run_boot(bus: EventBus, fast: bool = False) -> int:
    """Run the full boot sequence. Returns simulated total ms."""
    clear()
    banner()

    bus_hooks.emit_system_boot(VERSION)

    total = 0

    for st in STAGES[:-1]:   # last stage is completion, handled separately
        show_stage_start(st)
        show_stage_end(st.measured_ms, st.target_ms)
        total += st.measured_ms

        # Emit stage event to bus
        bus.emit(
            topic=f"boot.stage.{st.num}",
            source="boot",
            severity="INFO",
            stage=st.name,
            ms=st.measured_ms,
        )

    # Services
    show_services()
    total += STAGES[6].measured_ms

    # Complete
    show_boot_complete(total)

    bus.emit(Topic.SYSTEM_BOOT, "boot",
             severity="INFO", version=VERSION, total_ms=total)

    # Write boot log
    try:
        with open(BOOT_LOG, "a") as f:
            f.write(json.dumps({
                "ts": int(time.time() * 1000),
                "version": VERSION,
                "total_ms": total,
                "stages": [s.measured_ms for s in STAGES],
            }) + "\n")
    except OSError:
        pass

    return total


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
OMEGA Boot Sequence

Usage:
  python boot.py              run a full boot
  python boot.py --fast       run without delays
  python boot.py --then-dash  boot, then launch the dashboard
  python boot.py --log        show recent boot history
  python boot.py --help       this message
""")


def cli_log():
    if not os.path.exists(BOOT_LOG):
        print("(no boot history yet)")
        return
    print("Recent boots:")
    with open(BOOT_LOG) as f:
        for line in f.readlines()[-10:]:
            try:
                d = json.loads(line)
                ts = time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.localtime(d["ts"] / 1000))
                print(f"  {ts}  v{d['version']}  {d['total_ms']} ms")
            except (json.JSONDecodeError, KeyError):
                continue


def main():
    args = sys.argv[1:]

    if "--help" in args or "-h" in args:
        cli_help()
        return

    if "--log" in args:
        cli_log()
        return

    # Set up bus (in-process; not daemon)
    bus = EventBus(echo=False)
    bus_hooks.set_bus(bus)

    fast = "--fast" in args
    total = run_boot(bus, fast=fast)

    if "--then-dash" in args:
        print(c("     Launching dashboard...", C.GRAY))
        time.sleep(0.8)
        try:
            os.execvp("python", ["python", os.path.join(HOME, "omega", "omega_dash.py")])
        except Exception as e:
            print(c(f"     Failed: {e}", C.RED))


if __name__ == "__main__":
    main()
