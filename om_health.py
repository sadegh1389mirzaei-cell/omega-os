# ==============================================================
# OMEGA OS - Health Checker
# ==============================================================
# Comprehensive system health report:
#   - All modules importable?
#   - Which subsystems function correctly?
#   - HAL data from real hardware
#   - APK analysis summary
#   - Bus event throughput
#   - Test pass rate
# ==============================================================

import os
import sys
import time
import json
import importlib
import subprocess
import traceback
from typing import List, Dict, Tuple

OMEGA_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, OMEGA_DIR)


# ── Color helpers ──
class C:
    R = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    GRY = "\033[90m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{C.R}"


def ok():    return c("✓", C.GRN)
def fail():  return c("✗", C.RED)
def warn():  return c("!", C.YEL)
def skip():  return c("-", C.GRY)


# ==============================================================
# Categories
# ==============================================================

CATEGORIES = [
    # (name, module, optional)
    ("Foundation", [
        ("bus",           "bus",           False),
        ("bus_hooks",     "bus_hooks",     False),
    ]),
    ("Kernel Sim", [
        ("omega",          "omega",         False),
        ("scheduler",      "scheduler",     False),
        ("capabilities",   "capabilities",  False),
    ]),
    ("HAL", [
        ("hal",            "hal",           False),
        ("network",        "network",       False),
        ("real_telemetry", "real_telemetry", False),
    ]),
    ("Runtimes", [
        ("runtime",        "runtime",       False),
        ("acl",            "acl",           False),
        ("acl_bridge",     "acl_bridge",    False),
        ("apk_deep",       "apk_deep",      True),
        ("dexview",        "dexview",       True),
        ("emulator",       "emulator",      False),
    ]),
    ("AI Core", [
        ("security_ai",    "security_ai",   False),
        ("personal_ai",    "personal_ai",   False),
        ("processes",      "processes",     False),
    ]),
    ("Services", [
        ("modes",          "modes",         False),
        ("omfs",           "omfs",          False),
        ("virtual_fs",     "virtual_fs",    False),
        ("pkgman",         "pkgman",        False),
        ("sandbox",        "sandbox",       False),
        ("telemetry_proto","telemetry_proto", False),
    ]),
    ("Networking", [
        ("sync",           "sync",          False),
    ]),
    ("Boot & UI", [
        ("boot",           "boot",          False),
        ("omega_dash",     "omega_dash",    True),   # needs curses
        ("report",         "report",        False),
    ]),
]


# ==============================================================
# Checks
# ==============================================================

def check_import(module_name: str, optional: bool) -> Tuple[bool, str]:
    """Try importing a module. Return (success, message)."""
    try:
        importlib.import_module(module_name)
        return True, "imported"
    except ImportError as e:
        if optional:
            return False, f"optional — {str(e)[:40]}"
        return False, f"IMPORT ERROR: {str(e)[:50]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:50]}"


def check_hal() -> Dict:
    """Get HAL data."""
    try:
        from hal import HAL
        h = HAL()
        s = h.snapshot()
        return {
            "ok": True,
            "cores": s.get("core_count", 0),
            "battery": s.get("battery_pct", 0),
            "soc_temp": s.get("soc_temp_c", 0),
            "zones": len(s.get("thermal_raw", {})),
            "ram_used": s.get("memory", {}).get("used_mb", 0),
            "ram_total": s.get("memory", {}).get("total_mb", 0),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


def check_bus() -> Dict:
    """Check message bus."""
    try:
        from bus import EventBus
        from bus_hooks import set_bus
        received = []
        bus = EventBus(echo=False)
        set_bus(bus)
        bus.subscribe("*", lambda e: received.append(e))
        bus.emit("health.check", "health", value=1)
        return {"ok": len(received) == 1, "events": len(received)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


def check_decision_engine() -> Dict:
    """Test the Decision Engine with a fake input."""
    try:
        from omega import (Config, DecisionEngine, InputVector,
                          PerformanceState, PowerTier, WorkloadClass)
        eng = DecisionEngine(Config())
        iv = InputVector()
        iv.battery_percent = 75
        iv.power_source = 0
        iv.temp_soc_c = 380
        iv.foreground_workload = int(WorkloadClass.GAMING_HEAVY)
        iv.gpu_util_percent = 90
        cmd = eng.evaluate(iv)
        return {
            "ok": True,
            "state": PerformanceState(cmd.performance_state).name,
            "tier": PowerTier(cmd.power_tier).name,
            "cpu_cap": cmd.cpu_max_freq_percent,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


def check_security() -> Dict:
    """Test Security AI."""
    try:
        import tempfile, shutil
        from security_ai import SecurityAI
        d = tempfile.mkdtemp()
        try:
            sec = SecurityAI(state_dir=d)
            sec.scan()
            return {
                "ok": True,
                "threat": sec.threat_level,
                "incidents": sec.total_incidents,
            }
        finally:
            shutil.rmtree(d, ignore_errors=True)
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


def check_storage() -> Dict:
    """Test OMFS."""
    try:
        from omfs import OMFS
        omfs = OMFS(root=os.path.join(OMEGA_DIR, "storage"))
        s = omfs.stats()
        return {
            "ok": True,
            "projects": s["projects"],
            "files": s["files"],
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


def check_apks() -> Dict:
    """Analyze APKs in apks dir."""
    try:
        import glob
        from acl import APKAnalyzer, ACLSimulator
        apk_dir = os.path.join(OMEGA_DIR, "apks")
        if not os.path.isdir(apk_dir):
            return {"ok": False, "error": "no apks dir"}
        apks = glob.glob(os.path.join(apk_dir, "*.apk"))
        if not apks:
            return {"ok": True, "count": 0}

        analyzer = APKAnalyzer()
        sim = ACLSimulator()
        signed = 0
        with_perms = 0
        total_size = 0
        for a in apks:
            total_size += os.path.getsize(a) // 1024
            info = analyzer.analyze(a)
            rep = sim.analyze(info)
            if info.permissions:
                with_perms += 1
        return {
            "ok": True,
            "count": len(apks),
            "total_kb": total_size,
            "with_perms": with_perms,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


def check_tests() -> Dict:
    """Run test_suite quickly (just check it imports)."""
    try:
        from test_suite import DecisionEngineTests
        return {"ok": True, "status": "suite available"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


def check_disk() -> Dict:
    """Disk usage of omega dir."""
    try:
        total = 0
        n_files = 0
        for root, _, files in os.walk(OMEGA_DIR):
            if "__pycache__" in root or ".git" in root:
                continue
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                    n_files += 1
                except OSError:
                    pass
        return {
            "ok": True,
            "files": n_files,
            "size_kb": total // 1024,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:60]}


# ==============================================================
# Report printer
# ==============================================================

def print_header():
    print()
    print(c("     " + "═" * 68, C.CYN))
    print(c("         OMEGA OS — System Health Report", C.CYN + C.B))
    print(c("     " + "═" * 68, C.CYN))
    print()


def print_module_check():
    print(c("  Modules", C.WHT + C.B))
    print(c("  " + "─" * 66, C.GRY))

    total = 0
    passed = 0
    failures = []

    for cat_name, modules in CATEGORIES:
        print()
        print(f"  {c(cat_name, C.CYN)}")
        for display, mod, optional in modules:
            total += 1
            ok_, msg = check_import(mod, optional)
            if ok_:
                passed += 1
                print(f"    {ok()} {display:<20} {c('imported', C.GRY)}")
            elif optional:
                print(f"    {skip()} {display:<20} {c('optional', C.GRY)}")
            else:
                failures.append((display, msg))
                print(f"    {fail()} {display:<20} {c(msg[:40], C.RED)}")

    print()
    print(c("  " + "─" * 66, C.GRY))
    pct = 100 * passed / total if total else 0
    color = C.GRN if pct >= 95 else (C.YEL if pct >= 80 else C.RED)
    print(f"  Modules OK: {c(f'{passed}/{total}', color + C.B)}  ({pct:.0f}%)")
    return passed, total, failures


def print_subsystem_checks():
    print()
    print(c("  Subsystem Checks", C.WHT + C.B))
    print(c("  " + "─" * 66, C.GRY))
    print()

    checks = [
        ("Event Bus",       check_bus),
        ("Decision Engine", check_decision_engine),
        ("Security AI",     check_security),
        ("Storage (OMFS)",  check_storage),
        ("APK Analysis",    check_apks),
        ("Test Suite",      check_tests),
        ("HAL",             check_hal),
    ]

    results = {}
    for name, fn in checks:
        try:
            t0 = time.time()
            result = fn()
            ms = int((time.time() - t0) * 1000)
            results[name] = result
            status = ok() if result.get("ok") else fail()
            detail = _format_detail(name, result)
            print(f"  {status} {name:<18} {c(f'{ms}ms', C.GRY):<8} {detail}")
        except Exception as e:
            print(f"  {fail()} {name:<18} {c(str(e)[:40], C.RED)}")

    return results


def _format_detail(name: str, r: dict) -> str:
    if not r.get("ok"):
        return c(r.get("error", "failed")[:40], C.RED)

    if name == "Event Bus":
        return f"{r['events']} event(s) delivered"
    if name == "Decision Engine":
        return f"state={r['state']} tier={r['tier']} cpu_cap={r['cpu_cap']}%"
    if name == "Security AI":
        return f"threat={r['threat']} incidents={r['incidents']}"
    if name == "Storage (OMFS)":
        return f"{r['projects']} projects, {r['files']} files"
    if name == "APK Analysis":
        return f"{r['count']} APKs, {r['total_kb']} KB, {r['with_perms']} with permissions"
    if name == "Test Suite":
        return r.get("status", "ok")
    if name == "HAL":
        return (f"{r['cores']} cores, {r['zones']} zones, "
                f"battery={r['battery']}%, "
                f"RAM={r['ram_used']}/{r['ram_total']}MB, "
                f"SoC={r['soc_temp']}C")
    return "ok"


def print_disk():
    d = check_disk()
    if not d.get("ok"):
        return
    print()
    print(c("  Project Size", C.WHT + C.B))
    print(c("  " + "─" * 66, C.GRY))
    print(f"  Files  : {d['files']}")
    print(f"  Size   : {d['size_kb']} KB ({d['size_kb'] // 1024} MB)")


def print_summary(module_stats, results):
    passed, total, failures = module_stats

    print()
    print(c("     " + "─" * 68, C.CYN))
    print(c("     Summary", C.CYN + C.B))
    print(c("     " + "─" * 68, C.CYN))
    print()

    pct = 100 * passed / total if total else 0
    checks_ok = sum(1 for r in results.values() if r.get("ok"))
    checks_total = len(results)

    color_m = C.GRN if pct >= 95 else (C.YEL if pct >= 80 else C.RED)
    color_s = C.GRN if checks_ok == checks_total else C.YEL

    print(f"  Modules imported : {c(f'{passed}/{total}', color_m)}")
    print(f"  Subsystems live  : {c(f'{checks_ok}/{checks_total}', color_s)}")

    if failures:
        print()
        print(c(f"  ⚠ {len(failures)} module(s) failed:", C.YEL))
        for name, msg in failures[:5]:
            print(f"      {fail()} {name}: {c(msg[:50], C.GRY)}")

    # Overall verdict
    print()
    if pct >= 95 and checks_ok == checks_total:
        verdict = c("  ✅ SYSTEM HEALTHY", C.GRN + C.B)
    elif pct >= 80:
        verdict = c("  ⚠ SYSTEM DEGRADED", C.YEL + C.B)
    else:
        verdict = c("  ❌ SYSTEM UNHEALTHY", C.RED + C.B)
    print(verdict)
    print()


# ==============================================================
# Main
# ==============================================================

def main():
    print_header()

    t0 = time.time()

    # Phase 1: module imports
    module_stats = print_module_check()

    # Phase 2: subsystem functional checks
    results = print_subsystem_checks()

    # Phase 3: disk
    print_disk()

    # Phase 4: summary
    print_summary(module_stats, results)

    elapsed = int((time.time() - t0) * 1000)
    print(c(f"  Report generated in {elapsed} ms", C.GRY))
    print()

    # Return 0 if healthy
    ok_all = (module_stats[0] == module_stats[1] and
              all(r.get("ok") for r in results.values()))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
