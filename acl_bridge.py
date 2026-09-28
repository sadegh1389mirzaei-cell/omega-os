# ==============================================================
# OMEGA OS - ACL ↔ Runtime Bridge
# ==============================================================
# Connects Section 5.2 (ACL) to Section 5 (Runtime).
#
# Before:
#   RuntimeManager.estimate(app, ANDROID)
#   → uses SPECS[ANDROID] coefficients (same for ALL apps)
#
# After:
#   bridge.estimate_from_apk(apk, app_profile)
#   → uses THIS specific APK's overhead
# ==============================================================

import os
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from acl import (
    ACLSimulator, APKAnalyzer, APKInfo, CompatibilityReport,
    make_synthetic_apk,
)
from runtime import (
    RuntimeManager, RuntimeType, AppProfile, LaunchEstimate,
    SPECS, print_comparison,
)


HOME = os.path.expanduser("~")


# ==============================================================
# Bridge
# ==============================================================

class ACLRuntimeBridge:
    """
    Wraps ACL analysis and feeds the results into runtime estimation.
    Caches reports by APK SHA-256 so re-analysis is free.
    """

    def __init__(self, bus=None):
        self.bus = bus
        self.acl = ACLSimulator()
        self.runtime = RuntimeManager(bus=bus)
        self._analyzer = APKAnalyzer()

        # caches
        self.report_cache: Dict[str, CompatibilityReport] = {}
        self.info_cache: Dict[str, APKInfo] = {}

        self.stats = {
            "analyses": 0,
            "cache_hits": 0,
            "estimates": 0,
        }

    # ──────────────────────────────────────────────────────────
    # Analysis (cached by SHA-256)
    # ──────────────────────────────────────────────────────────

    def analyze(self, apk_path: str,
                force: bool = False) -> CompatibilityReport:
        """
        Analyze an APK. Cached by file hash.
        Returns CompatibilityReport.
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(apk_path)

        # Compute hash first for cache lookup
        sha = self._analyzer._hash(apk_path)

        if not force and sha in self.report_cache:
            self.stats["cache_hits"] += 1
            return self.report_cache[sha]

        info = self._analyzer.analyze(apk_path)
        report = self.acl.analyze(info)

        self.report_cache[sha] = report
        self.info_cache[sha] = info
        self.stats["analyses"] += 1

        # Emit to bus
        if self.bus:
            try:
                self.bus.emit(
                    "acl.analyzed", "acl_bridge",
                    apk=os.path.basename(apk_path),
                    score=report.score,
                    verdict=report.verdict,
                    dex=info.dex_count,
                    gms=info.uses_gms,
                )
            except Exception:
                pass

        return report

    def get_info(self, apk_path: str) -> APKInfo:
        sha = self._analyzer._hash(apk_path)
        if sha not in self.info_cache:
            self.analyze(apk_path)
        return self.info_cache[sha]

    # ──────────────────────────────────────────────────────────
    # Runtime estimation using real APK overhead
    # ──────────────────────────────────────────────────────────

    def estimate_from_apk(self,
                          apk_path: str,
                          base_cpu_mhz: int = 500,
                          base_mem_mb: int = 200,
                          base_gpu_mhz: int = 0,
                          base_battery_mw: float = 300.0,
                          app_name: Optional[str] = None) -> LaunchEstimate:
        """
        Estimate launch cost for THIS specific APK.
        Uses ACL's per-APK coefficients instead of generic ANDROID ones.
        """
        report = self.analyze(apk_path)
        info = report.info

        app_id = info.package or os.path.basename(apk_path)
        name = app_name or os.path.basename(apk_path)

        app = AppProfile(
            app_id=app_id,
            name=name,
            cpu_mhz=base_cpu_mhz,
            memory_mb=base_mem_mb,
            gpu_mhz=base_gpu_mhz,
            battery_mw=base_battery_mw,
        )

        # AC L's specific overhead (not the generic SPECS ones)
        spec = SPECS[RuntimeType.ANDROID]

        self.stats["estimates"] += 1

        return LaunchEstimate(
            runtime=RuntimeType.ANDROID,
            app=app,
            cpu_mhz=int(base_cpu_mhz * report.cpu_overhead),
            memory_mb=int(base_mem_mb * report.mem_overhead),
            gpu_mhz=int(base_gpu_mhz * report.gpu_overhead),
            battery_mw=round(base_battery_mw * spec.battery_multiplier, 1),
            launch_cold_ms=report.cold_start_ms,
            launch_warm_ms=report.warm_start_ms,
            cpu_mult=report.cpu_overhead,
            mem_mult=report.mem_overhead,
            reason=f"ACL: {report.verdict} ({report.score}/100)",
        )

    def compare_generic_vs_apk(self,
                               apk_path: str,
                               base_cpu_mhz: int = 500,
                               base_mem_mb: int = 200,
                               base_gpu_mhz: int = 0,
                               base_battery_mw: float = 300.0):
        """
        Returns (generic_estimate, apk_specific_estimate).
        Generic: uses SPECS[ANDROID] average.
        Specific: uses ACL's per-APK coefficients.
        """
        app = AppProfile(
            app_id="compare", name="Compare",
            cpu_mhz=base_cpu_mhz, memory_mb=base_mem_mb,
            gpu_mhz=base_gpu_mhz, battery_mw=base_battery_mw,
        )
        # Use variance=0.5 so generic is compared at the AVERAGE
        # of its range (not the optimistic low end).
        generic = self.runtime.estimate(app, RuntimeType.ANDROID,
                                       variance=0.5)
        specific = self.estimate_from_apk(
            apk_path,
            base_cpu_mhz=base_cpu_mhz,
            base_mem_mb=base_mem_mb,
            base_gpu_mhz=base_gpu_mhz,
            base_battery_mw=base_battery_mw,
        )
        return generic, specific

    # ──────────────────────────────────────────────────────────
    # Launch simulation (emit to bus)
    # ──────────────────────────────────────────────────────────

    def simulate_launch(self, apk_path: str,
                        prewarmed: bool = False,
                        **estimate_kwargs) -> LaunchEstimate:
        est = self.estimate_from_apk(apk_path, **estimate_kwargs)
        actual_ms = (est.launch_warm_ms if prewarmed
                    else est.launch_cold_ms)

        if self.bus:
            try:
                self.bus.emit(
                    "runtime.launch", "acl_bridge",
                    apk=os.path.basename(apk_path),
                    ms=actual_ms,
                    prewarmed=prewarmed,
                    cpu_mult=round(est.cpu_mult, 2),
                    mem_mult=round(est.mem_mult, 2),
                )
            except Exception:
                pass

        return est

    # ──────────────────────────────────────────────────────────
    # Snapshot
    # ──────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        return {
            "cached_reports": len(self.report_cache),
            "analyses": self.stats["analyses"],
            "cache_hits": self.stats["cache_hits"],
            "estimates": self.stats["estimates"],
        }


# ==============================================================
# Pretty print — side-by-side
# ==============================================================

def print_comparison_table(rows: List[tuple]):
    """
    rows: list of (apk_name, generic_est, specific_est, report)
    """
    C = "\033[96m"
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    D = "\033[90m"
    B = "\033[1m"
    Z = "\033[0m"

    print()
    print(f"{C}════════════════════════════════════════════════════════════════════{Z}")
    print(f"{C}  ACL ↔ Runtime Bridge — Per-APK Overhead{Z}")
    print(f"{C}════════════════════════════════════════════════════════════════════{Z}")

    print()
    print(f"{B}{'APK':<20} {'GENERIC':<24} {'APK-SPECIFIC':<24} {'VERDICT':<12}{Z}")
    print(f"{D}{'─'*80}{Z}")

    for name, gen, spec, rep in rows:
        gen_str = f"x{gen.cpu_mult:.2f}/{gen.mem_mult:.2f}"
        spec_str = f"x{spec.cpu_mult:.2f}/{spec.mem_mult:.2f}"
        # color spec green if better, red if worse
        delta = spec.cpu_mult - gen.cpu_mult
        color = G if delta < -0.02 else (R if delta > 0.02 else Z)

        vc = {"EXCELLENT": G, "GOOD": G,
              "FAIR": Y, "POOR": R}.get(rep.verdict, Z)

        print(f"{name:<20} "
              f"{D}{gen_str:<24}{Z} "
              f"{color}{spec_str:<24}{Z} "
              f"{vc}{rep.verdict:<12}{Z}")

    print()
    print(f"{D}(values are CPU/RAM overhead multipliers — lower is better){Z}")


def print_detailed(name: str, est_generic: LaunchEstimate,
                   est_specific: LaunchEstimate,
                   report: CompatibilityReport):
    C, G, Y, R, D, Z = ("\033[96m", "\033[92m", "\033[93m",
                        "\033[91m", "\033[90m", "\033[0m")

    print()
    print(f"{C}── {name} ──{Z}")

    info = report.info
    print(f"  dex: {info.dex_count}  "
          f"abi: {','.join(info.native_libs) or 'none'}  "
          f"vulkan: {info.uses_vulkan}  "
          f"gms: {info.uses_gms}  "
          f"size: {info.file_size_kb} KB")

    print()
    print(f"  {'':<14} {'CPU':<12} {'RAM':<12} {'COLD':<10} {'WARM':<10}")
    print(f"  {D}{'─'*56}{Z}")

    g = est_generic
    s = est_specific
    print(f"  {'Generic':<14} "
          f"x{g.cpu_mult:.2f}  {g.cpu_mhz:>4}MHz  "
          f"x{g.mem_mult:.2f}  {g.memory_mb:>4}MB  "
          f"{g.launch_cold_ms:>4}ms  {g.launch_warm_ms:>4}ms")
    print(f"  {'APK-specific':<14} "
          f"x{s.cpu_mult:.2f}  {s.cpu_mhz:>4}MHz  "
          f"x{s.mem_mult:.2f}  {s.memory_mb:>4}MB  "
          f"{s.launch_cold_ms:>4}ms  {s.launch_warm_ms:>4}ms")

    # Delta
    cpu_delta = (s.cpu_mhz - g.cpu_mhz)
    ram_delta = (s.memory_mb - g.memory_mb)
    cold_delta = (s.launch_cold_ms - g.launch_cold_ms)

    print()
    cpu_c = G if cpu_delta < 0 else (R if cpu_delta > 0 else Z)
    ram_c = G if ram_delta < 0 else (R if ram_delta > 0 else Z)
    cold_c = G if cold_delta < 0 else (R if cold_delta > 0 else Z)

    print(f"  Delta   : "
          f"CPU {cpu_c}{cpu_delta:+d}MHz{Z}  "
          f"RAM {ram_c}{ram_delta:+d}MB{Z}  "
          f"Cold {cold_c}{cold_delta:+d}ms{Z}")

    if report.notes:
        print()
        for n in report.notes:
            print(f"  • {n}")
    if report.issues:
        for i in report.issues:
            print(f"  {R}⚠  {i}{Z}")


# ==============================================================
# Demo
# ==============================================================

def demo():
    print()
    print("=" * 70)
    print("  OMEGA OS — ACL Runtime Bridge Demo")
    print("=" * 70)

    # Generate several synthetic APKs with distinct profiles
    scenarios = [
        ("light.apk", dict(dex_count=1, size_kb=800)),
        ("medium.apk", dict(dex_count=3, size_kb=3000)),
        ("heavy.apk", dict(dex_count=6, size_kb=8000,
                          with_vulkan=True)),
        ("gms_app.apk", dict(dex_count=2, size_kb=2500,
                            with_gms=True)),
    ]

    print()
    print("[1] Generating synthetic APKs...")
    paths = []
    for name, opts in scenarios:
        path = make_synthetic_apk(name=name, **opts)
        paths.append((name, path))
        print(f"    ✓ {name}")

    # Bridge
    bridge = ACLRuntimeBridge()

    print()
    print("[2] Comparing generic vs APK-specific overhead...")
    rows = []
    for name, path in paths:
        gen, spec = bridge.compare_generic_vs_apk(
            path,
            base_cpu_mhz=500,
            base_mem_mb=200,
            base_gpu_mhz=200,
        )
        report = bridge.analyze(path)
        rows.append((name, gen, spec, report))

    print_comparison_table(rows)

    # Detailed for the most interesting ones
    print()
    print("[3] Detailed comparison:")
    for name, path in paths[:2]:   # light + medium
        gen, spec = bridge.compare_generic_vs_apk(
            path, base_cpu_mhz=500, base_mem_mb=200, base_gpu_mhz=200)
        report = bridge.analyze(path)
        print_detailed(name, gen, spec, report)

    # Cache stats
    print()
    print("[4] Bridge statistics:")
    snap = bridge.snapshot()
    for k, v in snap.items():
        print(f"    {k:<20} {v}")

    # Simulate a launch (2nd call hits cache)
    print()
    print("[5] Simulating launch of light.apk (prewarmed)...")
    path = paths[0][1]
    est = bridge.simulate_launch(path, prewarmed=True,
                                 base_cpu_mhz=500, base_mem_mb=200)
    print(f"    Cold: {est.launch_cold_ms}ms   "
          f"Warm: {est.launch_warm_ms}ms")
    print(f"    CPU: {est.cpu_mhz}MHz (x{est.cpu_mult:.2f})")
    print(f"    RAM: {est.memory_mb}MB (x{est.mem_mult:.2f})")

    snap2 = bridge.snapshot()
    print()
    print(f"    (after 2nd analyze: {snap2['cache_hits']} cache hits)")

    print()


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
ACL ↔ Runtime Bridge

Usage:
  python acl_bridge.py              demo with synthetic APKs
  python acl_bridge.py <apk>        analyze one APK vs generic
  python acl_bridge.py --help
""")


def main():
    args = sys.argv[1:]

    if not args:
        demo()
        return
    if "--help" in args or "-h" in args:
        cli_help()
        return

    apk = args[0]
    if not os.path.exists(apk):
        print(f"[!] File not found: {apk}")
        return

    bridge = ACLRuntimeBridge()
    gen, spec = bridge.compare_generic_vs_apk(apk)
    report = bridge.analyze(apk)
    print_detailed(os.path.basename(apk), gen, spec, report)


if __name__ == "__main__":
    main()
