# ==============================================================
# OMEGA OS - Real Decision Engine on Real Hardware
# ==============================================================

import time
import sys

from omega import (
    Config, DecisionEngine, PowerTier, PowerSource,
    PerformanceState, ThermalState, DeviceMode, PreWarmStage,
    WorkloadClass, JsonStore,
)
from real_telemetry import RealTelemetry
from omega import C, colorize, STATE_COLOR, TIER_COLOR, THERMAL_COLOR


def format_real_line(idx: int, iv, cmd):
    ps = PerformanceState(cmd.performance_state).name
    dm = DeviceMode(cmd.device_mode).name
    pt = PowerTier(cmd.power_tier).name
    ts = ThermalState(cmd.thermal_state).name
    wc = WorkloadClass(iv.foreground_workload).name

    ps_c = colorize(f"{ps:<11}", STATE_COLOR.get(ps, ""))
    pt_c = colorize(f"{pt:<9}",  TIER_COLOR.get(pt, ""))
    ts_c = colorize(f"{ts:<9}",  THERMAL_COLOR.get(ts, ""))

    cpu_avg = sum(iv.cpu_util_percent[:iv.cpu_core_count])
    cpu_avg = cpu_avg // max(1, iv.cpu_core_count)
    ram_p = iv.ram_pressure_percent
    bat = iv.battery_percent

    line = (f"[{idx:03d}] {ps_c} {pt_c} {ts_c} "
            f"CPU:{cpu_avg:>3}% RAM:{ram_p:>3}% "
            f"BAT:{bat:>3}% "
            f"{wc:<12} "
            f"-> CPU{cmd.cpu_max_freq_percent}% GPU{cmd.gpu_max_freq_percent}%")
    return line


def main():
    cfg = Config.load("config.json")
    engine = DecisionEngine(cfg)
    rt = RealTelemetry()

    print(colorize("=" * 90, C.GREEN))
    print(colorize("  OMEGA OS - Real Decision Engine on This Device", C.BOLD))
    print(colorize("=" * 90, C.GREEN))
    print(f"  CPU cores : {rt.cpu_count}")
    print(f"  Battery   : {'termux-api OK' if rt.has_battery else 'not available (install termux-api)'}")
    print(f"  Cycle     : {cfg.decision_cycle_ms} ms")
    print()

    if len(sys.argv) > 1:
        try:
            steps = int(sys.argv[1])
        except ValueError:
            steps = 30
    else:
        steps = 30

    print(f"Running {steps} cycles... (Ctrl+C to stop)")
    print()
    print(f"{'#':<6}{'STATE':<12}{'TIER':<10}{'THERMAL':<10}"
          f"{'CPU':<7}{'RAM':<7}{'BAT':<7}{'WORKLOAD':<14}COMMANDS")
    print("-" * 90)

    history = []
    try:
        for i in range(1, steps + 1):
            iv = rt.next()
            cmd = engine.evaluate(iv)
            print(format_real_line(i, iv, cmd))

            history.append({
                "ts": iv.timestamp_ms,
                "state":   PerformanceState(cmd.performance_state).name,
                "mode":    DeviceMode(cmd.device_mode).name,
                "tier":    PowerTier(cmd.power_tier).name,
                "thermal": ThermalState(cmd.thermal_state).name,
                "prewarm": PreWarmStage(cmd.prewarm_stage).name,
                "frozen":  0,
                "thawed":  0,
                "zram_mb": 0,
                "memory_note": "",
                "reason":  cmd.reason,
                # real data
                "real_cpu_avg": sum(iv.cpu_util_percent[:iv.cpu_core_count]) // max(1, iv.cpu_core_count),
                "real_ram_used_mb": iv.ram_used_mb,
                "real_battery": iv.battery_percent,
                "real_workload": WorkloadClass(iv.foreground_workload).name,
            })

            time.sleep(cfg.decision_cycle_ms / 1000.0)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

    # Save
    store = JsonStore("history_real.json")
    store.save({"history": history})
    print()
    print(colorize(f"[+] Saved {len(history)} decisions -> history_real.json", C.GREEN))

    # Try to make report
    try:
        import report
        report.generate_html_report(
            "history_real.json", "report_real.html")
        print(colorize(f"[+] Report: report_real.html", C.GREEN))
    except Exception as e:
        print(f"[!] Report generation failed: {e}")


if __name__ == "__main__":
    main()
