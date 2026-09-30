# ==============================================================
# OMEGA OS - Live Dashboard (v4 — with Message Bus)
# ==============================================================

import os
import sys
import time
import curses
from collections import deque

from omega import (
    Config, DecisionEngine, PowerTier, PowerSource,
    PerformanceState, ThermalState, DeviceMode, PreWarmStage,
    WorkloadClass,
)
from modes import ModeManager
from real_telemetry import RealTelemetry
from processes import ProcessScanner, WorkloadClassifier
from security_v2 import SecurityAIv2 as SecurityAI
from bus import EventBus, Topic, Event
import bus_hooks


STATE_COLOR_CURSES = {
    PerformanceState.IDLE:        7,
    PerformanceState.BALANCED:    6,
    PerformanceState.PERFORMANCE: 2,
    PerformanceState.CREATIVE:    5,
    PerformanceState.COMPUTE:     3,
}
TIER_COLOR_CURSES = {
    PowerTier.NORMAL:    7,
    PowerTier.LOW_POWER: 3,
    PowerTier.EMERGENCY: 1,
}
THERMAL_COLOR_CURSES = {
    ThermalState.NORMAL:    7,
    ThermalState.WARNING:   3,
    ThermalState.THROTTLE:  5,
    ThermalState.EMERGENCY: 1,
}
THREAT_COLOR_CURSES = {
    "NORMAL":   2,
    "ELEVATED": 3,
    "HIGH":     5,
    "CRITICAL": 1,
}
SEV_COLOR = {
    "INFO":     7,
    "LOW":      2,
    "MEDIUM":   3,
    "HIGH":     5,
    "CRITICAL": 1,
}


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_BLUE, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
    curses.init_pair(6, curses.COLOR_CYAN, -1)
    curses.init_pair(7, curses.COLOR_WHITE, -1)


def make_bar(value: int, width: int, max_val: int = 100) -> str:
    if width < 2:
        return ""
    filled = max(0, min(width, int(value * width / max_val)))
    return "█" * filled + "░" * (width - filled)


def color_for(value: int, invert: bool = False) -> int:
    if invert:
        if value >= 50: return 2
        if value >= 20: return 3
        return 1
    if value >= 80: return 1
    if value >= 55: return 3
    return 2


def safe_addstr(stdscr, row, col, text, attr=0):
    try:
        h, w = stdscr.getmaxyx()
        if row < 0 or row >= h or col < 0 or col >= w:
            return
        max_len = w - col - 1
        if max_len <= 0:
            return
        stdscr.addstr(row, col, text[:max_len], attr)
    except curses.error:
        pass


def draw(stdscr, engine, rt, sample_count, last_iv, last_cmd,
         workload_summary, top_procs, security_summary, events):
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    # ── Header ──
    threat = security_summary.get("threat_level", "NORMAL") if security_summary else "NORMAL"
    threat_color = THREAT_COLOR_CURSES.get(threat, 7)

    safe_addstr(stdscr, 0, 0, " OMEGA LIVE ", curses.color_pair(2) | curses.A_BOLD)
    threat_text = f" [{threat}] "
    safe_addstr(stdscr, 0, max(0, w - len(threat_text) - 8),
                threat_text, curses.color_pair(threat_color) | curses.A_BOLD)
    counter = f" #{sample_count} "
    safe_addstr(stdscr, 0, max(0, w - len(counter) - 1),
                counter, curses.color_pair(7))

    if h > 1:
        safe_addstr(stdscr, 1, 0, "─" * w, curses.color_pair(7))

    row = 2

    # ── Decision states ──
    ps = PerformanceState(last_cmd.performance_state)
    pt = PowerTier(last_cmd.power_tier)
    ts = ThermalState(last_cmd.thermal_state)
    dm = DeviceMode(last_cmd.device_mode)

    safe_addstr(stdscr, row, 0, "S:", curses.color_pair(7))
    safe_addstr(stdscr, row, 2, f"{ps.name:<11}",
                curses.color_pair(STATE_COLOR_CURSES[ps]) | curses.A_BOLD)
    if w >= 40:
        safe_addstr(stdscr, row, 22, "M:", curses.color_pair(7))
        safe_addstr(stdscr, row, 24, f"{dm.name:<8}", curses.color_pair(6))
    row += 1

    safe_addstr(stdscr, row, 0, "T:", curses.color_pair(7))
    safe_addstr(stdscr, row, 2, f"{pt.name:<11}",
                curses.color_pair(TIER_COLOR_CURSES[pt]) | curses.A_BOLD)
    if w >= 40:
        safe_addstr(stdscr, row, 22, "H:", curses.color_pair(7))
        safe_addstr(stdscr, row, 24, f"{ts.name:<8}",
                    curses.color_pair(THERMAL_COLOR_CURSES[ts]))
    row += 1

    # ── Visual EMERGENCY banner (Section 7.4.4) ──
    if ts == ThermalState.EMERGENCY and row < h - 3:
        warn = " THERMAL EMERGENCY - COOL DOWN NOW "
        x = max(0, (w - len(warn)) // 2)
        safe_addstr(stdscr, row, x, warn,
                    curses.color_pair(1) | curses.A_BOLD | curses.A_BLINK)
        row += 1

    # ── Hardware bars ──
    if h > row + 4:
        safe_addstr(stdscr, row, 0, "─" * w, curses.color_pair(7))
        row += 1

        cpu_avg = sum(last_iv.cpu_util_percent) / max(1, last_iv.cpu_core_count)
        bar_w = max(4, w - 20)

        safe_addstr(stdscr, row, 0, f"CPU {int(cpu_avg):>3}%", curses.color_pair(7))
        safe_addstr(stdscr, row, 9, make_bar(int(cpu_avg), bar_w),
                    curses.color_pair(color_for(int(cpu_avg))))
        row += 1

        ram_p = last_iv.ram_pressure_percent
        safe_addstr(stdscr, row, 0, f"RAM {ram_p:>3}%", curses.color_pair(7))
        safe_addstr(stdscr, row, 9, make_bar(ram_p, bar_w),
                    curses.color_pair(color_for(ram_p)))
        row += 1

        bat_p = last_iv.battery_percent
        safe_addstr(stdscr, row, 0, f"BAT {bat_p:>3}%", curses.color_pair(7))
        safe_addstr(stdscr, row, 9, make_bar(bat_p, bar_w),
                    curses.color_pair(color_for(bat_p, invert=True)))
        row += 1

        if h > row + 1:
            wc = WorkloadClass(last_iv.foreground_workload).name
            info = f"Z:{last_iv.zram_compressed_mb}M T:{last_iv.temp_soc_c/10:.0f}C {wc}"
            safe_addstr(stdscr, row, 0, info, curses.color_pair(6))
            row += 1

    # ── Commands ──
    if h > row + 3:
        safe_addstr(stdscr, row, 0, "─" * w, curses.color_pair(7))
        row += 1
        safe_addstr(stdscr, row, 0,
                    f"CPU:{last_cmd.cpu_max_freq_percent}% "
                    f"GPU:{last_cmd.gpu_max_freq_percent}% "
                    f"R:{last_cmd.display_refresh_hz}Hz",
                    curses.color_pair(7))
        row += 1

    # ── Security ──
    if h > row + 3 and security_summary:
        t = security_summary.get("threat_level", "NORMAL")
        inc = security_summary.get("total_incidents", 0)
        trusted = security_summary.get("trusted_count", 0)
        dangerous = security_summary.get("dangerous_count", 0)

        safe_addstr(stdscr, row, 0, "SEC ", curses.color_pair(6) | curses.A_BOLD)
        safe_addstr(stdscr, row, 4, t,
                    curses.color_pair(THREAT_COLOR_CURSES.get(t, 7)) | curses.A_BOLD)
        safe_addstr(stdscr, row, 4 + len(t) + 1,
                    f"inc:{inc} T:{trusted} D:{dangerous}",
                    curses.color_pair(7))
        row += 1

    # ── Events (from bus) ──
    if events:
        safe_addstr(stdscr, row, 0, "─" * w, curses.color_pair(7))
        row += 1
        safe_addstr(stdscr, row, 0, "EVENTS", curses.color_pair(6) | curses.A_BOLD)
        row += 1

        available = h - row - 2
        for evt in list(events)[-available:]:
            if row >= h - 2:
                break
            hhmmss = time.strftime("%H:%M:%S",
                                   time.localtime(evt.ts / 1000))
            topic = evt.topic[:22]
            sev = evt.severity[:4]
            col = SEV_COLOR.get(evt.severity, 7)
            line = f"  {hhmmss} {sev:<4} {topic}"
            safe_addstr(stdscr, row, 0, line, curses.color_pair(col))
            row += 1

    # ── Footer ──
    footer = " Q:Quit  R:Reset  S:Save "
    safe_addstr(stdscr, h - 1, max(0, (w - len(footer)) // 2),
                footer, curses.color_pair(7) | curses.A_DIM)

    stdscr.refresh()


def save_session(engine, security):
    from omega import JsonStore
    store = JsonStore("history_live.json")
    store.save({"history": engine.history})
    security.trust.save()
    return len(engine.history)


# ==============================================================
# Main
# ==============================================================

def main(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)
    init_colors()

    # ── Event bus ──
    bus = EventBus(echo=False)   # don't print, dashboard handles display
    bus_hooks.set_bus(bus)

    # ring buffer of recent events for display
    recent_events = deque(maxlen=30)

    def on_any(evt: Event):
        recent_events.append(evt)

    bus.subscribe("*", on_any)

    bus_hooks.emit_system_boot("0.4")

    # ── Components ──
    cfg = Config.load("config.json")
    engine = DecisionEngine(cfg)
    mm = ModeManager(bus=bus)      # emits mode.* events to bus
    rt = RealTelemetry()
    scanner = ProcessScanner()
    classifier = WorkloadClassifier()
    security = SecurityAI(state_dir=".")

    sample_count = 0
    last_iv = None
    last_cmd = None
    last_workload_summary = ""
    last_top_procs = []
    last_security_summary = None
    prev_threat = None
    prev_state = None

    last_sample_time = 0.0
    last_security_time = 0.0
    SAMPLE_INTERVAL = 1.0
    SECURITY_INTERVAL = 10.0
    DECIDE_EVERY_N = 10

    # Initial
    last_iv = rt.next()
    last_cmd = engine.evaluate(last_iv)
    procs = scanner.scan()
    wc_class, _, wc_summary = classifier.classify(procs)
    last_iv.foreground_workload = int(wc_class)
    last_workload_summary = wc_summary
    last_top_procs = classifier.top_processes(procs, 3)
    sample_count = 1
    last_sample_time = time.time()

    last_security_summary = security.scan()
    last_security_time = time.time()

    while True:
        try:
            ch = stdscr.getch()
        except curses.error:
            ch = -1

        if ch in (ord('q'), ord('Q')):
            break

        if ch in (ord('r'), ord('R')):
            engine = DecisionEngine(cfg)
            sample_count = 0
            last_iv = rt.next()
            last_cmd = engine.evaluate(last_iv)
            sample_count = 1
            last_sample_time = time.time()
            prev_state = None

        if ch in (ord('s'), ord('S')):
            n = save_session(engine, security)
            h, w = stdscr.getmaxyx()
            safe_addstr(stdscr, h - 1, 2,
                        f" Saved {n} → history_live.json ",
                        curses.color_pair(2) | curses.A_BOLD)
            stdscr.refresh()
            time.sleep(1)

        now = time.time()

        # Sample real data every second
        if now - last_sample_time >= SAMPLE_INTERVAL:
            last_iv = rt.next()

            procs = scanner.scan()
            wc_class, _, wc_summary = classifier.classify(procs)
            last_iv.foreground_workload = int(wc_class)
            last_workload_summary = wc_summary
            last_top_procs = classifier.top_processes(procs, 3)

            last_sample_time = now
            sample_count += 1

            # IMMEDIATE thermal decision (Section 7.4.4)
            # When temp crosses 50.0C, we must NOT wait for the
            # 10-cycle counter — the spec requires immediate action.
            if last_iv.temp_soc_c >= 500:
                last_cmd = engine.evaluate(last_iv)
                new_state = PerformanceState(
                    last_cmd.performance_state).name
                if prev_state is not None and prev_state != new_state:
                    bus_hooks.emit_decision_change(
                        old=prev_state, new=new_state,
                        reason="thermal emergency: " + last_cmd.reason)
                prev_state = new_state

            # Emit telemetry every 5 seconds to avoid log spam
            if sample_count % 5 == 0:
                cpu_avg = sum(last_iv.cpu_util_percent) // max(1, last_iv.cpu_core_count)
                bus_hooks.emit_telemetry_sample(
                    cpu=int(cpu_avg),
                    ram=last_iv.ram_pressure_percent,
                    battery=last_iv.battery_percent,
                    temp_c=last_iv.temp_soc_c / 10,
                    workload=WorkloadClass(last_iv.foreground_workload).name,
                )

            # Mode manager (emits bus events on transition)
            try:
                mm.evaluate(last_iv)
            except Exception:
                pass

            if sample_count % DECIDE_EVERY_N == 0:
                last_cmd = engine.evaluate(last_iv)

                # Emit decision change
                new_state = PerformanceState(last_cmd.performance_state).name
                if prev_state is not None and prev_state != new_state:
                    bus_hooks.emit_decision_change(
                        old=prev_state, new=new_state,
                        reason=last_cmd.reason)
                prev_state = new_state

        # Security scan every 10s
        if now - last_security_time >= SECURITY_INTERVAL:
            try:
                last_security_summary = security.scan()
            except Exception:
                pass
            last_security_time = now

        draw(stdscr, engine, rt, sample_count, last_iv, last_cmd,
             workload_summary=last_workload_summary,
             top_procs=last_top_procs,
             security_summary=last_security_summary,
             events=list(recent_events))
        time.sleep(0.05)

    bus_hooks.emit_system_shutdown()
    if engine.history:
        n = save_session(engine, security)
        print(f"\nSaved {n} decisions → history_live.json")


if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\nStopped.")
