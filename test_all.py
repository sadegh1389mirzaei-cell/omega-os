# ==============================================================
# OMEGA OS - One-terminal Demo
# ==============================================================
# Runs everything in sequence and prints events live.
# No curses — plain text output.
# ==============================================================

import time
import os
import sys
from collections import deque

from bus import EventBus, Event
from bus_hooks import (
    set_bus, emit_system_boot, emit_telemetry_sample,
    emit_security_threat, emit_decision_change,
)
from real_telemetry import RealTelemetry
from omega import Config, DecisionEngine, WorkloadClass, PerformanceState


def ts_str():
    return time.strftime("%H:%M:%S")


def main():
    print("=" * 70)
    print("  OMEGA OS - One-Terminal Demo")
    print("=" * 70)
    print()

    # Build bus with echo=False; we handle output ourselves
    bus = EventBus(echo=False)
    set_bus(bus)

    # Ring buffer of last N events for display
    events = deque(maxlen=8)

    def on_any(evt: Event):
        events.append(evt)

    bus.subscribe("*", on_any)
    emit_system_boot("0.4-test")

    cfg = Config.load("config.json")
    engine = DecisionEngine(cfg)
    rt = RealTelemetry()

    print(f"  CPU cores : {rt.cpu_count}")
    print(f"  Bus log   : {bus.log_path}")
    print()

    prev_state = None
    prev_threat = "NORMAL"

    # Phase 1: telemetry + decisions
    print("[PHASE 1] Telemetry + Decision Engine")
    print("-" * 70)

    for i in range(1, 8):
        iv = rt.next()
        cmd = engine.evaluate(iv)

        cpu_avg = sum(iv.cpu_util_percent) // max(1, iv.cpu_core_count)
        wc = WorkloadClass(iv.foreground_workload).name

        emit_telemetry_sample(
            cpu=int(cpu_avg),
            ram=iv.ram_pressure_percent,
            battery=iv.battery_percent,
            temp_c=iv.temp_soc_c / 10,
            workload=wc,
        )

        state_name = PerformanceState(cmd.performance_state).name
        if prev_state and prev_state != state_name:
            emit_decision_change(prev_state, state_name, cmd.reason)
        prev_state = state_name

        # Print live line
        print(f"  [{ts_str()}] telemetry  cpu={cpu_avg:>3}%  "
              f"ram={iv.ram_pressure_percent:>3}%  "
              f"bat={iv.battery_percent:>3}%  "
              f"wl={wc:<10}  state={state_name}")

        time.sleep(0.8)

    # Phase 2: security threat
    print()
    print("[PHASE 2] Simulated Security Threat")
    print("-" * 70)

    threats = [
        ("LOW",    "file",    "~/.zshrc",       "sensitive file modified"),
        ("MEDIUM", "process", "suspicious.sh",  "unknown_high_cpu"),
        ("HIGH",   "process", "nc",             "netcat_listener"),
        ("CRITICAL", "process", "rm -rf /",     "destructive_rm"),
    ]

    for sev, cat, subj, detail in threats:
        emit_security_threat(severity=sev, subject=subj,
                             detail=detail, category=cat)
        time.sleep(0.6)

    # Phase 3: show the event log
    print()
    print("[PHASE 3] Message Bus - Recent Events")
    print("-" * 70)
    for evt in list(events):
        print("  " + evt.short())

    print()
    print(f"[+] Total events in log: {sum(1 for _ in open(bus.log_path))}")
    print(f"[+] Log: {bus.log_path}")


if __name__ == "__main__":
    main()
