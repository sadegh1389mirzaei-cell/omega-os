#!/usr/bin/env python3
# Runs one short collection burst, then exits.
# Android wakes us up periodically via termux-job-scheduler.

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bus import EventBus
from bus_hooks import set_bus, emit_telemetry_sample
from real_telemetry import RealTelemetry

bus = EventBus(echo=False)
set_bus(bus)
rt = RealTelemetry()

SAMPLES = 5          # collect 5 samples
INTERVAL = 15        # every 15 seconds
count = 0

for i in range(SAMPLES):
    try:
        iv = rt.next()
        cpu = sum(iv.cpu_util_percent) // max(1, iv.cpu_core_count)

        if cpu < 5:
            wl = "IDLE"
        elif cpu < 15:
            wl = "LIGHT"
        elif cpu < 30:
            wl = "WEB"
        elif cpu < 55:
            wl = "VIDEO"
        else:
            wl = "COMPUTE"

        emit_telemetry_sample(
            cpu=int(cpu),
            ram=iv.ram_pressure_percent,
            battery=iv.battery_percent,
            temp_c=iv.temp_soc_c / 10,
            workload=wl,
        )
        count += 1
    except Exception as e:
        print(f"[job] error: {e}", file=sys.stderr)
        break
    time.sleep(INTERVAL)

print(f"[job] collected {count} samples", flush=True)
