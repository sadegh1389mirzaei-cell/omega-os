#!/usr/bin/env python3
import os
import sys
import time
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bus import EventBus
from bus_hooks import set_bus, emit_telemetry_sample
from real_telemetry import RealTelemetry

bus = EventBus(echo=False)
set_bus(bus)
rt = RealTelemetry()

running = True
def stop(sig, frame):
    global running
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

INTERVAL = 30
count = 0

print(f"[collector] starting, interval={INTERVAL}s", flush=True)

while running:
    try:
        iv = rt.next()
        cpu = sum(iv.cpu_util_percent) // max(1, iv.cpu_core_count)

        # Workload from CPU%, not from process names
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
        print(f"[collector] #{count} cpu={cpu}% ram={iv.ram_pressure_percent}% wl={wl}", flush=True)
    except Exception as e:
        print(f"[collector] error: {e}", flush=True)

    for _ in range(INTERVAL):
        if not running:
            break
        time.sleep(1)
