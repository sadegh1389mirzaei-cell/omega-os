#!/usr/bin/env python3
# Persistent collector with visible notification
import os, sys, time, signal, subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bus import EventBus
from bus_hooks import set_bus, emit_telemetry_sample
from real_telemetry import RealTelemetry

bus = EventBus(echo=False)
set_bus(bus)
rt = RealTelemetry()

def notify(title, content):
    """Show persistent notification."""
    try:
        subprocess.run(
            ["termux-notification",
             "--id", "omega-collector",
             "--title", title,
             "--content", content,
             "--ongoing"],
            timeout=3,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

def is_charging():
    try:
        r = subprocess.run(["termux-battery-status"],
                          capture_output=True, timeout=3)
        if r.returncode == 0:
            import json
            d = json.loads(r.stdout.decode())
            return d.get("plugged", "UNPLUGGED") != "UNPLUGGED"
    except Exception:
        pass
    return False

running = True
def stop(sig, frame):
    global running
    running = False
    notify("OMEGA", "Collector stopped")
    sys.exit(0)

signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

INTERVAL = 30
count = 0
print(f"[collector-service] starting, interval={INTERVAL}s", flush=True)

while running:
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
        print(f"[collector-service] #{count} cpu={cpu}% wl={wl}", flush=True)

        # Update notification every 3 cycles (~90s)
        if count % 3 == 0:
            charging = "⚡" if is_charging() else ""
            notify(
                f"OMEGA Collector {charging}",
                f"#{count} | cpu={cpu}% | bat={iv.battery_percent}% | {wl}"
            )
    except Exception as e:
        print(f"[collector-service] error: {e}", flush=True)

    for _ in range(INTERVAL):
        if not running:
            break
        time.sleep(1)
