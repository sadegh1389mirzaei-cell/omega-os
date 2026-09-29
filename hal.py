# ==============================================================
# OMEGA OS - HAL v3
# ==============================================================
# Best of both worlds:
#   - sysfs direct read for per-core CPU freq (all 8 cores)
#   - psutil for memory, thermal zones (40+), battery
#   - ps fallback for CPU usage
#
# Suppresses psutil warnings from blocked /proc files.
# ==============================================================

import os
import sys
import json
import time
import warnings
import subprocess
from typing import Optional

# Suppress psutil RuntimeWarnings from blocked /proc files
warnings.filterwarnings("ignore", category=RuntimeWarning,
                       module="psutil")

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


# ── Thermal categorization ──
SOC_PREFIXES    = ("cpuss-", "cpu-1-", "hepta-cpu-")
GPU_PREFIXES    = ("gpu-",)
BATTERY_NAMES   = ("Battery", "battery", "rt_battery")
SKIN_PREFIXES   = ("shell_",)
MODEM_PREFIXES  = ("mdm-",)
WIFI_PREFIXES   = ("wlan-",)
CHARGER_NAMES   = ("charger",)
USB_PREFIXES    = ("usb_port",)
DSP_PREFIXES    = ("cdsp-hvx-",)
CAMERA_PREFIXES = ("camera-", "display-", "video-")
BOGUS_NAMES     = ("soc_boot_thermal", "bat_id", "quiet-thermal-")


class HAL:
    def __init__(self, bus=None):
        self.bus = bus
        self._battery_cache = None
        self._battery_cache_ts = 0
        self._battery_cache_ttl = 30.0  # seconds

    # ──────────────────────────────────────────────────────────
    # CPU frequency — sysfs direct (gets ALL cores)
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _read_sysfs(path: str) -> Optional[int]:
        try:
            with open(path) as f:
                return int(f.read().strip()) // 1000   # kHz → MHz
        except (OSError, ValueError):
            return None

    def _cpu_freq_sysfs(self, core_id: int):
        base = f"/sys/devices/system/cpu/cpu{core_id}/cpufreq"
        cur = (self._read_sysfs(f"{base}/scaling_cur_freq") or
               self._read_sysfs(f"{base}/cpuinfo_cur_freq"))
        mx = (self._read_sysfs(f"{base}/scaling_max_freq") or
              self._read_sysfs(f"{base}/cpuinfo_max_freq"))
        mn = (self._read_sysfs(f"{base}/scaling_min_freq") or
              self._read_sysfs(f"{base}/cpuinfo_min_freq"))
        return cur, mx, mn

    def _probe_cpu(self):
        cores = []
        count = (psutil.cpu_count(logical=True)
                 if _PSUTIL else os.cpu_count() or 0)

        # Try psutil first
        freq_by_id = {}
        if _PSUTIL:
            try:
                for i, f in enumerate(psutil.cpu_freq(percpu=True) or []):
                    freq_by_id[i] = (int(f.current), int(f.max),
                                    int(getattr(f, "min", 0)))
            except Exception:
                pass

        for i in range(count):
            # Prefer sysfs (covers all cores)
            cur, mx, mn = self._cpu_freq_sysfs(i)

            # Fallback to psutil for missing values
            if cur is None and i in freq_by_id:
                cur, mx, mn = freq_by_id[i]

            if cur is None:
                cur = 0
            if mx is None or mx == 0:
                mx = cur
            if mn is None:
                mn = 0

            cores.append({
                "id": i,
                "online": True,
                "cur_mhz": cur,
                "max_mhz": mx,
                "min_mhz": mn,
            })
        return cores

    def cpu_usage(self):
        """Return per-core CPU usage. Tries psutil, falls back to ps."""
        if _PSUTIL:
            try:
                return psutil.cpu_percent(interval=None, percpu=True)
            except Exception:
                pass
        # Fallback: aggregate from ps
        try:
            r = subprocess.run(["ps", "-eo", "pcpu"],
                              capture_output=True, timeout=3)
            if r.returncode == 0:
                total = 0.0
                for line in r.stdout.decode().splitlines()[1:]:
                    try:
                        total += float(line.strip())
                    except ValueError:
                        pass
                n = os.cpu_count() or 8
                avg = min(100.0, total / n)
                return [avg] * n
        except Exception:
            pass
        return [0] * (os.cpu_count() or 8)

    # ──────────────────────────────────────────────────────────
    # Memory
    # ──────────────────────────────────────────────────────────

    def _probe_memory(self):
        if not _PSUTIL:
            return {}
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                vm = psutil.virtual_memory()
                sm = psutil.swap_memory()
            return {
                "total_mb": vm.total // (1024 * 1024),
                "used_mb": vm.used // (1024 * 1024),
                "available_mb": vm.available // (1024 * 1024),
                "percent": int(vm.percent),
                "zram_total_mb": sm.total // (1024 * 1024),
                "zram_used_mb": sm.used // (1024 * 1024),
                "zram_percent": int(sm.percent),
            }
        except Exception:
            return {}

    # ──────────────────────────────────────────────────────────
    # Thermal zones
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _classify_zone(name: str):
        if name in BOGUS_NAMES:
            return None
        if any(name.startswith(p) for p in SOC_PREFIXES): return "soc"
        if any(name.startswith(p) for p in GPU_PREFIXES): return "gpu"
        if name in BATTERY_NAMES: return "battery"
        if any(name.startswith(p) for p in SKIN_PREFIXES): return "skin"
        if any(name.startswith(p) for p in MODEM_PREFIXES): return "modem"
        if any(name.startswith(p) for p in WIFI_PREFIXES): return "wifi"
        if name in CHARGER_NAMES: return "charger"
        if any(name.startswith(p) for p in USB_PREFIXES): return "usb"
        if any(name.startswith(p) for p in DSP_PREFIXES): return "dsp"
        if any(name.startswith(p) for p in CAMERA_PREFIXES): return "media"
        return "other"

    def _probe_temperatures(self):
        result = {"categories": {}, "raw_zones": {}}
        if not _PSUTIL:
            return result
        try:
            zones = psutil.sensors_temperatures() or {}
        except Exception:
            return result

        buckets = {}
        for zone_name, entries in zones.items():
            for entry in entries:
                t = entry.current
                if t is None or t < -20 or t > 150:
                    continue
                label = entry.label or zone_name
                result["raw_zones"][zone_name] = round(t, 1)
                cat = self._classify_zone(zone_name)
                if cat is None:
                    continue
                buckets.setdefault(cat, []).append(t)

        for cat, vals in buckets.items():
            result["categories"][cat] = round(sum(vals) / len(vals), 1)
        return result

    # ──────────────────────────────────────────────────────────
    # Battery
    # ──────────────────────────────────────────────────────────

    def _probe_battery(self):
        """Return battery info, cached for _battery_cache_ttl seconds."""
        now = time.time()
        if (self._battery_cache is not None
                and (now - self._battery_cache_ts) < self._battery_cache_ttl):
            return self._battery_cache

        result = self._probe_battery_uncached()
        if result:
            self._battery_cache = result
            self._battery_cache_ts = now
        return result

    def _probe_battery_uncached(self):
        # termux-api first (more reliable on Android)
        try:
            r = subprocess.run(["termux-battery-status"],
                              capture_output=True, timeout=3)
            if r.returncode == 0:
                d = json.loads(r.stdout.decode())
                plugged_str = str(d.get("plugged", "")).upper()
                return {
                    "percent": int(d.get("percentage", 0)),
                    "plugged": plugged_str not in ("UNPLUGGED", ""),
                    "temp_c": float(d.get("temperature", 0)),
                    "health": d.get("health", "UNKNOWN"),
                }
        except Exception:
            pass

        if _PSUTIL:
            try:
                b = psutil.sensors_battery()
                if b:
                    return {
                        "percent": int(b.percent),
                        "plugged": bool(b.power_plugged),
                        "secsleft": (b.secsleft
                                    if b.secsleft != -2 else -1),
                    }
            except Exception:
                pass
        return {}

    # ──────────────────────────────────────────────────────────
    # Network
    # ──────────────────────────────────────────────────────────

    def _probe_network(self):
        ifaces = {}
        if _PSUTIL:
            try:
                for name, addrs in psutil.net_if_addrs().items():
                    ifaces[name] = {"addrs": [a.address for a in addrs]}
            except Exception:
                pass
        return ifaces

    # ──────────────────────────────────────────────────────────
    # Snapshot
    # ──────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        cpu = self._probe_cpu()
        mem = self._probe_memory()
        therm = self._probe_temperatures()
        bat = self._probe_battery()
        net = self._probe_network()

        soc_temp = therm["categories"].get("soc", 0)
        gpu_temp = therm["categories"].get("gpu", 0)
        skin_temp = therm["categories"].get("skin", 0)
        bat_temp = therm["categories"].get("battery", 0)

        return {
            # ── Legacy keys (backward-compat) ──
            "core_count": len(cpu),
            "cores_online": sum(1 for c in cpu if c["online"]),
            "battery_pct": bat.get("percent", 0),
            "battery_temp_c": bat.get("temp_c", bat_temp),
            "plugged": "PLUGGED" if bat.get("plugged") else "UNPLUGGED",
            "thermal_zones": therm["raw_zones"],

            # ── New keys ──
            "cpu": cpu,
            "cpu_count": len(cpu),
            "cpu_usage": self.cpu_usage(),
            "memory": mem,
            "thermal_categories": therm["categories"],
            "thermal_raw": therm["raw_zones"],
            "battery": bat,
            "network": list(net.keys()),

            # Convenient top-level temps
            "soc_temp_c": soc_temp,
            "gpu_temp_c": gpu_temp,
            "skin_temp_c": skin_temp,
        }

    def emit(self):
        if not self.bus:
            return
        s = self.snapshot()
        self.bus.emit("hal.snapshot", "hal",
                     cores=s["cpu_count"],
                     battery=s["battery_pct"],
                     soc_temp=s["soc_temp_c"])


# ==============================================================
# Demo
# ==============================================================

def demo():
    h = HAL()
    s = h.snapshot()

    print("=" * 68)
    print("  HAL v3 — Hardware Snapshot")
    print("=" * 68)

    print(f"\n[CPU]  ({s['core_count']} cores)")
    for c in s["cpu"]:
        cur = f"{c['cur_mhz']:>4}" if c['cur_mhz'] else "  --"
        mx = f"{c['max_mhz']:>4}" if c['max_mhz'] else "  --"
        print(f"    cpu{c['id']}: {cur} / {mx} MHz")

    usage = s["cpu_usage"]
    print(f"\n  usage: {[int(u) for u in usage[:s['core_count']]]}%")

    m = s["memory"]
    if m:
        print(f"\n[Memory]")
        print(f"  RAM  : {m['used_mb']}/{m['total_mb']} MB ({m['percent']}%)")
        print(f"  ZRAM : {m['zram_used_mb']}/{m['zram_total_mb']} MB "
              f"({m['zram_percent']}%)")

    print(f"\n[Thermal Categories]  ({len(s['thermal_raw'])} zones total)")
    for cat in ("soc", "gpu", "battery", "skin", "modem", "wifi",
                "charger", "usb", "dsp", "media", "other"):
        if cat in s["thermal_categories"]:
            t = s["thermal_categories"][cat]
            bar = "█" * max(1, int(t / 5))
            print(f"  {cat:<10} {t:>6.1f}C  {bar}")

    print(f"\n[Battery]")
    print(f"  percent : {s['battery_pct']}%")
    print(f"  plugged : {s['plugged']}")
    print(f"  temp    : {s['battery_temp_c']}C")

    print(f"\n[Network]")
    for i in s["network"]:
        print(f"  {i}")
    print()


if __name__ == "__main__":
    demo()
