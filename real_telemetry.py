# ==============================================================
# OMEGA OS - Real Telemetry Reader (v3 — Android-friendly)
# ==============================================================
# Android 10+ blocks /proc/stat and /proc/loadavg for non-root.
# We use `ps` and `top` instead, which work in Termux.
# ==============================================================

import os
import re
import time
import json
import subprocess
from typing import Optional, Tuple

from omega import InputVector, WorkloadClass, PowerSource

try:
    from hal import HAL
    _HAS_HAL = True
except ImportError:
    _HAS_HAL = False


# ==============================================================
# CPU readers — Android friendly
# ==============================================================

def read_cpu_via_ps() -> Optional[float]:
    """
    Sum %CPU of all processes via `ps`.
    Returns 0..ncores*100.
    """
    try:
        r = subprocess.run(
            ["ps", "-eo", "pcpu"],
            capture_output=True, timeout=3,
        )
        if r.returncode != 0:
            return None
        text = r.stdout.decode("utf-8", errors="ignore")
        total = 0.0
        for line in text.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            try:
                total += float(line)
            except ValueError:
                continue
        return total
    except Exception:
        return None


def read_cpu_via_top() -> Optional[float]:
    """
    Sum %CPU column of all processes from `top -bn1`.
    Android's top column layout: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ ARGS
    """
    try:
        r = subprocess.run(
            ["top", "-bn1"],
            capture_output=True, timeout=4,
        )
        if r.returncode != 0:
            return None
        text = r.stdout.decode("utf-8", errors="ignore")
        total = 0.0
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 10:
                continue
            # state is a single letter like S, R, D, Z, T
            # right after state → %CPU, then %MEM, then TIME+
            # find TIME+ pattern like 0:00.01
            time_idx = None
            for i, p in enumerate(parts):
                if re.match(r"^\d+:\d+(\.\d+)?$", p):
                    time_idx = i
                    break
            if time_idx is None or time_idx < 2:
                continue
            try:
                cpu_val = float(parts[time_idx - 2])
                if 0 <= cpu_val <= 400:
                    total += cpu_val
            except ValueError:
                continue
        return total
    except Exception:
        return None


def read_freq_ratio() -> Optional[float]:
    """
    Last resort: use CPU frequency ratio as a rough load proxy.
    Returns 0..100.
    """
    ratios = []
    for i in range(os.cpu_count() or 1):
        cur = read_cpu_freq(i) or 0
        mx = read_cpu_max_freq(i) or 0
        if mx > 0:
            ratios.append(cur / mx)
    if not ratios:
        return None
    avg = sum(ratios) / len(ratios)
    # Empirical mapping: 0.2 → 0%, 0.9 → 100%
    pct = max(0.0, min(100.0, (avg - 0.2) * 100 / 0.7))
    return pct


# ==============================================================
# Simple readers (may be blocked)
# ==============================================================

def read_cpu_total():
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("cpu "):
                    parts = line.split()
                    vals = [int(x) for x in parts[1:9]]
                    while len(vals) < 8:
                        vals.append(0)
                    return vals
    except (OSError, ValueError):
        pass
    return None


def read_cpu_per_core(max_cores: int = 16):
    try:
        with open("/proc/stat") as f:
            lines = f.readlines()
    except OSError:
        return None
    cores = []
    for line in lines:
        if line.startswith("cpu") and line[3:4].isdigit():
            parts = line.split()
            try:
                vals = [int(x) for x in parts[1:9]]
            except ValueError:
                continue
            while len(vals) < 8:
                vals.append(0)
            cores.append(vals)
            if len(cores) >= max_cores:
                break
    return cores if cores else None


def delta_usage(prev, curr) -> int:
    prev_idle = prev[3] + prev[4]
    curr_idle = curr[3] + curr[4]
    total_diff = sum(curr) - sum(prev)
    idle_diff = curr_idle - prev_idle
    if total_diff <= 0:
        return 0
    busy = total_diff - idle_diff
    return max(0, min(100, int(busy * 100 / total_diff)))


def read_meminfo() -> Optional[dict]:
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
    except OSError:
        return None
    info = {}
    for line in lines:
        parts = line.split(":")
        if len(parts) != 2:
            continue
        try:
            info[parts[0].strip()] = int(parts[1].strip().split()[0])
        except (ValueError, IndexError):
            continue
    return info or None


def read_cpu_freq(idx: int) -> Optional[int]:
    base = f"/sys/devices/system/cpu/cpu{idx}/cpufreq"
    for fname in ("scaling_cur_freq", "cpuinfo_cur_freq"):
        try:
            with open(os.path.join(base, fname)) as f:
                return int(f.read().strip()) // 1000
        except (OSError, ValueError):
            continue
    return None


def read_cpu_max_freq(idx: int) -> Optional[int]:
    base = f"/sys/devices/system/cpu/cpu{idx}/cpufreq"
    for fname in ("scaling_max_freq", "cpuinfo_max_freq"):
        try:
            with open(os.path.join(base, fname)) as f:
                return int(f.read().strip()) // 1000
        except (OSError, ValueError):
            continue
    return None


# ==============================================================
# Battery
# ==============================================================

def termux_api_available() -> bool:
    try:
        r = subprocess.run(["termux-battery-status"],
                           capture_output=True, timeout=2)
        return r.returncode == 0
    except Exception:
        return False


def read_battery() -> Optional[dict]:
    try:
        r = subprocess.run(["termux-battery-status"],
                           capture_output=True, timeout=3)
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout.decode("utf-8"))
        return {
            "percent": int(data.get("percentage", 100)),
            "temperature_c": float(data.get("temperature", 30.0)),
            "plugged": str(data.get("plugged", "UNPLUGGED")).upper(),
        }
    except Exception:
        return None


# ==============================================================
# RealTelemetry
# ==============================================================

class RealTelemetry:

    def __init__(self):
        self.cpu_count = os.cpu_count() or 4
        self.prev_total = None
        self.prev_per_core = None

        self.has_battery = termux_api_available()
        self._battery = None
        self._battery_at = 0.0

        self.cpu_source = "none"
        self._detect_cpu_source()
        self._sample = 0

        # HAL for real thermal + memory
        self.hal = HAL() if _HAS_HAL else None

    def _detect_cpu_source(self):
        """Try each source, pick the first that gives a non-zero reading."""
        # 1. /proc/stat total
        a = read_cpu_total()
        time.sleep(0.15)
        b = read_cpu_total()
        if a and b:
            self.cpu_source = "stat_total"
            self.prev_total = b
            return

        # 2. /proc/stat per-core
        p1 = read_cpu_per_core()
        time.sleep(0.15)
        p2 = read_cpu_per_core()
        if p1 and p2 and len(p1) == len(p2):
            self.cpu_source = "stat_percore"
            self.prev_per_core = p2
            return

        # 3. ps -eo pcpu
        v = read_cpu_via_ps()
        if v is not None:
            self.cpu_source = "ps"
            return

        # 4. top -bn1
        v = read_cpu_via_top()
        if v is not None:
            self.cpu_source = "top"
            return

        # 5. Frequency ratio
        v = read_freq_ratio()
        if v is not None:
            self.cpu_source = "freq"
            return

        self.cpu_source = "none"

    def _battery_cached(self):
        now = time.time()
        if now - self._battery_at < 5.0 and self._battery:
            return self._battery
        if self.has_battery:
            b = read_battery()
            if b:
                self._battery = b
                self._battery_at = now
        return self._battery

    def _read_cpu_pct(self) -> float:
        """Return aggregate CPU usage 0..100 (avg over cores)."""
        ncores = max(1, self.cpu_count)

        if self.cpu_source == "stat_total":
            curr = read_cpu_total()
            if curr and self.prev_total:
                total = delta_usage(self.prev_total, curr)
                self.prev_total = curr
                return total
            if curr:
                self.prev_total = curr

        elif self.cpu_source == "stat_percore":
            curr = read_cpu_per_core()
            if curr and self.prev_per_core and len(curr) == len(self.prev_per_core):
                vals = [delta_usage(p, c)
                        for p, c in zip(self.prev_per_core, curr)]
                self.prev_per_core = curr
                return sum(vals) / len(vals) if vals else 0
            if curr:
                self.prev_per_core = curr

        elif self.cpu_source == "ps":
            total = read_cpu_via_ps()
            if total is not None:
                return min(100.0, total / ncores)

        elif self.cpu_source == "top":
            total = read_cpu_via_top()
            if total is not None:
                return min(100.0, total / ncores)

        elif self.cpu_source == "freq":
            v = read_freq_ratio()
            if v is not None:
                return v

        return 0.0

    def next(self) -> InputVector:
        self._sample += 1
        iv = InputVector()
        iv.timestamp_ms = int(time.time() * 1000)
        iv.cpu_core_count = self.cpu_count

        # ── CPU average ──
        avg = self._read_cpu_pct()
        iv.cpu_util_percent = [int(avg)] * 8

        # ── CPU frequency ──
        freqs = []
        for i in range(min(8, self.cpu_count)):
            freqs.append(read_cpu_freq(i) or 0)
        while len(freqs) < 8:
            freqs.append(0)
        # Normalize per-core using its own max
        freq_pct = []
        for i, f in enumerate(freqs[:8]):
            mx = read_cpu_max_freq(i) or max(freqs) or 1
            freq_pct.append(int(f * 100 / mx) if mx else 0)
        iv.cpu_freq_percent = freq_pct

        # ── RAM ──
        mem = read_meminfo()
        if mem:
            total_kb = mem.get("MemTotal", 0)
            avail_kb = mem.get("MemAvailable", mem.get("MemFree", 0))
            swap_total = mem.get("SwapTotal", 0)
            swap_free = mem.get("SwapFree", 0)

            total_mb = total_kb // 1024
            avail_mb = avail_kb // 1024
            used_mb = total_mb - avail_mb

            iv.ram_used_mb = used_mb
            iv.ram_available_mb = avail_mb
            iv.zram_compressed_mb = (swap_total - swap_free) // 1024
            if total_mb > 0:
                iv.ram_pressure_percent = max(0, min(100,
                    int(used_mb * 100 / total_mb)))

        # ── Workload heuristic ──
        dominant = avg
        if dominant < 5:
            iv.foreground_workload = WorkloadClass.IDLE
        elif dominant < 20:
            iv.foreground_workload = WorkloadClass.LIGHT
        elif dominant < 40:
            iv.foreground_workload = WorkloadClass.WEB
        elif dominant < 60:
            iv.foreground_workload = WorkloadClass.VIDEO
        elif dominant < 80:
            iv.foreground_workload = WorkloadClass.GAMING_LIGHT
        else:
            iv.foreground_workload = WorkloadClass.GAMING_HEAVY

        # ── Battery ──
        bat = self._battery_cached()
        if bat:
            iv.battery_percent = bat["percent"]
            iv.temp_battery_c = int(bat["temperature_c"] * 10)
            if "USB" in bat["plugged"] or "AC" in bat["plugged"]:
                iv.power_source = PowerSource.USB
            elif "WIRELESS" in bat["plugged"]:
                iv.power_source = PowerSource.WIRELESS
            else:
                iv.power_source = PowerSource.BATTERY
            iv.temp_soc_c = iv.temp_battery_c + 50
        else:
            iv.battery_percent = 50
            iv.power_source = PowerSource.BATTERY
            iv.temp_soc_c = 320

        iv.temp_skin_c = 320
        iv.temp_gpu_c = 320

        # ── Real thermal zones from HAL (psutil) ──
        if self.hal:
            try:
                snap = self.hal.snapshot()
                cats = snap.get("thermal_categories", {})
                if "soc" in cats:
                    iv.temp_soc_c = int(cats["soc"] * 10)
                if "gpu" in cats:
                    iv.temp_gpu_c = int(cats["gpu"] * 10)
                if "skin" in cats:
                    iv.temp_skin_c = int(cats["skin"] * 10)
                if "battery" in cats:
                    iv.temp_battery_c = int(cats["battery"] * 10)
            except Exception:
                pass

        return iv


# ==============================================================
# Demo
# ==============================================================

if __name__ == "__main__":
    rt = RealTelemetry()
    print(f"CPU cores      : {rt.cpu_count}")
    print(f"CPU source     : {rt.cpu_source}")
    print(f"Battery API    : {'YES' if rt.has_battery else 'NO'}")
    print()

    for i in range(8):
        iv = rt.next()
        wc = WorkloadClass(iv.foreground_workload).name
        avg = sum(iv.cpu_util_percent) / 8
        print(f"[{i+1}] CPU:{avg:>5.1f}%  "
              f"RAM:{iv.ram_pressure_percent:>3}%  "
              f"BAT:{iv.battery_percent:>3}%  "
              f"Workload:{wc}")
        time.sleep(1.5)
