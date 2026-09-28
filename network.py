# ==============================================================
# OMEGA OS - Network Monitor (v2 — multiple fallbacks)
# ==============================================================
# Section 4.8 of the OMEGA spec.
#
# Tries multiple sources:
#   1. /proc/net/dev           (Linux standard, often blocked)
#   2. `ip -s link`            (works if iproute2 installed)
#   3. termux-wifi-connectioninfo (needs Termux:API + permission)
# ==============================================================

import json
import os
import re
import time
import subprocess


def _run(cmd, timeout=3):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout.decode("utf-8", errors="ignore")
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return None


class NetworkMonitor:
    def __init__(self, bus=None):
        self.bus = bus
        self.prev = {}
        self.last_read = 0
        self.source = self._detect_source()

    def _detect_source(self):
        if os.path.exists("/proc/net/dev"):
            try:
                with open("/proc/net/dev") as f:
                    if len(f.readlines()) >= 2:
                        return "proc"
            except OSError:
                pass
        out = _run(["ip", "-s", "link"])
        if out:
            return "ip"
        out = _run(["ifconfig"])
        if out:
            return "ifconfig"
        return "termux"

    # ── /proc/net/dev parser ──
    def _read_proc(self):
        ifaces = {}
        try:
            with open("/proc/net/dev") as f:
                lines = f.readlines()[2:]
            for line in lines:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                name = parts[0].strip()
                vals = parts[1].split()
                if len(vals) < 16:
                    continue
                ifaces[name] = {
                    "rx_bytes": int(vals[0]),
                    "tx_bytes": int(vals[8]),
                }
        except (OSError, PermissionError, ValueError):
            pass
        return ifaces

    # ── ip -s link parser ──
    def _read_ip(self):
        out = _run(["ip", "-s", "link"])
        if not out:
            return {}
        ifaces = {}
        current = None
        for line in out.splitlines():
            # Header line: "2: wlan0: <BROADCAST,...>"
            m = re.match(r"^\d+:\s+([^:@]+)[:@]", line)
            if m:
                current = m.group(1).strip()
                ifaces[current] = {"rx_bytes": 0, "tx_bytes": 0}
                continue
            # Stats line: "    RX: bytes  packets ..."
            if current:
                m = re.match(r"^\s+RX:\s+bytes\s+(\d+)", line)
                if m:
                    ifaces[current]["rx_bytes"] = int(m.group(1))
                    continue
                m = re.match(r"^\s+TX:\s+bytes\s+(\d+)", line)
                if m:
                    ifaces[current]["tx_bytes"] = int(m.group(1))
        return ifaces

    # ── ifconfig parser ──
    def _read_ifconfig(self):
        out = _run(["ifconfig"])
        if not out:
            return {}
        ifaces = {}
        current = None
        for line in out.splitlines():
            m = re.match(r"^([a-zA-Z0-9_.:-]+):\s", line)
            if m:
                current = m.group(1)
                ifaces[current] = {"rx_bytes": 0, "tx_bytes": 0}
                continue
            if current:
                m = re.search(r"RX bytes[:=]?\s*(\d+)", line)
                if m:
                    ifaces[current]["rx_bytes"] = int(m.group(1))
                m = re.search(r"TX bytes[:=]?\s*(\d+)", line)
                if m:
                    ifaces[current]["tx_bytes"] = int(m.group(1))
        return ifaces

    def read_interfaces(self):
        if self.source == "proc":
            r = self._read_proc()
            if r:
                return r
            self.source = "ip"
            return self._read_ip()
        if self.source == "ip":
            r = self._read_ip()
            if r:
                return r
            self.source = "ifconfig"
            return self._read_ifconfig()
        if self.source == "ifconfig":
            return self._read_ifconfig()
        return {}

    # ── Wi-Fi via termux-api ──
    def read_wifi(self):
        out = _run(["termux-wifi-connectioninfo"])
        if out:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                pass
        return {}

    def sample(self):
        now = time.time()
        cur = self.read_interfaces()
        rates = {}
        dt = now - self.last_read if self.last_read else 0
        if dt > 0:
            for name, data in cur.items():
                old = self.prev.get(name)
                if old:
                    rx = (data["rx_bytes"] - old["rx_bytes"]) / dt
                    tx = (data["tx_bytes"] - old["tx_bytes"]) / dt
                    if rx >= 0 and tx >= 0:
                        rates[name] = {
                            "rx_bps": int(rx),
                            "tx_bps": int(tx),
                        }
        self.prev = cur
        self.last_read = now

        wifi = self.read_wifi()
        ssid = wifi.get("ssid", "")
        if ssid in ("<unknown ssid>", ""):
            ssid = ""

        return {
            "source": self.source,
            "interfaces": list(cur.keys()),
            "rates": rates,
            "wifi_ssid": ssid,
            "wifi_rssi": wifi.get("rssi", 0),
            "wifi_link_speed": wifi.get("link_speed_mbps", 0),
            "wifi_ip": wifi.get("ip", ""),
        }


def fmt_bps(n: int) -> str:
    if n < 1024:
        return f"{n} B/s"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB/s"
    return f"{n / (1024 * 1024):.1f} MB/s"


if __name__ == "__main__":
    n = NetworkMonitor()
    print("=" * 60)
    print("  Network Monitor  (v2)")
    print("=" * 60)
    print(f"  Source      : {n.source}")
    print()
    print("Sampling 2 seconds apart...")
    n.sample()
    time.sleep(2)
    s = n.sample()

    print(f"  Interfaces  : {s['interfaces'] or '(none)'}")
    print(f"  Wi-Fi SSID  : {s['wifi_ssid'] or '(unavailable)'}")
    print(f"  Wi-Fi RSSI  : {s['wifi_rssi']} dBm")
    print(f"  Wi-Fi IP    : {s['wifi_ip'] or '(n/a)'}")
    print()
    if s["rates"]:
        print("  Rates (2s avg):")
        for iface, r in sorted(s["rates"].items()):
            print(f"    {iface:<12} "
                  f"rx={fmt_bps(r['rx_bps']):>12}  "
                  f"tx={fmt_bps(r['tx_bps']):>12}")
    else:
        print("  (no rate data — all sources blocked)")
        print()
        print("  Try: pkg install iproute2")
        print("  or grant Location permission to Termux:API")
