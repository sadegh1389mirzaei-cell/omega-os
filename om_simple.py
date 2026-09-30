#!/usr/bin/env python3
# ==============================================================
# OMEGA OS - Simple Web Dashboard
# ==============================================================
# Minimal single-file dashboard. No dependencies on widgets.
# Just reads the data and serves one HTML page.
# ==============================================================

import os
import sys
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PORT = 8080


def get_data():
    """Collect data from all subsystems. Safe — catches all errors."""
    data = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    # HAL
    try:
        from hal import HAL
        s = HAL().snapshot()
        cpu = s.get("cpu_usage", [])
        cpu_avg = sum(cpu) / len(cpu) if cpu else 0
        mem = s.get("memory", {})
        data["cpu"] = round(cpu_avg, 1)
        data["ram_used"] = mem.get("used_mb", 0)
        data["ram_total"] = mem.get("total_mb", 0)
        data["ram_pct"] = mem.get("percent", 0)
        data["battery"] = s.get("battery_pct", 0)
        data["plugged"] = "PLUGGED" in s.get("plugged", "")
        data["soc"] = round(s.get("soc_temp_c", 0), 1)
        data["gpu_temp"] = round(s.get("gpu_temp_c", 0), 1)
        data["skin"] = round(s.get("skin_temp_c", 0), 1)
        data["zones"] = len(s.get("thermal_raw", {}))
        data["cores"] = s.get("core_count", 0)
    except Exception as e:
        data["hal_error"] = str(e)[:80]

    # Security
    try:
        from security_v2 import SecurityAIv2
        sec = SecurityAIv2()
        st = sec.stats()
        data["processes"] = st.get("processes_tracked", 0)
        data["events"] = st.get("events", 0)
        data["file_anomalies"] = st.get("file_anomalies", 0)
        data["quarantined"] = st.get("quarantined", 0)
    except Exception as e:
        data["sec_error"] = str(e)[:80]

    # File Trust
    try:
        from file_trust import FileTrustStore
        ts = FileTrustStore()
        stats = ts.stats()
        data["trusted_files"] = stats.get("total_files", 0)
        by = stats.get("by_status", {})
        data["danger_files"] = by.get("DANGER", 0)
        data["warn_files"] = by.get("WARN", 0)
    except Exception as e:
        data["ft_error"] = str(e)[:80]

    # Tasks
    try:
        from task_manager import TaskManager
        tm = TaskManager()
        tm.scan()
        data["tasks_scheduled"] = len(tm.scheduled)
        data["procs"] = len(tm.processes)
    except Exception as e:
        data["tm_error"] = str(e)[:80]

    return data


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OMEGA OS</title>
<style>
body {
    font-family: monospace;
    background: #0a0a0a;
    color: #e0e0e0;
    padding: 20px;
    max-width: 700px;
    margin: 0 auto;
}
h1 { color: #4ade80; font-size: 22px; margin-bottom: 4px; }
.time { color: #666; font-size: 12px; margin-bottom: 20px; }
.row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #1a1a1a;
    font-size: 14px;
}
.label { color: #888; }
.value { color: #e0e0e0; font-weight: bold; }
.green { color: #4ade80; }
.yellow { color: #facc15; }
.red { color: #ef4444; }
.cyan { color: #22d3ee; }
.section {
    margin-top: 20px;
    padding: 12px;
    background: #141414;
    border-radius: 8px;
    border: 1px solid #1e1e1e;
}
.section-title {
    color: #4ade80;
    font-size: 13px;
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.err { color: #ef4444; font-size: 11px; margin-top: 4px; }
</style>
</head>
<body>
<h1>OMEGA OS</h1>
<div class="time">Updated: <span id="t">--</span> &nbsp; <span id="status">Connecting...</span></div>

<div class="section">
  <div class="section-title">Hardware</div>
  <div class="row"><span class="label">CPU</span><span class="value" id="cpu">--</span></div>
  <div class="row"><span class="label">RAM</span><span class="value" id="ram">--</span></div>
  <div class="row"><span class="label">Battery</span><span class="value" id="bat">--</span></div>
  <div class="row"><span class="label">SoC Temp</span><span class="value" id="soc">--</span></div>
  <div class="row"><span class="label">GPU Temp</span><span class="value" id="gpu">--</span></div>
  <div class="row"><span class="label">Skin</span><span class="value" id="skin">--</span></div>
  <div class="row"><span class="label">Thermal Zones</span><span class="value cyan" id="zones">--</span></div>
</div>

<div class="section">
  <div class="section-title">Security</div>
  <div class="row"><span class="label">Processes</span><span class="value cyan" id="procs">--</span></div>
  <div class="row"><span class="label">Events</span><span class="value" id="events">--</span></div>
  <div class="row"><span class="label">File Anomalies</span><span class="value" id="anom">--</span></div>
  <div class="row"><span class="label">Quarantined</span><span class="value" id="q">--</span></div>
</div>

<div class="section">
  <div class="section-title">Files</div>
  <div class="row"><span class="label">Tracked</span><span class="value cyan" id="tracked">--</span></div>
  <div class="row"><span class="label">Trusted</span><span class="value green" id="trusted">--</span></div>
  <div class="row"><span class="label">WARN</span><span class="value yellow" id="warn">--</span></div>
  <div class="row"><span class="label">DANGER</span><span class="value red" id="danger">--</span></div>
</div>

<div class="section">
  <div class="section-title">Tasks</div>
  <div class="row"><span class="label">Scheduled</span><span class="value cyan" id="sched">--</span></div>
  <div class="row"><span class="label">Processes</span><span class="value" id="tprocs">--</span></div>
</div>

<div id="errors"></div>

<script>
function setVal(id, val, cls) {
    const el = document.getElementById(id);
    el.textContent = val;
    el.className = 'value' + (cls ? ' ' + cls : '');
}

function colorFor(val, green, yellow) {
    if (val > yellow) return 'red';
    if (val > green) return 'yellow';
    return 'green';
}

function update() {
    fetch('/api/data')
        .then(r => r.json())
        .then(d => {
            document.getElementById('status').textContent = '● Connected';
            document.getElementById('status').style.color = '#4ade80';
            document.getElementById('t').textContent = d.time;

            setVal('cpu', d.cpu + '%', colorFor(d.cpu, 40, 70));
            setVal('ram', d.ram_used + '/' + d.ram_total + ' MB (' + d.ram_pct + '%)', colorFor(d.ram_pct, 65, 85));
            setVal('bat', d.battery + '%' + (d.plugged ? ' ⚡' : ''), d.battery < 20 ? 'red' : (d.battery < 40 ? 'yellow' : 'green'));
            setVal('soc', d.soc + 'C', d.soc > 50 ? 'red' : (d.soc > 45 ? 'yellow' : 'green'));
            setVal('gpu', d.gpu_temp + 'C', d.gpu_temp > 50 ? 'red' : (d.gpu_temp > 45 ? 'yellow' : 'green'));
            setVal('skin', d.skin + 'C', 'green');
            setVal('zones', d.zones, 'cyan');

            setVal('procs', d.processes, 'cyan');
            setVal('events', d.events, '');
            setVal('anom', d.file_anomalies, d.file_anomalies > 0 ? 'yellow' : 'green');
            setVal('q', d.quarantined, d.quarantined > 0 ? 'red' : '');

            setVal('tracked', d.trusted_files, 'cyan');
            setVal('trusted', d.trusted_files - d.warn_files - d.danger_files, 'green');
            setVal('warn', d.warn_files, d.warn_files > 0 ? 'yellow' : '');
            setVal('danger', d.danger_files, d.danger_files > 0 ? 'red' : 'green');

            setVal('sched', d.tasks_scheduled, 'cyan');
            setVal('tprocs', d.procs, '');

            // Errors
            const errs = [];
            for (const k in d) {
                if (k.endsWith('_error')) errs.push(k + ': ' + d[k]);
            }
            const eb = document.getElementById('errors');
            if (errs.length > 0) {
                eb.innerHTML = '<div class="err">' + errs.join('<br>') + '</div>';
            } else {
                eb.innerHTML = '';
            }
        })
        .catch(e => {
            document.getElementById('status').textContent = '● Disconnected';
            document.getElementById('status').style.color = '#ef4444';
        });
}

update();
setInterval(update, 2000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(HTML.encode("utf-8"))
        elif self.path == "/api/data":
            data = get_data()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
        elif self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def main():
    port = PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    print()
    print("=" * 50)
    print("  OMEGA OS Simple Dashboard")
    print("=" * 50)
    print(f"  http://localhost:{port}")
    print("  Ctrl+C to stop")
    print()

    # Quick test
    print("  Testing data collection...")
    d = get_data()
    print(f"    CPU: {d.get('cpu', '?')}%  "
          f"Battery: {d.get('battery', '?')}%  "
          f"SoC: {d.get('soc', '?')}C")
    print()
    print("  Ready.")
    print()

    server = HTTPServer(("0.0.0.0", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
