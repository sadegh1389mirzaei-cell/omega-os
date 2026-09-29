#!/usr/bin/env python3
# ==============================================================
# OMEGA OS - Web Dashboard
# ==============================================================
# HTTP server that serves:
#   /              Live dashboard (HTML)
#   /api/status    JSON status of all subsystems
#   /api/hal       Hardware metrics
#   /api/events    Recent bus events
# ==============================================================

import os
import sys
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")

PORT = 8080

# ==============================================================
# Data collectors
# ==============================================================

def safe_import(name, attr=None):
    try:
        mod = __import__(name)
        if attr:
            return getattr(mod, attr, None)
        return mod
    except Exception:
        return None


def get_hal_snapshot() -> Dict[str, Any]:
    try:
        from hal import HAL
        h = HAL()
        s = h.snapshot()
        return {
            "ok": True,
            "cores": s.get("core_count", 0),
            "cores_online": s.get("cores_online", 0),
            "battery_pct": s.get("battery_pct", 0),
            "battery_temp_c": s.get("battery_temp_c", 0),
            "plugged": s.get("plugged", "UNKNOWN"),
            "soc_temp_c": s.get("soc_temp_c", 0),
            "gpu_temp_c": s.get("gpu_temp_c", 0),
            "skin_temp_c": s.get("skin_temp_c", 0),
            "thermal_zones": len(s.get("thermal_raw", {})),
            "thermal_categories": s.get("thermal_categories", {}),
            "memory": s.get("memory", {}),
            "cpu_usage": s.get("cpu_usage", [])[:8],
            "cpu_cores_detail": s.get("cpu", []),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}


def get_security_stats() -> Dict[str, Any]:
    try:
        from security_v2 import SecurityAIv2
        sec = SecurityAIv2()
        stats = sec.stats()
        recent_events = sec.events[-10:] if hasattr(sec, "events") else []
        return {
            "ok": True,
            "stats": stats,
            "recent_events": recent_events,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}


def get_personal_stats() -> Dict[str, Any]:
    try:
        from personal_ai_v2 import PersonalAIv2
        pai = PersonalAIv2()
        s = pai.summary()
        preds = []
        for state in ("LIGHT", "WEB", "COMPUTE", "IDLE"):
            preds.append({
                "after": state,
                "predictions": pai.predict_next(state)
            })
        return {
            "ok": True,
            "summary": s,
            "predictions": preds,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}


def get_task_stats() -> Dict[str, Any]:
    try:
        from task_manager import TaskManager
        tm = TaskManager()
        tm.scan()
        stats = tm.stats()
        tasks = [
            {
                "id": t.task_id,
                "name": t.name,
                "interval_s": t.interval_s,
                "enabled": t.enabled,
                "run_count": t.run_count,
                "fail_count": t.fail_count,
                "last_run": t.last_run,
            }
            for t in tm.list_tasks()
        ]
        return {
            "ok": True,
            "stats": stats,
            "tasks": tasks,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}


def get_recent_events(n: int = 20) -> list:
    path = os.path.join(OMEGA_DIR, "bus_log.jsonl")
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            lines = f.readlines()
        out = []
        for line in lines[-n:]:
            try:
                evt = json.loads(line)
                out.append({
                    "ts": evt.get("ts", 0),
                    "topic": evt.get("topic", "?"),
                    "source": evt.get("source", "?"),
                    "severity": evt.get("severity", "INFO"),
                })
            except json.JSONDecodeError:
                continue
        return list(reversed(out))
    except OSError:
        return []


def get_quarantine_stats() -> Dict[str, Any]:
    try:
        from quarantine import QuarantineManager
        qm = QuarantineManager()
        return {
            "ok": True,
            "stats": qm.stats(),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)[:100]}


def get_full_status() -> Dict[str, Any]:
    """Aggregate status from all subsystems."""
    return {
        "ts": int(time.time() * 1000),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hal": get_hal_snapshot(),
        "security": get_security_stats(),
        "personal": get_personal_stats(),
        "tasks": get_task_stats(),
        "quarantine": get_quarantine_stats(),
        "events": get_recent_events(20),
    }


# ==============================================================
# HTTP Handler
# ==============================================================

class OmegaHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Silent by default — too noisy
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, ensure_ascii=False)
        self.send_response(status)
        self.send_header("Content-Type",
                        "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type",
                        "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/" or path == "/index.html":
            self._send_html(HTML_PAGE)

        elif path == "/api/status":
            self._send_json(get_full_status())

        elif path == "/api/hal":
            self._send_json(get_hal_snapshot())

        elif path == "/api/security":
            self._send_json(get_security_stats())

        elif path == "/api/personal":
            self._send_json(get_personal_stats())

        elif path == "/api/tasks":
            self._send_json(get_task_stats())

        elif path == "/api/events":
            self._send_json(get_recent_events(50))

        elif path == "/api/quarantine":
            self._send_json(get_quarantine_stats())

        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()

        else:
            self._send_json({"error": "not found"}, 404)


# ==============================================================
# HTML Page (built-in dashboard)
# ==============================================================

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OMEGA OS Dashboard</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'SF Mono', 'Consolas', monospace;
    background: #0a0a0a;
    color: #e0e0e0;
    padding: 16px;
    max-width: 1400px;
    margin: 0 auto;
}
h1 {
    color: #4ade80;
    font-size: 24px;
    margin-bottom: 4px;
}
.subtitle {
    color: #666;
    font-size: 12px;
    margin-bottom: 20px;
}
.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
}
.card {
    background: #141414;
    border: 1px solid #1e1e1e;
    border-radius: 8px;
    padding: 14px 16px;
}
.card-title {
    color: #888;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 10px;
}
.metric {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 0;
    font-size: 13px;
}
.metric-label { color: #888; }
.metric-value {
    color: #e0e0e0;
    font-weight: bold;
}
.metric-value.green { color: #4ade80; }
.metric-value.yellow { color: #facc15; }
.metric-value.red { color: #ef4444; }
.metric-value.cyan { color: #22d3ee; }
.bar-bg {
    background: #1a1a1a;
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
    margin-top: 4px;
}
.bar-fill {
    height: 100%;
    transition: width 0.3s;
}
.bar-green { background: #4ade80; }
.bar-yellow { background: #facc15; }
.bar-red { background: #ef4444; }
.bar-cyan { background: #22d3ee; }
.events {
    max-height: 300px;
    overflow-y: auto;
    font-size: 12px;
}
.event-row {
    padding: 4px 8px;
    border-bottom: 1px solid #1a1a1a;
    display: flex;
    gap: 10px;
}
.event-row:last-child { border-bottom: none; }
.event-time { color: #555; min-width: 70px; }
.event-topic { color: #22d3ee; flex: 1; }
.event-source { color: #888; font-size: 11px; }
.sev-HIGH { color: #facc15; }
.sev-CRITICAL { color: #ef4444; }
.sev-MEDIUM { color: #fb923c; }
.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
}
.dot-green { background: #4ade80; }
.dot-red { background: #ef4444; }
.dot-yellow { background: #facc15; }
.temp-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 4px 0;
    font-size: 12px;
}
.temp-label { min-width: 80px; color: #888; }
.temp-fill {
    flex: 1;
    height: 8px;
    background: #1a1a1a;
    border-radius: 4px;
    overflow: hidden;
    position: relative;
}
.temp-fill-inner {
    height: 100%;
    transition: width 0.3s;
}
footer {
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid #1e1e1e;
    text-align: center;
    color: #444;
    font-size: 11px;
}
</style>
</head>
<body>

<h1>OMEGA OS Dashboard</h1>
<div class="subtitle">
    <span id="status-dot" class="status-dot dot-green"></span>
    <span id="status-text">Connecting...</span>
    <span style="float:right" id="last-update">--</span>
</div>

<div class="grid">

  <div class="card">
    <div class="card-title">Hardware</div>
    <div id="hw-cpu"></div>
    <div id="hw-ram"></div>
    <div id="hw-bat"></div>
    <div id="hw-zones"></div>
  </div>

  <div class="card">
    <div class="card-title">Thermal</div>
    <div id="thermal-list"></div>
  </div>

  <div class="card">
    <div class="card-title">Security AI</div>
    <div id="security-body"></div>
  </div>

  <div class="card">
    <div class="card-title">Personal AI</div>
    <div id="personal-body"></div>
  </div>

  <div class="card">
    <div class="card-title">Scheduled Tasks</div>
    <div id="tasks-body"></div>
  </div>

  <div class="card">
    <div class="card-title">Quarantine</div>
    <div id="quarantine-body"></div>
  </div>

</div>

<div class="card">
  <div class="card-title">Recent Events</div>
  <div class="events" id="events-list"></div>
</div>

<footer>
    OMEGA OS v0.8 "Axon" &nbsp;·&nbsp; <span id="footer-time">--</span><br>
    Auto-refresh every 2 seconds
</footer>

<script>
function updateDashboard() {
    fetch('/api/status')
        .then(r => r.json())
        .then(data => {
            document.getElementById('status-dot').className = 'status-dot dot-green';
            document.getElementById('status-text').textContent = 'Connected';
            document.getElementById('last-update').textContent = data.time;
            document.getElementById('footer-time').textContent = data.time;

            renderHardware(data.hal);
            renderThermal(data.hal);
            renderSecurity(data.security);
            renderPersonal(data.personal);
            renderTasks(data.tasks);
            renderQuarantine(data.quarantine);
            renderEvents(data.events);
        })
        .catch(err => {
            document.getElementById('status-dot').className = 'status-dot dot-red';
            document.getElementById('status-text').textContent = 'Disconnected';
        });
}

function renderHardware(hal) {
    if (!hal || !hal.ok) {
        document.getElementById('hw-cpu').innerHTML = '<span class="metric-value red">HAL offline</span>';
        return;
    }
    const cpu = hal.cpu_usage || [];
    const cpuAvg = cpu.length ? (cpu.reduce((a,b)=>a+b,0)/cpu.length).toFixed(1) : 0;
    const mem = hal.memory || {};
    const ramPct = mem.percent || 0;
    const batPct = hal.battery_pct || 0;

    const cpuClass = cpuAvg > 70 ? 'red' : (cpuAvg > 40 ? 'yellow' : 'green');
    const ramClass = ramPct > 80 ? 'red' : (ramPct > 60 ? 'yellow' : 'green');
    const batClass = batPct < 20 ? 'red' : (batPct < 40 ? 'yellow' : 'green');

    document.getElementById('hw-cpu').innerHTML =
        `<div class="metric">
           <span class="metric-label">CPU (${hal.cores} cores)</span>
           <span class="metric-value ${cpuClass}">${cpuAvg}%</span>
         </div>`;

    document.getElementById('hw-ram').innerHTML =
        `<div class="metric">
           <span class="metric-label">RAM</span>
           <span class="metric-value ${ramClass}">${mem.used_mb || 0}/${mem.total_mb || 0} MB (${ramPct}%)</span>
         </div>`;

    document.getElementById('hw-bat').innerHTML =
        `<div class="metric">
           <span class="metric-label">Battery</span>
           <span class="metric-value ${batClass}">${batPct}% ${hal.plugged === 'PLUGGED' ? '(charging)' : ''}</span>
         </div>`;

    document.getElementById('hw-zones').innerHTML =
        `<div class="metric">
           <span class="metric-label">Thermal Zones</span>
           <span class="metric-value cyan">${hal.thermal_zones}</span>
         </div>`;
}

function renderThermal(hal) {
    if (!hal || !hal.ok) return;
    const cats = hal.thermal_categories || {};
    const order = ['soc', 'gpu', 'battery', 'skin', 'modem', 'wifi'];
    let html = '';
    for (const cat of order) {
        if (!(cat in cats)) continue;
        const t = cats[cat];
        const pct = Math.min(100, (t / 70) * 100);
        const color = t > 55 ? 'bar-red' : (t > 45 ? 'bar-yellow' : 'bar-green');
        html += `<div class="temp-bar">
           <span class="temp-label">${cat}</span>
           <div class="temp-fill">
             <div class="temp-fill-inner ${color}" style="width:${pct}%"></div>
           </div>
           <span class="metric-value" style="min-width:50px;text-align:right">${t.toFixed(1)}C</span>
         </div>`;
    }
    document.getElementById('thermal-list').innerHTML = html;
}

function renderSecurity(sec) {
    if (!sec || !sec.ok) {
        document.getElementById('security-body').innerHTML = '<span class="metric-value yellow">Loading...</span>';
        return;
    }
    const s = sec.stats || {};
    document.getElementById('security-body').innerHTML = `
        <div class="metric"><span class="metric-label">Processes</span>
          <span class="metric-value cyan">${s.processes_tracked || 0}</span></div>
        <div class="metric"><span class="metric-label">Events</span>
          <span class="metric-value">${s.events || 0}</span></div>
        <div class="metric"><span class="metric-label">Transitions</span>
          <span class="metric-value">${s.total_transitions || 0}</span></div>
        <div class="metric"><span class="metric-label">Quarantined</span>
          <span class="metric-value red">${s.quarantined || 0}</span></div>`;
}

function renderPersonal(p) {
    if (!p || !p.ok) {
        document.getElementById('personal-body').innerHTML = '<span class="metric-value yellow">Loading...</span>';
        return;
    }
    const s = p.summary || {};
    document.getElementById('personal-body').innerHTML = `
        <div class="metric"><span class="metric-label">Sequences</span>
          <span class="metric-value cyan">${s.sequences || 0}</span></div>
        <div class="metric"><span class="metric-label">Transitions</span>
          <span class="metric-value">${s.transitions || 0}</span></div>
        <div class="metric"><span class="metric-label">States</span>
          <span class="metric-value">${s.states || 0}</span></div>
        <div class="metric"><span class="metric-label">Contexts</span>
          <span class="metric-value">${s.buckets || 0} buckets</span></div>`;
}

function renderTasks(t) {
    if (!t || !t.ok) {
        document.getElementById('tasks-body').innerHTML = '<span class="metric-value yellow">Loading...</span>';
        return;
    }
    const s = t.stats || {};
    let html = `
        <div class="metric"><span class="metric-label">Total</span>
          <span class="metric-value cyan">${s.scheduled || 0}</span></div>
        <div class="metric"><span class="metric-label">Processes</span>
          <span class="metric-value">${s.total || 0}</span></div>
        <div class="metric"><span class="metric-label">Frozen</span>
          <span class="metric-value">${s.frozen || 0}</span></div>`;
    document.getElementById('tasks-body').innerHTML = html;
}

function renderQuarantine(q) {
    if (!q || !q.ok) {
        document.getElementById('quarantine-body').innerHTML = '<span class="metric-value yellow">Loading...</span>';
        return;
    }
    const s = q.stats || {};
    document.getElementById('quarantine-body').innerHTML = `
        <div class="metric"><span class="metric-label">Killed</span>
          <span class="metric-value red">${s.killed_total || 0}</span></div>
        <div class="metric"><span class="metric-label">Whitelisted</span>
          <span class="metric-value green">${s.whitelisted || 0}</span></div>
        <div class="metric"><span class="metric-label">Last Kill</span>
          <span class="metric-value">${s.last_kill || '—'}</span></div>`;
}

function renderEvents(events) {
    if (!events || !events.length) {
        document.getElementById('events-list').innerHTML = '<span class="metric-value">No events</span>';
        return;
    }
    let html = '';
    for (const e of events) {
        const dt = new Date(e.ts);
        const time = dt.toTimeString().slice(0,8);
        const sevClass = e.severity !== 'INFO' ? 'sev-' + e.severity : '';
        html += `<div class="event-row">
            <span class="event-time">${time}</span>
            <span class="event-topic ${sevClass}">${e.topic}</span>
            <span class="event-source">${e.source}</span>
        </div>`;
    }
    document.getElementById('events-list').innerHTML = html;
}

// Update on load and every 2 seconds
updateDashboard();
setInterval(updateDashboard, 2000);
</script>

</body>
</html>
"""


# ==============================================================
# Main
# ==============================================================

def main():
    port = PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    print()
    print("=" * 60)
    print(f"  OMEGA OS Web Dashboard")
    print("=" * 60)
    print()
    print(f"  Server running on http://localhost:{port}")
    print(f"  On your phone: http://127.0.0.1:{port}")
    print(f"  From another device (same WiFi): "
          f"http://<phone-ip>:{port}")
    print()
    print("  Press Ctrl+C to stop")
    print()

    server = HTTPServer(("0.0.0.0", port), OmegaHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Server stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
