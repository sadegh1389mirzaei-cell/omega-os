#!/usr/bin/env python3
# ==============================================================
# OMEGA OS - Web Dashboard v2 (Auto-Discovering)
# ==============================================================
# Serves a live dashboard that:
#   - Auto-discovers widgets from all modules
#   - Auto-refreshes every 2 seconds
#   - New modules with web_widget() appear automatically
#   - No need to modify this file when adding modules
# ==============================================================

import os
import sys
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from widgets import WidgetCollector

HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
PORT = 8080


# ==============================================================
# Global collector (shared across requests)
# ==============================================================

_collector = WidgetCollector()


# ==============================================================
# HTTP Handler
# ==============================================================

class OmegaHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silent

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, ensure_ascii=False)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_html(self, html, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/" or path == "/index.html":
            self._send_html(HTML_PAGE)

        elif path == "/api/widgets":
            widgets = _collector.collect()
            self._send_json({
                "ts": int(time.time() * 1000),
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "widgets": widgets,
                "errors": _collector.errors,
                "count": len(widgets),
            })

        elif path == "/api/refresh":
            _collector.invalidate()
            widgets = _collector.collect(force=True)
            self._send_json({
                "ok": True,
                "count": len(widgets),
            })

        elif path == "/api/events":
            events = self._read_events(30)
            self._send_json(events)

        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()

        else:
            self._send_json({"error": "not found"}, 404)

    def _read_events(self, n: int):
        path = os.path.join(OMEGA_DIR, "bus_log.jsonl")
        if not os.path.exists(path):
            return []
        try:
            with open(path) as f:
                lines = f.readlines()[-n:]
            out = []
            for line in lines:
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


# ==============================================================
# HTML Page (auto-rendering, widget-type-aware)
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
    background: #0a0a0a; color: #e0e0e0;
    padding: 16px; max-width: 1400px;
    margin: 0 auto;
}
h1 { color: #4ade80; font-size: 24px; margin-bottom: 4px; }
.subtitle {
    color: #666; font-size: 12px; margin-bottom: 20px;
    display: flex; justify-content: space-between;
}
.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 12px; margin-bottom: 16px;
}
.card {
    background: #141414; border: 1px solid #1e1e1e;
    border-radius: 8px; padding: 14px 16px;
}
.card-title {
    color: #888; font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px; margin-bottom: 10px;
}
.metric {
    display: flex; justify-content: space-between;
    align-items: center; padding: 4px 0; font-size: 13px;
}
.metric-label { color: #888; }
.metric-value { color: #e0e0e0; font-weight: bold; }
.metric-value.green { color: #4ade80; }
.metric-value.yellow { color: #facc15; }
.metric-value.red { color: #ef4444; }
.metric-value.cyan { color: #22d3ee; }
.metric-value.orange { color: #fb923c; }

.list-item {
    padding: 6px 0;
    border-bottom: 1px solid #1a1a1a;
    display: flex; justify-content: space-between;
    align-items: center; gap: 8px;
    font-size: 12px;
}
.list-item:last-child { border-bottom: none; }
.list-primary { color: #e0e0e0; flex: 1; }
.list-secondary { color: #666; font-size: 11px; }
.list-badge {
    padding: 2px 6px; border-radius: 3px;
    font-size: 10px; font-weight: bold;
}
.badge-DANGER { background: #7f1d1d; color: #fca5a5; }
.badge-WARN { background: #78350f; color: #fcd34d; }
.badge-TRUSTED { background: #14532d; color: #86efac; }
.badge-NEUTRAL { background: #1e293b; color: #94a3b8; }

.status-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; margin-right: 6px;
}
.dot-green { background: #4ade80; }
.dot-red { background: #ef4444; }
.dot-yellow { background: #facc15; }

.events {
    max-height: 300px; overflow-y: auto; font-size: 12px;
}
.event-row {
    padding: 4px 8px; border-bottom: 1px solid #1a1a1a;
    display: flex; gap: 10px;
}
.event-row:last-child { border-bottom: none; }
.event-time { color: #555; min-width: 70px; }
.event-topic { color: #22d3ee; flex: 1; }
.event-source { color: #888; font-size: 11px; }
.sev-HIGH { color: #facc15; }
.sev-CRITICAL { color: #ef4444; }
.sev-MEDIUM { color: #fb923c; }

.error-box {
    background: #7f1d1d; color: #fca5a5;
    padding: 8px 12px; border-radius: 6px;
    margin-bottom: 12px; font-size: 12px;
}
footer {
    margin-top: 24px; padding-top: 16px;
    border-top: 1px solid #1e1e1e;
    text-align: center; color: #444; font-size: 11px;
}
</style>
</head>
<body>

<h1>OMEGA OS Dashboard</h1>
<div class="subtitle">
    <span>
        <span id="status-dot" class="status-dot dot-green"></span>
        <span id="status-text">Connected</span>
        <span id="widget-count" style="color:#666;margin-left:12px"></span>
    </span>
    <span id="last-update">--</span>
</div>

<div id="errors"></div>

<div class="grid" id="widgets"></div>

<div class="card">
  <div class="card-title">Recent Events</div>
  <div class="events" id="events-list"></div>
</div>

<footer>
    OMEGA OS v0.8 "Axon" &nbsp;·&nbsp; <span id="footer-time">--</span><br>
    Auto-refresh every 2 seconds &nbsp;·&nbsp; Auto-discovering widgets
</footer>

<script>
// ------------------------------------------------------------
// Widget rendering (type-aware)
// ------------------------------------------------------------

function renderMetricRow(row) {
    const color = row.color ? ' ' + row.color : '';
    return `<div class="metric">
        <span class="metric-label">${row.label}</span>
        <span class="metric-value${color}">${row.value}</span>
    </div>`;
}

function renderMetricsWidget(w) {
    const rows = (w.data.rows || []).map(renderMetricRow).join('');
    return `<div class="card">
        <div class="card-title">${w.title}</div>
        ${rows}
    </div>`;
}

function renderListWidget(w) {
    const items = (w.data.items || []).map(item => {
        const badge = item.badge
            ? `<span class="list-badge badge-${item.badge}">${item.badge}</span>`
            : '';
        const secondary = item.secondary
            ? `<span class="list-secondary">${item.secondary}</span>`
            : '';
        return `<div class="list-item">
            <span class="list-primary">${item.primary}</span>
            ${secondary}
            ${badge}
        </div>`;
    }).join('');
    return `<div class="card">
        <div class="card-title">${w.title}</div>
        ${items}
    </div>`;
}

function renderBadgeWidget(w) {
    return `<div class="card">
        <div class="card-title">${w.title}</div>
        <div class="metric">
            <span class="metric-value">${w.data.value || w.data.status}</span>
        </div>
    </div>`;
}

function renderTextWidget(w) {
    return `<div class="card">
        <div class="card-title">${w.title}</div>
        <div style="font-size:12px;color:#aaa">${w.data.text}</div>
    </div>`;
}

function renderWidget(w) {
    switch (w.type) {
        case 'metrics': return renderMetricsWidget(w);
        case 'list':    return renderListWidget(w);
        case 'badge':   return renderBadgeWidget(w);
        case 'text':    return renderTextWidget(w);
        default:        return '';
    }
}

// ------------------------------------------------------------
// Main update loop
// ------------------------------------------------------------

function updateDashboard() {
    fetch('/api/widgets')
        .then(r => r.json())
        .then(data => {
            document.getElementById('status-dot').className = 'status-dot dot-green';
            document.getElementById('status-text').textContent = 'Connected';
            document.getElementById('last-update').textContent = data.time;
            document.getElementById('footer-time').textContent = data.time;
            document.getElementById('widget-count').textContent =
                `(${data.count} widgets)`;

            // Render errors if any
            const errBox = document.getElementById('errors');
            if (data.errors && data.errors.length > 0) {
                errBox.innerHTML = `<div class="error-box">
                    <b>${data.errors.length} widget error(s):</b><br>
                    ${data.errors.map(e => '- ' + e).join('<br>')}
                </div>`;
            } else {
                errBox.innerHTML = '';
            }

            // Render all widgets
            const container = document.getElementById('widgets');
            container.innerHTML = (data.widgets || [])
                .map(renderWidget)
                .join('');
        })
        .catch(err => {
            document.getElementById('status-dot').className = 'status-dot dot-red';
            document.getElementById('status-text').textContent = 'Disconnected';
        });
}

function updateEvents() {
    fetch('/api/events')
        .then(r => r.json())
        .then(events => {
            const container = document.getElementById('events-list');
            if (!events || events.length === 0) {
                container.innerHTML = '<span style="color:#666">No events</span>';
                return;
            }
            container.innerHTML = events.map(e => {
                const dt = new Date(e.ts);
                const time = dt.toTimeString().slice(0, 8);
                const sevClass = e.severity !== 'INFO' ? ' sev-' + e.severity : '';
                return `<div class="event-row">
                    <span class="event-time">${time}</span>
                    <span class="event-topic${sevClass}">${e.topic}</span>
                    <span class="event-source">${e.source}</span>
                </div>`;
            }).join('');
        })
        .catch(() => {});
}

// Initial + interval
updateDashboard();
updateEvents();
setInterval(updateDashboard, 2000);
setInterval(updateEvents, 5000);
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
    print("  OMEGA OS Web Dashboard v2 (Auto-Discovering)")
    print("=" * 60)
    print()

    # Initial widget scan
    widgets = _collector.collect(force=True)
    print(f"  Discovered widgets: {len(widgets)}")
    for w in widgets:
        print(f"    [{w.get('priority', 50):>3}] "
              f"{w.get('id', '?'):<15} "
              f"{w.get('title', '?'):<25} "
              f"({w.get('type', '?')})")

    if _collector.errors:
        print()
        print(f"  Widget errors: {len(_collector.errors)}")
        for e in _collector.errors:
            print(f"    - {e}")

    print()
    print(f"  Server: http://localhost:{port}")
    print(f"  Ctrl+C to stop")
    print()

    server = HTTPServer(("0.0.0.0", port), OmegaHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Server stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
