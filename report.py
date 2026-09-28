# ==============================================================
# OMEGA OS - HTML Report Generator  (v0.4)
# ==============================================================

import os
import sys
import json
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HISTORY = os.path.join(SCRIPT_DIR, "history.json")
DEFAULT_OUTPUT  = os.path.join(SCRIPT_DIR, "report.html")

STATE_NAMES   = ["IDLE", "BALANCED", "PERFORMANCE", "CREATIVE", "COMPUTE"]
TIER_NAMES    = ["NORMAL", "LOW_POWER", "EMERGENCY"]
THERMAL_NAMES = ["NORMAL", "WARNING", "THROTTLE", "EMERGENCY"]
MODE_NAMES    = ["PHONE", "TABLET", "DESKTOP", "DOCKED"]
PREWARM_NAMES = ["NONE", "LOADING", "WAKING", "BOOSTING", "IMMINENT", "ABORTED"]

STATE_FILL   = {"IDLE":"#888","BALANCED":"#22d3ee","PERFORMANCE":"#4ade80",
                "CREATIVE":"#e879f9","COMPUTE":"#facc15"}
TIER_FILL    = {"NORMAL":"#4ade80","LOW_POWER":"#facc15","EMERGENCY":"#ef4444"}
THERMAL_FILL = {"NORMAL":"#4ade80","WARNING":"#facc15",
                "THROTTLE":"#fb923c","EMERGENCY":"#ef4444"}
MODE_FILL    = {"PHONE":"#888","TABLET":"#22d3ee","DESKTOP":"#4ade80","DOCKED":"#e879f9"}
PREWARM_FILL = {"NONE":"#333","LOADING":"#22d3ee","WAKING":"#3b82f6",
                "BOOSTING":"#facc15","IMMINENT":"#4ade80","ABORTED":"#ef4444"}


def load_history(path):
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    history = data.get("history", [])
    if not history:
        print(f"[!] No decisions in {path}")
        sys.exit(1)
    return history


def count_by(history, key, order):
    counts = {name: 0 for name in order}
    for h in history:
        v = h.get(key, "?")
        counts[v] = counts.get(v, 0) + 1
    return counts


def svg_bar_chart(counts, order, fill_map):
    total = sum(counts.values()) or 1
    bar_w, gap = 44, 14
    chart_w = len(order) * (bar_w + gap)
    chart_h, bar_h_max, top_pad = 160, 110, 40

    parts = [f'<svg width="{chart_w}" height="{chart_h + top_pad}" '
             f'xmlns="http://www.w3.org/2000/svg">']
    for i, label in enumerate(order):
        x = i * (bar_w + gap)
        count = counts.get(label, 0)
        h = int((count / total) * bar_h_max) if count else 2
        y = top_pad + (bar_h_max - h)
        fill = fill_map.get(label, "#3b82f6")
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" '
                     f'fill="{fill}" rx="4" opacity="0.9"/>')
        parts.append(f'<text x="{x + bar_w // 2}" y="{top_pad + bar_h_max + 18}" '
                     f'fill="#aaa" font-family="monospace" font-size="10" '
                     f'text-anchor="middle">{label}</text>')
        if count:
            parts.append(f'<text x="{x + bar_w // 2}" y="{y - 6}" '
                         f'fill="#fff" font-family="monospace" font-size="11" '
                         f'text-anchor="middle">{count}</text>')
    parts.append('</svg>')
    return "".join(parts)


def svg_line_chart(values, color="#4ade80", w=500, h=100):
    if not values:
        return ""
    max_v = max(values) or 1
    step = w / max(1, len(values) - 1)
    pts = []
    for i, v in enumerate(values):
        x = i * step
        y = h - (v / max_v) * (h - 10)
        pts.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(pts)
    return (f'<svg width="{w}" height="{h}" xmlns="http://www.w3.org/2000/svg">'
            f'<polyline points="{polyline}" fill="none" '
            f'stroke="{color}" stroke-width="2"/></svg>')


def generate_html_report(history_path=DEFAULT_HISTORY,
                          output_path=DEFAULT_OUTPUT):
    history = load_history(history_path)

    state_counts   = count_by(history, "state", STATE_NAMES)
    tier_counts    = count_by(history, "tier", TIER_NAMES)
    thermal_counts = count_by(history, "thermal", THERMAL_NAMES)
    mode_counts    = count_by(history, "mode", MODE_NAMES)
    prewarm_counts = count_by(history, "prewarm", PREWARM_NAMES)

    zram_series = [h.get("zram_mb", 0) for h in history]
    max_zram = max(zram_series) if zram_series else 0
    total_frozen = sum(h.get("frozen", 0) for h in history)
    total_thawed = sum(h.get("thawed", 0) for h in history)

    css = """
    * { box-sizing: border-box; }
    body { font-family: -apple-system, 'Segoe UI', monospace;
        background: #0f0f0f; color: #e0e0e0;
        padding: 24px; max-width: 1100px; margin: 0 auto; }
    h1 { color: #4ade80; margin-bottom: 4px; }
    h2 { color: #888; border-bottom: 1px solid #333;
         padding-bottom: 6px; margin-top: 32px; font-size: 16px; }
    .meta { color: #555; font-size: 12px; margin-bottom: 24px; }
    .stats { display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }
    .stat { background: #1a1a1a; padding: 14px 22px;
            border-radius: 8px; border: 1px solid #2a2a2a; min-width: 120px; }
    .stat-val { font-size: 22px; color: #4ade80; font-weight: bold; }
    .stat-lbl { font-size: 11px; color: #888; margin-top: 2px; }
    table { border-collapse: collapse; width: 100%;
            font-size: 12px; margin-top: 10px; }
    th, td { padding: 6px 10px; text-align: left;
             border-bottom: 1px solid #1e1e1e; }
    th { background: #1a1a1a; color: #888; font-weight: normal;
         position: sticky; top: 0; }
    tr:hover { background: #151515; }
    .IDLE,.NONE { color: #888; }
    .BALANCED { color: #22d3ee; }
    .PERFORMANCE { color: #4ade80; }
    .CREATIVE { color: #e879f9; }
    .COMPUTE { color: #facc15; }
    .NORMAL { color: #ddd; }
    .LOW_POWER { color: #facc15; }
    .EMERGENCY { color: #ef4444; font-weight: bold; }
    .WARNING { color: #facc15; }
    .THROTTLE { color: #fb923c; }
    .LOADING, .WAKING { color: #22d3ee; }
    .BOOSTING { color: #facc15; }
    .IMMINENT { color: #4ade80; font-weight: bold; }
    .ABORTED { color: #ef4444; }
    .mem-note { color: #22d3ee; font-size: 11px; }
    """

    rows = []
    for h in history:
        s = h.get("state", "?")
        m = h.get("mode", "?")
        t = h.get("tier", "?")
        th = h.get("thermal", "?")
        pw = h.get("prewarm", "NONE")
        fr = h.get("frozen", 0)
        tw = h.get("thawed", 0)
        zr = h.get("zram_mb", 0)
        note = h.get("memory_note", "")

        frozen_cell = f'<span style="color:#22d3ee">+{fr}</span>' if fr else "0"
        thawed_cell = f'<span style="color:#4ade80">-{tw}</span>' if tw else "0"

        rows.append(
            f'<tr>'
            f'<td style="color:#555">{h.get("ts","")}</td>'
            f'<td class="{s}">{s}</td>'
            f'<td>{m}</td>'
            f'<td class="{t}">{t}</td>'
            f'<td class="{th}">{th}</td>'
            f'<td class="{pw}">{pw}</td>'
            f'<td>{frozen_cell}/{thawed_cell}</td>'
            f'<td style="color:#888">{zr} MB</td>'
            f'<td class="mem-note">{note}</td>'
            f'</tr>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>OMEGA Decision Engine Report</title>
<style>{css}</style></head><body>
<h1>OMEGA Decision Engine</h1>
<div class="meta">Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
 &nbsp;|&nbsp; Source: {os.path.basename(history_path)}
 &nbsp;|&nbsp; {len(history)} decisions</div>

<div class="stats">
  <div class="stat"><div class="stat-val">{len(history)}</div>
    <div class="stat-lbl">Total Decisions</div></div>
  <div class="stat"><div class="stat-val">{total_frozen}</div>
    <div class="stat-lbl">Freeze Events</div></div>
  <div class="stat"><div class="stat-val">{total_thawed}</div>
    <div class="stat-lbl">Thaw Events</div></div>
  <div class="stat"><div class="stat-val">{max_zram} MB</div>
    <div class="stat-lbl">Peak ZRAM</div></div>
</div>

<h2>Performance State Distribution</h2>
{svg_bar_chart(state_counts, STATE_NAMES, STATE_FILL)}

<h2>Power Tier Distribution</h2>
{svg_bar_chart(tier_counts, TIER_NAMES, TIER_FILL)}

<h2>Thermal State Distribution</h2>
{svg_bar_chart(thermal_counts, THERMAL_NAMES, THERMAL_FILL)}

<h2>Device Mode Distribution</h2>
{svg_bar_chart(mode_counts, MODE_NAMES, MODE_FILL)}

<h2>Pre-warm Stage Distribution</h2>
{svg_bar_chart(prewarm_counts, PREWARM_NAMES, PREWARM_FILL)}

<h2>ZRAM Usage Over Time</h2>
{svg_line_chart(zram_series, color="#22d3ee")}

<h2>All Decisions</h2>
<table>
<thead><tr><th>Timestamp</th><th>State</th><th>Mode</th>
<th>Tier</th><th>Thermal</th><th>Prewarm</th>
<th>F/T</th><th>ZRAM</th><th>Memory</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Report: {output_path}")


if __name__ == "__main__":
    hist = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HISTORY
    out  = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT
    generate_html_report(hist, out)
