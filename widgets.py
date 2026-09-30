# ==============================================================
# OMEGA OS - Widget Registry
# ==============================================================
# Self-discovering dashboard widgets.
#
# Each module can define a web_widget() function that returns:
#   {
#       "id": "unique_id",
#       "title": "Card Title",
#       "priority": 10,        # lower = shown first
#       "type": "metrics",     # metrics | list | text | badge
#       "data": {...}          # depends on type
#   }
#
# The web server scans all modules and collects widgets.
# New modules with web_widget() automatically appear.
# ==============================================================

import os
import sys
import time
import importlib
from typing import Dict, List, Any, Optional


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")


# ==============================================================
# Widget discovery
# ==============================================================

# Modules to scan (order doesn't matter, priority field does)
SCAN_MODULES = [
    "widgets",       # self
    "hal",
    "security_v2",
    "personal_ai_v2",
    "task_manager",
    "file_trust",
    "file_monitor",
    "quarantine",
    "modes",
    "omfs",
]


class WidgetCollector:
    """Scans modules and collects widgets."""

    def __init__(self, modules: List[str] = None):
        self.modules = modules or SCAN_MODULES
        self.last_scan = 0
        self.cache: Dict[str, dict] = {}
        self.cache_ttl = 5.0  # seconds
        self.errors: List[str] = []

    def collect(self, force: bool = False) -> List[dict]:
        """Collect all widgets. Cached for cache_ttl seconds."""
        now = time.time()
        if not force and (now - self.last_scan) < self.cache_ttl:
            return list(self.cache.values())

        self.errors = []
        widgets = {}

        for mod_name in self.modules:
            try:
                mod = importlib.import_module(mod_name)
            except ImportError as e:
                continue
            except Exception as e:
                self.errors.append(f"{mod_name}: import {e}")
                continue

            # Check for web_widget
            if not hasattr(mod, "web_widget"):
                continue

            try:
                widget = mod.web_widget()
                if widget and isinstance(widget, dict):
                    wid = widget.get("id", mod_name)
                    widget["id"] = wid
                    widget["_module"] = mod_name
                    widgets[wid] = widget
            except Exception as e:
                self.errors.append(f"{mod_name}: {type(e).__name__}: {e}")

        self.cache = widgets
        self.last_scan = now

        # Sort by priority (lower first)
        return sorted(widgets.values(),
                     key=lambda w: w.get("priority", 50))

    def invalidate(self):
        """Force refresh on next collect."""
        self.last_scan = 0


# ==============================================================
# Helper functions for widget authors
# ==============================================================

def metric_row(label: str, value: Any,
               color: str = "") -> dict:
    """Create a metric row."""
    return {"label": label, "value": str(value), "color": color}


def metrics_widget(widget_id: str, title: str,
                   rows: List[dict],
                   priority: int = 50) -> dict:
    """Standard widget with metric rows."""
    return {
        "id": widget_id,
        "title": title,
        "priority": priority,
        "type": "metrics",
        "data": {"rows": rows},
    }


def list_widget(widget_id: str, title: str,
                items: List[dict],
                priority: int = 50,
                max_items: int = 10) -> dict:
    """
    Widget with a list of items.
    Each item: {"primary": "...", "secondary": "...", "badge": "..."}
    """
    return {
        "id": widget_id,
        "title": title,
        "priority": priority,
        "type": "list",
        "max_items": max_items,
        "data": {"items": items[:max_items]},
    }


def badge_widget(widget_id: str, title: str,
                 status: str, value: str = "",
                 priority: int = 50) -> dict:
    """Widget with a single status badge."""
    return {
        "id": widget_id,
        "title": title,
        "priority": priority,
        "type": "badge",
        "data": {"status": status, "value": value},
    }


def text_widget(widget_id: str, title: str,
                text: str,
                priority: int = 50) -> dict:
    """Simple text widget."""
    return {
        "id": widget_id,
        "title": title,
        "priority": priority,
        "type": "text",
        "data": {"text": text},
    }


# ==============================================================
# Widget for this module itself
# ==============================================================

def web_widget() -> dict:
    """Dashboard widget for the widget system itself."""
    collector = WidgetCollector()
    widgets = collector.collect()

    return metrics_widget(
        widget_id="widgets",
        title="Widget System",
        rows=[
            metric_row("Registered", len(widgets), "cyan"),
            metric_row("Modules scanned", len(SCAN_MODULES)),
            metric_row("Errors", len(collector.errors),
                      "red" if collector.errors else "green"),
        ],
        priority=99,
    )


