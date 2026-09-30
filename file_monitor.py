# ==============================================================
# OMEGA OS - File Monitor
# ==============================================================
# Security-focused file monitoring:
#   - Watch directories for new/changed files
#   - Verify file content matches its extension
#   - Detect suspicious patterns (executables in /tmp, etc)
#   - Emit security events to the message bus
#   - Integration with Security AI v2
# ==============================================================

import os
import sys
import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from file_inspector import (
    detect_by_magic, detect_by_extension,
    partial_hash, FileRecord,
)

# Bus integration (optional — works without it)
try:
    from bus import EventBus
    from bus_hooks import set_bus
    _BUS_AVAILABLE = True
except ImportError:
    _BUS_AVAILABLE = False
    EventBus = None
    set_bus = None


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
MONITOR_LOG = os.path.join(OMEGA_DIR, "file_monitor.jsonl")


# ==============================================================
# Extension -> expected magic content
# ==============================================================
# If extension says X, magic bytes should say one of these formats.

EXTENSION_EXPECTED = {
    ".apk":   ["ZIP/APK/JAR", "ZIP (empty)"],
    ".zip":   ["ZIP/APK/JAR", "ZIP (empty)"],
    ".jar":   ["ZIP/APK/JAR", "ZIP (empty)"],
    ".gz":    ["GZIP"],
    ".bz2":   ["BZIP2"],
    ".xz":    ["XZ"],
    ".7z":    ["7-Zip"],
    ".rar":   ["RAR"],

    ".png":   ["PNG"],
    ".jpg":   ["JPEG"],
    ".jpeg":  ["JPEG"],
    ".gif":   ["GIF87a", "GIF89a"],
    ".bmp":   ["BMP"],
    ".ico":   ["ICO"],

    ".mp3":   ["MP3 (ID3)", "RIFF (WAV/AVI)"],
    ".wav":   ["RIFF (WAV/AVI)"],
    ".ogg":   ["OGG"],
    ".flac":  ["FLAC"],
    ".mp4":   ["RIFF (WAV/AVI)"],
    ".avi":   ["RIFF (WAV/AVI)"],

    ".pdf":   ["PDF"],
    ".sqlite":["SQLite DB"],
    ".db":    ["SQLite DB"],

    # Text formats can be "text" or specific
    ".json":  ["text", "JSON-ish", "JSON array?"],
    ".jsonl": ["text", "JSON-ish", "JSON array?"],
    ".py":    ["text", "Script"],
    ".md":    ["text"],
    ".txt":   ["text"],
    ".html":  ["text", "HTML", "XML"],
    ".htm":   ["text", "HTML", "XML"],
    ".xml":   ["text", "XML"],
    ".log":   ["text"],
    ".sh":    ["text", "Script"],
    ".csv":   ["text"],
    ".yaml":  ["text"],
    ".yml":   ["text"],
    ".toml":  ["text"],
    ".ini":   ["text"],
    ".conf":  ["text"],
    ".cfg":   ["text"],
}

# Extensions that should NEVER contain executables
NEVER_EXECUTABLE = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".mp3", ".wav", ".ogg", ".flac", ".mp4",
    ".pdf", ".txt", ".md", ".csv",
    ".json", ".jsonl", ".yaml", ".yml",
    ".html", ".htm", ".xml",
}


# ==============================================================
# Suspicious path patterns
# ==============================================================

SUSPICIOUS_PATHS = [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/data/local/tmp/",  # Android
]


# ==============================================================
# File anomaly types
# ==============================================================

class FileAnomaly:
    EXTENSION_MISMATCH = "extension_mismatch"
    EXECUTABLE_DISGUISED = "executable_disguised"
    SUSPICIOUS_LOCATION = "suspicious_location"
    NO_EXTENSION_BINARY = "no_extension_binary"
    DOUBLE_EXTENSION = "double_extension"
    HIDDEN_EXECUTABLE = "hidden_executable"


# ==============================================================
# File anomaly record
# ==============================================================

@dataclass
class FileAnomalyRecord:
    ts: int
    path: str
    name: str
    size: int
    anomaly: str
    severity: str
    detail: str
    hash: str = ""

    def to_dict(self):
        return asdict(self)


# ==============================================================
# File Monitor
# ==============================================================

class FileMonitor:

    def __init__(self, watch_dirs: List[str] = None, bus=None):
        # Default watch dirs
        # Note: We deliberately do NOT watch storage/shared
        # (contains user photos with noisy extension mismatches)
        if watch_dirs is None:
            # NOTE: storage/downloads is a symlink to entire user storage
            # (including DCIM, Movies, SHAREit, etc) — we exclude it to
            # avoid false positives on real user files.
            watch_dirs = [
                os.path.join(HOME, "omega"),  # our own dir only
                "/tmp",                       # temp (usually safe)
            ]
        self.watch_dirs = [d for d in watch_dirs if os.path.isdir(d)]
        self.known_files: Dict[str, float] = {}  # path -> mtime
        self.anomalies: List[FileAnomalyRecord] = []
        self.total_scans = 0
        self.total_new_files = 0
        self.bus = bus  # optional EventBus

    # ─────────────────────────────────────────────────────
    # Scanning
    # ─────────────────────────────────────────────────────

    def scan(self) -> List[FileAnomalyRecord]:
        """
        Scan all watch dirs. Detect new/changed files.
        Returns list of anomalies found in this scan.
        """
        self.total_scans += 1
        new_anomalies = []

        for root_dir in self.watch_dirs:
            for dirpath, dirnames, filenames in os.walk(root_dir):
                # Skip cache, git, and known noisy dirs
                SKIP_DIRS = {
                    ".git", "__pycache__",
                    ".MyGallery", "DCIM",       # camera
                    ".thumbnails", "cache",      # cache dirs
                    ".caches", ".tmp",           # temp caches
                    "Android",                   # android internals
                    "Pictures", "Movies", "Music",  # media
                    "SHAREit",                   # share app cache
                    "WhatsApp",                  # messaging cache
                    "Telegram",                  # messaging cache
                }
                dirnames[:] = [d for d in dirnames
                              if d not in SKIP_DIRS]

                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        mtime = os.path.getmtime(fpath)
                    except OSError:
                        continue

                    # New or changed?
                    old_mtime = self.known_files.get(fpath)
                    if old_mtime is None:
                        # New file
                        self.total_new_files += 1
                        anomalies = self._inspect(fpath, fname)
                        new_anomalies.extend(anomalies)
                    elif mtime > old_mtime:
                        # Changed — also worth inspecting
                        anomalies = self._inspect(fpath, fname)
                        new_anomalies.extend(anomalies)

                    self.known_files[fpath] = mtime

        for a in new_anomalies:
            self.anomalies.append(a)
            self._log(a)

        return new_anomalies

    # ─────────────────────────────────────────────────────
    # Inspection
    # ─────────────────────────────────────────────────────

    def _inspect(self, path: str,
                 name: str) -> List[FileAnomalyRecord]:
        """Inspect a single file. Returns anomalies found."""
        anomalies = []
        try:
            size = os.path.getsize(path)
        except OSError:
            return anomalies

        if size == 0:
            return anomalies

        # Detect actual content
        magic_result = detect_by_magic(path)
        if magic_result is None:
            return anomalies
        fmt, cat = magic_result

        # Extension from filename
        ext = os.path.splitext(name)[1].lower()

        # --- Check 1: Executable disguised as non-executable (FIRST!) ---
        # This takes priority over generic extension_mismatch
        disguised = False
        if ext in NEVER_EXECUTABLE:
            if fmt in ("ELF binary", "Windows EXE",
                      "Mach-O fat", "Android DEX"):
                anomalies.append(FileAnomalyRecord(
                    ts=int(time.time() * 1000),
                    path=path, name=name, size=size,
                    anomaly=FileAnomaly.EXECUTABLE_DISGUISED,
                    severity="CRITICAL",
                    detail=f"{ext} file contains {fmt}",
                    hash=partial_hash(path) or "",
                ))
                disguised = True

        # --- Check 2: Extension mismatch (skip if already flagged) ---
        # Skip media files whose content reads as "text" — many MP4/MKV/AVI
        # have text-like headers (moov atoms) and are not threats.
        MEDIA_EXTS = {".mp4", ".mkv", ".avi", ".mov", ".webm",
                      ".flv", ".m4v", ".wmv"}
        if ext in MEDIA_EXTS and fmt in ("text", "unknown"):
            pass  # skip — not an anomaly
        elif not disguised and ext and ext in EXTENSION_EXPECTED:
            expected = EXTENSION_EXPECTED[ext]
            if fmt not in expected:
                if fmt not in ("unknown",):
                    result = self._severity_for_mismatch(
                        ext, fmt, cat)
                    if result is not None:
                        sev, reason = result
                        anomalies.append(FileAnomalyRecord(
                            ts=int(time.time() * 1000),
                            path=path, name=name, size=size,
                            anomaly=FileAnomaly.EXTENSION_MISMATCH,
                            severity=sev,
                            detail=f"ext={ext} but content={fmt}",
                            hash=partial_hash(path) or "",
                        ))

        # --- Check 3: Suspicious location ---
        for sus in SUSPICIOUS_PATHS:
            if sus in path:
                # Executables in /tmp are suspicious
                if fmt in ("ELF binary", "Windows EXE",
                          "Mach-O fat", "Android DEX", "Script"):
                    anomalies.append(FileAnomalyRecord(
                        ts=int(time.time() * 1000),
                        path=path, name=name, size=size,
                        anomaly=FileAnomaly.SUSPICIOUS_LOCATION,
                        severity="HIGH",
                        detail=f"{fmt} in {sus}",
                        hash=partial_hash(path) or "",
                    ))
                break

        # --- Check 4: No extension but binary content ---
        if not ext:
            if fmt in ("ELF binary", "Windows EXE",
                      "Mach-O fat"):
                anomalies.append(FileAnomalyRecord(
                    ts=int(time.time() * 1000),
                    path=path, name=name, size=size,
                    anomaly=FileAnomaly.NO_EXTENSION_BINARY,
                    severity="MEDIUM",
                    detail=f"no extension but {fmt}",
                    hash=partial_hash(path) or "",
                ))

        # --- Check 5: Double extension (fake.pdf.exe) ---
        # Only flag if the SECOND-TO-LAST part is a known DATA extension
        # (photo.jpg.exe, doc.pdf.scr) — NOT installer files
        # (python-3.13.15-amd64.exe is legitimate)
        parts = name.split(".")
        if len(parts) >= 3:
            last = parts[-1].lower()
            second_last = parts[-2].lower()

            DATA_EXTS = {
                "jpg", "jpeg", "png", "gif", "bmp", "svg",
                "pdf", "doc", "docx", "xls", "xlsx",
                "ppt", "pptx", "txt", "rtf", "odt",
                "mp3", "mp4", "avi", "mkv", "mov",
                "zip", "rar", "7z", "tar", "gz",
                "html", "htm", "xml", "csv", "json",
                "py", "sh", "js", "bat", "cmd",
            }

            EXECUTABLE_EXTS = {
                "exe", "scr", "bat", "cmd", "com", "pif",
                "vbs", "js", "jar", "msi", "lnk",
            }

            if last in EXECUTABLE_EXTS and second_last in DATA_EXTS:
                anomalies.append(FileAnomalyRecord(
                    ts=int(time.time() * 1000),
                    path=path, name=name, size=size,
                    anomaly=FileAnomaly.DOUBLE_EXTENSION,
                    severity="HIGH",
                    detail=f"double extension: .{second_last}.{last}",
                    hash=partial_hash(path) or "",
                ))

        # --- Check 6: Hidden executable (starts with .) ---
        if name.startswith(".") and fmt in (
                "ELF binary", "Windows EXE", "Mach-O fat"):
            anomalies.append(FileAnomalyRecord(
                ts=int(time.time() * 1000),
                path=path, name=name, size=size,
                anomaly=FileAnomaly.HIDDEN_EXECUTABLE,
                severity="HIGH",
                detail=f"hidden {fmt}: {name}",
                hash=partial_hash(path) or "",
            ))

        return anomalies

    def _severity_for_mismatch(self, ext: str, fmt: str,
                                cat: str) -> Tuple[str, str]:
        """Determine severity of an extension mismatch."""
        # Executable pretending to be data = critical
        if fmt in ("ELF binary", "Windows EXE", "Mach-O fat"):
            return "CRITICAL", "executable disguised as data"

        # All text formats are compatible with each other
        # (text files often start with [, {, <, etc.)
        text_formats = {"text", "JSON-ish", "JSON array?",
                       "XML", "HTML", "Script", "Markdown"}
        text_exts = {".log", ".txt", ".md", ".json", ".jsonl",
                    ".py", ".sh", ".html", ".htm", ".xml",
                    ".csv", ".yaml", ".yml", ".toml", ".ini",
                    ".conf", ".cfg"}

        if fmt in text_formats and ext in text_exts:
            # Both are text-like — no anomaly
            return None

        # Archive pretending to be something else
        if fmt in ("ZIP/APK/JAR",) and ext not in (
                ".apk", ".zip", ".jar"):
            return "MEDIUM", "archive with wrong extension"

        # Data pretending to be data = low
        if cat in ("image", "media", "document", "archive"):
            return "LOW", "content type differs from extension"

        # Generic
        return "MEDIUM", "content does not match extension"

    # ─────────────────────────────────────────────────────
    # Logging
    # ─────────────────────────────────────────────────────

    def _log(self, record: FileAnomalyRecord):
        # Save to file
        try:
            with open(MONITOR_LOG, "a") as f:
                f.write(json.dumps(record.to_dict()) + "\n")
        except OSError:
            pass

        # Emit to bus
        if self.bus is not None:
            try:
                self.bus.emit(
                    "security.file_anomaly",
                    "file_monitor",
                    severity=record.severity,
                    path=record.path,
                    name=record.name,
                    anomaly=record.anomaly,
                    detail=record.detail,
                )
            except Exception:
                pass

    # ─────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────

    def stats(self) -> dict:
        sev_counts = {}
        for a in self.anomalies:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1

        return {
            "watch_dirs": len(self.watch_dirs),
            "known_files": len(self.known_files),
            "total_scans": self.total_scans,
            "total_new_files": self.total_new_files,
            "anomalies": len(self.anomalies),
            "by_severity": sev_counts,
        }




# ==============================================================
# Display helpers
# ==============================================================

def print_header(title: str):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def print_anomaly(a: FileAnomalyRecord):
    print(f"  [{a.severity:<8}] {a.anomaly}")
    print(f"    file: {a.name}")
    print(f"    path: {a.path}")
    print(f"    detail: {a.detail}")
    print(f"    hash: {a.hash}")
    print()


def print_stats(stats: dict):
    print_header("File Monitor Statistics")
    print()
    print(f"  Watch dirs       : {stats['watch_dirs']}")
    print(f"  Known files      : {stats['known_files']}")
    print(f"  Total scans      : {stats['total_scans']}")
    print(f"  Total new files  : {stats['total_new_files']}")
    print(f"  Anomalies        : {stats['anomalies']}")
    print()
    if stats['by_severity']:
        print("  By severity:")
        for sev, count in sorted(stats['by_severity'].items(),
                                 key=lambda kv: -kv[1]):
            print(f"    {sev:<10} {count}")


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
OMEGA File Monitor

Usage:
  python file_monitor.py scan             one scan pass
  python file_monitor.py stats            show stats
  python file_monitor.py recent [N]       show recent anomalies
  python file_monitor.py watch            continuous watch (Ctrl+C to stop)
  python file_monitor.py threat-test      test with fake ELF file
  python file_monitor.py help             this message

Watch mode:
  Scans every 30 seconds by default.
  Override: python file_monitor.py watch 10   (10s interval)
""")


def get_watch_dirs() -> List[str]:
    """Default watch dirs — keep it tight to avoid false positives."""
    # NOTE: storage/shared is a symlink to entire user storage
    # (Documents, Music, Movies, Pictures, DCIM, SHAREit, WhatsApp...)
    # We deliberately exclude it to avoid noisy scans of user data.
    candidates = [
        os.path.join(HOME, "omega"),
        "/tmp",
    ]
    return [d for d in candidates if os.path.isdir(d)]


def cli_scan():
    mon = FileMonitor(watch_dirs=get_watch_dirs())
    anomalies = mon.scan()

    print_header("Scan Complete")
    print()
    print(f"  Files scanned : {mon.total_new_files}")
    print(f"  Anomalies     : {len(anomalies)}")
    print()

    if anomalies:
        print("  Anomalies found:")
        print()
        for a in anomalies:
            print_anomaly(a)
    else:
        print("  [OK] No anomalies")


def cli_stats():
    mon = FileMonitor(watch_dirs=get_watch_dirs())
    mon.scan()
    print_stats(mon.stats())


def cli_recent(n: int = 20):
    mon = FileMonitor()
    print_header(f"Recent Anomalies ({n})")

    # Read from log file
    log_path = MONITOR_LOG
    if not os.path.exists(log_path):
        print()
        print("  (no log file yet)")
        return

    try:
        with open(log_path) as f:
            lines = f.readlines()
    except OSError:
        print("  (cannot read log)")
        return

    entries = []
    for line in lines[-n:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not entries:
        print()
        print("  (no entries)")
        return

    print()
    for e in reversed(entries):
        dt = datetime.fromtimestamp(e["ts"] / 1000)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [{e['severity']:<8}] {time_str}  {e['name']}")
        print(f"    {e['detail']}")
        print()


def cli_watch(interval: int = 30):
    mon = FileMonitor(watch_dirs=get_watch_dirs())

    # Try to set up bus
    bus = None
    if _BUS_AVAILABLE:
        try:
            bus = EventBus(echo=False)
            set_bus(bus)
            mon.bus = bus
            print("[+] Message bus connected")
        except Exception as e:
            print(f"[!] Bus setup failed: {e}")

    print_header("File Monitor - Watch Mode")
    print()
    print(f"  Interval: {interval}s")
    print(f"  Watch dirs:")
    for d in mon.watch_dirs:
        print(f"    - {d}")
    print()
    print("  Press Ctrl+C to stop")
    print()

    scan_count = 0
    try:
        while True:
            scan_count += 1
            anomalies = mon.scan()

            if anomalies:
                dt = datetime.now().strftime("%H:%M:%S")
                print(f"  [{dt}] scan #{scan_count}: "
                      f"{len(anomalies)} anomalies")
                for a in anomalies:
                    print(f"    [{a.severity}] {a.name}: {a.detail}")
            else:
                dt = datetime.now().strftime("%H:%M:%S")
                print(f"  [{dt}] scan #{scan_count}: clean")

            time.sleep(interval)
    except KeyboardInterrupt:
        print()
        print(f"[+] Stopped after {scan_count} scans")
        print(f"    Total anomalies: {len(mon.anomalies)}")


def cli_threat_test():
    """Create a fake threat and verify detection."""
    test_path = os.path.join(HOME, "omega", "_threat_test.jpg")

    print_header("Threat Test")
    print()

    # Create fake ELF disguised as JPG
    print(f"  [1] Creating fake threat at {test_path}")
    try:
        with open(test_path, "wb") as f:
            f.write(b"\x7fELF")
            f.write(b"\x00" * 100)
        print("      OK")
    except OSError as e:
        print(f"      FAILED: {e}")
        return

    # Scan
    print()
    print(f"  [2] Scanning...")
    mon = FileMonitor(watch_dirs=[os.path.join(HOME, "omega")])
    anomalies = mon.scan()

    # Find our file
    found = [a for a in anomalies if "_threat_test" in a.name]

    print()
    if found:
        print(f"  [3] DETECTED: {len(found)} anomaly/ies")
        for a in found:
            print_anomaly(a)
    else:
        print("  [3] NOT DETECTED — check file_monitor logic")

    # Clean up
    print(f"  [4] Cleaning up")
    try:
        os.remove(test_path)
        print("      OK")
    except OSError:
        pass


def main():
    if len(sys.argv) < 2:
        cli_help()
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd in ("help", "-h", "--help"):
        cli_help()
    elif cmd == "scan":
        cli_scan()
    elif cmd == "stats":
        cli_stats()
    elif cmd == "recent":
        n = int(args[0]) if args else 20
        cli_recent(n)
    elif cmd == "watch":
        interval = int(args[0]) if args else 30
        cli_watch(interval)
    elif cmd == "threat-test":
        cli_threat_test()
    else:
        print(f"[!] unknown command: {cmd}")
        cli_help()


if __name__ == "__main__":
    main()
