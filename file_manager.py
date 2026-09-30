# ==============================================================
# OMEGA OS - File Manager
# ==============================================================
# Section 9.5 of the OMEGA spec.
#
# Automatic file management:
#   - Scan omega directory for files
#   - Classify by type (log, json, model, temp, code)
#   - Identify cleanup candidates (old, large, temp)
#   - Archive old logs
#   - Safe delete with confirmation
# ==============================================================

import os
import json
import time
import shutil
import gzip
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
ARCHIVE_DIR = os.path.join(OMEGA_DIR, "archive")
CLEANUP_LOG = os.path.join(OMEGA_DIR, "cleanup.jsonl")


# ==============================================================
# File classification
# ==============================================================

# Rules: (pattern, category, weight_for_cleanup)
# Higher weight = more likely to be cleaned
FILE_RULES = [
    # Order matters! More specific patterns FIRST.

    # Caches (must come before .py)
    (".pyc",          "cache",     10),
    ("__pycache__",   "cache",     10),

    # Temp files
    ("_tmp",          "temp",      10),
    ("tmp",           "temp",      9),

    # Backups
    (".backup",       "backup",    8),
    (".old",          "backup",    10),

    # APKs — large binaries, delete if not needed
    (".apk",          "apk",       6),

    # Critical — never clean
    (".py",           "code",      0),
    (".md",           "doc",       0),
    ("config.json",   "config",    0),
    ("readme",        "doc",       0),
    (".gitignore",    "config",    0),

    # Important state
    ("model.json",    "model",     1),
    ("tasks.json",    "state",     1),
    ("whitelist.json","security",  1),

    # HTML reports (old ones can go)
    (".html",         "report",    4),

    # History (JSON/CSV)
    ("history",       "history",   5),

    # Logs
    ("bus_log.jsonl", "log",       5),
    ("decisions.jsonl","log",      5),
    ("outcomes.jsonl","log",       5),
    ("quarantine.jsonl","log",     5),
    ("tasks.jsonl",   "log",       5),
    ("security_v2_events.jsonl","log", 5),
    (".jsonl",        "log",       5),
    (".log",          "log",       7),
]


def classify_file(path: str, name: str) -> Tuple[str, int]:
    """Return (category, cleanup_weight)."""
    name_lower = name.lower()
    for pattern, cat, weight in FILE_RULES:
        if pattern in name_lower:
            return cat, weight
    return "other", 3


# ==============================================================
# Data models
# ==============================================================

@dataclass
class FileInfo:
    path: str
    name: str
    size_bytes: int
    mtime: int
    age_days: float
    category: str
    cleanup_weight: int

    @property
    def size_kb(self) -> int:
        return self.size_bytes // 1024

    @property
    def size_human(self) -> str:
        s = self.size_bytes
        if s < 1024:
            return f"{s}B"
        if s < 1024 * 1024:
            return f"{s // 1024}KB"
        if s < 1024 * 1024 * 1024:
            return f"{s // (1024 * 1024)}MB"
        return f"{s // (1024 * 1024 * 1024)}GB"

    @property
    def age_human(self) -> str:
        a = self.age_days
        if a < 1 / 24:
            return f"{int(a * 24 * 60)}m"
        if a < 1:
            return f"{int(a * 24)}h"
        if a < 30:
            return f"{int(a)}d"
        if a < 365:
            return f"{int(a / 30)}mo"
        return f"{a / 365:.1f}y"


@dataclass
class CleanupAction:
    path: str
    name: str
    size_bytes: int
    category: str
    reason: str
    action: str  # "delete" | "archive" | "keep"


# ==============================================================
# Scanner
# ==============================================================

class FileScanner:

    def __init__(self, root: str = OMEGA_DIR):
        self.root = root
        self.files: List[FileInfo] = []

    def scan(self, max_depth: int = 2) -> List[FileInfo]:
        """Scan root directory. Returns list of FileInfo."""
        self.files = []
        now = time.time()

        for dirpath, dirnames, filenames in os.walk(self.root):
            # Skip .git
            if ".git" in dirpath:
                dirnames[:] = []
                continue

            # Depth check
            rel = os.path.relpath(dirpath, self.root)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            if depth >= max_depth:
                dirnames[:] = []
                continue

            # Skip archive dir
            if dirpath == ARCHIVE_DIR:
                continue

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.stat(fpath)
                except OSError:
                    continue

                age_days = (now - st.st_mtime) / 86400.0
                cat, weight = classify_file(fpath, fname)

                self.files.append(FileInfo(
                    path=fpath,
                    name=fname,
                    size_bytes=st.st_size,
                    mtime=int(st.st_mtime),
                    age_days=age_days,
                    category=cat,
                    cleanup_weight=weight,
                ))

        return self.files

    def by_category(self, category: str) -> List[FileInfo]:
        return [f for f in self.files if f.category == category]

    def top_largest(self, n: int = 10) -> List[FileInfo]:
        return sorted(self.files, key=lambda f: -f.size_bytes)[:n]

    def top_oldest(self, n: int = 10) -> List[FileInfo]:
        return sorted(self.files, key=lambda f: -f.age_days)[:n]

    def stats(self) -> dict:
        total_bytes = sum(f.size_bytes for f in self.files)
        by_cat = {}
        for f in self.files:
            if f.category not in by_cat:
                by_cat[f.category] = {"count": 0, "size_bytes": 0}
            by_cat[f.category]["count"] += 1
            by_cat[f.category]["size_bytes"] += f.size_bytes

        return {
            "total_files": len(self.files),
            "total_bytes": total_bytes,
            "total_human": self._human(total_bytes),
            "by_category": by_cat,
        }

    @staticmethod
    def _human(n: int) -> str:
        if n < 1024:
            return f"{n}B"
        if n < 1024 * 1024:
            return f"{n // 1024}KB"
        if n < 1024 * 1024 * 1024:
            return f"{n // (1024 * 1024)}MB"
        return f"{n // (1024 * 1024 * 1024)}GB"


# ==============================================================
# Cleanup policies
# ==============================================================

@dataclass
class CleanupPolicy:
    name: str
    # Conditions for cleanup candidate
    category: Optional[str] = None
    min_age_days: float = 0
    min_size_kb: int = 0
    # What to do
    action: str = "delete"  # "delete" | "archive"


DEFAULT_POLICIES = [
    # Temp files older than 1 day -> delete
    CleanupPolicy(name="temp_old", category="temp", min_age_days=1,
                  action="delete"),
    # Cache files older than 1 day -> delete
    CleanupPolicy(name="cache_old", category="cache", min_age_days=1,
                  action="delete"),
    # Backup files older than 7 days -> delete
    CleanupPolicy(name="backup_old", category="backup", min_age_days=7,
                  action="delete"),
    # Logs older than 14 days -> archive
    CleanupPolicy(name="log_archive", category="log", min_age_days=14,
                  action="archive"),
    # HTML reports older than 3 days -> delete
    CleanupPolicy(name="report_old", category="report", min_age_days=3,
                  action="delete"),
    # History files older than 7 days -> archive
    CleanupPolicy(name="history_archive", category="history",
                  min_age_days=7, action="archive"),
    # Old APKs (>30 days) -> delete (if user approves)
    CleanupPolicy(name="apk_old", category="apk", min_age_days=30,
                  action="delete"),
]


# ==============================================================
# Cleanup Engine
# ==============================================================

class CleanupEngine:

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.actions: List[CleanupAction] = []

    def plan(self, files: List[FileInfo],
             policies: List[CleanupPolicy] = None) -> List[CleanupAction]:
        """Compute what to do with each file. Doesn't execute."""
        policies = policies or DEFAULT_POLICIES
        self.actions = []

        for f in files:
            action = self._evaluate(f, policies)
            if action:
                self.actions.append(action)

        return self.actions

    def _evaluate(self, f: FileInfo,
                  policies: List[CleanupPolicy]) -> Optional[CleanupAction]:
        # Specific: .old and .backup files
        if f.name.endswith(".old") or f.name.endswith(".backup"):
            if f.age_days >= 7:
                return CleanupAction(
                    path=f.path, name=f.name,
                    size_bytes=f.size_bytes, category=f.category,
                    reason=f".old/.backup older than 7 days "
                          f"({f.age_days:.1f}d)",
                    action="delete",
                )

        # Policy-based
        for p in policies:
            if p.category and f.category != p.category:
                continue
            if f.age_days < p.min_age_days:
                continue
            if f.size_bytes < p.min_size_kb * 1024:
                continue

            reason = (f"{p.name}: "
                     f"{f.category} age={f.age_days:.1f}d "
                     f"size={f.size_human}")

            return CleanupAction(
                path=f.path, name=f.name,
                size_bytes=f.size_bytes, category=f.category,
                reason=reason, action=p.action,
            )

        return None

    def execute(self) -> dict:
        """Run planned actions. Returns summary."""
        deleted = 0
        archived = 0
        freed_bytes = 0
        errors = []

        os.makedirs(ARCHIVE_DIR, exist_ok=True)

        for action in self.actions:
            try:
                if action.action == "delete":
                    if not self.dry_run:
                        os.remove(action.path)
                    deleted += 1
                    freed_bytes += action.size_bytes
                    self._log(action)

                elif action.action == "archive":
                    if not self.dry_run:
                        self._archive_file(action.path)
                    archived += 1
                    freed_bytes += action.size_bytes
                    self._log(action)
            except Exception as e:
                errors.append(f"{action.name}: {e}")

        return {
            "dry_run": self.dry_run,
            "deleted": deleted,
            "archived": archived,
            "freed_bytes": freed_bytes,
            "freed_human": FileScanner._human(freed_bytes),
            "errors": errors,
        }

    def _archive_file(self, path: str):
        """Compress a file into ARCHIVE_DIR and remove original."""
        fname = os.path.basename(path)
        stamp = datetime.now().strftime("%Y%m%d")
        archived_name = f"{fname}.{stamp}.gz"
        archived_path = os.path.join(ARCHIVE_DIR, archived_name)

        with open(path, "rb") as fin:
            with gzip.open(archived_path, "wb") as fout:
                shutil.copyfileobj(fin, fout)

        os.remove(path)

    def _log(self, action: CleanupAction):
        record = {
            "ts": int(time.time() * 1000),
            "name": action.name,
            "path": action.path,
            "size_bytes": action.size_bytes,
            "action": action.action,
            "reason": action.reason,
            "dry_run": self.dry_run,
        }
        try:
            with open(CLEANUP_LOG, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass


# ==============================================================
# Display
# ==============================================================

def print_header(title: str):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def print_files(files: List[FileInfo], title: str, limit: int = 20):
    print_header(title)
    if not files:
        print("  (none)")
        return
    print()
    print(f"  {'NAME':<35} {'SIZE':>10} {'AGE':>6}  CATEGORY")
    print("  " + "-" * 68)
    for f in files[:limit]:
        print(f"  {f.name[:34]:<35} {f.size_human:>10} "
              f"{f.age_human:>6}  {f.category}")


def print_stats(stats: dict):
    print_header("File Statistics")
    print()
    print(f"  Total files: {stats['total_files']}")
    print(f"  Total size : {stats['total_human']}")
    print()
    print("  By category:")
    for cat, data in sorted(stats["by_category"].items(),
                            key=lambda kv: -kv[1]["size_bytes"]):
        size = data["size_bytes"]
        human = (f"{size // 1024}KB" if size < 1024 * 1024
                else f"{size // (1024 * 1024)}MB")
        print(f"    {cat:<12} {data['count']:>4} files  {human:>8}")


def print_plan(actions: List[CleanupAction]):
    print_header("Cleanup Plan")
    if not actions:
        print("  (nothing to clean)")
        return
    print()
    print(f"  {'ACTION':<10} {'NAME':<30} {'SIZE':>8}  REASON")
    print("  " + "-" * 68)
    total = 0
    for a in actions:
        size_h = (f"{a.size_bytes // 1024}KB"
                 if a.size_bytes < 1024 * 1024
                 else f"{a.size_bytes // (1024 * 1024)}MB")
        print(f"  {a.action.upper():<10} {a.name[:29]:<30} "
              f"{size_h:>8}  {a.reason[:30]}")
        total += a.size_bytes
    print()
    print(f"  Total would free: {total // 1024} KB")


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
OMEGA File Manager

Usage:
  python file_manager.py stats          file statistics
  python file_manager.py list           list all files
  python file_manager.py largest [N]    top N largest files
  python file_manager.py oldest [N]     top N oldest files
  python file_manager.py category NAME  files in category
  python file_manager.py cleanup-plan   show cleanup candidates (dry)
  python file_manager.py cleanup-run    actually run cleanup
  python file_manager.py help           this message
""")


def cli_stats():
    sc = FileScanner()
    sc.scan()
    print_stats(sc.stats())


def cli_list():
    sc = FileScanner()
    sc.scan()
    print_files(sc.files, "All Files", limit=50)


def cli_largest(n: int = 10):
    sc = FileScanner()
    sc.scan()
    print_files(sc.top_largest(n), f"Top {n} Largest Files")


def cli_oldest(n: int = 10):
    sc = FileScanner()
    sc.scan()
    print_files(sc.top_oldest(n), f"Top {n} Oldest Files")


def cli_category(cat: str):
    sc = FileScanner()
    sc.scan()
    files = sc.by_category(cat)
    print_files(files, f"Category: {cat}", limit=50)


def cli_cleanup_plan():
    sc = FileScanner()
    sc.scan()
    engine = CleanupEngine(dry_run=True)
    actions = engine.plan(sc.files)
    print_plan(actions)


def cli_cleanup_run():
    sc = FileScanner()
    sc.scan()
    engine = CleanupEngine(dry_run=False)
    actions = engine.plan(sc.files)
    print_plan(actions)
    if not actions:
        return
    print()
    confirm = input("Execute cleanup? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("  [cancelled]")
        return
    result = engine.execute()
    print()
    print(f"  Deleted  : {result['deleted']}")
    print(f"  Archived : {result['archived']}")
    print(f"  Freed    : {result['freed_human']}")
    if result["errors"]:
        print(f"  Errors   : {len(result['errors'])}")


def main():
    import sys
    if len(sys.argv) < 2:
        cli_help()
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "help" or cmd == "-h":
        cli_help()
    elif cmd == "stats":
        cli_stats()
    elif cmd == "list":
        cli_list()
    elif cmd == "largest":
        n = int(args[0]) if args else 10
        cli_largest(n)
    elif cmd == "oldest":
        n = int(args[0]) if args else 10
        cli_oldest(n)
    elif cmd == "category":
        if not args:
            print("[!] usage: category NAME")
        else:
            cli_category(args[0])
    elif cmd == "cleanup-plan":
        cli_cleanup_plan()
    elif cmd == "cleanup-run":
        cli_cleanup_run()
    else:
        print(f"[!] unknown command: {cmd}")
        cli_help()


if __name__ == "__main__":
    main()
