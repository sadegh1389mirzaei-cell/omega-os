# ==============================================================
# OMEGA OS - Task Manager
# ==============================================================
# Centralized process and task management:
#   - List processes with metadata (CPU, RAM, category, trust)
#   - Freeze/thaw via SIGSTOP/SIGCONT
#   - Kill with confirmation
#   - Schedule recurring tasks
#   - Priority management (task classes)
# ==============================================================

import os
import sys
import time
import json
import signal
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Set


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")
TASKS_FILE = os.path.join(OMEGA_DIR, "tasks.json")
TASKS_LOG = os.path.join(OMEGA_DIR, "tasks.jsonl")


# ==============================================================
# Process categorization
# ==============================================================

CATEGORY_COLORS = {
    "SYSTEM":    "gray",
    "SHELL":     "cyan",
    "RUNTIME":   "green",
    "BROWSER":   "yellow",
    "SUPERVISOR":"blue",
    "NETWORK":   "magenta",
    "TOOL":      "white",
    "ANDROID":   "gray",
    "UNKNOWN":   "white",
}


def classify_process(name: str, args: str = "") -> str:
    """Classify a process into a category."""
    text = (name + " " + args).lower()
    base = name.split()[0].split("/")[-1].lower()

    if base in ("runsvdir", "runsv", "svlogd"):
        return "SUPERVISOR"
    if base in ("sh", "bash", "zsh", "dash", "fish"):
        return "SHELL"
    if base in ("python", "python3", "node", "java", "ruby", "perl"):
        return "RUNTIME"
    if "chrome" in base or "firefox" in base or "browser" in base:
        return "BROWSER"
    if "ssh" in base or "nc" in base or "ncat" in base or "nmap" in base:
        return "NETWORK"
    if base in ("ps", "top", "grep", "sed", "awk", "cat", "tail",
                "head", "ls", "find", "sort", "wc"):
        return "TOOL"
    if base.startswith("["):
        return "SYSTEM"
    if "/data/data" in text or "/system/bin" in text:
        return "ANDROID"
    return "UNKNOWN"


# ==============================================================
# Data models
# ==============================================================

@dataclass
class ProcessInfo:
    pid: int
    name: str
    args: str
    user: str
    cpu_pct: float
    category: str
    frozen: bool = False
    trust: int = 50
    task_class: str = "BEST_EFFORT"

    def short_name(self) -> str:
        return self.name[:20] if self.name else "?"

    def display(self) -> str:
        state = "[FROZEN] " if self.frozen else ""
        return (f"{self.pid:>6}  {state}{self.short_name():<22} "
                f"{self.cpu_pct:>5.1f}%  {self.category:<10} "
                f"trust={self.trust}")


@dataclass
class ScheduledTask:
    task_id: int
    name: str
    command: List[str]
    interval_s: int
    enabled: bool = True
    last_run: int = 0
    run_count: int = 0
    fail_count: int = 0
    created: int = 0

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        t = cls(task_id=d["task_id"], name=d["name"],
                command=d["command"], interval_s=d["interval_s"])
        t.enabled = d.get("enabled", True)
        t.last_run = d.get("last_run", 0)
        t.run_count = d.get("run_count", 0)
        t.fail_count = d.get("fail_count", 0)
        t.created = d.get("created", 0)
        return t

    def is_due(self, now: float = None) -> bool:
        if not self.enabled:
            return False
        if now is None:
            now = time.time()
        return (now - self.last_run) >= self.interval_s


# ==============================================================
# Task Manager
# ==============================================================

class TaskManager:

    def __init__(self):
        self.processes: Dict[int, ProcessInfo] = {}
        self.frozen_pids: Set[int] = set()
        self.scheduled: Dict[int, ScheduledTask] = {}
        self.next_task_id = 1
        self._load_tasks()

    # ─────────────────────────────────────────────────────
    # Process scanning
    # ─────────────────────────────────────────────────────

    def scan(self):
        """Read process list from ps. Updates self.processes."""
        try:
            r = subprocess.run(
                ["ps", "-eo", "pid,user,pcpu,comm,args"],
                capture_output=True, timeout=5,
            )
            if r.returncode != 0:
                return
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return

        text = r.stdout.decode("utf-8", errors="ignore")
        lines = text.splitlines()

        new_procs = {}
        for line in lines[1:]:
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            try:
                pid = int(parts[0])
                user = parts[1]
                cpu = float(parts[2])
                comm = parts[3]
                args = parts[4]
            except (ValueError, IndexError):
                continue

            # Skip zombies
            combined = (comm + " " + args).lower()
            if "defunct" in combined:
                continue

            cat = classify_process(comm, args)

            # Filter self-measuring tools. Be precise: only zero out
            # the tool itself, not all instances of "python" etc.
            base = comm.split()[0].split("/")[-1].lower()
            args_lower = args.lower()

            is_self = (pid == os.getpid())
            is_ps = (base == "ps")
            is_task_mgr = ("task_manager" in args_lower)
            is_pure_tool = base in ("top", "grep", "tail", "head", "awk", "sed")

            if is_self or is_ps or is_task_mgr or is_pure_tool:
                cpu = 0.0

            info = ProcessInfo(
                pid=pid,
                name=comm,
                args=args,
                user=user,
                cpu_pct=cpu,
                category=cat,
                frozen=(pid in self.frozen_pids),
            )
            new_procs[pid] = info

        self.processes = new_procs

    # ─────────────────────────────────────────────────────
    # Filtering
    # ─────────────────────────────────────────────────────

    def by_category(self, category: str) -> List[ProcessInfo]:
        return [p for p in self.processes.values()
                if p.category == category]

    def by_name(self, name: str) -> List[ProcessInfo]:
        name_lower = name.lower()
        return [p for p in self.processes.values()
                if name_lower in p.name.lower()
                or name_lower in p.args.lower()]

    def top_cpu(self, n: int = 10) -> List[ProcessInfo]:
        return sorted(self.processes.values(),
                     key=lambda p: -p.cpu_pct)[:n]

    def all_sorted(self) -> List[ProcessInfo]:
        return sorted(self.processes.values(),
                     key=lambda p: (p.category, -p.cpu_pct))

    # ─────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────

    def stats(self) -> dict:
        cat_counts = {}
        for p in self.processes.values():
            cat_counts[p.category] = cat_counts.get(p.category, 0) + 1

        total_cpu = sum(p.cpu_pct for p in self.processes.values())
        return {
            "total": len(self.processes),
            "frozen": len(self.frozen_pids),
            "scheduled": len(self.scheduled),
            "by_category": cat_counts,
            "total_cpu": round(total_cpu, 1),
        }

    # ─────────────────────────────────────────────────────
    # Process actions
    # ─────────────────────────────────────────────────────

    def freeze(self, pid: int) -> tuple:
        """Send SIGSTOP to a process."""
        if pid not in self.processes:
            return False, "process not found"
        if pid in self.frozen_pids:
            return False, "already frozen"
        try:
            os.kill(pid, signal.SIGSTOP)
            self.frozen_pids.add(pid)
            self._log("freeze", pid,
                     self.processes[pid].name, "ok")
            return True, "frozen"
        except ProcessLookupError:
            return False, "process died"
        except PermissionError:
            return False, "permission denied"
        except Exception as e:
            return False, f"error: {e}"

    def thaw(self, pid: int) -> tuple:
        """Send SIGCONT to a process."""
        if pid not in self.frozen_pids:
            return False, "not frozen"
        try:
            os.kill(pid, signal.SIGCONT)
            self.frozen_pids.discard(pid)
            name = (self.processes[pid].name
                   if pid in self.processes else "?")
            self._log("thaw", pid, name, "ok")
            return True, "thawed"
        except ProcessLookupError:
            self.frozen_pids.discard(pid)
            return False, "process died"
        except Exception as e:
            return False, f"error: {e}"

    def kill(self, pid: int, force: bool = False,
             dry_run: bool = False) -> tuple:
        """Kill a process. Returns (success, message)."""
        if pid not in self.processes:
            return False, "process not found"

        name = self.processes[pid].name
        sig = signal.SIGKILL if force else signal.SIGTERM

        if dry_run:
            return True, f"would send {sig.name} to {name} (pid {pid})"

        try:
            os.kill(pid, sig)
            self._log("kill", pid, name,
                     "sigkill" if force else "sigterm")
            return True, f"sent {sig.name} to {name} (pid {pid})"
        except ProcessLookupError:
            return False, "process died"
        except PermissionError:
            return False, "permission denied"
        except Exception as e:
            return False, f"error: {e}"

    def batch_freeze(self, category: str) -> tuple:
        """Freeze all processes in a category."""
        targets = self.by_category(category)
        if not targets:
            return 0, "no processes in category"

        frozen = 0
        for p in targets:
            ok, _ = self.freeze(p.pid)
            if ok:
                frozen += 1
        return frozen, f"froze {frozen}/{len(targets)} in {category}"

    def batch_thaw_all(self) -> tuple:
        """Thaw all frozen processes."""
        if not self.frozen_pids:
            return 0, "none frozen"
        count = 0
        for pid in list(self.frozen_pids):
            ok, _ = self.thaw(pid)
            if ok:
                count += 1
        return count, f"thawed {count}"

    def _log(self, action: str, pid: int,
             name: str, result: str):
        record = {
            "ts": int(time.time() * 1000),
            "action": action,
            "pid": pid,
            "name": name,
            "result": result,
        }
        try:
            with open(TASKS_LOG, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass

    # ─────────────────────────────────────────────────────
    # Scheduled tasks
    # ─────────────────────────────────────────────────────

    def _load_tasks(self):
        try:
            with open(TASKS_FILE) as f:
                d = json.load(f)
            for task_id_str, t_dict in d.get("tasks", {}).items():
                task = ScheduledTask.from_dict(t_dict)
                self.scheduled[task.task_id] = task
                if task.task_id >= self.next_task_id:
                    self.next_task_id = task.task_id + 1
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _save_tasks(self):
        with open(TASKS_FILE, "w") as f:
            json.dump({
                "tasks": {str(t.task_id): t.to_dict()
                         for t in self.scheduled.values()},
                "next_id": self.next_task_id,
            }, f, indent=2)

    def add_task(self, name: str, command: List[str],
                 interval_s: int) -> ScheduledTask:
        task = ScheduledTask(
            task_id=self.next_task_id,
            name=name,
            command=command,
            interval_s=interval_s,
            created=int(time.time()),
        )
        self.next_task_id += 1
        self.scheduled[task.task_id] = task
        self._save_tasks()
        return task

    def remove_task(self, task_id: int) -> bool:
        if task_id in self.scheduled:
            del self.scheduled[task_id]
            self._save_tasks()
            return True
        return False

    def enable_task(self, task_id: int, enabled: bool) -> bool:
        if task_id in self.scheduled:
            self.scheduled[task_id].enabled = enabled
            self._save_tasks()
            return True
        return False

    def run_due_tasks(self) -> List[dict]:
        """Run all tasks that are due. Returns results."""
        now = time.time()
        results = []

        for task in list(self.scheduled.values()):
            if not task.is_due(now):
                continue
            result = self._run_task(task)
            results.append(result)

        return results

    def _run_task(self, task: ScheduledTask) -> dict:
        try:
            r = subprocess.run(
                task.command,
                capture_output=True,
                timeout=60,
            )
            task.last_run = int(time.time())
            task.run_count += 1
            if r.returncode == 0:
                outcome = "ok"
            else:
                task.fail_count += 1
                outcome = f"exit {r.returncode}"
        except subprocess.TimeoutExpired:
            task.last_run = int(time.time())
            task.run_count += 1
            task.fail_count += 1
            outcome = "timeout"
        except FileNotFoundError:
            task.last_run = int(time.time())
            task.fail_count += 1
            outcome = "command not found"
        except Exception as e:
            task.last_run = int(time.time())
            task.fail_count += 1
            outcome = f"error: {str(e)[:30]}"

        self._save_tasks()

        return {
            "task_id": task.task_id,
            "name": task.name,
            "outcome": outcome,
        }

    def list_tasks(self) -> List[ScheduledTask]:
        return sorted(self.scheduled.values(),
                     key=lambda t: t.task_id)


# ==============================================================
# Display helpers
# ==============================================================

def print_header(title: str):
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def print_processes(procs: List[ProcessInfo], title: str):
    print_header(title)
    if not procs:
        print("  (no processes)")
        return
    print()
    print(f"  {'PID':>6}  {'NAME':<24} {'CPU':>6}  {'CATEGORY':<12} TRUST")
    print("  " + "-" * 62)
    for p in procs[:30]:
        state = "F" if p.frozen else " "
        nm = p.short_name().ljust(22)
        print(f"  {p.pid:>6} {state} {nm} "
              f"{p.cpu_pct:>5.1f}%  {p.category:<12} {p.trust}")


def print_stats(stats: dict):
    print_header("Statistics")
    print()
    print(f"  Total processes : {stats['total']}")
    print(f"  Frozen          : {stats['frozen']}")
    print(f"  Scheduled tasks : {stats['scheduled']}")
    print(f"  Total CPU       : {stats['total_cpu']}%")
    print()
    print("  By category:")
    for cat, count in sorted(stats["by_category"].items()):
        print(f"    {cat:<15} {count}")


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
OMEGA Task Manager

Usage:
  python task_manager.py list           list all processes
  python task_manager.py top            top CPU processes
  python task_manager.py stats          show stats
  python task_manager.py category NAME  show processes of a category
  python task_manager.py freeze PID     freeze a process
  python task_manager.py thaw PID       thaw a process
  python task_manager.py kill PID       kill (SIGTERM)
  python task_manager.py kill -9 PID    force kill (SIGKILL)
  python task_manager.py tasks          list scheduled tasks
  python task_manager.py demo           run demo
  python task_manager.py help           this message
""")


def cli_list(tm: TaskManager):
    tm.scan()
    print_processes(tm.all_sorted(), "All Processes")


def cli_top(tm: TaskManager):
    tm.scan()
    print_processes(tm.top_cpu(15), "Top 15 by CPU")


def cli_stats(tm: TaskManager):
    tm.scan()
    print_stats(tm.stats())


def cli_category(tm: TaskManager, name: str):
    tm.scan()
    procs = tm.by_category(name.upper())
    print_processes(procs, f"Category: {name}")


def cli_freeze(tm: TaskManager, pid_str: str):
    try:
        pid = int(pid_str)
    except ValueError:
        print(f"[!] invalid PID: {pid_str}")
        return
    tm.scan()
    ok, msg = tm.freeze(pid)
    print(f"  {'[OK]' if ok else '[FAIL]'} {msg}")


def cli_thaw(tm: TaskManager, pid_str: str):
    try:
        pid = int(pid_str)
    except ValueError:
        print(f"[!] invalid PID: {pid_str}")
        return
    tm.scan()
    ok, msg = tm.thaw(pid)
    print(f"  {'[OK]' if ok else '[FAIL]'} {msg}")


def cli_kill(tm: TaskManager, args: List[str]):
    force = False
    if "-9" in args:
        force = True
        args = [a for a in args if a != "-9"]
    if not args:
        print("[!] usage: kill [-9] PID")
        return
    try:
        pid = int(args[0])
    except ValueError:
        print(f"[!] invalid PID: {args[0]}")
        return
    tm.scan()
    ok, msg = tm.kill(pid, force=force)
    print(f"  {'[OK]' if ok else '[FAIL]'} {msg}")


def cli_tasks(tm: TaskManager):
    tasks = tm.list_tasks()
    print_header("Scheduled Tasks")
    if not tasks:
        print("  (no tasks)")
        return
    print()
    print(f"  {'ID':>4}  {'NAME':<25} {'INTERVAL':<10} "
          f"{'RUNS':<6} {'FAILS':<6} ENABLED")
    print("  " + "-" * 68)
    for t in tasks:
        interval = f"{t.interval_s}s"
        if t.interval_s >= 60:
            interval = f"{t.interval_s // 60}m"
        if t.interval_s >= 3600:
            interval = f"{t.interval_s // 3600}h"
        print(f"  {t.task_id:>4}  {t.name:<25} {interval:<10} "
              f"{t.run_count:<6} {t.fail_count:<6} "
              f"{'yes' if t.enabled else 'no'}")


# ==============================================================
# Demo
# ==============================================================

def demo():
    tm = TaskManager()
    tm.scan()
    print_processes(tm.top_cpu(15), "Top 15 by CPU")
    print_stats(tm.stats())

    # Demo: freeze a test process
    print_header("Demo: Freeze/Thaw")
    print()
    # Start a sleep process
    proc = subprocess.Popen(["sleep", "300"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    tm.scan()

    print(f"  Started 'sleep 300' with PID {proc.pid}")
    ok, msg = tm.freeze(proc.pid)
    print(f"  Freeze: {'[OK]' if ok else '[FAIL]'} {msg}")
    time.sleep(0.5)

    ok, msg = tm.thaw(proc.pid)
    print(f"  Thaw:   {'[OK]' if ok else '[FAIL]'} {msg}")

    ok, msg = tm.kill(proc.pid)
    print(f"  Kill:   {'[OK]' if ok else '[FAIL]'} {msg}")

    print()
    print(f"  Frozen PIDs remaining: {len(tm.frozen_pids)}")
    print()


def main():
    if len(sys.argv) < 2:
        cli_help()
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]
    tm = TaskManager()

    if cmd == "help" or cmd == "-h" or cmd == "--help":
        cli_help()
    elif cmd == "list":
        cli_list(tm)
    elif cmd == "top":
        cli_top(tm)
    elif cmd == "stats":
        cli_stats(tm)
    elif cmd == "category":
        if not args:
            print("[!] usage: category NAME")
        else:
            cli_category(tm, args[0])
    elif cmd == "freeze":
        if not args:
            print("[!] usage: freeze PID")
        else:
            cli_freeze(tm, args[0])
    elif cmd == "thaw":
        if not args:
            print("[!] usage: thaw PID")
        else:
            cli_thaw(tm, args[0])
    elif cmd == "kill":
        cli_kill(tm, args)
    elif cmd == "tasks":
        cli_tasks(tm)
    elif cmd == "run-due":
        results = tm.run_due_tasks()
        if not results:
            print("(no tasks due)")
        else:
            for r in results:
                print(f"  [{r['task_id']}] {r['name']}: {r['outcome']}")
    elif cmd == "demo":
        demo()
    else:
        print(f"[!] unknown command: {cmd}")
        cli_help()


if __name__ == "__main__":
    main()
