# ==============================================================
# OMEGA OS - CPU Scheduler
# ==============================================================
# Section 3.2 of the OMEGA spec.
# Task classes with AI priority scores.
# ==============================================================

from enum import IntEnum
from dataclasses import dataclass
from typing import List, Dict


class TaskClass(IntEnum):
    RT          = 0
    INTERACTIVE = 1
    BEST_EFFORT = 2
    BACKGROUND  = 3
    FROZEN      = 4


BASE_PRIORITY = {
    TaskClass.RT:          240,
    TaskClass.INTERACTIVE: 180,
    TaskClass.BEST_EFFORT: 120,
    TaskClass.BACKGROUND:   60,
    TaskClass.FROZEN:        0,
}


@dataclass
class Task:
    pid: int
    name: str
    cls: TaskClass = TaskClass.BEST_EFFORT
    ai_score: int = 0
    cpu_pct: float = 0.0
    wait_time: float = 0.0

    # AI bonus is capped so it can NEVER push a task into a
    # higher class's range. RT > INTERACTIVE gap = 60, so bonus < 60.
    AI_BONUS_CAP = 30

    def priority(self) -> int:
        if self.cls == TaskClass.FROZEN:
            return 0
        bonus = min(self.AI_BONUS_CAP, self.ai_score // 4)
        return BASE_PRIORITY[self.cls] + bonus


class Scheduler:
    def __init__(self, core_count: int = 8):
        self.core_count = core_count
        self.cores: List[List[int]] = [[] for _ in range(core_count)]
        self.tasks: Dict[int, Task] = {}
        self.dispatched = 0

    def add(self, task: Task):
        self.tasks[task.pid] = task

    def remove(self, pid: int):
        self.tasks.pop(pid, None)
        for c in self.cores:
            if pid in c:
                c.remove(pid)

    def set_class(self, pid: int, cls: TaskClass, ai_score: int = 0):
        if pid in self.tasks:
            self.tasks[pid].cls = cls
            self.tasks[pid].ai_score = max(0, min(255, ai_score))

    def schedule(self) -> List[dict]:
        runnable = [t for t in self.tasks.values()
                    if t.cls != TaskClass.FROZEN]
        runnable.sort(key=lambda t: -t.priority())

        for c in self.cores:
            c.clear()

        assignments = []
        for i, task in enumerate(runnable):
            core = i % self.core_count
            self.cores[core].append(task.pid)
            task.wait_time = 0.0
            assignments.append({
                "pid": task.pid,
                "name": task.name,
                "cls": task.cls.name,
                "priority": task.priority(),
                "core": core,
            })
            self.dispatched += 1

        dispatched_pids = {a["pid"] for a in assignments}
        for t in self.tasks.values():
            if t.pid not in dispatched_pids:
                t.wait_time += 1.0

        return assignments

    def snapshot(self) -> dict:
        by_cls = {}
        for t in self.tasks.values():
            by_cls[t.cls.name] = by_cls.get(t.cls.name, 0) + 1
        return {
            "total_tasks": len(self.tasks),
            "dispatched": self.dispatched,
            "by_class": by_cls,
        }


if __name__ == "__main__":
    s = Scheduler(8)
    s.add(Task(1,  "game_main",       TaskClass.INTERACTIVE, 200))
    s.add(Task(2,  "audio_server",    TaskClass.RT,          255))
    s.add(Task(3,  "background_sync", TaskClass.BACKGROUND,   30))
    s.add(Task(4,  "browser",         TaskClass.BEST_EFFORT, 100))
    s.add(Task(5,  "old_app",         TaskClass.FROZEN,        0))

    print("=" * 70)
    print("  OMEGA Scheduler - Task Dispatch")
    print("=" * 70)
    print()
    print(f"{'PID':<5} {'NAME':<20} {'CLASS':<14} "
          f"{'PRIO':<6} {'CORE':<5}")
    print("-" * 70)
    for a in s.schedule():
        print(f"{a['pid']:<5} {a['name']:<20} {a['cls']:<14} "
              f"{a['priority']:<6} {a['core']:<5}")
    print()
    print("Snapshot:", s.snapshot())
