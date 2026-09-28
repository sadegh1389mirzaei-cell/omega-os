# ==============================================================
# OMEGA OS - Comprehensive Test Suite
# ==============================================================
# Tests every module with fake/synthetic data.
# Uses only stdlib (unittest, tempfile, json, ...).
# Run: python test_suite.py
#      python test_suite.py -v            (verbose)
#      python test_suite.py DecisionTests (only one class)
# ==============================================================

import os
import sys
import json
import time
import tempfile
import shutil
import unittest
from unittest.mock import patch
from dataclasses import dataclass

OMEGA_DIR = os.path.dirname(os.path.abspath(__file__))
if OMEGA_DIR not in sys.path:
    sys.path.insert(0, OMEGA_DIR)


# ==============================================================
# Fake data factory
# ==============================================================

def make_input(**overrides):
    """Create a synthetic InputVector with sensible defaults."""
    from omega import InputVector
    iv = InputVector()
    iv.timestamp_ms = int(time.time() * 1000)
    iv.cpu_core_count = 8
    iv.cpu_util_percent = [10, 10, 10, 10, 10, 10, 10, 10]
    iv.cpu_freq_percent = [50, 50, 50, 50, 50, 50, 50, 50]
    iv.gpu_util_percent = 5
    iv.gpu_freq_mhz = 200
    iv.ram_pressure_percent = 40
    iv.ram_used_mb = 2000
    iv.ram_available_mb = 2000
    iv.battery_percent = 80
    iv.power_source = 0          # BATTERY
    iv.temp_soc_c = 320          # 32.0C
    iv.temp_skin_c = 300
    iv.temp_gpu_c = 300
    iv.external_displays = 0
    iv.keyboard_connected = 0
    iv.mouse_connected = 0
    iv.foreground_workload = 0   # IDLE
    iv.security_threat_level = 0
    iv.low_power_threshold = 15

    for k, v in overrides.items():
        setattr(iv, k, v)
    return iv


# ==============================================================
# 1. Decision Engine (omega.py)
# ==============================================================

class DecisionEngineTests(unittest.TestCase):

    def setUp(self):
        from omega import Config, DecisionEngine
        self.cfg = Config()
        self.eng = DecisionEngine(self.cfg)

    def _state_name(self, cmd):
        from omega import PerformanceState
        return PerformanceState(cmd.performance_state).name

    def _tier_name(self, cmd):
        from omega import PowerTier
        return PowerTier(cmd.power_tier).name

    def _thermal_name(self, cmd):
        from omega import ThermalState
        return ThermalState(cmd.thermal_state).name

    def test_idle_when_no_workload(self):
        from omega import PerformanceState
        iv = make_input(foreground_workload=0)
        cmd = self.eng.evaluate(iv)
        self.assertEqual(self._state_name(cmd), "IDLE")

    def test_gaming_goes_performance(self):
        from omega import WorkloadClass
        iv = make_input(
            foreground_workload=int(WorkloadClass.GAMING_HEAVY),
            gpu_util_percent=90, gpu_freq_mhz=900, temp_soc_c=380,
        )
        cmd = self.eng.evaluate(iv)
        self.assertEqual(self._state_name(cmd), "PERFORMANCE")

    def test_low_battery_forces_low_power_tier(self):
        iv = make_input(battery_percent=10, power_source=0)
        cmd = self.eng.evaluate(iv)
        self.assertEqual(self._tier_name(cmd), "LOW_POWER")
        # LOW_POWER caps CPU to 50%
        self.assertLessEqual(cmd.cpu_max_freq_percent, 50)

    def test_critical_battery_emergency(self):
        iv = make_input(battery_percent=3, power_source=0)
        cmd = self.eng.evaluate(iv)
        self.assertEqual(self._tier_name(cmd), "EMERGENCY")
        self.assertEqual(self._state_name(cmd), "IDLE")

    def test_thermal_emergency_forces_idle(self):
        iv = make_input(temp_soc_c=520)   # 52.0C
        cmd = self.eng.evaluate(iv)
        self.assertEqual(self._thermal_name(cmd), "EMERGENCY")
        self.assertEqual(self._state_name(cmd), "IDLE")

    def test_thermal_warning_caps_but_keeps_state(self):
        from omega import WorkloadClass
        iv = make_input(
            foreground_workload=int(WorkloadClass.GAMING_HEAVY),
            temp_soc_c=440,   # 44C → WARNING
            gpu_util_percent=90,
        )
        cmd = self.eng.evaluate(iv)
        self.assertEqual(self._thermal_name(cmd), "WARNING")
        self.assertLessEqual(cmd.cpu_max_freq_percent, 80)

    def test_charger_connected_exits_low_power(self):
        # Start in LOW_POWER
        iv1 = make_input(battery_percent=10, power_source=0)
        self.eng.evaluate(iv1)
        # Plug in charger
        iv2 = make_input(battery_percent=10, power_source=1)
        cmd = self.eng.evaluate(iv2)
        self.assertEqual(self._tier_name(cmd), "NORMAL")

    def test_hysteresis_prevents_flapping(self):
        """Rapid switching shouldn't change state more than once."""
        from omega import WorkloadClass
        # First: force PERFORMANCE
        iv1 = make_input(
            foreground_workload=int(WorkloadClass.GAMING_HEAVY),
            gpu_util_percent=90,
        )
        cmd1 = self.eng.evaluate(iv1)
        state1 = self._state_name(cmd1)

        # Immediately switch to idle — should NOT change (hysteresis)
        iv2 = make_input(foreground_workload=0, gpu_util_percent=5)
        cmd2 = self.eng.evaluate(iv2)
        state2 = self._state_name(cmd2)

        # With hysteresis, second decision should still be PERFORMANCE
        # (or at least not immediately IDLE)
        self.assertNotEqual(state2, "IDLE",
                            "Hysteresis failed: state changed too fast")

    def test_desktop_never_idle(self):
        iv = make_input(
            external_displays=1, keyboard_connected=1, mouse_connected=1,
            foreground_workload=0,
        )
        cmd = self.eng.evaluate(iv)
        self.assertNotEqual(self._state_name(cmd), "IDLE")


# ==============================================================
# 2. Security AI
# ==============================================================

class SecurityAITests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        from security_ai import SecurityAI
        self.sec = SecurityAI(state_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_netcat_pattern_detected(self):
        from security_ai import Process
        p = Process(pid=1234, user="u0", comm="nc",
                    args="nc -l 9999", cpu_percent=0.0)
        # ProcessWatcher should flag this
        # Force first scan to be complete
        self.sec.process_watcher.first_scan = False
        self.sec.process_watcher.known_pids = set()

        events = self.sec.process_watcher.scan([p])
        reasons = [r for r, _, _ in events]
        self.assertIn("netcat_listener", reasons)

    def test_safe_process_not_flagged(self):
        from security_ai import Process
        p = Process(pid=100, user="u0", comm="python",
                    args="python test.py", cpu_percent=5.0)
        self.sec.process_watcher.first_scan = False
        self.sec.process_watcher.known_pids = set()

        events = self.sec.process_watcher.scan([p])
        self.assertEqual(len(events), 0)

    def test_trust_score_adjusts(self):
        from security_ai import TrustStore
        t = TrustStore(os.path.join(self.tmp, "trust.json"))
        t.set("app1", 50)
        t.adjust("app1", -20)
        self.assertEqual(t.get("app1"), 30)
        t.adjust("app1", -100)   # should floor at 0
        self.assertEqual(t.get("app1"), 0)

    def test_incident_log_persists(self):
        from security_ai import Incident, IncidentLogger
        logger = IncidentLogger(os.path.join(self.tmp, "inc.jsonl"))
        logger.log(Incident(ts=1000, severity="HIGH",
                            category="process", subject="nc",
                            detail="netcat listener"))
        logger.log(Incident(ts=2000, severity="LOW",
                            category="file", subject=".zshrc",
                            detail="modified"))
        self.assertEqual(logger.count(), 2)
        tail = logger.tail(5)
        self.assertEqual(tail[0]["severity"], "HIGH")

    def test_threat_level_recompute(self):
        sec = self.sec
        sec.recent.clear()
        sec._recompute_threat_level()
        self.assertEqual(sec.threat_level, "NORMAL")

        from security_ai import Incident
        sec.recent.append({
            "ts": 1, "severity": "HIGH", "category": "process",
            "subject": "nc", "detail": "x", "action": "logged",
        })
        sec._recompute_threat_level()
        self.assertEqual(sec.threat_level, "HIGH")


# ==============================================================
# 3. Personal AI
# ==============================================================

class PersonalAITests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "bus.jsonl")
        self.model = os.path.join(self.tmp, "model.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_event(self, ts, topic, **payload):
        from bus import Event
        e = Event(ts=ts, topic=topic, source="test", payload=payload)
        with open(self.log, "a") as f:
            f.write(e.to_jsonl() + "\n")

    def test_ingest_telemetry_events(self):
        from bus import Topic
        now = int(time.time() * 1000)
        for i in range(10):
            self._write_event(now + i * 100,
                             Topic.TELEMETRY_SAMPLE,
                             workload="LIGHT", battery=75)
        from personal_ai import PersonalAI
        ai = PersonalAI(log_path=self.log, model_path=self.model)
        n = ai.ingest_log(incremental=False)
        self.assertGreater(n, 0)
        self.assertGreater(ai.model.total_samples, 0)

    def test_ignores_boot_workload(self):
        from bus import Topic
        now = int(time.time() * 1000)
        self._write_event(now, Topic.TELEMETRY_SAMPLE,
                         workload="BOOT", battery=80)
        from personal_ai import PersonalAI
        ai = PersonalAI(log_path=self.log, model_path=self.model)
        ai.ingest_log(incremental=False)
        # BOOT should not appear in any workload map
        for hour_map in ai.model.workload_by_hour.values():
            self.assertNotIn("BOOT", hour_map)

    def test_predict_returns_known_workload(self):
        from bus import Topic
        now = int(time.time() * 1000)
        for i in range(20):
            self._write_event(now + i, Topic.TELEMETRY_SAMPLE,
                             workload="COMPUTE", battery=70)
        from personal_ai import PersonalAI
        ai = PersonalAI(log_path=self.log, model_path=self.model)
        ai.ingest_log(incremental=False)
        wl, conf = ai.predict(now)
        self.assertEqual(wl, "COMPUTE")
        self.assertGreater(conf, 0)

    def test_no_charge_suggestion_without_data(self):
        from personal_ai import PersonalAI
        ai = PersonalAI(log_path=self.log, model_path=self.model)
        sugs = ai.suggest(battery=20, on_battery=True, workload="LIGHT")
        charge_sugs = [s for s in sugs if s.kind == "charge"]
        self.assertEqual(len(charge_sugs), 0)


# ==============================================================
# 4. Modes (Section 7)
# ==============================================================

class ModesTests(unittest.TestCase):

    def setUp(self):
        from modes import ModeManager, DeviceMode, PerfState, PowerTier
        self.mm = ModeManager()
        self.ModeManager = ModeManager
        self.DeviceMode = DeviceMode
        self.PerfState = PerfState
        self.PowerTier = PowerTier
        # Bypass hysteresis for tests
        self.mm.MIN_STATE_DURATION = 0.0

    def test_initial_state(self):
        from modes import DeviceMode, PerfState
        self.assertEqual(self.mm.mode.device, DeviceMode.PHONE)
        self.assertEqual(self.mm.mode.perf, PerfState.IDLE)

    def test_ext_display_triggers_desktop(self):
        from modes import Trigger, DeviceMode
        self.mm.apply_trigger(Trigger.EXT_DISPLAY_CONNECTED,
                              keyboard=True, mouse=True)
        self.assertEqual(self.mm.mode.device, DeviceMode.DESKTOP)

    def test_ext_display_only_triggers_tablet(self):
        from modes import Trigger, DeviceMode
        self.mm.apply_trigger(Trigger.EXT_DISPLAY_CONNECTED,
                              keyboard=False, mouse=False)
        self.assertEqual(self.mm.mode.device, DeviceMode.TABLET)

    def test_battery_low_triggers_low_power(self):
        from modes import Trigger, PowerTier
        self.mm.apply_trigger(Trigger.BATTERY_LOW)
        self.assertEqual(self.mm.mode.power, PowerTier.LOW_POWER)

    def test_thermal_critical_forces_idle(self):
        from modes import Trigger, PerfState, ThermalState
        self.mm.apply_trigger(Trigger.TEMP_CRITICAL)
        self.assertEqual(self.mm.mode.thermal, ThermalState.EMERGENCY)
        self.assertEqual(self.mm.mode.perf, PerfState.IDLE)

    def test_heavy_app_goes_performance(self):
        from modes import Trigger, PerfState
        self.mm.apply_trigger(Trigger.HEAVY_APP_LAUNCHED,
                              workload="GAMING_HEAVY")
        self.assertEqual(self.mm.mode.perf, PerfState.PERFORMANCE)

    def test_thermal_cooldown_requires_time(self):
        from modes import ThermalState, Trigger
        # Set to EMERGENCY
        self.mm.apply_trigger(Trigger.TEMP_CRITICAL)
        self.assertEqual(self.mm.mode.thermal, ThermalState.EMERGENCY)
        # Try immediate cooldown — should be blocked
        ok = self.mm.set_thermal(ThermalState.NORMAL, "test cooldown")
        self.assertFalse(ok, "cooldown should require time")

    def test_evaluate_from_input(self):
        from modes import DeviceMode, PowerTier
        iv = make_input(
            external_displays=1, keyboard_connected=1, mouse_connected=1,
            battery_percent=10, power_source=0,
            temp_soc_c=420,
        )
        self.mm.evaluate(iv)
        self.assertEqual(self.mm.mode.device, DeviceMode.DESKTOP)
        self.assertEqual(self.mm.mode.power, PowerTier.LOW_POWER)


# ==============================================================
# 5. Scheduler
# ==============================================================

class SchedulerTests(unittest.TestCase):

    def setUp(self):
        from scheduler import Scheduler
        self.s = Scheduler(core_count=4)

    def test_rt_has_highest_priority(self):
        from scheduler import Task, TaskClass
        self.s.add(Task(1, "rt_task", TaskClass.RT, 0))
        self.s.add(Task(2, "user_task", TaskClass.INTERACTIVE, 255))
        assignments = self.s.schedule()
        # RT should come first
        self.assertEqual(assignments[0]["name"], "rt_task")

    def test_frozen_not_dispatched(self):
        from scheduler import Task, TaskClass
        self.s.add(Task(1, "active", TaskClass.BEST_EFFORT, 0))
        self.s.add(Task(2, "frozen", TaskClass.FROZEN, 0))
        assignments = self.s.schedule()
        names = [a["name"] for a in assignments]
        self.assertIn("active", names)
        self.assertNotIn("frozen", names)

    def test_priority_ordering(self):
        from scheduler import Task, TaskClass
        self.s.add(Task(1, "background", TaskClass.BACKGROUND, 0))
        self.s.add(Task(2, "interactive", TaskClass.INTERACTIVE, 0))
        assignments = self.s.schedule()
        prio = {a["name"]: a["priority"] for a in assignments}
        self.assertGreater(prio["interactive"], prio["background"])

    def test_set_class_updates(self):
        from scheduler import Task, TaskClass
        self.s.add(Task(1, "app", TaskClass.BEST_EFFORT, 0))
        self.s.set_class(1, TaskClass.INTERACTIVE, 100)
        self.assertEqual(self.s.tasks[1].cls, TaskClass.INTERACTIVE)
        self.assertEqual(self.s.tasks[1].ai_score, 100)


# ==============================================================
# 6. Capabilities
# ==============================================================

class CapabilityTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        from capabilities import CapabilityStore, Cap
        self.store = CapabilityStore(os.path.join(self.tmp, "caps.json"))
        self.Cap = Cap

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_new_process_has_no_caps(self):
        self.store.register(100, "test_app")
        self.assertFalse(self.store.check(100, self.Cap.CAMERA))

    def test_grant_then_check_passes(self):
        self.store.register(100, "test_app")
        self.store.grant(100, self.Cap.CAMERA)
        self.assertTrue(self.store.check(100, self.Cap.CAMERA))

    def test_revoke_removes_cap(self):
        self.store.register(100, "test_app")
        self.store.grant(100, self.Cap.CAMERA)
        self.store.revoke(100, self.Cap.CAMERA)
        self.assertFalse(self.store.check(100, self.Cap.CAMERA))

    def test_unknown_cap_rejected(self):
        self.store.register(100, "test_app")
        ok = self.store.grant(100, "INVALID_CAP")
        self.assertFalse(ok)

    def test_unknown_pid_rejected(self):
        ok = self.store.grant(999, self.Cap.CAMERA)
        self.assertFalse(ok)
        self.assertFalse(self.store.check(999, self.Cap.CAMERA))


# ==============================================================
# 7. OMFS
# ==============================================================

class OMFSTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        from omfs import OMFS
        self.omfs = OMFS(root=os.path.join(self.tmp, "storage"))
        # Create a couple of fake files
        self.f1 = os.path.join(self.tmp, "report.pdf")
        self.f2 = os.path.join(self.tmp, "report.docx")
        with open(self.f1, "w") as f:
            f.write("PDF DATA")
        with open(self.f2, "w") as f:
            f.write("DOCX DATA")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_project(self):
        p = self.omfs.create_project("Q3", "Q3 work")
        self.assertEqual(p.name, "Q3")
        self.assertIn("Q3", self.omfs.projects)

    def test_add_file(self):
        entry = self.omfs.add_file(self.f1, "Q3")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.project, "Q3")
        self.assertEqual(entry.category, "document")

    def test_tags_from_filename(self):
        entry = self.omfs.add_file(self.f1, "Q3")
        # "report" is semantic keyword
        self.assertIn("report", entry.tags)
        self.assertIn("document", entry.tags)

    def test_variant_relationship(self):
        e1 = self.omfs.add_file(self.f1, "Q3")
        e2 = self.omfs.add_file(self.f2, "Q3")
        # report.pdf and report.docx → variant_of
        # Check graph
        related = self.omfs.graph.get(e1.path, [])
        kinds = [r.split(":")[0] for r in related]
        self.assertTrue(any("variant" in k or "related" in k for k in kinds),
                        f"expected variant/related, got {kinds}")

    def test_search_by_query(self):
        self.omfs.add_file(self.f1, "Q3")
        hits = self.omfs.search(query="report")
        self.assertGreater(len(hits), 0)

    def test_search_by_category(self):
        self.omfs.add_file(self.f1, "Q3")
        hits = self.omfs.search(category="document")
        self.assertEqual(len(hits), 1)

    def test_stats(self):
        self.omfs.add_file(self.f1, "Q3")
        self.omfs.add_file(self.f2, "Personal")
        s = self.omfs.stats()
        self.assertEqual(s["files"], 2)
        self.assertEqual(s["projects"], 2)


# ==============================================================
# 8. Virtual FS
# ==============================================================

class VirtualFSTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        from omfs import OMFS
        from virtual_fs import VirtualFS
        self.omfs = OMFS(root=os.path.join(self.tmp, "storage"))
        self.vfs = VirtualFS(self.omfs)

        f = os.path.join(self.tmp, "test.py")
        with open(f, "w") as fp:
            fp.write("print()")
        self.omfs.add_file(f, "Dev")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_root_has_three_views(self):
        items = self.vfs.list("/")
        names = [n for n, k in items]
        self.assertIn("projects", names)
        self.assertIn("category", names)
        self.assertIn("tags", names)

    def test_list_projects(self):
        items = self.vfs.list("/projects")
        names = [n for n, k in items]
        self.assertIn("Dev", names)

    def test_normalize_removes_dotdot(self):
        from virtual_fs import VirtualFS
        self.assertEqual(VirtualFS.normalize("/a/b/../c"), "/a/c")
        self.assertEqual(VirtualFS.normalize("a//b"), "/a/b")

    def test_resolve_file(self):
        items = self.vfs.list("/projects/Dev")
        names = [n for n, k in items]
        self.assertIn("test.py", names)

        entry = self.vfs.resolve("/projects/Dev/test.py")
        self.assertIsNotNone(entry)

    def test_meta_for_project(self):
        meta = self.vfs.meta_for_path("/projects/Dev")
        self.assertEqual(meta["kind"], "project")
        self.assertEqual(meta["name"], "Dev")


# ==============================================================
# 9. Message Bus
# ==============================================================

class BusTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        from bus import EventBus
        self.bus = EventBus(log_path=os.path.join(self.tmp, "log.jsonl"))
        self.received = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_publish_to_wildcard(self):
        self.bus.subscribe("*", lambda e: self.received.append(e))
        self.bus.emit("test.topic", "test", value=42)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.received[0].payload["value"], 42)

    def test_wildcard_pattern(self):
        self.bus.subscribe("security.*",
                          lambda e: self.received.append(e))
        self.bus.emit("security.threat", "test", subject="nc")
        self.bus.emit("decision.state", "test", state="IDLE")
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.received[0].topic, "security.threat")

    def test_event_json_roundtrip(self):
        from bus import Event
        e = Event(ts=12345, topic="x.y", source="test",
                 payload={"a": 1}, severity="HIGH")
        line = e.to_jsonl()
        e2 = Event.from_jsonl(line)
        self.assertEqual(e.ts, e2.ts)
        self.assertEqual(e.topic, e2.topic)
        self.assertEqual(e.payload, e2.payload)
        self.assertEqual(e.severity, e2.severity)

    def test_log_persists(self):
        self.bus.emit("a.b", "test", x=1)
        self.bus.emit("c.d", "test", x=2)
        with open(self.bus.log_path) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)


# ==============================================================
# 10. Runtime
# ==============================================================

class RuntimeTests(unittest.TestCase):

    def setUp(self):
        from runtime import RuntimeManager, AppProfile, RuntimeType
        self.rm = RuntimeManager()
        self.App = AppProfile
        self.RT = RuntimeType

    def test_native_no_overhead(self):
        app = self.App("test", "App", cpu_mhz=500, memory_mb=200)
        e = self.rm.estimate(app, self.RT.NATIVE)
        self.assertEqual(e.cpu_mhz, 500)
        self.assertEqual(e.memory_mb, 200)

    def test_vm_has_higher_overhead(self):
        app = self.App("test", "App", cpu_mhz=500, memory_mb=200)
        e_native = self.rm.estimate(app, self.RT.NATIVE)
        e_vm = self.rm.estimate(app, self.RT.WINDOWS_VM)
        self.assertGreater(e_vm.cpu_mhz, e_native.cpu_mhz)
        self.assertGreater(e_vm.memory_mb, e_native.memory_mb)

    def test_android_overhead_in_range(self):
        app = self.App("test", "App", cpu_mhz=1000, memory_mb=500)
        e = self.rm.estimate(app, self.RT.ANDROID)
        # CPU mult between 1.15 and 1.35
        self.assertGreaterEqual(e.cpu_mult, 1.15)
        self.assertLessEqual(e.cpu_mult, 1.35)

    def test_recommend_prefers_native(self):
        app = self.App("test", "App")
        available = [self.RT.NATIVE, self.RT.LINUX, self.RT.ANDROID]
        best = self.rm.recommend(app, available)
        self.assertEqual(best, self.RT.NATIVE)

    def test_recommend_skips_missing(self):
        app = self.App("test", "App")
        available = [self.RT.ANDROID, self.RT.LINUX]
        best = self.rm.recommend(app, available)
        # Linux preferred over Android in our rule
        self.assertEqual(best, self.RT.LINUX)


# ==============================================================
# 11. Sync Protocol
# ==============================================================

class SyncTests(unittest.TestCase):

    def setUp(self):
        from sync import SyncEngine, Device, DeviceKind
        self.phone = SyncEngine(Device("ph-1", "Phone", DeviceKind.PHONE))
        self.tablet = SyncEngine(Device("tb-1", "Tablet", DeviceKind.TABLET))
        self.phone.discover(self.tablet.device)
        self.tablet.discover(self.phone.device)
        self.phone.connect("tb-1")
        self.tablet.connect("ph-1")

    def test_discover_peer(self):
        self.assertIn("tb-1", self.phone.peers)
        self.assertIn("ph-1", self.tablet.peers)

    def test_channel_established(self):
        self.assertIn("tb-1", self.phone.channels)
        ch = self.phone.channels["tb-1"]
        self.assertEqual(ch["cipher"], "AES-256-GCM")
        self.assertTrue(ch["forward_secret"])

    def test_clipboard_sync(self):
        self.phone.push_clipboard("text", "hello world")
        self.tablet.clipboard.merge(self.phone.clipboard)
        entry = self.tablet.pull_clipboard()
        self.assertIsNotNone(entry)
        self.assertIn("hello", entry["preview"])

    def test_file_chunking(self):
        data = b"x" * 10000
        self.phone.track_file("big.bin", data)
        sf = self.phone.files["big.bin"]
        self.assertGreater(len(sf.chunks), 1)

    def test_file_sync_dedup(self):
        self.phone.track_file("a.bin", b"a" * 8000)
        self.phone.sync_to(self.tablet)
        first_sent = self.phone.bytes_sent
        # Modify file but keep most chunks same
        self.phone.track_file("a.bin", b"a" * 8000 + b"NEW")
        self.phone.sync_to(self.tablet)
        second_sent = self.phone.bytes_sent - first_sent
        # Should be less than full file (chunks deduped)
        self.assertLess(second_sent, 8000)

    def test_session_handoff(self):
        from sync import SessionState
        s = SessionState(
            app_id="com.test.browser", title="Test",
            uri="http://x.com", scroll=100, cursor=5,
        )
        self.phone.save_session(s)
        ok = self.phone.handoff_to(self.tablet, "com.test.browser")
        self.assertTrue(ok)
        restored = self.tablet.restore_session("com.test.browser")
        self.assertEqual(restored["scroll"], 100)

    def test_crdt_last_writer_wins(self):
        from sync import LWWMap
        a = LWWMap()
        b = LWWMap()
        a.set("k", "A", ts=100)
        b.set("k", "B", ts=200)
        a.merge(b)
        self.assertEqual(a.get("k"), "B")


# ==============================================================
# 12. Package Manager
# ==============================================================

class PackageManagerTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Patch the PKG_DIR constant
        import pkgman
        self._old_dir = pkgman.PKG_DIR
        self._old_index = pkgman.INDEX
        pkgman.PKG_DIR = os.path.join(self.tmp, "packages")
        pkgman.INDEX = os.path.join(pkgman.PKG_DIR, "index.json")

        from pkgman import PackageManager
        self.pm = PackageManager()

    def tearDown(self):
        import pkgman
        pkgman.PKG_DIR = self._old_dir
        pkgman.INDEX = self._old_index
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_package(self):
        p = self.pm.create("com.test.app", "Test App",
                          version="1.0.0", trust=80)
        self.assertEqual(p.app_id, "com.test.app")
        self.assertIn("com.test.app", self.pm.packages)

    def test_remove_package(self):
        self.pm.create("com.test.app", "Test App")
        ok = self.pm.remove("com.test.app")
        self.assertTrue(ok)
        self.assertNotIn("com.test.app", self.pm.packages)

    def test_search_by_name(self):
        self.pm.create("com.omega.mail", "OMEGA Mail")
        self.pm.create("com.other.app", "Other App")
        hits = self.pm.search("mail")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].name, "OMEGA Mail")

    def test_low_trust_filter(self):
        self.pm.create("com.good.app", "Good", trust=90)
        self.pm.create("com.bad.app", "Bad", trust=15)
        low = [p for p in self.pm.packages.values() if p.trust < 40]
        self.assertEqual(len(low), 1)
        self.assertEqual(low[0].app_id, "com.bad.app")

    def test_by_category(self):
        self.pm.create("a", "A", category="productivity")
        self.pm.create("b", "B", category="game")
        self.pm.create("c", "C", category="productivity")
        prod = self.pm.by_category("productivity")
        self.assertEqual(len(prod), 2)


# ==============================================================
# 13. HAL
# ==============================================================

class HALTests(unittest.TestCase):

    def test_cpu_cores_enumerated(self):
        from hal import HAL
        h = HAL()
        s = h.snapshot()
        self.assertGreater(s["core_count"], 0)
        for c in s["cpu"]:
            self.assertIn("id", c)
            self.assertIn("online", c)
            self.assertIn("cur_mhz", c)
            self.assertIn("max_mhz", c)

    def test_snapshot_shape(self):
        from hal import HAL
        h = HAL()
        s = h.snapshot()
        # Legacy keys (backward-compat)
        for key in ("core_count", "cores_online", "battery_pct",
                    "battery_temp_c", "plugged", "thermal_zones"):
            self.assertIn(key, s)
        # New keys
        for key in ("cpu", "cpu_usage", "memory",
                    "thermal_categories", "thermal_raw",
                    "battery", "network"):
            self.assertIn(key, s)

    def test_thermal_zones_are_plausible(self):
        from hal import HAL
        s = HAL().snapshot()
        # Every reported zone should be in a sane range
        for name, t in s["thermal_raw"].items():
            self.assertGreater(t, -20, f"{name} too cold: {t}")
            self.assertLess(t, 150, f"{name} too hot: {t}")

    def test_memory_has_real_values(self):
        from hal import HAL
        s = HAL().snapshot()
        m = s["memory"]
        if m:  # psutil may not be installed
            self.assertGreater(m["total_mb"], 0)
            self.assertGreaterEqual(m["percent"], 0)
            self.assertLessEqual(m["percent"], 100)


# ==============================================================
# 14. Processes / Classifier
# ==============================================================

class ProcessTests(unittest.TestCase):

    def test_classifier_matches_gaming(self):
        from processes import Process, WorkloadClassifier
        procs = [
            Process(1, "u0", "com.miHoYo.game", "", cpu_percent=80),
        ]
        c = WorkloadClassifier()
        wc, conf, _ = c.classify(procs)
        from omega import WorkloadClass
        self.assertEqual(wc, WorkloadClass.GAMING_HEAVY)

    def test_classifier_matches_browser(self):
        from processes import Process, WorkloadClassifier
        procs = [Process(1, "u0", "chrome", "", cpu_percent=10)]
        c = WorkloadClassifier()
        wc, _, _ = c.classify(procs)
        from omega import WorkloadClass
        self.assertEqual(wc, WorkloadClass.WEB)

    def test_classifier_unknown_returns_light(self):
        from processes import Process, WorkloadClassifier
        procs = [Process(1, "u0", "unknown_binary", "", cpu_percent=5)]
        c = WorkloadClassifier()
        wc, _, _ = c.classify(procs)
        from omega import WorkloadClass
        self.assertEqual(wc, WorkloadClass.LIGHT)


# ==============================================================
# Custom runner for pretty output
# ==============================================================

class ColorTextResult(unittest.TextTestResult):
    GREEN = "\033[92m"
    RED   = "\033[91m"
    YELLOW = "\033[93m"
    GRAY  = "\033[90m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"

    def addSuccess(self, test):
        super().addSuccess(test)
        sys.stderr.write(
            f"  {self.GREEN}✓{self.RESET} {test._testMethodName}\n")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        sys.stderr.write(
            f"  {self.RED}✗{self.RESET} {test._testMethodName}\n")

    def addError(self, test, err):
        super().addError(test, err)
        sys.stderr.write(
            f"  {self.RED}E{self.RESET} {test._testMethodName}\n")

    def startTest(self, test):
        super().startTest(test)
        # no-op — we print after result

    def startTestClass(self, cls_name):
        sys.stderr.write(f"\n{self.BOLD}{self.GRAY}{cls_name}{self.RESET}\n")


class ColorTextRunner(unittest.TextTestRunner):

    def _makeResult(self):
        return ColorTextResult(self.stream, self.descriptions,
                              self.verbosity)

    def run(self, test):
        # Print class header
        result = self._makeResult()
        result.failfast = self.failfast
        result.buffer = self.buffer
        result.tb_locals = self.tb_locals

        test(result)
        self._print_summary(result)
        return result

    def _print_summary(self, result):
        sys.stderr.write("\n" + "=" * 66 + "\n")
        sys.stderr.write(f"  Tests run  : {result.testsRun}\n")
        sys.stderr.write(f"  Successes  : "
                        f"{result.testsRun - len(result.failures) - len(result.errors)}\n")
        if result.failures:
            sys.stderr.write(f"  Failures   : {len(result.failures)}\n")
        if result.errors:
            sys.stderr.write(f"  Errors     : {len(result.errors)}\n")

        if result.wasSuccessful():
            sys.stderr.write(
                f"\n  {result.GREEN if hasattr(result, 'GREEN') else ''}"
                f"  ✅  ALL TESTS PASSED{result.RESET if hasattr(result, 'RESET') else ''}\n")
        else:
            sys.stderr.write(f"\n  ❌  SOME TESTS FAILED\n")
        sys.stderr.write("=" * 66 + "\n")


def main():
    loader = unittest.TestLoader()

    # If args given, run only those test classes
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        names = sys.argv[1:]
        suite = unittest.TestSuite()
        for name in names:
            try:
                cls = globals()[name]
                tests = loader.loadTestsFromTestCase(cls)
                suite.addTests(tests)
            except KeyError:
                print(f"[!] Unknown test class: {name}")
                return 1
    else:
        suite = loader.loadTestsFromModule(sys.modules[__name__])

    # Print header
    print()
    print("=" * 66)
    print("  OMEGA OS — Comprehensive Test Suite")
    print("=" * 66)
    print()
    print(f"  Python {sys.version.split()[0]}")
    print(f"  Working dir: {OMEGA_DIR}")
    print()

    runner = ColorTextRunner(verbosity=1, stream=sys.stderr)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
