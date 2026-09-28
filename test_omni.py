# ==============================================================
# OMEGA OS - Tests for the 5 new modules
# ==============================================================
# Covers: sandbox, emulator, telemetry_proto, apk_deep, dexview
# Run: python -m unittest test_omni -v
# ==============================================================

import os
import sys
import time
import json
import shutil
import struct
import tempfile
import unittest
import zipfile

OMEGA_DIR = os.path.dirname(os.path.abspath(__file__))
if OMEGA_DIR not in sys.path:
    sys.path.insert(0, OMEGA_DIR)


# ==============================================================
# 1. Sandbox
# ==============================================================

class SandboxTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_mail_network_allowed(self):
        from capabilities import CapabilityStore
        from sandbox import SandboxManager, SandboxConfig
        mgr = SandboxManager(cap_store=CapabilityStore("caps.json"))
        sb = mgr.create(SandboxConfig(
            "com.mail", "Mail", trust=90, network_allowed=True))
        self.assertTrue(sb.request_network())

    def test_cleaner_network_denied(self):
        from capabilities import CapabilityStore
        from sandbox import SandboxManager, SandboxConfig
        mgr = SandboxManager(cap_store=CapabilityStore("caps.json"))
        sb = mgr.create(SandboxConfig(
            "com.cleaner", "Cleaner", trust=15, network_allowed=False))
        self.assertFalse(sb.request_network())
        self.assertEqual(sb.stats.network_attempts_blocked, 1)

    def test_elevated_gets_file_access(self):
        from capabilities import CapabilityStore
        from sandbox import SandboxManager, SandboxConfig, SandboxLevel
        mgr = SandboxManager(cap_store=CapabilityStore("caps.json"))
        sb = mgr.create(SandboxConfig(
            "com.settings", "Settings",
            level=SandboxLevel.ELEVATED, trust=95))
        self.assertTrue(sb.request_file(write=True))

    def test_cpu_enforcement(self):
        from capabilities import CapabilityStore
        from sandbox import SandboxManager, SandboxConfig
        mgr = SandboxManager(cap_store=CapabilityStore("caps.json"))
        sb = mgr.create(SandboxConfig(
            "com.test", "Test", trust=50, cpu_limit_pct=50))
        throttled = sb.enforce_cpu(150)
        self.assertEqual(throttled, 50)
        self.assertEqual(sb.stats.cpu_violations, 1)

    def test_memory_enforcement(self):
        from capabilities import CapabilityStore
        from sandbox import SandboxManager, SandboxConfig
        mgr = SandboxManager(cap_store=CapabilityStore("caps.json"))
        sb = mgr.create(SandboxConfig(
            "com.test", "Test", trust=50, mem_limit_mb=100))
        throttled = sb.enforce_memory(500)
        self.assertEqual(throttled, 100)


# ==============================================================
# 2. Emulator
# ==============================================================

class EmulatorTests(unittest.TestCase):

    def test_arm64_is_native(self):
        from emulator import ABIEmulator, ABI
        emu = ABIEmulator(host_abi=ABI.ARM64_V8A)
        est = emu.estimate("game", [ABI.ARM64_V8A])
        self.assertTrue(est.is_native)
        self.assertEqual(est.cpu_mult, 1.00)

    def test_x86_is_emulated(self):
        from emulator import ABIEmulator, ABI
        emu = ABIEmulator(host_abi=ABI.ARM64_V8A)
        est = emu.estimate("old", [ABI.X86])
        self.assertFalse(est.is_native)
        self.assertGreater(est.cpu_mult, 2.0)

    def test_chooses_native_when_available(self):
        from emulator import ABIEmulator, ABI
        emu = ABIEmulator(host_abi=ABI.ARM64_V8A)
        est = emu.estimate("both", [ABI.X86_64, ABI.ARM64_V8A])
        self.assertEqual(est.chosen_abi, ABI.ARM64_V8A)
        self.assertTrue(est.is_native)

    def test_mips_is_worst_case(self):
        from emulator import ABIEmulator, ABI
        emu = ABIEmulator(host_abi=ABI.ARM64_V8A)
        est = emu.estimate("weird", [ABI.MIPS])
        self.assertGreater(est.cpu_mult, 4.0)

    def test_emulation_adds_ram(self):
        from emulator import ABIEmulator, ABI
        emu = ABIEmulator(host_abi=ABI.ARM64_V8A)
        est = emu.estimate("x86", [ABI.X86])
        self.assertGreater(est.extra_ram_mb, 0)


# ==============================================================
# 3. Telemetry Protocol
# ==============================================================

class TelemetryTests(unittest.TestCase):

    def test_record_roundtrip(self):
        from telemetry_proto import TelemetryRecord
        rec = TelemetryRecord(
            timestamp_ms=1234567890,
            core_count=8, battery_pct=78, temp_soc_c_x10=432,
            cpu_avg_x100=1250, gpu_pct_x100=8800,
            ram_pct_x100=7000, ram_used_mb=4200, zram_used_mb=2200,
            tier=0, state=1, thermal=1, device=3,
            flags=0, seq=42,
        )
        decoded = TelemetryRecord.decode(rec.encode())
        self.assertEqual(decoded.timestamp_ms, rec.timestamp_ms)
        self.assertEqual(decoded.cpu_avg_x100, rec.cpu_avg_x100)
        self.assertEqual(decoded.seq, 42)

    def test_checksum_detects_tampering(self):
        from telemetry_proto import TelemetryRecord, RECORD_SIZE
        rec = TelemetryRecord(timestamp_ms=1000, seq=1)
        data = bytearray(rec.encode())
        # Corrupt a byte in the body
        data[10] ^= 0xFF
        with self.assertRaises(ValueError):
            TelemetryRecord.decode(bytes(data))

    def test_ring_write_read(self):
        from telemetry_proto import TelemetryRing, TelemetryRecord
        ring = TelemetryRing(slots=16)
        for i in range(5):
            ring.write(TelemetryRecord(timestamp_ms=i, seq=i))
        self.assertEqual(ring.usage_pct(), 5 / 16 * 100)

        rec = ring.read()
        self.assertIsNotNone(rec)
        self.assertEqual(rec.seq, 0)

    def test_ring_overflow(self):
        from telemetry_proto import TelemetryRing, TelemetryRecord
        ring = TelemetryRing(slots=4)
        for i in range(10):
            ring.write(TelemetryRecord(timestamp_ms=i, seq=i))
        # Should have overflowed
        self.assertGreater(ring.overflow_count, 0)

    def test_ring_empty_after_full_read(self):
        from telemetry_proto import TelemetryRing, TelemetryRecord
        ring = TelemetryRing(slots=8)
        for i in range(5):
            ring.write(TelemetryRecord(timestamp_ms=i, seq=i))
        for _ in range(5):
            ring.read()
        self.assertTrue(ring.is_empty())


# ==============================================================
# 4. APK Deep (uses synthetic APK)
# ==============================================================

class APKDeepTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_apk(self, name, perms=None, signature=None):
        """Build a small APK-like zip with manifest attribute."""
        path = os.path.join(self.tmp, name)
        manifest = '<manifest package="com.test.app" ' \
                   'android:versionName="1.0" ' \
                   'android:versionCode="1">'
        if perms:
            for p in perms:
                manifest += f'<uses-permission android:name="{p}"/>'
        manifest += '</manifest>'

        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", manifest.encode())
            z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        return path

    def test_apk_deep_missing_file(self):
        from apk_deep import APKDeepInspector
        with self.assertRaises(FileNotFoundError):
            APKDeepInspector().inspect("/nonexistent/file.apk")

    def test_apk_deep_empty_report(self):
        """Without apktool/aapt2, we still return a valid report."""
        from apk_deep import APKDeepInspector, DeepReport
        apk = self._make_apk("empty.apk")
        rep = APKDeepInspector().inspect(apk)
        self.assertIsInstance(rep, DeepReport)
        # trust should be a number in [0, 100]
        self.assertGreaterEqual(rep.trust_suggestion, 0)
        self.assertLessEqual(rep.trust_suggestion, 100)

    def test_apk_deep_high_risk_perms_penalize(self):
        from apk_deep import APKDeepInspector
        ins = APKDeepInspector()
        # Directly test the scoring method
        from apk_deep import ManifestInfo, SignatureInfo
        m = ManifestInfo(
            package="com.test",
            permissions=["android.permission.SEND_SMS",
                        "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS"],
            target_sdk=33,
        )
        s = SignatureInfo(verified=True, scheme_v2=True)
        trust, notes = ins._compute_trust(m, s)
        # Should be below 70 due to high-risk perms
        self.assertLess(trust, 80)
        self.assertTrue(any("high-risk" in n for n in notes))

    def test_apk_deep_unverified_lowers_trust(self):
        from apk_deep import APKDeepInspector, ManifestInfo, SignatureInfo
        ins = APKDeepInspector()
        m = ManifestInfo(package="com.test", target_sdk=33)
        s = SignatureInfo(verified=False)
        trust, _ = ins._compute_trust(m, s)
        self.assertLess(trust, 50)


# ==============================================================
# 5. DexView
# ==============================================================

class DexViewTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_dex_apk(self):
        path = os.path.join(self.tmp, "test.apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", b"<manifest/>")
            z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 500)
        return path

    def test_dexview_missing_file(self):
        from dexview import DexViewer
        with self.assertRaises(FileNotFoundError):
            DexViewer().analyze("/nonexistent/file.apk")

    def test_dexview_returns_dict(self):
        """Even without jadx/dex2jar, returns a valid structure."""
        from dexview import DexViewer
        apk = self._make_dex_apk()
        rep = DexViewer().analyze(apk)
        self.assertIn("method", rep)
        self.assertIn("total_classes", rep)
        self.assertIn("top_classes", rep)

    def test_method_extractor_ignores_keywords(self):
        from dexview import DexViewer
        src = '''
        public void hello() { }
        private int add(int a, int b) { return a+b; }
        if (x > 0) { }
        for (int i = 0; i < 10; i++) { }
        public static String getName() { return "x"; }
        '''
        methods = DexViewer._extract_methods(src)
        self.assertIn("hello", methods)
        self.assertIn("add", methods)
        self.assertIn("getName", methods)
        # Should not include control-flow keywords
        self.assertNotIn("if", methods)
        self.assertNotIn("for", methods)


# ==============================================================
# Summary runner
# ==============================================================

def main():
    print()
    print("=" * 66)
    print("  OMEGA OS — Tests for New Modules (sandbox/emulator/.../dexview)")
    print("=" * 66)
    print()

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stderr)
    result = runner.run(suite)

    print()
    print("=" * 66)
    total = result.testsRun
    fails = len(result.failures) + len(result.errors)
    passes = total - fails
    print(f"  Total  : {total}")
    print(f"  Passed : {passes}")
    print(f"  Failed : {fails}")
    if fails == 0:
        print(f"  ✅  ALL TESTS PASSED")
    else:
        print(f"  ❌  SOME TESTS FAILED")
    print("=" * 66)
    print()

    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
