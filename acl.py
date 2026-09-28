# ==============================================================
# OMEGA OS - Android Compatibility Layer (ACL)
# ==============================================================
# Section 5.2 of the OMEGA spec.
# Uses zipfile (pure Python) for APK inspection.
# ==============================================================

import os
import re
import sys
import json
import time
import shutil
import hashlib
import subprocess
import zipfile
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

try:
    from bus import EventBus
    _BUS = True
except ImportError:
    _BUS = False


HOME = os.path.expanduser("~")
TMP_APK_DIR = os.path.join(HOME, "omega", "acl_tmp")


# ==============================================================
# Permission map (Section 10.2)
# ==============================================================

DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA":              "OM_CAP_CAMERA",
    "android.permission.RECORD_AUDIO":        "OM_CAP_MICROPHONE",
    "android.permission.ACCESS_FINE_LOCATION":"OM_CAP_LOCATION_PRECISE",
    "android.permission.ACCESS_COARSE_LOCATION":"OM_CAP_LOCATION_COARSE",
    "android.permission.READ_CONTACTS":       "OM_CAP_CONTACTS_READ",
    "android.permission.WRITE_CONTACTS":      "OM_CAP_CONTACTS_WRITE",
    "android.permission.READ_SMS":            "OM_CAP_SMS_READ",
    "android.permission.SEND_SMS":            "OM_CAP_SMS_SEND",
    "android.permission.READ_CALL_LOG":       "OM_CAP_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE":"OM_CAP_FILES_READ",
    "android.permission.WRITE_EXTERNAL_STORAGE":"OM_CAP_FILES_WRITE",
    "android.permission.MANAGE_EXTERNAL_STORAGE":"OM_CAP_FILES_ALL",
    "android.permission.INTERNET":            "OM_CAP_NETWORK",
    "android.permission.ACCESS_NETWORK_STATE":"OM_CAP_NETWORK_STATE",
    "android.permission.BLUETOOTH":           "OM_CAP_BLUETOOTH",
    "android.permission.BODY_SENSORS":        "OM_CAP_BODY_SENSORS",
    "android.permission.POST_NOTIFICATIONS":  "OM_CAP_NOTIFICATIONS",
}

GMS_DEPENDENT = [
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.google.android.apps.maps",
    "com.google.firebase",
]


def which(tool: str) -> Optional[str]:
    return shutil.which(tool)


HAS_AAPT2  = bool(which("aapt2"))
HAS_UNZIP  = bool(which("unzip"))


# ==============================================================
# Data models
# ==============================================================

@dataclass
class APKInfo:
    path: str
    package: str = ""
    version: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: int = 0
    services: int = 0
    receivers: int = 0
    providers: int = 0
    file_size_kb: int = 0
    dex_count: int = 0
    native_libs: List[str] = field(default_factory=list)
    uses_vulkan: bool = False
    uses_opengl_es: bool = False
    uses_gms: bool = False
    sha256: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class CompatibilityReport:
    info: APKInfo
    cpu_overhead: float = 1.0
    mem_overhead: float = 1.0
    gpu_overhead: float = 1.0
    art_compile_ms: int = 0
    cold_start_ms: int = 0
    warm_start_ms: int = 0
    estimated_ram_mb: int = 0
    score: int = 50
    verdict: str = "UNKNOWN"
    notes: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["info"] = self.info.to_dict()
        return d


# ==============================================================
# APK analyzer
# ==============================================================

class APKAnalyzer:

    def __init__(self):
        os.makedirs(TMP_APK_DIR, exist_ok=True)

    # ──────────────────────────────────────────────────────────
    # Hash
    # ──────────────────────────────────────────────────────────

    def _hash(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()[:16]
        except OSError:
            return ""

    # ──────────────────────────────────────────────────────────
    # Zip contents — pure Python, no subprocess
    # ──────────────────────────────────────────────────────────

    def _inspect_zip(self, apk: str):
        """
        Returns (dex_count, native_abis, uses_vulkan, uses_opengl_es, has_gms).
        Uses only string operations — no regex on backslash sequences.
        """
        dex = 0
        libs = []
        vulkan = False
        gles = False
        has_gms = False
        dex_names = []

        try:
            with zipfile.ZipFile(apk) as z:
                for name in z.namelist():
                    lower = name.lower()
                    base = lower.rsplit("/", 1)[-1]

                    # DEX files: classes.dex, classes2.dex, classes10.dex
                    if base.startswith("classes") and base.endswith(".dex"):
                        middle = base[7:-4]   # strip "classes" and ".dex"
                        if middle == "" or middle.isdigit():
                            dex += 1
                            dex_names.append(name)
                            continue

                    # Native libs: lib/<abi>/libX.so
                    if lower.startswith("lib/") and lower.endswith(".so"):
                        parts = name.split("/")
                        if len(parts) >= 3:
                            abi = parts[1]
                            if abi not in libs:
                                libs.append(abi)

                    # Vulkan / GLES markers
                    if "libvulkan" in lower:
                        vulkan = True
                    if "libgles" in lower:
                        gles = True

                    # GMS markers
                    if "com/google/android/gms" in lower:
                        has_gms = True
                    if "firebase" in lower and "google" in lower:
                        has_gms = True
                    if base == "gms.properties":
                        has_gms = True

        except (zipfile.BadZipFile, OSError, RuntimeError):
            pass

        return dex, sorted(libs), vulkan, gles, has_gms, dex_names

    # ──────────────────────────────────────────────────────────
    # aapt2 badging (only if APK is real)
    # ──────────────────────────────────────────────────────────

    def _aapt2_badging(self, apk: str) -> str:
        if not HAS_AAPT2:
            return ""
        try:
            r = subprocess.run(["aapt2", "dump", "badging", apk],
                              capture_output=True, timeout=15)
            if r.returncode == 0:
                return r.stdout.decode("utf-8", errors="ignore")
        except Exception:
            pass
        return ""

    @staticmethod
    def _extract(text: str, pattern: str) -> str:
        m = re.search(pattern, text, re.MULTILINE)
        return m.group(1) if m else ""

    # ──────────────────────────────────────────────────────────
    # Main analysis
    # ──────────────────────────────────────────────────────────

    def analyze(self, apk_path: str) -> APKInfo:
        info = APKInfo(path=apk_path)

        if not os.path.exists(apk_path):
            return info

        info.file_size_kb = os.path.getsize(apk_path) // 1024
        info.sha256 = self._hash(apk_path)

        # ── Zip inspection (always works) ──
        dex, libs, vulkan, gles, has_gms, dex_names = self._inspect_zip(apk_path)
        info.dex_count = dex
        info.native_libs = libs
        info.uses_vulkan = vulkan
        info.uses_opengl_es = gles

        # ── aapt2 badging (real APKs only) ──
        badging = self._aapt2_badging(apk_path)
        if badging:
            info.package = self._extract(badging, r"^package: name='([^']+)'")
            info.version = self._extract(badging, r"versionName='([^']+)'")
            vc = self._extract(badging, r"versionCode='([^']+)'")
            if vc and vc.isdigit():
                info.version_code = int(vc)
            ms = self._extract(badging, r"sdkVersion:'(\d+)'")
            if ms:
                info.min_sdk = int(ms)
            ts = self._extract(badging, r"targetSdkVersion:'(\d+)'")
            if ts:
                info.target_sdk = int(ts)

            for m in re.finditer(r"uses-permission: name='([^']+)'", badging):
                info.permissions.append(m.group(1))

            info.activities = len(re.findall(r"^launchable-activity:", badging, re.M))
            info.activities += len(re.findall(r"^activity:", badging, re.M))
            info.services = len(re.findall(r"^service:", badging, re.M))
            info.receivers = len(re.findall(r"^receiver:", badging, re.M))
            info.providers = len(re.findall(r"^provider:", badging, re.M))

            for gms in GMS_DEPENDENT:
                if gms in badging:
                    info.uses_gms = True
                    break

        # GMS from zip contents
        if has_gms:
            info.uses_gms = True

        return info


# ==============================================================
# ACL Simulator
# ==============================================================

class ACLSimulator:

    BASE_CPU_OVERHEAD = 1.20
    BASE_MEM_OVERHEAD = 1.40
    BASE_GPU_OVERHEAD = 1.08
    DEX_CPU_COST      = 0.02
    DEX_MEM_COST_MB   = 8
    BASE_FRAMEWORK_MB = 60
    BASE_APP_MB       = 40

    def analyze(self, info: APKInfo) -> CompatibilityReport:
        r = CompatibilityReport(info=info)

        # CPU overhead
        dex_factor = min(0.10, info.dex_count * self.DEX_CPU_COST)
        r.cpu_overhead = self.BASE_CPU_OVERHEAD + dex_factor

        # Memory
        r.mem_overhead = self.BASE_MEM_OVERHEAD

        # GPU
        r.gpu_overhead = self.BASE_GPU_OVERHEAD
        if info.uses_vulkan:
            r.gpu_overhead = 1.02
            r.notes.append("Vulkan passthrough → minimal GPU overhead")
        if info.uses_opengl_es and not info.uses_vulkan:
            r.gpu_overhead = 1.10
            r.notes.append("OpenGL ES → translated via Zink")

        # ART compile
        r.art_compile_ms = info.dex_count * 150 + info.file_size_kb // 10

        # Start time
        dex_add = info.dex_count * 60
        r.cold_start_ms = 600 + dex_add
        r.warm_start_ms = 400 + dex_add // 2

        # RAM estimate
        r.estimated_ram_mb = (self.BASE_FRAMEWORK_MB +
                             self.BASE_APP_MB +
                             info.dex_count * self.DEX_MEM_COST_MB)

        # Score
        score = 100
        issues = []

        if info.uses_gms:
            score -= 30
            issues.append("Depends on Google Play Services — shim required")
            r.notes.append("GMS shim will be applied (Section 5.2.3)")

        if info.native_libs:
            if "arm64-v8a" in info.native_libs:
                r.notes.append("ARM64 native libs — full speed")
            elif "armeabi-v7a" in info.native_libs:
                score -= 5
                r.notes.append("32-bit ARM — slightly slower")
            elif "x86" in info.native_libs or "x86_64" in info.native_libs:
                score -= 20
                issues.append("x86 native libs — requires emulation")
            else:
                score -= 10
                issues.append(f"Unknown native ABI: {info.native_libs}")

        if info.dex_count > 3:
            penalty = min(15, (info.dex_count - 3) * 3)
            score -= penalty
            r.notes.append(f"{info.dex_count} dex files — "
                          f"more ART compilation work")

        if info.dex_count > 3:
            penalty = min(15, (info.dex_count - 3) * 3)
            score -= penalty
            r.notes.append(f"{info.dex_count} dex files — "
                          f"more ART compilation work")

        if info.dex_count > 3:
            penalty = min(15, (info.dex_count - 3) * 3)
            score -= penalty
            r.notes.append(f"{info.dex_count} dex files — "
                          f"more ART compilation work")

        if info.file_size_kb > 200_000:
            score -= 5
            r.notes.append("Large APK — slow first launch")

        if info.target_sdk and info.target_sdk < 28:
            score -= 10
            issues.append(f"Old target SDK ({info.target_sdk})")

        dangerous = [p for p in info.permissions
                    if p in DANGEROUS_PERMISSIONS]
        if len(dangerous) > 8:
            score -= 5
            r.notes.append(f"{len(dangerous)} dangerous permissions")

        r.score = max(0, min(100, score))

        if r.score >= 85:   r.verdict = "EXCELLENT"
        elif r.score >= 70: r.verdict = "GOOD"
        elif r.score >= 50: r.verdict = "FAIR"
        elif r.score >= 30: r.verdict = "POOR"
        else:               r.verdict = "UNSUPPORTED"

        r.issues = issues
        return r


# ==============================================================
# Permission mapping
# ==============================================================

def map_permissions(permissions: List[str]) -> Dict[str, str]:
    return {p: DANGEROUS_PERMISSIONS[p]
            for p in permissions if p in DANGEROUS_PERMISSIONS}


# ==============================================================
# Synthetic APK generator
# ==============================================================

def make_synthetic_apk(name: str = "sample.apk",
                       dex_count: int = 3,
                       size_kb: int = 5000,
                       with_gms: bool = False,
                       with_vulkan: bool = False,
                       with_gles: bool = False,
                       abi: str = "arm64-v8a") -> str:
    """Create a realistic APK-like zip for testing."""
    os.makedirs(TMP_APK_DIR, exist_ok=True)
    path = os.path.join(TMP_APK_DIR, name)
    if os.path.exists(path):
        os.remove(path)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")

        for i in range(dex_count):
            dname = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
            z.writestr(dname, b"dex\n035\x00" + b"\x00" * 900)

        z.writestr(f"lib/{abi}/libnative.so", b"\x7fELF" + b"\x00" * 500)
        if with_vulkan:
            z.writestr(f"lib/{abi}/libvulkan.so", b"\x7fELF" + b"\x00" * 400)
        if with_gles:
            z.writestr(f"lib/{abi}/libGLESv2.so", b"\x7fELF" + b"\x00" * 400)

        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 200)

        if with_gms:
            z.writestr("com/google/android/gms/common/api/Api.class",
                      b"java class")

        # Padding: UNCOMPRESSED so size_kb is respected
        current = os.path.getsize(path)
        target = size_kb * 1024
        if current < target:
            pad_size = target - current - 200
            if pad_size > 0:
                z.writestr("META-INF/pad.bin",
                          b"\x00" * pad_size,
                          compress_type=zipfile.ZIP_STORED)

    return path


# ==============================================================
# Pretty print
# ==============================================================

def print_report(r: CompatibilityReport):
    info = r.info
    C, G, Y, R, D, Z = ("\033[96m", "\033[92m", "\033[93m",
                        "\033[91m", "\033[90m", "\033[0m")
    vc_map = {"EXCELLENT": G, "GOOD": G,
             "FAIR": Y, "POOR": R, "UNSUPPORTED": R}

    print()
    print(f"{C}══════════════════════════════════════════════════════════{Z}")
    print(f"{C}  APK Analysis — {os.path.basename(info.path)}{Z}")
    print(f"{C}══════════════════════════════════════════════════════════{Z}")

    print(f"\n{D}[Identity]{Z}")
    print(f"  package      : {info.package or '(unknown)'}")
    print(f"  version      : {info.version or '(unknown)'} (code {info.version_code})")
    print(f"  size         : {info.file_size_kb} KB")
    print(f"  sha256[:16]  : {info.sha256}")

    print(f"\n{D}[Structure]{Z}")
    print(f"  dex files    : {info.dex_count}")
    print(f"  activities   : {info.activities}")
    print(f"  services     : {info.services}")
    print(f"  receivers    : {info.receivers}")
    print(f"  providers    : {info.providers}")
    print(f"  native ABIs  : {info.native_libs or '(none)'}")
    print(f"  Vulkan       : {info.uses_vulkan}")
    print(f"  OpenGL ES    : {info.uses_opengl_es}")
    print(f"  GMS dependent: {info.uses_gms}")

    if info.permissions:
        dangerous = [p for p in info.permissions
                    if p in DANGEROUS_PERMISSIONS]
        print(f"\n{D}[Permissions]{Z}  ({len(info.permissions)} total, "
              f"{len(dangerous)} dangerous)")
        for p in dangerous[:8]:
            short = p.replace("android.permission.", "")
            print(f"  → {short:<32} {D}→{Z} "
                  f"{DANGEROUS_PERMISSIONS[p]}")
        if len(dangerous) > 8:
            print(f"  {D}... ({len(dangerous) - 8} more){Z}")

    print(f"\n{D}[Estimated Runtime Cost]{Z}")
    print(f"  CPU overhead : x{r.cpu_overhead:.2f}")
    print(f"  RAM overhead : x{r.mem_overhead:.2f}")
    print(f"  GPU overhead : x{r.gpu_overhead:.2f}")
    print(f"  ART compile  : {r.art_compile_ms} ms (one-time)")
    print(f"  Cold start   : {r.cold_start_ms} ms")
    print(f"  Warm start   : {r.warm_start_ms} ms")
    print(f"  Est. RAM     : {r.estimated_ram_mb} MB")

    vc = vc_map.get(r.verdict, Z)
    print(f"\n{D}[Verdict]{Z}")
    print(f"  Compatibility: {vc}{r.verdict} ({r.score}/100){Z}")

    if r.notes:
        print(f"\n{D}[Notes]{Z}")
        for n in r.notes:
            print(f"  • {n}")

    if r.issues:
        print(f"\n{R}[Issues]{Z}")
        for i in r.issues:
            print(f"  ⚠  {i}")
    print()


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
OMEGA ACL — Android Compatibility Layer Analyzer

Usage:
  python acl.py <apk>               analyze a real APK
  python acl.py --synthetic          synthetic (3 dex, arm64)
  python acl.py --synthetic --gms    + GMS dependency
  python acl.py --synthetic --vulkan + Vulkan libs
  python acl.py --json <apk>         output JSON
  python acl.py --help
""")


def main():
    args = sys.argv[1:]

    if not args or "--help" in args:
        cli_help()
        return

    output_json = "--json" in args
    args = [a for a in args if a != "--json"]

    if "--synthetic" in args:
        apk = make_synthetic_apk(
            dex_count=3,
            size_kb=5000,
            with_gms="--gms" in args,
            with_vulkan="--vulkan" in args,
            with_gles="--gles" in args,
        )
        print(f"[+] Generated: {apk}")
    else:
        apk = args[0] if args else None
        if not apk:
            cli_help()
            return

    if not os.path.exists(apk):
        print(f"[!] File not found: {apk}")
        return

    info = APKAnalyzer().analyze(apk)
    report = ACLSimulator().analyze(info)

    if output_json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
