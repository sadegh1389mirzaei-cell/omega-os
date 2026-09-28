# ==============================================================
# OMEGA OS - APK Deep Inspector
# ==============================================================
# Uses apktool + aapt2 + apksigner for full APK analysis:
#   - Real AndroidManifest.xml (via apktool)
#   - Signature verification (via apksigner)
#   - Component listing (activities, services, providers)
#   - Intent filters
#   - Recommended trust score
# ==============================================================

import os
import re
import sys
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict


HOME = os.path.expanduser("~")
TMP = os.path.join(HOME, "omega", "apk_deep_tmp")


def which(tool): return shutil.which(tool)

HAS_APKTOOL   = bool(which("apktool"))
HAS_AAPT2     = bool(which("aapt2"))
HAS_APKSIGNER = bool(which("apksigner"))


# ==============================================================
# Models
# ==============================================================

@dataclass
class ManifestInfo:
    package: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    features: List[str] = field(default_factory=list)
    permissions_sdk23: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class SignatureInfo:
    verified: bool = False
    scheme_v1: bool = False
    scheme_v2: bool = False
    scheme_v3: bool = False
    signer_dn: str = ""
    signer_sha256: str = ""
    raw: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class DeepReport:
    manifest: ManifestInfo
    signature: SignatureInfo
    trust_suggestion: int = 50
    risk_notes: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "manifest": self.manifest.to_dict(),
            "signature": self.signature.to_dict(),
            "trust_suggestion": self.trust_suggestion,
            "risk_notes": self.risk_notes,
        }


# ==============================================================
# Analyzer
# ==============================================================

class APKDeepInspector:

    # Permissions that strongly increase risk
    HIGH_RISK_PERMS = {
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.PACKAGE_USAGE_STATS",
    }

    def __init__(self):
        os.makedirs(TMP, exist_ok=True)

    # ──────────────────────────────────────────────────────────

    def _aapt2_badging(self, apk: str) -> str:
        if not HAS_AAPT2:
            return ""
        try:
            r = subprocess.run(["aapt2", "dump", "badging", apk],
                              capture_output=True, timeout=60)
            if r.returncode == 0:
                return r.stdout.decode("utf-8", errors="ignore")
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        return ""

    def _apktool_manifest(self, apk: str, work_dir: str) -> str:
        """Decode APK with apktool and return manifest XML."""
        if not HAS_APKTOOL:
            return ""
        out = os.path.join(work_dir, "decoded")
        try:
            r = subprocess.run(
                ["apktool", "d", "-f", "-s", "-o", out, apk],
                capture_output=True, timeout=90,
            )
            # Even with non-zero returncode, the manifest may exist
            # (apktool can crash on classes.dex but manifest is decoded)
            mf = os.path.join(out, "AndroidManifest.xml")
            if os.path.exists(mf):
                with open(mf, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
        except Exception:
            pass
        return ""

    def _apksigner_verify(self, apk: str) -> SignatureInfo:
        info = SignatureInfo()
        if not HAS_APKSIGNER:
            return info
        try:
            r = subprocess.run(
                ["apksigner", "verify", "--verbose", "--print-certs", apk],
                capture_output=True, timeout=20,
            )
            text = r.stdout.decode("utf-8", errors="ignore")
            info.raw = text[:2000]

            # Correct modern apksigner patterns:
            #   Verified using v1 scheme (JAR signing): true
            #   Verified using v2 scheme (APK Signature Scheme v2): true
            #   Verified using v3 scheme (APK Signature Scheme v3): true
            for num, attr in (("v1", "scheme_v1"),
                              ("v2", "scheme_v2"),
                              ("v3", "scheme_v3")):
                m = re.search(
                    r"Verified using " + num +
                    r" scheme[^:]*:\s*(true|false)",
                    text, re.IGNORECASE)
                if m:
                    setattr(info, attr, m.group(1).lower() == "true")

            info.verified = (info.scheme_v1 or info.scheme_v2 or info.scheme_v3)

            m = re.search(r"Signer #1 certificate DN: (.+)", text)
            if m:
                info.signer_dn = m.group(1).strip()
            m = re.search(
                r"Signer #1 certificate SHA-256 digest: ([0-9a-f]+)",
                text, re.IGNORECASE)
            if m:
                info.signer_sha256 = m.group(1)[:16]
        except Exception:
            pass
        return info

    # ──────────────────────────────────────────────────────────

    def _parse_manifest_xml(self, xml: str) -> ManifestInfo:
        mi = ManifestInfo()

        # Package
        m = re.search(r'package="([^"]+)"', xml)
        if m: mi.package = m.group(1)

        # Version
        m = re.search(r'android:versionName="([^"]+)"', xml)
        if m: mi.version_name = m.group(1)
        m = re.search(r'android:versionCode="([^"]+)"', xml)
        if m and m.group(1).isdigit(): mi.version_code = int(m.group(1))

        # SDK
        m = re.search(r'android:minSdkVersion="(\d+)"', xml)
        if m: mi.min_sdk = int(m.group(1))
        m = re.search(r'android:targetSdkVersion="(\d+)"', xml)
        if m: mi.target_sdk = int(m.group(1))

        # Permissions
        for m in re.finditer(
            r'<uses-permission[^>]+android:name="([^"]+)"', xml):
            mi.permissions.append(m.group(1))

        for m in re.finditer(
            r'<uses-permission-sdk-23[^>]+android:name="([^"]+)"', xml):
            mi.permissions_sdk23.append(m.group(1))

        # Activities / Services / Receivers / Providers
        for m in re.finditer(
            r'<activity[^>]+android:name="([^"]+)"', xml):
            mi.activities.append(m.group(1))
        for m in re.finditer(
            r'<service[^>]+android:name="([^"]+)"', xml):
            mi.services.append(m.group(1))
        for m in re.finditer(
            r'<receiver[^>]+android:name="([^"]+)"', xml):
            mi.receivers.append(m.group(1))
        for m in re.finditer(
            r'<provider[^>]+android:name="([^"]+)"', xml):
            mi.providers.append(m.group(1))

        # Features
        for m in re.finditer(
            r'<uses-feature[^>]+android:name="([^"]+)"', xml):
            mi.features.append(m.group(1))

        return mi

    def _parse_badging(self, badging: str) -> ManifestInfo:
        mi = ManifestInfo()
        m = re.search(r"^package: name='([^']+)'", badging, re.M)
        if m: mi.package = m.group(1)
        m = re.search(r"versionName='([^']*)'", badging)
        if m and m.group(1): mi.version_name = m.group(1)
        m = re.search(r"versionCode='([^']*)'", badging)
        if m and m.group(1) and m.group(1).isdigit():
            mi.version_code = int(m.group(1))
        # sdkVersion can be missing in some APKs
        m = re.search(r"sdkVersion:'(\d+)'", badging)
        if m: mi.min_sdk = int(m.group(1))
        m = re.search(r"targetSdkVersion:'(\d+)'", badging)
        if m: mi.target_sdk = int(m.group(1))
        # Fall back to compileSdkVersion if targetSdk missing
        if not mi.target_sdk:
            m = re.search(r"compileSdkVersion='(\d+)'", badging)
            if m: mi.target_sdk = int(m.group(1))
        # Parse launchable-activity for a friendly name
        m = re.search(r"application-label:'([^']*)'", badging)
        if m and m.group(1):
            mi.features.append(f"label:{m.group(1)}")

        for m in re.finditer(r"uses-permission: name='([^']+)'", badging):
            mi.permissions.append(m.group(1))
        return mi

    # ──────────────────────────────────────────────────────────

    def inspect(self, apk_path: str) -> DeepReport:
        if not os.path.exists(apk_path):
            raise FileNotFoundError(apk_path)

        work_dir = tempfile.mkdtemp(dir=TMP)

        try:
            # 1) Manifest via apktool (best) or aapt2 (fallback)
            # Try both; merge for best coverage
            xml = self._apktool_manifest(apk_path, work_dir)
            badging = self._aapt2_badging(apk_path)

            from_xml = self._parse_manifest_xml(xml) if xml else None
            from_badging = self._parse_badging(badging) if badging else None

            manifest = self._merge_manifests(from_xml, from_badging)

            # 2) Signature
            sig = self._apksigner_verify(apk_path)

            # 3) Trust scoring
            trust, notes = self._compute_trust(manifest, sig)

            return DeepReport(
                manifest=manifest,
                signature=sig,
                trust_suggestion=trust,
                risk_notes=notes,
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _merge_manifests(self, a, b):
        """Merge two ManifestInfo — take best from each."""
        if a is None and b is None:
            return ManifestInfo()
        if a is None:
            return b
        if b is None:
            return a

        merged = ManifestInfo()
        for f in ("package", "version_name"):
            setattr(merged, f, getattr(a, f) or getattr(b, f))
        for f in ("version_code", "min_sdk", "target_sdk"):
            v = getattr(a, f) or getattr(b, f)
            setattr(merged, f, v)
        for f in ("permissions", "activities", "services",
                  "receivers", "providers", "features"):
            seen = set()
            out = []
            for item in (list(getattr(a, f)) + list(getattr(b, f))):
                if item not in seen:
                    seen.add(item)
                    out.append(item)
            setattr(merged, f, out)
        return merged

    def _compute_trust(self, m: ManifestInfo, s: SignatureInfo):
        trust = 50
        notes = []

        if s.verified:
            trust += 20
            notes.append(f"✓ Signature verified ({s.signer_dn[:40] or 'unknown'})")
        else:
            trust -= 20
            notes.append("✗ Signature NOT verified")

        if s.scheme_v2: trust += 5
        if s.scheme_v3: trust += 5

        high_risk = [p for p in m.permissions if p in self.HIGH_RISK_PERMS]
        if high_risk:
            penalty = min(20, len(high_risk) * 5)
            trust -= penalty
            notes.append(f"⚠ {len(high_risk)} high-risk permission(s): "
                        f"{', '.join(p.rsplit('.', 1)[-1] for p in high_risk[:3])}")

        if m.target_sdk and m.target_sdk < 28:
            trust -= 10
            notes.append(f"⚠ Old target SDK ({m.target_sdk})")

        if not m.package:
            trust -= 15
            notes.append("⚠ No package name in manifest")

        return max(0, min(100, trust)), notes


# ==============================================================
# CLI
# ==============================================================

def print_report(r: DeepReport, apk_path: str):
    C, G, Y, R, D, Z = ("\033[96m", "\033[92m", "\033[93m",
                        "\033[91m", "\033[90m", "\033[0m")

    print()
    print(f"{C}══════════════════════════════════════════════════════════{Z}")
    print(f"{C}  APK Deep Report — {os.path.basename(apk_path)}{Z}")
    print(f"{C}══════════════════════════════════════════════════════════{Z}")

    m = r.manifest
    print(f"\n{D}[Manifest]{Z}")
    print(f"  package       : {m.package or '(unknown)'}")
    print(f"  version       : {m.version_name} ({m.version_code})")
    print(f"  min/target SDK: {m.min_sdk} / {m.target_sdk}")

    print(f"\n{D}[Components]{Z}")
    print(f"  activities    : {len(m.activities)}")
    print(f"  services      : {len(m.services)}")
    print(f"  receivers     : {len(m.receivers)}")
    print(f"  providers     : {len(m.providers)}")
    print(f"  features      : {len(m.features)}")

    if m.activities:
        print(f"\n  Top activities:")
        for a in m.activities[:5]:
            print(f"    • {a.rsplit('.', 1)[-1]}")
        if len(m.activities) > 5:
            print(f"    {D}... {len(m.activities) - 5} more{Z}")

    print(f"\n{D}[Permissions] ({len(m.permissions)}){Z}")
    for p in m.permissions[:10]:
        short = p.replace("android.permission.", "")
        risk = "⚠ " if p in APKDeepInspector.HIGH_RISK_PERMS else "  "
        print(f"  {risk}{short}")
    if len(m.permissions) > 10:
        print(f"  {D}... {len(m.permissions) - 10} more{Z}")

    s = r.signature
    print(f"\n{D}[Signature]{Z}")
    print(f"  verified      : {G + 'YES' + Z if s.verified else R + 'NO' + Z}")
    print(f"  schemes       : v1={s.scheme_v1}, v2={s.scheme_v2}, v3={s.scheme_v3}")
    if s.signer_dn:
        print(f"  signer        : {s.signer_dn[:60]}")
    if s.signer_sha256:
        print(f"  cert sha256   : {s.signer_sha256}")

    print(f"\n{D}[Trust Suggestion]{Z}")
    trust = r.trust_suggestion
    color = G if trust >= 70 else (Y if trust >= 40 else R)
    bar = "█" * (trust // 5) + "░" * (20 - trust // 5)
    print(f"  score         : {color}{trust}/100{Z}  {color}{bar}{Z}")

    if r.risk_notes:
        print(f"\n{D}[Risk Notes]{Z}")
        for n in r.risk_notes:
            color = G if n.startswith("✓") else (R if n.startswith("✗") else Y)
            print(f"  {color}{n}{Z}")
    print()


def cli():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("""
APK Deep Inspector

Usage:
  python apk_deep.py <apk>          analyze an APK
  python apk_deep.py --json <apk>   JSON output
""")
        return

    args = sys.argv[1:]
    json_out = "--json" in args
    args = [a for a in args if a != "--json"]
    apk = args[0]

    if not os.path.exists(apk):
        print(f"[!] Not found: {apk}")
        return

    ins = APKDeepInspector()
    report = ins.inspect(apk)

    if json_out:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_report(report, apk)


if __name__ == "__main__":
    cli()
