import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apk_deep import APKDeepInspector

# Try OmegaSeed first, fallback to Hello
APK = os.path.expanduser("~/omega/apks/OmegaSeed.apk")
if not os.path.exists(APK):
    APK = os.path.expanduser("~/omega/apks/OMEGA_Hello.apk")

print("=" * 60)
print(f"  Diag2: {os.path.basename(APK)}")
print("=" * 60)

if not os.path.exists(APK):
    print(f"[!] APK not found: {APK}")
    print("    Run: ls ~/omega/apks/")
    sys.exit(1)

print(f"  size: {os.path.getsize(APK) // 1024} KB")

ins = APKDeepInspector()

# 1) apktool
work = tempfile.mkdtemp()
try:
    xml = ins._apktool_manifest(APK, work)
    print(f"\n[1] _apktool_manifest → {len(xml)} chars")
    if xml:
        print(f"    first 200: {xml[:200]}")
except Exception as e:
    print(f"\n[1] _apktool_manifest ERROR: {e}")
    xml = ""

# 2) aapt2
try:
    badging = ins._aapt2_badging(APK)
    print(f"\n[2] _aapt2_badging → {len(badging)} chars")
    if badging:
        print(f"    first 400: {badging[:400]}")
except Exception as e:
    print(f"\n[2] _aapt2_badging ERROR: {e}")
    badging = ""

# 3) parse both
print(f"\n[3] Parsing:")
from_xml = None
from_badging = None
try:
    if xml:
        from_xml = ins._parse_manifest_xml(xml)
        print(f"    from XML    : pkg={from_xml.package!r} "
              f"perms={len(from_xml.permissions)}")
except Exception as e:
    print(f"    XML parse ERROR: {e}")

try:
    if badging:
        from_badging = ins._parse_badging(badging)
        print(f"    from badging: pkg={from_badging.package!r} "
              f"perms={len(from_badging.permissions)}")
        if from_badging.permissions:
            for p in from_badging.permissions[:5]:
                print(f"      • {p}")
except Exception as e:
    print(f"    badging parse ERROR: {e}")

# 4) merged
try:
    merged = ins._merge_manifests(from_xml, from_badging)
    print(f"\n[4] Merged:")
    print(f"    package : {merged.package}")
    print(f"    version : {merged.version_name} ({merged.version_code})")
    print(f"    sdk     : {merged.min_sdk}/{merged.target_sdk}")
    print(f"    perms   : {len(merged.permissions)}")
    for p in merged.permissions[:5]:
        print(f"      • {p}")
except Exception as e:
    print(f"\n[4] merge ERROR: {e}")

# 5) signature
try:
    sig = ins._apksigner_verify(APK)
    print(f"\n[5] Signature:")
    print(f"    verified: {sig.verified}")
    print(f"    v1={sig.scheme_v1} v2={sig.scheme_v2} v3={sig.scheme_v3}")
    if sig.signer_dn:
        print(f"    signer  : {sig.signer_dn[:60]}")
except Exception as e:
    print(f"\n[5] signature ERROR: {e}")

shutil.rmtree(work, ignore_errors=True)
print()
