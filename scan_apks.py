# ==============================================================
# Scan all APKs in ~/omega/apks and report
# ==============================================================

import os
import sys
import glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apk_deep import APKDeepInspector
from acl import APKAnalyzer, ACLSimulator


APK_DIR = os.path.expanduser("~/omega/apks")


def main():
    if not os.path.isdir(APK_DIR):
        print(f"[!] Directory not found: {APK_DIR}")
        print(f"    Run: mkdir -p {APK_DIR}")
        return 1

    apks = sorted(glob.glob(os.path.join(APK_DIR, "*.apk")))
    if not apks:
        print(f"[!] No APKs in {APK_DIR}")
        return 1

    print()
    print("=" * 72)
    print(f"  Scanning {len(apks)} APKs")
    print("=" * 72)

    deep = APKDeepInspector()
    acl = ACLSimulator()
    analyzer = APKAnalyzer()

    for i, path in enumerate(apks, 1):
        name = os.path.basename(path)
        size_kb = os.path.getsize(path) // 1024

        print()
        print(f"[{i}/{len(apks)}] {name}  ({size_kb} KB)")

        # ── Quick ACL ──
        try:
            info = analyzer.analyze(path)
            report = acl.analyze(info)
            print(f"    dex={info.dex_count}  "
                  f"abi={info.native_libs or 'none'}  "
                  f"gms={info.uses_gms}  "
                  f"verdict={report.verdict} ({report.score}/100)")
        except Exception as e:
            print(f"    ACL error: {e}")

        # ── Deep ──
        try:
            r = deep.inspect(path)
            m = r.manifest
            s = r.signature
            print(f"    package: {m.package or '(unknown)'}")
            print(f"    version: {m.version_name} ({m.version_code})")
            print(f"    sdk    : {m.min_sdk}/{m.target_sdk}")
            print(f"    acts/svc/rcv/prov: "
                  f"{len(m.activities)}/{len(m.services)}/"
                  f"{len(m.receivers)}/{len(m.providers)}")
            print(f"    perms  : {len(m.permissions)}")
            print(f"    signed : {'YES' if s.verified else 'NO'}  "
                  f"v1={s.scheme_v1} v2={s.scheme_v2} v3={s.scheme_v3}")
            print(f"    trust  : {r.trust_suggestion}/100")
            for note in r.risk_notes[:3]:
                print(f"      {note}")
        except Exception as e:
            print(f"    deep error: {e}")

    print()
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
