import os, subprocess, shutil

APK = "/storage/emulated/0/Download/Projects/OmegaSeed.apk"
# یا هر APK که ۲۷ مگه

print("=" * 60)
print(f"  Diag: {os.path.basename(APK)}")
print("=" * 60)

print(f"\nsize: {os.path.getsize(APK) // 1024} KB")

# 1) apksigner
print("\n[1] apksigner --verbose")
if shutil.which("apksigner"):
    r = subprocess.run(["apksigner", "verify", "--verbose", APK],
                       capture_output=True, timeout=30)
    print(f"  returncode: {r.returncode}")
    print("  stdout (first 15 lines):")
    for line in r.stdout.decode().splitlines()[:15]:
        print(f"    {line}")
    if r.stderr:
        print("  stderr:", r.stderr.decode()[:300])
else:
    print("  apksigner NOT FOUND")

# 2) apktool
print("\n[2] apktool d (first 20 lines of stderr)")
if shutil.which("apktool"):
    r = subprocess.run(["apktool", "d", "-f", "-s", "-o", "/tmp/omegadiag", APK],
                       capture_output=True, timeout=60)
    print(f"  returncode: {r.returncode}")
    err = r.stderr.decode()
    for line in err.splitlines()[:20]:
        print(f"    {line}")
    if os.path.exists("/tmp/omegadiag/AndroidManifest.xml"):
        print("  ✓ manifest extracted")
    else:
        print("  ✗ NO manifest extracted")
else:
    print("  apktool NOT FOUND")

# 3) aapt2
print("\n[3] aapt2 dump badging (first 20 lines)")
if shutil.which("aapt2"):
    r = subprocess.run(["aapt2", "dump", "badging", APK],
                       capture_output=True, timeout=30)
    print(f"  returncode: {r.returncode}")
    if r.returncode != 0:
        print("  stderr:", r.stderr.decode()[:300])
    else:
        for line in r.stdout.decode().splitlines()[:20]:
            print(f"    {line}")
else:
    print("  aapt2 NOT FOUND")

# 4) zipfile check
print("\n[4] zipfile — first 30 entries")
import zipfile
try:
    with zipfile.ZipFile(APK) as z:
        names = z.namelist()
        print(f"  total entries: {len(names)}")
        for n in names[:30]:
            print(f"    {n}")
except Exception as e:
    print(f"  ERROR: {e}")
