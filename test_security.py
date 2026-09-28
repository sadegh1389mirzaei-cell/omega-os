# ==============================================================
# Security AI - Automated Threat Test
# ==============================================================

import os
import time
import subprocess
from security_ai import SecurityAI

HOME = os.path.expanduser("~")

def show_result(label, result):
    print(f"\n--- {label} ---")
    print(f"  Threat level   : {result['threat_level']}")
    print(f"  Total incidents: {result['total_incidents']}")
    for inc in result["recent"][-5:]:
        print(f"    [{inc['severity']:<8}] {inc['category']:<8} "
              f"{inc['subject'][:28]:<28} {inc['detail'][:40]}")

def stage_file_threat():
    print("\n[THREAT] modifying sensitive files...")
    try:
        with open(os.path.join(HOME, ".zshrc"), "a") as f:
            f.write(f"\n# security test {time.time()}\n")
        print("  -> appended to ~/.zshrc")
    except OSError as e:
        print(f"  -> failed: {e}")

    ssh_dir = os.path.join(HOME, ".ssh")
    if os.path.isdir(ssh_dir):
        try:
            with open(os.path.join(ssh_dir, "test_threat"), "w") as f:
                f.write("test\n")
            print("  -> created ~/.ssh/test_threat")
        except OSError as e:
            print(f"  -> failed: {e}")

def stage_process_threat():
    print("\n[THREAT] launching suspicious process...")
    try:
        subprocess.Popen(
            ["nc", "-l", "19999"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print("  -> nc -l 19999 started")
    except FileNotFoundError:
        print("  -> nc not found, skipping")
    except Exception as e:
        print(f"  -> failed: {e}")

def main():
    print("=" * 60)
    print("  OMEGA Security AI - Automated Threat Test")
    print("=" * 60)

    sec = SecurityAI(state_dir=".")

    # 1. Baseline
    print("\n[1] Baseline scan (no threats expected)")
    r1 = sec.scan()
    show_result("Baseline", r1)

    # 2. Trigger threats
    stage_file_threat()
    stage_process_threat()

    # 3. Wait a moment so filesystem settles
    time.sleep(2)

    # 4. Scan again
    print("\n[2] Post-threat scan")
    r2 = sec.scan()
    show_result("After threats", r2)

    # Summary
    print()
    print("=" * 60)
    if r2["total_incidents"] > r1["total_incidents"]:
        delta = r2["total_incidents"] - r1["total_incidents"]
        print(f"  ✅ SUCCESS: {delta} new incident(s) detected")
    else:
        print(f"  ⚠  No new incidents detected")
    print("=" * 60)

if __name__ == "__main__":
    main()
