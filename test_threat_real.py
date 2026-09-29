# ==============================================================
# Real threat test for Security AI v2
# ==============================================================
# Phase 1: learn baseline (normal processes)
# Phase 2: launch a threat (netcat listener)
# Phase 3: detect the anomaly
# ==============================================================

import os
import sys
import time
import subprocess

sys.path.insert(0, os.path.expanduser("~/omega"))

from security_v2 import SecurityAIv2, sigs_from_processes
from processes import ProcessScanner


def snapshot_and_observe(sec, scanner, label):
    procs = scanner.scan()
    sigs = sigs_from_processes(procs)
    sec.observe(sigs)
    print(f"  [{label}] {len(sigs)} processes observed")
    return sigs


def main():
    print()
    print("=" * 60)
    print("  Security AI v2 - Real Threat Test")
    print("=" * 60)
    print()

    sec = SecurityAIv2()
    scanner = ProcessScanner()

    # ─────────────────────────────────────────────
    # Phase 1: Learn baseline (5 snapshots)
    # ─────────────────────────────────────────────
    print("[Phase 1] Learning baseline (5 snapshots, 1s apart)")
    for i in range(5):
        snapshot_and_observe(sec, scanner, f"baseline #{i+1}")
        time.sleep(1)

    print(f"    baseline learned: {len(sec.baselines)} processes")
    baseline_names = set(sec.baselines.keys())
    print()

    # ─────────────────────────────────────────────
    # Phase 2: Launch threat (nc listener)
    # ─────────────────────────────────────────────
    print("[Phase 2] Launching threat: nc -l 19999")
    try:
        threat = subprocess.Popen(
            ["nc", "-l", "19999"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"    spawned nc with PID {threat.pid}")
    except FileNotFoundError:
        print("    [!] nc not found, using 'sleep' as threat instead")
        threat = subprocess.Popen(
            ["sleep", "300"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"    spawned sleep with PID {threat.pid}")

    time.sleep(1.5)

    # ─────────────────────────────────────────────
    # Phase 3: Observe threat
    # ─────────────────────────────────────────────
    print()
    print("[Phase 3] Observing while threat is active")
    for i in range(5):
        snapshot_and_observe(sec, scanner, f"threat #{i+1}")
        time.sleep(1)

    # ─────────────────────────────────────────────
    # Check for new processes
    # ─────────────────────────────────────────────
    print()
    print("[Analysis] New processes not in baseline:")
    new_procs = []
    for name, baseline in sec.baselines.items():
        short = name.split()[0].split("/")[-1]
        if name not in baseline_names:
            new_procs.append((name, baseline))
            print(f"    ⚠ {name}")
            print(f"      count={baseline.count} "
                  f"first_seen={baseline.first_seen}")
        else:
            pass

    if not new_procs:
        print("    (none)")

    # ─────────────────────────────────────────────
    # Check events
    # ─────────────────────────────────────────────
    print()
    print("[Events] Security events recorded:")
    if sec.events:
        for e in sec.events[-10:]:
            print(f"    [{e['severity']:<8}] {e['kind']:<22} "
                  f"{e['subject']}")
    else:
        print("    (none)")

    # ─────────────────────────────────────────────
    # Clean up
    # ─────────────────────────────────────────────
    print()
    print("[Cleanup] Killing threat process")
    try:
        threat.terminate()
        threat.wait(timeout=2)
        print(f"    killed PID {threat.pid}")
    except Exception as e:
        print(f"    error: {e}")

    # Save
    sec.save()
    print()
    print(f"[Saved] {sec.model_path}")
    print()


if __name__ == "__main__":
    main()
