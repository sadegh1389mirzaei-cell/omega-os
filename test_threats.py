# ==============================================================
# Security AI - Threat Simulator (for testing only)
# ==============================================================

import os
import time
import subprocess

HOME = os.path.expanduser("~")
PREFIX = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")

def stage1_file_attacks():
    print("[*] Stage 1: modifying sensitive files...")
    try:
        with open(os.path.join(HOME, ".zshrc"), "a") as f:
            f.write("\n# security test\n")
    except OSError as e:
        print(f"    failed: {e}")

    try:
        ssh_dir = os.path.join(HOME, ".ssh")
        if os.path.isdir(ssh_dir):
            p = os.path.join(ssh_dir, "test_threat_key")
            with open(p, "w") as f:
                f.write("test\n")
            print(f"    created {p}")
    except OSError as e:
        print(f"    failed: {e}")

def stage2_process_attack():
    print("[*] Stage 2: launching suspicious process...")
    try:
        subprocess.Popen(
            ["nc", "-l", "19999"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("    nc -l 19999 &")
    except FileNotFoundError:
        print("    nc not installed, trying curl | sh pattern...")
        subprocess.Popen(
            ["sh", "-c", "echo fake | cat"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

def stage3_cpu_spike():
    print("[*] Stage 3: CPU spike...")
    subprocess.Popen(
        ["python", "-c",
         "import time; t=time.time()+20\n"
         "while time.time()<t:\n"
         "    sum(i*i for i in range(100000))\n"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("    spawned CPU hog (20s)")

if __name__ == "__main__":
    print("=" * 50)
    print("  THREAT SIMULATOR (test only)")
    print("=" * 50)
    print()

    stage1_file_attacks()
    time.sleep(3)
    stage2_process_attack()
    time.sleep(3)
    stage3_cpu_spike()

    print()
    print("[+] Threats staged. Now watch security_ai.py output.")
    print("    Wait ~10 seconds and check incidents.jsonl.")
