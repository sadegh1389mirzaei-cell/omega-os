import os

print("=== /proc/loadavg ===")
try:
    with open("/proc/loadavg") as f:
        print(f.read().strip())
except Exception as e:
    print("ERR:", e)

print("\n=== /proc/stat (first 12 lines) ===")
try:
    with open("/proc/stat") as f:
        for i, line in enumerate(f):
            if i >= 12: break
            print(line.rstrip())
except Exception as e:
    print("ERR:", e)

print("\n=== CPU freq (sample) ===")
for i in range(8):
    p = f"/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_cur_freq"
    try:
        with open(p) as f:
            print(f"cpu{i}: {f.read().strip()} kHz")
    except Exception as e:
        print(f"cpu{i}: ERR {e}")

print("\n=== top test ===")
try:
    import subprocess
    r = subprocess.run(["top", "-bn1"], capture_output=True, timeout=3)
    print("top works, returncode:", r.returncode)
    # print last few lines
    lines = r.stdout.decode().splitlines()
    for line in lines[-5:]:
        print(line)
except Exception as e:
    print("top ERR:", e)
