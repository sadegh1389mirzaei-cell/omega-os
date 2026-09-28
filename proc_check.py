import subprocess
r = subprocess.run(["ps", "-eo", "pid,user,comm,args"],
                   capture_output=True, timeout=5)
lines = r.stdout.decode("utf-8", errors="ignore").splitlines()
print(f"Total processes visible: {len(lines) - 1}\n")
for line in lines[:25]:
    print(line[:110])
print("\n... total shown:", min(25, len(lines)))
