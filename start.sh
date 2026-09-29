#!/data/data/com.termux/files/usr/bin/bash
cd ~/omega
nohup python -u telemetry_loop.py > telemetry.log 2>&1 &
echo "PID: $!"
