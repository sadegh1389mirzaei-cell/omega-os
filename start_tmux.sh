#!/data/data/com.termux/files/usr/bin/bash
cd ~/omega

# اگر tmux session هست، فقط به آن attach کن
if tmux has-session -t omega 2>/dev/null; then
    echo "[+] attaching to existing session"
    tmux attach -t omega
    exit 0
fi

# session جدید بساز
echo "[+] creating new tmux session 'omega'"
tmux new-session -d -s omega -n collector

# wake lock
tmux send-keys -t omega:collector "termux-wake-lock" Enter

# اجرای collector
tmux send-keys -t omega:collector "cd ~/omega && python -u collector_service.py 2>&1 | tee -a telemetry.log" Enter

echo "[+] running in tmux"
echo "[+] to attach: tmux attach -t omega"
echo "[+] to detach: Ctrl+B then D"
echo "[+] to stop:   tmux kill-session -t omega"
