#!/data/data/com.termux/files/usr/bin/bash
cd /data/data/com.termux/files/home/omega

# Already running?
if tmux has-session -t web 2>/dev/null; then
    exit 0
fi

# Start
tmux new-session -d -s web
tmux send-keys -t web "python om_web_v2.py" Enter

echo "$(date): started web server v2" >> web_runner.log
