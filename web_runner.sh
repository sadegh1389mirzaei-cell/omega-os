#!/data/data/com.termux/files/usr/bin/bash

cd /data/data/com.termux/files/home/omega

# Already running? exit
if tmux has-session -t web 2>/dev/null; then
    exit 0
fi

# Start it
tmux new-session -d -s web
tmux send-keys -t web "python om_web.py" Enter

echo "$(date): started web server" >> web_runner.log
