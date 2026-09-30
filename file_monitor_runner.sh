#!/data/data/com.termux/files/usr/bin/bash
cd /data/data/com.termux/files/home/omega

# Run file monitor scan
python3 file_monitor.py scan >> file_monitor.log 2>&1

# Update trust scores from new anomalies
python3 file_trust.py integrate >> file_trust.log 2>&1

# Security AI reads new file anomalies
python3 -c "
from security_v2 import SecurityAIv2
sec = SecurityAIv2()
n = sec.ingest_file_anomalies()
if n > 0:
    print(f'[{__import__(\"datetime\").datetime.now().strftime(\"%H:%M:%S\")}] processed {n} anomalies')
" >> security_v2.log 2>&1
