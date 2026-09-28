# OMEGA OS

> A convergent, AI-native operating system prototype.

**Version 0.8 "Axon"** — built in Python, on Termux, on a phone.

## Highlights

- **AI Core** — Resource + Security + Personal AI
- **HAL** — reads 44 real thermal zones + 8 CPU cores
- **Message Bus** — pub/sub with wildcard topics
- **Decision Engine** — hierarchical state machine
- **Storage** — project-centric OMFS with knowledge graph
- **Runtimes** — real APK analysis via aapt2 + apksigner
- **Sync** — CRDT-based with block-level dedup
- **Sandbox** — capability-enforced isolation
- **Modes** — Device / Performance / Power / Thermal
- **Boot** — 9-stage sequence from ROM to shell

## Numbers

- 41 Python modules
- 14,590 lines of code
- 127 tests passing
- ~70% spec coverage
- 1 night of coding

## Quick Start

```bash
python main.py --fast
python main.py --status
python om_health.py
python omega_dash.py
```

## Technology

- Python 3.14 on Termux (Android)
- Honor X8 (Snapdragon 680, 6 GB RAM)
- Real sensors: 44 thermal zones, 8 CPU cores, battery

## Status

Research prototype. Runs on real hardware, reads real sensors,
but kernel and HAL are simulated in user space.

*Built on Termux, on a phone, in one night.*
