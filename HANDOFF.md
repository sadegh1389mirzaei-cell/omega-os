# OMEGA OS — Session Handoff

> **Status:** Active development
> **Last updated:** 2026-09-29
> **Version:** 0.8 "Axon"
> **Repo:** https://github.com/sadegh1389mirzaei-cell/omega-os

---

## 1. What is OMEGA OS?

A convergent, AI-native operating system prototype.
One OS that scales from phone to tablet to desktop, with AI
embedded at every layer — not as an app, but as a system service.

The full design is in a 1,100-page specification (17 sections).
Current implementation: end of Phase 0.5 (user-space simulator).

Spec sections:

1.  Introduction & Philosophy
2.  High-Level Architecture
3.  Kernel (scheduler, memory, power, IPC, security)
4.  Hardware Abstraction Layer (HAL)
5.  Runtime Environments (Native, Android, Linux, Windows)
6.  AI Core (Resource, Security, Personal, Decision Engine)
7.  System Modes (Device, Performance, Power, Thermal)
8.  UI & Window Management
9.  File System & Storage (project-centric OMFS)
10. Application Model (.omapp format)
11. Security Architecture (Zero Trust)
12. Networking & Multi-Device Sync
13. Boot Process (9 stages)
14. Simulated Daily Operation
15. Formal AI Resource Manager Spec
16. Development Roadmap
17. Appendix

---

## 2. Current Status

What works (real, not simulated):

- HAL — 44 thermal zones via psutil, 8 CPU cores
- Message Bus — pub/sub with wildcard topics
- Decision Engine — HSM with hysteresis
- Resource AI — predictive allocation
- Security AI v2 — Markov + threats + auto-quarantine
- Personal AI v2 — Markov chain with time-decay
- Feedback Loop — logs, evaluates, tunes
- Storage (OMFS) — project-centric + knowledge graph
- Sandbox — capability enforcement
- ACL — APK analysis (aapt2 + apksigner)
- Sync — CRDT + block dedup
- UI — curses dashboard

What is simulated:

- Boot sequence (9-stage animation)
- Runtime environments (overhead coefficients)
- Kernel (user-space simulation)

Numbers:

- ~50 Python files
- ~17,000 lines of code
- 12 git commits
- 130+ tests passing
- 16 of 17 spec sections covered

Environment:

- Device: Honor X8 (Snapdragon 680, 6 GB RAM, Android 13)
- Host: Termux
- Container: proot-distro Ubuntu 26.04 at /opt/omega
- Python 3.14
- Key tools: psutil, pytest, jadx, aapt2, apktool, apksigner

---

## 3. Architecture

Layer stack (top to bottom):

  [7] Applications / UI (curses dashboard)
  [6] AI Core
        - Resource AI   (omega.py)
        - Security AI v2 (security_v2.py)
        - Personal AI v2 (personal_ai_v2.py)
        - Decision Engine (omega.py)
  [5] Services
        - Storage (omfs.py, virtual_fs.py)
        - Sync (sync.py)
        - Sandbox (sandbox.py, capabilities.py)
        - Packages (pkgman.py)
        - Feedback (feedback_loop.py)
  [4] HAL
        - CPU + thermal (hal.py via psutil)
        - Network (network.py)
        - Telemetry (real_telemetry.py)
  [3] Kernel Simulation
        - Scheduler (scheduler.py, 5 task classes)
        - Capabilities (capabilities.py)
        - Memory Manager (omega.py)

All layers communicate via:
  - bus.py (Message Bus, pub/sub)
  - bus_hooks.py (thin emit wrappers)

---

## 4. Module Inventory

Core Foundation:

  bus.py              ~450 lines   Pub/sub message bus
  bus_hooks.py        ~120 lines   Emit wrappers
  main.py             ~820 lines   Entry point
  boot.py             ~280 lines   9-stage boot

Kernel Simulation:

  omega.py           ~1200 lines   Decision Engine + Memory
  scheduler.py        ~130 lines   5-class scheduler
  capabilities.py     ~150 lines   Capability store

HAL:

  hal.py              ~350 lines   Hardware reading via psutil
  network.py          ~220 lines   Network interfaces
  real_telemetry.py   ~460 lines   CPU/RAM/battery

AI Core:

  security_v2.py      ~600 lines   Security AI v2
  security_ai.py      ~380 lines   Security v1
  personal_ai_v2.py   ~240 lines   Personal AI v2
  personal_ai.py      ~330 lines   Personal v1
  processes.py        ~220 lines   Process scanner
  feedback_loop.py    ~370 lines   Decision feedback
  smart_engine.py      ~90 lines   Decision + Feedback

Runtimes:

  runtime.py          ~350 lines   5 environments
  acl.py              ~500 lines   APK analysis
  acl_bridge.py       ~450 lines   ACL to Runtime
  apk_deep.py         ~520 lines   Manifest + signature
  dexview.py          ~250 lines   jadx/dex2jar
  emulator.py         ~200 lines   ABI translation

Services:

  omfs.py             ~480 lines   Project-centric storage
  virtual_fs.py       ~480 lines   FUSE-like FS
  sync.py             ~600 lines   CRDT sync
  sandbox.py          ~280 lines   Capability sandbox
  quarantine.py       ~130 lines   Threat quarantine
  pkgman.py           ~140 lines   Package manager
  modes.py            ~480 lines   Device/Perf/Power states
  telemetry_proto.py  ~300 lines   Binary ring buffer

UI and Tools:

  omega_dash.py       ~480 lines   Live curses dashboard
  om_health.py        ~460 lines   Health checker
  om_report.py        ~680 lines   HTML report
  report.py           ~230 lines   Older HTML report

Tests:

  test_suite.py       ~990 lines   75 tests
  test_omni.py        ~340 lines   22 tests
  test_acl.py         ~150 lines   5 tests
  test_pytest.py      ~250 lines   30 tests
  test_property.py    ~250 lines   12 tests
  conftest.py          ~80 lines   pytest fixtures
  fuzzer.py           ~180 lines   Random fuzzer

---

## 5. Git History (12 commits)

  f4bc8ce  Add collectors, Personal AI v2, and test tools
  e4592d7  Add dynamic Trust Score to Security AI v2
  9192c83  Fix zombie process filter in Security AI v2
  d730ceb  Add auto-quarantine to Security AI v2
  d55f94c  Add threat pattern classification to Security AI v2
  ecb1358  Add Security AI v2 with behavioral learning
  292c00f  Fix two subtle bugs in feedback evaluation
  590e721  Add feedback loop for Decision Engine
  7476a1b  Add README
  15f276e  Initial commit: OMEGA OS v0.8 Axon

---

## 6. What Was Built (latest session)

### Security AI v2 (security_v2.py)

Capabilities:

- Markov chain on process behavior sequences
- Time-decay (halflife 48h)
- 14 threat patterns:
    nc -l          -> HIGH     (netcat listener)
    nc -e          -> CRITICAL (command execution)
    curl | sh      -> CRITICAL (remote script pipe)
    wget | sh      -> CRITICAL
    nmap           -> HIGH     (port scanner)
    masscan        -> HIGH
    chmod 777      -> MEDIUM   (weak permissions)
    rm -rf /       -> CRITICAL (destructive)
    base64 -d      -> MEDIUM   (obfuscation)
    sudo           -> MEDIUM
    su -           -> MEDIUM
    /dev/tcp       -> HIGH     (bash tcp redir)
    ncat -l        -> HIGH
    nc -c          -> CRITICAL

- Auto-quarantine: SIGTERM first, SIGKILL fallback
- Dynamic Trust Score (0-100):
    +1 per 10 stable samples
    -5  for LOW severity
    -10 for MEDIUM severity
    -25 for HIGH severity
    -50 for CRITICAL severity
    <= 15  -> auto-kill
    <= 30  -> warn
    >= 80  -> trusted

- Zombie process filter

Test output:

  [security] auto-quarantine: nc -l (pid=22049) -> killed_force
  [HIGH    ] new_process            nc -l

### Personal AI v2 (personal_ai_v2.py)

Capabilities:

- Markov chain on workload sequences
- Time-decay (halflife 24h)
- Context-aware prediction:
    hour_bucket:  night / morning / midday / evening / late
    weekday
    battery_bucket
- Sequence grouping (gap < 30 min = one sequence)

Sample output:

  LIGHT (44x):
    -> LIGHT    59.2%  (bucket:evening)
    -> IDLE     22.6%
    -> WEB      18.2%

  WEB (8x):
    -> LIGHT    77.6%

### Feedback Loop (feedback_loop.py + smart_engine.py)

Capabilities:

- Log every decision to decisions.jsonl
- Evaluate outcome 60s later
- Score 0-100 based on:
    temperature change (cooled / warmed / overheated)
    battery trend (efficient / drain / charging / anomaly)
    state appropriateness (idle_but_busy, perf_but_hot)
- Auto-tune parameters after 20 samples
- Consistency checker (battery anomaly detection)

Sample scores:

  [1] battery drops 75->74, on battery  -> 75 (efficient)
  [2] on charger, battery grows         -> 55 (on_charger)
  [3] heavy load, temp rises            -> 15 (overheating)

### Collector (collector_job.py)

Capabilities:

- Android JobScheduler-based (survives Android kills)
- 15-minute interval
- 5 samples per burst
- No wake lock needed
- No battery drain
- Network: any (works on mobile data)

Register with:

  termux-job-scheduler --script ~/omega/collector_job.py \
                      --period-ms 900000 \
                      --network any \
                      --battery-not-low true \
                      --persisted true

---

## 7. Known Issues

Active:

- Honor kills Termux background processes
    Impact: collector stops without JobScheduler
    Fix: JobScheduler + battery unrestricted

- HAL cannot write (read-only)
    Impact: no frequency control
    Fix: requires root

- No real APK execution
    Impact: analysis only
    Fix: needs Waydroid or similar

- Wake lock sometimes ignored on Honor
    Impact: background stops
    Fix: use JobScheduler instead

Fixed (this session):

- Battery trend said "charging" wrongly
    Fix: use power_source field, not trend

- Temperature threshold bug (< vs <=)
    Fix: inclusive comparison

- State comparison bug (int vs string)
    Fix: use numeric codes

- <defunct> processes counted as new
    Fix: filter by "defunct" in name+args

- Syntax error in patch (regex template)
    Fix: use lambda in re.subn

---

## 8. Roadmap

Short-term (this week):

  [ ] Connect Security v2 to collector
  [ ] Whitelist UI for user-approved processes
  [ ] N-gram for Personal AI (3+ tuple sequences)
  [ ] Web UI instead of curses

Mid-term (this month):

  [ ] HAL write access (needs root)
  [ ] ACL real execution (Waydroid)
  [ ] Runtime Native with Flutter UI
  [ ] Better threat patterns (behavioral)

Long-term (months):

  [ ] Custom Linux kernel + HAL
  [ ] Raspberry Pi port
  [ ] Real APK execution
  [ ] Team building

---

## 9. Coding Conventions and Lessons

Critical rules:

1. f-string formatting:
   NEVER use:  f"{expr:format, other}"
   ALWAYS split:
       padded = c(name.ljust(26), C.WHITE)
       print(f"{padded}")

2. Heredocs work, large pastes don't:
   - Use cat > file << 'END' for files < 100 lines
   - For larger files, build in parts:
       cat >> file << 'END2'
   - Termux breaks on pastes > 500 lines

3. Consistency checkers are essential:
   - Battery cannot increase without charger
   - Temperature cannot jump > 15C in 60s
   - State codes are ints (0=IDLE, 1=BALANCED, ...)

4. Never trust data without validation:
   - power_source is truth for charging, not battery trend
   - Zombie processes show as <defunct>
   - ps comm field truncates at 15 chars

5. Build in parts, test in parts:
   - Write first 100 lines -> test import
   - Add next 100 lines -> test
   - Never write 500 lines before testing

6. Always commit and push after significant work:
   git add .
   git commit -m "descriptive message"
   git push

7. Test with real data, not happy path:
   - Fake data hides bugs
   - Real processes reveal edge cases
   - ps -eo pid,user,pcpu,comm,args is source of truth

Language:

  Code:          English (variables, comments)
  Conversation:  Persian (Farsi)
  Documentation: English technical, Persian context

---

## 10. User Context

Age: 16
Location: Iran
Background: Learning as we go

Strengths:

  - Systematic thinking
  - Testing discipline
  - Asks sharp questions
  - Catches subtle bugs
  - Long focus sessions

Preferences:

  - Persian for chat, English for code
  - Wants depth, not breadth
  - Values honesty over encouragement
  - Prefers concrete examples

Constraints:

  - Only phone (Honor X8) with Termux
  - Limited battery
  - School schedule
  - No team yet

Communication style:

  - Asks precise questions
  - Responds well to honest assessments
  - Wants to understand why, not just how
  - Values professional and honest answers

---

## 11. Environment Setup

Termux:

  pkg install python git -y
  pip install psutil pytest
  cd ~/omega
  python main.py --fast

Ubuntu (proot-distro):

  proot-distro login ubuntu
  bash /root/omega-init.sh

Required for collectors:

  termux-job-scheduler --script ~/omega/collector_job.py \
                      --period-ms 900000 \
                      --network any \
                      --battery-not-low true \
                      --persisted true

Android settings (mandatory for background):

  1. Settings > Apps > Termux > Battery > Unrestricted
  2. Settings > Battery > App Launch > Termux > Manage manually
       Auto-launch ON
       Secondary launch ON
       Run in background ON
  3. Settings > Developer options > Don't keep activities > OFF
  4. Recent Apps > Termux card > lock icon

---

## 12. How to Continue in a New Session

Step 1 - Check current state:

  cd ~/omega
  git pull
  git --no-pager log --oneline | head -5
  python om_health.py

Step 2 - Read this file (HANDOFF.md)

Step 3 - Paste this prompt into the new conversation:

  -----BEGIN PROMPT-----

  I'm working on OMEGA OS - a convergent, AI-native operating
  system prototype written in Python, running on Termux (Android).

  Repo: https://github.com/sadegh1389mirzaei-cell/omega-os

  Please:
  1. cd ~/omega && git pull
  2. cat HANDOFF.md
  3. git log --oneline | head -10
  4. python om_health.py

  Then let's continue working on [TOPIC].

  -----END PROMPT-----

Step 4 - Pick a topic from Roadmap section

Step 5 - Work incrementally:
  - Build files in 100-line chunks
  - Test imports after each chunk
  - Commit and push after each feature

---

## 13. Quick Reference

Enums (from omega.py):

  PerformanceState:  IDLE=0, BALANCED=1, PERFORMANCE=2,
                     CREATIVE=3, COMPUTE=4
  DeviceMode:        PHONE=0, TABLET=1, DESKTOP=2, DOCKED=3
  PowerTier:         NORMAL=0, LOW_POWER=1, EMERGENCY=2
  ThermalState:      NORMAL=0, WARNING=1, THROTTLE=2, EMERGENCY=3
  WorkloadClass:     IDLE=0, LIGHT=1, WEB=2, VIDEO=3,
                     GAMING_LIGHT=4, GAMING_HEAVY=5,
                     CREATIVE=6, COMPUTE=7
  PowerSource:       BATTERY=0, USB=1, WIRELESS=2, DOCK=3

Key commands:

  python main.py --fast       Boot system + dashboard
  python main.py --status     Show status
  python main.py --list       List subsystems
  python om_health.py         Health check
  python om_report.py         HTML report
  python omega_dash.py        Live dashboard
  python test_suite.py        All tests
  python security_v2.py real  Test security
  python personal_ai_v2.py    Test Personal AI
  python feedback_loop.py     Feedback stats

File locations:

  ~/omega/                         Main code directory
  ~/omega/bus_log.jsonl            Message bus events
  ~/omega/decisions.jsonl          Feedback decisions
  ~/omega/quarantine.jsonl         Security quarantine log
  ~/omega/personal_v2_model.json   Personal AI model
  ~/omega/security_v2_model.json   Security AI model
  ~/omega/storage/                 OMFS projects
  /opt/omega/                      Ubuntu mirror
  /root/omega-init.sh              Ubuntu boot script

Git commands:

  git status
  git add -A
  git commit -m "message"
  git push
  git --no-pager log --oneline | head -5

---

## 14. Contact and Repository

GitHub:  https://github.com/sadegh1389mirzaei-cell/omega-os
Branch:  main
License: TBD

Author:  Mamad (sadegh1389mirzaei-cell)
Started: 2026-09-28 (one night, ~14 hours)
Status:  Active development

---

Built on Termux, on a phone, in one night.

The operating system follows the user, not the other way around.
