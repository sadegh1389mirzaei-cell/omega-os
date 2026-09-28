# ==============================================================
# OMEGA OS - Message Bus
# ==============================================================
# Section 2.4 of the OMEGA spec.
# Lightweight pub/sub bus with:
#   - In-process EventBus (callbacks + wildcard topics)
#   - Unix domain socket for cross-process publish
#   - Append-only JSONL log (tail-able, replayable)
#   - CLI for sending/listening/clearing
# ==============================================================

import os
import sys
import json
import time
import socket
import signal
import threading
import fnmatch
import shlex
from dataclasses import dataclass, field, asdict
from typing import Callable, List, Optional, Dict, Tuple, Iterator
from collections import defaultdict


HOME = os.path.expanduser("~")
DEFAULT_LOG = os.path.join(HOME, "omega", "bus_log.jsonl")
DEFAULT_SOCKET = os.path.join(HOME, "omega", "bus.sock")


# ==============================================================
# Topics (canonical names used across the project)
# ==============================================================

class Topic:
    # Telemetry
    TELEMETRY_SAMPLE     = "telemetry.sample"
    TELEMETRY_TEMP_WARN  = "telemetry.temp_warn"

    # Decision Engine
    DECISION_STATE       = "decision.state"
    DECISION_STATE_CHG   = "decision.state.change"
    DECISION_COMMAND     = "decision.command"
    DECISION_PREWARM     = "decision.prewarm"

    # Security AI
    SECURITY_THREAT      = "security.threat"
    SECURITY_FILE_CHG    = "security.file.changed"
    SECURITY_PROCESS     = "security.process.new"
    SECURITY_TRUST_CHG   = "security.trust.change"
    SECURITY_LEVEL_CHG   = "security.level.change"

    # Storage / OMFS
    STORAGE_FILE_ADDED   = "storage.file.added"
    STORAGE_FILE_REMOVED = "storage.file.removed"
    STORAGE_PROJECT_NEW  = "storage.project.created"

    # System-wide
    SYSTEM_BOOT          = "system.boot"
    SYSTEM_SHUTDOWN      = "system.shutdown"
    SYSTEM_MODE_CHANGE   = "system.mode.change"


# ==============================================================
# Event
# ==============================================================

@dataclass
class Event:
    ts: int                       # unix ms
    topic: str
    source: str                   # who emitted
    payload: dict = field(default_factory=dict)
    severity: str = "INFO"        # INFO / LOW / MEDIUM / HIGH / CRITICAL

    def to_dict(self) -> dict:
        return asdict(self)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        return cls(
            ts=d.get("ts", 0),
            topic=d.get("topic", "?"),
            source=d.get("source", "?"),
            payload=d.get("payload", {}) or {},
            severity=d.get("severity", "INFO"),
        )

    @classmethod
    def from_jsonl(cls, line: str) -> Optional["Event"]:
        try:
            return cls.from_dict(json.loads(line))
        except (json.JSONDecodeError, TypeError):
            return None

    def short(self) -> str:
        hhmmss = time.strftime("%H:%M:%S", time.localtime(self.ts / 1000))
        sev = f"[{self.severity:<8}]" if self.severity != "INFO" else " " * 10
        return f"{hhmmss} {sev} {self.topic:<26} {self.source:<12} {self._payload_str()}"

    def _payload_str(self) -> str:
        if not self.payload:
            return ""
        bits = []
        for k, v in list(self.payload.items())[:3]:
            if isinstance(v, str):
                bits.append(f"{k}={v[:20]}")
            else:
                bits.append(f"{k}={v}")
        return " ".join(bits)


# ==============================================================
# In-process EventBus
# ==============================================================

class EventBus:
    """
    Synchronous pub/sub with wildcard topic patterns.

    Usage:
        bus = EventBus()
        bus.subscribe("security.*", on_security)
        bus.subscribe("decision.state.change", on_state)
        bus.emit(Topic.SECURITY_THREAT, "security_ai", subject="nc")
    """

    def __init__(self,
                 log_path: Optional[str] = DEFAULT_LOG,
                 echo: bool = False):
        self.log_path = log_path
        self.echo = echo
        self.subscribers: List[Tuple[str, Callable[[Event], None]]] = []
        self._lock = threading.Lock()
        self.total_emitted = 0

        if self.log_path:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    # ── Subscribe ──
    def subscribe(self, pattern: str, callback: Callable[[Event], None]) -> None:
        """pattern supports fnmatch wildcards: 'security.*', '*', 'a.b.c'."""
        with self._lock:
            self.subscribers.append((pattern, callback))

    def unsubscribe(self, callback: Callable[[Event], None]) -> None:
        with self._lock:
            self.subscribers = [(p, c) for p, c in self.subscribers if c is not callback]

    # ── Publish ──
    def publish(self, event: Event) -> None:
        """Deliver event to matching subscribers + write to log."""
        self.total_emitted += 1

        # Log first (so it's durable even if a subscriber crashes)
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(event.to_jsonl() + "\n")
            except OSError:
                pass

        # Echo to terminal if enabled
        if self.echo:
            print("  " + event.short())

        # Fan out
        with self._lock:
            subscribers = list(self.subscribers)

        for pattern, cb in subscribers:
            if fnmatch.fnmatch(event.topic, pattern):
                try:
                    cb(event)
                except Exception as e:
                    # never let one subscriber kill the bus
                    print(f"[bus] subscriber error: {e}", file=sys.stderr)

    def emit(self, topic: str, source: str,
             severity: str = "INFO", **payload) -> Event:
        """Convenience: build + publish in one call."""
        event = Event(
            ts=int(time.time() * 1000),
            topic=topic,
            source=source,
            payload=payload,
            severity=severity,
        )
        self.publish(event)
        return event


# ==============================================================
# Unix socket server (cross-process)
# ==============================================================

class BusServer:
    """
    Listens on a Unix domain socket.
    Each connection sends one JSON line (an Event) and closes.
    Received events are published to the given EventBus.
    """

    def __init__(self,
                 socket_path: str = DEFAULT_SOCKET,
                 bus: Optional[EventBus] = None):
        self.socket_path = socket_path
        self.bus = bus or EventBus()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.total_received = 0

    def start(self) -> None:
        # Remove stale socket
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.socket_path)
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self._running = True

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(conn)
            except Exception as e:
                print(f"[busd] handler error: {e}", file=sys.stderr)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(1.0)
        buf = b""
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break

        for line in buf.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            evt = Event.from_jsonl(line)
            if evt is None:
                continue
            self.total_received += 1
            self.bus.publish(evt)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass


# ==============================================================
# Client (publish over socket)
# ==============================================================

class BusClient:
    """Publishes events to a BusServer over the Unix socket."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET):
        self.socket_path = socket_path

    def publish(self, event: Event, timeout: float = 1.0) -> bool:
        if not os.path.exists(self.socket_path):
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(self.socket_path)
            s.sendall((event.to_jsonl() + "\n").encode("utf-8"))
            s.close()
            return True
        except (OSError, socket.timeout):
            return False

    def emit(self, topic: str, source: str,
             severity: str = "INFO", **payload) -> bool:
        evt = Event(
            ts=int(time.time() * 1000),
            topic=topic,
            source=source,
            payload=payload,
            severity=severity,
        )
        return self.publish(evt)


# ==============================================================
# Log utilities
# ==============================================================

def tail_log(path: str = DEFAULT_LOG,
             pattern: Optional[str] = None,
             follow: bool = True,
             limit: Optional[int] = None) -> Iterator[Event]:
    """Yield events from the log. If follow=True, keep reading new lines."""
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as f:
        # If not following, just read all (maybe limited)
        if not follow:
            lines = f.readlines()
            if limit:
                lines = lines[-limit:]
            for line in lines:
                evt = Event.from_jsonl(line)
                if evt and (not pattern or fnmatch.fnmatch(evt.topic, pattern)):
                    yield evt
            return

        # Follow mode
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            evt = Event.from_jsonl(line)
            if evt and (not pattern or fnmatch.fnmatch(evt.topic, pattern)):
                yield evt


def log_size(path: str = DEFAULT_LOG) -> int:
    if not os.path.exists(path):
        return 0
    with open(path) as f:
        return sum(1 for _ in f)


def log_clear(path: str = DEFAULT_LOG) -> None:
    if os.path.exists(path):
        os.remove(path)


# ==============================================================
# CLI
# ==============================================================

def cli_help():
    print("""
OMEGA Message Bus - CLI

Commands:
  python bus.py listen [pattern]         tail the log (ctrl+c to stop)
  python bus.py send <topic> [k=v ...]   publish one event
  python bus.py log [n]                  show last n events
  python bus.py clear                    truncate the log
  python bus.py stats                    show log size and last topics
  python bus.py daemon                   run the socket server
  python bus.py emit-test                emit a few demo events

Examples:
  python bus.py send security.threat subject=nc severity=HIGH
  python bus.py listen 'security.*'
  python bus.py log 20
""")


def cli_send(args):
    if not args:
        print("usage: send <topic> [key=value ...]")
        return
    topic = args[0]
    payload = {}
    severity = "INFO"
    for kv in args[1:]:
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        if k == "severity":
            severity = v.upper()
        else:
            # try to coerce
            try:
                v = int(v)
            except ValueError:
                try:
                    v = float(v)
                except ValueError:
                    pass
            payload[k] = v

    client = BusClient()
    ok = client.emit(topic, source="cli", severity=severity, **payload)
    if ok:
        print(f"[+] sent to {topic}")
    else:
        print(f"[!] daemon not running — writing directly to log")
        bus = EventBus()
        bus.emit(topic, source="cli", severity=severity, **payload)


def cli_listen(args):
    pattern = args[0] if args else None
    print(f"[*] tailing {DEFAULT_LOG}" +
          (f" (pattern: {pattern})" if pattern else ""))
    print("    ctrl+c to stop\n")
    try:
        for evt in tail_log(pattern=pattern, follow=True):
            print("  " + evt.short())
    except KeyboardInterrupt:
        print("\n[*] stopped")


def cli_log(args):
    n = int(args[0]) if args else 20
    if not os.path.exists(DEFAULT_LOG):
        print("(no log yet)")
        return
    lines = open(DEFAULT_LOG).readlines()[-n:]
    for line in lines:
        evt = Event.from_jsonl(line)
        if evt:
            print("  " + evt.short())


def cli_clear(args):
    log_clear()
    print("[+] log cleared")


def cli_stats(args):
    size = log_size()
    print(f"log path    : {DEFAULT_LOG}")
    print(f"total events: {size}")

    if size == 0:
        return

    topics: Dict[str, int] = defaultdict(int)
    sources: Dict[str, int] = defaultdict(int)
    sevs: Dict[str, int] = defaultdict(int)
    for evt in tail_log(follow=False):
        topics[evt.topic] += 1
        sources[evt.source] += 1
        sevs[evt.severity] += 1

    print("\ntopics:")
    for t, c in sorted(topics.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  {t:<32} {c}")
    print("\nsources:")
    for s, c in sorted(sources.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  {s:<32} {c}")
    print("\nseverity:")
    for s, c in sorted(sevs.items(), key=lambda kv: -kv[1]):
        print(f"  {s:<32} {c}")


def cli_daemon(args):
    bus = EventBus(echo=True)
    server = BusServer(bus=bus)

    def on_sigint(sig, frame):
        print("\n[*] shutting down")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)
    signal.signal(signal.SIGTERM, on_sigint)

    server.start()
    print(f"[*] busd listening on {server.socket_path}")
    print(f"[*] log: {bus.log_path}")
    print(f"[*] ctrl+c to stop")
    while True:
        time.sleep(0.5)


def cli_emit_test(args):
    bus = EventBus(echo=True)
    bus.emit("system.boot", "system", version="0.4")
    time.sleep(0.1)
    bus.emit("decision.state.change", "decision",
             old="BALANCED", new="PERFORMANCE")
    time.sleep(0.1)
    bus.emit("security.threat", "security_ai",
             subject="nc", severity="HIGH", pid=1234)
    time.sleep(0.1)
    bus.emit("storage.file.added", "omfs",
             file="report.pdf", project="Q3")
    time.sleep(0.1)
    bus.emit("telemetry.sample", "telemetry",
             cpu=42, ram=76, battery=27)
    print("\n[+] wrote 5 events to log")


def main():
    if len(sys.argv) < 2:
        cli_help()
        return
    cmd = sys.argv[1]
    args = sys.argv[2:]

    dispatch = {
        "listen":    cli_listen,
        "send":      cli_send,
        "log":       cli_log,
        "clear":     cli_clear,
        "stats":     cli_stats,
        "daemon":    cli_daemon,
        "emit-test": cli_emit_test,
        "help":      lambda a: cli_help(),
    }

    handler = dispatch.get(cmd)
    if not handler:
        print(f"unknown command: {cmd}")
        cli_help()
        return
    handler(args)


if __name__ == "__main__":
    main()
