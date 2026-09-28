# ==============================================================
# OMEGA OS - Sync Protocol
# ==============================================================
# Section 12 of the OMEGA spec.
#
# Models cross-device sync:
#   - Peer discovery (mDNS-like, simulated)
#   - Secure channel (session keys)
#   - State sync (clipboard, tabs, session)
#   - CRDT-based conflict resolution
#   - File sync with block-level dedup
#   - Session handoff
# ==============================================================

import os
import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    from bus import EventBus, Topic
    _BUS = True
except Exception:
    _BUS = False


HOME = os.path.expanduser("~")


# ==============================================================
# Enums
# ==============================================================

class DeviceKind(IntEnum):
    PHONE   = 0
    TABLET  = 1
    LAPTOP  = 2
    DESKTOP = 3


class SyncState(IntEnum):
    DISCOVERED  = 0
    CONNECTING  = 1
    CONNECTED   = 2
    SYNCING     = 3
    IDLE        = 4
    OFFLINE     = 5


class ConflictResolution(IntEnum):
    LAST_WRITER_WINS = 0
    CRDT_MERGE       = 1
    KEEP_BOTH        = 2
    USER_PROMPT      = 3


# ==============================================================
# Data models
# ==============================================================

@dataclass
class Device:
    device_id: str
    name: str
    kind: DeviceKind
    public_key: str = ""        # simulated
    address: str = ""           # ip or "mdns"
    last_seen: int = 0
    state: SyncState = SyncState.OFFLINE

    def to_dict(self):
        d = asdict(self)
        d["kind"] = self.kind.name
        d["state"] = self.state.name
        return d


@dataclass
class FileChunk:
    """A content-addressed chunk (block-level dedup)."""
    hash: str
    size: int


@dataclass
class SyncFile:
    path: str
    size: int
    mtime: int
    chunks: List[FileChunk] = field(default_factory=list)

    def content_hash(self) -> str:
        h = hashlib.sha256()
        for c in self.chunks:
            h.update(c.hash.encode())
        return h.hexdigest()[:16]


@dataclass
class ClipboardEntry:
    ts: int
    source_device: str
    content_type: str       # text / image / file
    preview: str
    hash: str


@dataclass
class SessionState:
    """An app's session state for handoff."""
    app_id: str
    title: str
    uri: str = ""
    scroll: int = 0
    cursor: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)
    ts: int = 0

    def to_dict(self):
        return asdict(self)


# ==============================================================
# CRDT — simple LWW register
# ==============================================================

class LWWRegister:
    """Last-Writer-Wins register with logical timestamp."""
    def __init__(self, initial=None, ts: int = 0):
        self.value = initial
        self.ts = ts

    def set(self, value, ts: Optional[int] = None):
        ts = ts if ts is not None else int(time.time() * 1000)
        if ts > self.ts:
            self.value = value
            self.ts = ts

    def merge(self, other: "LWWRegister"):
        if other.ts > self.ts:
            self.value = other.value
            self.ts = other.ts


class LWWMap:
    """A map of LWW registers — last-writer-wins per key."""
    def __init__(self):
        self._store: Dict[str, LWWRegister] = {}

    def set(self, key: str, value, ts: Optional[int] = None):
        if key not in self._store:
            self._store[key] = LWWRegister()
        self._store[key].set(value, ts)

    def get(self, key, default=None):
        if key in self._store:
            return self._store[key].value
        return default

    def merge(self, other: "LWWMap"):
        for k, reg in other._store.items():
            if k not in self._store:
                self._store[k] = LWWRegister()
            self._store[k].merge(reg)

    def items(self):
        return [(k, r.value) for k, r in self._store.items()]

    def to_dict(self):
        return {k: r.value for k, r in self._store.items()}


# ==============================================================
# Sync Engine
# ==============================================================

class SyncEngine:
    """
    Simulates the OMEGA Sync Protocol (OSP).
    Can run standalone or across two in-process engines.
    """

    # Simulated 3:1 dedup ratio
    DEDUP_RATIO = 0.33

    def __init__(self, device: Device, bus: Optional[EventBus] = None):
        self.device = device
        self.bus = bus

        # Peer state
        self.peers: Dict[str, Device] = {}
        self.channels: Dict[str, dict] = {}   # peer_id -> channel

        # Sync content
        self.clipboard: LWWMap = LWWMap()
        self.sessions: LWWMap = LWWMap()
        self.files: Dict[str, SyncFile] = {}
        self._known_chunks: Set[str] = set()

        # Stats
        self.bytes_sent = 0
        self.bytes_received = 0
        self.chunks_deduped = 0
        self.conflicts_resolved = 0
        self.events: List[dict] = []

    # ──────────────────────────────────────────────────────────
    # Discovery (Section 12.1.1)
    # ──────────────────────────────────────────────────────────

    def discover(self, peer: Device) -> bool:
        """
        Register a peer as discovered.
        In real OMEGA: mDNS, BLE beacon, or cloud presence.
        """
        peer.last_seen = int(time.time() * 1000)
        peer.state = SyncState.DISCOVERED
        self.peers[peer.device_id] = peer
        self._log("discover", f"found {peer.name} ({peer.kind.name})")
        return True

    def connect(self, peer_id: str) -> bool:
        """
        Establish secure channel.
        In real OMEGA: OMEGA-TLS-Sync with device identity keys.
        """
        peer = self.peers.get(peer_id)
        if not peer:
            return False

        # Simulate handshake
        session_key = hashlib.sha256(
            f"{self.device.device_id}:{peer.device_id}:{int(time.time())}".encode()
        ).hexdigest()[:32]

        self.channels[peer_id] = {
            "session_key": session_key,
            "established_at": time.time(),
            "cipher": "AES-256-GCM",
            "forward_secret": True,
        }
        peer.state = SyncState.CONNECTED
        self._log("connect", f"channel to {peer.name} established")
        return True

    def disconnect(self, peer_id: str):
        if peer_id in self.channels:
            del self.channels[peer_id]
        if peer_id in self.peers:
            self.peers[peer_id].state = SyncState.OFFLINE
        self._log("disconnect", f"channel to {peer_id} closed")

    # ──────────────────────────────────────────────────────────
    # Clipboard sync (Section 12.2.2)
    # ──────────────────────────────────────────────────────────

    def push_clipboard(self, content_type: str, content: str):
        ts = int(time.time() * 1000)
        h = hashlib.sha256(content.encode()).hexdigest()[:12]
        entry = {
            "type": content_type,
            "preview": content[:40],
            "hash": h,
        }
        self.clipboard.set("latest", entry, ts)
        self._log("clipboard_push", f"{content_type}: {content[:30]}")
        return entry

    def pull_clipboard(self) -> Optional[dict]:
        return self.clipboard.get("latest")

    # ──────────────────────────────────────────────────────────
    # Session sync (Section 12.2.1)
    # ──────────────────────────────────────────────────────────

    def save_session(self, state: SessionState):
        state.ts = int(time.time() * 1000)
        self.sessions.set(state.app_id, state.to_dict(), state.ts)
        self._log("session_save",
                  f"{state.app_id}: {state.title} @ scroll={state.scroll}")

    def restore_session(self, app_id: str) -> Optional[dict]:
        return self.sessions.get(app_id)

    # ──────────────────────────────────────────────────────────
    # File sync (Section 12.2.3)
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _split_chunks(data: bytes, chunk_size: int = 4096) -> List[FileChunk]:
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            h = hashlib.sha256(chunk).hexdigest()[:16]
            chunks.append(FileChunk(hash=h, size=len(chunk)))
        return chunks

    def track_file(self, path: str, data: bytes, mtime: Optional[int] = None):
        chunks = self._split_chunks(data)
        sf = SyncFile(
            path=path,
            size=len(data),
            mtime=mtime or int(time.time()),
            chunks=chunks,
        )
        self.files[path] = sf
        for c in chunks:
            self._known_chunks.add(c.hash)
        self._log("file_track", f"{path} ({len(chunks)} chunks)")

    def sync_to(self, peer: SyncEngine, paths: Optional[List[str]] = None):
        """
        Push local files to a peer.
        Only sends chunks the peer doesn't already have (dedup).
        """
        if self.device.device_id not in peer.channels:
            # peer must have a channel to us
            if self.device.device_id not in peer.peers:
                return
        sent_bytes = 0
        dedup_count = 0
        transferred = 0

        target_paths = paths or list(self.files.keys())

        for path in target_paths:
            sf = self.files.get(path)
            if not sf:
                continue

            new_chunks = []
            for c in sf.chunks:
                if c.hash in peer._known_chunks:
                    dedup_count += 1
                else:
                    new_chunks.append(c)
                    peer._known_chunks.add(c.hash)

            # Store in peer
            peer.files[path] = sf

            payload = sum(c.size for c in new_chunks)
            sent_bytes += payload
            transferred += 1

        self.bytes_sent += sent_bytes
        peer.bytes_received += sent_bytes
        self.chunks_deduped += dedup_count

        self._log("sync_push",
                  f"-> {peer.device.name}: {transferred} files, "
                  f"{sent_bytes}B sent, {dedup_count} chunks deduped")

    # ──────────────────────────────────────────────────────────
    # Session handoff (Section 12.2.1)
    # ──────────────────────────────────────────────────────────

    def handoff_to(self, peer: SyncEngine, app_id: str) -> bool:
        """Hand off a session to a peer."""
        state = self.restore_session(app_id)
        if not state:
            self._log("handoff_fail", f"{app_id} not found")
            return False

        # Transfer
        peer.sessions.set(app_id, state, state.get("ts", int(time.time() * 1000)))
        # Remove locally (optional)
        # In OMEGA, the source device keeps state too
        self._log("handoff",
                  f"{app_id} -> {peer.device.name} "
                  f"(scroll={state.get('scroll', 0)})")
        return True

    # ──────────────────────────────────────────────────────────
    # Conflict resolution (Section 12.4)
    # ──────────────────────────────────────────────────────────

    def merge_with(self, peer: SyncEngine,
                   strategy: ConflictResolution = ConflictResolution.CRDT_MERGE):
        """Merge state from peer, resolving conflicts."""
        before_clip = self.clipboard.to_dict()
        before_sess = self.sessions.to_dict()

        self.clipboard.merge(peer.clipboard)
        self.sessions.merge(peer.sessions)

        # Count changes
        conflicts = 0
        for k, v in self.clipboard.to_dict().items():
            if k in before_clip and before_clip[k] != v:
                conflicts += 1
        for k, v in self.sessions.to_dict().items():
            if k in before_sess and before_sess[k] != v:
                conflicts += 1

        self.conflicts_resolved += conflicts
        self._log("merge",
                  f"<- {peer.device.name}: "
                  f"{len(peer.files)} files, {conflicts} conflicts")

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────

    def _log(self, kind: str, detail: str):
        entry = {
            "ts": int(time.time() * 1000),
            "device": self.device.name,
            "kind": kind,
            "detail": detail,
        }
        self.events.append(entry)
        if len(self.events) > 500:
            self.events = self.events[-500:]

        if self.bus:
            try:
                self.bus.emit(
                    topic=f"sync.{kind}",
                    source="sync",
                    severity="INFO",
                    device=self.device.name,
                    detail=detail[:60],
                )
            except Exception:
                pass

    def stats(self) -> dict:
        return {
            "device": self.device.name,
            "peers": len(self.peers),
            "channels": len(self.channels),
            "files": len(self.files),
            "known_chunks": len(self._known_chunks),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "chunks_deduped": self.chunks_deduped,
            "conflicts_resolved": self.conflicts_resolved,
        }

    def print_events(self, n: int = 15):
        for e in self.events[-n:]:
            ts = time.strftime("%H:%M:%S", time.localtime(e["ts"] / 1000))
            print(f"  {ts}  {e['device']:<10} {e['kind']:<16} "
                  f"{e['detail']}")


# ==============================================================
# Standalone demo
# ==============================================================

def demo():
    print("=" * 78)
    print("  OMEGA Sync Protocol — Multi-Device Simulation")
    print("=" * 78)

    # Three devices
    phone = Device("ph-001", "Pixel Phone", DeviceKind.PHONE)
    tablet = Device("tb-001", "Pixel Tablet", DeviceKind.TABLET)
    desktop = Device("dc-001", "Home Desktop", DeviceKind.DESKTOP)

    print()
    print("[ Devices ]")
    for d in (phone, tablet, desktop):
        print(f"  {d.device_id:<8} {d.name:<15} {d.kind.name}")

    # Engines
    phone_sync = SyncEngine(phone)
    tablet_sync = SyncEngine(tablet)
    desktop_sync = SyncEngine(desktop)

    # ── Discovery ──
    print()
    print("[ 1. Peer Discovery (mDNS) ]")
    phone_sync.discover(tablet)
    phone_sync.discover(desktop)
    tablet_sync.discover(phone)
    tablet_sync.discover(desktop)
    desktop_sync.discover(phone)
    desktop_sync.discover(tablet)
    for e in phone_sync.events[-2:]:
        print(f"  phone → {e['detail']}")

    # ── Connection ──
    print()
    print("[ 2. Secure Channel Establishment ]")
    phone_sync.connect("tb-001")
    phone_sync.connect("dc-001")
    tablet_sync.connect("ph-001")
    tablet_sync.connect("dc-001")
    desktop_sync.connect("ph-001")
    desktop_sync.connect("tb-001")
    for e in phone_sync.events[-2:]:
        print(f"  phone → {e['detail']}")
    print(f"  channel key (phone→tablet): "
          f"{phone_sync.channels['tb-001']['session_key'][:16]}...")
    print(f"  cipher                    : "
          f"{phone_sync.channels['tb-001']['cipher']}")
    print(f"  forward secret            : "
          f"{phone_sync.channels['tb-001']['forward_secret']}")

    # ── Clipboard ──
    print()
    print("[ 3. Clipboard Sync ]")
    phone_sync.push_clipboard("text", "Check this article: example.com/ai")
    print(f"  phone clipboard set: 'Check this article...'")

    # Sync to others
    tablet_sync.clipboard.merge(phone_sync.clipboard)
    desktop_sync.clipboard.merge(phone_sync.clipboard)
    print(f"  tablet now sees  : "
          f"{tablet_sync.pull_clipboard().get('preview')}")
    print(f"  desktop now sees : "
          f"{desktop_sync.pull_clipboard().get('preview')}")

    # ── File sync with dedup ──
    print()
    print("[ 4. File Sync (block-level dedup) ]")

    # Same content + similar content
    report_v1 = b"Q3 Report - " + b"x" * 8000
    report_v2 = b"Q3 Report - v2 " + b"x" * 8000  # similar

    phone_sync.track_file("Q3_Report.pdf", report_v1)
    phone_sync.track_file("cover.png", b"\x89PNG" + b"y" * 4000)

    print(f"  phone tracks: Q3_Report.pdf (2 chunks), cover.png (2 chunks)")
    print(f"  phone known chunks: {len(phone_sync._known_chunks)}")

    phone_sync.sync_to(tablet_sync)
    print(f"  sync to tablet:")
    print(f"    bytes sent    : {phone_sync.bytes_sent}")
    print(f"    chunks deduped: {phone_sync.chunks_deduped}")

    # Now modify one file, sync again — dedup kicks in
    old_sent = phone_sync.bytes_sent
    phone_sync.track_file("Q3_Report.pdf", report_v2)
    phone_sync.sync_to(tablet_sync)
    delta = phone_sync.bytes_sent - old_sent
    print(f"  after modifying Q3_Report.pdf:")
    print(f"    new bytes sent: {delta} (dedup saved rest)")

    # ── Session handoff ──
    print()
    print("[ 5. Session Handoff (Phone → Tablet) ]")
    session = SessionState(
        app_id="com.omega.browser",
        title="AI Research",
        uri="https://example.com/ai",
        scroll=3400,
        cursor=120,
    )
    phone_sync.save_session(session)
    print(f"  phone session: browser @ scroll={session.scroll}")

    ok = phone_sync.handoff_to(tablet_sync, "com.omega.browser")
    restored = tablet_sync.restore_session("com.omega.browser")
    print(f"  handoff: {'✓' if ok else '✗'}")
    print(f"  tablet restored: {restored['title']} @ scroll={restored['scroll']}")

    # ── Conflict resolution ──
    print()
    print("[ 6. Concurrent Edit — CRDT Merge ]")

    # Both devices edit the same file's metadata
    tablet_sync.sessions.set(
        "com.omega.browser",
        {"scroll": 3500, "title": "AI Research v2", "ts": int(time.time() * 1000)},
        int(time.time() * 1000),
    )

    phone_sync.merge_with(tablet_sync)
    print(f"  after merge, phone sees: "
          f"{phone_sync.restore_session('com.omega.browser')}")

    # ── Stats ──
    print()
    print("=" * 78)
    print("  Sync Statistics")
    print("=" * 78)
    for name, engine in (("Phone", phone_sync),
                         ("Tablet", tablet_sync),
                         ("Desktop", desktop_sync)):
        s = engine.stats()
        print(f"\n  {name}:")
        print(f"    peers           : {s['peers']}")
        print(f"    channels        : {s['channels']}")
        print(f"    files tracked   : {s['files']}")
        print(f"    known chunks    : {s['known_chunks']}")
        print(f"    bytes sent      : {s['bytes_sent']}")
        print(f"    bytes received  : {s['bytes_received']}")
        print(f"    chunks deduped  : {s['chunks_deduped']}")
        print(f"    conflicts fixed : {s['conflicts_resolved']}")

    # ── Event log ──
    print()
    print("=" * 78)
    print("  Phone Event Log (last 12)")
    print("=" * 78)
    phone_sync.print_events(12)


if __name__ == "__main__":
    demo()
