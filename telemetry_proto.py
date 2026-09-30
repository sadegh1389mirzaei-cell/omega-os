# ==============================================================
# OMEGA OS - Telemetry Protocol
# ==============================================================
# Section 3.6.1 of the OMEGA spec.
# Binary ring buffer between kernel and AI Core.
# Fixed-size records, lock-free, self-describing.
# ==============================================================

import os
import time
import struct
import hashlib
import tempfile
from dataclasses import dataclass
from typing import Optional, List

# ==============================================================
# Record format (fixed size = 64 bytes)
# ==============================================================
# Offset  Size  Field
#   0      8    timestamp_ms       uint64
#   8      1    core_count         uint8
#   9      1    battery_pct        uint8
#  10      2    temp_soc_c_x10     uint16
#  12      4    cpu_avg_x100       uint32     (avg % * 100)
#  16      4    gpu_pct_x100       uint32
#  20      4    ram_pct_x100       uint32
#  24      4    ram_used_mb        uint32
#  28      4    zram_used_mb       uint32
#  32      1    tier               uint8
#  33      1    state              uint8
#  34      1    thermal            uint8
#  35      1    device             uint8
#  36      4    flags              uint32
#  40      8    seq                uint64
#  48     16    checksum           bytes
# ==============================================================

RECORD_SIZE = 64   # actual computed below
RECORD_FMT = "!QBBHIII IBBBBII"  # big-endian, packed
# note: extra spaces ignored; must match exactly
RECORD_FMT = "!QBBHIIIIIBBBBQI"   # 15 fields (with zram)
RECORD_SIZE = struct.calcsize(RECORD_FMT) + 16   # +16 for checksum


# ==============================================================
# Record
# ==============================================================

@dataclass
class TelemetryRecord:
    timestamp_ms: int
    core_count: int = 8
    battery_pct: int = 0
    temp_soc_c_x10: int = 0
    cpu_avg_x100: int = 0
    gpu_pct_x100: int = 0
    ram_pct_x100: int = 0
    ram_used_mb: int = 0
    zram_used_mb: int = 0
    tier: int = 0
    state: int = 0
    thermal: int = 0
    device: int = 0
    flags: int = 0
    seq: int = 0
    checksum: bytes = b"\x00" * 16

    def encode(self) -> bytes:
        # pack body (without checksum)
        body = struct.pack(
            RECORD_FMT,
            self.timestamp_ms & 0xFFFFFFFFFFFFFFFF,
            self.core_count & 0xFF,
            self.battery_pct & 0xFF,
            self.temp_soc_c_x10 & 0xFFFF,
            self.cpu_avg_x100 & 0xFFFFFFFF,
            self.gpu_pct_x100 & 0xFFFFFFFF,
            self.ram_pct_x100 & 0xFFFFFFFF,
            self.ram_used_mb & 0xFFFFFFFF,
            self.zram_used_mb & 0xFFFFFFFF,
            self.tier & 0xFF,
            self.state & 0xFF,
            self.thermal & 0xFF,
            self.device & 0xFF,
            self.flags & 0xFFFFFFFF,
            self.seq & 0xFFFFFFFFFFFFFFFF,
        )
        # checksum = first 16 bytes of sha256(body)
        chk = hashlib.sha256(body).digest()[:16]
        return body + chk

    @classmethod
    def decode(cls, data: bytes) -> "TelemetryRecord":
        if len(data) < RECORD_SIZE:
            raise ValueError("short record")

        body = data[:struct.calcsize(RECORD_FMT)]
        chk = data[struct.calcsize(RECORD_FMT):RECORD_SIZE]

        vals = struct.unpack(RECORD_FMT, body)
        expected = hashlib.sha256(body).digest()[:16]
        if chk != expected:
            raise ValueError("checksum mismatch")

        return cls(
            timestamp_ms=vals[0],
            core_count=vals[1],
            battery_pct=vals[2],
            temp_soc_c_x10=vals[3],
            cpu_avg_x100=vals[4],
            gpu_pct_x100=vals[5],
            ram_pct_x100=vals[6],
            ram_used_mb=vals[7],
            zram_used_mb=vals[8],
            tier=vals[9],
            state=vals[10],
            thermal=vals[11],
            device=vals[12],
            flags=vals[13],
            seq=vals[14],
            checksum=chk,
        )


# ==============================================================
# Ring buffer
# ==============================================================

class TelemetryRing:
    """
    Simulates the shared-memory ring buffer between kernel and AI Core.
    Writer: kernel (produces telemetry records)
    Reader: AI Core (consumes without syscall)
    """

    def __init__(self, path: Optional[str] = None,
                 slots: int = 256):
        self.slots = slots
        self.path = path or os.path.join(
            tempfile.gettempdir(), "omega_telemetry.ring")
        self.records: List[bytes] = [b""] * slots
        self.head = 0
        self.tail = 0
        self.overflow_count = 0
        self.bytes_written = 0
        self.bytes_read = 0
        self.checksum_errors = 0

    # ──────────────────────────────────────────────────────────

    def write(self, rec: TelemetryRecord) -> bool:
        """Write one record. Returns False if ring is full."""
        next_head = (self.head + 1) % self.slots
        if next_head == self.tail:
            self.overflow_count += 1
            return False
        self.records[self.head] = rec.encode()
        self.head = next_head
        self.bytes_written += RECORD_SIZE
        return True

    def read(self) -> Optional[TelemetryRecord]:
        """Read one record. Returns None if empty."""
        if self.tail == self.head:
            return None
        data = self.records[self.tail]
        self.records[self.tail] = b""
        self.tail = (self.tail + 1) % self.slots
        self.bytes_read += RECORD_SIZE
        try:
            return TelemetryRecord.decode(data)
        except ValueError:
            self.checksum_errors += 1
            return None

    # ──────────────────────────────────────────────────────────

    def usage_pct(self) -> float:
        return 100.0 * ((self.head - self.tail) % self.slots) / self.slots

    def is_empty(self) -> bool:
        return self.head == self.tail

    def is_full(self) -> bool:
        return (self.head + 1) % self.slots == self.tail

    def stats(self) -> dict:
        return {
            "slots": self.slots,
            "usage_pct": round(self.usage_pct(), 1),
            "writes_bytes": self.bytes_written,
            "reads_bytes": self.bytes_read,
            "overflow": self.overflow_count,
            "checksum_errors": self.checksum_errors,
        }


# ==============================================================
# Demo
# ==============================================================

def demo():
    print()
    print("=" * 72)
    print("  OMEGA Telemetry Protocol — binary ring buffer")
    print("=" * 72)

    print(f"\n  Record size: {RECORD_SIZE} bytes")

    # Verify roundtrip
    rec = TelemetryRecord(
        timestamp_ms=int(time.time() * 1000),
        core_count=8, battery_pct=78, temp_soc_c_x10=432,
        cpu_avg_x100=1250, gpu_pct_x100=8800,
        ram_pct_x100=7000, ram_used_mb=4200, zram_used_mb=2200,
        tier=0, state=1, thermal=1, device=3,
        flags=0, seq=1,
    )
    encoded = rec.encode()
    decoded = TelemetryRecord.decode(encoded)

    print(f"\n[1] Roundtrip test:")
    print(f"    encoded size : {len(encoded)} bytes")
    print(f"    timestamp    : {decoded.timestamp_ms}")
    print(f"    cpu_avg      : {decoded.cpu_avg_x100 / 100:.2f}%")
    print(f"    temp         : {decoded.temp_soc_c_x10 / 10:.1f}C")
    print(f"    checksum ok  : {decoded.checksum == encoded[-16:]}")

    # Ring buffer test
    print(f"\n[2] Ring buffer (256 slots):")
    ring = TelemetryRing(slots=256)

    # Write 100 records
    for i in range(100):
        rec = TelemetryRecord(
            timestamp_ms=int(time.time() * 1000),
            core_count=8, battery_pct=78,
            temp_soc_c_x10=420 + i % 20,
            cpu_avg_x100=(i * 37) % 10000,
            ram_pct_x100=7000, ram_used_mb=4200,
            zram_used_mb=2200,
            tier=0, state=1, thermal=1, device=0,
            seq=i + 1,
        )
        ring.write(rec)

    print(f"    writes       : 100")
    print(f"    usage        : {ring.usage_pct():.1f}%")
    print(f"    bytes written: {ring.bytes_written}")

    # Read 50 records
    read = 0
    temps = []
    while True:
        r = ring.read()
        if r is None:
            break
        temps.append(r.temp_soc_c_x10)
        read += 1
        if read >= 50:
            break

    print(f"\n    reads        : {read}")
    print(f"    usage        : {ring.usage_pct():.1f}%")
    print(f"    bytes read   : {ring.bytes_read}")

    # Overflow test
    print(f"\n[3] Overflow test (small ring):")
    small = TelemetryRing(slots=8)
    for i in range(20):
        rec = TelemetryRecord(timestamp_ms=i, seq=i)
        small.write(rec)
    print(f"    slots        : 8")
    print(f"    writes       : 20")
    print(f"    overflow     : {small.overflow_count}")

    # Stats
    print(f"\n[4] Ring statistics:")
    for k, v in ring.stats().items():
        print(f"    {k:<18} {v}")

    # Performance
    print(f"\n[5] Performance:")
    import timeit
    r = TelemetryRecord(timestamp_ms=0)
    enc_time = timeit.timeit(lambda: r.encode(), number=10000)
    data = r.encode()
    dec_time = timeit.timeit(lambda: TelemetryRecord.decode(data),
                            number=10000)
    print(f"    encode: {enc_time * 100:.1f} us/record")
    print(f"    decode: {dec_time * 100:.1f} us/record")
    print(f"    → max rate: {int(1e6 / (enc_time * 100)):,} records/sec")
    print()


if __name__ == "__main__":
    demo()
