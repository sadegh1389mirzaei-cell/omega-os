# ==============================================================
# OMEGA OS - ABI Emulator Cost Model
# ==============================================================
# Section 5.2.1 of the OMEGA spec.
# When an APK has x86 native libs but the host is ARM,
# we must emulate. This module models the cost.
# ==============================================================

from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import List, Dict


class ABI(IntEnum):
    ARM64_V8A   = 0
    ARMEABI_V7A = 1
    X86         = 2
    X86_64      = 3
    MIPS        = 4
    RISCV64     = 5
    UNKNOWN     = 99


# ==============================================================
# Translation costs (from research: QEMU, Box86, ARM FEX)
# ==============================================================

# CPU multiplier when running <key> lib on <host>
# host assumed ARM64
ABI_COST: Dict[ABI, float] = {
    ABI.ARM64_V8A:   1.00,    # native
    ABI.ARMEABI_V7A: 1.15,    # 32-bit ARM on 64-bit ARM (via compat)
    ABI.X86:         2.50,    # x86 → ARM (Box86-like)
    ABI.X86_64:      2.20,    # x86_64 → ARM64 (Box64-like)
    ABI.MIPS:        4.50,    # almost no JIT
    ABI.RISCV64:     2.80,    # QEMU RISC-V
    ABI.UNKNOWN:     3.00,
}

# Syscall translation overhead (any foreign ABI)
SYSCALL_OVERHEAD = 0.10        # +10% on foreign ABI

# GPU access when translated
GPU_TRANSLATION = 1.05         # +5% for foreign ABI

# Memory overhead
MEM_OVERHEAD = 1.20            # +20% for emulation buffers


@dataclass
class EmulationEstimate:
    apk_name: str
    host_abi: ABI
    apk_abis: List[ABI]
    chosen_abi: ABI
    is_native: bool
    cpu_mult: float
    mem_mult: float
    gpu_mult: float
    syscall_penalty: float
    extra_ram_mb: int = 0
    notes: List[str] = None

    def __post_init__(self):
        self.notes = self.notes or []

    def total_cpu_mult(self) -> float:
        return self.cpu_mult + (self.syscall_penalty if not self.is_native else 0)

    def to_dict(self):
        d = asdict(self)
        d["host_abi"] = self.host_abi.name
        d["apk_abis"] = [a.name for a in self.apk_abis]
        d["chosen_abi"] = self.chosen_abi.name
        return d


# ==============================================================
# Emulator
# ==============================================================

class ABIEmulator:

    HOST_ABI = ABI.ARM64_V8A   # assume OMEGA runs on ARM64

    def __init__(self, host_abi: ABI = ABI.ARM64_V8A):
        self.host_abi = host_abi

    def estimate(self, apk_name: str,
                 apk_abis: List[ABI],
                 base_cpu_mhz: int = 500,
                 base_mem_mb: int = 200,
                 base_gpu_mhz: int = 200) -> EmulationEstimate:
        # Choose best ABI for our host
        chosen = self._choose_abi(apk_abis)
        is_native = (chosen == self.host_abi)

        cpu_mult = ABI_COST.get(chosen, ABI_COST[ABI.UNKNOWN])
        mem_mult = MEM_OVERHEAD if not is_native else 1.00
        gpu_mult = GPU_TRANSLATION if not is_native else 1.00
        syscall  = SYSCALL_OVERHEAD if not is_native else 0.00

        # Extra RAM for emulator runtime
        extra_ram = 0
        if not is_native:
            extra_ram = 50 + (30 if chosen in (ABI.X86, ABI.X86_64) else 0)

        notes = []
        if is_native:
            notes.append(f"Native {chosen.name} — full speed")
        else:
            notes.append(f"Emulating {chosen.name} on {self.host_abi.name}")
            notes.append(f"CPU cost x{cpu_mult:.2f}, "
                        f"syscall +{syscall*100:.0f}%")
            notes.append(f"Extra RAM for emulator: {extra_ram} MB")
            if chosen in (ABI.MIPS,):
                notes.append("⚠ MIPS JIT is very slow — heavy apps unlikely")

        return EmulationEstimate(
            apk_name=apk_name,
            host_abi=self.host_abi,
            apk_abis=apk_abis,
            chosen_abi=chosen,
            is_native=is_native,
            cpu_mult=cpu_mult,
            mem_mult=mem_mult,
            gpu_mult=gpu_mult,
            syscall_penalty=syscall,
            extra_ram_mb=extra_ram,
            notes=notes,
        )

    def _choose_abi(self, abis: List[ABI]) -> ABI:
        """Pick the ABI that's cheapest to emulate on our host."""
        if not abis:
            return ABI.UNKNOWN
        # Prefer same as host
        if self.host_abi in abis:
            return self.host_abi
        # Otherwise pick cheapest cost
        return min(abis, key=lambda a: ABI_COST.get(a, 3.0))


# ==============================================================
# Demo
# ==============================================================

def demo():
    print()
    print("=" * 72)
    print("  OMEGA ABI Emulator — translation cost model")
    print("=" * 72)

    emu = ABIEmulator(host_abi=ABI.ARM64_V8A)

    scenarios = [
        ("game_arm64.apk",  [ABI.ARM64_V8A]),
        ("legacy_arm32.apk",[ABI.ARMEABI_V7A]),
        ("old_x86.apk",     [ABI.X86]),
        ("native_x64.apk",  [ABI.X86_64]),
        ("riscv.apk",       [ABI.RISCV64]),
        ("both.apk",        [ABI.ARM64_V8A, ABI.X86_64]),
        ("weird.apk",       [ABI.MIPS]),
    ]

    print()
    print(f"  {'APK':<22} {'CHOSEN':<12} {'NATIVE':<7} "
          f"{'CPU':<6} {'MEM':<6} {'+RAM':<6}")
    print("  " + "─" * 68)

    for name, abis in scenarios:
        est = emu.estimate(name, abis)
        native = "YES" if est.is_native else "no"
        cpu = f"x{est.total_cpu_mult():.2f}"
        mem = f"x{est.mem_mult:.2f}"
        ram = f"{est.extra_ram_mb}MB" if est.extra_ram_mb else "—"
        print(f"  {name:<22} {est.chosen_abi.name:<12} {native:<7} "
              f"{cpu:<6} {mem:<6} {ram:<6}")

    # Detailed view
    print()
    print("[Details for old_x86.apk]")
    est = emu.estimate("old_x86.apk", [ABI.X86])
    for n in est.notes:
        print(f"  • {n}")
    print()

    # Actual resource estimates
    print("[Resource estimates for x86 APK]")
    base_cpu = 1000
    base_mem = 300
    est = emu.estimate("test.apk", [ABI.X86],
                      base_cpu_mhz=base_cpu, base_mem_mb=base_mem)
    print(f"  Base CPU       : {base_cpu} MHz")
    print(f"  Emulated CPU   : {int(base_cpu * est.total_cpu_mult())} MHz")
    print(f"  Base RAM       : {base_mem} MB")
    print(f"  Emulated RAM   : {int(base_mem * est.mem_mult) + est.extra_ram_mb} MB")
    print()


if __name__ == "__main__":
    demo()
