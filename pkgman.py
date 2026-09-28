# ==============================================================
# OMEGA OS - Package Manager
# ==============================================================
# Section 10 of the OMEGA spec.
# Manages .omapp packages (manifest + metadata).
# ==============================================================

import os
import json
import time
import shutil
from dataclasses import dataclass, field, asdict
from typing import List, Dict


HOME = os.path.expanduser("~")
PKG_DIR = os.path.join(HOME, "omega", "packages")
INDEX = os.path.join(PKG_DIR, "index.json")


@dataclass
class Package:
    app_id: str
    name: str
    version: str = "1.0.0"
    author: str = "unknown"
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    size_kb: int = 0
    installed_ts: int = 0
    trust: int = 50
    category: str = "utility"


class PackageManager:
    def __init__(self, bus=None):
        self.bus = bus
        os.makedirs(PKG_DIR, exist_ok=True)
        self.packages: Dict[str, Package] = {}
        self.load()

    def load(self):
        try:
            with open(INDEX) as f:
                d = json.load(f)
            for app_id, p in d.items():
                self.packages[app_id] = Package(**p)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self):
        with open(INDEX, "w") as f:
            json.dump({k: asdict(v) for k, v in self.packages.items()},
                     f, indent=2)

    def create(self, app_id: str, name: str, **kw) -> Package:
        p = Package(app_id=app_id, name=name,
                   installed_ts=int(time.time()), **kw)
        pkg_path = os.path.join(PKG_DIR, app_id)
        os.makedirs(pkg_path, exist_ok=True)
        with open(os.path.join(pkg_path, "manifest.json"), "w") as f:
            json.dump(asdict(p), f, indent=2)
        self.packages[app_id] = p
        self.save()
        if self.bus:
            self.bus.emit("package.install", "pkgman",
                         app_id=app_id, name=name)
        return p

    def remove(self, app_id: str) -> bool:
        if app_id not in self.packages:
            return False
        pkg_path = os.path.join(PKG_DIR, app_id)
        shutil.rmtree(pkg_path, ignore_errors=True)
        del self.packages[app_id]
        self.save()
        if self.bus:
            self.bus.emit("package.remove", "pkgman", app_id=app_id)
        return True

    def list_all(self) -> List[Package]:
        return sorted(self.packages.values(), key=lambda p: p.name)

    def search(self, query: str) -> List[Package]:
        q = query.lower()
        return [p for p in self.packages.values()
                if q in p.name.lower() or q in p.app_id.lower()
                or q in p.description.lower()]

    def by_category(self, cat: str) -> List[Package]:
        return [p for p in self.packages.values() if p.category == cat]

    def print_table(self):
        print(f"{'APP_ID':<28} {'VERSION':<9} {'TRUST':<6} NAME")
        print("-" * 80)
        for p in self.list_all():
            print(f"{p.app_id:<28} {p.version:<9} "
                  f"{p.trust:<6} {p.name}")


if __name__ == "__main__":
    pm = PackageManager()

    pm.create("com.omega.mail", "OMEGA Mail",
             version="2.1.0", author="OMEGA Team",
             description="Native mail client",
             permissions=["NETWORK", "FILES_READ"],
             trust=90, category="productivity")
    pm.create("com.omega.photos", "Photos",
             version="1.5.3", author="OMEGA Team",
             description="Photo viewer and editor",
             permissions=["FILES_READ", "CAMERA"],
             trust=85, category="creative")
    pm.create("com.omega.notes", "Notes",
             version="1.0.2", author="OMEGA Team",
             description="Simple note-taking",
             permissions=["FILES_READ", "FILES_WRITE"],
             trust=88, category="productivity")
    pm.create("com.thirdparty.cleaner", "System Cleaner",
             version="0.1.0", author="Unknown Corp",
             description="Cleans your device",
             permissions=["FILES_READ", "FILES_WRITE", "NETWORK"],
             trust=25, category="utility")

    print("=" * 80)
    print("  OMEGA Package Manager")
    print("=" * 80)
    pm.print_table()
    print()
    print(f"Total packages: {len(pm.packages)}")
    print()
    print("Search 'omega':")
    for p in pm.search("omega"):
        print(f"  {p.app_id:<28} trust={p.trust}")
    print()
    print("Low-trust packages (< 40):")
    for p in pm.packages.values():
        if p.trust < 40:
            print(f"  ⚠  {p.app_id:<28} trust={p.trust}  "
                  f"perms={','.join(p.permissions)}")
    print()
    print("Productivity category:")
    for p in pm.by_category("productivity"):
        print(f"  {p.name}  v{p.version}")
