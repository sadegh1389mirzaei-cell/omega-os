# ==============================================================
# OMEGA OS - Dex Viewer
# ==============================================================
# Decompile APK to Java using jadx, show class/method summary.
# Uses dex2jar as a fallback.
# ==============================================================

import os
import re
import sys
import shutil
import subprocess
import tempfile
from typing import List, Dict, Optional


HOME = os.path.expanduser("~")
TMP = os.path.join(HOME, "omega", "dexview_tmp")


def which(t): return shutil.which(t)

HAS_JADX    = bool(which("jadx"))
HAS_DEX2JAR = bool(which("d2j-dex2jar"))
HAS_D8      = bool(which("d8"))


class DexViewer:

    def __init__(self):
        os.makedirs(TMP, exist_ok=True)

    # ──────────────────────────────────────────────────────────
    # jadx-based decompile
    # ──────────────────────────────────────────────────────────

    def _jadx_classes(self, apk: str, work_dir: str) -> Dict[str, any]:
        """Run jadx, return {class_name: {methods, source_file}}."""
        if not HAS_JADX:
            return {}
        out = os.path.join(work_dir, "jadx")
        try:
            r = subprocess.run(
                ["jadx", "-d", out, "--no-res", "-j", "1",
                 "--show-bad-code", apk],
                capture_output=True, timeout=90,
            )
            # jadx often returns non-zero even on success
        except subprocess.TimeoutExpired:
            return {}

        sources_dir = os.path.join(out, "sources")
        if not os.path.isdir(sources_dir):
            return {}

        results = {}
        for root, _, files in os.walk(sources_dir):
            for f in files:
                if not f.endswith(".java"):
                    continue
                path = os.path.join(root, f)
                rel = os.path.relpath(path, sources_dir)
                class_name = rel[:-5].replace(os.sep, ".")
                try:
                    with open(path, "r", encoding="utf-8",
                              errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    continue
                methods = self._extract_methods(content)
                results[class_name] = {
                    "path": path,
                    "size": len(content),
                    "methods": methods,
                    "has_source": True,
                }
        return results

    @staticmethod
    def _extract_methods(java_src: str) -> List[str]:
        """Find method signatures in Java source."""
        # crude but effective
        methods = []
        pattern = re.compile(
            r"^\s*(?:public|private|protected|static|final|\s)+"
            r"[\w<>\[\],\s]+\s+(\w+)\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        )
        for m in pattern.finditer(java_src):
            name = m.group(1)
            if name not in ("if", "for", "while", "switch", "catch"):
                methods.append(name)
        return methods[:50]

    # ──────────────────────────────────────────────────────────
    # dex2jar fallback
    # ──────────────────────────────────────────────────────────

    def _dex2jar_classes(self, apk: str, work_dir: str) -> Dict[str, any]:
        """Extract dex2jar output — returns class list, no source."""
        if not HAS_DEX2JAR:
            return {}
        jar = os.path.join(work_dir, "output.jar")
        try:
            subprocess.run(
                ["d2j-dex2jar", "-f", "-o", jar, apk],
                capture_output=True, timeout=60,
            )
        except Exception:
            return {}

        if not os.path.exists(jar):
            return {}

        classes = self._list_jar_classes(jar)
        return {
            cls: {"path": jar, "has_source": False, "methods": []}
            for cls in classes
        }

    @staticmethod
    def _list_jar_classes(jar_path: str) -> List[str]:
        import zipfile
        classes = []
        try:
            with zipfile.ZipFile(jar_path) as z:
                for name in z.namelist():
                    if name.endswith(".class") and name != "META-INF/":
                        cls = name[:-6].replace("/", ".")
                        classes.append(cls)
        except Exception:
            pass
        return classes

    # ──────────────────────────────────────────────────────────

    def analyze(self, apk: str, top: int = 5) -> dict:
        if not os.path.exists(apk):
            raise FileNotFoundError(apk)

        work = tempfile.mkdtemp(dir=TMP)
        try:
            classes = self._jadx_classes(apk, work)
            method = "jadx"

            if not classes:
                classes = self._dex2jar_classes(apk, work)
                method = "dex2jar"

            # Pick top-N classes by size (most interesting)
            sorted_classes = sorted(
                classes.items(),
                key=lambda kv: kv[1].get("size", 0),
                reverse=True,
            )[:top]

            return {
                "method": method,
                "total_classes": len(classes),
                "top_classes": [
                    {
                        "name": name,
                        "size": info.get("size", 0),
                        "method_count": len(info.get("methods", [])),
                        "methods": info.get("methods", [])[:8],
                        "has_source": info.get("has_source", False),
                        "source_path": info.get("path", ""),
                    }
                    for name, info in sorted_classes
                ],
            }
        finally:
            # keep for inspection but not forever
            # shutil.rmtree(work, ignore_errors=True)
            pass


# ==============================================================
# CLI
# ==============================================================

def print_report(rep: dict, apk: str):
    C, G, Y, D, Z = ("\033[96m", "\033[92m", "\033[93m",
                     "\033[90m", "\033[0m")

    print()
    print(f"{C}══════════════════════════════════════════════════════════{Z}")
    print(f"{C}  Dex Viewer — {os.path.basename(apk)}{Z}")
    print(f"{C}══════════════════════════════════════════════════════════{Z}")

    print(f"\n  Method         : {rep['method']}")
    print(f"  Total classes  : {rep['total_classes']}")

    if not rep["top_classes"]:
        print(f"\n  {Y}(no classes extracted — decompiler unavailable or failed){Z}")
        return

    print(f"\n{D}[Top classes by size]{Z}")
    for i, cls in enumerate(rep["top_classes"], 1):
        name_short = cls["name"][-50:]
        print(f"\n  {i}. {C}{name_short}{Z}")
        print(f"     size: {cls['size']} bytes   "
              f"methods: {cls['method_count']}   "
              f"source: {'YES' if cls['has_source'] else 'bytecode-only'}")
        if cls["methods"]:
            print(f"     sample methods:")
            for m in cls["methods"][:5]:
                print(f"       • {m}()")
        if cls["has_source"]:
            print(f"     {D}file: {cls['source_path']}{Z}")


def cli():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("""
Dex Viewer — APK Decompiler

Usage:
  python dexview.py <apk>          decompile & summarize
  python dexview.py <apk> --top 10 top-10 classes
""")
        return

    apk = sys.argv[1]
    top = 5
    if "--top" in sys.argv:
        i = sys.argv.index("--top")
        if i + 1 < len(sys.argv):
            try: top = int(sys.argv[i + 1])
            except ValueError: pass

    if not os.path.exists(apk):
        print(f"[!] Not found: {apk}")
        return

    v = DexViewer()
    rep = v.analyze(apk, top=top)
    print_report(rep, apk)


if __name__ == "__main__":
    cli()
