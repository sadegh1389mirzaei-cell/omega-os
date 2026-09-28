# ==============================================================
# OMEGA OS - Virtual Filesystem
# ==============================================================
# Section 9.5.2 of the OMEGA spec (FUSE-like layer).
#
# Presents the OMFS project-centric storage as a conventional
# directory tree with three orthogonal views:
#
#   /projects/<name>/<file>      project view
#   /category/<cat>/<file>       category view
#   /tags/<tag>/<file>           tag view
#
# Also supports:
#   <any_dir>/.meta              directory metadata (JSON)
#   <any_file>.meta              file metadata (JSON)
# ==============================================================

import os
import json
import shlex
from typing import List, Optional, Dict, Tuple
from dataclasses import asdict

from omfs import OMFS, FileEntry, file_category


# ==============================================================
# Node abstraction
# ==============================================================

class VNode:
    """A virtual directory or file."""
    def __init__(self, name: str, kind: str,
                 entry: Optional[FileEntry] = None,
                 children: Optional[List["VNode"]] = None,
                 meta: Optional[dict] = None):
        self.name = name          # basename
        self.kind = kind          # "dir" | "file" | "meta"
        self.entry = entry        # FileEntry if kind == "file"
        self.children = children or []
        self.meta = meta or {}

    @property
    def is_dir(self) -> bool:
        return self.kind == "dir"

    def __repr__(self):
        return f"<VNode {self.kind} {self.name}>"


# ==============================================================
# Virtual Filesystem
# ==============================================================

class VirtualFS:
    """
    A read-only virtual filesystem built on top of OMFS.
    """

    def __init__(self, omfs: OMFS):
        self.omfs = omfs
        self.root = VNode("/", "dir")

    # ──────────────────────────────────────────────────────────
    # Path resolution
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def normalize(path: str) -> str:
        """Collapse .. and //, ensure leading /."""
        if not path.startswith("/"):
            path = "/" + path
        parts = []
        for p in path.split("/"):
            if p in ("", "."):
                continue
            if p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        return "/" + "/".join(parts)

    # ──────────────────────────────────────────────────────────
    # List directory
    # ──────────────────────────────────────────────────────────

    def list(self, path: str) -> List[Tuple[str, str]]:
        """
        Return list of (name, kind) entries at `path`.
        kind ∈ {"dir", "file"}
        """
        path = self.normalize(path)
        parts = [p for p in path.split("/") if p]

        if not parts:
            # Root: virtual top-level views
            return [
                ("projects", "dir"),
                ("category", "dir"),
                ("tags",     "dir"),
                (".meta",    "file"),
            ]

        top = parts[0]

        if top == "projects":
            if len(parts) == 1:
                return [(p.name, "dir") for p in self.omfs.list_projects()]

            project = parts[1]
            if project not in self.omfs.projects:
                return []
            if len(parts) == 2:
                entries = self.omfs.search(project=project)
                return [(os.path.basename(e.path), "file") for e in entries]
            return []   # no deeper (flat under project)

        if top == "category":
            if len(parts) == 1:
                cats = set(e.category for e in self.omfs.index.values())
                return [(c, "dir") for c in sorted(cats)]

            cat = parts[1]
            if len(parts) == 2:
                entries = self.omfs.search(category=cat)
                return [(os.path.basename(e.path), "file") for e in entries]
            return []

        if top == "tags":
            if len(parts) == 1:
                tags = set()
                for e in self.omfs.index.values():
                    tags.update(e.tags)
                return [(t, "dir") for t in sorted(tags)]

            tag = parts[1]
            if len(parts) == 2:
                entries = self.omfs.search(tags=[tag])
                return [(os.path.basename(e.path), "file") for e in entries]
            return []

        return []

    # ──────────────────────────────────────────────────────────
    # Resolve to FileEntry
    # ──────────────────────────────────────────────────────────

    def resolve(self, path: str) -> Optional[FileEntry]:
        """Return FileEntry if path points to a file (or .meta file)."""
        path = self.normalize(path)
        parts = [p for p in path.split("/") if p]

        # Handle .meta suffix
        if parts and parts[-1] == ".meta":
            return None   # special, handled separately
        if parts and parts[-1].endswith(".meta"):
            base = parts[-1][:-5]
            parts[-1] = base
            path = "/" + "/".join(parts)
            return self.resolve(path)

        if len(parts) < 3:
            return None

        top = parts[0]
        bucket = parts[1]
        fname = "/".join(parts[2:])

        if top == "projects":
            for e in self.omfs.search(project=bucket):
                if os.path.basename(e.path) == fname:
                    return e
        elif top == "category":
            for e in self.omfs.search(category=bucket):
                if os.path.basename(e.path) == fname:
                    return e
        elif top == "tags":
            for e in self.omfs.search(tags=[bucket]):
                if os.path.basename(e.path) == fname:
                    return e
        return None

    # ──────────────────────────────────────────────────────────
    # Metadata
    # ──────────────────────────────────────────────────────────

    def meta_for_path(self, path: str) -> Optional[dict]:
        """Return JSON-able metadata for a path."""
        path = self.normalize(path)
        parts = [p for p in path.split("/") if p]

        # File metadata (either explicit .meta or a plain file)
        stripped = path
        wants_meta_suffix = False
        if stripped.endswith(".meta"):
            stripped = stripped[:-5]
            wants_meta_suffix = True

        entry = self.resolve(stripped)
        if entry:
            d = entry.to_dict()
            d["size_kb"] = max(1, entry.size // 1024)
            d["path_virtual"] = path
            return d

        # Directory metadata
        if not parts:
            return {
                "kind": "dir",
                "path": "/",
                "views": ["projects", "category", "tags"],
                "projects": len(self.omfs.projects),
                "files": len(self.omfs.index),
            }

        top = parts[0]
        if top == "projects" and len(parts) == 2:
            proj = self.omfs.projects.get(parts[1])
            if proj:
                files = self.omfs.search(project=parts[1])
                return {
                    "kind": "project",
                    "name": proj.name,
                    "description": proj.description,
                    "tags": proj.tags,
                    "created": proj.created_ts,
                    "file_count": len(files),
                    "total_size_kb": sum(e.size for e in files) // 1024,
                }
        if top == "category" and len(parts) == 2:
            files = self.omfs.search(category=parts[1])
            return {
                "kind": "category",
                "name": parts[1],
                "file_count": len(files),
            }
        if top == "tags" and len(parts) == 2:
            files = self.omfs.search(tags=[parts[1]])
            return {
                "kind": "tag",
                "name": parts[1],
                "file_count": len(files),
            }

        return None

    # ──────────────────────────────────────────────────────────
    # Human-friendly listing
    # ──────────────────────────────────────────────────────────

    def ls(self, path: str) -> str:
        """Return formatted `ls` output."""
        path = self.normalize(path)
        items = self.list(path)

        if not items:
            return f"(empty or not found: {path})"

        # Partition
        dirs = [n for n, k in items if k == "dir"]
        files = [n for n, k in items if k == "file"]

        lines = [f"# {path}"]
        for d in sorted(dirs):
            lines.append(f"  [dir ]  {d}/")
        for f in sorted(files):
            # Try to show size if it's a real file
            entry = self.resolve(os.path.join(path, f))
            size = ""
            if entry:
                size = f"  ({max(1, entry.size // 1024)} KB)"
            lines.append(f"  [file]  {f}{size}")
        return "\n".join(lines)

    def tree(self, path: str = "/", depth: int = 2) -> str:
        """Pretty-print a subtree."""
        lines = []

        def walk(p: str, level: int):
            indent = "  " * level
            if level == 0:
                lines.append(p)
            if level >= depth:
                return
            for name, kind in self.list(p):
                child = p.rstrip("/") + "/" + name
                if kind == "dir":
                    lines.append(f"{indent}├── {name}/")
                    walk(child, level + 1)
                else:
                    lines.append(f"{indent}├── {name}")

        walk(self.normalize(path), 0)
        return "\n".join(lines)

    def cat(self, path: str) -> str:
        """Show file metadata (since we don't have file contents in VFS)."""
        entry = self.resolve(path)
        if not entry:
            return f"(not found: {path})"
        meta = entry.to_dict()
        meta["size_kb"] = max(1, entry.size // 1024)
        return json.dumps(meta, indent=2, ensure_ascii=False)

    def cat_meta(self, path: str) -> str:
        """Show .meta content for a path."""
        meta = self.meta_for_path(path)
        if not meta:
            return f"(no metadata: {path})"
        return json.dumps(meta, indent=2, ensure_ascii=False)


# ==============================================================
# Interactive shell
# ==============================================================

def shell_help():
    print("""
Commands:
  ls [path]           list directory
  tree [path] [depth] tree view
  cat <file>          show file metadata
  meta <path>         show path metadata
  pwd                 print current path
  cd <path>           change directory
  find <query>        find files by name
  tag <t1> [t2..]     find files by tags
  help                this message
  q | quit | exit     exit

Paths:
  /projects/<name>/<file>
  /category/<cat>/<file>
  /tags/<tag>/<file>
""")


def shell():
    omfs = OMFS()
    vfs = VirtualFS(omfs)
    cwd = "/"

    print("=" * 60)
    print("  OMFS Virtual Shell  (type 'help' for commands)")
    print("=" * 60)

    while True:
        try:
            line = input(f"vfs:{cwd}$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue

        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"parse error: {e}")
            continue

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("q", "quit", "exit"):
            break

        elif cmd == "help":
            shell_help()

        elif cmd == "pwd":
            print(cwd)

        elif cmd == "cd":
            target = args[0] if args else "/"
            new = target if target.startswith("/") else cwd.rstrip("/") + "/" + target
            new = VirtualFS.normalize(new)
            items = vfs.list(new)
            if not items and new != "/":
                print(f"(no such directory: {new})")
            else:
                cwd = new

        elif cmd == "ls":
            path = args[0] if args else cwd
            if not path.startswith("/"):
                path = cwd.rstrip("/") + "/" + path
            print(vfs.ls(path))

        elif cmd == "tree":
            path = args[0] if args else cwd
            depth = int(args[1]) if len(args) > 1 else 2
            if not path.startswith("/"):
                path = cwd.rstrip("/") + "/" + path
            print(vfs.tree(path, depth))

        elif cmd == "cat":
            if not args:
                print("usage: cat <file>")
                continue
            path = args[0] if args[0].startswith("/") else cwd.rstrip("/") + "/" + args[0]
            print(vfs.cat(path))

        elif cmd == "meta":
            if not args:
                print("usage: meta <path>")
                continue
            path = args[0] if args[0].startswith("/") else cwd.rstrip("/") + "/" + args[0]
            print(vfs.cat_meta(path))

        elif cmd == "find":
            if not args:
                print("usage: find <query>")
                continue
            q = args[0]
            hits = omfs.search(query=q)
            if not hits:
                print(f"(nothing matches '{q}')")
            for e in hits:
                print(f"  /projects/{e.project}/{os.path.basename(e.path)}")

        elif cmd == "tag":
            if not args:
                print("usage: tag <t1> [t2 ...]")
                continue
            hits = omfs.search(tags=args)
            if not hits:
                print(f"(nothing has tags {args})")
            for e in hits:
                print(f"  /projects/{e.project}/{os.path.basename(e.path)}")

        else:
            print(f"(unknown command: {cmd})")


# ==============================================================
# Demo (non-interactive)
# ==============================================================

def demo():
    omfs = OMFS()
    vfs = VirtualFS(omfs)

    print("=" * 60)
    print("  OMFS Virtual Filesystem Demo")
    print("=" * 60)

    print("\n[1] ls /")
    print(vfs.ls("/"))

    print("\n[2] ls /projects")
    print(vfs.ls("/projects"))

    print("\n[3] ls /projects/Dev")
    print(vfs.ls("/projects/Dev"))

    print("\n[4] ls /category")
    print(vfs.ls("/category"))

    print("\n[5] ls /tags")
    print(vfs.ls("/tags"))

    print("\n[6] tree / 3")
    print(vfs.tree("/", 3))

    print("\n[7] cat a file")
    print(vfs.cat("/projects/Dev/omega.py"))

    print("\n[8] meta a project")
    print(vfs.cat_meta("/projects/Dev"))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        shell()
