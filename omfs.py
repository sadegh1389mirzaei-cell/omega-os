# ==============================================================
# OMEGA OS - OMFS (Intelligent Storage)
# ==============================================================
# Section 9 of the OMEGA spec.
#
# Project-centric storage with:
#   - Projects as first-class containers
#   - Auto-tagging by file type + name
#   - Knowledge graph (simple relationships)
#   - Semantic search
# ==============================================================

import os
import re
import json
import time
import hashlib
import shutil
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict


HOME = os.path.expanduser("~")
DEFAULT_ROOT = os.path.join(HOME, "omega")


# ==============================================================
# File type detection
# ==============================================================

EXT_CATEGORY = {
    # Documents
    ".pdf": "document", ".doc": "document", ".docx": "document",
    ".odt": "document", ".rtf": "document", ".txt": "document",
    ".md": "document", ".tex": "document",

    # Spreadsheets
    ".xls": "spreadsheet", ".xlsx": "spreadsheet",
    ".ods": "spreadsheet", ".csv": "spreadsheet",

    # Presentations
    ".ppt": "presentation", ".pptx": "presentation",
    ".odp": "presentation", ".key": "presentation",

    # Images
    ".jpg": "image", ".jpeg": "image", ".png": "image",
    ".gif": "image", ".bmp": "image", ".webp": "image",
    ".svg": "image", ".heic": "image", ".tiff": "image",

    # Video
    ".mp4": "video", ".mkv": "video", ".avi": "video",
    ".mov": "video", ".webm": "video", ".flv": "video",

    # Audio
    ".mp3": "audio", ".wav": "audio", ".flac": "audio",
    ".ogg": "audio", ".m4a": "audio", ".opus": "audio",

    # Code
    ".py": "code", ".js": "code", ".ts": "code",
    ".rs": "code", ".c": "code", ".cpp": "code",
    ".h": "code", ".hpp": "code", ".go": "code",
    ".java": "code", ".kt": "code", ".rb": "code",
    ".sh": "code", ".bash": "code", ".zsh": "code",
    ".html": "code", ".css": "code", ".json": "code",
    ".yaml": "code", ".yml": "code", ".toml": "code",
    ".xml": "code", ".sql": "code",

    # Archives
    ".zip": "archive", ".tar": "archive", ".gz": "archive",
    ".bz2": "archive", ".xz": "archive", ".7z": "archive",
    ".rar": "archive",

    # Executables
    ".apk": "executable", ".exe": "executable",
    ".bin": "executable", ".deb": "executable",

    # Data / ML
    ".onnx": "model", ".pt": "model", ".tflite": "model",
    ".safetensors": "model", ".pkl": "model",
}


def file_category(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    return EXT_CATEGORY.get(ext, "other")


def file_hash(path: str, limit: int = 512 * 1024) -> str:
    """SHA-256 of first `limit` bytes."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read(limit))
        return h.hexdigest()[:16]
    except OSError:
        return ""


# ==============================================================
# Data models
# ==============================================================

@dataclass
class FileEntry:
    path: str
    project: str
    category: str
    tags: List[str]
    size: int
    added_ts: int
    modified_ts: int
    content_hash: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Project:
    name: str
    created_ts: int
    description: str = ""
    tags: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# ==============================================================
# OMFS
# ==============================================================

class OMFS:
    """
    Project-centric intelligent storage.

    Root layout:
        <root>/projects/<project>/...     actual files
        <root>/.omfs/index.json            file metadata
        <root>/.omfs/projects.json         project list
        <root>/.omfs/graph.json            relationships
    """

    # Words to ignore when extracting tags
    STOP_WORDS = {
        "the", "and", "for", "with", "from", "new", "old",
        "copy", "final", "draft", "backup", "temp", "tmp",
        "file", "data", "test",
    }

    # Semantic keywords to always highlight as tags
    SEMANTIC_KEYWORDS = {
        "report", "budget", "invoice", "receipt",
        "photo", "screenshot", "scan", "memo",
        "resume", "letter", "note",
        "log", "config", "setup", "install",
        "readme", "license", "notice",
    }

    def __init__(self, root: Optional[str] = None):
        self.root = root or os.path.join(DEFAULT_ROOT, "storage")
        self.projects_dir = os.path.join(self.root, "projects")
        self.meta_dir = os.path.join(self.root, ".omfs")

        os.makedirs(self.projects_dir, exist_ok=True)
        os.makedirs(self.meta_dir, exist_ok=True)

        self.index: Dict[str, FileEntry] = {}
        self.projects: Dict[str, Project] = {}
        self.graph: Dict[str, List[str]] = {}

        self._load()

    # ──────────────────────────────────────────────────────────
    # Persistence
    # ──────────────────────────────────────────────────────────

    def _index_path(self):
        return os.path.join(self.meta_dir, "index.json")

    def _projects_path(self):
        return os.path.join(self.meta_dir, "projects.json")

    def _graph_path(self):
        return os.path.join(self.meta_dir, "graph.json")

    def _load(self):
        try:
            with open(self._index_path()) as f:
                data = json.load(f)
            for path, d in data.items():
                self.index[path] = FileEntry(**d)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        try:
            with open(self._projects_path()) as f:
                data = json.load(f)
            for name, d in data.items():
                self.projects[name] = Project(**d)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        try:
            with open(self._graph_path()) as f:
                self.graph = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save(self):
        with open(self._index_path(), "w") as f:
            json.dump({p: e.to_dict() for p, e in self.index.items()},
                      f, indent=2)
        with open(self._projects_path(), "w") as f:
            json.dump({n: p.to_dict() for n, p in self.projects.items()},
                      f, indent=2)
        with open(self._graph_path(), "w") as f:
            json.dump(self.graph, f, indent=2)

    # ──────────────────────────────────────────────────────────
    # Project operations
    # ──────────────────────────────────────────────────────────

    def create_project(self, name: str, description: str = "",
                       tags: Optional[List[str]] = None) -> Project:
        if name in self.projects:
            return self.projects[name]

        p = Project(
            name=name,
            created_ts=int(time.time()),
            description=description,
            tags=tags or [],
        )
        self.projects[name] = p
        os.makedirs(os.path.join(self.projects_dir, name), exist_ok=True)
        self.save()
        return p

    def delete_project(self, name: str, delete_files: bool = False) -> bool:
        if name not in self.projects:
            return False
        if delete_files:
            shutil.rmtree(os.path.join(self.projects_dir, name),
                          ignore_errors=True)
        del self.projects[name]
        self.save()
        return True

    def list_projects(self) -> List[Project]:
        return list(self.projects.values())

    # ──────────────────────────────────────────────────────────
    # File operations
    # ──────────────────────────────────────────────────────────

    def _infer_tags(self, name: str, category: str) -> List[str]:
        """Extract semantic tags from filename + category."""
        tags = {category}
        base = os.path.splitext(name)[0].lower()

        # Split filename into words by common separators
        words = re.split(r"[-_.\s]+", base)
        words = [w for w in words if len(w) >= 3]

        # Add each significant word as a tag
        for w in words:
            if w not in self.STOP_WORDS:
                tags.add(w)

        # Highlight semantic keywords
        for w in words:
            if w in self.SEMANTIC_KEYWORDS:
                tags.add(w)

        # Detect dated files
        if re.search(r"\d{4}[-_]\d{2}[-_]\d{2}", base):
            tags.add("dated")

        return sorted(tags)

    def add_file(self, src_path: str, project: str,
                 dest_name: Optional[str] = None,
                 copy: bool = True) -> Optional[FileEntry]:
        """Add a file to a project. copy=True → actual copy, else symlink."""
        if not os.path.isfile(src_path):
            return None

        self.create_project(project)
        proj_dir = os.path.join(self.projects_dir, project)
        os.makedirs(proj_dir, exist_ok=True)

        name = dest_name or os.path.basename(src_path)
        dest = os.path.join(proj_dir, name)

        # Avoid duplicates
        if os.path.exists(dest):
            base, ext = os.path.splitext(name)
            i = 1
            while os.path.exists(dest):
                dest = os.path.join(proj_dir, f"{base}_{i}{ext}")
                i += 1

        try:
            if copy:
                shutil.copy2(src_path, dest)
            else:
                os.symlink(os.path.abspath(src_path), dest)
        except OSError:
            return None

        st = os.stat(dest)
        cat = file_category(dest)
        tags = self._infer_tags(name, cat)

        entry = FileEntry(
            path=dest,
            project=project,
            category=cat,
            tags=tags,
            size=st.st_size,
            added_ts=int(time.time()),
            modified_ts=int(st.st_mtime),
            content_hash=file_hash(dest),
        )
        self.index[dest] = entry
        self.projects[project].files.append(dest)

        self._update_graph(entry)
        self.rebuild_graph()
        self.save()
        return entry

    def _update_graph(self, entry: FileEntry):
        """
        Build meaningful relationships:
          1. duplicate_of  — same content hash
          2. variant_of    — same stem, different extension
          3. related(word) — shared significant word in filename (same project)
        """
        related = []

        entry_base = os.path.splitext(os.path.basename(entry.path))[0].lower()
        entry_stem_words = set(re.split(r"[-_.]+", entry_base))
        entry_stem_words = {w for w in entry_stem_words if len(w) >= 4}

        for path, other in self.index.items():
            if path == entry.path:
                continue

            # 1. Content duplicate
            if (other.content_hash and entry.content_hash
                    and other.content_hash == entry.content_hash):
                related.append(("duplicate_of", path))
                continue

            # 2. Same stem, different category → variant
            other_base = os.path.splitext(os.path.basename(path))[0].lower()
            if other_base == entry_base and other.category != entry.category:
                related.append(("variant_of", path))
                continue

            # 3. Shared significant word, same project
            if other.project != entry.project:
                continue
            other_stem_words = set(re.split(r"[-_.]+", other_base))
            shared = entry_stem_words & other_stem_words
            if shared:
                rel = "related(" + ",".join(sorted(shared)) + ")"
                related.append((rel, path))

        if related:
            self.graph[entry.path] = [f"{rel}:{p}" for rel, p in related]
        else:
            self.graph.pop(entry.path, None)

    def rebuild_graph(self):
        """Rebuild the entire graph from scratch to ensure symmetry."""
        self.graph = {}
        for entry in list(self.index.values()):
            self._update_graph(entry)

    def remove_file(self, path: str, delete: bool = False) -> bool:
        if path not in self.index:
            return False
        entry = self.index[path]
        if delete:
            try:
                os.remove(path)
            except OSError:
                pass
        if path in self.projects[entry.project].files:
            self.projects[entry.project].files.remove(path)
        del self.index[path]
        self.graph.pop(path, None)
        self.save()
        return True

    # ──────────────────────────────────────────────────────────
    # Search
    # ──────────────────────────────────────────────────────────

    def search(self,
               query: str = "",
               project: Optional[str] = None,
               category: Optional[str] = None,
               tags: Optional[List[str]] = None) -> List[FileEntry]:
        """Search across name, tags, category."""
        q = query.lower()
        out = []
        for entry in self.index.values():
            if project and entry.project != project:
                continue
            if category and entry.category != category:
                continue
            if tags:
                if not all(t in entry.tags for t in tags):
                    continue
            if q:
                name = os.path.basename(entry.path).lower()
                if (q not in name
                        and not any(q in t for t in entry.tags)
                        and q != entry.category):
                    continue
            out.append(entry)
        return out

    def stats(self) -> dict:
        total_size = sum(e.size for e in self.index.values())
        by_cat = defaultdict(int)
        by_proj = defaultdict(int)
        for e in self.index.values():
            by_cat[e.category] += 1
            by_proj[e.project] += 1

        return {
            "projects": len(self.projects),
            "files": len(self.index),
            "total_size_mb": total_size // (1024 * 1024),
            "by_category": dict(by_cat),
            "by_project": dict(by_proj),
            "graph_edges": sum(len(v) for v in self.graph.values()),
        }


# ==============================================================
# Standalone demo
# ==============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  OMFS - Intelligent Storage Demo")
    print("=" * 60)

    omfs = OMFS()

    omfs.create_project("Research", "AI research notes",
                        tags=["work", "science"])
    omfs.create_project("Personal", "Personal documents")
    omfs.create_project("Dev", "Development files",
                        tags=["work", "code"])

    print(f"\n[+] Projects: {[p.name for p in omfs.list_projects()]}")

    here = os.path.dirname(os.path.abspath(__file__))
    samples = [
        (os.path.join(here, "omega.py"), "Dev"),
        (os.path.join(here, "security_ai.py"), "Dev"),
        (os.path.join(here, "processes.py"), "Dev"),
        (os.path.join(here, "omega_dash.py"), "Dev"),
        (os.path.join(here, "real_telemetry.py"), "Dev"),
        (os.path.join(here, "omfs.py"), "Dev"),
    ]

    print(f"\n[+] Adding {len(samples)} files to projects...")
    for src, proj in samples:
        if os.path.exists(src):
            entry = omfs.add_file(src, proj)
            if entry:
                tags_str = ",".join(entry.tags)
                print(f"  {os.path.basename(src):<25} -> {proj:<10} "
                      f"tags=[{tags_str}]")

    print(f"\n[+] Stats:")
    for k, v in omfs.stats().items():
        print(f"  {k:<18} {v}")

    print(f"\n[+] Search 'telemetry':")
    for e in omfs.search("telemetry"):
        print(f"  {os.path.basename(e.path):<25} [{e.project}]")

    print(f"\n[+] Search tag='omega':")
    for e in omfs.search(tags=["omega"]):
        print(f"  {os.path.basename(e.path):<25} [{e.project}] "
              f"tags={e.tags}")

    print(f"\n[+] Search category='code':")
    for e in omfs.search(category="code"):
        print(f"  {os.path.basename(e.path):<25} [{e.project}]")

    if omfs.graph:
        print(f"\n[+] Knowledge graph ({len(omfs.graph)} entries):")
        for path, related in list(omfs.graph.items()):
            print(f"  {os.path.basename(path)}:")
            for r in related:
                rel, other = r.split(":", 1)
                print(f"    {rel:<22} -> {os.path.basename(other)}")
    else:
        print(f"\n[+] Knowledge graph: empty (no relationships found)")

    print()
    print(f"[+] Storage root: {omfs.root}")
