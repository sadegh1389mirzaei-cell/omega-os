# ==============================================================
# OMEGA OS - File Inspector
# ==============================================================
# Content-aware file inspection:
#   - Magic bytes detection (not just extension)
#   - Partial SHA-256 hashing
#   - Duplicate detection
#   - File signature verification
# ==============================================================

import os
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple


HOME = os.path.expanduser("~")
OMEGA_DIR = os.environ.get("OMEGA_DIR") or os.path.join(HOME, "omega")


# ==============================================================
# Magic bytes signatures
# ==============================================================

MAGIC_SIGNATURES = [
    # (offset, magic_bytes, format_name, category)
    (0, b"PK\x03\x04",       "ZIP/APK/JAR",  "archive"),
    (0, b"PK\x05\x06",       "ZIP (empty)",  "archive"),
    (0, b"\x1f\x8b",         "GZIP",         "archive"),
    (0, b"BZh",              "BZIP2",        "archive"),
    (0, b"\xfd7zXZ",         "XZ",           "archive"),
    (0, b"7z\xbc\xaf\x27\x1c","7-Zip",       "archive"),
    (0, b"Rar!",             "RAR",          "archive"),

    # Executables
    (0, b"\x7fELF",          "ELF binary",   "binary"),
    (0, b"MZ",               "Windows EXE",  "binary"),
    (0, b"\xca\xfe\xba\xbe", "Mach-O fat",   "binary"),
    (0, b"dex\n",            "Android DEX",  "binary"),
    (0, b"\x89PNG\r\n\x1a\n","PNG",          "image"),
    (0, b"\xff\xd8\xff",     "JPEG",         "image"),
    (0, b"GIF87a",           "GIF87a",       "image"),
    (0, b"GIF89a",           "GIF89a",       "image"),
    (0, b"BM",               "BMP",          "image"),
    (0, b"RIFF",             "RIFF (WAV/AVI)","media"),
    (0, b"\x00\x00\x01\x00", "ICO",          "image"),
    (0, b"OggS",             "OGG",          "media"),
    (0, b"ID3",              "MP3 (ID3)",    "media"),
    (0, b"fLaC",             "FLAC",         "media"),
    (0, b"%PDF",             "PDF",          "document"),
    (0, b"SQLite format 3",  "SQLite DB",    "database"),
    (0, b"\x00asm",          "WebAssembly",  "binary"),

    # Text-ish (check after binary)
    (0, b"<?xml",            "XML",          "text"),
    (0, b"<!DOCTYPE",        "HTML",         "text"),
    (0, b"<html",            "HTML",         "text"),
    (0, b"#!",               "Script",       "text"),
    (0, b"{\n",              "JSON-ish",     "text"),
    (0, b"[\n",              "JSON-ish",     "text"),
    (0, b"[{",               "JSON-ish",     "text"),
]


def detect_by_magic(path: str, sample_size: int = 16) -> Optional[Tuple[str, str]]:
    """
    Read first bytes of file and detect format.
    Returns (format_name, category) or None.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(sample_size)
    except OSError:
        return None

    for offset, magic, fmt, cat in MAGIC_SIGNATURES:
        if header[offset:offset+len(magic)] == magic:
            return fmt, cat

    # Fallback: check if it's UTF-8 text
    try:
        header.decode("utf-8")
        return "text", "text"
    except UnicodeDecodeError:
        return "unknown", "unknown"


def detect_by_extension(name: str) -> Tuple[str, str]:
    """Fallback detection by extension."""
    ext = os.path.splitext(name)[1].lower()

    EXT_MAP = {
        ".py":    ("Python source",   "code"),
        ".json":  ("JSON",            "config"),
        ".jsonl": ("JSON Lines",      "log"),
        ".md":    ("Markdown",        "doc"),
        ".html":  ("HTML",            "text"),
        ".css":   ("CSS",             "text"),
        ".js":    ("JavaScript",      "code"),
        ".txt":   ("Text",            "text"),
        ".log":   ("Log",             "log"),
        ".sh":    ("Shell script",    "code"),
    }
    return EXT_MAP.get(ext, ("unknown", "unknown"))


# ==============================================================
# Hashing
# ==============================================================

def partial_hash(path: str, size: int = 65536) -> Optional[str]:
    """SHA-256 of first N bytes + size + last N bytes (for uniqueness)."""
    try:
        file_size = os.path.getsize(path)
        h = hashlib.sha256()

        with open(path, "rb") as f:
            # First chunk
            h.update(f.read(size))

            # If file bigger than 2*size, read last chunk too
            if file_size > 2 * size:
                f.seek(-size, os.SEEK_END)
                h.update(f.read(size))

        # Include size for uniqueness
        h.update(str(file_size).encode())
        return h.hexdigest()[:16]
    except OSError:
        return None


def full_hash(path: str) -> Optional[str]:
    """Full SHA-256 (for small files)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ==============================================================
# File record
# ==============================================================

@dataclass
class FileRecord:
    path: str
    name: str
    size: int
    detected_format: str
    detected_category: str
    hash: Optional[str] = None

    def to_dict(self):
        return {
            "path": self.path,
            "name": self.name,
            "size": self.size,
            "format": self.detected_format,
            "category": self.detected_category,
            "hash": self.hash,
        }


# ==============================================================
# Inspector
# ==============================================================

class FileInspector:

    def __init__(self, root: str = OMEGA_DIR):
        self.root = root
        self.records: List[FileRecord] = []

    def scan(self, max_depth: int = 2,
             skip_dirs: set = None) -> List[FileRecord]:
        """Scan and inspect all files."""
        skip_dirs = skip_dirs or {".git", "__pycache__", "archive"}
        self.records = []

        for dirpath, dirnames, filenames in os.walk(self.root):
            # Skip configured dirs
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]

            # Depth check
            rel = os.path.relpath(dirpath, self.root)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            if depth >= max_depth:
                dirnames[:] = []

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue

                # Detect format
                result = detect_by_magic(fpath)
                if result:
                    fmt, cat = result
                    if cat == "unknown":
                        fmt, cat = detect_by_extension(fname)
                else:
                    fmt, cat = detect_by_extension(fname)

                # Partial hash for files > 1KB
                ph = None
                if size > 1024:
                    ph = partial_hash(fpath)
                elif size > 0:
                    ph = full_hash(fpath)
                    if ph:
                        ph = ph[:16]

                self.records.append(FileRecord(
                    path=fpath,
                    name=fname,
                    size=size,
                    detected_format=fmt,
                    detected_category=cat,
                    hash=ph,
                ))

        return self.records

    def find_duplicates(self) -> Dict[str, List[FileRecord]]:
        """
        Find duplicate files by hash.
        Returns {hash: [records]} for hashes with >1 file.
        """
        by_hash = {}
        for r in self.records:
            if not r.hash:
                continue
            if r.hash not in by_hash:
                by_hash[r.hash] = []
            by_hash[r.hash].append(r)

        return {h: files for h, files in by_hash.items()
                if len(files) > 1}

    def by_format(self, fmt: str) -> List[FileRecord]:
        return [r for r in self.records
                if fmt.lower() in r.detected_format.lower()]

    def by_category(self, cat: str) -> List[FileRecord]:
        return [r for r in self.records
                if r.detected_category == cat]


