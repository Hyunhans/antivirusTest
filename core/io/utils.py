"""Utility helpers for APK I/O operations."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable, Optional
from zipfile import ZipFile, ZipInfo


BUFFER_SIZE = 1024 * 1024


def compute_sha256(path: Path) -> str:
    """Compute the SHA-256 hash of a file."""

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(BUFFER_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_zip(path: Path) -> ZipFile:
    """Open an APK archive as a :class:`~zipfile.ZipFile`."""

    return ZipFile(path, "r")


def read_zip_member(zf: ZipFile, name: str) -> Optional[bytes]:
    """Safely read a member from a zip archive."""

    try:
        with zf.open(name) as member:
            return member.read()
    except KeyError:
        return None


def list_signature_files(zf: ZipFile) -> Iterable[ZipInfo]:
    """Yield entries that correspond to v1 signature files."""

    for info in zf.infolist():
        if info.filename.upper().startswith("META-INF/") and info.filename.upper().endswith(
            (".RSA", ".DSA", ".EC")
        ):
            yield info


def detect_v2_signature(path: Path) -> bool:
    """Detect the presence of an APK Signature Scheme v2 block."""

    # APK Signing Block magic: 0xAEE... as ASCII "APK Sig Block 42"
    magic = b"APK Sig Block 42"
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        file_size = fh.tell()
        if file_size < len(magic) + 8:
            return False
        search_window = min(file_size, 65536)
        fh.seek(file_size - search_window)
        tail = fh.read(search_window)
    return magic in tail


def ensure_path(path: os.PathLike | str) -> Path:
    """Coerce *path* to :class:`~pathlib.Path`."""

    if isinstance(path, Path):
        return path
    return Path(path)


def iter_apk_files(root: Path) -> Iterable[Path]:
    """Yield APK files under ``root`` recursively."""

    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.lower().endswith(".apk"):
                yield Path(dirpath) / filename


class HashCache:
    """Simple in-memory cache that keeps track of processed APK hashes."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def check_and_add(self, sha256: str) -> bool:
        """Return ``True`` if the hash was already seen; otherwise add it."""

        if sha256 in self._seen:
            return True
        self._seen.add(sha256)
        return False
