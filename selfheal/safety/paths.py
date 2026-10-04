"""Exact allowlisted file access, with no-follow directory traversal on POSIX."""

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def posix_flag(name: str) -> int:
    """Read a POSIX flag only after platform capability checks."""
    return int(getattr(os, name))


def _not_link(path: Path) -> None:
    """Reject symlinks and Windows reparse points, including junctions."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("symlink or reparse point is not authorized")


class PathAccess:
    """Authorize exact files, not prefixes or arbitrary descendants."""

    def __init__(self, paths: list[str]) -> None:
        """Pin lexical absolute inventory paths; reject traversal in configuration."""
        self.allowed: set[Path] = set()
        for raw in paths:
            if ".." in Path(raw).parts:
                raise ValueError("path traversal is not authorized")
            self.allowed.add(Path(raw).absolute())

    def authorize(self, raw: str, allow_missing: bool = False) -> Path:
        """Reject control characters, traversal, unknown paths and link components."""
        if any(ord(c) < 32 for c in raw) or ".." in Path(raw).parts:
            raise ValueError("invalid path")
        path = Path(raw).absolute()
        if path not in self.allowed:
            raise LookupError("file is outside inventory")
        for component in list(reversed(path.parents)) + [path]:
            try:
                _not_link(component)
            except FileNotFoundError:
                if component != path or not allow_missing:
                    raise
        return path

    @contextmanager
    def parent(self, raw: str) -> Iterator[tuple[Path, int]]:
        """Open each POSIX directory without following a symlink, retaining final fd."""
        path = self.authorize(raw, allow_missing=True)
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise RuntimeError("race-resistant directory operations require POSIX")
        descriptor = os.open(
            path.anchor, os.O_RDONLY | posix_flag("O_DIRECTORY") | posix_flag("O_NOFOLLOW")
        )
        try:
            for part in path.parent.parts[1:]:
                child = os.open(
                    part,
                    os.O_RDONLY | posix_flag("O_DIRECTORY") | posix_flag("O_NOFOLLOW"),
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            yield path, descriptor
        finally:
            os.close(descriptor)

    def read(self, raw: str, limit: int = 4096, tail: bool = False) -> bytes:
        """Read only an opened authorized regular file, with a strict byte limit."""
        path = self.authorize(raw)
        if os.name == "posix":
            with self.parent(raw) as (_, parent):
                descriptor = os.open(
                    path.name,
                    os.O_RDONLY | posix_flag("O_NOFOLLOW") | posix_flag("O_NONBLOCK"),
                    dir_fd=parent,
                )
        else:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("diagnostics read regular files only")
            if os.name == "nt":
                self._check_windows_handle(descriptor, path)
            if tail:
                os.lseek(descriptor, max(0, info.st_size - limit), os.SEEK_SET)
            return os.read(descriptor, limit)
        finally:
            os.close(descriptor)

    @staticmethod
    def _check_windows_handle(descriptor: int, expected: Path) -> None:
        """Check the resolved opened handle, closing the Windows path-open race."""
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        function = kernel.GetFinalPathNameByHandleW
        function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        function.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = function(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise OSError("cannot verify opened file path")
        resolved = buffer.value
        if resolved.startswith("\\\\?\\UNC\\"):
            resolved = "\\\\" + resolved[8:]
        elif resolved.startswith("\\\\?\\"):
            resolved = resolved[4:]
        if os.path.normcase(resolved) != os.path.normcase(str(expected)):
            raise ValueError("opened handle escaped inventory")
