"""Reversible single-file operations restricted to private, quiescent POSIX directories."""

import os
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from selfheal.remediation.contracts import Receipt
from selfheal.safety.contracts import Snapshot
from selfheal.safety.inventory import revision
from selfheal.safety.paths import PathAccess, posix_flag


def owner_uid() -> int:
    """Read the current UID only inside POSIX-only operations."""
    function_name = "getuid"
    return int(getattr(os, function_name)())


@dataclass(frozen=True)
class ManagedFile:
    """Operator attestation for one dedicated file; never a recursive cleanup root."""

    target: str
    path: str
    kind: str
    minimum_age_seconds: int
    quiescent: bool = False
    contains_secrets: bool = True
    critical: bool = False


class FileOperations:
    """Quarantine/rotate exact regular files without deleting original contents."""

    def __init__(self, files: list[ManagedFile]) -> None:
        """Only explicit managed files gain write capability."""
        self.files = {f.target: f for f in files}
        if len(self.files) != len(files):
            raise ValueError("duplicate managed file alias")
        self.access = PathAccess([f.path for f in files])
        self.receipts: dict[str, Receipt] = {}

    def inspect(self, target: str) -> Snapshot:
        """Validate private ownership, regularity, age, links and operator attestation."""
        file = self.files[target]
        if (
            not file.quiescent
            or file.contains_secrets
            or file.minimum_age_seconds < 1
            or file.kind not in {"tmp_file", "log_file"}
        ):
            raise ValueError("file lacks safe operator attestations")
        if any(
            part.lower() in {".ssh", ".env", "secrets", "credentials"}
            for part in Path(file.path).parts
        ):
            raise ValueError("sensitive paths are forbidden")
        with self.access.parent(file.path) as (path, parent):
            directory = os.fstat(parent)
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if directory.st_uid != owner_uid() or directory.st_mode & 0o077:
                raise ValueError("managed directory must be private and agent-owned")
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != owner_uid()
                or info.st_mode & 0o077
            ):
                raise ValueError("managed file must be private, regular, singly linked and owned")
            if time.time() - info.st_mtime < file.minimum_age_seconds:
                raise ValueError("file is not old enough")
            values = {
                "device": info.st_dev,
                "inode": info.st_ino,
                "size": info.st_size,
                "mtime": info.st_mtime_ns,
                "parent_device": directory.st_dev,
                "parent_inode": directory.st_ino,
            }
            return Snapshot(
                target,
                file.kind,
                f"{info.st_dev}:{info.st_ino}",
                revision(values),
                "quiescent",
                False,
                file.critical,
            )

    def execute(
        self, name: str, snapshot: Snapshot, stopped: Callable[[], bool] | None = None
    ) -> Receipt:
        """Recheck before renaming into same-directory quarantine; never recurse."""
        file = self.files[snapshot.target]
        if (name, file.kind) not in {("clear_tmp_files", "tmp_file"), ("rotate_logs", "log_file")}:
            raise ValueError("file operation does not match typed file kind")
        if self.inspect(snapshot.target) != snapshot:
            raise RuntimeError("file changed before operation")
        with self.access.parent(file.path) as (path, parent):
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if f"{info.st_dev}:{info.st_ino}" != snapshot.identity:
                raise RuntimeError("file identity changed")
            backup = ".slime-quarantine-" + uuid4().hex
            self._guard(stopped)
            os.rename(path.name, backup, src_dir_fd=parent, dst_dir_fd=parent)
            new_identity = ""
            try:
                if name == "rotate_logs":
                    self._guard(stopped)
                    descriptor = os.open(
                        path.name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | posix_flag("O_NOFOLLOW"),
                        0o600,
                        dir_fd=parent,
                    )
                    try:
                        new = os.fstat(descriptor)
                        new_identity = f"{new.st_dev}:{new.st_ino}"
                    finally:
                        os.close(descriptor)
            except Exception:
                # link() is no-clobber: never overwrite a new competing file.
                try:
                    self._guard(stopped)
                    os.link(
                        backup,
                        path.name,
                        src_dir_fd=parent,
                        dst_dir_fd=parent,
                        follow_symlinks=False,
                    )
                    self._guard(stopped)
                    os.unlink(backup, dir_fd=parent)
                except OSError:
                    pass
                raise
            receipt = Receipt(
                "original contents retained in private quarantine",
                rollback_data={
                    "backup": backup,
                    "original_identity": snapshot.identity,
                    "new_identity": new_identity,
                    "original_size": str(info.st_size),
                    "original_mtime": str(info.st_mtime_ns),
                    "parent_identity": f"{os.fstat(parent).st_dev}:{os.fstat(parent).st_ino}",
                },
            )
            self.receipts[snapshot.target] = receipt
            return receipt

    def verify(self, target: str) -> bool:
        """Ensure quarantine retains original inode and source has expected post-state."""
        receipt = self.receipts[target]
        file = self.files[target]
        # Original may legitimately be absent after quarantine: authorize its parent
        # by the configured file spelling, then validate the retained parent fd.
        with self._parent_after(file.path) as (path, parent):
            if (
                f"{os.fstat(parent).st_dev}:{os.fstat(parent).st_ino}"
                != receipt.rollback_data["parent_identity"]
            ):
                return False
            backup = os.stat(receipt.rollback_data["backup"], dir_fd=parent, follow_symlinks=False)
            if (
                f"{backup.st_dev}:{backup.st_ino}" != receipt.rollback_data["original_identity"]
                or str(backup.st_size) != receipt.rollback_data["original_size"]
                or str(backup.st_mtime_ns) != receipt.rollback_data["original_mtime"]
            ):
                return False
            try:
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return not receipt.rollback_data["new_identity"]
            return f"{current.st_dev}:{current.st_ino}" == receipt.rollback_data[
                "new_identity"
            ] and stat.S_ISREG(current.st_mode)

    def rollback(
        self, snapshot: Snapshot, receipt: Receipt, stopped: Callable[[], bool] | None = None
    ) -> bool:
        """Restore without clobbering another file; a changed rotated file blocks rollback."""
        file = self.files[snapshot.target]
        with self._parent_after(file.path) as (path, parent):
            if (
                f"{os.fstat(parent).st_dev}:{os.fstat(parent).st_ino}"
                != receipt.rollback_data["parent_identity"]
            ):
                return False
            backup = os.stat(receipt.rollback_data["backup"], dir_fd=parent, follow_symlinks=False)
            if f"{backup.st_dev}:{backup.st_ino}" != snapshot.identity:
                return False
            try:
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if current is not None:
                if (
                    not receipt.rollback_data["new_identity"]
                    or current.st_size != 0
                    or f"{current.st_dev}:{current.st_ino}" != receipt.rollback_data["new_identity"]
                ):
                    return False
                self._guard(stopped)
                os.unlink(path.name, dir_fd=parent)
            self._guard(stopped)
            os.link(
                receipt.rollback_data["backup"],
                path.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
            self._guard(stopped)
            os.unlink(receipt.rollback_data["backup"], dir_fd=parent)
            return True

    @staticmethod
    def _guard(stopped: Callable[[], bool] | None) -> None:
        """Stop even if an earlier metadata read completed after a kill request."""
        if stopped is not None and stopped():
            raise InterruptedError("operator stopped file mutation")

    @contextmanager
    def _parent_after(self, raw: str) -> Iterator[tuple[Path, int]]:
        """Open an authorized parent even when the configured source is quarantined."""
        with self.access.parent(raw) as opened:
            _, descriptor = opened
            info = os.fstat(descriptor)
            if info.st_uid != owner_uid() or info.st_mode & 0o077:
                raise ValueError("managed parent is no longer private and owned")
            yield opened
