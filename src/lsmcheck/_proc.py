# SPDX-License-Identifier: 0BSD
"""Safe readers for procfs and sysfs.

Every read degrades to None on OSError so introspection is safe to call
on any kernel, inside containers, or without securityfs mounted. Writes
raise LsmError instead: they are explicit requests and must not fail
silently.
"""

from __future__ import annotations

from pathlib import Path

from .errors import LsmError

PROC = Path("/proc")
SYS_KERNEL_SECURITY = Path("/sys/kernel/security")
SELINUX_ROOT = Path("/sys/fs/selinux")
FILESYSTEMS_FILE = PROC / "filesystems"
MOUNTS_FILE = PROC / "self/mounts"


def read_text(path: Path) -> str | None:
    """Return the stripped contents of path, or None when unreadable.

    Unreadable covers missing files, permission errors and the EINVAL
    proc attr files return when no LSM implements their hook.
    """
    try:
        return path.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return None


def read_int(path: Path) -> int | None:
    """Return the integer contents of path, or None."""
    text = read_text(path)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def write_text(path: Path, value: str) -> None:
    """Write value to path, raising LsmError on failure."""
    try:
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise LsmError(exc.errno, exc.strerror, exc.filename) from exc


def proc_attr(pid: int | None, *parts: str) -> Path:
    """Build a path under /proc/<pid>/attr. pid None means self."""
    if pid is None:
        return PROC / "self/attr" / Path(*parts)
    if pid < 0:
        raise ValueError(f"pid must not be negative: {pid}")
    return PROC / str(pid) / "attr" / Path(*parts)


def filesystems(path: Path | None = None) -> frozenset[str]:
    """Return the set of filesystem names from /proc/filesystems."""
    text = read_text(FILESYSTEMS_FILE if path is None else path)
    if text is None:
        return frozenset()
    return frozenset(line.split()[-1] for line in text.splitlines() if line.split())


def mounted_filesystems(path: Path | None = None) -> frozenset[str]:
    """Return the set of filesystem types currently mounted."""
    text = read_text(MOUNTS_FILE if path is None else path)
    if text is None:
        return frozenset()
    result = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            result.add(fields[2])
    return frozenset(result)
