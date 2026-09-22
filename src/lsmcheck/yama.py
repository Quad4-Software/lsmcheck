# SPDX-License-Identifier: 0BSD
"""Yama introspection: the ptrace_scope sysctl.

Kernel reference: docs.kernel.org/admin-guide/LSM/Yama.
"""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

from . import _proc
from .lsms import LSM, is_active

__all__ = ["PtraceScope", "active", "ptrace_scope"]

_SCOPE_FILE = Path("/proc/sys/kernel/yama/ptrace_scope")


class PtraceScope(IntEnum):
    """Values of /proc/sys/kernel/yama/ptrace_scope."""

    CLASSIC = 0
    RESTRICTED = 1
    ADMIN = 2
    NO_ATTACH = 3


def active() -> bool:
    """Whether Yama is in the kernel's active LSM list."""
    return is_active(LSM.YAMA)


def ptrace_scope() -> PtraceScope | int | None:
    """Return the current ptrace_scope value.

    None means Yama is absent. Values unknown to PtraceScope pass
    through as plain ints so future scopes are still usable.
    """
    value = _proc.read_int(_SCOPE_FILE)
    if value is None:
        return None
    try:
        return PtraceScope(value)
    except ValueError:
        return value
