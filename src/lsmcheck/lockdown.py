# SPDX-License-Identifier: 0BSD
"""Kernel lockdown mode introspection.

/sys/kernel/security/lockdown lists the modes with the active one in
brackets, for example "[none] integrity confidentiality".

Kernel reference: docs.kernel.org/admin-guide/LSM/lockdown.
"""

from __future__ import annotations

from enum import Enum

from . import _proc

__all__ = ["LockdownMode", "lockdown", "parse_lockdown"]

_LOCKDOWN_FILE = _proc.SYS_KERNEL_SECURITY / "lockdown"


class LockdownMode(str, Enum):
    """A kernel lockdown mode."""

    NONE = "none"
    INTEGRITY = "integrity"
    CONFIDENTIALITY = "confidentiality"


def parse_lockdown(text: str) -> LockdownMode | str | None:
    """Extract the bracketed mode from a lockdown file line.

    Mode names unknown to LockdownMode pass through as plain strings;
    None means no bracketed token was found.
    """
    for token in text.split():
        if token.startswith("[") and token.endswith("]"):
            name = token[1:-1]
            try:
                return LockdownMode(name)
            except ValueError:
                return name
    return None


def lockdown() -> LockdownMode | str | None:
    """Return the active lockdown mode; None when unsupported."""
    text = _proc.read_text(_LOCKDOWN_FILE)
    if text is None:
        return None
    return parse_lockdown(text)
