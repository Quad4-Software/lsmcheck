# SPDX-License-Identifier: 0BSD
"""SELinux introspection.

Presence is detected through selinuxfs (/proc/filesystems and
/sys/fs/selinux); the enforcing flag, policy version and MLS flag come
from the selinuxfs top-level files, and process contexts come from
attr/current in user:role:type[:level] form.

Kernel reference: docs.kernel.org/admin-guide/LSM/SELinux, selinuxfs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from . import _proc
from .attrs import attr
from .lsms import LSM, is_active

__all__ = [
    "SELinuxContext",
    "SELinuxMode",
    "current",
    "enforcing",
    "mls",
    "mode",
    "policyvers",
    "present",
]

_ENFORCE_FILE = _proc.SELINUX_ROOT / "enforce"
_POLICYVERS_FILE = _proc.SELINUX_ROOT / "policyvers"
_MLS_FILE = _proc.SELINUX_ROOT / "mls"


class SELinuxMode(str, Enum):
    """The operating mode of SELinux."""

    ENFORCING = "enforcing"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"


@dataclass(frozen=True)
class SELinuxContext:
    """An SELinux context: user:role:type with an optional MLS level.

    level holds the sensitivity and category range such as "s0" or
    "s0-s0:c0.c1023" and is None for kernels or contexts without MLS.
    """

    user: str
    role: str
    type: str
    level: str | None = None

    @classmethod
    def parse(cls, text: str) -> SELinuxContext | None:
        """Parse an attr/current context; None when not SELinux shaped.

        The MLS level may itself contain a colon, as in
        "s0-s0:c0.c1023", so the first three fields are split off and
        everything after the third colon is kept as the level.
        """
        parts = text.strip().split(":", 3)
        if len(parts) not in (3, 4) or not all(parts[:3]):
            return None
        level = parts[3] if len(parts) == 4 and parts[3] else None
        return cls(parts[0], parts[1], parts[2], level)


def present() -> bool:
    """Whether SELinux is enabled on this kernel."""
    return (
        is_active(LSM.SELINUX)
        or _proc.SELINUX_ROOT.is_dir()
        or "selinuxfs" in _proc.filesystems()
    )


def enforcing() -> bool | None:
    """Whether SELinux is enforcing; None when undeterminable."""
    value = _proc.read_int(_ENFORCE_FILE)
    return None if value is None else bool(value)


def mode() -> SELinuxMode | None:
    """ENFORCING, PERMISSIVE or DISABLED; None when SELinux is absent."""
    if not present():
        return None
    enforced = enforcing()
    if enforced is None:
        return SELinuxMode.DISABLED
    return SELinuxMode.ENFORCING if enforced else SELinuxMode.PERMISSIVE


def policyvers() -> int | None:
    """The maximum policy version the kernel supports, if readable."""
    return _proc.read_int(_POLICYVERS_FILE)


def mls() -> bool | None:
    """Whether the policy uses MLS; None when undeterminable."""
    value = _proc.read_int(_MLS_FILE)
    return None if value is None else bool(value)


def current(pid: int | None = None) -> SELinuxContext | None:
    """Return the SELinux context of a process.

    Reads the legacy attr/current; labels belonging to other LSMs fail
    the context parse and come back as None.
    """
    text = attr("current", pid)
    if text is None:
        return None
    return SELinuxContext.parse(text)
