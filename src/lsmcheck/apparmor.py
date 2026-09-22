# SPDX-License-Identifier: 0BSD
"""AppArmor introspection.

Detection uses /sys/module/apparmor/parameters/enabled plus the lsm
list; the running profile and its mode come from
/proc/<pid>/attr/apparmor/current (or the legacy attr/current when
AppArmor is the only MAC module). Loaded profiles are listed by
/sys/kernel/security/apparmor/profiles when readable.

Kernel reference: docs.kernel.org/admin-guide/LSM/apparmor.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import _proc
from .attrs import attr
from .lsms import LSM, is_active

__all__ = [
    "AppArmorContext",
    "AppArmorMode",
    "active",
    "current",
    "enabled",
    "profiles",
]

_ENABLED_FILE = Path("/sys/module/apparmor/parameters/enabled")
_PROFILES_FILE = _proc.SYS_KERNEL_SECURITY / "apparmor" / "profiles"


class AppArmorMode(str, Enum):
    """The enforcement mode attached to an AppArmor label."""

    ENFORCE = "enforce"
    COMPLAIN = "complain"
    UNCONFINED = "unconfined"
    KILL = "kill"
    PROMPT = "prompt"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AppArmorContext:
    """A process AppArmor label parsed from attr/current.

    profile is None when the process is unconfined. mode is UNKNOWN
    when the kernel reports a mode token newer than this library.
    """

    profile: str | None
    mode: AppArmorMode
    raw: str

    @classmethod
    def parse(cls, text: str) -> AppArmorContext:
        """Parse an attr/current value such as "docker-default (enforce)"."""
        raw = text.strip()
        if raw.endswith(")") and " (" in raw:
            profile, _, token = raw.rpartition(" (")
            token = token[:-1]
            try:
                mode = AppArmorMode(token)
            except ValueError:
                mode = AppArmorMode.UNKNOWN
            return cls(profile or None, mode, raw)
        if raw == "unconfined":
            return cls(None, AppArmorMode.UNCONFINED, raw)
        # Bare label without a mode suffix; older or future format.
        return cls(raw or None, AppArmorMode.UNKNOWN, raw)


def enabled() -> bool | None:
    """Whether the AppArmor kernel module is enabled.

    Reads /sys/module/apparmor/parameters/enabled: True for Y, False
    for N, None when the module is not present at all.
    """
    text = _proc.read_text(_ENABLED_FILE)
    if text is None:
        return None
    return text.upper() == "Y"


def active() -> bool:
    """Whether AppArmor is in the kernel's active LSM list."""
    return is_active(LSM.APPARMOR)


def _other_mac_active() -> bool:
    return any(is_active(m) for m in (LSM.SELINUX, LSM.SMACK, LSM.TOMOYO))


def current(pid: int | None = None) -> AppArmorContext | None:
    """Return the AppArmor label and mode of a process.

    Reads attr/apparmor/current first; when absent it falls back to the
    legacy attr/current, but only if AppArmor looks like the MAC module
    that owns it. None means AppArmor is absent or the file cannot be
    read.
    """
    text = attr("apparmor/current", pid)
    if text is None and active() and not _other_mac_active():
        text = attr("current", pid)
    if text is None:
        return None
    return AppArmorContext.parse(text)


def profiles() -> dict[str, AppArmorMode]:
    """Return loaded profiles mapped to their mode.

    Reads /sys/kernel/security/apparmor/profiles, which needs
    CAP_MAC_ADMIN or an unconfined process; an empty dict means the
    file is missing or unreadable.
    """
    text = _proc.read_text(_PROFILES_FILE)
    if text is None:
        return {}
    result: dict[str, AppArmorMode] = {}
    for line in text.splitlines():
        ctx = AppArmorContext.parse(line)
        if ctx.profile is not None:
            result[ctx.profile] = ctx.mode
    return result
