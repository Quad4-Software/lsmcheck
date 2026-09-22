# SPDX-License-Identifier: 0BSD
"""Detection of the LSMs enabled in the running kernel.

The authoritative source is /sys/kernel/security/lsm, a comma separated
list in the order the kernel runs the hooks. When securityfs is not
mounted the list is inferred from /proc/filesystems and well known
per-module files. Inference loses ordering and may miss modules that
leave no filesystem trace, such as BPF and Landlock.

Kernel references: docs.kernel.org/admin-guide/LSM, lsm= in
admin-guide/kernel-parameters.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from . import _proc
from .errors import UnsupportedError

__all__ = [
    "LSM",
    "active_lsms",
    "is_active",
    "require_active",
    "securityfs_mounted",
]

_LSM_FILE = _proc.SYS_KERNEL_SECURITY / "lsm"
_YAMA_SCOPE_FILE = Path("/proc/sys/kernel/yama/ptrace_scope")
_APPARMOR_ENABLED_FILE = Path("/sys/module/apparmor/parameters/enabled")
_APPARMOR_SECURITY_DIR = _proc.SYS_KERNEL_SECURITY / "apparmor"
_LOCKDOWN_FILE = _proc.SYS_KERNEL_SECURITY / "lockdown"
_TOMOYO_SECURITY_DIR = _proc.SYS_KERNEL_SECURITY / "tomoyo"


class LSM(str, Enum):
    """A Linux Security Module as named in /sys/kernel/security/lsm.

    The string value is the kernel's name for the module, so members
    compare equal to plain strings: LSM.YAMA == "yama".
    """

    APPARMOR = "apparmor"
    BPF = "bpf"
    CAPABILITY = "capability"
    IPE = "ipe"
    LANDLOCK = "landlock"
    LOADPIN = "loadpin"
    LOCKDOWN = "lockdown"
    SAFESETID = "safesetid"
    SELINUX = "selinux"
    SMACK = "smack"
    TOMOYO = "tomoyo"
    YAMA = "yama"


# Canonical order used for inferred results: capability first per the
# kernel docs, then minor modules, then the major MAC modules.
_CANONICAL_ORDER = (
    LSM.CAPABILITY,
    LSM.YAMA,
    LSM.LOADPIN,
    LSM.SAFESETID,
    LSM.LOCKDOWN,
    LSM.LANDLOCK,
    LSM.BPF,
    LSM.IPE,
    LSM.APPARMOR,
    LSM.SELINUX,
    LSM.SMACK,
    LSM.TOMOYO,
)


def parse_lsm_list(text: str) -> list[LSM | str]:
    """Parse a /sys/kernel/security/lsm line into LSM members.

    Names unknown to this library, such as future or out-of-tree
    modules, pass through as plain strings. Since LSM is a str enum the
    result can still be compared with names directly.
    """
    result: list[LSM | str] = []
    for name in text.split(","):
        name = name.strip()
        if not name:
            continue
        try:
            result.append(LSM(name))
        except ValueError:
            result.append(name)
    return result


def securityfs_mounted() -> bool:
    """Whether a securityfs instance is mounted anywhere."""
    return "securityfs" in _proc.mounted_filesystems()


def active_lsms() -> list[LSM | str]:
    """Return the active LSMs in kernel hook order.

    Reads /sys/kernel/security/lsm. When securityfs is unavailable the
    result is inferred from /proc/filesystems and per-module files and
    returned in canonical order. Inference may miss modules that leave
    no filesystem trace.
    """
    text = _proc.read_text(_LSM_FILE)
    if text is not None:
        return parse_lsm_list(text)
    return _infer_lsms()


def _infer_lsms() -> list[LSM | str]:
    """Best effort LSM detection without securityfs."""
    found = {LSM.CAPABILITY}
    fstypes = _proc.filesystems()

    if "selinuxfs" in fstypes or _proc.SELINUX_ROOT.is_dir():
        found.add(LSM.SELINUX)
    if "smackfs" in fstypes:
        found.add(LSM.SMACK)
    if _YAMA_SCOPE_FILE.is_file():
        found.add(LSM.YAMA)
    if (
        _proc.read_text(_APPARMOR_ENABLED_FILE) in ("Y", "y")
        or _APPARMOR_SECURITY_DIR.is_dir()
    ):
        found.add(LSM.APPARMOR)
    if _LOCKDOWN_FILE.is_file():
        found.add(LSM.LOCKDOWN)
    if _TOMOYO_SECURITY_DIR.is_dir():
        found.add(LSM.TOMOYO)

    return [m for m in _CANONICAL_ORDER if m in found]


def is_active(name: LSM | str) -> bool:
    """Whether the named module is in the active LSM list."""
    return any(m == name for m in active_lsms())


def require_active(name: LSM | str) -> None:
    """Raise UnsupportedError unless the named module is active."""
    if not is_active(name):
        raise UnsupportedError(f"LSM not active: {name}")
