# SPDX-License-Identifier: 0BSD
"""Linux Security Module introspection.

Answers which LSMs are active on the running kernel and what they say
about a process, using only procfs and sysfs reads: no shell-outs, no C
libraries, no runtime dependencies. Every reader degrades gracefully
to None or an empty result when the kernel lacks the feature, so the
library is safe to call anywhere.

Kernel references: docs.kernel.org/admin-guide/LSM, proc_pid_attr(5).
"""

from . import apparmor, lockdown, selinux, yama
from .attrs import (
    ATTR_NAMES,
    attr,
    current,
    exec_context,
    prev,
    set_attr,
    set_exec_context,
)
from .errors import LsmError, UnsupportedError
from .lsms import (
    LSM,
    active_lsms,
    is_active,
    require_active,
    securityfs_mounted,
)

__version__ = "0.1.0"

__all__ = [
    "ATTR_NAMES",
    "LSM",
    "LsmError",
    "UnsupportedError",
    "__version__",
    "active_lsms",
    "apparmor",
    "attr",
    "current",
    "exec_context",
    "is_active",
    "lockdown",
    "prev",
    "require_active",
    "securityfs_mounted",
    "selinux",
    "set_attr",
    "set_exec_context",
    "yama",
]
