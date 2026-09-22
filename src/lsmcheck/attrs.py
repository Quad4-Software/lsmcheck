# SPDX-License-Identifier: 0BSD
"""Per-process security attributes under /proc/<pid>/attr.

The files current, exec, fscreate, keycreate, sockcreate and prev are
the legacy interface for the major LSM. Modules such as AppArmor and
Smack also provide subdirectories named after them, addressable here by
passing a name like "apparmor/current".

Reads return None when the file is missing, unreadable, or the kernel
answers EINVAL because no active LSM implements the hook. Writes go to
set_attr and raise LsmError on failure. The kernel only permits writing
the caller's own attributes, so a pid argument mainly affects reads.

Kernel reference: proc_pid_attr(5).
"""

from __future__ import annotations

from . import _proc

__all__ = [
    "ATTR_NAMES",
    "attr",
    "current",
    "exec_context",
    "prev",
    "set_attr",
    "set_exec_context",
]

#: The legacy attribute files provided under /proc/<pid>/attr.
ATTR_NAMES = ("current", "exec", "fscreate", "keycreate", "sockcreate", "prev")


def attr(name: str, pid: int | None = None) -> str | None:
    """Read /proc/<pid>/attr/<name>. None means unset or unsupported.

    name may include a module subdirectory prefix, for example
    "apparmor/current" or "smack/current". pid None means self.
    """
    return _proc.read_text(_proc.proc_attr(pid, name))


def set_attr(name: str, value: str, pid: int | None = None) -> None:
    """Write value to an attribute file, raising LsmError on failure.

    Which writes the kernel accepts depends on the active LSMs: SELinux
    takes full contexts, AppArmor takes commands such as
    "changeprofile". prev is read-only. Kernels restrict writes to the
    caller's own attribute files.
    """
    _proc.write_text(_proc.proc_attr(pid, name), value)


def current(pid: int | None = None) -> str | None:
    """The current security context of a process, as raw text.

    The format belongs to whichever major LSM is active: an SELinux
    context, an AppArmor label with mode, a Smack label, and so on.
    """
    return attr("current", pid)


def prev(pid: int | None = None) -> str | None:
    """The previous security context of a process (read-only)."""
    return attr("prev", pid)


def exec_context(pid: int | None = None) -> str | None:
    """The security context a process will take on exec, if set."""
    return attr("exec", pid)


def set_exec_context(value: str) -> None:
    """Set the security context for the next exec, raising LsmError."""
    set_attr("exec", value)
