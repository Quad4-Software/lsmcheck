# SPDX-License-Identifier: 0BSD
"""Exception types raised by lsmcheck."""


class LsmError(OSError):
    """An LSM-related filesystem operation failed."""


class UnsupportedError(LsmError):
    """The running kernel does not provide the requested LSM feature."""
