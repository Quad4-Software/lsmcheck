# SPDX-License-Identifier: 0BSD

import os
from pathlib import Path

import pytest

import lsmcheck
from lsmcheck.errors import LsmError


def _raw_attr(name: str) -> str | None:
    try:
        return Path(f"/proc/self/attr/{name}").read_text(encoding="ascii").strip()
    except OSError:
        return None


def test_attr_names() -> None:
    assert lsmcheck.ATTR_NAMES == (
        "current",
        "exec",
        "fscreate",
        "keycreate",
        "sockcreate",
        "prev",
    )


def test_attr_missing_name() -> None:
    assert lsmcheck.attr("definitely-not-an-attr") is None


def test_current_matches_raw_file() -> None:
    assert lsmcheck.current() == _raw_attr("current")


def test_prev_matches_raw_file() -> None:
    assert lsmcheck.prev() == _raw_attr("prev")


def test_exec_context_matches_raw_file() -> None:
    assert lsmcheck.exec_context() == _raw_attr("exec")


def test_attr_for_pid_matches_self() -> None:
    assert lsmcheck.attr("current", os.getpid()) == _raw_attr("current")


def test_attr_negative_pid() -> None:
    with pytest.raises(ValueError, match="pid"):
        lsmcheck.attr("current", -1)


def test_attr_module_subdir() -> None:
    assert lsmcheck.attr("apparmor/current") == _raw_attr("apparmor/current")


def test_set_attr_missing_name_raises() -> None:
    with pytest.raises(LsmError):
        lsmcheck.set_attr("definitely-not-an-attr", "x")


def test_set_exec_context_error_propagates() -> None:
    if lsmcheck.apparmor.active() or lsmcheck.selinux.present():
        pytest.skip("an LSM may accept exec context writes here")
    with pytest.raises(LsmError):
        lsmcheck.set_exec_context("definitely-invalid-context")
