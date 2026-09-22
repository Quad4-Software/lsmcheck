# SPDX-License-Identifier: 0BSD

from pathlib import Path

import pytest

import lsmcheck
import lsmcheck.yama
from lsmcheck.yama import PtraceScope


def test_scope_members() -> None:
    assert PtraceScope.CLASSIC.value == 0
    assert PtraceScope.RESTRICTED.value == 1
    assert PtraceScope.ADMIN.value == 2
    assert PtraceScope.NO_ATTACH.value == 3


def test_ptrace_scope_matches_sysctl() -> None:
    path = Path("/proc/sys/kernel/yama/ptrace_scope")
    if not path.is_file():
        pytest.skip("yama ptrace_scope not available")
    raw = int(path.read_text(encoding="ascii").strip())
    assert lsmcheck.yama.ptrace_scope() == raw


def test_active_matches_lsm_list() -> None:
    assert lsmcheck.yama.active() == lsmcheck.is_active("yama")


def test_scope_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(lsmcheck.yama, "_SCOPE_FILE", tmp_path / "nope")
    assert lsmcheck.yama.ptrace_scope() is None


def test_scope_future_value_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "ptrace_scope"
    path.write_text("7\n", encoding="ascii")
    monkeypatch.setattr(lsmcheck.yama, "_SCOPE_FILE", path)
    value = lsmcheck.yama.ptrace_scope()
    assert value == 7
    assert not isinstance(value, PtraceScope)
