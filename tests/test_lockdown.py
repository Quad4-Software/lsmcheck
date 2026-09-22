# SPDX-License-Identifier: 0BSD

from pathlib import Path

import pytest

from lsmcheck import lockdown as lockdown_mod
from lsmcheck.lockdown import LockdownMode


def test_parse_none() -> None:
    assert (
        lockdown_mod.parse_lockdown("[none] integrity confidentiality")
        is LockdownMode.NONE
    )


def test_parse_integrity() -> None:
    assert (
        lockdown_mod.parse_lockdown("none [integrity] confidentiality")
        is LockdownMode.INTEGRITY
    )


def test_parse_confidentiality() -> None:
    assert (
        lockdown_mod.parse_lockdown("none integrity [confidentiality]")
        is LockdownMode.CONFIDENTIALITY
    )


def test_parse_no_brackets() -> None:
    assert lockdown_mod.parse_lockdown("none integrity confidentiality") is None


def test_parse_unknown_mode_passes_through() -> None:
    assert (
        lockdown_mod.parse_lockdown("none [futuremode] confidentiality") == "futuremode"
    )


def test_lockdown_matches_real_file() -> None:
    path = Path("/sys/kernel/security/lockdown")
    if not path.is_file():
        pytest.skip("lockdown file not available")
    raw = path.read_text(encoding="ascii").strip()
    assert lockdown_mod.lockdown() == lockdown_mod.parse_lockdown(raw)


def test_lockdown_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(lockdown_mod, "_LOCKDOWN_FILE", tmp_path / "nope")
    assert lockdown_mod.lockdown() is None
