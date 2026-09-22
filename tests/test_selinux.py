# SPDX-License-Identifier: 0BSD

from pathlib import Path

import pytest

from lsmcheck import _proc, is_active, selinux
from lsmcheck.selinux import SELinuxContext, SELinuxMode


def test_parse_basic_context() -> None:
    ctx = SELinuxContext.parse("system_u:system_r:kernel_t:s0")
    assert ctx is not None
    assert ctx.user == "system_u"
    assert ctx.role == "system_r"
    assert ctx.type == "kernel_t"
    assert ctx.level == "s0"


def test_parse_no_level() -> None:
    ctx = SELinuxContext.parse("user_u:role_r:type_t")
    assert ctx is not None
    assert ctx.level is None


def test_parse_mls_range() -> None:
    ctx = SELinuxContext.parse("user_u:role_r:type_t:s0-s0:c0.c1023")
    assert ctx is not None
    assert ctx.level == "s0-s0:c0.c1023"


def test_parse_mls_single_level_categories() -> None:
    ctx = SELinuxContext.parse("user_u:role_r:type_t:s0:c0.c1023")
    assert ctx is not None
    assert ctx.level == "s0:c0.c1023"


def test_parse_trailing_colon() -> None:
    ctx = SELinuxContext.parse("user_u:role_r:type_t:")
    assert ctx is not None
    assert ctx.level is None


def test_parse_non_selinux_labels() -> None:
    assert SELinuxContext.parse("unconfined") is None
    assert SELinuxContext.parse("docker-default (enforce)") is None
    assert SELinuxContext.parse("a:b") is None
    assert SELinuxContext.parse("") is None
    assert SELinuxContext.parse("a::c:d") is None


def test_present_matches_real_system() -> None:
    has_root = Path("/sys/fs/selinux").is_dir()
    if has_root:
        assert selinux.present()
    else:
        # selinuxfs may still be listed in /proc/filesystems or the lsm
        # list. present() must agree with at least one of them.
        expected = is_active("selinux") or "selinuxfs" in _proc.filesystems()
        assert selinux.present() == expected


def test_enforcing_and_mode_absent() -> None:
    if Path("/sys/fs/selinux").is_dir() or selinux.present():
        pytest.skip("SELinux files present on this system")
    assert selinux.enforcing() is None
    assert selinux.mode() is None
    assert selinux.policyvers() is None
    assert selinux.mls() is None


def test_mode_enforcing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "selinux"
    root.mkdir()
    (root / "enforce").write_text("1\n", encoding="ascii")
    monkeypatch.setattr(selinux, "_ENFORCE_FILE", root / "enforce")
    monkeypatch.setattr(selinux, "present", lambda: True)
    assert selinux.enforcing() is True
    assert selinux.mode() is SELinuxMode.ENFORCING


def test_mode_permissive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "enforce"
    path.write_text("0\n", encoding="ascii")
    monkeypatch.setattr(selinux, "_ENFORCE_FILE", path)
    monkeypatch.setattr(selinux, "present", lambda: True)
    assert selinux.enforcing() is False
    assert selinux.mode() is SELinuxMode.PERMISSIVE


def test_mode_disabled_when_enforce_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(selinux, "_ENFORCE_FILE", tmp_path / "nope")
    monkeypatch.setattr(selinux, "present", lambda: True)
    assert selinux.mode() is SELinuxMode.DISABLED


def test_policyvers_and_mls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    vers = tmp_path / "policyvers"
    vers.write_text("33\n", encoding="ascii")
    mls = tmp_path / "mls"
    mls.write_text("1\n", encoding="ascii")
    monkeypatch.setattr(selinux, "_POLICYVERS_FILE", vers)
    monkeypatch.setattr(selinux, "_MLS_FILE", mls)
    assert selinux.policyvers() == 33
    assert selinux.mls() is True


def test_current_parses_selinux_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(selinux, "attr", lambda name, pid=None: "u:r:t:s0")
    ctx = selinux.current()
    assert ctx is not None
    assert ctx.user == "u"
    assert ctx.level == "s0"


def test_current_ignores_foreign_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(selinux, "attr", lambda name, pid=None: "unconfined")
    assert selinux.current() is None


def test_current_none_when_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(selinux, "attr", lambda name, pid=None: None)
    assert selinux.current() is None
