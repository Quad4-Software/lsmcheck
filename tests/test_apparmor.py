# SPDX-License-Identifier: 0BSD

from pathlib import Path

import pytest

import lsmcheck
from lsmcheck import apparmor
from lsmcheck.apparmor import AppArmorContext, AppArmorMode


def test_parse_unconfined() -> None:
    ctx = AppArmorContext.parse("unconfined\n")
    assert ctx.profile is None
    assert ctx.mode is AppArmorMode.UNCONFINED
    assert ctx.raw == "unconfined"


def test_parse_enforce() -> None:
    ctx = AppArmorContext.parse("docker-default (enforce)")
    assert ctx.profile == "docker-default"
    assert ctx.mode is AppArmorMode.ENFORCE


def test_parse_complain() -> None:
    ctx = AppArmorContext.parse("my profile (complain)")
    assert ctx.profile == "my profile"
    assert ctx.mode is AppArmorMode.COMPLAIN


def test_parse_hat_and_kill() -> None:
    ctx = AppArmorContext.parse("prof//hat (kill)")
    assert ctx.profile == "prof//hat"
    assert ctx.mode is AppArmorMode.KILL


def test_parse_prompt() -> None:
    ctx = AppArmorContext.parse("prof (prompt)")
    assert ctx.mode is AppArmorMode.PROMPT


def test_parse_unknown_mode() -> None:
    ctx = AppArmorContext.parse("prof (futuremode)")
    assert ctx.profile == "prof"
    assert ctx.mode is AppArmorMode.UNKNOWN


def test_parse_bare_label() -> None:
    ctx = AppArmorContext.parse("someprofile")
    assert ctx.profile == "someprofile"
    assert ctx.mode is AppArmorMode.UNKNOWN


def test_enabled_matches_module_param() -> None:
    path = Path("/sys/module/apparmor/parameters/enabled")
    if not path.is_file():
        assert apparmor.enabled() is None
        return
    raw = path.read_text(encoding="ascii").strip()
    assert apparmor.enabled() == (raw.upper() == "Y")


def test_enabled_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(apparmor, "_ENABLED_FILE", tmp_path / "nope")
    assert apparmor.enabled() is None


def test_enabled_parsing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "enabled"
    monkeypatch.setattr(apparmor, "_ENABLED_FILE", path)
    path.write_text("Y\n", encoding="ascii")
    assert apparmor.enabled() is True
    path.write_text("N\n", encoding="ascii")
    assert apparmor.enabled() is False


def test_active_matches_lsm_list() -> None:
    assert apparmor.active() == lsmcheck.is_active("apparmor")


def test_current_subdir_label(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apparmor, "attr", lambda name, pid=None: "worker (enforce)")
    ctx = apparmor.current()
    assert ctx is not None
    assert ctx.profile == "worker"
    assert ctx.mode is AppArmorMode.ENFORCE


def test_current_legacy_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_attr(name: str, pid: int | None = None) -> str | None:
        if name == "apparmor/current":
            return None
        if name == "current":
            return "docker-default (enforce)"
        return None

    monkeypatch.setattr(apparmor, "attr", fake_attr)
    monkeypatch.setattr(apparmor, "is_active", lambda n: n == "apparmor")
    ctx = apparmor.current()
    assert ctx is not None
    assert ctx.profile == "docker-default"


def test_current_no_fallback_when_selinux_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With another MAC module active the legacy attr/current belongs to
    # it, so its context must not be read as an AppArmor label.
    def fake_attr(name: str, pid: int | None = None) -> str | None:
        if name == "current":
            return "system_u:system_r:kernel_t:s0"
        return None

    monkeypatch.setattr(apparmor, "attr", fake_attr)
    monkeypatch.setattr(apparmor, "is_active", lambda n: True)
    assert apparmor.current() is None


def test_current_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apparmor, "attr", lambda name, pid=None: None)
    monkeypatch.setattr(apparmor, "is_active", lambda n: False)
    assert apparmor.current() is None


def test_current_real() -> None:
    ctx = apparmor.current()
    if ctx is None:
        assert not Path("/proc/self/attr/apparmor/current").is_file() or (
            not apparmor.active()
        )
    else:
        assert ctx.raw


def test_profiles_parsing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "profiles"
    path.write_text(
        "docker-default (enforce)\nmyprof (complain)\n",
        encoding="ascii",
    )
    monkeypatch.setattr(apparmor, "_PROFILES_FILE", path)
    assert apparmor.profiles() == {
        "docker-default": AppArmorMode.ENFORCE,
        "myprof": AppArmorMode.COMPLAIN,
    }


def test_profiles_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(apparmor, "_PROFILES_FILE", tmp_path / "nope")
    assert apparmor.profiles() == {}
