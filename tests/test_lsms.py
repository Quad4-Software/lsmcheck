# SPDX-License-Identifier: 0BSD

from pathlib import Path

import pytest

import lsmcheck
import lsmcheck._proc
import lsmcheck.lsms
from lsmcheck.errors import UnsupportedError
from lsmcheck.lsms import LSM


def test_parse_lsm_list() -> None:
    text = "lockdown,capability,landlock,yama,apparmor,bpf"
    assert lsmcheck.lsms.parse_lsm_list(text) == [
        LSM.LOCKDOWN,
        LSM.CAPABILITY,
        LSM.LANDLOCK,
        LSM.YAMA,
        LSM.APPARMOR,
        LSM.BPF,
    ]


def test_parse_lsm_list_unknown_passes_through() -> None:
    result = lsmcheck.lsms.parse_lsm_list("capability,futuremod")
    assert result == [LSM.CAPABILITY, "futuremod"]
    assert result[1] == "futuremod"


def test_parse_lsm_list_empty_and_whitespace() -> None:
    assert lsmcheck.lsms.parse_lsm_list("") == []
    assert lsmcheck.lsms.parse_lsm_list(" capability , yama \n") == [
        LSM.CAPABILITY,
        LSM.YAMA,
    ]


def test_lsm_members_match_kernel_names() -> None:
    assert LSM.APPARMOR.value == "apparmor"
    assert LSM.SAFESETID.value == "safesetid"
    assert LSM.CAPABILITY.value == "capability"


def test_active_lsms_matches_real_file() -> None:
    lsm_file = Path("/sys/kernel/security/lsm")
    if not lsm_file.is_file():
        pytest.skip("securityfs lsm file not available")
    raw = lsm_file.read_text(encoding="ascii").strip()
    assert lsmcheck.active_lsms() == lsmcheck.lsms.parse_lsm_list(raw)


def test_is_active_consistent() -> None:
    active = lsmcheck.active_lsms()
    for name in active:
        assert lsmcheck.is_active(name)
    assert not lsmcheck.is_active("definitely-not-an-lsm")


def test_require_active() -> None:
    with pytest.raises(UnsupportedError):
        lsmcheck.require_active("definitely-not-an-lsm")
    for name in lsmcheck.active_lsms():
        lsmcheck.require_active(name)


def test_securityfs_mounted_matches_mounts() -> None:
    expected = "securityfs" in lsmcheck._proc.mounted_filesystems()
    assert lsmcheck.securityfs_mounted() == expected


def test_securityfs_mounted_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "securityfs /sys/kernel/security securityfs rw 0 0\n", encoding="ascii"
    )
    monkeypatch.setattr(lsmcheck._proc, "MOUNTS_FILE", mounts)
    assert lsmcheck.securityfs_mounted()
    mounts.write_text("proc /proc proc rw 0 0\n", encoding="ascii")
    assert not lsmcheck.securityfs_mounted()


def _gate_lsm_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(lsmcheck.lsms, "_LSM_FILE", tmp_path / "no-lsm-file")


def test_infer_selinux_from_filesystems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _gate_lsm_file(monkeypatch, tmp_path)
    filesystems = tmp_path / "filesystems"
    filesystems.write_text("nodev\tselinuxfs\n", encoding="ascii")
    monkeypatch.setattr(lsmcheck._proc, "FILESYSTEMS_FILE", filesystems)
    monkeypatch.setattr(lsmcheck._proc, "SELINUX_ROOT", tmp_path / "no-selinux")
    monkeypatch.setattr(lsmcheck.lsms, "_YAMA_SCOPE_FILE", tmp_path / "no-yama")
    monkeypatch.setattr(lsmcheck.lsms, "_APPARMOR_ENABLED_FILE", tmp_path / "no-aa")
    monkeypatch.setattr(lsmcheck.lsms, "_APPARMOR_SECURITY_DIR", tmp_path / "no-aa-dir")
    monkeypatch.setattr(lsmcheck.lsms, "_LOCKDOWN_FILE", tmp_path / "no-lockdown")
    monkeypatch.setattr(lsmcheck.lsms, "_TOMOYO_SECURITY_DIR", tmp_path / "no-tomoyo")
    assert lsmcheck.active_lsms() == [LSM.CAPABILITY, LSM.SELINUX]


def test_infer_per_module_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _gate_lsm_file(monkeypatch, tmp_path)
    monkeypatch.setattr(lsmcheck._proc, "FILESYSTEMS_FILE", tmp_path / "no-fs")
    monkeypatch.setattr(lsmcheck._proc, "SELINUX_ROOT", tmp_path / "no-selinux")

    yama_file = tmp_path / "ptrace_scope"
    yama_file.write_text("1\n", encoding="ascii")
    monkeypatch.setattr(lsmcheck.lsms, "_YAMA_SCOPE_FILE", yama_file)

    enabled = tmp_path / "enabled"
    enabled.write_text("Y\n", encoding="ascii")
    monkeypatch.setattr(lsmcheck.lsms, "_APPARMOR_ENABLED_FILE", enabled)
    monkeypatch.setattr(lsmcheck.lsms, "_APPARMOR_SECURITY_DIR", tmp_path / "no-aa-dir")

    lockdown_file = tmp_path / "lockdown"
    lockdown_file.write_text("[none] integrity confidentiality\n")
    monkeypatch.setattr(lsmcheck.lsms, "_LOCKDOWN_FILE", lockdown_file)

    tomoyo_dir = tmp_path / "tomoyo"
    tomoyo_dir.mkdir()
    monkeypatch.setattr(lsmcheck.lsms, "_TOMOYO_SECURITY_DIR", tomoyo_dir)

    result = lsmcheck.active_lsms()
    assert result == [
        LSM.CAPABILITY,
        LSM.YAMA,
        LSM.LOCKDOWN,
        LSM.APPARMOR,
        LSM.TOMOYO,
    ]


def test_infer_smack_and_selinux_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _gate_lsm_file(monkeypatch, tmp_path)
    filesystems = tmp_path / "filesystems"
    filesystems.write_text("nodev\tsmackfs\n", encoding="ascii")
    monkeypatch.setattr(lsmcheck._proc, "FILESYSTEMS_FILE", filesystems)
    selinux_root = tmp_path / "selinux"
    selinux_root.mkdir()
    monkeypatch.setattr(lsmcheck._proc, "SELINUX_ROOT", selinux_root)
    monkeypatch.setattr(lsmcheck.lsms, "_YAMA_SCOPE_FILE", tmp_path / "no-yama")
    monkeypatch.setattr(lsmcheck.lsms, "_APPARMOR_ENABLED_FILE", tmp_path / "no-aa")
    monkeypatch.setattr(lsmcheck.lsms, "_APPARMOR_SECURITY_DIR", tmp_path / "no-aa-dir")
    monkeypatch.setattr(lsmcheck.lsms, "_LOCKDOWN_FILE", tmp_path / "no-lockdown")
    monkeypatch.setattr(lsmcheck.lsms, "_TOMOYO_SECURITY_DIR", tmp_path / "no-tomoyo")
    assert lsmcheck.active_lsms() == [
        LSM.CAPABILITY,
        LSM.SELINUX,
        LSM.SMACK,
    ]
