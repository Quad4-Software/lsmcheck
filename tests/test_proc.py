# SPDX-License-Identifier: 0BSD

from pathlib import Path

import pytest

from lsmcheck import _proc
from lsmcheck.errors import LsmError


def test_read_text_missing(tmp_path: Path) -> None:
    assert _proc.read_text(tmp_path / "nope") is None


def test_read_text_strips(tmp_path: Path) -> None:
    path = tmp_path / "value"
    path.write_text("  hello\n", encoding="ascii")
    assert _proc.read_text(path) == "hello"


def test_read_text_directory_is_none(tmp_path: Path) -> None:
    assert _proc.read_text(tmp_path) is None


def test_read_int(tmp_path: Path) -> None:
    path = tmp_path / "num"
    path.write_text("42\n", encoding="ascii")
    assert _proc.read_int(path) == 42


def test_read_int_bad_value(tmp_path: Path) -> None:
    path = tmp_path / "num"
    path.write_text("not-a-number\n", encoding="ascii")
    assert _proc.read_int(path) is None


def test_read_int_missing(tmp_path: Path) -> None:
    assert _proc.read_int(tmp_path / "nope") is None


def test_write_text(tmp_path: Path) -> None:
    path = tmp_path / "out"
    _proc.write_text(path, "data")
    assert path.read_text(encoding="ascii") == "data"


def test_write_text_error_raises(tmp_path: Path) -> None:
    with pytest.raises(LsmError):
        _proc.write_text(tmp_path / "missing-dir" / "out", "data")


def test_proc_attr_self() -> None:
    assert _proc.proc_attr(None, "current") == Path("/proc/self/attr/current")


def test_proc_attr_pid() -> None:
    assert _proc.proc_attr(1234, "exec") == Path("/proc/1234/attr/exec")


def test_proc_attr_subdir() -> None:
    path = _proc.proc_attr(None, "apparmor/current")
    assert path == Path("/proc/self/attr/apparmor/current")


def test_proc_attr_negative_pid() -> None:
    with pytest.raises(ValueError, match="pid"):
        _proc.proc_attr(-1, "current")


def test_filesystems(tmp_path: Path) -> None:
    path = tmp_path / "filesystems"
    path.write_text("nodev\text4\n\text3\nnodev\tsecurityfs\n", encoding="ascii")
    assert _proc.filesystems(path) == frozenset({"ext4", "ext3", "securityfs"})


def test_filesystems_missing(tmp_path: Path) -> None:
    assert _proc.filesystems(tmp_path / "nope") == frozenset()


def test_filesystems_real() -> None:
    if not _proc.FILESYSTEMS_FILE.is_file():
        pytest.skip("/proc/filesystems not available")
    assert _proc.filesystems()


def test_mounted_filesystems(tmp_path: Path) -> None:
    path = tmp_path / "mounts"
    path.write_text(
        "proc /proc proc rw 0 0\nsecurityfs /sys/kernel/security securityfs rw 0 0\n",
        encoding="ascii",
    )
    assert _proc.mounted_filesystems(path) == frozenset({"proc", "securityfs"})


def test_mounted_filesystems_missing(tmp_path: Path) -> None:
    assert _proc.mounted_filesystems(tmp_path / "nope") == frozenset()
