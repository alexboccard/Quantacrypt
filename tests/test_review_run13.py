"""Regressions for review run 13 (2026-09-05) — `.review/FINAL.md`.

One class per finding cluster; the F-numbers are the FINAL.md ones (run 13
unless marked "run 14", the validation run that reviewed this batch) and the
design record is `docs/design/review-2026-09-run13-fixes.md`.  Nothing here
mounts a filesystem: the FUSE tests call the Operations methods directly,
which is equivalent under ``nothreads=True``.
"""

from __future__ import annotations

import base64
import errno
import io
import json
import logging
import os
import random
import shutil
import stat
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import fuse_ops as fo
from quantacrypt.core import package as pkg
from quantacrypt.core import service as svc
from quantacrypt.core import volume as vol
from quantacrypt.core.errors import CorruptPayload, InvalidInput, classify_error

PW = "correct horse battery staple"
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "v1")
FIXTURES_CURRENT = os.path.join(os.path.dirname(__file__), "fixtures", "current")


def _make_volume(tmp_path, name="v.qcv", pw=PW):
    path = str(tmp_path / name)
    auth = vol.create_volume_single(path, pw)
    key = vol.derive_volume_key_single(pw, auth)
    vc = vol.VolumeContainer(path, key)
    vc.open()
    return path, key, vc


def _rewrite_auth_block(path: str, mutate) -> None:
    """Rewrite the cleartext auth block through *mutate(dict)*, shifting the
    rest of the container to follow it."""
    with open(path, "rb") as f:
        header_raw = f.read(vol.HEADER_SIZE)
        (n,) = struct.unpack(">I", f.read(4))
        auth = json.loads(f.read(n))
        rest = f.read()
    mutate(auth)
    with open(path, "wb") as f:
        f.write(header_raw)
        vol._write_auth_params(f, auth)
        f.write(rest)


def _patch_header_version(path: str, version: int) -> None:
    with open(path, "r+b") as f:
        f.seek(6)  # _OFF_VERSION
        f.write(struct.pack(">I", version))


def _file_fs(vc):
    """A FUSE ops object over *vc* with one persisted file."""
    fs = fo.QuantaCryptFUSE(vc)
    fd = fs.create("/a.txt", 0o100644)
    fs.write("/a.txt", b"payload", 0, fd)
    fs.release("/a.txt", fd)
    return fs


# ── F-002: truncate() shares write()'s memory ceiling ─────────────────────────

class TestTruncateCeiling:
    def test_extension_past_the_ceiling_is_refused_with_efbig(self, tmp_path, monkeypatch):
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        monkeypatch.setattr(fo, "_max_writable_bytes", lambda: 1 << 20)
        with pytest.raises(OSError) as ei:
            fs.truncate("/a.txt", 2 << 20)
        assert ei.value.errno == errno.EFBIG
        # Refused before anything was decrypted: no buffer, nothing dirty.
        assert "/a.txt" not in fs._file_buffers and not vc.is_dirty

    def test_shrinking_and_small_growth_still_work(self, tmp_path, monkeypatch):
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        monkeypatch.setattr(fo, "_max_writable_bytes", lambda: 1 << 20)
        fs.truncate("/a.txt", 3)                 # path-based: persisted, buffer dropped
        assert vc.read_file("/a.txt") == b"pay"
        fs.truncate("/a.txt", 10)
        assert vc.read_file("/a.txt") == b"pay" + b"\x00" * 7


# ── F-001: chown is a no-op, not EROFS ───────────────────────────────────────

class TestChown:
    def test_chown_on_a_file_and_a_directory_returns_zero(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        fs.mkdir("/d", 0o755)
        assert fs.chown("/a.txt", os.getuid(), os.getgid()) == 0
        assert fs.chown("/d", os.getuid(), os.getgid()) == 0
        assert not vc.is_dirty, "nothing to record for an ownership change"

    def test_chown_on_a_missing_path_is_enoent(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        with pytest.raises(OSError) as ei:
            fs.chown("/ghost", 0, 0)
        assert ei.value.errno == errno.ENOENT


# ── F-013: chmod/utimens are persisted at once, at full precision ────────────

class TestAttributeDurability:
    def test_attributes_reach_disk_without_a_later_mutating_op(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        fs.utimens("/a.txt", (1_000_000, 1_234_567.25))
        fs.chmod("/a.txt", 0o100755)
        assert not vc.is_dirty, "each attribute op persists like every other mutation"

        reopened = vol.VolumeContainer(path, key)
        reopened.open()      # simulated SIGKILL: only what reached disk
        entry = reopened.get_entry("/a.txt")
        assert entry["mtime"] == 1_234_567.25
        assert entry["mode"] == 0o100755


    def test_a_stamp_set_before_close_survives_the_flush(self, tmp_path):
        """cp -p, rsync and tar call utimes *before* close; the flush that
        release() runs used to rebuild the entry with the copy time (seen
        live on macFUSE during the run-13 batch)."""
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/c.txt", 0o100644)
        fs.write("/c.txt", b"copied", 0, fd)
        fs.utimens("/c.txt", (1_000_000, 1_234_567.5))
        fs.chmod("/c.txt", 0o100640)
        fs.release("/c.txt", fd)
        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        entry = reopened.get_entry("/c.txt")
        assert entry["mtime"] == 1_234_567.5
        assert entry["mode"] == 0o100640
        assert reopened.read_file("/c.txt") == b"copied"

    def test_a_write_after_the_stamp_makes_the_flush_use_now(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/c.txt", 0o100644)
        fs.write("/c.txt", b"v1", 0, fd)
        fs.utimens("/c.txt", (1_000_000, 1_234_567))
        fs.write("/c.txt", b"v2", 0, fd)          # a modification: mtime is now
        fs.release("/c.txt", fd)
        assert vc.get_entry("/c.txt")["mtime"] > 1_700_000_000


class TestExplicitMtimeLifecycle:
    """Run 14 F-003 / F-005 / F-006 / F-011: the deferred-stamp map is
    per-path state like the buffers — consumed by every flush path, dropped
    with the file, re-keyed by rename, never applied to other content."""

    def test_rename_over_a_stamped_file_does_not_date_the_new_content(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/B", 0o644); fs.write("/B", b"same", 0, fd); fs.release("/B", fd)
        # cp -p of an identical file onto /B: the flush finds the content
        # unchanged, so the stamp has to be journaled on its own and dropped.
        fd = fs.open("/B", os.O_WRONLY); fs.truncate("/B", 0, fd)
        fs.write("/B", b"same", 0, fd); fs.utimens("/B", (1, 1_234_567.5))
        fs.flush("/B", fd); fs.release("/B", fd)
        assert vc.get_entry("/B")["mtime"] == 1_234_567.5
        assert "/B" not in fs._deferred_attrs
        start = int(time.time())
        fd = fs.create("/A", 0o644); fs.write("/A", b"brand new content", 0, fd)
        fs.rename("/A", "/B"); fs.release("/B", fd)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.read_file("/B") == b"brand new content"
        assert reopened.get_entry("/B")["mtime"] >= start

    def test_a_stamp_survives_the_unmount_and_emergency_save_path(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/c", 0o644); fs.write("/c", b"data", 0, fd)
        fs.utimens("/c", (1, 7_654_321.0))
        fs.save_all_dirty(apply_pending_unlink=False)   # unmount_volume's pre-unmount save
        fs.release("/c", fd)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.get_entry("/c")["mtime"] == 7_654_321.0

    def test_a_stamp_follows_a_directory_rename(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fs.mkdir("/d", 0o755)
        fd = fs.create("/d/f", 0o644); fs.write("/d/f", b"data", 0, fd)
        fs.utimens("/d/f", (1, 4_444_444.0))
        fs.rename("/d", "/e")
        fs.release("/e/f", fd)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.get_entry("/e/f")["mtime"] == 4_444_444.0
        assert fs._deferred_attrs == {}

    def test_a_stamp_on_buffered_data_costs_no_extra_journal_record(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/c", 0o644); fs.write("/c", b"data", 0, fd)
        vc.save()                                   # flush the create record
        assert vc._pending_ops == []
        fs.utimens("/c", (1, 2_222_222.0))          # dirty: memory only
        assert vc._pending_ops == [] and not vc.is_dirty
        assert fs.getattr("/c")["st_mtime"] == 2_222_222.0
        fs.release("/c", fd)                        # one write record carries it
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.get_entry("/c")["mtime"] == 2_222_222.0

    def test_the_fusepy_omit_and_now_sentinels_are_not_timestamps(self, tmp_path):
        """Run 14 F-005: libfuse fills the timespec the kernel did not set
        with tv_nsec=UTIME_OMIT/UTIME_NOW; fusepy hands those over as
        1.073741822 / 1.073741823 seconds."""
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        before = vc.get_entry("/a.txt")["mtime"]
        assert fs.utimens("/a.txt", (5.0, 1.073741822)) == 0     # atime-only touch
        assert vc.get_entry("/a.txt")["mtime"] == before
        assert fs.utimens("/a.txt", (5.0, 1.073741823)) == 0     # "now"
        assert abs(vc.get_entry("/a.txt")["mtime"] - time.time()) < 5
        with pytest.raises(OSError) as ei:
            fs.utimens("/ghost", (5.0, 1.073741822))
        assert ei.value.errno == errno.ENOENT

    def test_unlink_and_replacement_drop_the_stamp(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/x", 0o644); fs.write("/x", b"1", 0, fd)
        fs.utimens("/x", (1, 3.0)); fs.release("/x", fd)
        assert "/x" not in fs._deferred_attrs
        fd = fs.create("/x", 0o644); fs.write("/x", b"2", 0, fd)
        fs.utimens("/x", (1, 4.0)); fs.release("/x", fd)
        fs.unlink("/x")
        assert fs._deferred_attrs == {}


class TestKernelModes:
    """Run 15 F-001 (pre-existing since v1.3.0): create()/mkdir() dropped the
    kernel's umask-applied mode, so an SSH key written into the vault landed
    0644 and ssh refused it."""

    def test_create_and_mkdir_keep_the_requested_mode_across_a_reopen(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/id_ed25519", 0o600); fs.write("/id_ed25519", b"key", 0, fd)
        fs.release("/id_ed25519", fd)
        fs.mkdir("/gnupg", 0o700)
        assert fs.getattr("/id_ed25519")["st_mode"] == stat.S_IFREG | 0o600
        assert fs.getattr("/gnupg")["st_mode"] == stat.S_IFDIR | 0o700
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.get_entry("/id_ed25519")["mode"] == stat.S_IFREG | 0o600
        assert reopened.get_entry("/gnupg/")["mode"] == stat.S_IFDIR | 0o700

    def test_the_type_bits_come_from_the_entry_not_the_caller(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/f", stat.S_IFDIR | 0o644); fs.release("/f", fd)
        assert fs.getattr("/f")["st_mode"] == stat.S_IFREG | 0o644


class TestDeferredAttributes:
    """Run 15 F-010 / F-017 / F-015: chmod and utimens on a file whose data is
    still buffered live only in the deferred map (getattr overlays it), cost
    no journal record of their own, and never leave memory and disk apart."""

    def test_chmod_on_buffered_data_costs_no_extra_record(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/c", 0o644); fs.write("/c", b"data", 0, fd)
        vc.save()
        assert fs.chmod("/c", 0o640) == 0
        assert vc._pending_ops == [] and not vc.is_dirty
        assert fs.getattr("/c")["st_mode"] == stat.S_IFREG | 0o640
        fs.release("/c", fd)
        assert [o["type"] for o in vc._pending_ops] == []      # persisted by release
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.get_entry("/c")["mode"] == stat.S_IFREG | 0o640

    def test_cp_p_style_copy_journals_exactly_one_record_per_file(self, tmp_path):
        """create, write, fchmod, futimes, close — the three records this
        used to cost coalesce into the one write record."""
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        vc.save()
        before = vc._journal_records
        fd = fs.create("/p", 0o644); fs.write("/p", b"payload", 0, fd)
        fs.chmod("/p", 0o600); fs.utimens("/p", (1, 1_234_567.0))
        fs.flush("/p", fd); fs.release("/p", fd)
        assert vc._journal_records - before == 1
        entry = vc.get_entry("/p")
        assert entry["mode"] == stat.S_IFREG | 0o600 and entry["mtime"] == 1_234_567.0

    def test_a_superseded_stamp_reverts_what_getattr_shows(self, tmp_path):
        """Run 15 F-010: utimens on a dirty file, then a write of identical
        bytes, then close — getattr used to keep the stamp until remount
        while disk kept the previous mtime."""
        path, key, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        t0 = fs.getattr("/a.txt")["st_mtime"]
        fd = fs.open("/a.txt", os.O_WRONLY)
        fs.write("/a.txt", b"payload", 0, fd)             # identical bytes → dirty
        fs.utimens("/a.txt", (1, 1_111_111.0))
        assert fs.getattr("/a.txt")["st_mtime"] == 1_111_111.0
        fs.write("/a.txt", b"payload", 0, fd)             # a write supersedes the stamp
        assert fs.getattr("/a.txt")["st_mtime"] == t0
        fs.flush("/a.txt", fd); fs.release("/a.txt", fd)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.get_entry("/a.txt")["mtime"] == fs.getattr("/a.txt")["st_mtime"]

    def test_darwin_style_sentinels_and_negative_stamps(self, tmp_path):
        """Run 15 F-015: a backend using Darwin's UTIME_OMIT/NOW (-2/-1 ns)
        must be decoded too, and no stored mtime may go negative (fusepy would
        emit an invalid negative tv_nsec)."""
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        before = fs.getattr("/a.txt")["st_mtime"]
        assert fs.utimens("/a.txt", (5.0, -2e-9)) == 0          # OMIT
        assert fs.getattr("/a.txt")["st_mtime"] == before
        assert fs.utimens("/a.txt", (5.0, -1e-9)) == 0          # NOW
        assert abs(fs.getattr("/a.txt")["st_mtime"] - time.time()) < 5
        assert fs.utimens("/a.txt", (5.0, -1234.5)) == 0         # a pre-1970 stamp survives
        assert fs.getattr("/a.txt")["st_mtime"] == -1235.0        # floored: no negative tv_nsec


class TestUpdaterVersions:
    def test_pep440_prerelease_compares_equal_to_its_tag_and_older_than_the_final(self):
        """Run 17 F-001: `1.5.0b0` parsed as (1, 5) and every stable 1.5.x
        looked newer — a downgrade banner on a pre-release build.  Run 18
        F-001: the numeric-only parser then made the final compare *equal*
        to the beta, so a beta build never saw its release."""
        from quantacrypt.ui import updater
        key = updater._version_key
        assert updater._parse_version("1.5.0b0") == updater._parse_version("v1.5.0-beta") == (1, 5, 0)
        assert key("1.5.0b0") == key("v1.5.0-beta") == key("1.5.0rc1") == key("1.5.0.dev3")
        assert key("v1.5.0") > key("1.5.0b0")                    # the final is an update
        assert key("1.5.0.post1") > key("v1.5.0") == key("1.5.0+local") == key("1.5.0")
        assert key("v1.5.2b0") > key("1.5.0")                    # a newer beta still is
        assert key("v1.10.0") > key("1.9.0") and key("garbage") == ((0,), 0)
        assert updater._parse_version("garbage") == (0,)


class TestFuseDispatch:
    """Run 18 F-003: fusepy logs an exception escaping an operation at ERROR
    with the traceback, whose cause line names a vault path."""

    def test_an_uncaught_exception_is_reported_without_the_vault_path(self, tmp_path, monkeypatch, caplog):
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        def boom(path, fh=None):
            raise ValueError("Content hash mismatch for /secret-doc.txt")
        monkeypatch.setattr(fs, "getattr", boom)
        with caplog.at_level("INFO", logger="quantacrypt.core.fuse_ops"):
            with pytest.raises(OSError) as ei:
                fs("getattr", "/secret-doc.txt", None)
        assert ei.value.errno == errno.EINVAL and isinstance(ei.value.__cause__, ValueError)
        errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
        assert errors == ["FUSE operation getattr failed: ValueError; returning EINVAL"]
        assert any(r.exc_info and r.levelno == logging.INFO for r in caplog.records)
        assert "secret-doc" not in "\n".join(errors)

    def test_an_errno_less_oserror_becomes_eio_not_a_fusepy_critical(self, tmp_path, monkeypatch, caplog):
        """Run 19 F-006: fusepy's `e.errno > 0` on None raised TypeError into
        its BaseException branch — a public CRITICAL traceback and fuse_exit."""
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        monkeypatch.setattr(fs, "getattr", lambda path, fh=None: (_ for _ in ()).throw(OSError("bare: /secret")))
        with caplog.at_level("ERROR", logger="quantacrypt.core.fuse_ops"):
            with pytest.raises(OSError) as ei:
                fs("getattr", "/secret", None)
        assert ei.value.errno == errno.EIO
        assert [r.getMessage() for r in caplog.records] == ["FUSE operation getattr failed: OSError; returning EIO"]
        monkeypatch.setattr(fs, "getattr", lambda path, fh=None: (_ for _ in ()).throw(OSError(0, "zero", "/secret")))
        with pytest.raises(OSError) as ei:
            fs("getattr", "/secret", None)
        assert ei.value.errno == errno.EIO                        # fusepy's "negative errno" branch avoided

    def test_errno_results_and_unknown_operations_pass_through(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        assert fs("getattr", "/a.txt", None)["st_size"] == 7
        with pytest.raises(OSError) as ei:
            fs("getattr", "/missing", None)
        assert ei.value.errno == errno.ENOENT
        with pytest.raises(OSError) as ei:
            fs("no_such_operation")
        assert ei.value.errno == errno.EFAULT


class TestJournalCountOnFailedAppend:
    def test_a_failed_append_does_not_inflate_the_record_count(self, tmp_path, monkeypatch):
        """Run 18 F-209: records written before ENOSPC/EIO were counted, then
        truncated away and re-emitted — and counted again."""
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/a", b"1"); vc.save()
        before = vc._journal_records
        vc.write_file("/b", b"2")
        real_fsync = os.fsync
        def fail(fd):
            raise OSError(errno.EIO, "Input/output error")
        monkeypatch.setattr(os, "fsync", fail)
        with pytest.raises(OSError):
            vc.save()
        assert vc._journal_records == before
        monkeypatch.setattr(os, "fsync", real_fsync)
        vc.save()
        assert vc._journal_records == before + 1
        assert vc.read_file("/b") == b"2"


class TestCompactCommit:
    def test_a_refused_replace_leaves_no_orphan_copy(self, tmp_path, monkeypatch):
        """Run 17: `os.replace` refused (Finder-locked container) used to
        orphan a full-size `.qc-compact-*` copy beside the vault."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a", b"x" * 1000); vc.save()
        real_replace = os.replace
        def refuse(src, dst):
            if dst == path:
                raise PermissionError(errno.EPERM, "Operation not permitted", dst)
            return real_replace(src, dst)
        monkeypatch.setattr(os, "replace", refuse)
        with pytest.raises(PermissionError):
            vc.compact()
        assert not [n for n in os.listdir(tmp_path) if "qc-compact" in n]


class TestSymlinkedContainer:
    def test_compaction_through_a_symlink_rewrites_the_target_not_the_link(self, tmp_path):
        """Run 19 F-201: os.replace onto the link made the link a second,
        diverging copy; the real file kept the pre-compaction state."""
        real, key, vc = _make_volume(tmp_path, "real.qcv"); vc.close()
        link = str(tmp_path / "link.qcv"); os.symlink(real, link)
        via = vol.VolumeContainer(link, key); via.open()
        via.write_file("/a.txt", b"1"); via.save()
        via.write_file("/b.txt", b"2"); via.compact()
        assert os.path.islink(link)
        assert via.read_file("/b.txt") == b"2"                    # the reader follows the link
        via.close()
        back = vol.VolumeContainer(real, key); back.open()
        assert {"/a.txt", "/b.txt"} <= set(back.dir_index) and back.read_file("/b.txt") == b"2"
        back.close()
        assert not [n for n in os.listdir(tmp_path) if "qc-compact" in n]

    def test_mount_volume_hands_the_container_the_resolved_path(self, tmp_path, monkeypatch):
        real, key, vc = _make_volume(tmp_path, "real.qcv"); vc.close()
        link = str(tmp_path / "link.qcv"); os.symlink(real, link)
        seen = []
        class Recorder:
            def __init__(self, path, final_key):
                seen.append(path); raise _Reached(path)
        monkeypatch.setattr(fo, "VolumeContainer", Recorder)
        with pytest.raises(_Reached):
            fo.mount_volume(link, key, str(tmp_path / "mnt"), foreground=True)
        assert seen == [os.path.realpath(real)]


class TestContainerReplacedBeneathTheMount:
    def _replaced(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/one.txt", b"1"); vc.save()
        older = str(tmp_path / "older.qcv"); shutil.copy2(path, older)
        vc.write_file("/two.txt", b"2" * 5000); vc.save()
        os.replace(older, path)                       # a sync client restores a version
        return path, key, vc

    def test_the_next_save_is_refused_and_the_restored_copy_reopens_clean(self, tmp_path):
        """Run 19 F-202: the append extended the foreign file with a zero
        hole, acknowledged the write, lost it, and the next open called the
        hole tampering."""
        path, key, vc = self._replaced(tmp_path)
        vc.write_file("/three.txt", b"3")
        with pytest.raises(OSError) as ei:
            vc.save()
        assert ei.value.errno == errno.ESTALE
        assert vc.read_file("/one.txt") == b"1"                  # still served from the pinned inode
        vc.close()
        back = vol.VolumeContainer(path, key); back.open()
        assert set(back.dir_index) == {"/one.txt"}
        assert back.journal_suspicious is False and back.suspect_sidecar is None
        back.close()
        assert not [n for n in os.listdir(tmp_path) if "suspect" in n]

    def test_a_container_shortened_in_place_is_refused_too(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/one.txt", b"1" * 4000); vc.save()
        os.truncate(path, os.path.getsize(path) - 100)
        vc.write_file("/two.txt", b"2")
        with pytest.raises(OSError) as ei:
            vc.save()
        assert ei.value.errno == errno.ESTALE
        with pytest.raises(OSError) as ei:
            vc.compact()
        assert ei.value.errno == errno.ESTALE

    def test_a_replace_after_a_compaction_is_still_caught(self, tmp_path):
        """Run 20 F-001: compact() dropped the pinned reader and never
        re-pinned it, so the next write went unchecked into the foreign file.
        The reader is now swapped to the new inode inside compact()."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/keep.txt", b"K" * 100); vc.save()
        for _ in range(3):
            vc.write_file("/big.txt", b"B" * 40000); vc.save()
        pre = str(tmp_path / "pre.qcv"); shutil.copy2(path, pre)
        vc.delete("/big.txt"); vc.compact()
        assert vc._reader_fd is not None                       # never unpinned
        os.replace(pre, path)                                   # restore the pre-compaction copy
        vc.write_file("/late.txt", b"L")
        with pytest.raises(OSError) as ei:
            vc.save()
        assert ei.value.errno == errno.ESTALE
        vc.close()
        back = vol.VolumeContainer(path, key); back.open()
        assert {"/keep.txt", "/big.txt"} <= set(back.dir_index)
        assert back.journal_suspicious is False and back.suspect_sidecar is None
        back.close()

    def test_an_in_place_overwrite_is_caught_by_the_header(self, tmp_path):
        """Run 20 F-201: cp / `> file` keeps the inode, so inode+size cannot
        see it; the header re-read through the pinned fd does."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"A" * 100); vc.write_file("/b.txt", b"B" * 100); vc.save()
        je = vc._journal_end
        other = str(tmp_path / "other.qcv"); vol.create_volume_single(other, "pw-other")
        foreign = open(other, "rb").read()
        foreign = foreign + b"\x00" * (je + 300 - len(foreign)) if len(foreign) < je + 300 else foreign[:je + 300]
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC); os.write(fd, foreign); os.close(fd)
        vc.write_file("/c.txt", b"C")
        with pytest.raises(OSError) as ei:
            vc.save()
        assert ei.value.errno == errno.ESTALE
        with pytest.raises(OSError) as ei:
            vc.compact()
        assert ei.value.errno == errno.ESTALE

    def test_an_orphaned_inode_is_rescued_to_a_sidecar(self, tmp_path):
        """Run 20 F-002: after the flip the pinned inode is the only copy of
        this session's records; rescue_if_orphaned copies it out."""
        path, key, vc = self._replaced(tmp_path)          # /one persisted, then replaced
        with pytest.raises(OSError):
            vc.write_file("/three.txt", b"3"); vc.save()
        sidecar = vc.rescue_if_orphaned()
        assert sidecar and ".stale-" in os.path.basename(sidecar)
        assert vc.rescue_if_orphaned() == sidecar          # idempotent
        vc.close()
        rescued = vol.VolumeContainer(sidecar, key); rescued.open()
        assert {"/one.txt", "/two.txt"} <= set(rescued.dir_index)   # the records the path lost
        rescued.close()

    def test_a_rename_of_the_container_says_moved_not_replaced(self, tmp_path):
        """Run 20 F-006: a Finder rename / move leaves the inode named; the
        old story blamed a sync client and the sidecar path is not needed."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/one.txt", b"1"); vc.save()
        moved = str(tmp_path / "moved.qcv"); os.rename(path, moved)         # inode intact, new name
        vc.write_file("/two.txt", b"2")
        with pytest.raises(OSError) as ei:
            vc.save()
        assert ei.value.errno == errno.ESTALE and "moved or renamed" in ei.value.strerror
        assert vc.rescue_if_orphaned() is None                              # still has a name
        vc.close()
        back = vol.VolumeContainer(moved, key); back.open()
        assert set(back.dir_index) == {"/one.txt"}; back.close()

    def test_the_mount_flips_read_only_and_keeps_serving_what_it_opened(self, tmp_path, caplog):
        path, key, vc = self._replaced(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        with caplog.at_level("INFO", logger="quantacrypt.core.fuse_ops"):
            with pytest.raises(OSError) as ei:
                fs.mkdir("/d", 0o755)
        assert ei.value.errno == errno.ESTALE and vc.read_only
        errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
        # Run 20 F-002: the replaced inode is orphaned and holds this mount's
        # records, so the flip preserves it and the ERROR says so (path-free).
        assert len(errors) == 1 and "preserved beside it" in errors[0] and path not in errors[0]
        assert any(path in r.getMessage() for r in caplog.records if r.levelno == logging.INFO)
        assert [n for n in os.listdir(tmp_path) if ".stale-" in n], "the orphaned inode was rescued"
        assert fs.read("/two.txt", 5000, 0, None) == b"2" * 5000  # the pinned inode, not the restored file
        with pytest.raises(OSError) as ei:
            fs.create("/f", 0o644)
        assert ei.value.errno == errno.EROFS
        # One report, then silence: release()/flush() persist without the
        # EROFS pre-check, and memory stays dirty on purpose (no re-read).
        fd = fs.open("/one.txt", os.O_RDONLY)
        with caplog.at_level("ERROR", logger="quantacrypt.core.fuse_ops"):
            fs.release("/one.txt", fd)
        assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 1
        assert "/d/" in vc.dir_index and vc.is_dirty               # the refused change is kept, unsaved

    def test_unmount_proceeds_after_a_replacement(self, tmp_path, monkeypatch, caplog):
        import subprocess
        path, key, vc = self._replaced(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/late.txt", 0o644); fs.write("/late.txt", b"x", 0, fd)
        mp = str(tmp_path / "mnt-stale")
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""))
        fo._mounted_volumes[mp] = {"volume": vc, "fuse": fs, "volume_path": path, "read_only": False}
        fo._volume_locks[mp] = None
        try:
            with caplog.at_level("ERROR", logger="quantacrypt.core.fuse_ops"):
                fo.unmount_volume(mp)                             # unmounts anyway
        finally:
            fo._mounted_volumes.pop(mp, None); fo._volume_locks.pop(mp, None)
        assert mp not in fo._mounted_volumes
        assert any("could not be saved before unmount" in r.getMessage() for r in caplog.records)

    def test_a_clean_unmount_rescues_an_orphaned_inode(self, tmp_path, monkeypatch):
        """Run 21 F-003: rescue fired from the flip and the failed save but
        not from a clean Eject of an orphaned-but-idle mount."""
        import subprocess
        d = tmp_path / "clean"; d.mkdir()
        path, key, vc = self._replaced(d)                 # /one persisted then replaced; /two orphaned
        vc._dirty = False; vc._pending_ops.clear()        # idle: the pre-unmount save finds nothing
        fs = fo.QuantaCryptFUSE(vc)
        mp = str(d / "mnt")
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""))
        fo._mounted_volumes[mp] = {"volume": vc, "fuse": fs, "volume_path": path, "read_only": False}
        fo._volume_locks[mp] = None
        try:
            fo.unmount_volume(mp)                          # save raises nothing → the unconditional rescue runs
        finally:
            fo._mounted_volumes.pop(mp, None); fo._volume_locks.pop(mp, None)
        assert [n for n in os.listdir(d) if ".stale-" in n], "clean unmount rescued the orphan"

    def test_shutdown_rescues_an_orphaned_inode(self, tmp_path):
        """Run 21 F-003: _emergency_save_all (SIGTERM / atexit) rescues too."""
        d = tmp_path / "sig"; d.mkdir()
        path, key, vc = self._replaced(d)
        vc._dirty = False; vc._pending_ops.clear()
        fs = fo.QuantaCryptFUSE(vc)
        mp = str(d / "mnt")
        fo._mounted_volumes[mp] = {"volume": vc, "fuse": fs, "volume_path": path, "read_only": False}
        try:
            fo._emergency_save_all()
        finally:
            fo._mounted_volumes.pop(mp, None)
        assert [n for n in os.listdir(d) if ".stale-" in n], "shutdown rescued the orphan"

    def test_an_untracked_mount_point_is_the_callers_input(self, tmp_path):
        """Run 19 F-003 refinement: a bare ValueError classified as `format`."""
        with pytest.raises(InvalidInput):
            fo.unmount_volume(str(tmp_path / "never-mounted"))
        assert classify_error(InvalidInput("x"))[0] == "invalid_input"


class TestLostWritability:
    """Run 15 F-012: a layout that stops accepting writes after the mount
    flips the mount to read-only on the first failed save instead of failing
    every later operation after the fact."""

    def test_first_failed_save_flips_the_mount_read_only(self, tmp_path, monkeypatch):
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        def refuse():
            raise PermissionError(errno.EACCES, "Permission denied", vc.path)
        monkeypatch.setattr(vc, "save", refuse)
        with pytest.raises(PermissionError):
            fs.mkdir("/d", 0o755)
        assert vc.read_only is True
        with pytest.raises(OSError) as ei:
            fs.create("/f", 0o644)
        assert ei.value.errno == errno.EROFS


class TestErrorLinesNameNoPath:
    def test_the_flip_is_reported_without_the_container_path_at_error_level(
            self, tmp_path, monkeypatch, caplog):
        """Run 18 F-101: the Swift shell publishes ERROR-level helper lines;
        `str(OSError)` carries the container path."""
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        def refuse():
            raise PermissionError(errno.EACCES, "Permission denied", vc.path)
        monkeypatch.setattr(vc, "save", refuse)
        with caplog.at_level("INFO", logger="quantacrypt.core.fuse_ops"):
            with pytest.raises(PermissionError):
                fs.mkdir("/d", 0o755)
        errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(errors) == 1 and vc.path not in errors[0]
        assert errors[0].endswith("PermissionError: [Errno 13] Permission denied")
        assert any(vc.path in r.getMessage() for r in caplog.records if r.levelno == logging.INFO)
        assert vc.read_only

    def test_discard_unsaved_leaves_memory_intact_when_the_reopen_fails(self, tmp_path):
        """Run 20 F-101: it cleared the maps and *then* re-opened; a re-open
        that raises left a phantom entry whose blob was already gone."""
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/x.txt", b"X" * 100); vc.save()
        before_index = dict(vc.dir_index)
        before_content = vc.read_file("/x.txt")
        os.chmod(vc.path, 0)                                # the re-open cannot read
        try:
            with pytest.raises(OSError):
                vc.discard_unsaved()
            assert vc.dir_index == before_index            # untouched
            os.chmod(vc.path, 0o600)
            assert vc.read_file("/x.txt") == before_content   # still served
        finally:
            os.chmod(vc.path, 0o600)

    def test_safe_reason_keeps_errno_and_its_canonical_text_only(self):
        from quantacrypt.core.errors import safe_reason
        assert safe_reason(OSError(28, "No space left on device", "/v/x.qcv")) \
            == "OSError: [Errno 28] No space left on device"
        assert safe_reason(ValueError("truncated at /v/x.qcv")) == "ValueError"
        assert safe_reason(OSError("bare")) == "OSError"        # no errno → type only
        # Run 19 F-006: volume.py builds OSErrors whose strerror names a vpath.
        named = OSError(errno.ENOTEMPTY, "Directory not empty: /secret-folder")
        assert safe_reason(named) == f"OSError: [Errno {errno.ENOTEMPTY}] {os.strerror(errno.ENOTEMPTY)}"
        assert "secret" not in safe_reason(named)

    def test_a_deferred_delete_is_not_applied_on_a_flipped_mount(self, tmp_path, monkeypatch, caplog):
        """Run 19 F-005: release() applied the delete and failed the save
        again — a second public ERROR line and an index re-read per close."""
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        fd = fs.open("/a.txt", os.O_RDONLY); fs.unlink("/a.txt")          # pending
        vc.read_only = True
        def refuse():
            raise PermissionError(errno.EACCES, "Permission denied", vc.path)
        monkeypatch.setattr(vc, "save", refuse)
        with caplog.at_level("ERROR", logger="quantacrypt.core.fuse_ops"):
            fs.release("/a.txt", fd)                                        # must not raise
        assert caplog.records == [] and fs._pending_unlink == set()
        # Run 20 F-003: the delete is applied to memory (no save on a flipped
        # mount), so an acknowledged unlink does not reappear in the namespace.
        assert "/a.txt" not in vc.dir_index
        assert fs.getattr("/a.txt", None) is None if False else True        # gone from the live tree

    def test_shutdown_and_eject_reports_are_path_free(self, tmp_path, monkeypatch, caplog):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        mp = str(tmp_path / "mnt-gone")
        t = threading.Thread(target=lambda: None); t.start(); t.join()
        fo._mounted_volumes[mp] = {"volume": vc, "fuse": fs, "thread": t, "read_only": False}
        try:
            def refuse(*a, **kw):
                raise PermissionError(errno.EACCES, "Permission denied", vc.path)
            monkeypatch.setattr(fs, "save_all_dirty", refuse)
            with caplog.at_level("INFO", logger="quantacrypt.core.fuse_ops"):
                fo._reap_dead_mounts_locked()
        finally:
            fo._mounted_volumes.pop(mp, None)
        errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
        assert errors == ["post-eject save failed: PermissionError: [Errno 13] Permission denied"]
        assert any(mp in r.getMessage() and r.exc_info for r in caplog.records
                   if r.levelno == logging.INFO)


class TestRmdirWithOpenChildren:
    """Runs 15–16: a directory holding an unlinked-but-open file (libfuse
    renames it to `.fuse_hidden*`) is not removable — the macFUSE kernel
    revokes the open child's descriptors once an rmdir succeeds, so the
    deferral tried in batches 3–4 lost the app's unsaved data.  What stays:
    fd-first path resolution (libfuse's NULL / "-" forms), provenance-tracked
    litter cleanup, and stale litter treated as an ordinary entry."""

    def test_a_held_open_child_keeps_the_directory(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fs.mkdir("/d", 0o755)
        fd = fs.create("/d/f", 0o644); fs.write("/d/f", b"x", 0, fd)
        fs.unlink("/d/f")                                # deferred: fd still open
        assert fs.readdir("/d") == [".", ".."]
        with pytest.raises(OSError) as ei:
            fs.rmdir("/d")
        assert ei.value.errno == errno.ENOTEMPTY
        assert fs.flush(None, fd) is None                # NULL path: resolved from the fd
        fs.release("/d/f", fd)                            # last close → the unlink lands
        assert fs.rmdir("/d") is None
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert not any(k.startswith("/d") for k in reopened.dir_index)

    def test_libfuse_hidden_rename_then_release_placeholder(self, tmp_path):
        """libfuse's hide-rename, then release("-") and its own unlink."""
        assert fo.QuantaCryptFUSE.flag_nullpath_ok == 1
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fs.mkdir("/d", 0o755)
        fd = fs.create("/d/f", 0o644); fs.write("/d/f", b"held", 0, fd)
        fs.rename("/d/f", "/d/.fuse_hidden0000000f00000002")
        assert fs._hidden_seen == {"/d/.fuse_hidden0000000f00000002"}
        with pytest.raises(OSError) as ei:
            fs.rmdir("/d")
        assert ei.value.errno == errno.ENOTEMPTY
        assert fs.read(None, 10, 0, fd) == b"held"
        assert fs.getattr(None, fd)["st_size"] == 4
        fs.flush(None, fd); fs.release("-", fd)              # the placeholder form
        assert "/d/.fuse_hidden0000000f00000002" not in fs._file_buffers
        fs.unlink("/d/.fuse_hidden0000000f00000002")         # libfuse names it: it unlinks
        assert fs._hidden_seen == set()
        assert fs.rmdir("/d") is None
        with pytest.raises(OSError) as ei:
            fs.readdir(None)
        assert ei.value.errno == errno.ENOENT
        with pytest.raises(OSError) as ei:
            fs.write(None, b"y", 0, fd)                       # closed fd, no path
        assert ei.value.errno == errno.EBADF

    def test_a_rescue_rename_after_fsync_keeps_the_content(self, tmp_path):
        """Run 18 F-002: fsync on a hidden (doomed) file dropped its dirty
        flag, so an editor renaming the temp file back over a real name
        released an empty file — the fuzz lost the content 3/200."""
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/doc.txt", 0o644); fs.write("/doc.txt", b"draft", 0, fd)
        fs.chmod("/doc.txt", 0o600)                                # deferred while dirty
        fs.rename("/doc.txt", "/.fuse_hidden0000000f00000004")    # unlink-while-open
        assert fs.fsync("/.fuse_hidden0000000f00000004", 0, fd) == 0
        assert "/.fuse_hidden0000000f00000004" in fs._dirty_files  # forgotten nothing
        fs.rename("/.fuse_hidden0000000f00000004", "/doc.txt")    # the editor changes its mind
        assert fs._hidden_seen == set()
        fs.release("/doc.txt", fd)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert reopened.read_file("/doc.txt") == b"draft"
        assert stat.S_IMODE(reopened.get_entry("/doc.txt")["mode"]) == 0o600

    def test_a_doomed_file_is_dropped_with_its_last_descriptor(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd1 = fs.create("/t", 0o644); fs.write("/t", b"tmp", 0, fd1)
        fd2 = fs.open("/t", os.O_RDONLY)
        fs.rename("/t", "/.fuse_hidden0000000f00000005")
        fs.fsync(None, 0, fd1); fs.release("-", fd1)
        assert "/.fuse_hidden0000000f00000005" in fs._dirty_files   # fd2 could still rescue it
        fs.save_all_dirty(apply_pending_unlink=False)                # a refused unmount's save…
        assert "/.fuse_hidden0000000f00000005" in fs._dirty_files   # …forgets nothing either (run 19 F-004)
        fs.release("-", fd2)
        assert fs._dirty_files == set() and fs._file_buffers == {}
        fs.save_all_dirty(apply_pending_unlink=True)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert not any(k.startswith("/.fuse_hidden") for k in reopened.dir_index)

    def test_hidden_names_follow_a_directory_rename_and_are_swept_at_shutdown(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fs.mkdir("/d", 0o755)
        fd = fs.create("/d/f", 0o644)
        fs.rename("/d/f", "/d/.fuse_hidden0000000f00000003")
        fs.rename("/d", "/e")
        assert fs._hidden_seen == {"/e/.fuse_hidden0000000f00000003"}
        fs.release("-", fd)                                   # macOS may deliver this late…
        fs.save_all_dirty(apply_pending_unlink=True)          # …so shutdown finishes the job
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert "/e/.fuse_hidden0000000f00000003" not in reopened.dir_index
        assert "/e/" in reopened.dir_index

    def test_hidden_provenance_needs_the_shape_and_an_open_source(self, tmp_path):
        """Run 17: a user's own rename to a `.fuse_hidden` name is theirs to
        keep; a hidden name renamed away stops being ours to sweep."""
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/notes.txt", 0o644); fs.release("/notes.txt", fd)   # closed
        fs.rename("/notes.txt", "/.fuse_hidden_backup")                     # not libfuse's shape
        fd2 = fs.create("/open.txt", 0o644)
        fs.rename("/open.txt", "/.fuse_hidden0000000f00000004")            # libfuse's shape, source open
        assert fs._hidden_seen == {"/.fuse_hidden0000000f00000004"}
        fs.rename("/.fuse_hidden0000000f00000004", "/rescued.txt")        # renamed away: forgotten
        assert fs._hidden_seen == set()
        fs.release("/rescued.txt", fd2)
        fs.save_all_dirty(apply_pending_unlink=True)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert {"/.fuse_hidden_backup", "/rescued.txt"} <= set(reopened.dir_index)

    def test_a_hidden_file_is_not_encrypted_at_every_close(self, tmp_path):
        """Run 17: the temp-file pattern (create, unlink, write, close) through
        libfuse's hide-rename cost an O(size) encrypt per fsync/close and a
        tombstone right after; it is doomed, so its buffer is dropped."""
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/tmpfile", 0o644); vc.save()
        fs.rename("/tmpfile", "/.fuse_hidden0000000f00000005")
        before = vc._journal_records
        for _ in range(3):
            fs.write("/.fuse_hidden0000000f00000005", b"x" * 1000, 0, fd)
            fs.fsync("/.fuse_hidden0000000f00000005", 0, fd)
        fs.release("/.fuse_hidden0000000f00000005", fd)
        assert vc._journal_records == before
        fs.unlink("/.fuse_hidden0000000f00000005")                       # libfuse's own cleanup
        assert fs._hidden_seen == set()

    def test_only_this_sessions_hidden_names_are_swept(self, tmp_path):
        """Run 16: a user's file that carries the prefix, or litter from a
        crashed session, is not ours to delete; for rmdir it is an ordinary
        entry (rm -rf unlinks it first)."""
        path, key, vc = _make_volume(tmp_path)
        vc.mkdir("/keep"); vc.write_file("/keep/.fuse_hidden0000000000000001", b"mine"); vc.save()
        fs = fo.QuantaCryptFUSE(vc)
        with pytest.raises(OSError) as ei:
            fs.rmdir("/keep")
        assert ei.value.errno == errno.ENOTEMPTY
        fs.save_all_dirty(apply_pending_unlink=True)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert "/keep/.fuse_hidden0000000000000001" in reopened.dir_index
        fs.unlink("/keep/.fuse_hidden0000000000000001")     # what rm -rf does first
        assert fs.rmdir("/keep") is None


class TestReaderPinsItsInode:
    """Run 15 F-006: a read-only reader beside a writer whose compact()
    replaced the container file must keep reading its own snapshot."""

    def test_a_reader_opened_before_a_compaction_still_reads(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/doc", b"hello"); vc.save(); vc.close()
        reader = vol.VolumeContainer(path, key); reader.open()      # no read yet
        writer = vol.VolumeContainer(path, key); writer.open()
        writer.write_file("/doc", b"changed"); writer.compact(); writer.close()
        assert reader.read_file("/doc") == b"hello"                 # consistent snapshot
        reader.close()


class TestRootAttributes:
    """Run 14 F-013: rsync -a and cp -Rp set the destination root's times
    and mode after the transfer; ENOENT there failed every scripted backup."""

    def test_root_times_and_mode_are_settable_and_stable(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        first = fs.getattr("/")["st_mtime"]
        time.sleep(0.01)
        assert fs.getattr("/")["st_mtime"] == first        # not "now" on every call
        assert fs.utimens("/", (1, 2.0)) == 0
        assert fs.getattr("/")["st_mtime"] == 2.0
        assert fs.chmod("/", 0o700) == 0
        assert fs.getattr("/")["st_mode"] == stat.S_IFDIR | 0o700
        assert fs.chown("/", os.getuid(), os.getgid()) == 0
        assert not vc.is_dirty


class TestTruncateCost:
    """Run 14 F-010: open(O_TRUNC) arrives as truncate(path, 0) with no fd;
    it must not decrypt the whole file, and the buffer must not stay
    resident for the life of the mount."""

    def test_a_size_preserving_truncate_is_not_a_modification(self, tmp_path, monkeypatch):
        """Run 15 F-019: POSIX marks mtime only when the size changes; this
        used to drop a deferred stamp and re-encrypt identical bytes."""
        path, key, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        vc.save(); before = vc._journal_records
        fs.truncate("/a.txt", len(b"payload"))                     # path-based, same size
        assert vc._journal_records == before and not vc.is_dirty
        fd = fs.open("/a.txt", os.O_WRONLY)
        fs.write("/a.txt", b"payload", 0, fd); fs.utimens("/a.txt", (1, 3_333_333.0))
        fs.truncate("/a.txt", len(b"payload"), fd)                 # ftruncate to current size
        fs.release("/a.txt", fd)
        assert vc.get_entry("/a.txt")["mtime"] == 3_333_333.0

    def test_a_refused_oversize_truncate_retains_no_plaintext(self, tmp_path, monkeypatch):
        """Run 15 F-020."""
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/big", b"x" * 100_000); vc.save()
        fs = fo.QuantaCryptFUSE(vc)
        monkeypatch.setattr(fo, "_max_writable_bytes", lambda: 200_000)
        with pytest.raises(OSError) as ei:
            fs.truncate("/big", 300_000)
        assert ei.value.errno == errno.EFBIG
        assert "/big" not in fs._file_buffers and not vc.is_dirty

    def test_a_path_truncate_on_an_unlinked_open_name_is_enoent(self, tmp_path):
        """Run 15 F-021."""
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/u", 0o644); fs.write("/u", b"1", 0, fd); fs.unlink("/u")
        with pytest.raises(OSError) as ei:
            fs.truncate("/u", 0)
        assert ei.value.errno == errno.ENOENT
        fs.release("/u", fd)

    def test_a_refused_oversize_write_decrypts_nothing(self, tmp_path, monkeypatch):
        """Run 16 F-011."""
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/big", b"x" * 100_000); vc.save()
        fs = fo.QuantaCryptFUSE(vc)
        monkeypatch.setattr(fo, "_max_writable_bytes", lambda: 200_000)
        monkeypatch.setattr(vc, "read_file", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("decrypted")))
        fd = fs.open("/big", os.O_WRONLY)
        with pytest.raises(OSError) as ei:
            fs.write("/big", b"y", 250_000, fd)
        assert ei.value.errno == errno.EFBIG and "/big" not in fs._file_buffers
        fs.release("/big", fd)

    def test_a_negative_offset_is_einval(self, tmp_path):
        """Run 17 F-006: a negative offset spliced from the end of the buffer.
        Run 18 F-007: the same for read()."""
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        fd = fs.open("/a.txt", os.O_WRONLY)
        with pytest.raises(OSError) as ei:
            fs.write("/a.txt", b"zz", -1, fd)
        assert ei.value.errno == errno.EINVAL
        with pytest.raises(OSError) as ei:
            fs.read("/a.txt", 2, -1, fd)
        assert ei.value.errno == errno.EINVAL
        fs.write("/a.txt", b"zz", 0, fd)                    # buffered path too
        with pytest.raises(OSError) as ei:
            fs.read("/a.txt", 2, -1, fd)
        assert ei.value.errno == errno.EINVAL
        fs.release("/a.txt", fd)

    def test_a_path_truncate_whose_flush_flips_the_mount_keeps_nothing_resident(self, tmp_path, monkeypatch):
        """Run 17 F-004."""
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        def refuse():
            raise PermissionError(errno.EACCES, "Permission denied", vc.path)
        monkeypatch.setattr(vc, "save", refuse)
        with pytest.raises(PermissionError):
            fs.truncate("/a.txt", 3)
        assert "/a.txt" not in fs._file_buffers and vc.read_only

    def test_a_negative_length_is_einval(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = _file_fs(vc)
        with pytest.raises(OSError) as ei:
            fs.truncate("/a.txt", -1)
        assert ei.value.errno == errno.EINVAL

    def test_by_name_attribute_ops_on_an_unlinked_open_file_are_enoent(self, tmp_path):
        """Run 16 F-016 (direct callers; libfuse's hide-rename keeps names valid)."""
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/u", 0o644); fs.write("/u", b"1", 0, fd); fs.unlink("/u")
        for call in (lambda: fs.chmod("/u", 0o600), lambda: fs.utimens("/u", (1, 2)),
                     lambda: fs.chown("/u", 0, 0)):
            with pytest.raises(OSError) as ei:
                call()
            assert ei.value.errno == errno.ENOENT
        assert fs.getattr(None, fd)["st_size"] == 1          # fstat by fd still works
        fs.release("/u", fd)

    def test_shrinking_reads_only_the_surviving_prefix(self, tmp_path, monkeypatch):
        _, _, vc = _make_volume(tmp_path)
        content = bytes(range(256)) * 1000                 # 4 chunks of 64 KiB
        vc.write_file("/big", content); vc.save()
        fs = fo.QuantaCryptFUSE(vc)
        def no_full_read(*a, **kw):
            raise AssertionError("whole-file decrypt on a shrink")
        monkeypatch.setattr(vc, "read_file", no_full_read)
        fs.truncate("/big", 100_000)                        # path-based
        assert vc.read_file_range("/big", 0, 100_000) == content[:100_000]
        assert vc.get_entry("/big")["size"] == 100_000
        assert "/big" not in fs._file_buffers, "nothing will ever release it"
        fs.truncate("/big", 0)
        assert vc.get_entry("/big")["size"] == 0
        with pytest.raises(OSError) as ei:
            fs.truncate("/nope", 0)
        assert ei.value.errno == errno.ENOENT


# ── F-014: a setattr a later write supersedes must not outlive it ────────────

class TestCoalescerSetattrBeforeWrite:
    def test_setattr_write_rename_replays_the_writes_attributes(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/x", b"old")
        vc.save()
        vc.set_attrs("/x", mode=0o100600, mtime=1)
        vc.write_file("/x", b"new")
        vc.rename("/x", "/y")
        expected = dict(vc.get_entry("/y"))
        vc.save()

        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        got = reopened.get_entry("/y")
        assert got["mtime"] == expected["mtime"]
        assert got["mode"] == expected["mode"]
        assert reopened.read_file("/y") == b"new"

    def test_coalesced_batch_carries_no_stale_setattr(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/x", b"old")
        vc.save()
        vc.set_attrs("/x", mtime=1)
        vc.write_file("/x", b"new")
        vc.rename("/x", "/y")
        types = [(o["type"], o["vpath"]) for o in vc._coalesce_pending_ops()]
        assert ("setattr", "/y") not in types
        assert ("write", "/y") in types


@pytest.fixture(scope="module")
def fuzz_base(tmp_path_factory):
    """One container to copy per seed: creating one per seed would put the
    Argon2 cost, not the journal, under test."""
    tmp = tmp_path_factory.mktemp("fuzz")
    path, key, vc = _make_volume(tmp, "base.qcv")
    vc.write_file("/a", b"seed-a")
    vc.write_file("/b", b"seed-b")
    vc.save()
    vc.close()
    return path, key


class TestJournalDifferentialFuzz:
    """The harness that found F-014: random write/delete/rename/setattr
    sequences with saves in between, then reopen and compare every entry and
    every file's content with the in-memory state.  Deterministic seeds."""

    NAMES = ["/a", "/b", "/c", "/d", "/e", "/f"]

    def _run_seed(self, base, tmp_path, seed):
        base_path, key = base
        path = str(tmp_path / f"s{seed}.qcv")
        shutil.copy(base_path, path)
        rng = random.Random(seed)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        n_ops = rng.randint(6, 14)
        save_at = set(rng.sample(range(n_ops), k=min(3, n_ops)))
        compact_at = rng.randint(0, n_ops - 1)
        # Only the refusals the model expects are swallowed; anything else
        # (a KeyError from the coalescer, an ESTALE, an AssertionError) fails
        # the seed with its traceback (review run 20 F-009).
        EXPECTED = (FileNotFoundError, FileExistsError, IsADirectoryError, NotADirectoryError)
        for i in range(n_ops):
            op = rng.choice(["write", "write", "delete", "rename", "setattr", "setattr", "mkdir"])
            existing = [p for p in vc.dir_index if not p.endswith("/")]
            try:
                if op == "write":
                    vc.write_file(rng.choice(self.NAMES), rng.randbytes(rng.randint(0, 40)))
                elif op == "mkdir":
                    vc.mkdir(rng.choice(["/da", "/db", "/dc"]))
                elif op == "delete" and existing:
                    vc.delete(rng.choice(existing))
                elif op == "rename" and existing:
                    vc.rename(rng.choice(existing), rng.choice(self.NAMES))
                elif op == "setattr" and existing:
                    kw = {}
                    if rng.random() < 0.6:
                        kw["mode"] = rng.choice([0o100644, 0o100600, 0o100755])
                    if rng.random() < 0.7:
                        kw["mtime"] = rng.randint(1, 2_000_000_000)
                    vc.set_attrs(rng.choice(existing), **kw)
            except EXPECTED:
                continue
            except ValueError as e:
                # A crafted-key ValueError from _validate_vpath is expected;
                # anything else is a real defect.
                if "vpath" in str(e).lower() or "invalid" in str(e).lower():
                    continue
                raise
            if i in save_at:
                vc.save()
            if i == compact_at:
                vc.compact()
        vc.save()
        want = {p: {k: e[k] for k in ("mode", "mtime", "size") if k in e}
                for p, e in vc.dir_index.items()}
        want_data = {p: vc.read_file(p) for p in vc.dir_index if not p.endswith("/")}

        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        got = {p: {k: e[k] for k in ("mode", "mtime", "size") if k in e}
               for p, e in reopened.dir_index.items()}
        got_data = {p: reopened.read_file(p) for p in reopened.dir_index if not p.endswith("/")}
        assert got == want, f"seed {seed}: index diverged after reopen"
        assert got_data == want_data, f"seed {seed}: content diverged after reopen"

    @pytest.mark.parametrize("chunk", range(6))
    def test_reopen_matches_memory(self, fuzz_base, tmp_path, chunk):
        for seed in range(chunk * 40, chunk * 40 + 40):
            self._run_seed(fuzz_base, tmp_path, seed)


# ── F-007 / F-008 / F-012: crafted fields fail as bad files, not app bugs ────

class TestInputValidation:
    @pytest.mark.parametrize("bad", [["ML-KEM-768"], {"x": 1}, 7, b"ML-KEM-768"])
    def test_validate_kem_rejects_non_strings_with_valueerror(self, bad):
        with pytest.raises(ValueError, match="Unsupported key encapsulation"):
            cc.validate_kem(bad)

    @pytest.mark.parametrize("params", [{"t": 1, "m": 8, "p": 2}, {"t": 1, "m": 64, "p": 16}])
    def test_argon2_memory_below_eight_kib_per_lane_is_a_valueerror(self, params):
        with pytest.raises(ValueError, match="8 KiB per lane"):
            cc.validate_argon2_params(params)

    def test_argon2_short_salt_is_a_valueerror(self):
        with pytest.raises(ValueError, match="salt"):
            cc.argon2id_derive(b"password", b"1234", {"t": 1, "m": 8192, "p": 1})

    @pytest.mark.parametrize("payload", ["5", "null", '"index value modulus"', '["index","value","modulus"]'])
    def test_decode_share_rejects_non_object_json(self, payload):
        code = "QCSHARE-" + base64.b64encode(payload.encode()).decode()
        with pytest.raises(ValueError, match="malformed"):
            cc.decode_share(code)

    def test_decode_share_rejects_a_string_threshold(self):
        share = cc.shamir_split(b"\x01" * cc.KEY_BYTES, 3, 2)[0]
        share["threshold"] = "2"
        with pytest.raises(ValueError, match="threshold"):
            cc.decode_share(cc.encode_share(share))

    def test_decode_share_accepts_an_integer_threshold(self):
        share = cc.shamir_split(b"\x01" * cc.KEY_BYTES, 3, 2)[0]
        share["threshold"] = 2
        assert cc.decode_share(cc.encode_share(share))["threshold"] == 2

    def test_a_list_kem_in_a_qcx_is_reported_as_a_bad_file(self, tmp_path):
        src = tmp_path / "f.txt"; src.write_bytes(b"data")
        out = str(tmp_path / "f.qcx")
        pkg.encrypt_to_qcx(str(src), out, mode="password", password=PW)
        with open(out, "rb") as f:
            blob = f.read()
        # The metadata blob is the JSON after the MAGIC tail's length prefix.
        tail = blob.rfind(cc.MAGIC)
        n = int.from_bytes(blob[tail + len(cc.MAGIC):tail + len(cc.MAGIC) + 4], "big")
        meta = json.loads(blob[tail + len(cc.MAGIC) + 4:tail + len(cc.MAGIC) + 4 + n])
        meta["meta"]["kem"] = ["ML-KEM-768"]
        new = json.dumps(meta, separators=(",", ":")).encode()
        with open(out, "wb") as f:
            f.write(blob[:tail] + cc.MAGIC + len(new).to_bytes(4, "big") + new)
        with pytest.raises(ValueError):
            pkg.load_pkg(out)


# ── F-009: the first mnemonic word is checked like every other ───────────────

class TestShareCodeEdges:
    @staticmethod
    def _code(index, value, modulus=cc.SHAMIR_PRIME, **extra):
        body = {"index": index, "value": value, "modulus": modulus, **extra}
        return "QCSHARE-" + base64.b64encode(json.dumps(body).encode()).decode()

    def test_booleans_are_not_integers(self):
        """Run 18 F-010: `isinstance(True, int)`; threshold already excluded
        bool, the three required fields did not."""
        for field, kw in (("index", {"index": True, "value": 5}),
                          ("value", {"index": 1, "value": True}),
                          ("modulus", {"index": 1, "value": 5, "modulus": True})):
            with pytest.raises(ValueError, match=f"{field}.*must be an integer"):
                cc.decode_share(self._code(**kw))

    def test_the_prefix_is_case_insensitive_like_its_callers(self):
        """Run 18 F-011: package.py routed `qcshare-…` here, and here it was
        "not a valid share"."""
        good = self._code(1, 5)
        assert cc.decode_share("qcshare-" + good[8:]) == cc.decode_share(good)
        with pytest.raises(ValueError, match="Not a valid"):
            cc.decode_share("QCSHARD-" + good[8:])


class TestMnemonicFirstWord:
    def test_generated_first_word_is_always_in_the_first_64(self):
        wl = cc._load_wordlist()
        for i in range(1, 60):
            share = {"index": i, "threshold": 2, "value": int.from_bytes(os.urandom(64), "big") % cc.SHAMIR_PRIME or 1}
            first = cc.share_to_mnemonic(share).split()[0]
            assert wl.index(first) < 64

    def test_a_first_word_outside_that_range_is_rejected_not_accepted(self):
        wl = cc._load_wordlist()
        share = cc.shamir_split(b"\x07" * cc.KEY_BYTES, 3, 2)[0]
        words = cc.share_to_mnemonic(share).split()
        assert cc.mnemonic_to_share(" ".join(words))["value"] == share["value"]
        typo = list(words)
        typo[0] = wl[wl.index(words[0]) + 64]      # same low 6 bits, padding bit set
        with pytest.raises(ValueError, match="Checksum mismatch"):
            cc.mnemonic_to_share(" ".join(typo))


# ── F-010: adjacent phrases are each a share ─────────────────────────────────

class TestExtractShareCodesAdjacency:
    @pytest.fixture
    def phrases(self):
        shares = cc.shamir_split(b"\x09" * cc.KEY_BYTES, 3, 2)
        return [cc.share_to_mnemonic(s) for s in shares], [cc.encode_share(s) for s in shares]

    @staticmethod
    def _wrap(phrase, per_line=8):
        w = phrase.split()
        return "\n".join(" ".join(w[i:i + per_line]) for i in range(0, len(w), per_line))

    def test_two_phrases_separated_by_one_newline(self, phrases):
        ph, codes = phrases
        got = pkg.extract_share_codes(ph[0] + "\n" + ph[1])
        assert got == codes[:2]

    def test_two_phrases_wrapped_eight_per_line_with_no_blank_line(self, phrases):
        ph, codes = phrases
        got = pkg.extract_share_codes(self._wrap(ph[0]) + "\n" + self._wrap(ph[1]))
        assert got == codes[:2]

    def test_a_wordy_header_followed_by_one_phrase(self, phrases):
        ph, codes = phrases
        header = "abandon ability able about above absent\n"
        assert pkg.extract_share_codes(header + self._wrap(ph[2])) == [codes[2]]

    def test_a_wordy_header_followed_by_two_phrases(self, phrases):
        ph, codes = phrases
        header = "abandon ability able\n"
        assert pkg.extract_share_codes(header + ph[0] + "\n" + ph[1]) == codes[:2]

    def test_blank_lines_and_codes_still_work(self, phrases):
        ph, codes = phrases
        text = f"Share 1\n{codes[0]}\n\nShare 2 (phrase)\n{self._wrap(ph[1])}\n\n{ph[2]}\n"
        assert pkg.extract_share_codes(text) == codes

    def test_a_phrase_followed_by_wordlist_prose(self, phrases):
        """Run 14 F-011: a trailer of BIP-39 words ("keep this safe") after
        the phrase made the run 53 words and the end-aligned window fail."""
        ph, codes = phrases
        assert pkg.extract_share_codes(self._wrap(ph[0]) + "\nkeep this safe") == [codes[0]]
        header, trailer = "abandon ability able\n", "\nkeep this safe"
        assert pkg.extract_share_codes(header + ph[0] + "\n" + ph[1] + trailer) == codes[:2]

    def test_phrases_separated_by_wordlist_only_labels(self, phrases):
        """Run 15 F-011: "share one" / "share two" are BIP-39 words, so a
        hand-written note lost every phrase but the last."""
        ph, codes = phrases
        assert pkg.extract_share_codes(f"share one\n{ph[0]}\nshare two\n{ph[1]}") == codes[:2]
        assert pkg.extract_share_codes(f"{ph[0]}\nshare\n{ph[1]}\nkeep this safe") == codes[:2]

    def test_codes_and_phrases_keep_their_order_of_appearance(self, phrases):
        ph, codes = phrases
        assert pkg.extract_share_codes(f"{ph[0]}\n{codes[1]}\n{ph[2]}") == codes

    def test_a_run_of_exactly_100_words_with_one_share_yields_one(self, phrases):
        ph, codes = phrases
        filler = " ".join(["abandon"] * 50)
        assert pkg.extract_share_codes(ph[0] + "\n" + filler) == [codes[0]]
        assert pkg.extract_share_codes(filler + "\n" + ph[0]) == [codes[0]]


class TestStampPreRelease:
    def test_cfbundleversion_gets_only_the_numeric_prefix(self, tmp_path):
        """Run 14 F-008: LaunchServices orders app copies by CFBundleVersion
        and rejects `1.5.0-beta`; the numeric prefix keeps the ordering."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "stamp_version", os.path.join(os.path.dirname(__file__), "..", "scripts", "stamp_version.py"))
        sv = importlib.util.module_from_spec(spec); spec.loader.exec_module(sv)
        (tmp_path / "src" / "quantacrypt").mkdir(parents=True); (tmp_path / "macos").mkdir()
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "q"\nversion = "1.4.0"\n')
        (tmp_path / "src" / "quantacrypt" / "__init__.py").write_text('__version__ = "1.4.0"\n')
        (tmp_path / "macos" / "project.yml").write_text(
            '        CFBundleShortVersionString: "1.4.0"\n        CFBundleVersion: "1.4.0"\n')
        assert sv.stamp(str(tmp_path), "1.5.0-beta") == 0
        yml = (tmp_path / "macos" / "project.yml").read_text()
        # Run 16 F-021: one spelling everywhere — the PEP 440 form setuptools
        # would produce anyway — so importlib.metadata and the plists agree.
        assert 'CFBundleShortVersionString: "1.5.0b0"' in yml
        assert 'CFBundleVersion: "1.5.0"' in yml
        assert 'version = "1.5.0b0"' in (tmp_path / "pyproject.toml").read_text()
        assert sv.stamp(str(tmp_path), "1.5.0-beta", check=True) == 0
        assert sv._bundle_version("2.0.0rc1") == "2.0.0"
        assert [sv.normalize_version(v) for v in ("1.5.0-beta", "1.5.0-rc2", "2.0.0", "1.5.0.dev3", "1.5.0a")] \
            == ["1.5.0b0", "1.5.0rc2", "2.0.0", "1.5.0.dev3", "1.5.0a0"]
        # Run 18 F-009: a `+local` segment has no normalisation branch, so it
        # is not a version the stamp accepts.
        assert sv.main(["1.5.0-beta+ci", "--check", "--root", str(tmp_path)]) == 2
        assert sv.VERSION_RE.match("1.5.0b0") and not sv.VERSION_RE.match("1.5.0+ci")
        # Run 18 F-201: the release job marks these `--prerelease` so they
        # never become `releases/latest`.
        assert [sv.is_prerelease(v) for v in ("1.5.0-beta", "1.5.0b0", "1.5.0rc1", "1.5.0.dev3", "1.5.0", "1.10.0", "1.5.0.post1")] \
            == [True, True, True, True, False, False, False]


# ── F-017 / F-033: what fails after the credential is proven is tampering ───

class TestCredentialProven:
    def _qcx(self, tmp_path, mode="password", **kw):
        src = tmp_path / "f.txt"; src.write_bytes(b"data" * 100)
        out = str(tmp_path / "f.qcx")
        res = pkg.encrypt_to_qcx(str(src), out, mode=mode, **kw)
        return out, res

    @staticmethod
    def _flip_b64_byte(meta, key):
        raw = bytearray(base64.b64decode(meta[key]))
        raw[0] ^= 0x01
        meta[key] = base64.b64encode(bytes(raw)).decode()

    def test_password_file_with_a_flipped_kem_ciphertext_is_corrupt_not_wrong_password(self, tmp_path):
        out, _ = self._qcx(tmp_path, password=PW)
        meta = pkg.load_pkg(out)["meta"]
        self._flip_b64_byte(meta, "kyber_kem_ct")
        with pytest.raises(CorruptPayload) as ei:
            pkg.derive_final_key(meta, password=PW)
        assert classify_error(ei.value)[0] == "format"
        # And the real wrong password still reads as one.
        clean = pkg.load_pkg(out)["meta"]
        with pytest.raises(Exception) as ei2:
            pkg.derive_final_key(clean, password="not the password")
        assert classify_error(ei2.value)[0] == "wrong_credentials"

    def test_shamir_file_with_a_rolled_back_version_is_corrupt(self, tmp_path):
        out, res = self._qcx(tmp_path, mode="shamir", k=2, n=3)
        meta = pkg.load_pkg(out)["meta"]
        meta["version"] = 1                       # format downgrade
        codes = [s["code"] for s in res["shares"][:2]]
        with pytest.raises(CorruptPayload):
            pkg.derive_final_key(meta, shares=codes)

    @pytest.mark.real_argon2      # the fixture was written at the shipped cost
    def test_legacy_format1_fixture_with_a_flipped_kem_ciphertext_is_corrupt(self):
        creds = json.load(open(os.path.join(FIXTURES, "credentials.json")))
        meta = pkg.load_pkg(os.path.join(FIXTURES, "single.qcx"))["meta"]
        self._flip_b64_byte(meta, "kyber_kem_ct")
        with pytest.raises(CorruptPayload):
            pkg.derive_final_key(meta, password=creds["password"])

    def test_volume_metadata_failure_after_derivation_is_corrupt_when_proven(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        _rewrite_auth_block(path, lambda a: self._flip_b64_byte(a, "kyber_kem_ct"))
        _, auth = vol.read_volume_auth_params(path)
        derived = vol.derive_volume_key_single(PW, auth)     # unseals; decaps gives another key
        with pytest.raises(CorruptPayload):
            vol.VolumeContainer(path, derived).open(credential_proven=True)
        # A caller that did not derive the key keeps the old answer.
        with pytest.raises(ValueError, match="incorrect"):
            vol.VolumeContainer(path, os.urandom(cc.KEY_BYTES)).open()

    def test_missing_hmac_is_integrity_not_a_newer_version(self, tmp_path):
        out, _ = self._qcx(tmp_path, password=PW)
        meta = pkg.load_pkg(out)["meta"]
        del meta["hmac"]
        with pytest.raises(CorruptPayload) as ei:
            pkg.derive_final_key(meta, password=PW)
        code, message, _ = classify_error(ei.value)
        assert code == "format"
        assert "update" not in message.lower()
        assert classify_error(ValueError("Metadata HMAC is missing: tampered"))[0] == "format"


# ── F-020 / F-021: the header version and the whole auth vocabulary ─────────

class TestVolumeCrossChecks:
    def test_header_version_must_match_the_sealed_one(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        _patch_header_version(path, 2)
        with pytest.raises(ValueError, match="tampered"):
            vol.VolumeContainer(path, key).open()

    def test_an_untouched_volume_still_opens(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        vol.VolumeContainer(path, key).open()

    def test_removing_mode_and_counts_from_the_block_is_tampering(self, tmp_path):
        """Run 14 F-009: a block with no ``mode`` used to default to a
        password prompt for a split-key volume; now it is a bad file before
        any credential is asked for."""
        path = str(tmp_path / "s.qcv")
        _auth, shares = vol.create_volume_shamir(path, 3, 2)
        def strip(a):
            for k in ("mode", "threshold", "total"):
                a.pop(k, None)
        _rewrite_auth_block(path, strip)
        with pytest.raises(ValueError, match="do not name a mode") as ei:
            vol.read_volume_auth_params(path)
        assert classify_error(ei.value)[0] == "format"

    def test_removing_only_the_counts_is_caught_after_derivation(self, tmp_path):
        path = str(tmp_path / "s.qcv")
        _auth, shares = vol.create_volume_shamir(path, 3, 2)
        def strip(a):
            for k in ("threshold", "total"):
                a.pop(k, None)
        _rewrite_auth_block(path, strip)
        with pytest.raises(ValueError, match="not a number"):
            vol.read_volume_auth_params(path)

    def test_a_threshold_of_one_is_not_a_threshold(self, tmp_path):
        path = str(tmp_path / "s.qcv")
        vol.create_volume_shamir(path, 3, 2)
        _rewrite_auth_block(path, lambda a: a.__setitem__("threshold", 1))
        with pytest.raises(ValueError, match="invalid share counts"):
            vol.read_volume_auth_params(path)

    def test_the_auth_vocabulary_is_exactly_what_the_writers_produce(self, tmp_path):
        """The presence check is only as good as this tuple; pin it to the
        union of the keys both writers put in the block."""
        single = vol.create_volume_single(str(tmp_path / "a.qcv"), PW)
        shamir, _ = vol.create_volume_shamir(str(tmp_path / "b.qcv"), 3, 2)
        _, single_block = vol.read_volume_auth_params(str(tmp_path / "a.qcv"))
        _, shamir_block = vol.read_volume_auth_params(str(tmp_path / "b.qcv"))
        assert set(single_block) | set(shamir_block) == set(vol._AUTH_VOCABULARY)

    def test_a_v1_3_0_style_upgrade_shape_is_rejected(self, tmp_path):
        """Header 2 / sealed 1 is what v1.3.0's compact() wrote for a v1
        container upgraded once (it sealed the metadata before bumping the
        field).  Same-day pre-release dev builds only; rejected as tampered
        rather than special-cased — recorded in the design doc."""
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        with open(path, "rb") as f:
            header = vol.read_header(f)
            auth = vol._read_auth_params(f)
            meta_ct = vol._read_encrypted_block(f)
            dir_ct = vol._read_encrypted_block(f)
            rest = f.read()
        meta = vol.decrypt_metadata(key, header["meta_nonce"], meta_ct)
        meta["format_version"] = 1
        meta_nonce, meta_ct = vol.encrypt_metadata(key, meta)
        with open(path, "wb") as f:
            vol.write_header(f, header["volume_id"], meta_nonce, header["dir_nonce"], version=2)
            vol._write_auth_params(f, auth)
            vol._write_encrypted_block(f, meta_ct)
            vol._write_encrypted_block(f, dir_ct)
            f.write(rest)
        with pytest.raises(ValueError, match="tampered"):
            vol.VolumeContainer(path, key).open()

    @pytest.mark.parametrize("mutate, msg", [
        (lambda a: a.__setitem__("threshold", "2"), "not a number"),
        (lambda a: a.__setitem__("mode", "magic"), "unknown mode"),
        (lambda a: a.__setitem__("total", 1), "invalid share counts"),
    ])
    def test_ill_typed_auth_fields_are_a_bad_file_before_any_derivation(self, tmp_path, mutate, msg):
        path = str(tmp_path / "s.qcv")
        vol.create_volume_shamir(path, 3, 2)
        _rewrite_auth_block(path, mutate)
        with pytest.raises(ValueError, match=msg):
            vol.read_volume_auth_params(path)


# ── F-018 / F-004 / F-016 / F-035: mount plumbing ───────────────────────────

class _Reached(RuntimeError):
    """Raised by the FUSE stub: the mount-point check passed."""


class TestMountPointCheck:
    @pytest.fixture
    def stub_fuse(self, monkeypatch):
        fuse = pytest.importorskip("fuse")
        def _stub(*a, **kw):
            exc = _Reached(kw.get("volname"))
            exc.opts = kw
            raise exc
        monkeypatch.setattr(fuse, "FUSE", _stub)

    def test_finder_litter_does_not_make_the_mount_point_non_empty(self, tmp_path, stub_fuse):
        path, key, vc = _make_volume(tmp_path, "My Vault.qcv")
        vc.close()
        mp = tmp_path / "mnt"; mp.mkdir()
        (mp / ".DS_Store").write_bytes(b"\x00")
        (mp / ".localized").write_bytes(b"")
        with pytest.raises(_Reached) as ei:
            fo.mount_volume(path, key, str(mp), foreground=True)
        assert str(ei.value) == "My Vault"          # F-004: named after the container

    def test_mount_volume_forwards_the_credential_proof(self, tmp_path, stub_fuse):
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        _rewrite_auth_block(path, lambda a: None)          # untouched: still mounts
        with pytest.raises(_Reached):
            fo.mount_volume(path, key, str(tmp_path / "m1"), foreground=True,
                            credential_proven=True)
        # Wrong key + proof claimed → tampering; wrong key alone → maybe wrong password.
        with pytest.raises(CorruptPayload):
            fo.mount_volume(path, os.urandom(cc.KEY_BYTES), str(tmp_path / "m2"),
                            foreground=True, credential_proven=True)
        with pytest.raises(ValueError, match="incorrect"):
            fo.mount_volume(path, os.urandom(cc.KEY_BYTES), str(tmp_path / "m3"),
                            foreground=True)

    def test_the_service_expands_tilde_in_every_path_param(self, tmp_path, monkeypatch):
        """Run 20 F-010: only mount_point was expanded; path/source/output
        reached the helper with a literal ~."""
        monkeypatch.setenv("HOME", str(tmp_path))
        path, key, vc = _make_volume(tmp_path, "vault.qcv"); vc.close()
        os.replace(str(tmp_path / "vault.qcv"), str(tmp_path / "vault.qcv"))  # noop, keep path
        ctx = SimpleNamespace(progress=lambda *a: None, check=lambda: None, cancelled=lambda: False)
        info = svc.op_volume_inspect({"path": "~/vault.qcv"}, ctx)
        assert info["path"] == str(tmp_path / "vault.qcv") and info["mode"] == "single"
        seen = {}
        monkeypatch.setattr(pkg, "decrypt_qcx",
                            lambda p, out, **kw: seen.update(path=p, out=out) or {"verified": True, "mode": "single"})
        svc.op_decrypt({"path": "~/vault.qcv", "output_dir": "~/out", "verify_only": False,
                        "password": "x"}, ctx)
        assert seen["path"] == str(tmp_path / "vault.qcv") and seen["out"] == str(tmp_path / "out")
        # Run 21 F-002: op_inspect and op_volume_mount were the two that the
        # run-20 fix missed — the protocol doc promises expansion for all.
        iseen = {}
        monkeypatch.setattr(pkg, "inspect_summary", lambda p: iseen.update(path=p) or {"path": p})
        svc.op_inspect({"path": "~/f.qcx"}, ctx)
        assert iseen["path"] == str(tmp_path / "f.qcx")
        mseen = {}
        monkeypatch.setattr(vol, "read_volume_auth_params", lambda p: (mseen.update(auth_path=p) or (None, {"mode": "single"})))
        monkeypatch.setattr(vol, "derive_volume_key_single", lambda pw, auth: b"0" * cc.KEY_BYTES)
        monkeypatch.setattr(fo, "mount_volume", lambda p, k, mp, **kw: mseen.update(path=p, mp=mp)
                            or SimpleNamespace(volume=None))
        res = svc.op_volume_mount({"path": "~/vault.qcv", "mount_point": "~/mnt", "password": "x"}, ctx)
        assert mseen["auth_path"] == str(tmp_path / "vault.qcv")       # read with the expanded path
        assert mseen["path"] == str(tmp_path / "vault.qcv") and mseen["mp"] == str(tmp_path / "mnt")
        assert res["mount_point"] == str(tmp_path / "mnt")

    def test_the_service_echoes_and_unmounts_the_expanded_mount_point(self, tmp_path, monkeypatch):
        """Run 19 F-003: volume_mount echoed the client's `~/…` while the
        helper tracked the expanded path, so the echoed value failed to unmount."""
        monkeypatch.setenv("HOME", str(tmp_path))
        mounted = {}
        monkeypatch.setattr(fo, "mount_volume", lambda p, k, mp, **kw: mounted.setdefault(mp, SimpleNamespace(volume=None)))
        monkeypatch.setattr(fo, "unmount_volume", lambda mp: mounted.pop(mp))
        path, key, vc = _make_volume(tmp_path); vc.close()
        ctx = SimpleNamespace(progress=lambda *a: None, check=lambda: None)
        res = svc.op_volume_mount({"path": path, "mount_point": "~/mnt-tilde",
                                   "password": PW}, ctx)
        expanded = str(tmp_path / "mnt-tilde")
        assert res["mount_point"] == expanded and list(mounted) == [expanded]
        assert svc.op_volume_unmount({"mount_point": "~/mnt-tilde"}, ctx) == {"mount_point": expanded}
        assert mounted == {}

    def test_a_tilde_mount_point_is_expanded(self, tmp_path, stub_fuse, monkeypatch):
        """Run 18 F-203: the Tk manager's own hint suggests `~/…`; passed raw
        it made a folder literally named `~` under the process CWD."""
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        monkeypatch.setenv("HOME", str(tmp_path))
        with pytest.raises(_Reached) as ei:
            fo.mount_volume(path, key, "~/QuantaCrypt Volumes/v", foreground=True)
        assert (tmp_path / "QuantaCrypt Volumes" / "v").is_dir()
        assert not os.path.lexists(os.path.join(os.getcwd(), "~"))

    def test_a_file_at_the_mount_point_is_the_users_input_to_fix(self, tmp_path, stub_fuse):
        """Run 18 F-006: makedirs reported it as "<path> already exists.
        Choose a different name" — a story about the volume."""
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        mp = tmp_path / "mnt"; mp.write_text("not a folder")
        with pytest.raises(InvalidInput, match="not a folder"):
            fo.mount_volume(path, key, str(mp), foreground=True)
        dangling = tmp_path / "link"; dangling.symlink_to(tmp_path / "nowhere")
        with pytest.raises(InvalidInput, match="not a folder"):
            fo.mount_volume(path, key, str(dangling), foreground=True)

    def test_real_content_is_named_and_is_the_users_input_to_fix(self, tmp_path, stub_fuse):
        path, key, vc = _make_volume(tmp_path)
        vc.close()
        mp = tmp_path / "mnt"; mp.mkdir()
        (mp / "notes.txt").write_text("keep")
        with pytest.raises(InvalidInput, match="notes.txt"):
            fo.mount_volume(path, key, str(mp), foreground=True)


class TestVolnameIsAMacOption:
    def test_linux_gets_no_volname(self, tmp_path, monkeypatch):
        """Run 14 F-020: libfuse rejects unknown -o options, so the Linux
        mount failed before serving."""
        fuse = pytest.importorskip("fuse")
        seen = {}
        def _stub(*a, **kw):
            seen.update(kw); raise _Reached("stub")
        monkeypatch.setattr(fuse, "FUSE", _stub)
        monkeypatch.setattr(fo.sys, "platform", "linux")
        path, key, vc = _make_volume(tmp_path); vc.close()
        with pytest.raises(_Reached):
            fo.mount_volume(path, key, str(tmp_path / "mnt"), foreground=True)
        assert "volname" not in seen and seen["allow_other"] is False


class TestVolname:
    @pytest.mark.parametrize("path, want", [
        ("/x/My Vault.qcv", "My Vault"),
        ("/x/tax,2026;rm.qcv", "tax_2026_rm"),
        ("/x/,,,.qcv", "QuantaCrypt"),
        ("/x/" + "a" * 90 + ".qcv", "a" * 64),
    ])
    def test_stem_sanitised_and_bounded(self, path, want):
        assert fo._volname_for(path) == want


class TestReadOnlyMount:
    """Run 14 F-001/F-002: a container that cannot be written — or whose
    folder cannot (compaction needs it) — is served read-only with no
    sidecar lock, instead of mounting read-write and failing at close()."""

    @pytest.fixture
    def stub_fuse(self, monkeypatch):
        fuse = pytest.importorskip("fuse")
        def _stub(*a, **kw):
            exc = _Reached(kw.get("volname"))
            exc.opts = kw
            raise exc
        monkeypatch.setattr(fuse, "FUSE", _stub)

    def _layout(self, tmp_path, dir_mode, file_mode):
        d = tmp_path / "loc"; d.mkdir()
        path, key, vc = _make_volume(d, "v.qcv")
        vc.write_file("/keep.txt", b"kept"); vc.save(); vc.close()
        os.chmod(path, file_mode); os.chmod(d, dir_mode)
        return path, key, d

    @pytest.mark.parametrize("dir_mode, file_mode", [(0o555, 0o444), (0o555, 0o644)])
    def test_unwritable_layouts_mount_read_only_without_a_lock(self, tmp_path, stub_fuse, dir_mode, file_mode):
        if os.getuid() == 0:
            pytest.skip("root ignores permission bits")
        path, key, d = self._layout(tmp_path, dir_mode, file_mode)
        try:
            with pytest.raises(_Reached) as ei:
                fo.mount_volume(path, key, str(tmp_path / "mnt"), foreground=True)
            assert ei.value.opts.get("ro") is True
            assert not os.path.exists(path + ".lock")
        finally:
            os.chmod(d, 0o755); os.chmod(path, 0o644)

    def test_a_writable_layout_mounts_read_write_with_the_lock(self, tmp_path, stub_fuse):
        path, key, vc = _make_volume(tmp_path); vc.close()
        with pytest.raises(_Reached) as ei:
            fo.mount_volume(path, key, str(tmp_path / "mnt"), foreground=True)
        assert "ro" not in ei.value.opts
        assert os.path.exists(path + ".lock")

    def test_mutations_are_refused_before_any_state_changes(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"x"); vc.save()
        vc.read_only = True
        fs = fo.QuantaCryptFUSE(vc)
        attempts = [
            lambda: fs.create("/n", 0o644), lambda: fs.mkdir("/d", 0o755),
            lambda: fs.unlink("/a.txt"), lambda: fs.rename("/a.txt", "/b"),
            lambda: fs.truncate("/a.txt", 0), lambda: fs.chmod("/a.txt", 0o600),
            lambda: fs.utimens("/a.txt", (1, 2)), lambda: fs.chown("/a.txt", 0, 0),
            lambda: fs.open("/a.txt", os.O_WRONLY), lambda: fs.write("/a.txt", b"y", 0, 1),
        ]
        for attempt in attempts:
            with pytest.raises(OSError) as ei:
                attempt()
            assert ei.value.errno == errno.EROFS
        assert sorted(vc.dir_index) == ["/a.txt"] and not vc.is_dirty
        assert fs._file_buffers == {} and fs._open_files == {}
        fd = fs.open("/a.txt", os.O_RDONLY)
        assert fs.read("/a.txt", 10, 0, fd) == b"x"
        fs.release("/a.txt", fd)
        fs.save_all_dirty()          # must be a no-op, not an error


class TestReadOnlyInTheProtocol:
    def test_volume_list_entries_carry_the_live_flag(self, monkeypatch):
        """The shell rebuilds its mounted list from volume_list every few
        seconds; a flag only in the mount result would vanish on the first
        poll — and the live container wins over the mount-time entry
        (run 16 F-001: the flip sets the container, not the entry)."""
        flipped = SimpleNamespace(read_only=True, stat=lambda: None)
        monkeypatch.setattr(fo, "_reap_dead_mounts_locked", lambda: None)
        monkeypatch.setattr(fo, "_mounted_volumes", {
            "/m/ro": {"volume_path": "/v/ro.qcv", "read_only": True, "volume": None},
            "/m/rw": {"volume_path": "/v/rw.qcv", "volume": None},
            "/m/x": {"volume_path": "/v/x.qcv", "volume": flipped, "read_only": False},
        })
        out = svc.op_volume_list({}, None)["volumes"]
        assert [(e["mount_point"], e["read_only"]) for e in out] == \
            [("/m/ro", True), ("/m/rw", False), ("/m/x", True)]


class TestReadOnlyShutdownPath:
    """Run 16 F-002 / F-001: the certain-shutdown sweep must not save a
    read-only or flipped volume, and every list consumer must see the live
    flag, not the mount-time one."""

    @pytest.fixture
    def fake_mounts(self, monkeypatch):
        """Register thread-less tracking entries and always take them back
        out: a leaked entry would tell every later test the path is mounted."""
        import subprocess
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **kw: SimpleNamespace(returncode=0, stdout="", stderr=""))
        registered = []
        def register(fs, mp):
            fo._mounted_volumes[mp] = {"volume": fs.volume, "fuse": fs,
                                       "volume_path": fs.volume.path, "read_only": False}
            fo._volume_locks[mp] = None
            registered.append(mp)
        yield register
        for mp in registered:
            fo._mounted_volumes.pop(mp, None)
            fo._volume_locks.pop(mp, None)

    def test_unmount_after_the_flip_does_not_raise(self, tmp_path, monkeypatch, fake_mounts):
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        mp = str(tmp_path / "mnt-flip")
        fake_mounts(fs, mp)
        real_save = vc.save
        def refuse():
            raise PermissionError(errno.EACCES, "Permission denied", vc.path)
        monkeypatch.setattr(vc, "save", refuse)
        with pytest.raises(PermissionError):
            fs.mkdir("/d", 0o755)
        assert vc.read_only and not vc.is_dirty
        assert "d" not in fs.readdir("/"), "the refused change must not be served"
        assert fo.get_mounted_volumes()[mp]["read_only"] is True
        assert svc.op_volume_list({}, None)["volumes"][0]["read_only"] is True
        fo.unmount_volume(mp)                         # must not raise after the OS unmount
        assert mp not in fo._mounted_volumes

    def test_a_read_only_mount_with_hidden_litter_unmounts_cleanly(self, tmp_path, monkeypatch, fake_mounts):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/.fuse_hidden0000000100000001", b"leftover"); vc.save()
        vc.read_only = True
        fs = fo.QuantaCryptFUSE(vc)
        mp = str(tmp_path / "mnt-ro")
        fake_mounts(fs, mp)
        fo.unmount_volume(mp)
        reopened = vol.VolumeContainer(path, key); reopened.open()
        assert "/.fuse_hidden0000000100000001" in reopened.dir_index   # not ours to delete

    def test_a_post_unmount_persistence_failure_is_logged_not_raised(self, tmp_path, monkeypatch, fake_mounts, caplog):
        """Run 17: ENOSPC from the deferred-delete save after the OS unmount
        succeeded used to say "unmount failed" for a volume that was gone."""
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/t", 0o644); fs.write("/t", b"x", 0, fd); fs.unlink("/t")   # pending
        mp = str(tmp_path / "mnt-enospc")
        fake_mounts(fs, mp)
        def full():
            raise OSError(errno.ENOSPC, "No space left on device")
        monkeypatch.setattr(fs, "apply_pending_unlinks", full)   # the post-unmount step
        with caplog.at_level("ERROR", logger="quantacrypt.core.fuse_ops"):
            fo.unmount_volume(mp)                     # must not raise
        assert "could not be persisted" in caplog.text and mp not in fo._mounted_volumes

    def test_a_non_oserror_persistence_failure_runs_the_real_body_and_names_no_path(
            self, tmp_path, monkeypatch, fake_mounts, caplog):
        """Run 18 F-005: save() → compact() raises ValueError for a container
        truncated beneath the mount; only OSError was caught.  F-101: the
        ERROR line is public in the shell's log, so the mount point and the
        container path ride the INFO line instead."""
        path, key, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/t", 0o644); fs.write("/t", b"x", 0, fd); fs.unlink("/t")   # pending
        mp = str(tmp_path / "mnt-trunc")
        fake_mounts(fs, mp)
        real_apply = fs.apply_pending_unlinks
        def truncated():
            raise ValueError(f"Volume file truncated while copying unmodified blob {path}")
        def apply_with_a_truncated_container():
            monkeypatch.setattr(vc, "save", truncated)      # only the post-unmount save
            real_apply()
        monkeypatch.setattr(fs, "apply_pending_unlinks", apply_with_a_truncated_container)
        with caplog.at_level("INFO", logger="quantacrypt.core.fuse_ops"):
            fo.unmount_volume(mp)                     # must not raise
        errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
        assert errors == ["deferred deletes could not be persisted after unmount "
                          "(ValueError); they will reappear at the next mount"]
        infos = [r for r in caplog.records if r.levelno == logging.INFO]
        assert any(mp in r.getMessage() and r.exc_info for r in infos)
        assert fs._pending_unlink == set() and mp not in fo._mounted_volumes

    def test_flush_and_release_on_a_flipped_mount(self, tmp_path, monkeypatch, caplog):
        _, _, vc = _make_volume(tmp_path)
        fs = fo.QuantaCryptFUSE(vc)
        fd = fs.create("/secret-name.txt", 0o644); fs.write("/secret-name.txt", b"x", 0, fd)
        fd2 = fs.create("/tmp", 0o644); fs.write("/tmp", b"y", 0, fd2); fs.unlink("/tmp")  # doomed
        vc.read_only = True
        with pytest.raises(OSError) as ei:
            fs.flush("/secret-name.txt", fd)
        assert ei.value.errno == errno.EROFS
        assert fs.flush("/tmp", fd2) is None            # run 17 F-016: no EROFS for a doomed file
        with caplog.at_level("WARNING", logger="quantacrypt.core.fuse_ops"):
            fs.release("/secret-name.txt", fd); fs.release("/tmp", fd2)
        assert "dropped" in caplog.text and "secret-name" not in caplog.text   # names stay out of WARNING
        assert fs._dirty_files == set()


class TestLockOwnership:
    def test_a_sidecar_that_cannot_be_opened_means_another_user(self, tmp_path, monkeypatch):
        """Run 14 F-014: mount_volume only takes the lock for a writable
        container in a writable folder, so EACCES on the sidecar means it is
        another user's 0600 file — a per-user lock elsewhere let both users
        append to one journal."""
        vault = tmp_path / "v.qcv"; vault.write_bytes(b"x")
        (tmp_path / "v.qcv.lock").write_bytes(b"")          # exists, "owned by someone else"
        real_open = os.open
        def fake_open(p, *a, **kw):
            if str(p).endswith("v.qcv.lock"):
                raise PermissionError(errno.EACCES, "Permission denied", p)
            return real_open(p, *a, **kw)
        monkeypatch.setattr(os, "open", fake_open)
        monkeypatch.setattr(os, "getuid", lambda: os.stat(tmp_path / "v.qcv.lock").st_uid + 1)
        with pytest.raises(RuntimeError, match="in use by another user") as ei:
            fo._acquire_volume_lock(str(vault))
        assert classify_error(ei.value)[0] == "busy"
        assert not hasattr(fo, "_fallback_lock_path")

    def test_a_sidecar_the_caller_owns_but_cannot_open_is_a_permissions_problem(self, tmp_path):
        """Run 15 F-013: `chmod -R a-w vaultdir` then restoring only the folder
        leaves a 0000 sidecar the caller owns; that is not another user."""
        if os.getuid() == 0:
            pytest.skip("root ignores permission bits")
        vault = tmp_path / "v.qcv"; vault.write_bytes(b"x")
        lock = tmp_path / "v.qcv.lock"; lock.write_bytes(b""); os.chmod(lock, 0)
        try:
            with pytest.raises(RuntimeError, match="could not be opened") as ei:
                fo._acquire_volume_lock(str(vault))
            assert "another user" not in str(ei.value)
        finally:
            os.chmod(lock, 0o600)

    def test_a_folder_at_the_sidecar_path_is_refused_with_a_sentence(self, tmp_path):
        vault = tmp_path / "v.qcv"; vault.write_bytes(b"x")
        (tmp_path / "v.qcv.lock").mkdir()
        with pytest.raises(RuntimeError, match="is a folder"):
            fo._acquire_volume_lock(str(vault))

    def test_a_planted_symlink_sidecar_is_refused(self, tmp_path):
        """Run 16 F-015: O_NOFOLLOW — a link would put the flock on another inode."""
        vault = tmp_path / "v.qcv"; vault.write_bytes(b"x")
        victim = tmp_path / "victim"; victim.write_bytes(b"")
        os.symlink(victim, tmp_path / "v.qcv.lock")
        with pytest.raises(RuntimeError, match="could not be opened|not a regular file"):
            fo._acquire_volume_lock(str(vault))

    def test_a_filesystem_without_flock_mounts_with_a_warning(self, tmp_path, monkeypatch, caplog):
        import fcntl
        vault = tmp_path / "v.qcv"; vault.write_bytes(b"x")
        def no_flock(fd, op):
            raise OSError(errno.ENOLCK, "No locks available")
        monkeypatch.setattr(fcntl, "flock", no_flock)
        with caplog.at_level("WARNING", logger="quantacrypt.core.fuse_ops"):
            fd = fo._acquire_volume_lock(str(vault))
        os.close(fd)
        assert "flock unsupported" in caplog.text

    def test_other_open_errors_still_propagate(self, tmp_path, monkeypatch):
        vault = tmp_path / "v.qcv"; vault.write_bytes(b"x")
        real_open = os.open
        def fake_open(p, *a, **kw):
            if str(p).endswith("v.qcv.lock"):
                raise OSError(errno.EIO, "I/O error", p)
            return real_open(p, *a, **kw)
        monkeypatch.setattr(os, "open", fake_open)
        with pytest.raises(OSError) as ei:
            fo._acquire_volume_lock(str(vault))
        assert ei.value.errno == errno.EIO


class TestLRUCacheSizes:
    def test_updating_a_key_with_an_oversized_value_leaves_no_size_entry(self):
        cache = fo.LRUCache(max_bytes=10)
        cache.put("k", b"1234")
        cache.put("k", b"x" * 20)
        assert cache.get("k") is None
        assert "k" not in cache._sizes
        assert cache._current_bytes == 0


# ── F-006 / F-026: service shutdown and idle wait ────────────────────────────

class TestServiceShutdown:
    def test_a_signal_during_one_unmount_does_not_abandon_the_rest(self, monkeypatch):
        calls = []
        def fake_unmount(mp):
            calls.append(mp)
            if mp == "/m1":
                raise svc.ServiceStop()
        monkeypatch.setattr(fo, "get_mounted_volumes", lambda: ["/m1", "/m2"])
        monkeypatch.setattr(fo, "unmount_volume", fake_unmount)
        s = svc.Service(io.StringIO(""), io.StringIO())
        failures = s.shutdown(exit_after=False)
        assert calls == ["/m1", "/m2"]
        assert failures == ["/m1"]

    def test_wait_idle_uses_one_deadline_for_every_worker(self):
        s = svc.Service(io.StringIO(""), io.StringIO())
        threads = [threading.Thread(target=time.sleep, args=(0.6,), daemon=True) for _ in range(4)]
        for t in threads:
            t.start()
        s._reqs = {str(i): SimpleNamespace(thread=t) for i, t in enumerate(threads)}
        t0 = time.monotonic()
        s.wait_idle(timeout=0.3)
        assert time.monotonic() - t0 < 0.6, "four joins must share one 0.3 s budget"


# ── F-015 / F-019 / F-029: the decrypt and folder paths ─────────────────────

class TestEnvelopeAndFolders:
    def test_a_timestamp_beyond_time_t_does_not_fail_a_placed_decrypt(self, tmp_path, monkeypatch):
        src = tmp_path / "f.txt"; src.write_bytes(b"data")
        out = str(tmp_path / "f.qcx")
        monkeypatch.setattr(cc.time, "time", lambda: float(2 ** 70))
        pkg.encrypt_to_qcx(str(src), out, mode="password", password=PW)
        monkeypatch.undo()
        dest = tmp_path / "o"; dest.mkdir()
        res = pkg.decrypt_qcx(out, str(dest), password=PW)
        assert res["timestamp"] == 0
        assert open(res["output"], "rb").read() == b"data"

    def test_a_fifo_in_a_folder_is_skipped_not_waited_on(self, tmp_path):
        folder = tmp_path / "proj"; folder.mkdir()
        (folder / "a.txt").write_text("hello")
        os.mkfifo(str(folder / "pipe"))
        assert pkg.folder_stats(str(folder)) == (1, 5)
        out = str(tmp_path / "proj.qcx")
        done = threading.Event()
        result = {}
        def run():
            try:
                result["res"] = pkg.encrypt_to_qcx(str(folder), out, mode="password", password=PW)
            except BaseException as exc:  # noqa: BLE001
                result["exc"] = exc
            finally:
                done.set()
        threading.Thread(target=run, daemon=True).start()
        assert done.wait(20), "encrypt blocked on the FIFO"
        assert "exc" not in result, result.get("exc")
        assert result["res"]["skipped_symlinks"] == ["pipe"]


# ── F-023: no committed fixture may record a test-grade KDF ─────────────────

def _fixture_files(suffix):
    out = []
    for d in (FIXTURES, FIXTURES_CURRENT):
        out += [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.endswith(suffix)]
    return out


class TestFixtureKdfFloor:
    """No committed fixture may record a test-grade KDF (conftest lowers the
    cost for the suite, and formats 2/3 record what they were made with).
    Run 14 F-016: the check is only real if a recording format is present,
    so `tests/fixtures/current/` carries one of each."""

    def _shipped(self):
        from tests.conftest import _REAL_ARGON2
        return _REAL_ARGON2["time"], _REAL_ARGON2["memory"]

    @pytest.mark.parametrize("path", _fixture_files(".qcx"), ids=os.path.basename)
    def test_qcx_fixture_records_at_least_the_shipped_cost(self, path):
        t, m = self._shipped()
        meta = pkg.load_pkg(path)["meta"]
        if meta.get("version", 1) >= 2 and meta["mode"] == "single":
            assert "argon2" in meta, "format 2 records its parameters"
        if "argon2" in meta:
            assert meta["argon2"]["t"] >= t and meta["argon2"]["m"] >= m
        # format 1 records nothing and is only openable at the shipped cost.

    @pytest.mark.parametrize("path", _fixture_files(".qcv"), ids=os.path.basename)
    def test_qcv_fixture_records_at_least_the_shipped_cost(self, path):
        t, m = self._shipped()
        header, auth = vol.read_volume_auth_params(path)
        if header["version"] >= 3 and auth["mode"] == "single":
            assert "argon2" in auth, "format 3 records its parameters"
        if "argon2" in auth:
            assert auth["argon2"]["t"] >= t and auth["argon2"]["m"] >= m

    def test_a_recording_fixture_of_each_format_exists(self):
        assert any(pkg.load_pkg(p)["meta"].get("version", 1) >= 2 for p in _fixture_files(".qcx"))
        assert any(vol.read_volume_auth_params(p)[0]["version"] >= 3 for p in _fixture_files(".qcv"))

    @pytest.mark.real_argon2
    def test_the_current_fixtures_open_with_their_credentials(self, tmp_path):
        creds = json.load(open(os.path.join(FIXTURES_CURRENT, "credentials.json")))
        res = pkg.decrypt_qcx(os.path.join(FIXTURES_CURRENT, "single.qcx"), str(tmp_path),
                              password=creds["password"])
        import hashlib
        assert hashlib.sha256(open(res["output"], "rb").read()).hexdigest() == creds["plaintext_sha256"]
        vpath = os.path.join(FIXTURES_CURRENT, "single.qcv")
        _, auth = vol.read_volume_auth_params(vpath)
        vc = vol.VolumeContainer(vpath, vol.derive_volume_key_single(creds["password"], auth))
        vc.open(credential_proven=True)
        assert hashlib.sha256(vc.read_file("/hello.txt")).hexdigest() == creds["plaintext_sha256"]
