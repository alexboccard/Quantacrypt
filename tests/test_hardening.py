"""Behavioural tests for the review-11 hardening batch.

One class per finding from `.review/FINAL.md`. These assert what the fix
guarantees, not how it is written — the review flagged source-text
assertions as the codebase's weakest testing pattern, so none appear here.
"""

import ctypes
import os
import stat
import subprocess
import sys
import threading
import time

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from quantacrypt.core import volume as vol
from quantacrypt.core.errors import InvalidInput
from quantacrypt.core.fuse_ops import QuantaCryptFUSE, _emergency_save_all, _mounted_volumes

PW = "correct horse battery"


@pytest.fixture
def trace(monkeypatch):
    """Record every os.fsync / os.replace as (kind, detail), in order.

    The durability fix is an ordering between two syscalls, so the ordering
    is what has to be observed — a helper that returns without raising says
    nothing about whether anything was flushed.
    """
    real_fsync, real_replace = os.fsync, os.replace
    calls = []

    def traced_fsync(fd):
        kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
        calls.append(("fsync", kind))
        return real_fsync(fd)

    def traced_replace(src, dst, **kw):
        calls.append(("replace", os.fspath(dst)))
        return real_replace(src, dst, **kw)

    monkeypatch.setattr(os, "fsync", traced_fsync)
    monkeypatch.setattr(os, "replace", traced_replace)
    return calls


def _make_volume(tmp_path, name="v.qcv", password=PW):
    path = str(tmp_path / name)
    meta = vol.create_volume_single(path, password)
    key = vol.derive_volume_key_single(password, meta)
    vc = vol.VolumeContainer(path, key)
    vc.open()
    return path, key, vc


# ── F-020: the password floor lives in the core ─────────────────────────────

class TestPasswordFloor:
    """Both front ends pass through these two entry points, and the Tk batch
    path used to reach neither a floor nor a warning."""

    @pytest.mark.parametrize("password", ["", "a", "short7"])
    def test_volume_creation_refuses_short_passwords(self, tmp_path, password):
        with pytest.raises(ValueError, match="at least 8|cannot be empty"):
            vol.create_volume_single(str(tmp_path / "x.qcv"), password)
        assert not os.path.exists(tmp_path / "x.qcv")

    @pytest.mark.parametrize("password", ["a", "short7"])
    def test_qcx_encryption_refuses_short_passwords(self, tmp_path, password):
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        with pytest.raises(InvalidInput, match="at least 8"):
            pkg.encrypt_to_qcx(str(src), str(tmp_path / "f.qcx"),
                               mode="password", password=password)
        assert not os.path.exists(tmp_path / "f.qcx")

    def test_exactly_the_minimum_is_accepted(self, tmp_path):
        assert len("12345678") == cc.MIN_PASSWORD_LENGTH
        vol.create_volume_single(str(tmp_path / "ok.qcv"), "12345678")
        assert os.path.exists(tmp_path / "ok.qcv")

    def test_unlocking_is_not_subject_to_the_floor(self, tmp_path):
        """The floor guards creation only. Enforcing it on unlock would lock
        users out of volumes created before it existed — so a short candidate
        must derive a (wrong) key rather than raise."""
        from cryptography.exceptions import InvalidTag
        path, _, vc = _make_volume(tmp_path)
        _, auth = vol.read_volume_auth_params(path)
        # Fails as a wrong password (the wrapped Kyber key will not
        # authenticate), never as a policy violation.
        with pytest.raises(InvalidTag):
            vol.derive_volume_key_single("tiny", auth)


# ── F-008: chmod/utimens survive an unmount ─────────────────────────────────

class TestAttributesPersist:
    """utimens is what cp -p, rsync -t, unzip, tar -x and Finder issue after
    writing, so dropping it re-stamped every copied file with its copy time."""

    def test_mode_and_mtime_survive_save_and_reopen(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()

        fs = QuantaCryptFUSE(vc)
        fs.chmod("/a.txt", 0o100755)
        fs.utimens("/a.txt", (1_000_000, 1_234_567))
        # Run 13 (F-013): attribute ops persist at once like every other
        # mutation, so nothing is left dirty for a later save to carry.
        assert not vc.is_dirty

        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        entry = reopened.get_entry("/a.txt")
        assert entry["mode"] == 0o100755
        assert entry["mtime"] == 1_234_567

    def test_write_preserves_a_mode_set_earlier(self, tmp_path):
        """chmod +x followed by any write used to silently drop the bit."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/s.sh", b"#!/bin/sh\n")
        vc.set_attrs("/s.sh", mode=0o100755)
        vc.write_file("/s.sh", b"#!/bin/sh\necho hi\n")
        assert vc.get_entry("/s.sh")["mode"] == 0o100755

    def test_set_attrs_reports_unknown_paths(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        assert vc.set_attrs("/nope.txt", mode=0o100644) is False

    def test_no_op_change_does_not_dirty_the_volume(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"x")
        vc.save()
        assert not vc.is_dirty
        assert vc.set_attrs("/a.txt") is True
        assert not vc.is_dirty

    def test_fuse_reports_enoent_for_a_missing_path(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        with pytest.raises(OSError):
            fs.chmod("/ghost", 0o100644)
        with pytest.raises(OSError):
            fs.utimens("/ghost")


# ── F-009: the suspicious journal tail is preserved ─────────────────────────

class TestSuspiciousTailPreserved:
    """A complete journal record that fails authentication is the tamper /
    rollback shape. The next save truncates it away, so it has to be copied
    out at the only moment it is guaranteed to still exist."""

    #: Appended past the journal end. The first 12 bytes read as a nonce and
    #: the next 4 as a big-endian record length of 0 — fully present, and
    #: below _JOURNAL_MIN_HEADER_CT, which is the "garbage where a header
    #: should be" branch rather than the crash-truncated one. Deterministic:
    #: no key, no timing and no filesystem behaviour is involved.
    TAIL = b"\x00" * 64 + b"tampered-tail-bytes" + b"\xff" * 64

    def _corrupt_tail(self, path):
        with open(path, "r+b") as f:
            f.seek(0, os.SEEK_END)
            f.write(self.TAIL)

    def _reopen_corrupted(self, path, key):
        """Reopen and assert the tail was classified as tampering.

        This used to be `if not journal_suspicious: pytest.skip(...)`, which
        meant the day a change to _read_journal_records's heuristics stopped
        classifying these bytes, both sidecar tests would skip silently and
        the fix would be untested on a green run. The classification is
        itself the property worth pinning, so assert it.
        """
        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        assert reopened.journal_suspicious, (
            "an appended, fully-present, unauthenticated record must read as "
            "tampering, not as a crash-truncated tail")
        return reopened

    def test_tail_is_copied_to_a_sidecar(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()
        self._corrupt_tail(path)

        reopened = self._reopen_corrupted(path, key)
        sidecar = reopened.suspect_sidecar
        assert sidecar and os.path.exists(sidecar)
        assert b"tampered-tail-bytes" in open(sidecar, "rb").read()
        # Key material never lands here, but the sidecar still describes a
        # container the user cares about.
        assert oct(os.stat(sidecar).st_mode)[-3:] == "600"

    def test_sidecar_survives_the_save_that_truncates_the_tail(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()
        self._corrupt_tail(path)

        reopened = self._reopen_corrupted(path, key)
        sidecar = reopened.suspect_sidecar

        # The write macOS would do within seconds of mounting.
        reopened.write_file("/.DS_Store", b"junk")
        reopened.save()

        assert b"tampered-tail-bytes" not in open(path, "rb").read(), \
            "the tail should be gone from the container"
        assert b"tampered-tail-bytes" in open(sidecar, "rb").read(), \
            "but preserved in the sidecar"

    def test_a_crash_truncated_tail_is_not_flagged(self, tmp_path):
        """The negative control for the assertion above: a record that simply
        runs out of bytes at EOF is what a crash leaves behind, and calling
        that tampering would cry wolf on every unclean shutdown."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()
        vc.write_file("/b.txt", b"more")
        vc.save()
        with open(path, "r+b") as f:
            f.truncate(os.path.getsize(path) - 32)

        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        # Really a partial record, not a clean cut: replay stopped short of
        # EOF and dropped the second file.
        assert reopened._file_size > reopened._journal_end
        assert sorted(reopened.dir_index) == ["/a.txt"]
        assert reopened.journal_suspicious is False
        assert reopened.suspect_sidecar is None

    def test_a_clean_volume_gets_no_sidecar(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()
        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        assert reopened.journal_suspicious is False
        assert reopened.suspect_sidecar is None


# ── F-010: durability before atomicity ──────────────────────────────────────

class TestDurableReplace:
    """The fix is an ordering: a container's bytes reach the platter before
    the rename that publishes them, and the directory entry after it. Every
    one of the four sites could drop its os.fsync and still satisfy a test
    that only calls _fsync_dir and checks it does not raise, so trace both
    syscalls and pin the sequence instead."""

    def _sequence(self, trace, fn):
        del trace[:]        # ignore whatever setup did
        fn()
        return trace

    def test_single_volume_creation_is_durable_then_atomic(self, tmp_path, trace):
        path = str(tmp_path / "v.qcv")
        assert self._sequence(trace, lambda: vol.create_volume_single(path, PW)) == [
            ("fsync", "file"), ("replace", path), ("fsync", "dir")]

    def test_shamir_volume_creation_is_durable_then_atomic(self, tmp_path, trace):
        """The strictest of the four: the shares are handed out the moment
        this returns, so a container whose blocks never reached disk is
        unrecoverable by design."""
        path = str(tmp_path / "s.qcv")
        assert self._sequence(trace, lambda: vol.create_volume_shamir(path, 3, 2)) == [
            ("fsync", "file"), ("replace", path), ("fsync", "dir")]

    def test_compaction_is_durable_then_atomic(self, tmp_path, trace):
        path, _, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()
        assert self._sequence(trace, vc.compact) == [
            ("fsync", "file"), ("replace", path), ("fsync", "dir")]

    def test_qcx_encryption_is_durable_then_atomic(self, tmp_path, trace):
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        out = str(tmp_path / "f.qcx")
        assert self._sequence(trace, lambda: pkg.encrypt_to_qcx(
            str(src), out, mode="password", password=PW)) == [
            ("fsync", "file"), ("replace", out), ("fsync", "dir")]

    def test_a_delta_save_fsyncs_its_appended_journal(self, tmp_path, trace):
        """A delta save appends in place, so there is no rename to make
        durable — but the record still has to survive the next crash."""
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        got = self._sequence(trace, vc.save)
        assert ("fsync", "file") in got
        assert not [c for c in got if c[0] == "replace"], \
            "a delta save must append, not rewrite the whole container"

    def test_fsync_dir_tolerates_a_missing_directory(self, trace):
        """Best-effort by contract: a failure here must never fail a write
        that otherwise completed — and it must not fsync something else
        instead of failing quietly."""
        vol._fsync_dir("/definitely/not/a/real/path/file.qcv")
        assert trace == []

    def test_fsync_dir_syncs_the_parent_not_the_file(self, tmp_path, trace):
        """os.replace() is atomic in ordering, not in durability: it is the
        *directory* entry that still needs flushing afterwards."""
        target = tmp_path / "anything"
        target.write_bytes(b"x")
        vol._fsync_dir(str(target))
        assert trace == [("fsync", "dir")]


# ── F-019: decrypted output is quarantined ──────────────────────────────────

@pytest.mark.skipif(sys.platform != "darwin", reason="quarantine is a macOS concept")
class TestQuarantine:
    """A .qcx carries someone else's content, and both UIs put an "Open file"
    button on the success card."""

    def test_decrypted_output_carries_the_attribute(self, tmp_path):
        src = tmp_path / "from-a-stranger.txt"
        src.write_bytes(b"content")
        qcx = str(tmp_path / "s.qcx")
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        pkg.encrypt_to_qcx(str(src), qcx, mode="password", password=PW)
        res = pkg.decrypt_qcx(qcx, str(out_dir), password=PW)

        listed = subprocess.run(["xattr", res["output"]],
                                capture_output=True, text=True).stdout
        assert "com.apple.quarantine" in listed

    def test_a_libc_failure_does_not_fail_a_completed_decrypt(self, tmp_path,
                                                              monkeypatch):
        """_mark_quarantined swallows everything, so calling it directly can
        never fail. The property worth pinning is one level up: decrypt_qcx
        calls it *after* the output has been moved into place, inside a
        `except BaseException: remove(tmp); raise`. An exception escaping
        here therefore rolls back nothing — the plaintext stays in the output
        folder under its final name — and still reports the decrypt as
        failed. Verified: with the swallow removed, decrypt_qcx raises and
        the file is left behind unannounced."""
        src = tmp_path / "f.txt"
        src.write_bytes(b"content")
        qcx = str(tmp_path / "s.qcx")
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        pkg.encrypt_to_qcx(str(src), qcx, mode="password", password=PW)

        def boom(*a, **kw):
            raise OSError("libc unavailable")

        monkeypatch.setattr(ctypes, "CDLL", boom)
        res = pkg.decrypt_qcx(qcx, str(out_dir), password=PW)
        assert os.path.exists(res["output"])
        assert open(res["output"], "rb").read() == b"content"

    def test_marking_a_missing_file_is_a_no_op(self, tmp_path):
        """setxattr(2) on a missing path returns ENOENT; ctypes does not
        raise for it, and nothing must be created in its place."""
        ghost = str(tmp_path / "no-such-file")
        pkg._mark_quarantined(ghost)
        assert not os.path.exists(ghost)


# ── F-006: the signal path cannot hang the process ──────────────────────────

class TestBoundedEmergencySave:
    """Python runs signal handlers on the main thread between bytecodes, so
    an unbounded acquire here hangs the process when a FUSE worker holds the
    lock — the caller then escalates to SIGKILL, losing the buffer the
    handler exists to save."""

    def test_a_held_lock_is_skipped_rather_than_waited_on(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        fs.create("/a.txt", 0o100644)
        fs.write("/a.txt", b"unsaved", 0, 1)

        released = threading.Event()
        holding = threading.Event()

        def hold():
            with fs._lock:
                holding.set()
                released.wait(5)

        t = threading.Thread(target=hold, daemon=True)
        t.start()
        assert holding.wait(2)

        started = time.monotonic()
        fs.save_all_dirty(lock_timeout=0.2)   # must return, not block
        elapsed = time.monotonic() - started
        released.set()
        t.join(5)

        assert elapsed < 2.0, f"signal path blocked for {elapsed:.1f}s"

    def _register(self, tmp_path):
        _, key, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        fs.create("/a.txt", 0o100644)
        fs.write("/a.txt", b"unsaved", 0, 1)
        _mounted_volumes["/mnt/x"] = {
            "volume": vc, "volume_path": vc.path, "thread": None, "fuse": fs,
        }
        return key, vc, fs

    def test_emergency_save_all_persists_a_reachable_volume(self, tmp_path):
        """The positive half: the handler exists to save the buffer, so it
        has to actually save it when nothing is in the way."""
        _mounted_volumes.clear()
        try:
            key, vc, fs = self._register(tmp_path)
            _emergency_save_all(lock_timeout=0.2)
            assert not fs._dirty_files
            reopened = vol.VolumeContainer(vc.path, key)
            reopened.open()
            assert reopened.read_file("/a.txt") == b"unsaved"
        finally:
            _mounted_volumes.clear()

    def test_emergency_save_all_passes_the_timeout_through(self, tmp_path):
        """Without the pass-through this blocks for as long as the holder
        keeps the lock — on the signal path that is the main thread, so the
        process stops responding and the caller escalates to SIGKILL."""
        _mounted_volumes.clear()
        released = threading.Event()
        holding = threading.Event()
        t = None
        try:
            _, vc, fs = self._register(tmp_path)

            def hold():
                with fs._lock:
                    holding.set()
                    released.wait(5)

            t = threading.Thread(target=hold, daemon=True)
            t.start()
            assert holding.wait(2)

            started = time.monotonic()
            _emergency_save_all(lock_timeout=0.2)
            elapsed = time.monotonic() - started

            assert elapsed < 2.0, f"signal path blocked for {elapsed:.1f}s"
            # Skipped, exactly as a SIGKILL would have left it — losing one
            # volume beats hanging and losing every other one too.
            assert fs._dirty_files == {"/a.txt"}
        finally:
            released.set()
            if t is not None:
                t.join(5)
            _mounted_volumes.clear()


# ── F-011: statfs reports the real, memory-bound ceiling ────────────────────

class TestWriteCeiling:
    """The write path buffers the whole file ~4x in RAM. Run 12 F-003: the
    first version of this bound was applied to statfs, which turned a volume
    on a 274 GB disk into a 2 GB drive — a per-file limit is not a filesystem
    size. It belongs in write(), as EFBIG."""

    def test_statfs_reports_the_host_not_the_write_ceiling(self, tmp_path, monkeypatch):
        from quantacrypt.core import fuse_ops
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        monkeypatch.setattr(fuse_ops, "_max_writable_bytes", lambda: 8 * 1024 * 1024)
        st = fs.statfs("/")
        host = os.statvfs(str(tmp_path))
        host_free = host.f_bavail * host.f_frsize
        reported = st["f_bavail"] * st["f_frsize"]
        # Free space must still track the host; a tiny ceiling must not make
        # the volume look full.
        assert reported > 8 * 1024 * 1024
        assert abs(reported - host_free) < max(host_free * 0.05, 1 << 26)

    def test_a_write_past_the_ceiling_is_refused_with_efbig(self, tmp_path, monkeypatch):
        import errno as _errno
        from quantacrypt.core import fuse_ops
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        monkeypatch.setattr(fuse_ops, "_max_writable_bytes", lambda: 1024)
        fs.create("/big.bin", 0o100644)
        with pytest.raises(OSError) as exc:
            fs.write("/big.bin", b"x" * 2048, 0, 1)
        assert exc.value.errno == _errno.EFBIG
        # And nothing partial was buffered.
        assert fs._file_buffers.get("/big.bin", bytearray()) == bytearray()

    def test_a_write_at_the_ceiling_is_allowed(self, tmp_path, monkeypatch):
        from quantacrypt.core import fuse_ops
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        monkeypatch.setattr(fuse_ops, "_max_writable_bytes", lambda: 1024)
        fs.create("/ok.bin", 0o100644)
        assert fs.write("/ok.bin", b"x" * 1024, 0, 1) == 1024

    def test_ceiling_has_a_floor_and_is_plausible(self):
        from quantacrypt.core.fuse_ops import _max_writable_bytes
        ceiling = _max_writable_bytes()
        assert ceiling >= 64 * 1024 * 1024
        assert ceiling < (1 << 40)


class TestSetattrCoalescing:
    """Run 12 F-002: the setattr record was dropped by the coalescer in the
    exact sequence rsync uses, so the fix did not deliver its headline case."""

    def test_rsync_sequence_preserves_mode_and_mtime(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/.f.tmp", b"payload")
        vc.set_attrs("/.f.tmp", mode=0o100755, mtime=1_000_000_000)
        vc.rename("/.f.tmp", "/f.txt")
        vc.save()

        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        entry = reopened.get_entry("/f.txt")
        assert entry["mode"] == 0o100755
        assert entry["mtime"] == 1_000_000_000

    def test_coalescing_is_free_of_side_effects(self, tmp_path):
        """Calling it twice must give the same answer — the first version
        rewrote _pending_ops in place, so it did not."""
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/.f.tmp", b"payload")
        vc.set_attrs("/.f.tmp", mode=0o100755)
        vc.rename("/.f.tmp", "/f.txt")
        first = [(o["type"], o["vpath"]) for o in vc._coalesce_pending_ops()]
        second = [(o["type"], o["vpath"]) for o in vc._coalesce_pending_ops()]
        assert first == second
        assert first == [("write", "/f.txt"), ("setattr", "/f.txt")]

    def test_attributes_are_dropped_when_the_path_is_deleted(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"x")
        vc.save()
        vc.set_attrs("/a.txt", mode=0o100755)
        vc.delete("/a.txt")
        types = [o["type"] for o in vc._coalesce_pending_ops()]
        assert "setattr" not in types


class TestPasswordFloorErrorCode:
    """Run 12: one condition must report one code. create_volume_* raised a
    bare ValueError, which classify_error maps to "format" — the code that
    means a damaged container."""

    def test_both_creation_paths_raise_invalid_input(self, tmp_path):
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        with pytest.raises(InvalidInput):
            pkg.encrypt_to_qcx(str(src), str(tmp_path / "f.qcx"),
                               mode="password", password="short")
        with pytest.raises(InvalidInput):
            vol.create_volume_single(str(tmp_path / "v.qcv"), "short")

    def test_the_service_reports_invalid_input_for_both(self, tmp_path):
        from quantacrypt.core.errors import classify_error
        for exc in (InvalidInput("Use at least 8 characters."),):
            assert classify_error(exc)[0] == "invalid_input"

    def test_baseline_rename_preserves_attributes(self, tmp_path):
        """Run 12 follow-up: the other half of the coalescer. A setattr on an
        already-saved path followed by a rename was re-keyed to the
        destination but still emitted at its original index, so it landed
        before that path existed. Replay's rename carries the entry, so the
        change must stay on the old name."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()                       # /a.txt is now a baseline path
        vc.set_attrs("/a.txt", mode=0o100755, mtime=1_000_000_000)
        vc.rename("/a.txt", "/b.txt")
        vc.save()

        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        entry = reopened.get_entry("/b.txt")
        assert entry["mode"] == 0o100755
        assert entry["mtime"] == 1_000_000_000


# ── round-1 F-007: a failed creation must not wedge the path ────────────────

class TestVolumeCreateCleansUpAfterFailure:
    """A transient ENOSPC used to leave `<path>.part` behind forever: the
    name was fixed, so every retry collided with it, and no screen in the app
    knows that name to offer clearing it."""

    @staticmethod
    def _explode_once(monkeypatch):
        """Fail the way a full disk does — mid-container, after the header."""
        calls = []
        real = vol._write_encrypted_block

        def boom(f, ciphertext):
            calls.append(1)
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(vol, "_write_encrypted_block", boom)
        return calls, real

    def test_a_failed_password_create_leaves_nothing_behind(self, tmp_path, monkeypatch):
        path = str(tmp_path / "v.qcv")
        calls, real = self._explode_once(monkeypatch)
        with pytest.raises(OSError):
            vol.create_volume_single(path, PW)
        assert calls, "the failure has to land after the container was opened"
        assert list(tmp_path.iterdir()) == []

        # And the same path is immediately usable again.
        monkeypatch.setattr(vol, "_write_encrypted_block", real)
        vol.create_volume_single(path, PW)
        assert os.path.exists(path)

    def test_a_failed_shamir_create_leaves_nothing_behind(self, tmp_path, monkeypatch):
        path = str(tmp_path / "s.qcv")
        calls, real = self._explode_once(monkeypatch)
        with pytest.raises(OSError):
            vol.create_volume_shamir(path, 3, 2)
        assert calls
        assert list(tmp_path.iterdir()) == []

        monkeypatch.setattr(vol, "_write_encrypted_block", real)
        vol.create_volume_shamir(path, 3, 2)
        assert os.path.exists(path)

    def test_a_failing_cleanup_does_not_mask_the_real_error(self, tmp_path, monkeypatch):
        """Removing the scratch file is best effort, so it must never replace
        the error that explains why the create failed."""
        self._explode_once(monkeypatch)

        def _refuse(_path):
            raise OSError(13, "Permission denied")

        monkeypatch.setattr(os, "remove", _refuse)
        with pytest.raises(OSError) as exc:
            vol.create_volume_single(str(tmp_path / "v.qcv"), PW)
        assert exc.value.errno == 28, "the ENOSPC has to survive the cleanup"

    def test_a_stale_scratch_file_cannot_block_a_create(self, tmp_path):
        """The old fixed name is no longer consulted, so an artefact left by
        a hard kill or a power loss is litter, not a wall."""
        path = str(tmp_path / "v.qcv")
        open(path + ".part", "wb").write(b"leftover from a crash")
        vol.create_volume_single(path, PW)
        assert os.path.exists(path)

    def test_a_new_container_is_owner_only(self, tmp_path):
        path = str(tmp_path / "v.qcv")
        vol.create_volume_single(path, PW)
        assert oct(os.stat(path).st_mode)[-3:] == "600"


# ── round-1 F-008: chmod cannot destroy an entry's file type ────────────────

class TestChmodKeepsTheFileType:
    """A FUSE backend that masks chmod's argument with ALLPERMS hands over
    permission bits only. Stored verbatim that reports no file type at all
    (`ls` shows `?---------`), and since the change now reaches the journal
    it is permanent rather than discarded at unmount."""

    def test_a_permission_only_chmod_keeps_the_file_a_file(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        fs.create("/a.txt", 0o100644)
        fs.chmod("/a.txt", 0o755)
        mode = fs.getattr("/a.txt")["st_mode"]
        assert stat.S_ISREG(mode), oct(mode)
        assert stat.S_IMODE(mode) == 0o755

    def test_a_directory_type_bit_on_a_file_is_ignored(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        fs.create("/a.txt", 0o100644)
        fs.chmod("/a.txt", 0o040755)
        mode = fs.getattr("/a.txt")["st_mode"]
        assert stat.S_ISREG(mode) and not stat.S_ISDIR(mode), oct(mode)
        assert vc.get_entry("/a.txt")["type"] == "file"

    def test_a_directory_keeps_its_type(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        fs = QuantaCryptFUSE(vc)
        fs.mkdir("/d", 0o40755)
        fs.chmod("/d", 0o700)
        mode = fs.getattr("/d")["st_mode"]
        assert stat.S_ISDIR(mode), oct(mode)
        assert stat.S_IMODE(mode) == 0o700

    def test_setuid_and_sticky_bits_are_preserved(self, tmp_path):
        _, _, vc = _make_volume(tmp_path)
        vc.write_file("/s", b"x")
        vc.set_attrs("/s", mode=0o4755)
        assert vc.get_entry("/s")["mode"] == (stat.S_IFREG | 0o4755)

    def test_the_normalised_mode_is_what_survives_a_reopen(self, tmp_path):
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.set_attrs("/a.txt", mode=0o755)
        vc.save()
        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        assert reopened.get_entry("/a.txt")["mode"] == 0o100755

    def test_an_index_poisoned_by_an_older_build_heals_on_reopen(self, tmp_path):
        """A record written before the fix carries a bare permission mask;
        replay has to repair it rather than keep reproducing it."""
        path, key, vc = _make_volume(tmp_path)
        vc.write_file("/a.txt", b"payload")
        vc.save()
        # Exactly what the unfixed set_attrs appended.
        vc._pending_ops.append({"type": "setattr", "vpath": "/a.txt",
                                "mode": 0o040755})
        vc._dirty = True
        vc.save()

        reopened = vol.VolumeContainer(path, key)
        reopened.open()
        mode = reopened.get_entry("/a.txt")["mode"]
        assert stat.S_ISREG(mode), oct(mode)
        assert stat.S_IMODE(mode) == 0o755


# ── The shipped KDF parameters ──────────────────────────────────────────────

@pytest.mark.real_argon2
class TestShippedArgon2Parameters:
    """Tests run with cheap KDF parameters (see conftest._cheap_argon2), so
    something has to pin the real ones. CLAUDE.md forbids weakening these for
    existing password-mode files, and nothing else in the suite asserts them."""

    def test_parameters_meet_the_documented_floor(self):
        assert cc.ARGON2_TIME_COST >= 4
        assert cc.ARGON2_MEMORY_COST >= 65536      # 64 MiB
        assert cc.ARGON2_PARALLELISM == 1          # single lane, full memory
        assert cc.KEY_BYTES == 64

    def test_the_cheap_test_parameters_are_not_what_ships(self):
        """Guards against the fixture leaking into a real build."""
        from tests.conftest import _TEST_ARGON2_TIME_COST, _TEST_ARGON2_MEMORY_COST
        assert cc.ARGON2_TIME_COST != _TEST_ARGON2_TIME_COST
        assert cc.ARGON2_MEMORY_COST != _TEST_ARGON2_MEMORY_COST

    def test_both_formats_record_their_kdf_parameters(self, tmp_path):
        """Format 2 (.qcx) and 3 (.qcv) record the Argon2id parameters the
        container was made with, so raising the shipped values later cannot
        strand existing files — a reader derives with what the file says.
        The recorded values are the shipped ones, and the block that mount
        reads before any credential exists carries the same copy."""
        shipped = {"t": cc.ARGON2_TIME_COST, "m": cc.ARGON2_MEMORY_COST, "p": 1}
        vpath = str(tmp_path / "real.qcv")
        vmeta = vol.create_volume_single(vpath, PW)
        assert vmeta["argon2"] == shipped and vmeta["kem"] == cc.KEM_ML_KEM768
        _, auth = vol.read_volume_auth_params(vpath)
        assert auth["argon2"] == shipped and auth["kem"] == cc.KEM_ML_KEM768

        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        pkg.encrypt_to_qcx(str(src), str(tmp_path / "f.qcx"),
                           mode="password", password=PW)
        qmeta = pkg.load_pkg(str(tmp_path / "f.qcx"))["meta"]
        assert qmeta["argon2"] == shipped and qmeta["kem"] == cc.KEM_ML_KEM768

    def test_a_reader_derives_with_the_recorded_parameters(self, tmp_path, monkeypatch):
        """The whole point: a file made under one cost still opens after the
        shipped cost changes, because the reader honours the file."""
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        out = str(tmp_path / "f.qcx")
        pkg.encrypt_to_qcx(str(src), out, mode="password", password=PW)
        monkeypatch.setattr(cc, "ARGON2_TIME_COST", cc.ARGON2_TIME_COST + 1)
        assert pkg.decrypt_qcx(out, str(tmp_path), password=PW,
                               verify_only=True)["verified"]
