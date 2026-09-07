"""Edge-path behaviour tests for the core modules.

Every class here pins one contract the happy-path suite never reaches:
crash-truncated journals, tampered directory entries, cleanup that itself
fails, and the platform branches of the FUSE plumbing.

The volume fixtures copy one pre-built container instead of creating a new
one per test — Argon2id at t=4 / m=64 MB otherwise dominates the runtime of
the whole module.
"""

import ctypes
import errno
import hashlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tests.conftest import fusepy_backend
from quantacrypt.core import crypto as cc
from quantacrypt.core import fuse_ops as fo
from quantacrypt.core import package as pkg
from quantacrypt.core import service as svc_mod
from quantacrypt.core import volume as vol
from quantacrypt.core.errors import CorruptPayload, InvalidInput, InvalidRequest
from quantacrypt.core.fuse_ops import QuantaCryptFUSE
from quantacrypt.core.service import Service

PW = "correct horse battery staple"


# ── Fixtures & helpers ──────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def blank_volume(tmp_path_factory):
    """Bytes of one freshly created empty .qcv plus its final key.

    Argon2id is deliberately expensive; paying for it once per module and
    copying the container keeps this file's runtime in seconds.
    """
    d = tmp_path_factory.mktemp("core_edges")
    path = str(d / "blank.qcv")
    meta = vol.create_volume_single(path, PW)
    key = vol.derive_volume_key_single(PW, meta)
    with open(path, "rb") as f:
        return f.read(), key


@pytest.fixture
def volume(tmp_path, blank_volume):
    """(path, key, open VolumeContainer) on a private copy of the blank."""
    blob, key = blank_volume
    path = str(tmp_path / "v.qcv")
    with open(path, "wb") as f:
        f.write(blob)
    vc = vol.VolumeContainer(path, key)
    vc.open()
    return path, key, vc


def _reopen(path, key):
    vc = vol.VolumeContainer(path, key)
    vc.open()
    return vc


def _append_journal_bytes(path, key, header_plain, body=b""):
    """Append one journal record with *header_plain* as the header plaintext.

    Written by hand rather than through _write_journal_record because replay
    has to survive headers this app would never emit (a future version's, a
    corrupted one), and that helper only accepts well-formed op dicts.
    """
    with open(path, "r+b") as f:
        f.seek(0, 2)
        start = f.tell()
        nonce = secrets.token_bytes(12)
        ct = AESGCM(cc.derive_aes_key(key)).encrypt(
            nonce, header_plain, start.to_bytes(8, "big"))
        f.write(nonce)
        f.write(struct.pack(">I", len(ct)))
        f.write(ct)
        f.write(body)


def _append_journal_op(path, key, op, body=b""):
    d = dict(op)
    d.setdefault("body_length", len(body))
    _append_journal_bytes(
        path, key,
        json.dumps(d, sort_keys=True, separators=(",", ":")).encode(),
        body)


def _rewrite_container(path, key, mutate_dir=None, mutate_meta=None):
    """Re-encrypt a container's metadata / directory blocks after mutating
    them.  Simulates an attacker (or bit rot) that got at the encrypted
    index — the only way to feed VolumeContainer.open() an index the public
    API refuses to build."""
    with open(path, "rb") as f:
        header = vol.read_header(f)
        auth = vol._read_auth_params(f)
        meta_ct = vol._read_encrypted_block(f)
        dir_ct = vol._read_encrypted_block(f)
        tail = f.read()
    meta = vol.decrypt_metadata(key, header["meta_nonce"], meta_ct)
    dir_index = vol.decrypt_directory(key, header["dir_nonce"], dir_ct)
    if mutate_meta:
        mutate_meta(meta)
    if mutate_dir:
        mutate_dir(dir_index)
    meta_nonce, meta_ct = vol.encrypt_metadata(key, meta)
    dir_nonce, dir_ct = vol.encrypt_directory(key, dir_index)
    with open(path, "wb") as f:
        vol.write_header(f, header["volume_id"], meta_nonce, dir_nonce)
        vol._write_auth_params(f, auth)
        vol._write_encrypted_block(f, meta_ct)
        vol._write_encrypted_block(f, dir_ct)
        f.write(tail)


def _patch_blob_bytes(path, vc, vpath, offset, data):
    """Overwrite bytes inside a file's on-disk encrypted blob."""
    entry = vc.get_entry(vpath)
    absolute = vc._data_offset + entry["data_offset"] + offset
    with open(path, "r+b") as f:
        f.seek(absolute)
        f.write(data)


def _open_fd_count():
    """Descriptors this process holds open right now.

    /dev/fd lists them on both macOS and Linux.  The listing itself needs one
    descriptor, but it needs exactly one every time, so comparing two counts
    taken this way is stable.
    """
    return len(os.listdir("/dev/fd"))


@pytest.fixture(autouse=True)
def restore_fuse_library_path():
    """_prepare_fuse_environment writes FUSE_LIBRARY_PATH into the real
    environment, and monkeypatch.delenv on a variable that was never set
    records nothing to restore — so without this the value would survive into
    every later test in the process, including a real mount, which would then
    try to dlopen a library the stubs only pretended was there."""
    saved = os.environ.get("FUSE_LIBRARY_PATH")
    yield
    if saved is None:
        os.environ.pop("FUSE_LIBRARY_PATH", None)
    else:
        os.environ["FUSE_LIBRARY_PATH"] = saved


@pytest.fixture(autouse=True)
def restore_mount_registry():
    """Mount bookkeeping is module-global; leave it exactly as found."""
    saved_mounts = dict(fo._mounted_volumes)
    saved_locks = dict(fo._volume_locks)
    yield
    for mp, fd in list(fo._volume_locks.items()):
        if saved_locks.get(mp) != fd:
            try:
                os.close(fd)
            except OSError:
                pass
    fo._mounted_volumes.clear()
    fo._mounted_volumes.update(saved_mounts)
    fo._volume_locks.clear()
    fo._volume_locks.update(saved_locks)


# ════════════════════════════════════════════════════════════════════════════
# volume.py
# ════════════════════════════════════════════════════════════════════════════

class TestFsyncDirIsBestEffort:
    """_fsync_dir makes a rename durable where it can, and is a no-op where
    it cannot — a filesystem that refuses to fsync a directory must not fail
    an otherwise complete write."""

    def test_a_refused_directory_fsync_does_not_fail_the_write(
            self, volume, monkeypatch):
        import stat as stat_mod
        path, key, vc = volume
        real_fsync = os.fsync

        def _refuse_dirs(fd):
            # Some filesystems genuinely refuse fsync on a directory fd;
            # the file's own fsync is not best-effort and stays real.
            if stat_mod.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "fsync not supported here")
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", _refuse_dirs)
        vc.write_file("/a.txt", b"durable")
        vc.compact()
        assert _reopen(path, key).read_file("/a.txt") == b"durable"

    def test_it_fsyncs_the_containing_directory_and_closes_the_descriptor(
            self, tmp_path, monkeypatch):
        """The happy path.  An fsync has no userspace-visible result, so the
        two observable facts are *which* object was synced (the parent
        directory of the target, not the target) and that the descriptor did
        not leak — the helper runs on every save of every mounted volume."""
        target = tmp_path / "sub" / "v.qcv"
        target.parent.mkdir()
        target.write_bytes(b"x")
        real_fsync = os.fsync
        synced = []

        def _record(fd):
            synced.append(os.fstat(fd))
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", _record)
        vol._fsync_dir(str(target))
        assert len(synced) == 1
        parent = os.stat(str(target.parent))
        assert (synced[0].st_dev, synced[0].st_ino) == (parent.st_dev, parent.st_ino)
        # The fd is closed in a finally, so nothing is left open afterwards.
        assert _open_fd_count() == self._before

    def test_a_refused_fsync_is_swallowed_and_still_closes_the_descriptor(
            self, tmp_path, monkeypatch):
        """Best-effort is the documented contract, but "swallow the error"
        must not mean "leak the fd": save() calls this on every write, so a
        leak here exhausts the process's descriptors on a busy volume."""
        target = tmp_path / "v.qcv"
        target.write_bytes(b"x")

        def _refuse(_fd):
            raise OSError(errno.EINVAL, "fsync not supported here")

        monkeypatch.setattr(os, "fsync", _refuse)
        assert vol._fsync_dir(str(target)) is None
        assert _open_fd_count() == self._before

    def test_an_unopenable_directory_is_skipped(self, tmp_path):
        # A path whose parent does not exist: os.open() fails, and the
        # documented contract is a silent return, not an exception.
        assert vol._fsync_dir(str(tmp_path / "gone" / "x.qcv")) is None
        assert _open_fd_count() == self._before

    @pytest.fixture(autouse=True)
    def _fd_baseline(self):
        self._before = _open_fd_count()
        yield


class TestJournalTruncatedTail:
    """A crash during save() can only leave a record that runs out of bytes
    at EOF.  Replay must stop there, keep every earlier record, and NOT flag
    the container as suspicious — that flag means tampering."""

    @pytest.fixture
    def one_record(self, volume):
        path, key, vc = volume
        vc.write_file("/keep.txt", b"kept")
        vc.save()
        return path, key, vc._journal_start

    @pytest.mark.parametrize("extra,label", [
        (0, "nothing written"),
        (5, "partial nonce"),
        (14, "nonce, partial length"),
        (30, "nonce, length, partial header"),
    ])
    def test_a_partial_record_is_dropped_not_flagged(
            self, one_record, extra, label):
        path, key, journal_start = one_record
        # Overwrite the committed record with a partial second one.
        with open(path, "r+b") as f:
            f.truncate(journal_start + extra)
        vc = _reopen(path, key)
        assert vc.dir_index == {}, label
        assert vc.journal_suspicious is False
        assert vc.suspect_sidecar is None

    def test_a_truncated_body_keeps_the_previous_records(self, volume):
        path, key, vc = volume
        vc.write_file("/first.txt", b"one")
        vc.save()
        vc.write_file("/second.txt", b"two-with-a-longer-body")
        vc.save()
        # Chop the last few bytes of the second record's body.
        with open(path, "r+b") as f:
            f.truncate(os.path.getsize(path) - 5)
        reopened = _reopen(path, key)
        assert reopened.read_file("/first.txt") == b"one"
        assert "/second.txt" not in reopened.dir_index
        assert reopened.journal_suspicious is False

    def test_appending_after_a_truncated_tail_stays_readable(self, volume):
        """Appends must resume at the last VALID record, not at raw EOF."""
        path, key, vc = volume
        vc.write_file("/first.txt", b"one")
        vc.save()
        with open(path, "r+b") as f:
            f.write(b"")
            f.seek(0, 2)
            f.write(secrets.token_bytes(9))   # crash garbage, < 12 bytes
        reopened = _reopen(path, key)
        reopened.write_file("/second.txt", b"two")
        reopened.save()
        final = _reopen(path, key)
        assert final.read_file("/first.txt") == b"one"
        assert final.read_file("/second.txt") == b"two"


class TestJournalSuspiciousTail:
    """A *complete* record that fails to make sense is not the crash shape.
    It is flagged, and the unreadable tail is copied out before the next
    save overwrites the only evidence."""

    def test_a_non_object_header_is_suspicious_and_preserved(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"payload")
        vc.save()
        valid_end = os.path.getsize(path)
        _append_journal_bytes(path, key, b'"not-an-object"')
        tail = open(path, "rb").read()[valid_end:]

        reopened = _reopen(path, key)
        assert reopened.journal_suspicious is True
        assert reopened.read_file("/a.txt") == b"payload"
        assert reopened._journal_end == valid_end
        assert reopened.suspect_sidecar is not None
        assert open(reopened.suspect_sidecar, "rb").read() == tail

    def test_a_negative_body_length_is_suspicious(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"payload")
        vc.save()
        valid_end = os.path.getsize(path)
        _append_journal_op(path, key,
                           {"type": "write", "vpath": "/evil", "body_length": -1})
        reopened = _reopen(path, key)
        assert reopened.journal_suspicious is True
        assert "/evil" not in reopened.dir_index
        assert reopened._journal_end == valid_end

    def test_the_suspect_tail_is_overwritten_by_the_next_save(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"payload")
        vc.save()
        _append_journal_bytes(path, key, b'"garbage"')
        reopened = _reopen(path, key)
        sidecar = reopened.suspect_sidecar
        reopened.write_file("/b.txt", b"second")
        reopened.save()
        final = _reopen(path, key)
        assert final.read_file("/b.txt") == b"second"
        assert final.journal_suspicious is False
        # The evidence survives only because open() copied it out first.
        assert os.path.exists(sidecar)


class TestPreserveSuspectTail:
    """Copying the tail out is best-effort: it must never be the reason a
    user cannot open their own volume."""

    @pytest.mark.parametrize("delta", [0, 7])
    def test_a_tail_of_zero_or_fewer_bytes_writes_no_sidecar(self, volume, delta):
        """Boundary n and n+1: valid_end exactly at EOF, and past it (the
        shape a truncation behind our back leaves).  Both mean "no tail"."""
        path, key, vc = volume
        before = sorted(os.listdir(os.path.dirname(path)))
        vc._preserve_suspect_tail(vc._file_size + delta)
        assert vc.suspect_sidecar is None
        assert sorted(os.listdir(os.path.dirname(path))) == before

    def test_a_one_byte_tail_is_preserved(self, volume):
        """Boundary n-1: the smallest tail there is still gets copied out,
        byte for byte."""
        path, key, vc = volume
        vc._preserve_suspect_tail(vc._file_size - 1)
        assert vc.suspect_sidecar is not None
        assert open(vc.suspect_sidecar, "rb").read() == \
            open(path, "rb").read()[-1:]

    def test_a_short_source_preserves_what_is_actually_there(self, volume):
        path, key, vc = volume
        real_size = os.path.getsize(path)
        # Bookkeeping claims more bytes than the file holds (the shape a
        # concurrent truncation leaves behind).
        vc._file_size = real_size + 500
        vc._preserve_suspect_tail(real_size - 20)
        assert vc.suspect_sidecar is not None
        saved = open(vc.suspect_sidecar, "rb").read()
        assert saved == open(path, "rb").read()[-20:]

    def test_an_unreadable_source_leaves_no_sidecar_recorded(self, volume):
        """DOCUMENTS A DEFECT alongside the contract.

        The contract half: the OSError is swallowed and ``suspect_sidecar``
        stays None, so a failure here can never stop a volume opening.

        The defect half: the sidecar is created with O_EXCL *before* the
        source is opened, and the except branch does not unlink it — so a
        0-byte ``<volume>.qcv.suspect-<stamp>`` file is left in the user's
        folder claiming to hold evidence it does not hold.  The fix is an
        os.unlink of the sidecar in _preserve_suspect_tail's except branch;
        that will flip the last two assertions to "no litter at all".
        """
        path, key, vc = volume
        folder = os.path.dirname(path)
        os.remove(path)
        vc._file_size = 100
        vc._preserve_suspect_tail(0)      # contract: swallows the OSError
        assert vc.suspect_sidecar is None
        litter = [n for n in os.listdir(folder) if ".suspect-" in n]
        assert len(litter) == 1                                    # defect
        assert os.path.getsize(os.path.join(folder, litter[0])) == 0   # defect


class TestJournalReplaySkipsMalformedRecords:
    """Replay is defensive per record: one unusable record is skipped, the
    rest of the journal still applies."""

    def _good_write(self, path, key, vpath, data):
        nonce, blob, chunks, digest = vol.encrypt_file_data(
            data, key, vol.VOLUME_CHUNK_SIZE)
        import base64
        _append_journal_op(path, key, {
            "type": "write", "vpath": vpath, "size": len(data),
            "mode": 0o100644, "mtime": 1700000000,
            "nonce": base64.b64encode(nonce).decode(),
            "chunk_count": chunks, "content_hash": digest,
        }, body=blob)

    def test_a_non_string_vpath_is_skipped_and_replay_continues(self, volume):
        path, key, vc = volume
        _append_journal_op(path, key, {"type": "write", "vpath": 42})
        self._good_write(path, key, "/after.txt", b"still applied")
        reopened = _reopen(path, key)
        assert reopened.read_file("/after.txt") == b"still applied"
        assert 42 not in reopened.dir_index

    def test_a_traversal_vpath_is_skipped_and_replay_continues(self, volume):
        path, key, vc = volume
        _append_journal_op(path, key, {"type": "write", "vpath": "/../escape"})
        self._good_write(path, key, "/after.txt", b"still applied")
        reopened = _reopen(path, key)
        assert reopened.read_file("/after.txt") == b"still applied"
        assert "/../escape" not in reopened.dir_index

    def test_a_rename_with_a_non_string_destination_is_skipped(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"body")
        vc.save()
        _append_journal_op(path, key,
                           {"type": "rename", "vpath": "/a.txt", "new_vpath": 7})
        reopened = _reopen(path, key)
        assert reopened.read_file("/a.txt") == b"body"

    def test_a_rename_to_a_traversal_path_is_skipped(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"body")
        vc.save()
        _append_journal_op(path, key, {"type": "rename", "vpath": "/a.txt",
                                       "new_vpath": "/../out.txt"})
        reopened = _reopen(path, key)
        assert reopened.read_file("/a.txt") == b"body"
        assert "/../out.txt" not in reopened.dir_index

    def test_an_unknown_op_type_is_ignored(self, volume):
        """Forward compatibility: a record type this version has never heard
        of must not abort replay of the ones it does understand."""
        path, key, vc = volume
        _append_journal_op(path, key, {"type": "teleport", "vpath": "/x"})
        self._good_write(path, key, "/after.txt", b"applied")
        reopened = _reopen(path, key)
        assert reopened.read_file("/after.txt") == b"applied"
        assert "/x" not in reopened.dir_index


class TestJournalReplayNormalisesDirectoryPaths:
    """Directory keys carry a trailing slash; records that name a directory
    without one still have to land on the right entry."""

    @pytest.fixture
    def with_dir(self, volume):
        path, key, vc = volume
        vc.mkdir("/docs")
        vc.save()
        return path, key

    def test_a_slashless_mkdir_record_creates_the_directory_key(self, volume):
        path, key, vc = volume
        _append_journal_op(path, key,
                           {"type": "mkdir", "vpath": "/photos", "mode": 0o40700,
                            "mtime": 1700000001})
        reopened = _reopen(path, key)
        entry = reopened.get_entry("/photos/")
        assert entry is not None and entry["type"] == "dir"
        assert entry["mode"] == 0o40700
        assert reopened.list_dir("/") == ["photos"]

    def test_a_slashless_setattr_record_finds_the_directory(self, with_dir):
        path, key = with_dir
        _append_journal_op(path, key, {"type": "setattr", "vpath": "/docs",
                                       "mode": 0o40711, "mtime": 1700000002})
        reopened = _reopen(path, key)
        assert reopened.get_entry("/docs/")["mode"] == 0o40711
        assert reopened.get_entry("/docs/")["mtime"] == 1700000002

    def test_a_setattr_for_an_unknown_path_changes_nothing(self, with_dir):
        path, key = with_dir
        before = dict(_reopen(path, key).dir_index)
        assert before          # the comparison below only means something
        assert "/ghost" not in before and "/ghost/" not in before
        _append_journal_op(path, key,
                           {"type": "setattr", "vpath": "/ghost", "mode": 0o100777})
        after = _reopen(path, key).dir_index
        assert after == before
        # In particular the record did not invent an entry for the path.
        assert "/ghost" not in after and "/ghost/" not in after

    def test_a_slashless_rmdir_record_removes_the_directory(self, with_dir):
        path, key = with_dir
        _append_journal_op(path, key, {"type": "rmdir", "vpath": "/docs"})
        assert "/docs/" not in _reopen(path, key).dir_index


class TestDecryptFileDataRejectsBadBlobs:
    """decrypt_file_data authenticates every chunk; the framing around them
    has to be checked before the AEAD can be asked anything sensible."""

    def test_round_trip_across_chunk_boundaries(self, blank_volume):
        _, key = blank_volume
        data = b"".join(bytes([i % 251]) for i in range(200))
        nonce, blob, chunks, digest = vol.encrypt_file_data(data, key, 64)
        assert chunks == 4                     # 200 bytes at 64-byte chunks
        assert vol.decrypt_file_data(blob, key, nonce, chunks) == data

    def test_empty_input_still_produces_one_authenticated_chunk(self, blank_volume):
        _, key = blank_volume
        nonce, blob, chunks, _ = vol.encrypt_file_data(b"", key, 64)
        assert chunks == 1
        assert vol.decrypt_file_data(blob, key, nonce, chunks) == b""

    def test_a_reordered_chunk_header_is_rejected(self, blank_volume):
        _, key = blank_volume
        nonce, blob, chunks, _ = vol.encrypt_file_data(b"x" * 200, key, 64)
        tampered = struct.pack(">I", 3) + blob[4:]
        with pytest.raises(ValueError, match="Chunk sequence mismatch at 0"):
            vol.decrypt_file_data(tampered, key, nonce, chunks)

    def test_a_blob_cut_short_mid_chunk_is_rejected(self, blank_volume):
        _, key = blank_volume
        nonce, blob, chunks, _ = vol.encrypt_file_data(b"y" * 200, key, 64)
        with pytest.raises(ValueError, match="incomplete chunk"):
            vol.decrypt_file_data(blob[:-5], key, nonce, chunks)

    def test_a_blob_missing_a_whole_chunk_header_is_rejected(self, blank_volume):
        _, key = blank_volume
        nonce, blob, chunks, _ = vol.encrypt_file_data(b"z" * 200, key, 64)
        stride = 8 + 64 + 16
        with pytest.raises(ValueError, match="missing chunk header"):
            vol.decrypt_file_data(blob[:stride + 4], key, nonce, chunks)

    def test_the_wrong_key_fails_authentication_rather_than_returning_junk(
            self, blank_volume):
        """The BAD path that matters: a wrong key must be an error, never a
        plausible-looking plaintext.  It has to be named as chunk 0 so the
        caller can tell "wrong password" from "damage at byte 900k"."""
        _, key = blank_volume
        nonce, blob, chunks, _ = vol.encrypt_file_data(b"secret" * 40, key, 64)
        other = secrets.token_bytes(len(key))
        with pytest.raises(ValueError, match="Authentication failed on chunk 0"):
            vol.decrypt_file_data(blob, other, nonce, chunks)

    def test_dropping_the_final_chunk_is_caught_by_the_last_chunk_flag(
            self, blank_volume):
        """Truncation attack: hand over the first n-1 chunks and claim that
        is the whole file.  Every chunk's AAD carries an is-last flag, so the
        new final chunk fails to authenticate instead of silently yielding a
        shortened file."""
        _, key = blank_volume
        nonce, blob, chunks, _ = vol.encrypt_file_data(b"w" * 200, key, 64)
        assert chunks == 4
        stride = 8 + 64 + 16
        with pytest.raises(ValueError, match="Authentication failed on chunk 2"):
            vol.decrypt_file_data(blob[:3 * stride], key, nonce, chunks - 1)

    def test_a_chunk_count_of_zero_yields_nothing(self, blank_volume):
        """Zero iterations of the loop.  encrypt_file_data never emits this
        (it always writes one chunk, even for empty input), so it can only
        arrive from a tampered directory entry — and it must not be confused
        with the legitimately-empty file above."""
        _, key = blank_volume
        nonce, blob, chunks, _ = vol.encrypt_file_data(b"payload", key, 64)
        assert vol.decrypt_file_data(blob, key, nonce, 0) == b""


class TestOpenRejectsCorruptContainers:
    """open() has to name what is wrong: the same "it failed" for a wrong
    password and a shredded directory block is useless to a user."""

    def test_a_corrupt_directory_block_names_the_directory_index(self, volume):
        path, key, vc = volume
        with open(path, "rb") as f:
            vol.read_header(f)
            vol._read_auth_params(f)
            vol._read_encrypted_block(f)
            dir_block_start = f.tell()
        with open(path, "r+b") as f:
            f.seek(dir_block_start + 4)       # first byte of the dir ciphertext
            first = f.read(1)
            f.seek(dir_block_start + 4)
            f.write(bytes([first[0] ^ 0xFF]))
        with pytest.raises(ValueError, match="directory index"):
            _reopen(path, key)

    def test_an_entry_pointing_past_the_data_section_is_rejected(self, volume):
        """Both sides of the bound: an entry ending exactly at the end of the
        baseline is the healthy case, one byte further is corruption."""
        path, key, vc = volume
        vc.write_file("/a.txt", b"payload bytes")
        vc.compact()
        # n: the last entry ends exactly at the baseline end.
        assert _reopen(path, key).read_file("/a.txt") == b"payload bytes"

        def _shift(index):
            index["/a.txt"]["data_offset"] += 1

        # n+1.
        _rewrite_container(path, key, mutate_dir=_shift)
        with pytest.raises(ValueError, match="extends past end of volume"):
            _reopen(path, key)

    def test_truncation_inside_the_baseline_is_an_error_not_a_crash_tail(
            self, volume):
        """A short journal tail is a crash during save and is tolerated; a
        file that stops inside the canonical baseline data is unrecoverable
        and has to say so rather than opening with silently missing bytes."""
        path, key, vc = volume
        vc.write_file("/a.txt", b"x" * 4000)
        vc.compact()
        with open(path, "r+b") as f:
            f.truncate(os.path.getsize(path) - 1)
        with pytest.raises(ValueError, match="truncated within baseline data"):
            _reopen(path, key)

    def test_directory_entries_are_skipped_by_the_bounds_check(self, volume):
        """A dir entry has no data_offset/data_length; treating it as a file
        would make every volume with a folder in its baseline unopenable."""
        path, key, vc = volume
        vc.mkdir("/docs")
        vc.write_file("/docs/a.txt", b"inside")
        vc.compact()                       # both land in the baseline
        reopened = _reopen(path, key)
        assert reopened.get_entry("/docs/")["type"] == "dir"
        assert reopened.read_file("/docs/a.txt") == b"inside"
        assert reopened.list_dir("/docs") == ["a.txt"]


class TestTamperedDirectoryEntries:
    """AES-GCM catches bit flips; these checks are the layer that stops a
    plausible-looking but wrong entry from being acted on at all."""

    @pytest.fixture
    def with_file(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"the original payload")
        vc.save()
        reopened = _reopen(path, key)
        return path, key, reopened

    def test_the_untampered_entry_reads_back(self, with_file):
        path, key, vc = with_file
        assert vc.read_file("/a.txt") == b"the original payload"
        assert vc.read_file_range("/a.txt", 4, 8) == b"original"

    def test_a_zero_chunk_entry_reads_as_empty(self, with_file):
        path, key, vc = with_file
        vc.dir_index["/a.txt"]["chunk_count"] = 0
        assert vc.read_file("/a.txt") == b""
        assert vc.read_file_range("/a.txt", 0, 10) == b""

    def test_a_zero_length_entry_reports_missing_data(self, with_file):
        path, key, vc = with_file
        vc.dir_index["/a.txt"]["data_length"] = 0
        with pytest.raises(ValueError, match="File data missing"):
            vc.read_file("/a.txt")

    def test_an_inflated_data_length_is_caught_as_truncation(self, with_file):
        path, key, vc = with_file
        vc.dir_index["/a.txt"]["data_length"] += 4096
        with pytest.raises(ValueError, match="truncated on disk"):
            vc.read_file("/a.txt")

    def test_an_inflated_data_length_is_caught_on_range_reads_too(self, with_file):
        path, key, vc = with_file
        vc.dir_index["/a.txt"]["data_length"] += 100
        with pytest.raises(ValueError, match="truncated on disk"):
            vc.read_file_range("/a.txt", 0, 4)

    def test_a_data_length_below_one_chunk_is_rejected_on_range_reads(self, with_file):
        path, key, vc = with_file
        vc.dir_index["/a.txt"]["data_length"] = 20   # < 8 header + 16 tag
        with pytest.raises(ValueError, match="does not fit in data_length"):
            vc.read_file_range("/a.txt", 0, 4)

    @pytest.mark.parametrize("bad", [-1, "seven", None])
    def test_a_non_positive_integer_chunk_count_is_rejected(self, with_file, bad):
        path, key, vc = with_file
        vc.dir_index["/a.txt"]["chunk_count"] = bad
        with pytest.raises(ValueError, match="Invalid chunk_count"):
            vc.read_file_range("/a.txt", 0, 4)

    def test_an_absurd_chunk_count_is_rejected_before_looping(self, with_file):
        """Without this bound a tampered entry with chunk_count = 2**32 would
        loop or OOM long before any AEAD tag could disagree."""
        path, key, vc = with_file
        vc.dir_index["/a.txt"]["chunk_count"] = 2 ** 32
        with pytest.raises(ValueError, match="exceeds what"):
            vc.read_file_range("/a.txt", 0, 4)

    def test_a_rewritten_chunk_sequence_number_is_rejected(self, with_file):
        path, key, vc = with_file
        _patch_blob_bytes(path, vc, "/a.txt", 0, struct.pack(">I", 9))
        fresh = _reopen(path, key)
        with pytest.raises(ValueError, match="sequence mismatch"):
            fresh.read_file("/a.txt")
        with pytest.raises(ValueError, match="sequence mismatch"):
            fresh.read_file_range("/a.txt", 0, 4)

    def test_a_rewritten_chunk_length_is_rejected_on_range_reads(self, with_file):
        path, key, vc = with_file
        real = vc.get_entry("/a.txt")["data_length"]
        _patch_blob_bytes(path, vc, "/a.txt", 4, struct.pack(">I", real))
        fresh = _reopen(path, key)
        with pytest.raises(ValueError, match="length mismatch"):
            fresh.read_file_range("/a.txt", 0, 4)


class TestAppendJournalDirectly:
    """_append_journal is the delta-save fast path; save() hands it a
    coalesced list, and a direct caller gets the coalescing for free."""

    def test_it_coalesces_when_called_without_ops(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"first")
        vc.write_file("/a.txt", b"second")     # supersedes the first
        vc._append_journal()
        assert vc.is_dirty is False
        reopened = _reopen(path, key)
        assert reopened.read_file("/a.txt") == b"second"
        assert list(reopened.dir_index) == ["/a.txt"]

    def test_a_write_whose_blob_vanished_is_not_persisted(self, volume):
        """A record with chunk_count > 0 and no body would reopen as an
        unreadable entry; skipping it keeps the container consistent."""
        path, key, vc = volume
        vc.write_file("/a.txt", b"payload")
        del vc._file_data["/a.txt"]            # blob lost before the append
        vc.save()
        reopened = _reopen(path, key)
        assert "/a.txt" not in reopened.dir_index
        assert reopened.journal_suspicious is False


class TestSetattrCoalescingAcrossRenames:
    """chmod/utimens are metadata on a *name*, so a rename in the same
    session has to carry them to the destination — otherwise the journal
    records them against a path replay never materialises."""

    def test_attributes_follow_an_in_session_write_through_a_rename(self, volume):
        """rsync's sequence: write /.f.tmp → chmod + utimes it → rename to
        /f.txt.  All three have to land on /f.txt."""
        path, key, vc = volume
        vc.write_file("/.f.tmp", b"payload")
        vc.set_attrs("/.f.tmp", mode=0o100755, mtime=1700000000)
        vc.rename("/.f.tmp", "/f.txt")
        vc.save()
        reopened = _reopen(path, key)
        entry = reopened.get_entry("/f.txt")
        assert reopened.read_file("/f.txt") == b"payload"
        assert entry["mode"] == 0o100755
        assert entry["mtime"] == 1700000000
        assert "/.f.tmp" not in reopened.dir_index

    def test_attributes_survive_a_rename_of_an_already_saved_path(self, volume):
        """`chmod +x foo && mv foo bar` on a file that was already saved.

        This test previously documented a defect (the change was lost on
        reopen). Fixed in run 12: the setattr stays on the *source* name and
        is emitted before the rename, because replay's rename moves the whole
        entry — so the attributes travel with it. Asserting the outcome
        rather than the shape of the coalesced record keeps this honest if
        the coalescer is reorganised again.
        """
        path, key, vc = volume
        vc.write_file("/foo", b"payload")
        vc.save()                                # /foo is now persisted

        session = _reopen(path, key)
        session.set_attrs("/foo", mode=0o100755, mtime=1700000000)
        session.rename("/foo", "/bar")
        session.save()
        assert session.get_entry("/bar")["mode"] == 0o100755   # in memory

        reopened = _reopen(path, key)
        entry = reopened.get_entry("/bar")
        assert reopened.read_file("/bar") == b"payload"
        assert entry["mode"] == 0o100755
        assert entry["mtime"] == 1700000000
        assert "/foo" not in reopened.dir_index

    def test_attributes_on_a_path_deleted_later_are_dropped(self, volume):
        path, key, vc = volume
        vc.write_file("/tmp.txt", b"scratch")
        vc.set_attrs("/tmp.txt", mode=0o100600)
        vc.delete("/tmp.txt")
        assert vc._coalesce_pending_ops() == []
        vc.save()
        assert _reopen(path, key).dir_index == {}


def _compact_temps(path):
    """The mkstemp scratch files compact() writes beside *path*."""
    d, base = os.path.split(path)
    return [os.path.join(d, n) for n in os.listdir(d)
            if n.startswith(f".{base}.qc-compact-")]


class TestCompactFailureLeavesNoDebris:
    """compact() needs ~2x the container size; the likely failure is disk
    full, and a failed compact must leave both disk and memory usable."""

    def test_a_truncated_source_aborts_and_removes_the_temp_file(self, volume):
        path, key, vc = volume
        vc.write_file("/a.bin", b"x" * 5000)
        vc.compact()
        # Truncate behind the open container's back, as a concurrent
        # writer or a failing disk would.
        with open(path, "r+b") as f:
            f.truncate(vc._data_offset + 10)
        # Run 19 F-202: refused before a temp file is even created — the
        # container is no longer what open() read (ESTALE), so the
        # mid-copy "truncated" ValueError is never reached.
        with pytest.raises(OSError) as ei:
            vc.compact()
        assert ei.value.errno == errno.ESTALE
        assert not _compact_temps(path)

    def test_a_failed_temp_cleanup_does_not_mask_the_real_error(
            self, volume, monkeypatch):
        path, key, vc = volume
        vc.write_file("/a.bin", b"x" * 5000)
        vc.compact()
        # A failure once the temp exists (the fsync of the new baseline);
        # shortening the source is refused earlier since run 19 F-202.
        def _refuse(_p):
            raise OSError(errno.EPERM, "cannot unlink")

        def _fail_fsync(_fd):
            raise OSError(errno.EIO, "Input/output error")

        monkeypatch.setattr(os, "unlink", _refuse)
        monkeypatch.setattr(os, "fsync", _fail_fsync)
        with pytest.raises(OSError) as ei:
            vc.compact()
        assert ei.value.errno == errno.EIO, "the real error, not the cleanup's"
        monkeypatch.undo()
        # The temp survives precisely because the cleanup failed — that is
        # the branch under test.
        temps = _compact_temps(path)
        assert len(temps) == 1
        os.remove(temps[0])

    def test_a_compacted_container_keeps_its_permission_bits(self, volume):
        """compact() used to open ``<path>.tmp`` with the umask, so the
        first compaction widened a 0600 container to 0644."""
        path, key, vc = volume
        os.chmod(path, 0o600)
        vc.write_file("/a.bin", b"x" * 5000)
        vc.compact()
        assert oct(os.stat(path).st_mode)[-3:] == "600"
        os.chmod(path, 0o640)
        vc.write_file("/b.bin", b"y" * 5000)
        vc.compact()
        assert oct(os.stat(path).st_mode)[-3:] == "640"


# ════════════════════════════════════════════════════════════════════════════
# fuse_ops.py
# ════════════════════════════════════════════════════════════════════════════

class TestFuseEnvironmentPreparation:
    """fusepy's Darwin loader never looks for libfuse-t.dylib, so a FUSE-T
    only machine needs FUSE_LIBRARY_PATH pointed at it."""

    FUSE_T = "/usr/local/lib/libfuse-t.dylib"

    def test_fuse_t_is_pointed_at_when_macfuse_is_absent(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("FUSE_LIBRARY_PATH", raising=False)
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "isfile", lambda p: p == self.FUSE_T)
        fo._prepare_fuse_environment()
        assert os.environ["FUSE_LIBRARY_PATH"] == self.FUSE_T

    def test_apple_silicon_homebrew_wins_over_the_intel_prefix(self, monkeypatch):
        """Both prefixes can exist on a machine that was migrated from an
        Intel Mac; the arm64 one is checked first and must be the one used."""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("FUSE_LIBRARY_PATH", raising=False)
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "isfile", lambda p: p in (
            "/opt/homebrew/lib/libfuse-t.dylib", self.FUSE_T))
        fo._prepare_fuse_environment()
        assert os.environ["FUSE_LIBRARY_PATH"] == \
            "/opt/homebrew/lib/libfuse-t.dylib"

    def test_macfuse_is_left_alone(self, monkeypatch):
        """The discriminating half: libfuse-t IS present, so the only reason
        not to point at it is that macFUSE was found first (fusepy's own
        loader handles that one)."""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("FUSE_LIBRARY_PATH", raising=False)
        monkeypatch.setattr(os.path, "isdir",
                            lambda p: p == "/Library/Filesystems/macfuse.fs")
        monkeypatch.setattr(os.path, "isfile", lambda p: p == self.FUSE_T)
        fo._prepare_fuse_environment()
        assert "FUSE_LIBRARY_PATH" not in os.environ

    def test_neither_backend_present_sets_nothing(self, monkeypatch):
        """No macFUSE and no libfuse-t: leave the variable alone so fusepy
        raises its own "no backend" error rather than one about a path."""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("FUSE_LIBRARY_PATH", raising=False)
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "isfile", lambda p: False)
        fo._prepare_fuse_environment()
        assert "FUSE_LIBRARY_PATH" not in os.environ

    def test_linux_is_never_touched(self, monkeypatch):
        """The whole helper is a Darwin workaround; on Linux libfuse is found
        by the dynamic loader and a stray override would break it."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("FUSE_LIBRARY_PATH", raising=False)
        monkeypatch.setattr(os.path, "isfile", lambda p: True)
        fo._prepare_fuse_environment()
        assert "FUSE_LIBRARY_PATH" not in os.environ

    def test_an_existing_setting_in_a_backend_location_is_kept(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setenv("FUSE_LIBRARY_PATH", "/usr/local/lib/libfuse-custom.dylib")
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "isfile", lambda p: True)
        fo._prepare_fuse_environment()
        assert os.environ["FUSE_LIBRARY_PATH"] == "/usr/local/lib/libfuse-custom.dylib"

    def test_a_preset_outside_every_backend_location_is_dropped(self, monkeypatch):
        """fusepy hands the variable to ctypes.CDLL inside the process that
        holds every mounted volume's key, so a value planted in the app's
        environment must not pick the library.  The FUSE-T fallback then
        applies as if nothing had been set."""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setenv("FUSE_LIBRARY_PATH", "/tmp/evil/libfuse.dylib")
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "isfile", lambda p: True)
        fo._prepare_fuse_environment()
        assert os.environ["FUSE_LIBRARY_PATH"] == "/opt/homebrew/lib/libfuse-t.dylib"

    def test_a_preset_that_is_not_a_file_is_dropped(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setenv("FUSE_LIBRARY_PATH", "/usr/local/lib/missing.dylib")
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "isfile", lambda p: False)
        fo._prepare_fuse_environment()
        assert "FUSE_LIBRARY_PATH" not in os.environ


class TestFuseAvailabilityReporting:
    """The guided-setup screen renders these strings; they have to say which
    half is missing, because the fixes are different commands."""

    def test_a_missing_fusepy_says_how_to_install_it(self, monkeypatch):
        # None in sys.modules is what a stripped install looks like to
        # `import fuse`: ImportError, not ModuleNotFoundError-on-disk.
        monkeypatch.setitem(sys.modules, "fuse", None)
        ok, msg = fo.check_fuse_available()
        assert ok is False
        assert "pip install fusepy" in msg
        assert "macfuse" in msg

    def test_components_report_fusepy_separately_from_the_backend(
            self, monkeypatch):
        """The two halves are independent: a missing fusepy must not be
        reported as a missing backend, because the fixes differ."""
        monkeypatch.setitem(sys.modules, "fuse", None)
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(
            os.path, "isfile",
            lambda p: p == "/opt/homebrew/lib/libfuse-t.dylib")
        comps = fo.check_fuse_components()
        assert comps["fusepy"] == {"ok": False,
                                   "detail": "fusepy is not installed"}
        assert comps["fuse_backend"] == {"ok": True, "detail": "FUSE-T detected"}

    @pytest.mark.parametrize("present,expected_ok,expected_detail", [
        ("/opt/homebrew/lib/libfuse-t.dylib", True, "FUSE-T detected"),
        ("/usr/local/lib/libfuse-t.dylib", True, "FUSE-T detected"),
        ("/Library/Filesystems/macfuse.fs", True, "macFUSE detected"),
        ("/Library/Filesystems/osxfuse.fs", True, "osxfuse detected"),
        (None, False, "No FUSE backend found (macFUSE or FUSE-T)"),
    ])
    def test_each_macos_backend_is_named_in_the_setup_screen(
            self, monkeypatch, present, expected_ok, expected_detail):
        """The guided-setup screen prints this detail verbatim, and the
        install command it then offers depends on which backend was found."""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(os.path, "isfile", lambda p: p == present)
        monkeypatch.setattr(os.path, "isdir", lambda p: p == present)
        backend = fo.check_fuse_components()["fuse_backend"]
        assert backend == {"ok": expected_ok, "detail": expected_detail}

    @pytest.mark.parametrize("tool,dev_fuse,expected", [
        ("fusermount", False, {"ok": True, "detail": "FUSE detected"}),
        ("fusermount3", False, {"ok": True, "detail": "FUSE detected"}),
        (None, True, {"ok": True, "detail": "FUSE detected"}),
        (None, False, {"ok": False,
                       "detail": "No FUSE backend found (libfuse)"}),
    ])
    def test_the_linux_backend_is_detected_three_ways(
            self, monkeypatch, tool, dev_fuse, expected):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(shutil, "which",
                            lambda name: "/bin/x" if name == tool else None)
        monkeypatch.setattr(os.path, "exists",
                            lambda p: dev_fuse and p == "/dev/fuse")
        assert fo.check_fuse_components()["fuse_backend"] == expected

    def test_available_when_fusepy_imports(self):
        fusepy_backend()
        ok, msg = fo.check_fuse_available()
        assert ok is True and "available" in msg


class TestMaxWritableBytes:
    """The write path holds ~4x the file in RAM, so statfs caps free space
    at what that can survive — an unknown page count must not cap anything."""

    def test_an_unknown_page_size_does_not_constrain(self, monkeypatch):
        def _refuse(_name):
            raise ValueError("unknown configuration name")

        monkeypatch.setattr(os, "sysconf", _refuse)
        assert fo._max_writable_bytes() == 1 << 40

    def test_a_known_page_count_yields_an_eighth_of_ram(self, monkeypatch):
        values = {"SC_PAGE_SIZE": 4096, "SC_PHYS_PAGES": 1 << 20}  # 4 GB
        monkeypatch.setattr(os, "sysconf", lambda n: values[n])
        assert fo._max_writable_bytes() == (4 << 30) // 2 // 4

    def test_a_tiny_machine_still_gets_the_64mb_floor(self, monkeypatch):
        values = {"SC_PAGE_SIZE": 4096, "SC_PHYS_PAGES": 16}
        monkeypatch.setattr(os, "sysconf", lambda n: values[n])
        assert fo._max_writable_bytes() == 64 * 1024 * 1024

    @pytest.mark.parametrize("ram_mb,expected_mb", [
        (511, 64),      # below the floor: clamped up
        (512, 64),      # exactly the floor: 512/2/4 == 64 MB
        (520, 65),      # just above: the computed value wins, unclamped
    ])
    def test_the_floor_applies_on_the_right_side_only(self, monkeypatch,
                                                      ram_mb, expected_mb):
        """Both sides of the 64 MB clamp.  A floor that also applied above
        the boundary would silently cap every machine at 64 MB per file."""
        page = 4096
        values = {"SC_PAGE_SIZE": page,
                  "SC_PHYS_PAGES": (ram_mb << 20) // page}
        monkeypatch.setattr(os, "sysconf", lambda n: values[n])
        assert fo._max_writable_bytes() == expected_mb << 20

    def test_a_missing_sysconf_does_not_constrain_either(self, monkeypatch):
        """Windows/Emscripten have no os.sysconf at all — an AttributeError,
        not the ValueError above."""
        monkeypatch.delattr(os, "sysconf")
        assert fo._max_writable_bytes() == 1 << 40


class TestStatfs:
    """Finder's copy pre-flight reads these numbers; a zero here refuses
    every copy into the mount."""

    def test_free_space_is_the_host_free_space_in_4k_blocks(self, volume,
                                                            monkeypatch):
        """The exact arithmetic, against a fixed host.

        Deliberately not compared with a second live os.statvfs call: real
        free space moves between the two syscalls whenever anything else on
        the machine writes a block, which makes an equality assertion fail at
        random (it did).
        """
        path, key, vc = volume
        vc.write_file("/a.txt", b"z" * 8192)     # 8 KB of plaintext held
        fs = QuantaCryptFUSE(vc)

        class _Host:
            f_bavail = 1000
            f_frsize = 8192                      # 8 MB free, in 8 KB blocks

        monkeypatch.setattr(os, "statvfs", lambda _p: _Host())
        st = fs.statfs("/")
        free = 1000 * 8192
        assert st["f_bsize"] == 4096 and st["f_frsize"] == 4096
        assert st["f_bavail"] == free // 4096
        assert st["f_bfree"] == free // 4096
        assert st["f_blocks"] == (8192 + free) // 4096   # used + free
        assert st["f_namemax"] == 255

    def test_the_host_looked_at_is_the_one_holding_the_container(self, volume,
                                                                 monkeypatch):
        """A volume on an external disk must report that disk's free space,
        not the boot drive's — so the path handed to statvfs matters."""
        path, key, vc = volume
        asked = []
        real = os.statvfs
        monkeypatch.setattr(os, "statvfs",
                            lambda p: (asked.append(p), real(p))[1])
        st = QuantaCryptFUSE(vc).statfs("/")
        assert asked == [os.path.dirname(os.path.abspath(path))]
        # And the number really came from there rather than the 1 TB
        # unstat-able fallback or a hardcoded zero.
        host_free = real(asked[0]).f_bavail * real(asked[0]).f_frsize
        assert 0 < st["f_bavail"] * 4096 <= host_free + (1 << 26)
        assert st["f_bavail"] != (1 << 40) // 4096

    def test_an_unstatable_host_claims_a_terabyte(self, volume, monkeypatch):
        path, key, vc = volume
        vc.write_file("/a.txt", b"abcdefgh")
        fs = QuantaCryptFUSE(vc)

        def _refuse(_p):
            raise OSError(errno.EIO, "host is gone")

        monkeypatch.setattr(os, "statvfs", _refuse)
        st = fs.statfs("/")
        assert st["f_bavail"] == (1 << 40) // 4096
        assert st["f_blocks"] == (8 + (1 << 40)) // 4096

    @pytest.mark.parametrize("entries,expected", [
        ([], 0),                                   # empty volume
        ([("f", "/only.txt")], 1),                 # one
        ([("d", "/d"), ("f", "/d/a.txt"), ("f", "/b.txt")], 3),   # many
    ])
    def test_file_and_dir_counts_are_reported(self, volume, entries, expected):
        """f_files counts files AND directories; zero, one and many."""
        path, key, vc = volume
        for kind, vpath in entries:
            if kind == "d":
                vc.mkdir(vpath)
            else:
                vc.write_file(vpath, b"x")
        st = QuantaCryptFUSE(vc).statfs("/")
        assert st["f_files"] == expected


class TestFuseReadWriteEdges:
    """read()/write() are the hot path; the boundary cases decide whether a
    tool sees a short read or a zeroed file."""

    @pytest.fixture
    def fs(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"0123456789")
        vc.save()
        return path, key, vc, QuantaCryptFUSE(vc)

    def test_reading_a_missing_path_is_enoent(self, fs):
        _, _, _, f = fs
        with pytest.raises(OSError) as exc:
            f.read("/ghost.txt", 10, 0, 1)
        assert exc.value.errno == errno.ENOENT

    @pytest.mark.parametrize("size,offset", [(0, 0), (-1, 0), (5, 10), (5, 99)])
    def test_reads_at_or_past_eof_return_nothing(self, fs, size, offset):
        # offset 10 == size is the boundary itself; 99 is well past it.
        _, _, _, f = fs
        assert f.read("/a.txt", size, offset, 1) == b""

    @pytest.mark.parametrize("size,offset,expected", [
        (1, 0, b"0"),          # smallest useful read, at the start
        (10, 0, b"0123456789"),  # exactly the whole file
        (5, 9, b"9"),          # offset n-1: the last byte still comes back
        (1, 9, b"9"),
    ])
    def test_reads_inside_the_file_return_exactly_those_bytes(
            self, fs, size, offset, expected):
        _, _, _, f = fs
        assert f.read("/a.txt", size, offset, 1) == expected

    def test_a_read_spanning_eof_returns_what_exists(self, fs):
        _, _, _, f = fs
        assert f.read("/a.txt", 100, 6, 1) == b"6789"

    def test_writing_to_an_unknown_path_starts_from_an_empty_buffer(self, fs):
        path, key, vc, f = fs
        assert f.write("/fresh.txt", b"new bytes", 0, 1) == 9
        f.flush("/fresh.txt", 1)
        assert _reopen(path, key).read_file("/fresh.txt") == b"new bytes"

    def test_writing_into_a_directory_path_starts_empty_too(self, fs):
        """A write against a directory path must not try to materialise the
        directory as plaintext; it starts a fresh buffer, and the directory
        entry itself is left intact underneath."""
        path, key, vc, f = fs
        vc.mkdir("/d")
        assert f.write("/d/", b"x", 0, 1) == 1
        assert f.read("/d/", 10, 0, 1) == b"x"
        assert vc.get_entry("/d/")["type"] == "dir"

    def test_an_existing_file_is_materialised_before_a_partial_write(self, fs):
        """open() no longer decrypts eagerly, so the first write has to load
        the plaintext or everything outside its range becomes zeros."""
        path, key, vc, f = fs
        f.write("/a.txt", b"XY", 4, 1)
        f.flush("/a.txt", 1)
        assert _reopen(path, key).read_file("/a.txt") == b"0123XY6789"


class TestDeferredUnlinkRaces:
    """POSIX delete-on-last-close: the deferred delete can find the entry
    already gone, and that is not an error."""

    def test_release_tolerates_an_entry_deleted_underneath_it(self, volume):
        path, key, vc = volume
        f = QuantaCryptFUSE(vc)
        fd = f.create("/tmp.swp", 0o100644)
        f.unlink("/tmp.swp")
        assert "/tmp.swp" in f._pending_unlink
        vc.delete("/tmp.swp")             # vanishes behind FUSE's back
        f.release("/tmp.swp", fd)
        assert "/tmp.swp" not in f._pending_unlink
        assert vc.get_entry("/tmp.swp") is None

    def test_apply_pending_unlinks_tolerates_the_same(self, volume):
        path, key, vc = volume
        f = QuantaCryptFUSE(vc)
        f.create("/tmp.swp", 0o100644)
        f.unlink("/tmp.swp")
        vc.delete("/tmp.swp")
        f.apply_pending_unlinks()
        assert f._pending_unlink == set()
        assert "/tmp.swp" not in _reopen(path, key).dir_index

    def test_an_unlinked_but_open_file_is_never_persisted(self, volume):
        path, key, vc = volume
        f = QuantaCryptFUSE(vc)
        fd = f.create("/tmp.swp", 0o100644)
        f.write("/tmp.swp", b"scratch", 0, fd)
        f.unlink("/tmp.swp")
        f.save_all_dirty()
        assert "/tmp.swp" not in _reopen(path, key).dir_index


class TestSaveAllDirty:
    """unmount and the emergency paths both come through here; a volume that
    is dirty without any buffered FUSE write still has to be persisted."""

    def test_a_dirty_volume_with_no_buffers_is_saved(self, volume):
        path, key, vc = volume
        vc.write_file("/a.txt", b"container-level write")
        f = QuantaCryptFUSE(vc)
        assert f._dirty_files == set()
        f.save_all_dirty(apply_pending_unlink=False)
        assert vc.is_dirty is False
        assert _reopen(path, key).read_file("/a.txt") == b"container-level write"

    def test_an_uncontended_lock_timeout_still_saves(self, volume):
        path, key, vc = volume
        f = QuantaCryptFUSE(vc)
        f.write("/b.txt", b"buffered", 0, 1)
        f.save_all_dirty(lock_timeout=5.0)
        assert _reopen(path, key).read_file("/b.txt") == b"buffered"

    def test_a_held_lock_is_skipped_rather_than_waited_on(self, volume):
        """The signal path must not hang the process on a busy volume."""
        path, key, vc = volume
        f = QuantaCryptFUSE(vc)
        f.write("/c.txt", b"buffered", 0, 1)
        held = threading.Event()
        release = threading.Event()

        def _hold():
            with f._lock:
                held.set()
                release.wait(5)

        t = threading.Thread(target=_hold)
        t.start()
        try:
            assert held.wait(5)
            started = time.monotonic()
            f.save_all_dirty(lock_timeout=0.05)
            waited = time.monotonic() - started
            assert "/c.txt" in f._dirty_files      # skipped, not flushed
            # It gave up near the timeout instead of blocking on the holder,
            # which keeps the SIGTERM path bounded.
            assert waited < 2.0
            # And nothing reached the container, so the skip really was a
            # skip rather than a save that happened to leave the flag set.
            assert "/c.txt" not in _reopen(path, key).dir_index
        finally:
            release.set()
            t.join(5)


class TestVolumeLockRelease:
    """The flock fd is dropped by closing it; a stale fd must still clear the
    tracking entry or the volume can never be remounted."""

    def test_a_stale_descriptor_still_clears_the_entry(self):
        fo._volume_locks["/mnt/stale"] = 1_000_000   # certainly not open
        fo._release_volume_lock("/mnt/stale")
        assert "/mnt/stale" not in fo._volume_locks

    def test_an_untracked_mount_point_is_a_no_op(self):
        """Releasing a mount point we never locked must not disturb the locks
        we do hold — a stray close() here would unlock a live mount."""
        fo._volume_locks["/mnt/other"] = 1_000_001
        before = dict(fo._volume_locks)
        fo._release_volume_lock("/mnt/never-locked")
        assert fo._volume_locks == before
        assert fo._volume_locks["/mnt/other"] == 1_000_001


class TestReapDeadMounts:
    """An external eject (Finder, umount, backend crash) ends the worker
    thread without ever calling unmount_volume."""

    @staticmethod
    def _dead_thread():
        t = threading.Thread(target=lambda: None)
        t.start()
        t.join()
        return t

    def test_an_ejected_mount_is_saved_and_untracked(self, volume):
        path, key, vc = volume
        f = QuantaCryptFUSE(vc)
        f.write("/late.txt", b"written just before the eject", 0, 1)
        fo._mounted_volumes["/mnt/ejected"] = {
            "thread": self._dead_thread(), "volume": vc,
            "fuse": f, "volume_path": path,
        }
        assert "/mnt/ejected" not in fo.get_mounted_volumes()
        assert _reopen(path, key).read_file("/late.txt") == \
            b"written just before the eject"

    def test_an_ejected_mount_without_a_fuse_object_still_saves(self, volume):
        path, key, vc = volume
        vc.write_file("/late.txt", b"container write")
        fo._mounted_volumes["/mnt/ejected"] = {
            "thread": self._dead_thread(), "volume": vc,
            "fuse": None, "volume_path": path,
        }
        assert "/mnt/ejected" not in fo.get_mounted_volumes()
        assert _reopen(path, key).read_file("/late.txt") == b"container write"

    def test_a_failing_post_eject_save_still_reclaims_the_entry(self, volume):
        """Otherwise every remount fails with "mounted by another process"
        for the lifetime of the app."""
        path, key, vc = volume
        vc.write_file("/late.txt", b"doomed")
        os.remove(path)                  # save() will raise
        fo._mounted_volumes["/mnt/ejected"] = {
            "thread": self._dead_thread(), "volume": vc,
            "fuse": None, "volume_path": path,
        }
        fo._volume_locks["/mnt/ejected"] = 1_000_000
        assert "/mnt/ejected" not in fo.get_mounted_volumes()
        assert "/mnt/ejected" not in fo._volume_locks

    def test_a_live_mount_is_left_alone(self, volume):
        path, key, vc = volume
        vc.write_file("/live.txt", b"still being written")
        stop = threading.Event()
        t = threading.Thread(target=lambda: stop.wait(10), daemon=True)
        t.start()
        try:
            fo._mounted_volumes["/mnt/live"] = {
                "thread": t, "volume": vc, "fuse": None, "volume_path": path,
            }
            assert "/mnt/live" in fo.get_mounted_volumes()
            # The discriminator against the reaped case: reaping saves the
            # volume, so a still-dirty container proves nothing was reaped.
            assert vc.is_dirty is True
            assert "/live.txt" not in _reopen(path, key).dir_index
        finally:
            stop.set()
            t.join(5)

    def test_a_thread_less_entry_is_left_alone(self, volume):
        """Liveness is unknowable for direct-API entries, so they persist."""
        path, key, vc = volume
        vc.write_file("/injected.txt", b"unsaved")
        fo._mounted_volumes["/mnt/injected"] = {
            "thread": None, "volume": vc, "fuse": None, "volume_path": path,
        }
        assert "/mnt/injected" in fo.get_mounted_volumes()
        assert vc.is_dirty is True
        assert "/injected.txt" not in _reopen(path, key).dir_index


class TestEmergencySaveAll:
    """atexit and the signal handler run this; one volume disappearing must
    not cost the others their data."""

    def test_a_concurrently_removed_entry_is_skipped(self, volume, monkeypatch):
        path, key, vc = volume
        vc.write_file("/kept.txt", b"survives")

        class _Vanishing(dict):
            """A key that is listed and then gone — a concurrent unmount."""
            def get(self, key, default=None):
                if key == "/mnt/vanishing":
                    self.pop(key, None)
                    return default
                return super().get(key, default)

        registry = _Vanishing()
        registry["/mnt/vanishing"] = {"thread": None, "volume": vc,
                                      "fuse": None, "volume_path": path}
        registry["/mnt/real"] = {"thread": None, "volume": vc,
                                 "fuse": None, "volume_path": path}
        monkeypatch.setattr(fo, "_mounted_volumes", registry)
        fo._emergency_save_all()
        # The loop carried on past the vanished entry and saved the real one.
        assert "/mnt/vanishing" not in registry
        assert _reopen(path, key).read_file("/kept.txt") == b"survives"

    def test_a_failing_volume_does_not_stop_the_others(self, tmp_path,
                                                       blank_volume, monkeypatch):
        blob, key = blank_volume
        good = str(tmp_path / "good.qcv")
        bad = str(tmp_path / "bad.qcv")
        for p in (good, bad):
            with open(p, "wb") as f:
                f.write(blob)
        good_vc = _reopen(good, key)
        bad_vc = _reopen(bad, key)
        good_vc.write_file("/g.txt", b"saved anyway")
        bad_vc.write_file("/b.txt", b"lost")
        os.remove(bad)                     # its save() will raise

        registry = {
            "/mnt/bad": {"thread": None, "volume": bad_vc, "fuse": None,
                         "volume_path": bad},
            "/mnt/good": {"thread": None, "volume": good_vc, "fuse": None,
                          "volume_path": good},
        }
        monkeypatch.setattr(fo, "_mounted_volumes", registry)
        fo._emergency_save_all()
        assert _reopen(good, key).read_file("/g.txt") == b"saved anyway"


class TestMountVolume:
    """mount_volume owns the cross-process flock and the tracking entry; a
    failed startup must leave neither behind."""

    @staticmethod
    def _lock_is_free(path):
        """True when the cross-process flock on *path* can be taken.

        A real predicate rather than a bare "it didn't raise": the callers
        below assert on the value, and a helper that returned True
        unconditionally would make every one of those assertions vacuous.
        """
        try:
            fd = fo._acquire_volume_lock(path)
        except RuntimeError:
            return False
        os.close(fd)
        return True

    def test_the_lock_predicate_detects_a_held_lock(self, volume):
        """Guard for the helper the other tests in this class rely on."""
        path, key, vc = volume
        assert self._lock_is_free(path) is True
        held = fo._acquire_volume_lock(path)
        try:
            assert self._lock_is_free(path) is False
        finally:
            os.close(held)
        assert self._lock_is_free(path) is True

    def test_a_foreground_mount_returns_and_releases_the_lock(
            self, volume, tmp_path, monkeypatch):
        fusepy = fusepy_backend()
        path, key, vc = volume
        seen = {}

        def _fake_fuse(ops, mount_point, **kwargs):
            seen["ops"] = ops
            seen["mount_point"] = mount_point
            seen["volname"] = kwargs.get("volname")

        monkeypatch.setattr(fusepy, "FUSE", _fake_fuse)
        mp = str(tmp_path / "mnt")
        obj = fo.mount_volume(path, key, mp, foreground=True)
        assert isinstance(obj, QuantaCryptFUSE)
        assert seen["ops"] is obj
        assert seen["mount_point"] == mp
        # Named after the container (run 13 F-004), not a constant.
        assert seen["volname"] == os.path.splitext(os.path.basename(path))[0]
        assert os.path.isdir(mp)               # created for us
        assert mp not in fo._mounted_volumes   # foreground never registers
        assert self._lock_is_free(path)

    def test_a_worker_that_exits_without_error_is_not_registered(
            self, volume, tmp_path, monkeypatch):
        fusepy = fusepy_backend()
        path, key, vc = volume
        monkeypatch.setattr(fo, "_FUSE_STARTUP_TIMEOUT", 1.0)
        monkeypatch.setattr(fusepy, "FUSE", lambda *a, **kw: None)
        mp = str(tmp_path / "mnt")
        with pytest.raises(RuntimeError, match="exited before the mount"):
            fo.mount_volume(path, key, mp)
        assert fo._mounted_volumes == {}
        assert self._lock_is_free(path)

    def test_a_worker_that_raises_reports_the_reason(
            self, volume, tmp_path, monkeypatch):
        fusepy = fusepy_backend()
        path, key, vc = volume
        monkeypatch.setattr(fo, "_FUSE_STARTUP_TIMEOUT", 1.0)

        def _boom(*a, **kw):
            raise RuntimeError("no libfuse backend")

        monkeypatch.setattr(fusepy, "FUSE", _boom)
        mp = str(tmp_path / "mnt")
        with pytest.raises(RuntimeError, match="no libfuse backend"):
            fo.mount_volume(path, key, mp)
        assert fo._mounted_volumes == {}
        assert self._lock_is_free(path)

    def test_a_serving_mount_is_registered_with_its_lock(
            self, volume, tmp_path, monkeypatch):
        fusepy = fusepy_backend()
        path, key, vc = volume
        serving = threading.Event()
        monkeypatch.setattr(fo, "_FUSE_STARTUP_TIMEOUT", 0.3)
        monkeypatch.setattr(fusepy, "FUSE",
                            lambda *a, **kw: serving.wait(10))
        mp = str(tmp_path / "mnt")
        try:
            obj = fo.mount_volume(path, key, mp)
            info = fo.get_mounted_volumes()[mp]
            assert info["fuse"] is obj
            assert info["volume_path"] == path
            assert info["volume"].path == path
            assert mp in fo._volume_locks
            # A second mount of the same container is refused by real path.
            with pytest.raises(RuntimeError, match="already mounted"):
                fo.mount_volume(path, key, str(tmp_path / "mnt2"))
        finally:
            serving.set()

    def test_a_mount_that_loses_the_registration_race_releases_its_lock(
            self, volume, tmp_path, monkeypatch):
        """Two racers can both pass the snapshot check; the loser must not
        strand the flock, or the volume becomes unmountable."""
        fusepy_backend()
        path, key, vc = volume
        mp = str(tmp_path / "mnt")

        def _inject_competitor():
            fo._mounted_volumes["/mnt/other"] = {
                "thread": None, "volume": vc, "fuse": None,
                "volume_path": path,
            }
            return True, "fusepy is available"

        monkeypatch.setattr(fo, "check_fuse_available",
                            lambda: _inject_competitor())
        with pytest.raises(RuntimeError, match="already mounted at /mnt/other"):
            fo.mount_volume(path, key, mp)
        assert mp not in fo._mounted_volumes
        assert self._lock_is_free(path)

    def test_an_already_mounted_container_is_refused_up_front(self, volume,
                                                              tmp_path):
        path, key, vc = volume
        mp = str(tmp_path / "mnt")
        fo._mounted_volumes["/mnt/first"] = {
            "thread": None, "volume": vc, "fuse": None, "volume_path": path,
        }
        with pytest.raises(RuntimeError, match="already mounted at /mnt/first"):
            fo.mount_volume(path, key, mp)
        # Refused before anything was claimed: no flock, no tracking entry,
        # and no mount directory created on the user's disk.
        assert self._lock_is_free(path) is True
        assert mp not in fo._mounted_volumes
        assert not os.path.exists(mp)

    def test_a_second_process_holding_the_flock_is_refused(self, volume,
                                                           tmp_path):
        path, key, vc = volume
        held = fo._acquire_volume_lock(path)
        try:
            with pytest.raises(RuntimeError, match="another process"):
                fo._acquire_volume_lock(path)
        finally:
            os.close(held)
        # Released again once the holder closes its descriptor.
        assert self._lock_is_free(path)


class TestUnmountVolume:
    """unmount only ever runs the external tool for paths we own, and a
    failure has to leave the mount reachable for a retry."""

    @pytest.fixture
    def tracked(self, volume, tmp_path):
        path, key, vc = volume
        f = QuantaCryptFUSE(vc)
        mp = str(tmp_path / "mnt")
        os.makedirs(mp, exist_ok=True)
        fo._mounted_volumes[mp] = {
            "thread": None, "volume": vc, "fuse": f, "volume_path": path,
        }
        return path, key, vc, f, mp

    def test_an_untracked_mount_point_is_refused(self, tracked, tmp_path):
        """Never run umount against a path we did not mount, and never let
        that refusal disturb the mounts we do own."""
        _, _, _, _, mp = tracked
        before = dict(fo._mounted_volumes)
        with pytest.raises(ValueError, match="already have been ejected"):
            fo.unmount_volume(str(tmp_path / "not-ours"))
        assert fo._mounted_volumes == before
        assert mp in fo._mounted_volumes

    def test_linux_uses_fusermount(self, tracked, monkeypatch):
        path, key, vc, f, mp = tracked
        f.write("/pending.txt", b"flushed on unmount", 0, 1)
        calls = []

        class _Result:
            returncode = 0
            stdout = stderr = ""

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(shutil, "which", lambda tool: None)
        monkeypatch.setattr(subprocess, "run",
                            lambda cmd, **kw: (calls.append(cmd), _Result())[1])
        fo.unmount_volume(mp)
        # The chosen command is the only observable effect of the branch.
        assert calls == [["fusermount", "-u", mp]]
        assert mp not in fo._mounted_volumes
        assert _reopen(path, key).read_file("/pending.txt") == \
            b"flushed on unmount"

    def test_linux_prefers_fusermount3_when_present(self, tracked, monkeypatch):
        path, key, vc, f, mp = tracked
        calls = []

        class _Result:
            returncode = 0
            stdout = stderr = ""

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(shutil, "which",
                            lambda tool: "/bin/fusermount3"
                            if tool == "fusermount3" else None)
        monkeypatch.setattr(subprocess, "run",
                            lambda cmd, **kw: (calls.append(cmd), _Result())[1])
        f.write("/pending.txt", b"flushed on unmount", 0, 1)
        fo.unmount_volume(mp)
        assert calls == [["fusermount3", "-u", mp]]
        assert mp not in fo._mounted_volumes
        assert _reopen(path, key).read_file("/pending.txt") == \
            b"flushed on unmount"

    def test_a_hung_unmount_tool_keeps_the_mount_tracked(self, tracked,
                                                         monkeypatch):
        path, key, vc, f, mp = tracked

        def _hang(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 30))

        monkeypatch.setattr(subprocess, "run", _hang)
        with pytest.raises(RuntimeError, match="timed out"):
            fo.unmount_volume(mp)
        # Still ours: emergency save and a retry must be able to reach it.
        assert mp in fo._mounted_volumes

    def test_a_failing_unmount_reports_the_tool_output(self, tracked,
                                                       monkeypatch):
        path, key, vc, f, mp = tracked

        class _Result:
            returncode = 1
            stdout = ""
            stderr = "Resource busy"

        monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Result())
        with pytest.raises(RuntimeError, match="Resource busy"):
            fo.unmount_volume(mp)
        assert mp in fo._mounted_volumes


# ════════════════════════════════════════════════════════════════════════════
# package.py
# ════════════════════════════════════════════════════════════════════════════

class TestExtractShareCodes:
    """"Load from file…" and "Paste all" both go through this, so it has to
    survive headers, prose, and a share with a typo in it."""

    @pytest.fixture(scope="class")
    @classmethod
    def three_shares(cls):
        """Three (code, mnemonic) pairs, built from fixed values.

        Deliberately NOT from shamir_split(): the mnemonic carries an 8-bit
        checksum, so a typo-detection test built on a random share passes
        only 255 times out of 256.  extract_share_codes never reconstructs a
        secret — it only parses — so any well-formed share serves, and a
        fixed one makes the outcome the same on every run.
        """
        out = []
        for i in (1, 2, 3):
            value = int.from_bytes(
                hashlib.sha512(f"qc-core-edges-{i}".encode()).digest(),
                "big") % cc.SHAMIR_PRIME
            share = {"index": i, "value": value,
                     "modulus": cc.SHAMIR_PRIME, "threshold": 2}
            out.append((cc.encode_share(share), cc.share_to_mnemonic(share)))
        return out

    @pytest.fixture(scope="class")
    @classmethod
    def one_share(cls, three_shares):
        return three_shares[0]

    def test_a_genuine_shamir_share_is_recognised_in_both_forms(self):
        """The fixed shares above keep the parser tests deterministic; this
        one proves the parser still agrees with what shamir_split actually
        emits."""
        raw = cc.shamir_split(secrets.token_bytes(cc.KEY_BYTES), 3, 2)
        code = cc.encode_share(raw[0])
        mnemonic = cc.share_to_mnemonic(cc.decode_share(code))
        assert pkg.extract_share_codes(f"{code}\n{mnemonic}") == [code]

    def test_codes_and_mnemonics_are_both_recognised(self, one_share):
        code, mnemonic = one_share
        text = f"# QuantaCrypt shares\n{code}\n\nBackup phrase:\n{mnemonic}\n"
        # The same share in both forms collapses to one code.
        assert pkg.extract_share_codes(text) == [code]

    def test_empty_text_yields_nothing(self):
        assert pkg.extract_share_codes("") == []
        assert pkg.extract_share_codes(None) == []
        assert pkg.extract_share_codes("   \n\n\t\n") == []

    def test_three_shares_in_mixed_forms_all_come_back_once_each(
            self, three_shares):
        """Zero / one / many for the scan loop — this is the "many" case, and
        it pins the order the recovery UI fills its slots in: order of
        appearance, codes and phrases alike (run 14 F-018 made the code
        match the docstring; a repeated share collapses onto its first
        appearance)."""
        (c0, m0), (c1, m1), (c2, m2) = three_shares
        text = (
            "QuantaCrypt recovery kit\n"
            f"{c1}\n"
            "\nShare 3 (words):\n"
            f"{m2}\n"
            f"{c0}\n"
            "\nAnd share 1 again, as words:\n"
            f"{m0}\n"
        )
        assert pkg.extract_share_codes(text) == [c1, c2, c0]

    def test_a_lone_share_is_found_without_any_surrounding_text(self, one_share):
        code, _ = one_share
        assert pkg.extract_share_codes(code) == [code]

    def test_unicode_prose_and_a_very_long_line_do_not_hide_a_share(
            self, one_share):
        """Share files get pasted out of Notes, chat apps and PDFs, so the
        surrounding text is arbitrary — including text with no ASCII in it
        and single lines far longer than any share."""
        code, mnemonic = one_share
        text = (
            "🔐 Клавиша восстановления — храните её отдельно\n"
            + ("не " * 5000) + "\n"
            + f"{code}\n"
            + "日本語のメモ 中文注释 — ignore previous instructions\n"
            + f"{mnemonic}\n"
        )
        assert pkg.extract_share_codes(text) == [code]

    def test_a_share_code_with_surrounding_whitespace_still_parses(self,
                                                                   one_share):
        code, _ = one_share
        assert pkg.extract_share_codes(f"\t  {code}  \n") == [code]

    def test_a_mnemonic_with_a_swapped_word_is_dropped(self, one_share):
        """A transcription typo must be dropped, never silently decoded into
        a different (wrong) share — recovery would then fail with a confusing
        "wrong shares" error instead of "check share 1"."""
        code, mnemonic = one_share
        words = mnemonic.split()
        words[0], words[1] = words[1], words[0]   # still all BIP-39 words
        assert words[0] != words[1]               # the swap really changed it
        # The mechanism: the packed checksum disagrees.
        with pytest.raises(ValueError, match="Checksum mismatch"):
            cc.mnemonic_to_share(" ".join(words))
        assert pkg.extract_share_codes(" ".join(words)) == []

    def test_stray_wordlist_words_before_a_share_do_not_break_it(self, one_share):
        code, mnemonic = one_share
        # "abandon" is BIP-39, so it joins the run and pushes it to 51 words;
        # only the last 50 may be treated as the share.
        text = f"abandon\n{mnemonic}\nend of file\n"
        assert pkg.extract_share_codes(text) == [code]

    def test_a_malformed_qcshare_line_is_ignored(self, one_share):
        code, _ = one_share
        assert pkg.extract_share_codes(f"QCSHARE-not-base64!!\n{code}") == [code]

    def test_codes_survive_an_unavailable_wordlist(self, one_share, monkeypatch):
        code, mnemonic = one_share

        def _no_wordlist():
            raise RuntimeError("mnemonic package is missing")

        monkeypatch.setattr(cc, "_load_wordlist", _no_wordlist)
        # Codes still parse; only the mnemonic half is given up on.
        assert pkg.extract_share_codes(f"{code}\n{mnemonic}") == [code]


@pytest.mark.skipif(sys.platform != "darwin",
                    reason="quarantine xattrs are a macOS concept")
class TestQuarantineMarking:
    """A .qcx is a transport container for someone else's content, so the
    decrypted output has to look downloaded to Gatekeeper."""

    @staticmethod
    def _quarantine(path):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.getxattr.restype = ctypes.c_ssize_t
        buf = ctypes.create_string_buffer(512)
        n = libc.getxattr(os.fsencode(path), b"com.apple.quarantine",
                          buf, 512, 0, 0)
        return None if n < 0 else buf.raw[:n]

    def test_output_is_flagged_downloaded_never_opened(self, tmp_path):
        p = tmp_path / "out.bin"
        p.write_bytes(b"payload")
        pkg._mark_quarantined(str(p))
        value = self._quarantine(str(p))
        assert value is not None
        assert value.startswith(b"0081;")
        assert b"QuantaCrypt" in value

    def test_nothing_is_written_off_darwin(self, tmp_path, monkeypatch):
        p = tmp_path / "out.bin"
        p.write_bytes(b"payload")
        monkeypatch.setattr(pkg.sys, "platform", "linux")
        pkg._mark_quarantined(str(p))
        assert self._quarantine(str(p)) is None

    def test_a_libc_failure_never_fails_a_completed_decrypt(self, tmp_path,
                                                            monkeypatch):
        p = tmp_path / "out.bin"
        p.write_bytes(b"payload")

        def _refuse(*a, **kw):
            raise OSError("cannot load libc")

        monkeypatch.setattr(pkg.ctypes, "CDLL", _refuse)
        # Contract: best-effort — the decrypt has already succeeded.
        assert pkg._mark_quarantined(str(p)) is None
        monkeypatch.undo()          # the reader below needs a working libc
        assert self._quarantine(str(p)) is None
        assert p.read_bytes() == b"payload"


class TestEncryptToQcxRejections:
    """Every rejection here has to happen before a single byte is written."""

    def test_password_mode_needs_a_password(self, tmp_path):
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        out = tmp_path / "f.qcx"
        with pytest.raises(InvalidInput, match="password is required"):
            pkg.encrypt_to_qcx(str(src), str(out), mode="password", password="")
        assert not out.exists()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["f.txt"]

    def test_the_output_may_not_be_the_source(self, tmp_path):
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        with pytest.raises(InvalidInput, match="can't be the source file"):
            pkg.encrypt_to_qcx(str(src), str(src), mode="password",
                               password=PW)
        assert src.read_bytes() == b"data"

    def test_the_output_may_not_live_inside_the_source_folder(self, tmp_path):
        folder = tmp_path / "docs"
        folder.mkdir()
        (folder / "a.txt").write_bytes(b"data")
        with pytest.raises(InvalidInput, match="inside the folder"):
            pkg.encrypt_to_qcx(str(folder), str(folder / "out.qcx"),
                               mode="password", password=PW)
        assert sorted(p.name for p in folder.iterdir()) == ["a.txt"]

    def test_an_unknown_mode_is_refused(self, tmp_path):
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        with pytest.raises(InvalidRequest, match="Unknown mode"):
            pkg.encrypt_to_qcx(str(src), str(tmp_path / "f.qcx"),
                               mode="telepathy", password=PW)
        assert sorted(p.name for p in tmp_path.iterdir()) == ["f.txt"]
        assert src.read_bytes() == b"data"

    def test_a_missing_source_is_refused(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            pkg.encrypt_to_qcx(str(tmp_path / "gone.txt"),
                               str(tmp_path / "f.qcx"),
                               mode="password", password=PW)
        assert not (tmp_path / "f.qcx").exists()


class TestEncryptCleanupFailures:
    """Cleanup that fails must not change the outcome of the operation."""

    def test_a_cancelled_encryption_still_reports_the_cancel(self, tmp_path,
                                                             monkeypatch):
        src = tmp_path / "f.txt"
        src.write_bytes(b"data" * 1000)
        out = tmp_path / "f.qcx"

        def _refuse(_p):
            raise OSError(errno.EPERM, "cannot unlink")

        monkeypatch.setattr(os, "remove", _refuse)
        with pytest.raises(cc.CancelledOperation):
            pkg.encrypt_to_qcx(str(src), str(out), mode="password",
                               password=PW, cancel_check=lambda: True)
        monkeypatch.undo()
        # The temp survives (the removal failed) but the real output never
        # appears — "cancelled" still means "nothing written".
        assert not out.exists()

    def test_a_folder_encrypt_never_writes_a_plaintext_staging_file(self, tmp_path):
        """The folder is archived straight into the cipher.  The output
        directory is watched at every progress step: the only files that
        may ever appear there are the 0600 ciphertext temp and the result.
        (The previous design zipped to a plaintext staging file beside the
        output — on a synced or removable destination, a copy of the
        plaintext that survived its own deletion.)"""
        folder = tmp_path / "docs"
        folder.mkdir()
        (folder / "a.txt").write_bytes(b"hello " * 10_000)
        (folder / "b.bin").write_bytes(os.urandom(70_000))
        out = tmp_path / "docs.qcx"
        seen: set[str] = set()

        def watch(_msg):
            seen.update(p.name for p in tmp_path.iterdir())

        result = pkg.encrypt_to_qcx(str(folder), str(out), mode="password",
                                    password=PW, progress=watch)
        seen.update(p.name for p in tmp_path.iterdir())
        assert result["filename"] == "docs.zip"
        assert out.exists() and out.stat().st_size > 0
        assert not [n for n in seen if "staging" in n or n.endswith(".zip")], seen
        assert all(n in ("docs", "docs.qcx") or n.startswith(".docs.qcx.qc-enc-")
                   for n in seen), seen
        # And the archive inside is a normal zip: stored where deflate
        # cannot help, deflated where it can, every member intact.
        got = pkg.decrypt_qcx(str(out), str(tmp_path / "restore"), password=PW) \
            if (tmp_path / "restore").mkdir() is None else None
        import zipfile
        with zipfile.ZipFile(got["output"]) as zf:
            assert zf.testzip() is None
            kinds = {i.filename: i.compress_type for i in zf.infolist()}
            assert kinds["docs/a.txt"] == zipfile.ZIP_DEFLATED
            assert kinds["docs/b.bin"] == zipfile.ZIP_STORED
            assert zf.read("docs/b.bin") == (folder / "b.bin").read_bytes()


class TestDecryptQcxFailurePaths:
    """decrypt_qcx writes to a temp file and only then places it; every exit
    must leave the output directory as it found it."""

    @pytest.fixture(scope="class")
    @classmethod
    def qcx(cls, tmp_path_factory):
        d = tmp_path_factory.mktemp("qcx_edges")
        src = d / "notes.txt"
        src.write_bytes(b"quantum-safe notes " * 50)
        out = d / "notes.qcx"
        pkg.encrypt_to_qcx(str(src), str(out), mode="password", password=PW)
        return str(out), src.read_bytes()

    def test_the_happy_path_restores_the_original_bytes(self, qcx, tmp_path):
        path, original = qcx
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = pkg.decrypt_qcx(path, str(out_dir), password=PW)
        assert result["filename"] == "notes.txt"
        assert open(result["output"], "rb").read() == original
        assert result["renamed"] is False

    def test_the_wrong_password_writes_nothing_and_reads_as_wrong_credentials(
            self, qcx, tmp_path):
        """The commonest failure of all, and the one the previous batch left
        out.  It must (a) stop at key derivation, (b) leave the output folder
        untouched — not even a scratch file — and (c) reach the UI as
        "wrong credentials" rather than "damaged file", because the two
        prompt completely different next steps."""
        from cryptography.exceptions import InvalidTag

        from quantacrypt.core.errors import classify_error
        path, original = qcx
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        before = open(path, "rb").read()
        with pytest.raises(InvalidTag) as exc:
            pkg.decrypt_qcx(path, str(out_dir), password=PW + "!")
        assert list(out_dir.iterdir()) == []
        assert open(path, "rb").read() == before      # the .qcx is untouched
        assert classify_error(exc.value)[0] == "wrong_credentials"
        # And the right password still works afterwards.
        assert open(pkg.decrypt_qcx(path, str(out_dir), password=PW)["output"],
                    "rb").read() == original

    def test_an_empty_password_is_refused_before_any_argon2_work(self, qcx,
                                                                 tmp_path):
        """Boundary on the other side of "has a password": an empty string is
        not a wrong password, it is a missing one, and it must not cost the
        user a 4-pass Argon2id derivation to find that out."""
        path, _ = qcx
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        with pytest.raises(InvalidInput, match="password is required"):
            pkg.decrypt_qcx(path, str(out_dir), password="")
        assert list(out_dir.iterdir()) == []

    def test_shares_offered_for_a_password_file_are_refused(self, qcx,
                                                            tmp_path):
        """Wrong *kind* of credential.  A single-mode file needs a password;
        handing it shares must not be mistaken for a corrupt container."""
        path, _ = qcx
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        with pytest.raises(InvalidInput, match="password is required"):
            pkg.decrypt_qcx(path, str(out_dir), shares=["QCSHARE-nonsense"])
        assert list(out_dir.iterdir()) == []

    def test_cancelling_during_the_payload_leaves_nothing_behind(self, qcx,
                                                                 tmp_path):
        path, _ = qcx
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        state = {"cancel": False}

        def _progress(message):
            # Cancel only once key derivation is done, so the cancel lands
            # inside the payload loop rather than in derive_final_key.
            if "Decrypting payload" in message:
                state["cancel"] = True

        with pytest.raises(cc.CancelledOperation):
            pkg.decrypt_qcx(path, str(out_dir), password=PW,
                            progress=_progress,
                            cancel_check=lambda: state["cancel"])
        assert list(out_dir.iterdir()) == []

    def test_a_corrupt_payload_is_named_as_damage_not_a_wrong_password(
            self, qcx, tmp_path):
        path, _ = qcx
        copy = tmp_path / "damaged.qcx"
        shutil.copyfile(path, copy)
        meta = pkg.load_pkg(str(copy))["meta"]
        with open(copy, "r+b") as f:
            f.seek(meta["payload_offset"] + 8 + 4)   # into chunk 0 ciphertext
            b = f.read(1)
            f.seek(meta["payload_offset"] + 8 + 4)
            f.write(bytes([b[0] ^ 0xFF]))
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        with pytest.raises(CorruptPayload, match="password is right"):
            pkg.decrypt_qcx(str(copy), str(out_dir), password=PW)
        assert list(out_dir.iterdir()) == []

    def test_a_framing_error_is_not_relabelled_as_damage(self, qcx, tmp_path):
        """A rewritten sequence number is not an auth failure, so it must
        surface as itself rather than being wrapped as CorruptPayload."""
        path, _ = qcx
        copy = tmp_path / "reordered.qcx"
        shutil.copyfile(path, copy)
        meta = pkg.load_pkg(str(copy))["meta"]
        with open(copy, "r+b") as f:
            f.seek(meta["payload_offset"])
            f.write(struct.pack(">I", 7))
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        with pytest.raises(ValueError, match="sequence mismatch") as exc:
            pkg.decrypt_qcx(str(copy), str(out_dir), password=PW)
        assert not isinstance(exc.value, CorruptPayload)
        assert list(out_dir.iterdir()) == []

    def test_an_implausible_chunk_length_is_refused_before_allocating(
            self, qcx, tmp_path):
        """The length field is still unauthenticated when it is read, so a
        crafted header would otherwise request a multi-gigabyte allocation
        before any GCM tag got the chance to disagree with it."""
        path, _ = qcx
        copy = tmp_path / "huge-chunk.qcx"
        shutil.copyfile(path, copy)
        meta = pkg.load_pkg(str(copy))["meta"]
        with open(copy, "r+b") as f:
            f.seek(meta["payload_offset"] + 4)      # the ct_len field
            f.write(struct.pack(">I", cc.CHUNK_SIZE + 17))
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        with pytest.raises(ValueError, match="implausible size"):
            pkg.decrypt_qcx(str(copy), str(out_dir), password=PW)
        assert list(out_dir.iterdir()) == []

    def test_a_failed_temp_cleanup_does_not_mask_the_real_error(
            self, qcx, tmp_path, monkeypatch):
        path, _ = qcx
        copy = tmp_path / "damaged.qcx"
        shutil.copyfile(path, copy)
        meta = pkg.load_pkg(str(copy))["meta"]
        with open(copy, "r+b") as f:
            f.seek(meta["payload_offset"] + 12)
            b = f.read(1)
            f.seek(meta["payload_offset"] + 12)
            f.write(bytes([b[0] ^ 0xFF]))
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        def _refuse(_p):
            raise OSError(errno.EPERM, "cannot unlink")

        monkeypatch.setattr(os, "remove", _refuse)
        with pytest.raises(CorruptPayload):
            pkg.decrypt_qcx(str(copy), str(out_dir), password=PW)
        monkeypatch.undo()
        # The stranded temp is a dot-prefixed scratch file, never the output.
        assert all(p.name.startswith(".qc-decrypt-") for p in out_dir.iterdir())

    def test_a_refused_utime_still_returns_the_decrypted_file(
            self, qcx, tmp_path, monkeypatch):
        path, original = qcx
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        def _refuse(_p, _times):
            raise OSError(errno.EPERM, "read-only filesystem")

        monkeypatch.setattr(os, "utime", _refuse)
        result = pkg.decrypt_qcx(path, str(out_dir), password=PW)
        monkeypatch.undo()
        assert result["timestamp"] > 0
        assert open(result["output"], "rb").read() == original

    def test_a_missing_output_directory_is_refused(self, qcx, tmp_path):
        path, _ = qcx
        missing = tmp_path / "nope"
        with pytest.raises(InvalidInput, match="output folder doesn't exist"):
            pkg.decrypt_qcx(path, str(missing), password=PW)
        # Refused, not silently created — a typo'd path must not scatter
        # decrypted plaintext into a directory the user never chose.
        assert not missing.exists()


# ════════════════════════════════════════════════════════════════════════════
# service.py
# ════════════════════════════════════════════════════════════════════════════

class TestServiceRunLoop:
    """run() must always reach teardown, whichever way the loop ends."""

    def test_a_service_stop_from_the_signal_handler_unwinds_cleanly(self):
        import io

        class _Reader:
            """stdin as the SIGTERM handler leaves it: one line, then the
            handler's ServiceStop raised out of the blocked read."""
            def __iter__(self):
                yield json.dumps({"id": "p", "op": "ping"}) + "\n"
                raise svc_mod.ServiceStop()

        out = io.StringIO()
        exited = []
        Service(_Reader(), out, exit_fn=lambda: exited.append(True)).run()
        events = [json.loads(ln) for ln in out.getvalue().splitlines()
                  if ln.strip()]
        assert events == [{"id": "p", "event": "done", "result": {}}]
        assert exited == [True]

    def test_eof_finishes_in_flight_work_before_exiting(self):
        import io
        out = io.StringIO()
        exited = []
        s = Service(io.StringIO(json.dumps({"id": "v", "op": "version"}) + "\n"),
                    out, exit_fn=lambda: exited.append(True))
        s.run()
        events = [json.loads(ln) for ln in out.getvalue().splitlines()
                  if ln.strip()]
        assert events[0]["event"] == "done"
        assert events[0]["result"]["version"]
        assert exited == [True]


class TestServiceAlwaysEndsARequest:
    """Every request has to produce a terminal event or the client hangs —
    even when the transport itself is broken."""

    def test_an_unwritable_stream_falls_back_to_stderr(self, capsys):
        import io

        class _BrokenWriter(io.StringIO):
            def write(self, _s):
                raise OSError(errno.EPIPE, "broken pipe")

        s = Service(io.StringIO(), _BrokenWriter())
        s.handle_line(json.dumps({"id": "r2", "op": "fuse_check"}))
        s.wait_idle()
        err = capsys.readouterr().err
        assert "could not report failure of r2" in err
        # The bookkeeping is still clean, so the id is reusable.
        assert s._reqs == {}


class TestServiceParameterValidation:
    """Bad params are refused before any work starts."""

    def test_a_non_string_optional_parameter_is_refused(self, tmp_path):
        import io
        src = tmp_path / "f.txt"
        src.write_bytes(b"data")
        out = tmp_path / "f.qcx"
        s = Service(io.StringIO(), io.StringIO())
        ctx = svc_mod._Ctx(s, svc_mod._Request("r", "encrypt", {}))
        with pytest.raises(InvalidRequest, match="'embed_binary' must be a string"):
            svc_mod.op_encrypt({"source": str(src), "output": str(out),
                                "mode": "password", "password": PW,
                                "embed_binary": 17}, ctx)
        assert not out.exists()

    def test_a_non_list_shares_parameter_is_refused(self, tmp_path):
        """A single share string is the obvious client mistake; refusing it
        by type (rather than iterating the characters of it) has to happen
        before the output directory is touched."""
        import io
        s = Service(io.StringIO(), io.StringIO())
        ctx = svc_mod._Ctx(s, svc_mod._Request("r", "decrypt", {}))
        with pytest.raises(InvalidRequest, match="'shares' must be a list"):
            svc_mod.op_decrypt({"path": "x.qcx", "output_dir": str(tmp_path),
                                "shares": "QCSHARE-abc"}, ctx)
        assert list(tmp_path.iterdir()) == []

    def test_a_list_of_shares_gets_past_the_type_check(self, tmp_path):
        """The other side of the branch: a well-typed list is accepted and
        the operation then fails on the missing file, not on the type."""
        import io
        s = Service(io.StringIO(), io.StringIO())
        ctx = svc_mod._Ctx(s, svc_mod._Request("r", "decrypt", {}))
        with pytest.raises(Exception) as exc:
            svc_mod.op_decrypt({"path": str(tmp_path / "gone.qcx"),
                                "output_dir": str(tmp_path),
                                "shares": ["QCSHARE-abc"]}, ctx)
        assert not isinstance(exc.value, InvalidRequest)
        assert list(tmp_path.iterdir()) == []


class TestVolumeCreateCancellation:
    """"Cancelled" has to mean "nothing written": the shares or password for
    a half-created container would never be shown to anyone."""

    class _CancelledCtx:
        def __init__(self):
            self.messages = []

        def progress(self, message):
            self.messages.append(message)

        def cancelled(self):
            return True

        def check(self):
            raise cc.CancelledOperation("Cancelled")

    def test_no_container_survives_a_cancel_before_the_first_write(self,
                                                                   tmp_path):
        path = str(tmp_path / "vault.qcv")
        with pytest.raises(cc.CancelledOperation):
            svc_mod.op_volume_create({"path": path, "mode": "password",
                                      "password": PW}, self._CancelledCtx())
        # Nothing at all — not the container, not its .part scratch file.
        assert list(tmp_path.iterdir()) == []

    def test_a_cancelled_shamir_create_leaves_nothing_either(self, tmp_path):
        path = str(tmp_path / "vault.qcv")
        with pytest.raises(cc.CancelledOperation):
            svc_mod.op_volume_create({"path": path, "mode": "shamir",
                                      "k": 2, "n": 3}, self._CancelledCtx())
        assert list(tmp_path.iterdir()) == []

    def test_an_existing_path_is_refused(self, tmp_path):
        import io
        path = tmp_path / "vault.qcv"
        path.write_bytes(b"not really a volume")
        s = Service(io.StringIO(), io.StringIO())
        ctx = svc_mod._Ctx(s, svc_mod._Request("r", "volume_create", {}))
        with pytest.raises(FileExistsError):
            svc_mod.op_volume_create({"path": str(path), "mode": "password",
                                      "password": PW}, ctx)
        assert path.read_bytes() == b"not really a volume"


# ════════════════════════════════════════════════════════════════════════════
# crypto.py
# ════════════════════════════════════════════════════════════════════════════

class TestContentIntegrityCheck:
    """The per-chunk GCM tags authenticate the ciphertext.  Format-1 files
    also carry a whole-file SHA-256 in the envelope; format 2 dropped it
    (the tags, AAD and authenticated chunk count already prove every byte),
    but a recorded hash is still honoured when one is present."""

    @pytest.fixture(scope="class")
    @classmethod
    def encrypted(cls, tmp_path_factory):
        d = tmp_path_factory.mktemp("integrity")
        src = d / "data.bin"
        src.write_bytes(b"content integrity " * 100)
        enc = d / "data.qcx"
        with open(enc, "wb") as f:
            offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, PW,
                                               filename="data.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        import base64
        argon = cc.argon2id_derive(PW.encode(),
                                   base64.b64decode(meta["argon_salt"]),
                                   meta.get("argon2"))
        sk = cc.aes_gcm_decrypt(argon,
                                base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                base64.b64decode(meta["kyber_sk_enc"]))
        ss = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]),
                             cc.validate_kem(meta.get("kem")))
        return str(enc), meta, cc.xor_bytes(argon, ss), src.read_bytes()

    def test_a_format_2_envelope_carries_no_hash_and_decrypts(self, encrypted):
        import base64
        import io
        path, meta, key, original = encrypted
        inner = json.loads(cc.aes_gcm_decrypt(
            key, base64.b64decode(meta["filename_nonce"]),
            base64.b64decode(meta["filename_enc"])))
        assert "sha256" not in inner
        buf = io.BytesIO()
        name, size, ts = cc.decrypt_streaming(path, buf, dict(meta), key)
        assert buf.getvalue() == original
        assert name == "data.bin"
        assert size == len(original)
        assert ts > 0

    def test_a_matching_recorded_hash_decrypts(self, encrypted):
        """A format-1 style envelope: the hash is present and agrees."""
        import base64
        import hashlib
        import io
        path, meta, key, original = encrypted
        inner = json.loads(cc.aes_gcm_decrypt(
            key, base64.b64decode(meta["filename_nonce"]),
            base64.b64decode(meta["filename_enc"])))
        inner["sha256"] = hashlib.sha256(original).hexdigest()
        nonce, ct = cc.aes_gcm_encrypt(
            key, json.dumps(inner, separators=(",", ":")).encode())
        hashed = dict(meta)
        hashed["filename_nonce"] = base64.b64encode(nonce).decode()
        hashed["filename_enc"] = base64.b64encode(ct).decode()
        buf = io.BytesIO()
        cc.decrypt_streaming(path, buf, hashed, key)
        assert buf.getvalue() == original

    def test_a_disagreeing_recorded_hash_is_refused(self, encrypted):
        import base64
        import io
        path, meta, key, original = encrypted
        # Re-seal the envelope with a hash that does not describe the
        # payload — the shape a partial write or a bad sector produces.
        inner = json.loads(cc.aes_gcm_decrypt(
            key, base64.b64decode(meta["filename_nonce"]),
            base64.b64decode(meta["filename_enc"])))
        inner["sha256"] = "0" * 64
        nonce, ct = cc.aes_gcm_encrypt(
            key, json.dumps(inner, separators=(",", ":")).encode())
        forged = dict(meta)
        forged["filename_nonce"] = base64.b64encode(nonce).decode()
        forged["filename_enc"] = base64.b64encode(ct).decode()
        sink = io.BytesIO()
        with pytest.raises(ValueError, match="Content integrity check failed"):
            cc.decrypt_streaming(path, sink, forged, key)
        # The check is end-to-end, so it can only fire once the whole payload
        # has been streamed out: the destination DOES hold bytes at that
        # point, and every caller is therefore obliged to discard them.
        # decrypt_qcx does exactly that by streaming into a temp file it
        # unlinks — see TestDecryptQcxFailurePaths.
        assert sink.getvalue() == original

    def test_an_envelope_without_a_hash_still_decrypts(self, encrypted):
        """Files written before the hash existed must keep opening."""
        import base64
        import io
        path, meta, key, original = encrypted
        inner = json.loads(cc.aes_gcm_decrypt(
            key, base64.b64decode(meta["filename_nonce"]),
            base64.b64decode(meta["filename_enc"])))
        inner.pop("sha256", None)
        nonce, ct = cc.aes_gcm_encrypt(
            key, json.dumps(inner, separators=(",", ":")).encode())
        legacy = dict(meta)
        legacy["filename_nonce"] = base64.b64encode(nonce).decode()
        legacy["filename_enc"] = base64.b64encode(ct).decode()
        buf = io.BytesIO()
        cc.decrypt_streaming(path, buf, legacy, key)
        assert buf.getvalue() == original
